//! Delta Sharing management on the admin API: a share's tables, dropping a
//! share, and recipients. (Listing and creating shares, and listing
//! recipients, are in `admin`.)
//!
//! A share belongs to a tenant, and that tenant's admins manage it, as the
//! system admin does every share. It exposes data of its own tenant: only
//! the system admin may add a table held in another tenant's bucket, which
//! is how cross-tenant sharing is meant to work. A share holds Delta tables
//! only. A
//! recipient is managed by whoever administers every share it reads.

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use objectio_auth::AuthResult;
use objectio_delta_sharing::handlers::delta_only;
use objectio_delta_sharing::types::{
    AddTableRequest, CreateRecipientRequest, CreateRecipientResponse,
};
use objectio_proto::metadata::{
    DeltaAddTableRequest, DeltaCreateRecipientRequest, DeltaDropRecipientRequest,
    DeltaDropShareRequest, DeltaGetShareRequest, DeltaListRecipientsRequest,
    DeltaListTablesRequest, DeltaRemoveTableRequest, GetBucketRequest,
};
use std::sync::Arc;
use tracing::info;

use crate::admin::{
    extract_caller, is_system_admin, meta_failure, require_system_admin,
    require_tenant_admin_access,
};
use crate::s3::AppState;

type Auth = Option<Extension<AuthResult>>;

/// A meta error as an admin API answer.
fn meta_error(e: &tonic::Status) -> Response {
    match e.code() {
        tonic::Code::NotFound => (StatusCode::NOT_FOUND, e.message().to_string()).into_response(),
        tonic::Code::AlreadyExists => {
            (StatusCode::CONFLICT, e.message().to_string()).into_response()
        }
        tonic::Code::InvalidArgument => {
            (StatusCode::BAD_REQUEST, e.message().to_string()).into_response()
        }
        _ => meta_failure(e),
    }
}

/// The tenant a share belongs to (empty = the system tenant).
async fn share_tenant(state: &AppState, share: &str) -> Result<String, Response> {
    let resp = state
        .meta_client
        .clone()
        .delta_get_share(DeltaGetShareRequest {
            name: share.to_string(),
        })
        .await
        .map_err(|e| meta_error(&e))?
        .into_inner();
    resp.share.map(|s| s.tenant).ok_or_else(|| {
        (StatusCode::NOT_FOUND, format!("share '{share}' not found")).into_response()
    })
}

/// Refuse a caller who doesn't administer `tenant`'s shares: the system
/// admin for the system tenant's, that tenant's admins (or the system
/// admin) for a tenant's.
async fn require_share_admin(
    state: &AppState,
    auth: &Auth,
    headers: &HeaderMap,
    tenant: &str,
) -> Option<Response> {
    if tenant.is_empty() {
        require_system_admin(auth, headers)
    } else {
        require_tenant_admin_access(state, auth, headers, tenant).await
    }
}

/// The share's tenant, once the caller is known to administer it.
async fn administered_share(
    state: &AppState,
    auth: &Auth,
    headers: &HeaderMap,
    share: &str,
) -> Result<String, Response> {
    // Who is asking first: an unauthenticated caller learns nothing, not
    // even whether the share exists.
    if !extract_caller(auth, headers).authenticated {
        return Err((StatusCode::UNAUTHORIZED, "Authentication required").into_response());
    }
    let tenant = share_tenant(state, share).await?;
    match require_share_admin(state, auth, headers, &tenant).await {
        Some(deny) => Err(deny),
        None => Ok(tenant),
    }
}

/// The tenant holding the data a share table points at: its bucket's. A
/// share serves Delta tables only; an Iceberg one is refused here, before
/// it is recorded.
async fn data_tenant(state: &AppState, body: &AddTableRequest) -> Result<String, Response> {
    delta_only(&body.table_type, &body.schema, &body.name)
        .map_err(|e| (e.status, e.message).into_response())?;
    if body.bucket.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "a delta table needs a bucket").into_response());
    }
    match state
        .meta_client
        .clone()
        .get_bucket(GetBucketRequest {
            name: body.bucket.clone(),
        })
        .await
    {
        Ok(r) => r.into_inner().bucket.map(|b| b.tenant).ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                format!("no bucket '{}'", body.bucket),
            )
                .into_response()
        }),
        Err(e) if e.code() == tonic::Code::NotFound => Err((
            StatusCode::BAD_REQUEST,
            format!("no bucket '{}'", body.bucket),
        )
            .into_response()),
        Err(e) => Err(meta_failure(&e)),
    }
}

/// `DELETE /_admin/shares/{share}`
pub async fn drop_share(
    State(state): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Path(share): Path<String>,
) -> Response {
    if let Err(deny) = administered_share(&state, &auth, &headers, &share).await {
        return deny;
    }
    match state
        .meta_client
        .clone()
        .delta_drop_share(DeltaDropShareRequest {
            name: share.clone(),
        })
        .await
    {
        Ok(_) => {
            info!("Dropped delta share '{share}'");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => meta_error(&e),
    }
}

/// `GET /_admin/shares/{share}/tables`
pub async fn list_share_tables(
    State(state): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Path(share): Path<String>,
) -> Response {
    if let Err(deny) = administered_share(&state, &auth, &headers, &share).await {
        return deny;
    }
    match state
        .meta_client
        .clone()
        .delta_list_tables(DeltaListTablesRequest {
            share,
            schema: String::new(),
            max_results: 0,
            page_token: String::new(),
        })
        .await
    {
        Ok(resp) => {
            let tables: Vec<serde_json::Value> = resp
                .into_inner()
                .tables
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "share": t.share,
                        "schema": t.schema,
                        "name": t.table_name,
                        "table_type": t.table_type,
                    })
                })
                .collect();
            Json(serde_json::json!({ "tables": tables })).into_response()
        }
        Err(e) => meta_error(&e),
    }
}

/// `POST /_admin/shares/{share}/tables`
pub async fn add_share_table(
    State(state): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Path(share): Path<String>,
    Json(body): Json<AddTableRequest>,
) -> Response {
    let share_tenant = match administered_share(&state, &auth, &headers, &share).await {
        Ok(t) => t,
        Err(deny) => return deny,
    };
    let data_tenant = match data_tenant(&state, &body).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };
    if data_tenant != share_tenant && !is_system_admin(&extract_caller(&auth, &headers)) {
        return (
            StatusCode::FORBIDDEN,
            "A share exposes its own tenant's data; only the system admin shares across tenants",
        )
            .into_response();
    }
    match state
        .meta_client
        .clone()
        .delta_add_table(DeltaAddTableRequest {
            share: share.clone(),
            schema: body.schema,
            table_name: body.name,
            table_type: body.table_type,
            bucket: body.bucket,
            path: body.path,
            warehouse: body.warehouse,
            namespace: body.namespace,
        })
        .await
    {
        Ok(resp) => {
            let Some(t) = resp.into_inner().table else {
                return (StatusCode::INTERNAL_SERVER_ERROR, "no table in response").into_response();
            };
            info!(
                "Added table '{}.{}' to delta share '{share}'",
                t.schema, t.table_name
            );
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "share": t.share,
                    "schema": t.schema,
                    "name": t.table_name,
                    "table_type": t.table_type,
                })),
            )
                .into_response()
        }
        Err(e) => meta_error(&e),
    }
}

/// `DELETE /_admin/shares/{share}/schemas/{schema}/tables/{table}`
pub async fn remove_share_table(
    State(state): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Path((share, schema, table)): Path<(String, String, String)>,
) -> Response {
    if let Err(deny) = administered_share(&state, &auth, &headers, &share).await {
        return deny;
    }
    match state
        .meta_client
        .clone()
        .delta_remove_table(DeltaRemoveTableRequest {
            share,
            schema,
            table_name: table,
        })
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => meta_error(&e),
    }
}

/// Refuse a caller who doesn't administer every one of `shares`. A
/// recipient of no share at all is the system admin's.
async fn require_admin_of_shares(
    state: &AppState,
    auth: &Auth,
    headers: &HeaderMap,
    shares: &[String],
) -> Option<Response> {
    if shares.is_empty() || is_system_admin(&extract_caller(auth, headers)) {
        return require_system_admin(auth, headers);
    }
    for share in shares {
        if let Err(deny) = administered_share(state, auth, headers, share).await {
            return Some(deny);
        }
    }
    None
}

/// `POST /_admin/recipients`
pub async fn create_recipient(
    State(state): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Json(body): Json<CreateRecipientRequest>,
) -> Response {
    if body.name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    if let Some(deny) = require_admin_of_shares(&state, &auth, &headers, &body.shares).await {
        return deny;
    }
    match state
        .meta_client
        .clone()
        .delta_create_recipient(DeltaCreateRecipientRequest {
            name: body.name,
            shares: body.shares,
        })
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            let Some(recipient) = inner.recipient else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "no recipient in response",
                )
                    .into_response();
            };
            info!("Created delta recipient '{}'", recipient.name);
            (
                StatusCode::CREATED,
                Json(CreateRecipientResponse {
                    name: recipient.name,
                    shares: recipient.shares,
                    bearer_token: inner.raw_token,
                }),
            )
                .into_response()
        }
        Err(e) => meta_error(&e),
    }
}

/// `DELETE /_admin/recipients/{name}`
pub async fn drop_recipient(
    State(state): State<Arc<AppState>>,
    auth: Auth,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if !extract_caller(&auth, &headers).authenticated {
        return (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
    }
    // There is no lookup by name: find it in the list.
    let recipient = match state
        .meta_client
        .clone()
        .delta_list_recipients(DeltaListRecipientsRequest {
            max_results: 0,
            page_token: String::new(),
        })
        .await
    {
        Ok(resp) => resp
            .into_inner()
            .recipients
            .into_iter()
            .find(|r| r.name == name),
        Err(e) => return meta_failure(&e),
    };
    let Some(recipient) = recipient else {
        return (
            StatusCode::NOT_FOUND,
            format!("recipient '{name}' not found"),
        )
            .into_response();
    };
    if let Some(deny) = require_admin_of_shares(&state, &auth, &headers, &recipient.shares).await {
        return deny;
    }
    match state
        .meta_client
        .clone()
        .delta_drop_recipient(DeltaDropRecipientRequest { name: name.clone() })
        .await
    {
        Ok(_) => {
            info!("Dropped delta recipient '{name}'");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => meta_error(&e),
    }
}
