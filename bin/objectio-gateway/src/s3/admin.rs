//! The admin API for users and access keys.

use super::*;

/// Admin API response types
#[derive(Serialize)]
pub struct AdminUserResponse {
    pub user_id: String,
    pub display_name: String,
    pub arn: String,
    pub status: String,
    pub created_at: u64,
    pub email: String,
    pub tenant: String,
}

#[derive(Serialize)]
pub struct AdminAccessKeyResponse {
    pub access_key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_access_key: Option<String>,
    pub user_id: String,
    pub status: String,
    pub created_at: u64,
    /// `s3://bucket/prefix/` the key is confined to. Empty = unscoped.
    pub scope: String,
    /// `"READ"` or `"READ_WRITE"`.
    pub operation: String,
}

/// Optional JSON body for `POST /_admin/users/{user_id}/keys`.
///
/// An absent or empty body yields an unscoped read-write key, which is what
/// every pre-scoping caller sends.
#[derive(Debug, Deserialize, Default)]
pub struct CreateAccessKeyBody {
    /// `s3://bucket/prefix/` restriction. Omitted or empty = unscoped.
    #[serde(default)]
    pub scope: String,
    /// `"R"`/`"read-only"` or `"RW"`/`"read-write"`. Omitted = read-write.
    #[serde(default)]
    pub operation: Option<String>,
}

#[derive(Serialize)]
pub struct AdminListUsersResponse {
    pub users: Vec<AdminUserResponse>,
    pub is_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_marker: Option<String>,
}

#[derive(Serialize)]
pub struct AdminListAccessKeysResponse {
    pub access_keys: Vec<AdminAccessKeyResponse>,
}

#[derive(Deserialize)]
pub struct CreateUserParams {
    pub display_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub tenant: String,
}

/// List users (GET /_admin/users)
pub async fn admin_list_users(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    // Extract tenant before auth check consumes auth
    let tenant = auth
        .as_ref()
        .map(|Extension(a)| a.tenant.clone())
        .or_else(|| crate::console_auth::validate_session_from_headers(&headers).map(|s| s.tenant))
        .unwrap_or_default();

    // This handler already filters its result to the caller's tenant — it was
    // written for tenant admins. The gate in front of it was not: over SigV4
    // `check_admin_access` admits only the root key, so a tenant admin could
    // create a user and mint its keys but never list them back. Every sibling
    // route (list/create/delete access keys, delete user) uses the
    // tenant-aware gate; this one was the outlier.
    if tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &tenant).await
    {
        return deny;
    }

    let mut client = state.meta_client.clone();

    match client
        .list_users(ListUsersRequest {
            max_results: 1000,
            marker: String::new(),
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();
            let result = AdminListUsersResponse {
                users: resp
                    .users
                    .into_iter()
                    .filter(|u| tenant.is_empty() || u.tenant == tenant)
                    .map(|u| AdminUserResponse {
                        user_id: u.user_id,
                        display_name: u.display_name,
                        arn: u.arn,
                        status: crate::admin::user_status_label(u.status).to_string(),
                        created_at: u.created_at,
                        email: u.email,
                        tenant: u.tenant,
                    })
                    .collect(),
                is_truncated: resp.is_truncated,
                next_marker: if resp.next_marker.is_empty() {
                    None
                } else {
                    Some(resp.next_marker)
                },
            };

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&result).unwrap()))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to list users: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(admin_error_json(e.message())))
                .unwrap()
        }
    }
}

/// Create user (POST /_admin/users)
pub async fn admin_create_user(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let caller = crate::admin::extract_caller(&auth, &headers);

    let params: CreateUserParams = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(e) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(admin_error_json(&format!("Invalid JSON: {e}"))))
                .unwrap();
        }
    };

    // Default to the caller's tenant if the body leaves it empty.
    let tenant = if params.tenant.is_empty() {
        caller.tenant.clone()
    } else {
        params.tenant
    };

    // System admin can create users in any tenant (including system scope).
    // Tenant admins can only create users inside their own tenant.
    if tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &tenant).await
    {
        return deny;
    }

    let mut client = state.meta_client.clone();

    match client
        .create_user(CreateUserRequest {
            display_name: params.display_name,
            email: params.email,
            tenant,
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();
            let user = resp.user.unwrap();
            let result = AdminUserResponse {
                user_id: user.user_id,
                display_name: user.display_name,
                arn: user.arn,
                status: crate::admin::user_status_label(user.status).to_string(),
                created_at: user.created_at,
                email: user.email,
                tenant: user.tenant,
            };

            info!("Created user: {}", result.user_id);
            Response::builder()
                .status(StatusCode::CREATED)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&result).unwrap()))
                .unwrap()
        }
        Err(e) => {
            error!("Failed to create user: {}", e);
            // Map the gRPC code rather than calling everything a 500, and
            // send `e.message()` rather than `e` — the Display impl embeds the
            // whole tonic Status including its MetadataMap, which put response
            // headers and internal detail into the client's error body.
            let status = match e.code() {
                tonic::Code::AlreadyExists => StatusCode::CONFLICT,
                tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
                tonic::Code::NotFound => StatusCode::NOT_FOUND,
                tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    serde_json::json!({ "error": e.message() }).to_string(),
                ))
                .unwrap()
        }
    }
}

/// Resolve a user_id to its tenant via meta. Returns `None` if the user
/// does not exist, letting callers respond 404 appropriately.
pub(crate) async fn lookup_user_tenant(state: &AppState, user_id: &str) -> Option<String> {
    let mut client = state.meta_client.clone();
    let resp = client
        .get_user(GetUserRequest {
            user_id: user_id.to_string(),
        })
        .await
        .ok()?
        .into_inner();
    resp.user.map(|u| u.tenant)
}

/// Resolve an access_key_id to its tenant via meta.
/// Whatever the key's status: an inactive key, or one of a suspended user,
/// is still its tenant's to delete.
pub(crate) async fn lookup_access_key_tenant(
    state: &AppState,
    access_key_id: &str,
) -> Option<String> {
    let mut client = state.meta_client.clone();
    let key = client
        .get_access_key(objectio_proto::metadata::GetAccessKeyRequest {
            access_key_id: access_key_id.to_string(),
        })
        .await
        .ok()?
        .into_inner()
        .access_key?;
    lookup_user_tenant(state, &key.user_id).await
}

/// Delete user (DELETE /_admin/users/{user_id})
pub async fn admin_delete_user(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    // Look up target user's tenant so tenant admins cannot delete users
    // outside their own tenant.
    let target_tenant = match lookup_user_tenant(&state, &user_id).await {
        Some(t) => t,
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"User not found"}"#))
                .unwrap();
        }
    };
    if target_tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &target_tenant).await
    {
        return deny;
    }

    let mut client = state.meta_client.clone();

    match client
        .delete_user(DeleteUserRequest {
            user_id: user_id.clone(),
        })
        .await
    {
        Ok(_) => {
            state.auth_state.forget_user(&user_id);
            info!("Deleted user: {}", user_id);
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"User not found"}"#))
                    .unwrap()
            } else {
                error!("Failed to delete user: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(admin_error_json(e.message())))
                    .unwrap()
            }
        }
    }
}

/// List access keys for user (GET /_admin/users/{user_id}/access-keys)
pub async fn admin_list_access_keys(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    let target_tenant = match lookup_user_tenant(&state, &user_id).await {
        Some(t) => t,
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"User not found"}"#))
                .unwrap();
        }
    };
    if target_tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &target_tenant).await
    {
        return deny;
    }

    let mut client = state.meta_client.clone();

    match client
        .list_access_keys(ListAccessKeysRequest {
            user_id: user_id.clone(),
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();
            let result = AdminListAccessKeysResponse {
                access_keys: resp
                    .access_keys
                    .into_iter()
                    .map(|k| AdminAccessKeyResponse {
                        access_key_id: k.access_key_id,
                        secret_access_key: None, // Don't return secret on list
                        user_id: k.user_id,
                        status: crate::admin::key_status_label(k.status).to_string(),
                        created_at: k.created_at,
                        scope: k.scope,
                        operation: operation_label(k.operation),
                    })
                    .collect(),
            };

            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&result).unwrap()))
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"User not found"}"#))
                    .unwrap()
            } else {
                error!("Failed to list access keys: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(admin_error_json(e.message())))
                    .unwrap()
            }
        }
    }
}

/// 400 with a JSON error body, for bad scope/operation input.
pub(crate) fn admin_key_error(message: &str) -> Response {
    let body = serde_json::json!({ "error": message }).to_string();
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap()
}

/// Create access key for user (POST /_admin/users/{user_id}/access-keys)
pub async fn admin_create_access_key(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    body: Bytes,
) -> Response {
    let target_tenant = match lookup_user_tenant(&state, &user_id).await {
        Some(t) => t,
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"User not found"}"#))
                .unwrap();
        }
    };
    if target_tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &target_tenant).await
    {
        return deny;
    }

    // Body is optional: callers that predate scoped keys send none.
    let params: CreateAccessKeyBody = if body.is_empty() {
        CreateAccessKeyBody::default()
    } else {
        match serde_json::from_slice(&body) {
            Ok(p) => p,
            Err(e) => return admin_key_error(&format!("invalid request body: {e}")),
        }
    };

    // Reject a malformed scope rather than storing one that matches nothing.
    if !params.scope.is_empty()
        && let Err(msg) = objectio_auth::validate_scope(&params.scope)
    {
        return admin_key_error(&msg);
    }

    let operation = match params.operation.as_deref() {
        None => ProtoKeyOperation::KeyOpReadWrite,
        Some(raw) => match objectio_auth::Operation::parse(raw) {
            Some(objectio_auth::Operation::Read) => ProtoKeyOperation::KeyOpRead,
            Some(objectio_auth::Operation::ReadWrite) => ProtoKeyOperation::KeyOpReadWrite,
            None => {
                return admin_key_error(&format!(
                    "invalid operation '{raw}': expected 'R'/'read-only' or 'RW'/'read-write'"
                ));
            }
        },
    };

    let mut client = state.meta_client.clone();

    match client
        .create_access_key(CreateAccessKeyRequest {
            user_id: user_id.clone(),
            scope: params.scope.clone(),
            operation: operation as i32,
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();
            let key = resp.access_key.unwrap();
            let result = AdminAccessKeyResponse {
                access_key_id: key.access_key_id,
                secret_access_key: Some(key.secret_access_key), // Include secret on create
                user_id: key.user_id,
                status: crate::admin::key_status_label(key.status).to_string(),
                created_at: key.created_at,
                scope: key.scope,
                operation: operation_label(key.operation),
            };

            info!(
                "Created access key {} for user {}",
                result.access_key_id, user_id
            );
            Response::builder()
                .status(StatusCode::CREATED)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&result).unwrap()))
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"User not found"}"#))
                    .unwrap()
            } else {
                error!("Failed to create access key: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(admin_error_json(e.message())))
                    .unwrap()
            }
        }
    }
}

/// Delete access key (DELETE /_admin/access-keys/{access_key_id})
pub async fn admin_delete_access_key(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(access_key_id): Path<String>,
) -> Response {
    let target_tenant = match lookup_access_key_tenant(&state, &access_key_id).await {
        Some(t) => t,
        None => {
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"error":"Access key not found"}"#))
                .unwrap();
        }
    };
    if target_tenant.is_empty() {
        if let Some(deny) = crate::admin::require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) =
        crate::admin::require_tenant_admin_access(&state, &auth, &headers, &target_tenant).await
    {
        return deny;
    }

    let mut client = state.meta_client.clone();

    match client
        .delete_access_key(DeleteAccessKeyRequest {
            access_key_id: access_key_id.clone(),
        })
        .await
    {
        Ok(_) => {
            state.auth_state.forget_key(&access_key_id);
            info!("Deleted access key: {}", access_key_id);
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap()
        }
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"error":"Access key not found"}"#))
                    .unwrap()
            } else {
                error!("Failed to delete access key: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(admin_error_json(e.message())))
                    .unwrap()
            }
        }
    }
}
