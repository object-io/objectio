//! Admin configuration API handlers
//!
//! Provides REST endpoints for managing cluster configuration:
//! - `GET    /_admin/config`             — list all config sections
//! - `GET    /_admin/config/{section}`   — get config for a section
//! - `PUT    /_admin/config/{section}`   — set config for a section
//! - `DELETE /_admin/config/{section}`   — delete config
//!
//! OIDC provider configs at `identity/openid/{name}` get special handling:
//! secrets are redacted on GET, and values are validated on PUT.

use axum::{
    Extension, Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use objectio_auth::AuthResult;
use objectio_proto::metadata::{
    CreatePoolRequest, CreateTenantRequest, DeleteConfigRequest, DeletePoolRequest,
    DeleteTenantRequest, GetConfigRequest, GetDrainStatusRequest, GetListingNodesRequest,
    GetPoolRequest, GetRebalanceStatusRequest, GetTenantRequest, ListConfigRequest,
    ListPoolsRequest, ListTenantsRequest, OsdAdminState as ProtoOsdAdminState, PoolConfig,
    SetConfigRequest, SetOsdAdminStateRequest, TenantConfig, UpdatePoolRequest,
    UpdateTenantRequest,
};
use objectio_proto::storage::storage_service_client::StorageServiceClient;

/// `base` with each top-level field of `update` put over it.
fn overlay(mut base: serde_json::Value, update: &serde_json::Value) -> serde_json::Value {
    if let (Some(base), Some(update)) = (base.as_object_mut(), update.as_object()) {
        for (k, v) in update {
            base.insert(k.clone(), v.clone());
        }
    }
    base
}

/// Convert JSON to PoolConfig (prost types don't implement Deserialize)
fn json_to_pool(v: &serde_json::Value) -> PoolConfig {
    PoolConfig {
        name: v["name"].as_str().unwrap_or_default().to_string(),
        ec_type: v["ec_type"].as_i64().unwrap_or_default() as i32,
        ec_k: v["ec_k"].as_u64().unwrap_or(3) as u32,
        ec_m: v["ec_m"].as_u64().unwrap_or(2) as u32,
        ec_local_parity: v["ec_local_parity"].as_u64().unwrap_or_default() as u32,
        ec_global_parity: v["ec_global_parity"].as_u64().unwrap_or_default() as u32,
        replication_count: v["replication_count"].as_u64().unwrap_or_default() as u32,
        osd_tags: v["osd_tags"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        failure_domain: v["failure_domain"].as_str().unwrap_or("rack").to_string(),
        quota_bytes: v["quota_bytes"].as_u64().unwrap_or_default(),
        description: v["description"].as_str().unwrap_or_default().to_string(),
        enabled: v["enabled"].as_bool().unwrap_or(true),
        created_at: 0,
        updated_at: 0,
        // Placement-group sizing. 0 places each object directly (CRUSH,
        // no placement groups), the default; for PG-based placement pass
        // "pg_count": 256 (or higher) on pool creation.
        pg_count: v["pg_count"].as_u64().unwrap_or_default() as u32,
        tier: v["tier"].as_str().unwrap_or_default().to_string(),
    }
}

/// Convert JSON to TenantConfig
fn json_to_tenant(v: &serde_json::Value) -> TenantConfig {
    TenantConfig {
        name: v["name"].as_str().unwrap_or_default().to_string(),
        display_name: v["display_name"].as_str().unwrap_or_default().to_string(),
        default_pool: v["default_pool"].as_str().unwrap_or_default().to_string(),
        allowed_pools: v["allowed_pools"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        quota_bytes: v["quota_bytes"].as_u64().unwrap_or_default(),
        quota_buckets: v["quota_buckets"].as_u64().unwrap_or_default(),
        quota_objects: v["quota_objects"].as_u64().unwrap_or_default(),
        admin_users: v["admin_users"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default(),
        oidc_provider: v["oidc_provider"].as_str().unwrap_or_default().to_string(),
        labels: v["labels"]
            .as_object()
            .map(|m| {
                m.iter()
                    .map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string()))
                    .collect()
            })
            .unwrap_or_default(),
        enabled: v["enabled"].as_bool().unwrap_or(true),
        created_at: 0,
        updated_at: 0,
        // Validated by the handler first (`tenant_dedup_error`).
        dedup: v
            .get("dedup")
            .filter(|d| !d.is_null())
            .and_then(|d| objectio_proto::dedup::from_json(d).ok()),
    }
}

/// Why a tenant body's `dedup` cannot be stored, if it cannot.
fn tenant_dedup_error(v: &serde_json::Value) -> Option<String> {
    let d = v.get("dedup").filter(|d| !d.is_null())?;
    objectio_proto::dedup::from_json(d)
        .and_then(|p| objectio_proto::dedup::validate(&p))
        .err()
}

/// Convert a PoolConfig to JSON (prost types don't implement Serialize)
fn pool_to_json(p: &PoolConfig) -> serde_json::Value {
    serde_json::json!({
        "name": p.name,
        "ec_type": p.ec_type,
        "ec_k": p.ec_k,
        "ec_m": p.ec_m,
        "ec_local_parity": p.ec_local_parity,
        "ec_global_parity": p.ec_global_parity,
        "replication_count": p.replication_count,
        "osd_tags": p.osd_tags,
        "failure_domain": p.failure_domain,
        "quota_bytes": p.quota_bytes,
        "description": p.description,
        "enabled": p.enabled,
        "created_at": p.created_at,
        "updated_at": p.updated_at,
        "pg_count": p.pg_count,
        "tier": p.tier,
    })
}

/// Convert a TenantConfig to JSON
fn tenant_to_json(t: &TenantConfig) -> serde_json::Value {
    serde_json::json!({
        "name": t.name,
        "display_name": t.display_name,
        "default_pool": t.default_pool,
        "allowed_pools": t.allowed_pools,
        "quota_bytes": t.quota_bytes,
        "quota_buckets": t.quota_buckets,
        "quota_objects": t.quota_objects,
        "admin_users": t.admin_users,
        "oidc_provider": t.oidc_provider,
        "labels": t.labels,
        "enabled": t.enabled,
        "created_at": t.created_at,
        "updated_at": t.updated_at,
        // Round-trips: the console saves the whole tenant, and a field it
        // did not send back would reset to inherit.
        "dedup": t.dedup.as_ref().map(objectio_proto::dedup::to_json),
    })
}
use serde::Deserialize;
use std::sync::Arc;
use tracing::{info, warn};

use crate::s3::AppState;

/// Query params for list config
#[derive(Debug, Deserialize)]
pub struct ListConfigParams {
    #[serde(default)]
    pub prefix: String,
}

/// List all config entries (optionally filtered by prefix)
pub async fn admin_list_config(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query<ListConfigParams>,
) -> Response {
    // Tenant admins can list ONLY their own tenant's OIDC config keys (so
    // the Identity page can render them). Anything else stays system-admin
    // gated.
    let caller = extract_caller(&auth, &headers);
    let scoped_keys: Option<Vec<String>> = if is_system_admin(&caller) {
        None
    } else if caller.authenticated {
        let keys = caller_tenant_oidc_config_keys(&state, &auth, &headers).await;
        if keys.is_empty() {
            return Json::<Vec<serde_json::Value>>(Vec::new()).into_response();
        }
        Some(keys)
    } else {
        return (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
    };

    let mut client = state.meta_client.clone();
    match client
        .list_config(ListConfigRequest {
            prefix: params.prefix,
        })
        .await
    {
        Ok(resp) => {
            let entries = resp.into_inner().entries;
            let result: Vec<serde_json::Value> = entries
                .iter()
                .filter(|e| scoped_keys.as_ref().is_none_or(|ks| ks.contains(&e.key)))
                .map(|e| {
                    let value = redact_if_secret(&e.key, &e.value);
                    serde_json::json!({
                        "key": e.key,
                        "value": value,
                        "updated_at": e.updated_at,
                        "updated_by": e.updated_by,
                        "version": e.version,
                    })
                })
                .collect();
            Json(result).into_response()
        }
        Err(e) => {
            warn!("Failed to list config: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response()
        }
    }
}

/// Get config for a specific section/key
pub async fn admin_get_config(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(section): Path<String>,
) -> Response {
    let caller = extract_caller(&auth, &headers);
    if !is_system_admin(&caller) {
        if !caller.authenticated {
            return (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
        }
        // Tenant admins can read ONLY their own tenant's OIDC config keys.
        let allowed = caller_tenant_oidc_config_keys(&state, &auth, &headers).await;
        if !allowed.contains(&section) {
            return (StatusCode::FORBIDDEN, "System admin access required").into_response();
        }
    }

    let mut client = state.meta_client.clone();
    match client
        .get_config(GetConfigRequest {
            key: section.clone(),
        })
        .await
    {
        Ok(resp) => {
            let resp = resp.into_inner();
            if !resp.found {
                return (StatusCode::NOT_FOUND, "Config not found").into_response();
            }
            if let Some(entry) = resp.entry {
                let value = redact_if_secret(&entry.key, &entry.value);
                let result = serde_json::json!({
                    "key": entry.key,
                    "value": value,
                    "updated_at": entry.updated_at,
                    "updated_by": entry.updated_by,
                    "version": entry.version,
                });
                Json(result).into_response()
            } else {
                (StatusCode::NOT_FOUND, "Config not found").into_response()
            }
        }
        Err(e) => {
            warn!("Failed to get config '{}': {}", section, e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response()
        }
    }
}

/// Set config for a specific section/key
pub async fn admin_set_config(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(section): Path<String>,
    body: Bytes,
) -> Response {
    let caller = extract_caller(&auth, &headers);
    if !is_system_admin(&caller) {
        if !caller.authenticated {
            return (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
        }
        // Tenant admins can manage ONLY their own tenant's OIDC config —
        // they cannot wire a different provider name (which would not be
        // bound to any tenant) or touch non-OIDC config like balancer
        // tuning.
        let allowed = caller_tenant_oidc_config_keys(&state, &auth, &headers).await;
        if !allowed.contains(&section) {
            return (StatusCode::FORBIDDEN, "System admin access required").into_response();
        }
    }

    // Validate JSON
    let Ok(new_value) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return (StatusCode::BAD_REQUEST, "Invalid JSON").into_response();
    };

    if !is_system_admin(&caller)
        && section.starts_with("identity/openid/")
        && (flags_system_admin(&new_value) || is_system_provider(&state, &section).await)
    {
        return (
            StatusCode::FORBIDDEN,
            "Only the system admin may manage a system_admin provider",
        )
            .into_response();
    }

    // Reads redact a provider's client secret to "********". Writing back
    // what was read must keep the real secret, not store the asterisks.
    let mut value = body.to_vec();
    if section.starts_with("identity/openid/")
        && new_value
            .get("client_secret")
            .and_then(serde_json::Value::as_str)
            == Some(REDACTED)
    {
        let existing = state
            .meta_client
            .clone()
            .get_config(GetConfigRequest {
                key: section.clone(),
            })
            .await
            .ok()
            .and_then(|r| r.into_inner().entry)
            .and_then(|e| serde_json::from_slice::<serde_json::Value>(&e.value).ok());
        value = keep_stored_secret(&new_value, existing.as_ref())
            .to_string()
            .into_bytes();
    }

    let updated_by = auth
        .as_ref()
        .map(|Extension(a)| a.user_id.clone())
        .unwrap_or_else(|| "anonymous".to_string());

    let mut client = state.meta_client.clone();
    match client
        .set_config(SetConfigRequest {
            key: section.clone(),
            value,
            updated_by,
        })
        .await
    {
        Ok(resp) => {
            let entry = resp.into_inner().entry;
            info!("Config updated: {}", section);

            // Slug bootstrap: if the caller is a tenant user (not the
            // system admin) and just PUT their tenant's slug-style OIDC
            // key `identity/openid/t-{tenant}`, auto-bind the tenant's
            // `oidc_provider` field to it. This lets a tenant admin
            // create their first OIDC config without needing the system
            // admin to wire it up.
            if !is_system_admin(&caller)
                && let Some((tenant_name, slug_key)) = caller_tenant_slug_key(&auth, &headers)
                && section == slug_key
            {
                let slug = tenant_oidc_slug(&tenant_name);
                if let Ok(t_resp) = client
                    .clone()
                    .get_tenant(GetTenantRequest {
                        name: tenant_name.clone(),
                    })
                    .await
                    && let Some(mut tenant) = t_resp.into_inner().tenant
                    && tenant.oidc_provider != slug
                {
                    tenant.oidc_provider = slug;
                    if let Err(e) = client
                        .update_tenant(UpdateTenantRequest {
                            tenant: Some(tenant),
                        })
                        .await
                    {
                        warn!(
                            "Slug-bound OIDC saved but tenant binding update failed for '{}': {}",
                            tenant_name, e
                        );
                    } else {
                        info!("Auto-bound tenant '{}' to OIDC provider slug", tenant_name);
                    }
                }
            }

            if let Some(entry) = entry {
                let value = redact_if_secret(&entry.key, &entry.value);
                Json(serde_json::json!({
                    "key": entry.key,
                    "value": value,
                    "version": entry.version,
                }))
                .into_response()
            } else {
                StatusCode::OK.into_response()
            }
        }
        Err(e) => {
            warn!("Failed to set config '{}': {}", section, e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response()
        }
    }
}

/// Delete config for a specific section/key
pub async fn admin_delete_config(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(section): Path<String>,
) -> Response {
    let caller = extract_caller(&auth, &headers);
    if !is_system_admin(&caller) {
        if !caller.authenticated {
            return (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
        }
        let allowed = caller_tenant_oidc_config_keys(&state, &auth, &headers).await;
        if !allowed.contains(&section) || is_system_provider(&state, &section).await {
            return (StatusCode::FORBIDDEN, "System admin access required").into_response();
        }
    }

    let mut client = state.meta_client.clone();
    match client
        .delete_config(DeleteConfigRequest {
            key: section.clone(),
        })
        .await
    {
        Ok(resp) => {
            if resp.into_inner().success {
                info!("Config deleted: {}", section);
                StatusCode::NO_CONTENT.into_response()
            } else {
                (StatusCode::NOT_FOUND, "Config not found").into_response()
            }
        }
        Err(e) => {
            warn!("Failed to delete config '{}': {}", section, e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response()
        }
    }
}

/// Identity of the caller, normalized across SigV4 and console session auth.
#[derive(Default, Clone, Debug)]
pub struct CallerIdentity {
    pub user_id: String,
    pub user_arn: String,
    pub tenant: String,
    pub authenticated: bool,
}

/// Pull the caller's identity from either SigV4 auth extension or a valid
/// console session cookie. Returns a default (unauthenticated) identity if
/// neither is present.
pub fn extract_caller(
    auth: &Option<Extension<AuthResult>>,
    headers: &axum::http::HeaderMap,
) -> CallerIdentity {
    // An anonymous request has an identity only to say it has none.
    if let Some(Extension(a)) = auth
        && a.auth_mode != objectio_auth::AuthMode::Anonymous
    {
        return CallerIdentity {
            user_id: a.user_id.clone(),
            user_arn: a.user_arn.clone(),
            tenant: a.tenant.clone(),
            authenticated: true,
        };
    }
    if let Some(s) = crate::console_auth::validate_session_from_headers(headers) {
        return CallerIdentity {
            user_id: s.user,
            user_arn: String::new(),
            tenant: s.tenant,
            authenticated: true,
        };
    }
    CallerIdentity::default()
}

/// Refuse a credential that carries a bucket/prefix scope.
///
/// A scope is a narrowing filter on the *data* path: it can only subtract
/// from what the identity already has. Nothing was applying it to `/_admin/*`,
/// so a scoped key kept every admin right its user had — and since minting an
/// access key is an admin right, a read-only key confined to one bucket could
/// mint itself a fresh unscoped read-write one. That defeats scoping entirely
/// the moment a key is issued from an admin's own user, which is exactly what
/// a provisioner (a CSI driver, say) would do.
///
/// Admin work needs an unscoped credential. This is deliberately a flat
/// refusal rather than a narrowing: there is no meaningful way to apply
/// "confined to s3://ws1/" to "create a tenant".
fn deny_scoped_credential(auth: &Option<Extension<AuthResult>>) -> Option<Response> {
    let Some(Extension(a)) = auth else {
        return None;
    };
    let scoped = a.scope.as_ref().is_some_and(|s| !s.scope.is_empty());
    if scoped {
        return Some(
            (
                StatusCode::FORBIDDEN,
                "This access key is scoped to a bucket or prefix and cannot be \
                 used on the admin API. Use an unscoped credential.",
            )
                .into_response(),
        );
    }
    None
}

pub(crate) const SYSTEM_ADMIN_USER_ARN: &str = "arn:objectio:iam::user/admin";

/// True iff the caller is a system-scope admin. Tenant users (tenant != "")
/// never satisfy this.
///
/// - SigV4 path: requires the canonical admin ARN (strict).
/// - Session path: any authenticated session with an empty tenant scope
///   passes. The session payload does not carry the ARN, so we rely on the
///   invariant that users in the system scope are, by definition,
///   system-scope admins.
pub fn is_system_admin(caller: &CallerIdentity) -> bool {
    if !caller.authenticated {
        return false;
    }
    if !caller.user_arn.is_empty() {
        return caller.user_arn == SYSTEM_ADMIN_USER_ARN;
    }
    caller.tenant.is_empty()
}

/// Check whether the caller is allowed to act as an admin for `target_tenant`:
/// - system admin always passes
/// - else caller.tenant must equal target_tenant AND caller.user_id (or ARN)
///   must be listed in TenantConfig.admin_users.
///
/// Returns `None` on success, or a ready-to-send error response on denial.
pub async fn require_tenant_admin_access(
    state: &AppState,
    auth: &Option<Extension<AuthResult>>,
    headers: &axum::http::HeaderMap,
    target_tenant: &str,
) -> Option<Response> {
    if let Some(deny) = deny_scoped_credential(auth) {
        return Some(deny);
    }
    let caller = extract_caller(auth, headers);
    if !caller.authenticated {
        return Some((StatusCode::UNAUTHORIZED, "Authentication required").into_response());
    }
    if is_system_admin(&caller) {
        return None;
    }
    // Tenant users can only act on their own tenant
    if target_tenant.is_empty() || caller.tenant != target_tenant {
        return Some(
            (
                StatusCode::FORBIDDEN,
                "Not authorized for this tenant scope",
            )
                .into_response(),
        );
    }
    // Consult TenantConfig.admin_users
    let mut client = state.meta_client.clone();
    let tenant = match client
        .get_tenant(GetTenantRequest {
            name: target_tenant.to_string(),
        })
        .await
    {
        Ok(resp) => {
            let r = resp.into_inner();
            if !r.found {
                return Some((StatusCode::FORBIDDEN, "Tenant not found").into_response());
            }
            match r.tenant {
                Some(t) => t,
                None => {
                    return Some((StatusCode::FORBIDDEN, "Tenant not found").into_response());
                }
            }
        }
        Err(_) => {
            return Some(
                (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load tenant").into_response(),
            );
        }
    };
    let is_tenant_admin = tenant
        .admin_users
        .iter()
        .any(|entry| entry == &caller.user_id || entry == &caller.user_arn);
    if is_tenant_admin {
        return None;
    }
    Some((StatusCode::FORBIDDEN, "Not a tenant admin").into_response())
}

/// Validate admin access from either SigV4 auth or console session cookie.
/// This is the "tenant-unaware" gate — passes for system admin or any
/// authenticated session. Tenant-scoped endpoints should prefer
/// [`require_tenant_admin_access`] instead so tenant users cannot touch
/// other tenants.
pub fn require_admin_or_session(
    auth: &Option<Extension<AuthResult>>,
    headers: &axum::http::HeaderMap,
) -> Option<Response> {
    if let Some(deny) = deny_scoped_credential(auth) {
        return Some(deny);
    }
    // If SigV4 auth is present, use it
    if let Some(Extension(auth_result)) = auth {
        if auth_result.user_arn.ends_with("user/admin") {
            return None; // allowed
        }
        return Some((StatusCode::FORBIDDEN, "Admin access required").into_response());
    }

    // Otherwise check for console session cookie
    // Login already validated credentials — any valid session is allowed
    if crate::console_auth::validate_session_from_headers(headers).is_some() {
        return None;
    }

    Some((StatusCode::UNAUTHORIZED, "Authentication required").into_response())
}

/// Gate that only allows the true system admin — used for cluster-wide
/// operations like pool/tenant/node management where tenant admins must
/// never be allowed.
pub fn require_system_admin(
    auth: &Option<Extension<AuthResult>>,
    headers: &axum::http::HeaderMap,
) -> Option<Response> {
    if let Some(deny) = deny_scoped_credential(auth) {
        return Some(deny);
    }
    let caller = extract_caller(auth, headers);
    if !caller.authenticated {
        return Some((StatusCode::UNAUTHORIZED, "Authentication required").into_response());
    }
    if is_system_admin(&caller) {
        return None;
    }
    Some((StatusCode::FORBIDDEN, "System admin access required").into_response())
}

fn flags_system_admin(config: &serde_json::Value) -> bool {
    config
        .get("system_admin")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// Whether the stored provider at `key` vouches for system administrators
/// (console login, STS for system roles). A tenant admin who could edit
/// one would point it at their own IdP and sign in as the operator, so
/// only the system admin may set the flag or touch a provider carrying it.
async fn is_system_provider(state: &AppState, key: &str) -> bool {
    state
        .meta_client
        .clone()
        .get_config(GetConfigRequest {
            key: key.to_string(),
        })
        .await
        .ok()
        .and_then(|r| r.into_inner().entry)
        .and_then(|e| serde_json::from_slice::<serde_json::Value>(&e.value).ok())
        .is_some_and(|v| flags_system_admin(&v))
}

/// Slug-style provider name reserved for a tenant's own OIDC config.
/// Tenant admins can create/manage exactly `identity/openid/{slug}` where
/// slug is `t-{tenant_name}`. The `t-` prefix is a namespace marker so
/// tenant-owned configs can never collide with system-admin-named ones.
fn tenant_oidc_slug(tenant: &str) -> String {
    format!("t-{}", tenant.to_lowercase())
}

/// The OIDC provider config keys the caller is allowed to read/manage when
/// they're a tenant admin (not the system admin). Returns:
///   - the tenant's slug-owned key `identity/openid/t-{tenant}` (always
///     allowed; tenant admin may bootstrap their own provider here), and
///   - the key for `tenant.oidc_provider` if it's set to anything else
///     (so a system-admin-provisioned provider stays visible/manageable
///     by the tenant admin who uses it).
///
/// Returns an empty Vec if the caller is unauthenticated or has no tenant.
async fn caller_tenant_oidc_config_keys(
    state: &AppState,
    auth: &Option<Extension<AuthResult>>,
    headers: &axum::http::HeaderMap,
) -> Vec<String> {
    let caller = extract_caller(auth, headers);
    if !caller.authenticated || caller.tenant.is_empty() {
        return Vec::new();
    }
    let mut keys = vec![format!(
        "identity/openid/{}",
        tenant_oidc_slug(&caller.tenant)
    )];
    if let Ok(resp) = state
        .meta_client
        .clone()
        .get_tenant(GetTenantRequest {
            name: caller.tenant.clone(),
        })
        .await
        && let Some(t) = resp.into_inner().tenant
        && !t.oidc_provider.is_empty()
    {
        let bound = format!("identity/openid/{}", t.oidc_provider);
        if !keys.contains(&bound) {
            keys.push(bound);
        }
    }
    keys
}

/// Tenant slug key for the caller, if they have a tenant scope. Used by
/// `admin_set_config` to detect when the caller just PUT their own slug
/// and auto-bind it to the tenant.
fn caller_tenant_slug_key(
    auth: &Option<Extension<AuthResult>>,
    headers: &axum::http::HeaderMap,
) -> Option<(String, String)> {
    let caller = extract_caller(auth, headers);
    if !caller.authenticated || caller.tenant.is_empty() {
        return None;
    }
    let slug = tenant_oidc_slug(&caller.tenant);
    let key = format!("identity/openid/{slug}");
    Some((caller.tenant, key))
}

/// Extract tenant from SigV4 auth or session cookie. Empty = system admin.
fn extract_tenant(auth: &Option<Extension<AuthResult>>, headers: &axum::http::HeaderMap) -> String {
    auth.as_ref()
        .map(|Extension(a)| a.tenant.clone())
        .or_else(|| crate::console_auth::validate_session_from_headers(headers).map(|s| s.tenant))
        .unwrap_or_default()
}

/// What a stored client secret reads as.
const REDACTED: &str = "********";

/// A provider config written back with its secret as read (redacted): the
/// stored secret in place of the placeholder.
fn keep_stored_secret(
    new: &serde_json::Value,
    stored: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut merged = new.clone();
    merged["client_secret"] = stored
        .and_then(|v| v.get("client_secret").cloned())
        .unwrap_or_else(|| serde_json::Value::String(String::new()));
    merged
}

/// Redact sensitive fields in OIDC config responses
fn redact_if_secret(key: &str, value: &[u8]) -> serde_json::Value {
    let Ok(mut json) = serde_json::from_slice::<serde_json::Value>(value) else {
        // Not valid JSON, return as base64
        return serde_json::Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            value,
        ));
    };

    // Redact secrets in OIDC configs
    if key.starts_with("identity/openid/")
        && let Some(obj) = json.as_object_mut()
        && let Some(secret) = obj.get_mut("client_secret")
        && secret.as_str().is_some_and(|s| !s.is_empty())
    {
        *secret = serde_json::Value::String(REDACTED.to_string());
    }

    json
}

// ============ Server Pools ============

pub async fn admin_list_pools(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let mut client = state.meta_client.clone();
    match client.list_pools(ListPoolsRequest {}).await {
        Ok(resp) => Json(
            resp.into_inner()
                .pools
                .iter()
                .map(pool_to_json)
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response(),
    }
}

pub async fn admin_create_pool(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let pool = json_to_pool(&body);
    let mut client = state.meta_client.clone();
    match client
        .create_pool(CreatePoolRequest { pool: Some(pool) })
        .await
    {
        Ok(resp) => (
            StatusCode::CREATED,
            Json(resp.into_inner().pool.map(|p| pool_to_json(&p))),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

pub async fn admin_get_pool(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let mut client = state.meta_client.clone();
    match client.get_pool(GetPoolRequest { name }).await {
        Ok(resp) => {
            let r = resp.into_inner();
            if r.found {
                Json(r.pool.map(|p| pool_to_json(&p))).into_response()
            } else {
                (StatusCode::NOT_FOUND, "Pool not found").into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response(),
    }
}

/// `GET /_admin/pools/{name}/placement-groups[?start_after=N&max=1000]`
/// — paginated listing of a pool's placement groups with their OSD
/// assignments and current version. Feeds the console's PG view.
pub async fn admin_list_pool_placement_groups(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    use objectio_proto::metadata::ListPlacementGroupsRequest;

    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let start_after: u32 = params
        .get("start_after")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let max_results: u32 = params
        .get("max")
        .and_then(|v| v.parse().ok())
        .unwrap_or(1000);

    let mut client = state.meta_client.clone();
    match client
        .list_placement_groups(ListPlacementGroupsRequest {
            pool: name,
            start_after_pg_id: start_after,
            max_results,
        })
        .await
    {
        Ok(resp) => {
            let r = resp.into_inner();
            let pgs: Vec<serde_json::Value> = r
                .pgs
                .iter()
                .map(|pg| {
                    serde_json::json!({
                        "pool": pg.pool,
                        "pg_id": pg.pg_id,
                        "osd_ids": pg.osd_ids.iter().map(hex::encode).collect::<Vec<_>>(),
                        "version": pg.version,
                        "updated_at": pg.updated_at,
                        "migrating_to_osd_ids": pg
                            .migrating_to_osd_ids
                            .iter()
                            .map(hex::encode)
                            .collect::<Vec<_>>(),
                    })
                })
                .collect();
            Json(serde_json::json!({
                "pgs": pgs,
                "next_pg_id": r.next_pg_id,
            }))
            .into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response(),
    }
}

pub async fn admin_update_pool(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let mut client = state.meta_client.clone();
    // An update changes what it names: the rest is read and kept, so a
    // partial body can't reset the pool's coding or failure domain.
    let existing = match client.get_pool(GetPoolRequest { name: name.clone() }).await {
        Ok(r) => match r.into_inner() {
            r if r.found => r.pool,
            _ => None,
        },
        Err(e) => return (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    };
    let Some(existing) = existing else {
        return (StatusCode::NOT_FOUND, "Pool not found").into_response();
    };
    let mut pool = json_to_pool(&overlay(pool_to_json(&existing), &body));
    pool.name = name;
    pool.created_at = existing.created_at;
    match client
        .update_pool(UpdatePoolRequest { pool: Some(pool) })
        .await
    {
        Ok(resp) => Json(resp.into_inner().pool.map(|p| pool_to_json(&p))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

pub async fn admin_delete_pool(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let mut client = state.meta_client.clone();
    match client.delete_pool(DeletePoolRequest { name }).await {
        Ok(resp) => {
            if resp.into_inner().success {
                StatusCode::NO_CONTENT.into_response()
            } else {
                (StatusCode::NOT_FOUND, "Pool not found").into_response()
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

// ============ Tenants ============

pub async fn admin_list_tenants(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    // System admin sees all tenants. A tenant admin (or any tenant user)
    // sees only their own tenant — this endpoint powers the console's
    // tenant picker.
    let caller = extract_caller(&auth, &headers);
    if !caller.authenticated {
        return (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
    }
    let mut client = state.meta_client.clone();
    match client.list_tenants(ListTenantsRequest {}).await {
        Ok(resp) => {
            let mut tenants = resp.into_inner().tenants;
            if !is_system_admin(&caller) {
                tenants.retain(|t| t.name == caller.tenant);
            }
            Json(tenants.iter().map(tenant_to_json).collect::<Vec<_>>()).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response(),
    }
}

pub async fn admin_create_tenant(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    if let Some(e) = tenant_dedup_error(&body) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }
    let tenant = json_to_tenant(&body);
    let mut client = state.meta_client.clone();
    match client
        .create_tenant(CreateTenantRequest {
            tenant: Some(tenant),
        })
        .await
    {
        Ok(resp) => (
            StatusCode::CREATED,
            Json(resp.into_inner().tenant.map(|t| tenant_to_json(&t))),
        )
            .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

pub async fn admin_get_tenant(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    // Tenant admins can read their own tenant's config; anyone else
    // (including tenant admins targeting a different tenant) must be
    // system admin.
    let caller = extract_caller(&auth, &headers);
    if !caller.authenticated {
        return (StatusCode::UNAUTHORIZED, "Authentication required").into_response();
    }
    if !is_system_admin(&caller) && caller.tenant != name {
        return (StatusCode::FORBIDDEN, "Not authorized for this tenant").into_response();
    }
    let mut client = state.meta_client.clone();
    match client.get_tenant(GetTenantRequest { name }).await {
        Ok(resp) => {
            let r = resp.into_inner();
            if r.found {
                Json(r.tenant.map(|t| tenant_to_json(&t))).into_response()
            } else {
                (StatusCode::NOT_FOUND, "Tenant not found").into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response(),
    }
}

pub async fn admin_update_tenant(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    if let Some(e) = tenant_dedup_error(&body) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }
    let mut client = state.meta_client.clone();
    // An update changes what it names: the rest is read and kept, so a
    // partial body can't clear the tenant's admins, quotas or labels.
    let existing = match client
        .get_tenant(GetTenantRequest { name: name.clone() })
        .await
    {
        Ok(r) => match r.into_inner() {
            r if r.found => r.tenant,
            _ => None,
        },
        Err(e) => return (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    };
    let Some(existing) = existing else {
        return (StatusCode::NOT_FOUND, "Tenant not found").into_response();
    };
    let mut tenant = json_to_tenant(&overlay(tenant_to_json(&existing), &body));
    tenant.name = name;
    tenant.created_at = existing.created_at;
    match client
        .update_tenant(UpdateTenantRequest {
            tenant: Some(tenant),
        })
        .await
    {
        Ok(resp) => Json(resp.into_inner().tenant.map(|t| tenant_to_json(&t))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

pub async fn admin_delete_tenant(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let mut client = state.meta_client.clone();
    match client.delete_tenant(DeleteTenantRequest { name }).await {
        Ok(resp) => {
            if resp.into_inner().success {
                StatusCode::NO_CONTENT.into_response()
            } else {
                (StatusCode::NOT_FOUND, "Tenant not found").into_response()
            }
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

// ============================================================================
// Tenant admin_users management (system admin only)
// ============================================================================

/// POST /_admin/tenants/{name}/admins  body: {"user_id": "..."} or {"user_arn": "..."}
///
/// Adds a user to this tenant's admin list. Either user_id (UUID) or
/// user_arn may be provided; both are accepted going forward by the
/// tenant-admin gate, so either works.
pub async fn admin_add_tenant_admin(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let entry = body["user_id"]
        .as_str()
        .or_else(|| body["user_arn"].as_str())
        .unwrap_or_default()
        .to_string();
    if entry.is_empty() {
        return (StatusCode::BAD_REQUEST, "user_id or user_arn required").into_response();
    }

    let mut client = state.meta_client.clone();
    let Some(mut tenant) = get_tenant_or_404(&mut client, &name).await else {
        return (StatusCode::NOT_FOUND, "Tenant not found").into_response();
    };
    if !tenant.admin_users.iter().any(|u| u == &entry) {
        tenant.admin_users.push(entry);
    }
    match client
        .update_tenant(UpdateTenantRequest {
            tenant: Some(tenant),
        })
        .await
    {
        Ok(resp) => Json(resp.into_inner().tenant.map(|t| tenant_to_json(&t))).into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

/// DELETE /_admin/tenants/{name}/admins/{user}
///
/// Removes an entry from the tenant admin list. The path segment is matched
/// exactly against stored entries (so pass the same format used when adding).
pub async fn admin_remove_tenant_admin(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path((name, user)): Path<(String, String)>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let mut client = state.meta_client.clone();
    let Some(mut tenant) = get_tenant_or_404(&mut client, &name).await else {
        return (StatusCode::NOT_FOUND, "Tenant not found").into_response();
    };
    let before = tenant.admin_users.len();
    tenant.admin_users.retain(|u| u != &user);
    if tenant.admin_users.len() == before {
        return (StatusCode::NOT_FOUND, "Admin entry not found").into_response();
    }
    match client
        .update_tenant(UpdateTenantRequest {
            tenant: Some(tenant),
        })
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

async fn get_tenant_or_404(
    client: &mut objectio_proto::metadata::metadata_service_client::MetadataServiceClient<
        tonic::transport::Channel,
    >,
    name: &str,
) -> Option<TenantConfig> {
    client
        .get_tenant(GetTenantRequest {
            name: name.to_string(),
        })
        .await
        .ok()
        .and_then(|r| {
            let r = r.into_inner();
            if r.found { r.tenant } else { None }
        })
}

/// Look up the tenant owning a bucket. Empty string = system-scope bucket.
/// Returns None if the bucket does not exist.
async fn lookup_bucket_tenant(state: &AppState, bucket: &str) -> Option<String> {
    let mut client = state.meta_client.clone();
    let resp = client
        .get_bucket(objectio_proto::metadata::GetBucketRequest {
            name: bucket.to_string(),
        })
        .await
        .ok()?
        .into_inner();
    resp.bucket.map(|b| b.tenant)
}

/// Look up a user's tenant. Returns None if the user does not exist.
async fn lookup_user_tenant(state: &AppState, user_id: &str) -> Option<String> {
    let mut client = state.meta_client.clone();
    let resp = client
        .get_user(objectio_proto::metadata::GetUserRequest {
            user_id: user_id.to_string(),
        })
        .await
        .ok()?
        .into_inner();
    resp.user.map(|u| u.tenant)
}

/// Gate a request on the tenant that owns `user_id`.
async fn require_user_tenant_admin(
    state: &AppState,
    auth: &Option<Extension<AuthResult>>,
    headers: &HeaderMap,
    user_id: &str,
) -> Option<Response> {
    let tenant = match lookup_user_tenant(state, user_id).await {
        Some(t) => t,
        None => return Some((StatusCode::NOT_FOUND, "User not found").into_response()),
    };
    if tenant.is_empty() {
        require_system_admin(auth, headers)
    } else {
        require_tenant_admin_access(state, auth, headers, &tenant).await
    }
}

/// Gate a request on the tenant that owns `bucket`. System admin passes for
/// any bucket; tenant admins only for buckets in their own tenant.
async fn require_bucket_tenant_admin(
    state: &AppState,
    auth: &Option<Extension<AuthResult>>,
    headers: &HeaderMap,
    bucket: &str,
) -> Option<Response> {
    let tenant = match lookup_bucket_tenant(state, bucket).await {
        Some(t) => t,
        None => return Some((StatusCode::NOT_FOUND, "Bucket not found").into_response()),
    };
    if tenant.is_empty() {
        require_system_admin(auth, headers)
    } else {
        require_tenant_admin_access(state, auth, headers, &tenant).await
    }
}

// ============================================================================
// Buckets (admin API — bypasses SigV4 for console)
// ============================================================================

pub async fn admin_list_buckets(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    let tenant = extract_tenant(&auth, &headers);
    // Like the user listing, this already scopes its query to the caller's
    // tenant but was gated on the root key alone — so a tenant admin could
    // create a bucket and never see it again. A provisioner that cannot list
    // what it made cannot reconcile, which is most of what a provisioner does.
    if tenant.is_empty() {
        if let Some(deny) = require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) = require_tenant_admin_access(&state, &auth, &headers, &tenant).await {
        return deny;
    }

    let mut client = state.meta_client.clone();
    match client
        .list_buckets(objectio_proto::metadata::ListBucketsRequest {
            owner: String::new(),
            tenant,
        })
        .await
    {
        Ok(resp) => {
            let buckets: Vec<serde_json::Value> = resp
                .into_inner()
                .buckets
                .iter()
                .map(|b| {
                    serde_json::json!({
                        "name": b.name,
                        "created_at": b.created_at,
                        "owner": b.owner,
                        "versioning": b.versioning,
                        "pool": b.pool,
                        "tenant": b.tenant,
                    })
                })
                .collect();
            Json(serde_json::json!({ "buckets": buckets })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response(),
    }
}

pub async fn admin_create_bucket(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let name = body["name"].as_str().unwrap_or_default().to_string();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    // Note: no capacity gate here. Creating a bucket is a logical carve-out
    // of existing capacity, not an addition of physical storage. Raw-capacity
    // enforcement lives at meta's RegisterOsd path where new disks actually
    // grow the cluster's footprint.
    // Default to caller's tenant; body may override (system admin only).
    let caller_tenant = extract_tenant(&auth, &headers);
    let body_tenant = body["tenant"].as_str().unwrap_or_default().to_string();
    let tenant = if body_tenant.is_empty() {
        caller_tenant
    } else {
        body_tenant
    };
    if tenant.is_empty() {
        if let Some(deny) = require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) = require_tenant_admin_access(&state, &auth, &headers, &tenant).await {
        return deny;
    }
    let mut client = state.meta_client.clone();
    match client
        .create_bucket(objectio_proto::metadata::CreateBucketRequest {
            name: name.clone(),
            // The creator, not the literal string "admin". Authorization
            // falls back to ownership when no policy speaks, and it compares
            // against `user_id` — so a hardcoded "admin" matched nobody and
            // left every console-created bucket reachable only by the root
            // key, whatever policy its tenant admin attached. The S3
            // CreateBucket path has recorded the real creator since
            // ownership was introduced; this one was missed.
            owner: extract_caller(&auth, &headers).user_id,
            storage_class: "STANDARD".to_string(),
            region: String::new(),
            tenant,
            settings: crate::public_access::initial_settings(&state).await,
            pool: body["pool"].as_str().unwrap_or_default().to_string(),
        })
        .await
    {
        Ok(r) => Json(serde_json::json!({
            "name": name,
            "pool": r.into_inner().bucket.map(|b| b.pool).unwrap_or_default(),
        }))
        .into_response(),
        Err(e) => {
            let status = match e.code() {
                tonic::Code::PermissionDenied => StatusCode::FORBIDDEN,
                tonic::Code::AlreadyExists => StatusCode::CONFLICT,
                _ => StatusCode::BAD_REQUEST,
            };
            (status, e.message().to_string()).into_response()
        }
    }
}

pub async fn admin_delete_bucket(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    // Resolve bucket → tenant so tenant admins cannot drop other tenants'
    // buckets.
    let mut client = state.meta_client.clone();
    let tenant = match client
        .get_bucket(objectio_proto::metadata::GetBucketRequest { name: name.clone() })
        .await
    {
        Ok(resp) => resp
            .into_inner()
            .bucket
            .map(|b| b.tenant)
            .unwrap_or_default(),
        Err(_) => return (StatusCode::NOT_FOUND, "Bucket not found").into_response(),
    };
    if tenant.is_empty() {
        if let Some(deny) = require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) = require_tenant_admin_access(&state, &auth, &headers, &tenant).await {
        return deny;
    }
    // Refuse a bucket that still holds objects, as S3 does.
    //
    // This used to drop the bucket regardless, without deleting the objects
    // in it — so every one of their shards was orphaned on the platter with
    // nothing left to point at them. It is the same leak that filled this
    // deployment's disk, reached by a different route, and it survived the
    // fix to the object-delete path because it never went through it.
    //
    // Refusing rather than cascading: a bucket delete that silently removes
    // an unknown quantity of data is the wrong default for an operator API,
    // and a caller that wants it gone can list and delete, which now
    // reclaims correctly.
    match state
        .scatter_gather
        .list_objects(&mut client.clone(), &name, "", 1, None, "")
        .await
    {
        Ok(result) if result.objects.iter().any(|o| !o.is_delete_marker) => {
            return (
                StatusCode::CONFLICT,
                format!("bucket '{name}' is not empty: delete its objects first"),
            )
                .into_response();
        }
        Ok(_) => {}
        Err(e) => {
            // Cannot prove it is empty, so do not destroy it.
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("could not check whether '{name}' is empty: {e}"),
            )
                .into_response();
        }
    }

    match client
        .delete_bucket(objectio_proto::metadata::DeleteBucketRequest { name })
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

// Bucket policy management
// ============================================================================

pub async fn admin_get_bucket_policy(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(bucket): Path<String>,
) -> Response {
    if let Some(deny) = require_bucket_tenant_admin(&state, &auth, &headers, &bucket).await {
        return deny;
    }
    let mut client = state.meta_client.clone();
    match client
        .get_bucket_policy(objectio_proto::metadata::GetBucketPolicyRequest {
            bucket: bucket.clone(),
        })
        .await
    {
        Ok(resp) => {
            let inner = resp.into_inner();
            if inner.has_policy {
                Json(serde_json::json!({
                    "has_policy": true,
                    "policy": serde_json::from_str::<serde_json::Value>(&inner.policy_json).unwrap_or_default(),
                }))
                .into_response()
            } else {
                Json(serde_json::json!({ "has_policy": false, "policy": null })).into_response()
            }
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response(),
    }
}

pub async fn admin_put_bucket_policy(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(bucket): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    if let Some(deny) = require_bucket_tenant_admin(&state, &auth, &headers, &bucket).await {
        return deny;
    }
    // The same path as S3's PutBucketPolicy: the document checked as
    // authorization will read it, Block Public Access applied, caches
    // dropped. This endpoint used to store any JSON, public or not.
    crate::s3::put_bucket_policy_internal(state, bucket, body).await
}

pub async fn admin_delete_bucket_policy(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(bucket): Path<String>,
) -> Response {
    if let Some(deny) = require_bucket_tenant_admin(&state, &auth, &headers, &bucket).await {
        return deny;
    }
    crate::s3::delete_bucket_policy_internal(state, bucket).await
}

// ============================================================================
/// `PUT /_admin/buckets/{bucket}/owner` — reassign a bucket's owner.
///
/// Body: `{"owner": "<user_id>"}`.
///
/// Gated per-bucket: the system admin may re-home any bucket, a tenant admin
/// only buckets in their own tenant. Buckets with no tenant stay system-admin
/// only. This matches the other bucket admin endpoints, and without it a
/// tenant admin cannot re-home a bucket whose owner has left — leaving it
/// owned by a departed account with the operator as the only recourse.
pub async fn admin_set_bucket_owner(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(bucket): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(deny) = require_bucket_tenant_admin(&state, &auth, &headers, &bucket).await {
        return deny;
    }
    let owner = body["owner"].as_str().unwrap_or_default().to_string();
    if owner.is_empty() {
        return (StatusCode::BAD_REQUEST, "owner must not be empty").into_response();
    }

    // A bucket in a tenant must be owned by someone in that tenant. The
    // authorization chain denies on tenant mismatch before it ever reaches the
    // ownership check, so a cross-tenant owner would be unable to open their
    // own bucket — an unreachable bucket rather than a useful handover.
    let bucket_tenant = lookup_bucket_tenant(&state, &bucket)
        .await
        .unwrap_or_default();
    if !bucket_tenant.is_empty() {
        match lookup_user_tenant(&state, &owner).await {
            None => return (StatusCode::BAD_REQUEST, "owner user not found").into_response(),
            Some(t) if t != bucket_tenant => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "owner is in tenant '{t}' but bucket '{bucket}' is in tenant '{bucket_tenant}'; the owner would not be able to access it"
                    ),
                )
                    .into_response();
            }
            Some(_) => {}
        }
    }

    let mut client = state.meta_client.clone();
    match client
        .set_bucket_owner(objectio_proto::metadata::SetBucketOwnerRequest {
            bucket: bucket.clone(),
            owner: owner.clone(),
        })
        .await
    {
        Ok(_) => {
            // The chain caches bucket owner alongside bucket policy.
            state.policy_cache.invalidate(&bucket);
            tracing::info!("Set owner of bucket '{bucket}' to '{owner}'");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) if e.code() == tonic::Code::NotFound => {
            (StatusCode::NOT_FOUND, e.message().to_string()).into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

/// Query params for admin object listing
#[derive(Debug, serde::Deserialize)]
pub struct AdminListObjectsParams {
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub delimiter: String,
    #[serde(rename = "max-keys", default)]
    pub max_keys: Option<u32>,
}

pub async fn admin_list_objects(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(bucket): Path<String>,
    Query(params): Query<AdminListObjectsParams>,
) -> Response {
    if let Some(deny) = require_bucket_tenant_admin(&state, &auth, &headers, &bucket).await {
        return deny;
    }

    let max_keys = params.max_keys.unwrap_or(1000);
    let mut meta_client = state.meta_client.clone();

    // Use the scatter-gather engine (same as the S3 list_objects handler)
    let all_objects = match state
        .scatter_gather
        .list_objects(
            &mut meta_client,
            &bucket,
            &params.prefix,
            max_keys,
            None,
            "",
        )
        .await
    {
        Ok(result) => result.objects,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to list objects: {e}"),
            )
                .into_response();
        }
    };

    // Apply delimiter to split into objects and common prefixes
    let delimiter = if params.delimiter.is_empty() {
        None
    } else {
        Some(params.delimiter.as_str())
    };
    let prefix_str = &params.prefix;

    let mut contents = Vec::new();
    let mut common_prefixes = std::collections::BTreeSet::new();

    for obj in &all_objects {
        if obj.is_delete_marker {
            continue;
        }
        if let Some(delim) = delimiter
            && obj.key.len() > prefix_str.len()
        {
            let after_prefix = &obj.key[prefix_str.len()..];
            if let Some(pos) = after_prefix.find(delim) {
                let cp = format!("{}{}", prefix_str, &after_prefix[..=pos]);
                common_prefixes.insert(cp);
                continue;
            }
        }
        contents.push(serde_json::json!({
            "key": obj.key,
            "size": obj.size,
            "etag": obj.etag,
            "last_modified": obj.modified_at,
        }));
        if contents.len() >= max_keys as usize {
            break;
        }
    }

    Json(serde_json::json!({
        "contents": contents,
        "common_prefixes": common_prefixes.into_iter().collect::<Vec<_>>(),
        "prefix": params.prefix,
    }))
    .into_response()
}

#[derive(Debug, serde::Deserialize)]
pub struct AdminObjectParams {
    #[serde(rename = "versionId", default)]
    pub version_id: Option<String>,
}

/// Upload an object from the console.
///
/// The S3 path (`PUT /{bucket}/{key}`) is signed with SigV4, and the console
/// holds a session cookie rather than a key pair — so without this the browser
/// would have to be handed a live access key to put a single file. This runs
/// the same handler behind the same tenant-admin check as the rest of
/// `/_admin/*`, which keeps the credential where it belongs.
///
/// A key ending in `/` with an empty body is how the object browser makes a
/// folder: there are no directories to create, only a zero-byte marker that
/// makes an empty prefix visible to a delimiter listing.
pub async fn admin_put_object(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if let Some(deny) = require_bucket_tenant_admin(&state, &auth, &headers, &bucket).await {
        return deny;
    }
    if key.is_empty() {
        return (StatusCode::BAD_REQUEST, "object key is required").into_response();
    }
    crate::s3::put_object(State(state), Path((bucket, key)), auth, headers, body).await
}

/// Delete one object from the console. `?versionId=` targets a single version.
pub async fn admin_delete_object(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
    Query(params): Query<AdminObjectParams>,
) -> Response {
    if let Some(deny) = require_bucket_tenant_admin(&state, &auth, &headers, &bucket).await {
        return deny;
    }
    crate::s3::delete_object(
        State(state),
        Path((bucket, key)),
        auth,
        params.version_id,
        headers,
    )
    .await
}

/// Download an object from the console.
///
/// Forces `Content-Disposition: attachment` so a click saves the file instead
/// of navigating the console away to render it — an HTML object would
/// otherwise load as a page on the console's own origin.
pub async fn admin_get_object(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    if let Some(deny) = require_bucket_tenant_admin(&state, &auth, &headers, &bucket).await {
        return deny;
    }
    let filename = key.rsplit('/').next().unwrap_or(&key).to_string();
    let mut resp = crate::s3::get_object(State(state), Path((bucket, key)), auth, headers).await;
    if resp.status().is_success()
        && let Ok(v) = axum::http::HeaderValue::from_str(&format!(
            "attachment; filename=\"{}\"",
            filename.replace('"', "")
        ))
    {
        resp.headers_mut()
            .insert(axum::http::header::CONTENT_DISPOSITION, v);
    }
    resp
}

// ============================================================================
// Warehouses
// ============================================================================

pub async fn admin_list_warehouses(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_admin_or_session(&auth, &headers) {
        return deny;
    }
    let tenant = extract_tenant(&auth, &headers);
    let mut client = state.meta_client.clone();
    match client
        .iceberg_list_warehouses(objectio_proto::metadata::IcebergListWarehousesRequest { tenant })
        .await
    {
        Ok(resp) => {
            let warehouses: Vec<serde_json::Value> = resp
                .into_inner()
                .warehouses
                .iter()
                .map(|w| {
                    serde_json::json!({
                        "name": w.name,
                        "bucket": w.bucket,
                        "location": w.location,
                        "tenant": w.tenant,
                        "created_at": w.created_at,
                        "properties": w.properties,
                    })
                })
                .collect();
            Json(serde_json::json!({ "warehouses": warehouses })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response(),
    }
}

pub async fn admin_create_warehouse(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let name = body["name"].as_str().unwrap_or_default().to_string();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    // Use caller tenant if body leaves it empty. Tenant admins can only
    // create warehouses inside their tenant; system admin can target any.
    let tenant = {
        let body_tenant = body["tenant"].as_str().unwrap_or_default().to_string();
        if body_tenant.is_empty() {
            extract_tenant(&auth, &headers)
        } else {
            body_tenant
        }
    };
    if tenant.is_empty() {
        if let Some(deny) = require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) = require_tenant_admin_access(&state, &auth, &headers, &tenant).await {
        return deny;
    }
    let properties: std::collections::HashMap<String, String> = body["properties"]
        .as_object()
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let mut client = state.meta_client.clone();
    match client
        .iceberg_create_warehouse(objectio_proto::metadata::IcebergCreateWarehouseRequest {
            name,
            tenant,
            properties,
        })
        .await
    {
        Ok(resp) => {
            let wh = resp.into_inner().warehouse.unwrap_or_default();
            Json(serde_json::json!({
                "name": wh.name,
                "bucket": wh.bucket,
                "location": wh.location,
                "tenant": wh.tenant,
                "created_at": wh.created_at,
            }))
            .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

pub async fn admin_delete_warehouse(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    // Find the warehouse via a system-wide list to discover its tenant so we
    // can gate the delete properly. There is no dedicated Get RPC yet.
    let mut client = state.meta_client.clone();
    let tenant = match client
        .iceberg_list_warehouses(objectio_proto::metadata::IcebergListWarehousesRequest {
            tenant: String::new(),
        })
        .await
    {
        Ok(resp) => resp
            .into_inner()
            .warehouses
            .into_iter()
            .find(|w| w.name == name)
            .map(|w| w.tenant)
            .unwrap_or_default(),
        Err(_) => return (StatusCode::NOT_FOUND, "Warehouse not found").into_response(),
    };
    if tenant.is_empty() {
        if let Some(deny) = require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) = require_tenant_admin_access(&state, &auth, &headers, &tenant).await {
        return deny;
    }
    match client
        .iceberg_delete_warehouse(objectio_proto::metadata::IcebergDeleteWarehouseRequest { name })
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

// ============================================================================
// IAM Policies (PBAC)
// ============================================================================

// ============================================================================
// Table Sharing (tenant-aware wrappers)
// ============================================================================

pub async fn admin_list_shares_tenant(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_admin_or_session(&auth, &headers) {
        return deny;
    }
    let tenant = extract_tenant(&auth, &headers);
    let mut client = state.meta_client.clone();
    match client
        .delta_list_shares(objectio_proto::metadata::DeltaListSharesRequest {
            max_results: 0,
            page_token: String::new(),
            tenant,
        })
        .await
    {
        Ok(resp) => {
            let shares: Vec<serde_json::Value> = resp
                .into_inner()
                .shares
                .iter()
                .map(|s| {
                    serde_json::json!({
                        "name": s.name,
                        "comment": s.comment,
                        "tenant": s.tenant,
                    })
                })
                .collect();
            Json(serde_json::json!({ "shares": shares })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response(),
    }
}

pub async fn admin_create_share_tenant(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let name = body["name"].as_str().unwrap_or_default().to_string();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    let tenant = {
        let body_tenant = body["tenant"].as_str().unwrap_or_default().to_string();
        if body_tenant.is_empty() {
            extract_tenant(&auth, &headers)
        } else {
            body_tenant
        }
    };
    if tenant.is_empty() {
        if let Some(deny) = require_system_admin(&auth, &headers) {
            return deny;
        }
    } else if let Some(deny) = require_tenant_admin_access(&state, &auth, &headers, &tenant).await {
        return deny;
    }
    let mut client = state.meta_client.clone();
    match client
        .delta_create_share(objectio_proto::metadata::DeltaCreateShareRequest {
            name: name.clone(),
            comment: body["comment"].as_str().unwrap_or_default().to_string(),
            tenant,
        })
        .await
    {
        Ok(resp) => {
            let s = resp.into_inner().share.unwrap_or_default();
            Json(serde_json::json!({ "name": s.name, "comment": s.comment, "tenant": s.tenant }))
                .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

pub async fn admin_list_recipients_tenant(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_admin_or_session(&auth, &headers) {
        return deny;
    }
    let tenant = extract_tenant(&auth, &headers);
    let mut client = state.meta_client.clone();
    // List all recipients, then filter by shares that belong to tenant's shares
    match client
        .delta_list_recipients(objectio_proto::metadata::DeltaListRecipientsRequest {
            max_results: 0,
            page_token: String::new(),
        })
        .await
    {
        Ok(resp) => {
            let mut recipients: Vec<serde_json::Value> = resp
                .into_inner()
                .recipients
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "shares": r.shares,
                    })
                })
                .collect();
            // If tenant user, filter recipients to only show those with access to tenant's shares
            if !tenant.is_empty()
                && let Ok(shares_resp) = client
                    .delta_list_shares(objectio_proto::metadata::DeltaListSharesRequest {
                        max_results: 0,
                        page_token: String::new(),
                        tenant: tenant.clone(),
                    })
                    .await
            {
                let tenant_shares: std::collections::HashSet<String> = shares_resp
                    .into_inner()
                    .shares
                    .iter()
                    .map(|s| s.name.clone())
                    .collect();
                recipients.retain(|r| {
                    r["shares"].as_array().is_some_and(|arr| {
                        arr.iter()
                            .any(|s| tenant_shares.contains(s.as_str().unwrap_or("")))
                    })
                });
            }
            Json(serde_json::json!({ "recipients": recipients })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response(),
    }
}

// ============================================================================
// Nodes / Drives
// ============================================================================

pub async fn admin_list_nodes(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }

    let mut meta = state.meta_client.clone();
    // Admin UI needs every OSD including operator-disabled ones so it
    // can render Mark Out state and let the operator flip it back.
    let nodes = match meta
        .get_listing_nodes(GetListingNodesRequest {
            bucket: String::new(),
            include_all_states: true,
        })
        .await
    {
        Ok(resp) => resp.into_inner().nodes,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response();
        }
    };

    // Deduplicate by address (scatter-gather may return dupes for different shards)
    let mut seen = std::collections::HashSet::new();
    let mut unique_addrs: Vec<(String, Vec<u8>, i32)> = Vec::new();
    for node in &nodes {
        if seen.insert(node.address.clone()) {
            unique_addrs.push((node.address.clone(), node.node_id.clone(), node.admin_state));
        }
    }

    let mut result = Vec::new();

    for (addr, node_id, admin_state_i32) in &unique_addrs {
        let admin_state_str = admin_state_label(*admin_state_i32);
        let osd_addr = if addr.starts_with("http") {
            addr.clone()
        } else {
            format!("http://{addr}")
        };
        let status = match StorageServiceClient::connect(osd_addr).await {
            Ok(mut client) => {
                match client
                    .get_status(objectio_proto::storage::GetStatusRequest::default())
                    .await
                {
                    Ok(resp) => {
                        let s = resp.into_inner();
                        let disks: Vec<serde_json::Value> = s
                            .disks
                            .iter()
                            .map(|d| {
                                serde_json::json!({
                                    "disk_id": hex::encode(&d.disk_id),
                                    "path": d.path,
                                    "total_capacity": d.total_capacity,
                                    "used_capacity": d.used_capacity,
                                    "status": d.status,
                                    "shard_count": d.shard_count,
                                })
                            })
                            .collect();
                        serde_json::json!({
                            "node_id": hex::encode(node_id),
                            "node_name": s.node_name,
                            "address": addr,
                            "total_capacity": s.total_capacity,
                            "used_capacity": s.used_capacity,
                            "shard_count": s.shard_count,
                            "uptime_seconds": s.uptime_seconds,
                            "disks": disks,
                            "online": true,
                            "kubernetes_node": s.kubernetes_node,
                            "pod_name": s.pod_name,
                            "hostname": s.hostname,
                            "os_info": s.os_info,
                            "cpu_cores": s.cpu_cores,
                            "memory_bytes": s.memory_bytes,
                            "version": s.version,
                            "admin_state": admin_state_str,
                        })
                    }
                    Err(_) => {
                        let mut n = offline_node(node_id, addr);
                        n["admin_state"] = serde_json::Value::String(admin_state_str.into());
                        n
                    }
                }
            }
            Err(_) => {
                let mut n = offline_node(node_id, addr);
                n["admin_state"] = serde_json::Value::String(admin_state_str.into());
                n
            }
        };
        result.push(status);
    }

    Json(serde_json::json!({ "nodes": result })).into_response()
}

/// Wire enum i32 → lowercase label consumed by the console. Unknown
/// values fall back to "in" — conservative, preserves placement.
fn admin_state_label(s: i32) -> &'static str {
    match ProtoOsdAdminState::try_from(s) {
        Ok(ProtoOsdAdminState::OsdAdminIn) => "in",
        Ok(ProtoOsdAdminState::OsdAdminOut) => "out",
        Ok(ProtoOsdAdminState::OsdAdminDraining) => "draining",
        Err(_) => "in",
    }
}

/// `PUT /_admin/osds/{node_id}/admin-state`
///
/// Flip the operator-declared state of an OSD (In / Out / Draining).
/// Routes through the meta's Raft — non-leader meta returns a forward
/// hint the gateway surfaces as a 503; console retries.
///
/// Body: `{"state":"in"|"out"|"draining"}`
#[derive(Debug, serde::Deserialize)]
pub struct AdminStatePayload {
    pub state: String,
}

pub async fn admin_set_osd_state(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    axum::extract::Path(node_id_hex): axum::extract::Path<String>,
    Json(body): Json<AdminStatePayload>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }

    // Parse 32-char hex → 16 raw bytes.
    let node_id_bytes = match hex::decode(&node_id_hex) {
        Ok(b) if b.len() == 16 => b,
        Ok(_) => {
            return (
                StatusCode::BAD_REQUEST,
                "node_id must be 32 hex chars (16 bytes)",
            )
                .into_response();
        }
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "node_id must be valid hex").into_response();
        }
    };

    let wire_state = match body.state.to_ascii_lowercase().as_str() {
        "in" => ProtoOsdAdminState::OsdAdminIn,
        "out" => ProtoOsdAdminState::OsdAdminOut,
        "draining" => ProtoOsdAdminState::OsdAdminDraining,
        other => {
            return (
                StatusCode::BAD_REQUEST,
                format!("unknown state: {other} (expected in | out | draining)"),
            )
                .into_response();
        }
    };

    // Attribute the change to the authenticated user when possible so
    // the audit log reads right; fall back to "console" when the noauth
    // path is in use.
    let requested_by = match &auth {
        Some(Extension(a)) => a.user_id.clone(),
        None => "console".to_string(),
    };

    let mut meta = state.meta_client.clone();
    let resp = meta
        .set_osd_admin_state(SetOsdAdminStateRequest {
            node_id: node_id_bytes,
            state: wire_state as i32,
            requested_by,
        })
        .await;

    match resp {
        Ok(r) => {
            let r = r.into_inner();
            Json(serde_json::json!({
                "found": r.found,
                "changed": r.changed,
                "state": body.state.to_ascii_lowercase(),
            }))
            .into_response()
        }
        Err(e) => {
            // FailedPrecondition from meta means Raft isn't the leader
            // or is not initialised; surface as 503 so the console can
            // retry rather than treating it as a permanent error.
            let code = if e.code() == tonic::Code::FailedPrecondition {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (code, e.message().to_string()).into_response()
        }
    }
}

// ============================================================================
// Host lifecycle — /_admin/hosts (Add Host) and /_admin/osds/{id}/reboot
// ============================================================================

/// Map a `HostProviderError` to an axum `Response` with the right
/// HTTP status. Unsupported → 501, InvalidRequest → 400,
/// Unavailable → 503, Other → 500. Shared by every host endpoint.
fn host_provider_error_to_response(e: crate::host_provider::HostProviderError) -> Response {
    use crate::host_provider::HostProviderError;
    let (code, msg) = match e {
        HostProviderError::Unsupported(m) => (StatusCode::NOT_IMPLEMENTED, m.to_string()),
        HostProviderError::InvalidRequest(m) => (StatusCode::BAD_REQUEST, m),
        HostProviderError::Unavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
        HostProviderError::Other(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
    };
    (code, msg).into_response()
}

/// `POST /_admin/hosts`
///
/// Body: `{"count": N}` (N ≥ 1; default 1 if missing).
///
/// Asks the configured host provider to add N more OSD hosts. On k8s
/// this scales the OSD StatefulSet; each new pod self-registers
/// against meta when it comes up.
#[derive(Debug, serde::Deserialize, Default)]
pub struct AddHostPayload {
    #[serde(default = "AddHostPayload::default_count")]
    pub count: i32,
}

impl AddHostPayload {
    const fn default_count() -> i32 {
        1
    }
}

pub async fn admin_add_hosts(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    body: Option<Json<AddHostPayload>>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let payload = body.map(|Json(p)| p).unwrap_or_default();
    match state.host_provider.add_hosts(payload.count).await {
        Ok(outcome) => Json(serde_json::json!({
            "provider": state.host_provider.name(),
            "previous_replicas": outcome.previous_replicas,
            "new_replicas": outcome.new_replicas,
            "pods_added": outcome.pods_added,
        }))
        .into_response(),
        Err(e) => host_provider_error_to_response(e),
    }
}

/// `POST /_admin/osds/{node_id}/reboot`
///
/// Reboots the pod / machine hosting the given OSD. Resolves the OSD
/// to its hostname / pod-name by looking it up in the meta's node
/// list; the host provider then acts on that. Without a platform
/// provider, returns 501.
pub async fn admin_reboot_osd(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    axum::extract::Path(node_id_hex): axum::extract::Path<String>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }

    // Resolve node_id → pod/hostname via meta + the OSD's get_status.
    // We need a concrete hostname to hand to the platform provider;
    // `host_provider.reboot("objectio-osd-2")` is how the k8s
    // implementation knows which pod to delete.
    let mut meta = state.meta_client.clone();
    let nodes = match meta
        .get_listing_nodes(GetListingNodesRequest {
            bucket: String::new(),
            include_all_states: true,
        })
        .await
    {
        Ok(resp) => resp.into_inner().nodes,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response();
        }
    };

    // Parse hex once so we can byte-compare to each listing's node_id.
    let node_id_bytes = match hex::decode(&node_id_hex) {
        Ok(b) if b.len() == 16 => b,
        _ => {
            return (StatusCode::BAD_REQUEST, "node_id must be 32 hex chars").into_response();
        }
    };

    // Find the matching node's address, then fetch the OSD's pod_name
    // from its status RPC. Pod name is what k8s delete-pod needs.
    let addr = match nodes.iter().find(|n| n.node_id == node_id_bytes) {
        Some(n) => n.address.clone(),
        None => {
            return (StatusCode::NOT_FOUND, format!("no OSD {node_id_hex}")).into_response();
        }
    };
    let osd_addr = if addr.starts_with("http") {
        addr
    } else {
        format!("http://{addr}")
    };
    let pod_name = match StorageServiceClient::connect(osd_addr.clone()).await {
        Ok(mut client) => match client
            .get_status(objectio_proto::storage::GetStatusRequest::default())
            .await
        {
            Ok(r) => r.into_inner().pod_name,
            Err(e) => {
                return (
                    StatusCode::BAD_GATEWAY,
                    format!("osd unreachable at {osd_addr}: {e}"),
                )
                    .into_response();
            }
        },
        Err(e) => {
            return (StatusCode::BAD_GATEWAY, format!("osd connect failed: {e}")).into_response();
        }
    };
    if pod_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "osd did not report a pod_name (not running under k8s?)",
        )
            .into_response();
    }

    match state.host_provider.reboot(&pod_name).await {
        Ok(outcome) => Json(serde_json::json!({
            "provider": state.host_provider.name(),
            "pod": outcome.pod,
            "requested": outcome.requested,
        }))
        .into_response(),
        Err(e) => host_provider_error_to_response(e),
    }
}

/// `GET /_admin/drain-status`
///
/// Returns the current per-OSD drain progress snapshot (one entry per
/// Draining OSD). Empty response when no drains are in flight.
pub async fn admin_drain_status(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let mut meta = state.meta_client.clone();
    let resp = match meta.get_drain_status(GetDrainStatusRequest {}).await {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response();
        }
    };

    let drains: Vec<serde_json::Value> = resp
        .drains
        .into_iter()
        .map(|d| {
            serde_json::json!({
                "node_id": hex::encode(&d.node_id),
                "shards_remaining": d.shards_remaining,
                "initial_shards": d.initial_shards,
                "shards_migrated": d.shards_migrated,
                "updated_at": d.updated_at,
                "last_error": d.last_error,
            })
        })
        .collect();

    Json(serde_json::json!({ "drains": drains })).into_response()
}

/// `GET /_admin/rebalance-status` — cluster-wide rebalance progress.
pub async fn admin_rebalance_status(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let mut meta = state.meta_client.clone();
    let r = match meta
        .get_rebalance_status(GetRebalanceStatusRequest {})
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response();
        }
    };
    Json(serde_json::json!({
        "started": r.started,
        "paused": r.paused,
        "last_sweep_at": r.last_sweep_at,
        "scanned_this_pass": r.scanned_this_pass,
        "drifts_seen_this_pass": r.drifts_seen_this_pass,
        "shards_rebalanced_total": r.shards_rebalanced_total,
        "last_error": r.last_error,
        // PG balancer counters — the banner uses these when
        // pgs_moved_total > 0 to show balancer activity.
        "pgs_moved_total": r.pgs_moved_total,
        "pg_candidates_last_tick": r.pg_candidates_last_tick,
        "pgs_scanned_last_tick": r.pgs_scanned_last_tick,
    }))
    .into_response()
}

/// `POST /_admin/rebalance/pause` — pause the cluster rebalancer.
/// Persisted via Raft (`rebalance/paused = true`) so it survives
/// leader failover and restarts.
pub async fn admin_rebalance_pause(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    admin_rebalance_set_paused(&state, &auth, &headers, true).await
}

/// `POST /_admin/rebalance/resume` — re-enable the cluster rebalancer.
pub async fn admin_rebalance_resume(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    admin_rebalance_set_paused(&state, &auth, &headers, false).await
}

async fn admin_rebalance_set_paused(
    state: &Arc<AppState>,
    auth: &Option<Extension<AuthResult>>,
    headers: &HeaderMap,
    paused: bool,
) -> Response {
    if let Some(deny) = require_system_admin(auth, headers) {
        return deny;
    }
    let who = auth
        .as_ref()
        .map(|Extension(a)| a.user_id.clone())
        .unwrap_or_else(|| "console".to_string());

    let mut meta = state.meta_client.clone();
    let req = SetConfigRequest {
        key: "rebalance/paused".to_string(),
        value: if paused {
            b"true".to_vec()
        } else {
            b"false".to_vec()
        },
        updated_by: who,
    };
    match meta.set_config(req).await {
        Ok(_) => Json(serde_json::json!({ "paused": paused })).into_response(),
        Err(e) => {
            let code = if e.code() == tonic::Code::FailedPrecondition {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (code, e.message().to_string()).into_response()
        }
    }
}

/// `GET /_admin/host-provider`
///
/// Returns the provider name — used by the console to decide whether
/// to render Add Host / Reboot buttons as active, or show a hint that
/// a platform provider needs configuring.
pub async fn admin_host_provider_info(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    Json(serde_json::json!({
        "provider": state.host_provider.name(),
        "supports_add_host": state.host_provider.name() != "noop",
        "supports_reboot": state.host_provider.name() != "noop",
    }))
    .into_response()
}

// ============================================================================
// Cluster info — gateway self-topology + live distance to every OSD
// ============================================================================

/// GET /_admin/cluster-info — returns the gateway's configured
/// self-topology plus, for every active OSD, the computed
/// [`TopologyDistance`]. Used by the console to render "this gateway is in
/// rack-02; closest OSDs are …" and by operators to sanity-check that
/// `--topology-*` flags were passed correctly.
pub async fn admin_cluster_info(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_admin_or_session(&auth, &headers) {
        return deny;
    }
    let mut client = state.meta_client.clone();
    let nodes = match client
        .get_listing_nodes(GetListingNodesRequest {
            bucket: String::new(),
            include_all_states: false,
        })
        .await
    {
        Ok(resp) => resp.into_inner().nodes,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response();
        }
    };

    let me = &state.self_topology;
    let osd_entries: Vec<serde_json::Value> = nodes
        .iter()
        .map(|n| {
            let fd = n.failure_domain.clone().unwrap_or_default();
            let peer = objectio_placement::FailureDomainInfo::new_full(
                &fd.region,
                &fd.zone,
                &fd.datacenter,
                &fd.rack,
                &fd.host,
            );
            let dist = objectio_placement::distance(me, &peer);
            serde_json::json!({
                "node_id": hex::encode(&n.node_id),
                "address": n.address,
                "failure_domain": {
                    "region": fd.region,
                    "zone": fd.zone,
                    "datacenter": fd.datacenter,
                    "rack": fd.rack,
                    "host": fd.host,
                },
                "distance": dist.as_str(),
                "is_local": dist.is_local(),
            })
        })
        .collect();

    Json(serde_json::json!({
        "self_topology": {
            "region": me.region,
            "zone": me.zone,
            "datacenter": me.datacenter,
            "rack": me.rack,
            "host": me.host,
            "configured": !me.region.is_empty(),
        },
        "osds": osd_entries,
    }))
    .into_response()
}

// ============================================================================
// Topology + placement validation
// ============================================================================

/// GET /_admin/topology — aggregated OSD tree with per-level counts.
/// The tree is region → zone → datacenter → rack → host → osds; empty
/// levels collapse to a synthetic "(none)" node so the console still
/// renders a usable hierarchy.
pub async fn admin_get_topology(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_admin_or_session(&auth, &headers) {
        return deny;
    }
    let mut client = state.meta_client.clone();
    let nodes = match client
        .get_listing_nodes(GetListingNodesRequest {
            bucket: String::new(),
            include_all_states: false,
        })
        .await
    {
        Ok(resp) => resp.into_inner().nodes,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response();
        }
    };

    // Build a nested counts structure as JSON. Each level carries the
    // display name + how many distinct children it has + an array of
    // children. Small enough for every size of cluster we'll deploy.
    use std::collections::BTreeMap;
    type Tree = BTreeMap<
        String,
        BTreeMap<String, BTreeMap<String, BTreeMap<String, BTreeMap<String, Vec<String>>>>>,
    >;
    let mut tree: Tree = BTreeMap::new();
    for n in &nodes {
        let fd = n.failure_domain.clone().unwrap_or_default();
        let region = if fd.region.is_empty() {
            "(none)".into()
        } else {
            fd.region
        };
        let zone = if fd.zone.is_empty() {
            "(none)".into()
        } else {
            fd.zone
        };
        let dc = if fd.datacenter.is_empty() {
            "(none)".into()
        } else {
            fd.datacenter
        };
        let rack = if fd.rack.is_empty() {
            "(none)".into()
        } else {
            fd.rack
        };
        let host = if fd.host.is_empty() {
            "(none)".into()
        } else {
            fd.host
        };
        tree.entry(region)
            .or_default()
            .entry(zone)
            .or_default()
            .entry(dc)
            .or_default()
            .entry(rack)
            .or_default()
            .entry(host)
            .or_default()
            .push(hex::encode(&n.node_id));
    }

    // Render.
    let regions: Vec<serde_json::Value> = tree
        .into_iter()
        .map(|(region_name, zones)| {
            let zones_json: Vec<serde_json::Value> = zones
                .into_iter()
                .map(|(zone_name, dcs)| {
                    let dcs_json: Vec<serde_json::Value> = dcs
                        .into_iter()
                        .map(|(dc_name, racks)| {
                            let racks_json: Vec<serde_json::Value> = racks
                                .into_iter()
                                .map(|(rack_name, hosts)| {
                                    let hosts_json: Vec<serde_json::Value> = hosts
                                        .into_iter()
                                        .map(|(host_name, osds)| {
                                            serde_json::json!({
                                                "host": host_name,
                                                "osds": osds,
                                            })
                                        })
                                        .collect();
                                    serde_json::json!({ "rack": rack_name, "hosts": hosts_json })
                                })
                                .collect();
                            serde_json::json!({ "datacenter": dc_name, "racks": racks_json })
                        })
                        .collect();
                    serde_json::json!({ "zone": zone_name, "datacenters": dcs_json })
                })
                .collect();
            serde_json::json!({ "region": region_name, "zones": zones_json })
        })
        .collect();

    // Per-level distinct counts for quick "can pool X place?" questions.
    let mut r_set = std::collections::HashSet::new();
    let mut z_set = std::collections::HashSet::new();
    let mut d_set = std::collections::HashSet::new();
    let mut rk_set = std::collections::HashSet::new();
    let mut h_set = std::collections::HashSet::new();
    for n in &nodes {
        let fd = n.failure_domain.clone().unwrap_or_default();
        r_set.insert(fd.region.clone());
        z_set.insert(format!("{}:{}", fd.region, fd.zone));
        d_set.insert(format!("{}:{}:{}", fd.region, fd.zone, fd.datacenter));
        rk_set.insert(format!(
            "{}:{}:{}:{}",
            fd.region, fd.zone, fd.datacenter, fd.rack
        ));
        h_set.insert(format!(
            "{}:{}:{}:{}:{}",
            fd.region, fd.zone, fd.datacenter, fd.rack, fd.host
        ));
    }

    Json(serde_json::json!({
        "osd_count": nodes.len(),
        "distinct": {
            "region": r_set.len(),
            "zone": z_set.len(),
            "datacenter": d_set.len(),
            "rack": rk_set.len(),
            "host": h_set.len(),
        },
        "tree": regions,
    }))
    .into_response()
}

/// GET /_admin/placement/validate?pool=NAME — answer "can this pool place
/// data in the current topology?". Returns the required spread level,
/// how many distinct domains exist, and a satisfiability verdict.
pub async fn admin_validate_placement(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Some(deny) = require_admin_or_session(&auth, &headers) {
        return deny;
    }
    let Some(pool_name) = params.get("pool") else {
        return (StatusCode::BAD_REQUEST, "?pool=NAME required").into_response();
    };
    let mut client = state.meta_client.clone();
    // Fetch pool config
    let pool = match client
        .get_pool(GetPoolRequest {
            name: pool_name.clone(),
        })
        .await
    {
        Ok(r) => {
            let r = r.into_inner();
            if !r.found {
                return (StatusCode::NOT_FOUND, "pool not found").into_response();
            }
            match r.pool {
                Some(p) => p,
                None => return (StatusCode::NOT_FOUND, "pool not found").into_response(),
            }
        }
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response();
        }
    };

    let shard_count = u64::from(pool.ec_k) + u64::from(pool.ec_m);
    let level = pool.failure_domain.as_str();

    // Fetch nodes and count distinct domain keys at the pool's level.
    let nodes = match client
        .get_listing_nodes(GetListingNodesRequest {
            bucket: String::new(),
            include_all_states: false,
        })
        .await
    {
        Ok(resp) => resp.into_inner().nodes,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response();
        }
    };
    let mut keys = std::collections::HashSet::new();
    for n in &nodes {
        let fd = n.failure_domain.clone().unwrap_or_default();
        // Pool `failure_domain` strings come from the existing PoolConfig —
        // accept every synonym we've ever written. `osd` / `node` / `disk`
        // all mean "each OSD is its own domain" for Phase 1; we'll split
        // disk out as a finer level once OSDs report per-disk health.
        let key = match level {
            "region" => fd.region,
            "zone" => format!("{}:{}", fd.region, fd.zone),
            "datacenter" | "dc" => format!("{}:{}:{}", fd.region, fd.zone, fd.datacenter),
            "host" => format!(
                "{}:{}:{}:{}:{}",
                fd.region, fd.zone, fd.datacenter, fd.rack, fd.host
            ),
            "osd" | "node" | "disk" => hex::encode(&n.node_id),
            // Default (including "rack") — collapse to rack-level key.
            _ => format!("{}:{}:{}:{}", fd.region, fd.zone, fd.datacenter, fd.rack),
        };
        keys.insert(key);
    }
    let available = keys.len() as u64;
    let satisfiable = available >= shard_count;
    Json(serde_json::json!({
        "pool": pool_name,
        "required_level": level,
        "required_count": shard_count,
        "available_count": available,
        "satisfiable": satisfiable,
        "reason": if satisfiable {
            format!("{} distinct {}s available for {} shards", available, level, shard_count)
        } else {
            format!(
                "Pool needs {} distinct {}s but topology has only {}. Add more {}s or relax the pool's failure_domain.",
                shard_count, level, available, level
            )
        },
    }))
    .into_response()
}

fn offline_node(node_id: &[u8], addr: &str) -> serde_json::Value {
    serde_json::json!({
        "node_id": hex::encode(node_id),
        "node_name": "",
        "address": addr,
        "total_capacity": 0,
        "used_capacity": 0,
        "shard_count": 0,
        "uptime_seconds": 0,
        "disks": [],
        "online": false,
    })
}

// ============================================================================
// IAM Groups
// ============================================================================
//
// The meta service already has full group RPCs (CreateGroup, DeleteGroup,
// ListGroups, AddUserToGroup, RemoveUserFromGroup); these handlers expose
// them as REST endpoints under `/_admin/groups*` so the console + CLI can
// drive them. Group ARNs participate in the same `PolicyEvaluator` as user
// ARNs — attaching a policy to a group is identical to attaching it to a
// user, just with `group_id` set instead of `user_id`.

#[derive(serde::Deserialize)]
pub struct AdminCreateGroupBody {
    pub group_name: String,
}

#[derive(serde::Deserialize)]
pub struct AdminGroupMemberBody {
    pub user_id: String,
}

// ============================================================================
// Usage
// ============================================================================

/// Storage consumption per bucket and tenant, plus cluster capacity.
///
/// A system admin gets everything. A tenant caller gets only their own
/// tenant's row and buckets, and no cluster section — raw capacity and
/// other tenants' consumption are not theirs to see. Served from the
/// gateway's background refresh, so it is at most one poll interval old
/// (`updated_at` says exactly how old).
pub async fn admin_usage(auth: Option<Extension<AuthResult>>, headers: HeaderMap) -> Response {
    let full = require_system_admin(&auth, &headers);
    let caller = extract_caller(&auth, &headers);
    if full.is_some() && (!caller.authenticated || caller.tenant.is_empty()) {
        return full.unwrap_or_else(|| StatusCode::FORBIDDEN.into_response());
    }

    let Some(mut report) = objectio_s3::s3_metrics().usage() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Usage has not been gathered yet; try again shortly",
        )
            .into_response();
    };

    if full.is_none() {
        return Json(report).into_response();
    }
    report.buckets.retain(|b| b.tenant == caller.tenant);
    report.tenants.retain(|t| t.tenant == caller.tenant);
    Json(serde_json::json!({
        "updated_at": report.updated_at,
        "cluster": serde_json::Value::Null,
        "tenants": report.tenants,
        "buckets": report.buckets,
    }))
    .into_response()
}

// ---- Deduplication policy (objectio-docs architecture/design/core/dedup.md) ----

fn status_response(e: &tonic::Status) -> Response {
    let code = match e.code() {
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::Aborted => StatusCode::CONFLICT,
        tonic::Code::FailedPrecondition | tonic::Code::Unavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, e.message().to_string()).into_response()
}

fn dedup_policy_json(p: &objectio_proto::metadata::GetDedupPolicyResponse) -> serde_json::Value {
    use objectio_proto::dedup::{mode_name, scope_name, to_json};
    serde_json::json!({
        "bucket": p.bucket.as_ref().map(to_json),
        "tenant": p.tenant.as_ref().map(to_json),
        "tenant_name": p.tenant_name,
        "cluster": p.cluster.as_ref().map(to_json),
        "effective": {
            "mode": mode_name(p.effective_mode()),
            "scope": scope_name(p.effective_scope()),
            "mode_from": p.mode_from,
            "scope_from": p.scope_from,
        },
    })
}

async fn fetch_dedup_policy(state: &AppState, bucket: &str) -> Response {
    let mut meta = state.meta_client.clone();
    match meta
        .get_dedup_policy(objectio_proto::metadata::GetDedupPolicyRequest {
            bucket: bucket.to_string(),
        })
        .await
    {
        Ok(r) => Json(dedup_policy_json(&r.into_inner())).into_response(),
        Err(e) => status_response(&e),
    }
}

/// `GET /_admin/dedup`: the cluster default.
pub async fn admin_get_dedup(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    fetch_dedup_policy(&state, "").await
}

/// `PUT /_admin/dedup` `{"mode": …, "scope": …}`: set the cluster default.
pub async fn admin_put_dedup(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let policy = match objectio_proto::dedup::from_json(&body)
        .and_then(|p| objectio_proto::dedup::validate(&p).map(|()| p))
    {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let who = auth
        .as_ref()
        .map_or_else(|| "console".to_string(), |Extension(a)| a.user_id.clone());
    let mut meta = state.meta_client.clone();
    if let Err(e) = meta
        .set_config(SetConfigRequest {
            key: objectio_proto::dedup::CLUSTER_KEY.to_string(),
            value: objectio_proto::dedup::to_json(&policy)
                .to_string()
                .into_bytes(),
            updated_by: who,
        })
        .await
    {
        return status_response(&e);
    }
    fetch_dedup_policy(&state, "").await
}

/// `GET /_admin/buckets/{name}/dedup`: the bucket's policy at every level,
/// and what it resolves to.
pub async fn admin_get_bucket_dedup(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(bucket): Path<String>,
) -> Response {
    if let Some(deny) = require_bucket_tenant_admin(&state, &auth, &headers, &bucket).await {
        return deny;
    }
    fetch_dedup_policy(&state, &bucket).await
}

async fn set_bucket_dedup(
    state: &AppState,
    bucket: &str,
    policy: Option<objectio_proto::metadata::DedupPolicy>,
) -> Response {
    let mut meta = state.meta_client.clone();
    if let Err(e) = meta
        .set_bucket_dedup(objectio_proto::metadata::SetBucketDedupRequest {
            bucket: bucket.to_string(),
            policy,
        })
        .await
    {
        return status_response(&e);
    }
    fetch_dedup_policy(state, bucket).await
}

/// `PUT /_admin/buckets/{name}/dedup` `{"mode": …, "scope": …}`; absent
/// fields inherit.
pub async fn admin_put_bucket_dedup(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(bucket): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(deny) = require_bucket_tenant_admin(&state, &auth, &headers, &bucket).await {
        return deny;
    }
    match objectio_proto::dedup::from_json(&body) {
        Ok(p) => set_bucket_dedup(&state, &bucket, Some(p)).await,
        Err(e) => (StatusCode::BAD_REQUEST, e).into_response(),
    }
}

/// `DELETE /_admin/buckets/{name}/dedup`: inherit everything.
pub async fn admin_delete_bucket_dedup(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(bucket): Path<String>,
) -> Response {
    if let Some(deny) = require_bucket_tenant_admin(&state, &auth, &headers, &bucket).await {
        return deny;
    }
    set_bucket_dedup(&state, &bucket, None).await
}

/// `POST /_admin/dedup/dry-run/reset`: every OSD forgets the fingerprints
/// dry-run has noted, starting a new measurement window.
pub async fn admin_reset_dedup_dry_run(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Some(deny) = require_system_admin(&auth, &headers) {
        return deny;
    }
    let mut meta = state.meta_client.clone();
    let nodes = match meta
        .get_listing_nodes(GetListingNodesRequest {
            bucket: String::new(),
            include_all_states: true,
        })
        .await
    {
        Ok(r) => r.into_inner().nodes,
        Err(e) => return status_response(&e),
    };
    let mut seen = std::collections::HashSet::new();
    let (mut forgotten, mut failed) = (0u64, Vec::new());
    for node in nodes {
        if !seen.insert(node.address.clone()) {
            continue;
        }
        let result = async {
            let mut client = state
                .osd_pool
                .get_or_connect(&node.node_id, &node.address)
                .await
                .map_err(|e| e.to_string())?;
            client
                .reset_chunk_notes(objectio_proto::storage::ResetChunkNotesRequest {})
                .await
                .map(|r| r.into_inner().forgotten)
                .map_err(|e| e.message().to_string())
        }
        .await;
        match result {
            Ok(n) => forgotten += n,
            Err(e) => failed.push(serde_json::json!({ "osd": node.address, "error": e })),
        }
    }
    Json(serde_json::json!({ "forgotten": forgotten, "failed": failed })).into_response()
}

// ── Users, keys, policies, groups, roles: reading and changing ───────────

fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

fn grpc_error(e: &tonic::Status) -> Response {
    let status = match e.code() {
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::AlreadyExists | tonic::Code::Aborted => StatusCode::CONFLICT,
        tonic::Code::InvalidArgument | tonic::Code::FailedPrecondition => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    json_error(status, e.message())
}

fn user_json(u: &objectio_proto::metadata::UserMeta) -> serde_json::Value {
    serde_json::json!({
        "user_id": u.user_id,
        "display_name": u.display_name,
        "arn": u.arn,
        "email": u.email,
        "tenant": u.tenant,
        "created_at": u.created_at,
        "status": user_status_label(u.status),
    })
}

/// A user's status as the API spells it.
pub(crate) const fn user_status_label(status: i32) -> &'static str {
    match status {
        0 => "active",
        1 => "suspended",
        _ => "deleted",
    }
}

/// An access key's status as the API spells it.
pub(crate) const fn key_status_label(status: i32) -> &'static str {
    if status == 0 { "active" } else { "inactive" }
}

/// `GET /_admin/users/{user_id}`
pub async fn admin_get_user(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Response {
    if let Some(deny) = require_user_tenant_admin(&state, &auth, &headers, &user_id).await {
        return deny;
    }
    match state
        .meta_client
        .clone()
        .get_user(objectio_proto::metadata::GetUserRequest { user_id })
        .await
    {
        Ok(r) => r.into_inner().user.map_or_else(
            || json_error(StatusCode::NOT_FOUND, "user not found"),
            |u| Json(user_json(&u)).into_response(),
        ),
        Err(e) => grpc_error(&e),
    }
}

/// `PUT /_admin/users/{user_id}` `{"status": "active"|"suspended",
/// "display_name", "email"}`: suspending refuses the user's every key
/// (within the gateways' 15 s credential cache) without deleting anything.
pub async fn admin_update_user(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    if let Some(deny) = require_user_tenant_admin(&state, &auth, &headers, &user_id).await {
        return deny;
    }
    let status = match body["status"].as_str() {
        None => None,
        Some("active") => Some(objectio_proto::metadata::UserStatus::UserActive as i32),
        Some("suspended") => Some(objectio_proto::metadata::UserStatus::UserSuspended as i32),
        Some(other) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                &format!("status must be active or suspended, not {other:?}"),
            );
        }
    };
    // Nobody suspends themselves out of the cluster.
    if status == Some(objectio_proto::metadata::UserStatus::UserSuspended as i32)
        && extract_caller(&auth, &headers).user_id == user_id
    {
        return json_error(StatusCode::BAD_REQUEST, "you can't suspend yourself");
    }
    state.auth_state.forget_user(&user_id);
    match state
        .meta_client
        .clone()
        .update_user(objectio_proto::metadata::UpdateUserRequest {
            user_id,
            status,
            display_name: body["display_name"].as_str().map(str::to_string),
            email: body["email"].as_str().map(str::to_string),
        })
        .await
    {
        Ok(r) => {
            let user = r.into_inner().user.unwrap_or_default();
            // Dropped again after the commit: a request in between may have
            // cached the old status.
            state.auth_state.forget_user(&user.user_id);
            Json(user_json(&user)).into_response()
        }
        Err(e) => grpc_error(&e),
    }
}

/// `PUT /_admin/access-keys/{access_key_id}` `{"status": "active"|"inactive"}`
pub async fn admin_update_access_key(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(access_key_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Response {
    let mut client = state.meta_client.clone();
    // Whose key, whatever its status: a tenant admin reactivates its own
    // tenant's inactive keys.
    let owner = match client
        .get_access_key(objectio_proto::metadata::GetAccessKeyRequest {
            access_key_id: access_key_id.clone(),
        })
        .await
    {
        Ok(r) => r
            .into_inner()
            .access_key
            .map(|k| k.user_id)
            .unwrap_or_default(),
        Err(_) => String::new(),
    };
    let deny = if owner.is_empty() {
        require_system_admin(&auth, &headers)
    } else {
        require_user_tenant_admin(&state, &auth, &headers, &owner).await
    };
    if let Some(deny) = deny {
        return deny;
    }
    let status = match body["status"].as_str() {
        Some("active") => objectio_proto::metadata::KeyStatus::KeyActive as i32,
        Some("inactive") => objectio_proto::metadata::KeyStatus::KeyInactive as i32,
        _ => return json_error(StatusCode::BAD_REQUEST, "status must be active or inactive"),
    };
    if status == objectio_proto::metadata::KeyStatus::KeyInactive as i32
        && auth
            .as_ref()
            .is_some_and(|Extension(a)| a.access_key_id == access_key_id)
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            "you can't deactivate the key you are using",
        );
    }
    match client
        .update_access_key(objectio_proto::metadata::UpdateAccessKeyRequest {
            access_key_id,
            status,
        })
        .await
    {
        Ok(r) => {
            let k = r.into_inner().key.unwrap_or_default();
            state.auth_state.forget_key(&k.access_key_id);
            Json(serde_json::json!({
                "access_key_id": k.access_key_id,
                "user_id": k.user_id,
                "status": key_status_label(k.status),
            }))
            .into_response()
        }
        Err(e) => grpc_error(&e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use objectio_auth::scope::{CredentialScope, Operation};

    fn auth_with(scope: Option<&str>) -> Option<Extension<AuthResult>> {
        Some(Extension(AuthResult {
            user_id: "u1".into(),
            user_arn: "arn:objectio:iam::acme:user/app".into(),
            tenant: "acme".into(),
            scope: scope.map(|s| CredentialScope {
                scope: s.to_string(),
                operation: Operation::ReadWrite,
            }),
            ..Default::default()
        }))
    }

    #[test]
    fn unscoped_credentials_reach_the_admin_api() {
        assert!(deny_scoped_credential(&auth_with(None)).is_none());
        assert!(deny_scoped_credential(&None).is_none());
    }

    #[test]
    fn a_scoped_credential_is_refused() {
        // The escalation this closes: minting an access key is an admin
        // action, so without this a key confined to one bucket could mint
        // itself an unscoped one and walk out of its own scope.
        let denied = deny_scoped_credential(&auth_with(Some("s3://ws1/")));
        assert!(denied.is_some());
        assert_eq!(denied.unwrap().status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn an_empty_scope_string_is_not_a_scope() {
        // Meta stores "no scope" as an empty string, and older records decode
        // to `Some(CredentialScope { scope: "" })` rather than `None`. Reading
        // that as scoped would lock every pre-existing key out of the console.
        assert!(deny_scoped_credential(&auth_with(Some(""))).is_none());
    }

    #[test]
    fn a_redacted_secret_written_back_keeps_the_stored_one() {
        let stored = serde_json::json!({"client_id": "a", "client_secret": "s3cret"});
        let back = serde_json::json!({"client_id": "b", "client_secret": REDACTED});
        let merged = keep_stored_secret(&back, Some(&stored));
        assert_eq!(merged["client_secret"], "s3cret");
        assert_eq!(merged["client_id"], "b");
        // Nothing stored: no secret, never the placeholder.
        assert_eq!(keep_stored_secret(&back, None)["client_secret"], "");
    }
}
