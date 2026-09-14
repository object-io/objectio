//! Console authentication — session-token based login for the web console.
//!
//! Supports two login methods:
//! 1. **AK/SK**: `POST /_console/api/login` with access key + secret key
//! 2. **OIDC SSO**: `GET /_console/api/oidc/authorize` → redirect to provider → callback
//!
//! Both methods result in the same `objectio-session` cookie.

use axum::{
    Extension, Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use hmac::{Hmac, Mac};
use objectio_proto::metadata::GetAccessKeyForAuthRequest;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use tracing::{debug, info, warn};

use crate::s3::AppState;

/// State for OIDC console routes
pub struct ConsoleOidcState {
    pub oidc_provider: Option<Arc<objectio_auth::OidcProvider>>,
    pub external_endpoint: String,
    pub meta_client: objectio_proto::metadata::metadata_service_client::MetadataServiceClient<
        tonic::transport::Channel,
    >,
}

/// Build an OidcProvider from a stored identity config (identity/openid/{name})
fn build_oidc_provider_from_config(
    config: &serde_json::Value,
) -> Option<objectio_auth::OidcProvider> {
    let issuer_url = config.get("issuer_url")?.as_str()?.to_string();
    let client_id = config.get("client_id")?.as_str()?.to_string();
    let client_secret = config
        .get("client_secret")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let audience = config
        .get("audience")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(&client_id)
        .to_string();
    let scopes = config
        .get("scopes")
        .and_then(|v| v.as_str())
        .unwrap_or("openid profile email")
        .to_string();
    let groups_claim = config
        .get("claim_name")
        .and_then(|v| v.as_str())
        .unwrap_or("groups")
        .to_string();

    Some(objectio_auth::OidcProvider::new(
        objectio_auth::OidcConfig {
            issuer_url,
            client_id,
            client_secret,
            audience,
            jwks_uri: None,
            token_endpoint: None,
            groups_claim,
            role_claim: String::new(),
            scopes,
        },
    ))
}

/// Default storage quota given to a tenant that registers itself through a
/// multi-tenant provider. Self-registration is open by design, so the default
/// is a modest allowance rather than unlimited; an operator raises it per
/// tenant afterwards.
pub const DEFAULT_SELF_REGISTERED_QUOTA_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Tenancy behavior for one OIDC provider, read from its stored config.
#[derive(Debug, Clone)]
pub struct ProviderTenancy {
    /// True when the provider federates many upstream tenants (Entra
    /// `common` / `organizations`). Each upstream tenant then gets its own
    /// ObjectIO tenant, created on first login.
    pub multi_tenant: bool,
    /// Role/group claim value that makes a user an admin of their tenant.
    /// Empty means nobody is promoted and only the system admin can manage it.
    pub tenant_admin_role: String,
    /// Quota applied to a self-registered tenant.
    pub quota_bytes: u64,
    /// Upstream tenant ids permitted to self-register. Empty means open —
    /// any upstream tenant may register, which is what `common` implies.
    pub allowed_tids: Vec<String>,
}

impl ProviderTenancy {
    /// Read the tenancy settings out of a stored provider config document.
    #[must_use]
    pub fn from_config(config: &serde_json::Value) -> Self {
        Self {
            multi_tenant: config
                .get("tenancy")
                .and_then(|v| v.as_str())
                .is_some_and(|v| v.eq_ignore_ascii_case("multi")),
            tenant_admin_role: config
                .get("tenant_admin_role")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            quota_bytes: config
                .get("tenant_quota_bytes")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(DEFAULT_SELF_REGISTERED_QUOTA_BYTES),
            allowed_tids: config
                .get("allowed_tids")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(ToString::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// May this upstream tenant register? Open unless an allowlist is set.
    #[must_use]
    pub fn admits(&self, tid: &str) -> bool {
        self.allowed_tids.is_empty() || self.allowed_tids.iter().any(|t| t == tid)
    }
}

/// Label under which a tenant records the upstream tenant it belongs to.
///
/// The mapping is keyed on the upstream `tid` rather than a domain because a
/// domain can be added to or removed from an Entra tenant, while `tid` is
/// immutable — keying on the name would break the moment a customer changes
/// their vanity domain.
pub const OIDC_TID_LABEL: &str = "oidc_tid";

/// Derive a tenant name from an upstream identity.
///
/// Prefers the domain part of the user's sign-in name, which is readable and
/// stable enough for display, and falls back to the tid. The name is only an
/// identifier for humans; lookup always goes through [`OIDC_TID_LABEL`].
#[must_use]
pub fn derive_tenant_name(upstream_user: &str, tid: &str) -> String {
    let candidate = upstream_user
        .rsplit('@')
        .next()
        .filter(|d| !d.is_empty() && d.contains('.'))
        .unwrap_or(tid);
    let cleaned: String = candidate
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.is_empty() {
        tid.to_string()
    } else {
        cleaned
    }
}

/// Find, or self-register, the ObjectIO tenant for an upstream tenant id.
///
/// Returns the tenant name, or an error string suitable for showing the user.
/// A tenant is created only when the provider is multi-tenant and the upstream
/// tenant is admitted; it starts enabled, with the provider's quota, and
/// carries the upstream id in [`OIDC_TID_LABEL`] so later logins find it again
/// even if it is renamed.
pub async fn resolve_or_register_tenant(
    meta: &mut objectio_proto::metadata::metadata_service_client::MetadataServiceClient<
        tonic::transport::Channel,
    >,
    tenancy: &ProviderTenancy,
    provider_name: &str,
    tid: &str,
    upstream_user: &str,
) -> Result<String, String> {
    if !tenancy.admits(tid) {
        return Err(format!(
            "upstream tenant {tid} is not permitted to register"
        ));
    }

    let existing = meta
        .list_tenants(objectio_proto::metadata::ListTenantsRequest {})
        .await
        .map_err(|e| format!("tenant lookup failed: {e}"))?
        .into_inner()
        .tenants;

    // Match on the immutable upstream id, never the name.
    if let Some(t) = existing
        .iter()
        .find(|t| t.labels.get(OIDC_TID_LABEL).is_some_and(|v| v == tid))
    {
        return Ok(t.name.clone());
    }

    // Pick a free name. The derived one is for humans; collisions just get a
    // suffix rather than failing a login.
    let base = derive_tenant_name(upstream_user, tid);
    let mut name = base.clone();
    if existing.iter().any(|t| t.name == name) {
        name = format!("{base}-{}", &tid[..8.min(tid.len())]);
    }

    let mut labels = std::collections::HashMap::new();
    labels.insert(OIDC_TID_LABEL.to_string(), tid.to_string());
    labels.insert("oidc_provider".to_string(), provider_name.to_string());

    let tenant = objectio_proto::metadata::TenantConfig {
        name: name.clone(),
        display_name: base,
        oidc_provider: provider_name.to_string(),
        quota_bytes: tenancy.quota_bytes,
        enabled: true,
        labels,
        ..Default::default()
    };

    meta.create_tenant(objectio_proto::metadata::CreateTenantRequest {
        tenant: Some(tenant),
    })
    .await
    .map_err(|e| format!("could not register tenant: {e}"))?;

    info!(
        "self-registered tenant '{name}' for upstream tid={tid} via provider '{provider_name}' \
         (quota {} bytes)",
        tenancy.quota_bytes
    );
    Ok(name)
}

/// Add a user to their tenant's admin list when their token carries the
/// provider's configured admin role.
///
/// Control therefore sits in the customer's own identity provider: their
/// administrators decide who administers their ObjectIO tenant, and we do not
/// have to guess from login order.
pub async fn apply_tenant_admin_role(
    meta: &mut objectio_proto::metadata::metadata_service_client::MetadataServiceClient<
        tonic::transport::Channel,
    >,
    tenancy: &ProviderTenancy,
    tenant_name: &str,
    user_arn: &str,
    roles: &[String],
) {
    if tenancy.tenant_admin_role.is_empty()
        || !roles.iter().any(|r| r == &tenancy.tenant_admin_role)
    {
        return;
    }
    let Ok(resp) = meta
        .get_tenant(objectio_proto::metadata::GetTenantRequest {
            name: tenant_name.to_string(),
        })
        .await
    else {
        return;
    };
    let inner = resp.into_inner();
    let Some(mut tenant) = inner.tenant.filter(|_| inner.found) else {
        return;
    };
    if tenant.admin_users.iter().any(|a| a == user_arn) {
        return;
    }
    tenant.admin_users.push(user_arn.to_string());
    if let Err(e) = meta
        .update_tenant(objectio_proto::metadata::UpdateTenantRequest {
            tenant: Some(tenant),
        })
        .await
    {
        warn!("could not promote {user_arn} to admin of '{tenant_name}': {e}");
    } else {
        info!("promoted {user_arn} to tenant admin of '{tenant_name}' via role claim");
    }
}

/// Which console surface a request belongs to.
///
/// Two signals can say this now. A dedicated listener carries a
/// [`ListenerKind`]; a single-port deployment distinguishes the surfaces by
/// path instead (`/_console/admin` vs `/_console/tenant`). The path is the
/// more specific of the two, so it wins where both are present — on the
/// legacy listener the path is the *only* signal, since `ListenerKind::Legacy`
/// deliberately gates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleAudience {
    /// Operator surface: system-admin sessions only.
    Ops,
    /// Self-service surface: tenant sessions only.
    Tenant,
    /// Nothing to enforce — legacy single bundle, or a non-console listener.
    Unscoped,
}

/// Resolve the audience from the request path, falling back to the listener.
///
/// `path` is the console path the browser was on when it started the flow: the
/// request path for direct calls, or the `Referer` for the OIDC callback,
/// which the identity provider sends to one fixed redirect URI regardless of
/// which surface the user began on.
#[must_use]
pub fn console_audience(path: &str, listener: Option<ListenerKind>) -> ConsoleAudience {
    if path.contains("/_console/admin") {
        return ConsoleAudience::Ops;
    }
    if path.contains("/_console/tenant") {
        return ConsoleAudience::Tenant;
    }
    match listener {
        Some(ListenerKind::OpsConsole | ListenerKind::AdminApi) => ConsoleAudience::Ops,
        Some(ListenerKind::TenantConsole) => ConsoleAudience::Tenant,
        _ => ConsoleAudience::Unscoped,
    }
}

/// Which composite listener received this request. Set per-listener as
/// an Axum `Extension` layer in `lib.rs` so handlers can refuse session
/// flows that don't fit the listener's audience — e.g. system-admin
/// login at the public tenant console.
///
/// Absent in tests and any code path that pre-dates the multi-listener
/// split, so handlers must always treat it as `Option`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenerKind {
    /// `--listen` in legacy mode — single port carrying everything.
    /// No login restrictions (current behavior preserved).
    Legacy,
    /// `--listen` in split mode — S3 / Iceberg / Delta Sharing only.
    /// Console login isn't reachable here (the route isn't mounted).
    Data,
    /// `--admin-listen` — admin API + `/metrics`. Console login is
    /// mounted (so a CLI user could call it) but no UI is served.
    /// Treated like the ops listener for login-gating purposes.
    AdminApi,
    /// `--ops-console-listen` — system-admin SPA + admin API.
    /// Refuses login by tenant-scoped users.
    OpsConsole,
    /// `--tenant-console-listen` — end-user SPA + admin API
    /// (server-side tenant-scoped). Refuses login by system admins.
    TenantConsole,
}

type HmacSha256 = Hmac<Sha256>;

/// Secret used to sign session tokens — derived from a fixed prefix.
/// In production this should be a configurable secret.
const TOKEN_SECRET: &[u8] = b"objectio-console-session-v1";

/// Session token validity: 24 hours
const SESSION_TTL_SECS: u64 = 86400;

#[derive(Deserialize)]
pub struct LoginRequest {
    #[serde(rename = "accessKey")]
    access_key: String,
    #[serde(rename = "secretKey")]
    secret_key: String,
    /// AWS-style "account" hint typed by the user on the login page.
    /// Optional. When supplied, the server refuses login if it
    /// doesn't match the tenant encoded in the access key — catches
    /// "wrong account" mistakes that would otherwise silently log
    /// the user into the wrong tenant scope.
    #[serde(default)]
    account: String,
}

#[derive(Serialize)]
pub struct SessionInfo {
    /// Canonical user id (UUID). Used as the lookup key for meta and for
    /// IAM-policy `user_id` attachments.
    pub user: String,
    pub access_key: String,
    pub expires_at: u64,
    pub tenant: String,
    /// Human-readable display name for the console UI. Populated on login
    /// and by `/_console/api/session` (via a meta lookup); empty on paths
    /// where only the signed session payload is available.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub display_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
}

/// POST /_console/api/login
pub async fn console_login(
    State(state): State<Arc<AppState>>,
    listener: Option<Extension<ListenerKind>>,
    Json(body): Json<LoginRequest>,
) -> Response {
    // Validate credentials via meta service
    let mut client = state.meta_client.clone();
    let resp = match client
        .get_access_key_for_auth(GetAccessKeyForAuthRequest {
            access_key_id: body.access_key.clone(),
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(_) => {
            return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
        }
    };

    let access_key_meta = match resp.access_key {
        Some(ak) => ak,
        None => {
            return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
        }
    };

    if access_key_meta.secret_access_key != body.secret_key {
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    let user_id = access_key_meta.user_id;
    let (tenant, display_name, email) = match resp.user {
        Some(u) => (u.tenant, u.display_name, u.email),
        None => (String::new(), String::new(), String::new()),
    };

    // Per-listener audience gate.
    //
    // - Ops console (system-admin surface, mgmt-network only) refuses
    //   tenant-scoped logins. A tenant user landing on the ops URL is
    //   either misconfigured or hostile — in either case they should
    //   not be able to mint a session here.
    // - Tenant console (public, end-user surface) refuses system-admin
    //   logins. Admin credentials should never flow through the
    //   internet-facing endpoint; the operator firewalled the ops
    //   console for a reason.
    //
    // Returns 403 with a hint pointing at the correct portal so a
    // confused human can re-route themselves.
    if let Some(Extension(kind)) = listener {
        match kind {
            ListenerKind::OpsConsole if !tenant.is_empty() => {
                warn!(
                    "ops-console login refused: user '{}' is tenant-scoped (tenant={})",
                    user_id, tenant
                );
                return (
                    StatusCode::FORBIDDEN,
                    "This account is tenant-scoped — sign in at the tenant console.",
                )
                    .into_response();
            }
            ListenerKind::TenantConsole if tenant.is_empty() => {
                warn!(
                    "tenant-console login refused: user '{}' is a system admin",
                    user_id
                );
                return (
                    StatusCode::FORBIDDEN,
                    "System-admin login is on the ops console.",
                )
                    .into_response();
            }
            _ => {}
        }
    }

    // "Wrong account" guard. If the user typed an account name in the
    // login form, it must match the tenant encoded in the access key.
    // Empty (= system-admin) creds with a typed account = also a
    // mismatch. We compare case-insensitively because the AWS-style
    // input is forgiving (Account name).
    let typed = body.account.trim();
    if !typed.is_empty() && !typed.eq_ignore_ascii_case(&tenant) {
        warn!(
            "login refused: typed account '{}' does not match credential tenant '{}' (user={})",
            typed, tenant, user_id
        );
        return (
            StatusCode::FORBIDDEN,
            "Account name does not match these credentials.",
        )
            .into_response();
    }

    // Build session token: base64(user_id|access_key|tenant|expires_at|hmac)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires = now + SESSION_TTL_SECS;

    let payload = format!("{user_id}|{}|{tenant}|{expires}", body.access_key);
    let sig = sign_payload(&payload);
    let token = format!("{payload}|{sig}");
    let token_b64 = base64_encode(&token);

    // Set cookie
    let cookie = format!(
        "objectio-session={token_b64}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL_SECS}"
    );

    let session = SessionInfo {
        user: user_id,
        access_key: body.access_key,
        expires_at: expires,
        tenant: tenant.clone(),
        display_name,
        email,
    };

    Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&session).unwrap_or_default(),
        ))
        .unwrap()
}

/// GET /_console/api/session
pub async fn console_session(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(mut info) = validate_session_from_headers(&headers) else {
        return (StatusCode::UNAUTHORIZED, "No valid session").into_response();
    };
    // Enrich with display_name + email so the console can show a friendly
    // label instead of the raw user_id UUID. Best-effort: a failed lookup
    // just falls through with the id.
    if info.display_name.is_empty()
        && let Ok(resp) = state
            .meta_client
            .clone()
            .get_user(objectio_proto::metadata::GetUserRequest {
                user_id: info.user.clone(),
            })
            .await
        && let Some(u) = resp.into_inner().user
    {
        info.display_name = u.display_name;
        info.email = u.email;
    }
    Json(info).into_response()
}

/// POST /_console/api/logout
pub async fn console_logout() -> Response {
    let cookie = "objectio-session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0";
    Response::builder()
        .status(StatusCode::OK)
        .header(header::SET_COOKIE, cookie)
        .body(axum::body::Body::from("{}"))
        .unwrap()
}

/// Validate session token from request headers (cookie or Authorization bearer).
/// Returns `Some(SessionInfo)` if valid, `None` otherwise.
pub fn validate_session_from_headers(headers: &HeaderMap) -> Option<SessionInfo> {
    // Try cookie first
    let token_b64 = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix("objectio-session=")
            })
        })
        // Fallback: Authorization: Bearer <token>
        .or_else(|| {
            headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        })?;

    let token = base64_decode(token_b64)?;

    // Parse: user_id|access_key|tenant|expires_at|sig
    let (payload, sig) = token.rsplit_once('|')?;

    // Verify HMAC
    let expected_sig = sign_payload(payload);
    if sig != expected_sig {
        // Try legacy format (colon-delimited, no tenant)
        return validate_legacy_token(&token);
    }

    // Parse payload fields: user_id|access_key|tenant|expires_at
    let fields: Vec<&str> = payload.splitn(4, '|').collect();
    if fields.len() != 4 {
        return None;
    }
    let user_id = fields[0];
    let access_key = fields[1];
    let tenant = fields[2];
    let expires_at: u64 = fields[3].parse().ok()?;

    // Check expiry
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now > expires_at {
        return None;
    }

    Some(SessionInfo {
        user: user_id.to_string(),
        access_key: access_key.to_string(),
        expires_at,
        tenant: tenant.to_string(),
        display_name: String::new(),
        email: String::new(),
    })
}

/// Parse legacy colon-delimited tokens (pre-tenant format)
fn validate_legacy_token(token: &str) -> Option<SessionInfo> {
    let (payload, sig) = token.rsplit_once(':')?;
    let expected_sig = sign_payload(payload);
    if sig != expected_sig {
        return None;
    }
    let fields: Vec<&str> = payload.splitn(3, ':').collect();
    if fields.len() != 3 {
        return None;
    }
    let expires_at: u64 = fields[2].parse().ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now > expires_at {
        return None;
    }
    Some(SessionInfo {
        user: fields[0].to_string(),
        access_key: fields[1].to_string(),
        expires_at,
        tenant: String::new(),
        display_name: String::new(),
        email: String::new(),
    })
}

fn sign_payload(payload: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(TOKEN_SECRET).expect("HMAC key");
    mac.update(payload.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn base64_encode(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
}

fn base64_decode(s: &str) -> Option<String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .ok()?;
    String::from_utf8(bytes).ok()
}

// ============================================================
// Self-service: My Account (any authenticated user)
// ============================================================

/// GET /_console/api/me/keys — list own access keys
pub async fn my_list_keys(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let session = match validate_session_from_headers(&headers) {
        Some(s) => s,
        None => return (StatusCode::UNAUTHORIZED, "No session").into_response(),
    };

    // The session user is a user_id (UUID). Look up their access keys.
    let mut client = state.meta_client.clone();
    match client
        .list_access_keys(objectio_proto::metadata::ListAccessKeysRequest {
            user_id: session.user.clone(),
        })
        .await
    {
        Ok(resp) => {
            let keys: Vec<serde_json::Value> = resp
                .into_inner()
                .access_keys
                .iter()
                .map(|k| {
                    serde_json::json!({
                        "access_key_id": k.access_key_id,
                        "status": k.status,
                        "created_at": k.created_at,
                    })
                })
                .collect();
            axum::Json(serde_json::json!({ "access_keys": keys })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.message().to_string()).into_response(),
    }
}

/// POST /_console/api/me/keys — create own access key
pub async fn my_create_key(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let session = match validate_session_from_headers(&headers) {
        Some(s) => s,
        None => return (StatusCode::UNAUTHORIZED, "No session").into_response(),
    };

    let mut client = state.meta_client.clone();
    match client
        .create_access_key(objectio_proto::metadata::CreateAccessKeyRequest {
            user_id: session.user.clone(),
            // Self-service console keys inherit the user's full access.
            scope: String::new(),
            operation: 0,
        })
        .await
    {
        Ok(resp) => {
            let key = resp.into_inner().access_key.unwrap_or_default();
            axum::Json(serde_json::json!({
                "access_key_id": key.access_key_id,
                "secret_access_key": key.secret_access_key,
                "created_at": key.created_at,
            }))
            .into_response()
        }
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

/// DELETE /_console/api/me/keys/{key_id} — delete own access key
pub async fn my_delete_key(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    axum::extract::Path(key_id): axum::extract::Path<String>,
) -> Response {
    let session = match validate_session_from_headers(&headers) {
        Some(s) => s,
        None => return (StatusCode::UNAUTHORIZED, "No session").into_response(),
    };

    // Verify the key belongs to this user first
    let mut client = state.meta_client.clone();
    if let Ok(resp) = client
        .list_access_keys(objectio_proto::metadata::ListAccessKeysRequest {
            user_id: session.user.clone(),
        })
        .await
    {
        let owns_key = resp
            .into_inner()
            .access_keys
            .iter()
            .any(|k| k.access_key_id == key_id);
        if !owns_key {
            return (StatusCode::FORBIDDEN, "Key does not belong to you").into_response();
        }
    }

    match client
        .delete_access_key(objectio_proto::metadata::DeleteAccessKeyRequest {
            access_key_id: key_id,
        })
        .await
    {
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, e.message().to_string()).into_response(),
    }
}

// ============================================================
// OIDC SSO Login
// ============================================================

/// GET /_console/api/oidc/enabled — check if OIDC is configured, list providers.
///
/// Filtered by listener kind so the login page only surfaces buttons
/// that can lead to a usable session on this listener:
///
/// - **TenantConsole** returns an empty provider list. Tenant SSO is
///   discovered via `/_console/api/tenant/{name}/sso` (the AWS-style
///   per-account lookup) — the global `User SSO` button would just
///   round-trip through Entra and then get refused by the audience
///   gate in `oidc_callback`, so we don't show it.
/// - **OpsConsole** returns only providers flagged `system_admin: true`
///   (plus the global `--oidc-*` provider, which is implicitly
///   system-admin). Tenant-bound providers don't belong here.
/// - **Legacy / AdminApi / Data** return everything (pre-split
///   behavior preserved).
pub async fn oidc_enabled(
    State(state): State<Arc<ConsoleOidcState>>,
    listener: Option<Extension<ListenerKind>>,
) -> Json<serde_json::Value> {
    let kind = listener.map(|l| l.0).unwrap_or(ListenerKind::Legacy);

    if kind == ListenerKind::TenantConsole {
        return Json(serde_json::json!({"enabled": false, "providers": []}));
    }

    let only_system_admin = kind == ListenerKind::OpsConsole;
    let has_global = state.oidc_provider.is_some();

    let mut providers = Vec::new();

    let mut client = state.meta_client.clone();
    if let Ok(resp) = client
        .list_config(objectio_proto::metadata::ListConfigRequest {
            prefix: "identity/openid/".to_string(),
        })
        .await
    {
        for entry in &resp.into_inner().entries {
            let provider_name = entry
                .key
                .strip_prefix("identity/openid/")
                .unwrap_or(&entry.key);
            if let Ok(config) = serde_json::from_slice::<serde_json::Value>(&entry.value) {
                let display = config
                    .get("display_name")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("SSO");
                let enabled = config
                    .get("enabled")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                let system_admin = config
                    .get("system_admin")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if !enabled {
                    continue;
                }
                // Ops console only surfaces system-admin-flagged providers.
                if only_system_admin && !system_admin {
                    continue;
                }
                providers.push(serde_json::json!({
                    "name": provider_name,
                    "label": format!("User SSO{}", if display != "SSO" { format!(" ({display})") } else { String::new() }),
                }));
            }
        }
    }

    // Global `--oidc-*` provider is implicitly system-admin scoped, so
    // skip it on listeners that don't want system-admin SSO buttons.
    let surface_global = has_global && !matches!(kind, ListenerKind::TenantConsole);
    if surface_global {
        providers.insert(
            0,
            serde_json::json!({
                "name": "system",
                "label": "System SSO",
            }),
        );
    }

    Json(serde_json::json!({
        "enabled": surface_global || !providers.is_empty(),
        "providers": providers,
        // The exact redirect URI the gateway will send to the IdP, so the
        // console can tell an operator what to register. It is derived from
        // --external-endpoint and is the same for every provider and tenant
        // (provider and tenant travel in the OAuth `state`, not the URL), so
        // it is reported rather than configured per provider.
        "callback_url": format!("{}/_console/api/oidc/callback", state.external_endpoint),
        // True when --external-endpoint was never set, in which case the
        // callback above is built from the bind address and no IdP will
        // accept it. Surfaced so the console can say so instead of handing
        // over a URL that silently cannot work.
        "callback_url_is_default": state.external_endpoint.starts_with("http://0.0.0.0")
            || state.external_endpoint.starts_with("http://127.0.0.1")
            || state.external_endpoint.starts_with("http://localhost"),
    }))
}

/// Query params for authorize
#[derive(Deserialize, Default)]
pub struct AuthorizeParams {
    /// OIDC provider name (e.g. "system" for global, "entra" for a stored config)
    #[serde(default)]
    pub provider: String,
    /// Tenant name (looks up tenant's oidc_provider)
    #[serde(default)]
    pub tenant: String,
}

/// `GET /_console/api/tenant/{name}/sso` — what does the login page need
/// to render for this tenant? No auth required — the answer is just
/// "is there an SSO button to show, and what should it say".
///
/// This is the AWS-style "account login" lookup: a user lands on
/// `/_console/?tenant=corerun`, the page hits this endpoint, and we
/// reply with whether to show an SSO button (and its label) or not.
/// Returning a 404 for unknown tenants is intentional — leaks fewer
/// tenant names than returning `{exists:false}`.
pub async fn tenant_sso_info(
    State(state): State<Arc<ConsoleOidcState>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> Response {
    let mut client = state.meta_client.clone();
    let tenant = match client
        .get_tenant(objectio_proto::metadata::GetTenantRequest { name: name.clone() })
        .await
    {
        Ok(resp) => {
            let r = resp.into_inner();
            if !r.found {
                return (StatusCode::NOT_FOUND, "tenant not found").into_response();
            }
            match r.tenant {
                Some(t) => t,
                None => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
            }
        }
        Err(_) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
    };

    if tenant.oidc_provider.is_empty() {
        return Json(serde_json::json!({
            "tenant": name,
            "display_name": tenant.display_name,
            "sso_enabled": false,
        }))
        .into_response();
    }

    Json(serde_json::json!({
        "tenant": name,
        "display_name": tenant.display_name,
        "sso_enabled": true,
        "provider_name": tenant.oidc_provider,
    }))
    .into_response()
}

/// GET /_console/api/oidc/authorize — redirect to OIDC provider
pub async fn oidc_authorize(
    State(state): State<Arc<ConsoleOidcState>>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    // Resolve the OIDC provider: by provider name, by tenant, or global default
    let (oidc, tenant_name) = if !params.provider.is_empty() && params.provider != "system" {
        // Look up named provider from config store
        let mut client = state.meta_client.clone();
        let config_key = format!("identity/openid/{}", params.provider);
        match client
            .get_config(objectio_proto::metadata::GetConfigRequest { key: config_key })
            .await
        {
            Ok(resp) => {
                let entry = resp.into_inner().entry.unwrap_or_default();
                match serde_json::from_slice::<serde_json::Value>(&entry.value) {
                    Ok(config) => match build_oidc_provider_from_config(&config) {
                        Some(p) => (p, params.tenant.clone()),
                        None => {
                            return (StatusCode::BAD_REQUEST, "Invalid OIDC config")
                                .into_response();
                        }
                    },
                    Err(_) => {
                        return (StatusCode::BAD_REQUEST, "Invalid OIDC config").into_response();
                    }
                }
            }
            Err(_) => return (StatusCode::NOT_FOUND, "OIDC provider not found").into_response(),
        }
    } else if !params.tenant.is_empty() {
        // Look up tenant's OIDC provider
        let mut client = state.meta_client.clone();
        match client
            .get_tenant(objectio_proto::metadata::GetTenantRequest {
                name: params.tenant.clone(),
            })
            .await
        {
            Ok(resp) => {
                let tc = resp.into_inner().tenant.unwrap_or_default();
                if tc.oidc_provider.is_empty() {
                    return (
                        StatusCode::BAD_REQUEST,
                        "Tenant has no OIDC provider configured",
                    )
                        .into_response();
                }
                let config_key = format!("identity/openid/{}", tc.oidc_provider);
                match client
                    .get_config(objectio_proto::metadata::GetConfigRequest { key: config_key })
                    .await
                {
                    Ok(resp2) => {
                        let entry = resp2.into_inner().entry.unwrap_or_default();
                        match serde_json::from_slice::<serde_json::Value>(&entry.value) {
                            Ok(config) => match build_oidc_provider_from_config(&config) {
                                Some(p) => (p, params.tenant.clone()),
                                None => {
                                    return (StatusCode::BAD_REQUEST, "Invalid OIDC config")
                                        .into_response();
                                }
                            },
                            Err(_) => {
                                return (StatusCode::BAD_REQUEST, "Invalid OIDC config")
                                    .into_response();
                            }
                        }
                    }
                    Err(_) => {
                        return (StatusCode::NOT_FOUND, "OIDC provider config not found")
                            .into_response();
                    }
                }
            }
            Err(_) => return (StatusCode::NOT_FOUND, "Tenant not found").into_response(),
        }
    } else {
        // Global default
        match state.oidc_provider.as_ref() {
            Some(p) => ((**p).clone(), String::new()),
            None => return (StatusCode::BAD_REQUEST, "OIDC not configured").into_response(),
        }
    };

    let auth_endpoint = match oidc.resolve_authorization_endpoint().await {
        Ok(ep) => ep,
        Err(e) => {
            warn!("Failed to resolve OIDC authorization endpoint: {e}");
            // Return the detail rather than a bare "discovery failed". This is
            // reached by an operator who has just configured a provider, and
            // the useful part — the provider's own rejection, e.g. a tenant
            // that does not exist — is otherwise only visible in the gateway
            // log. The discovery URL is the configured issuer, which is sent
            // to the browser in the redirect anyway.
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("OIDC discovery failed: {e}"),
            )
                .into_response();
        }
    };

    let callback_url = format!("{}/_console/api/oidc/callback", state.external_endpoint);

    // Encode provider + tenant in state for callback resolution
    let csrf = format!("{:x}", uuid::Uuid::new_v4().as_u128());
    let state_value = format!(
        "{}:{}:{}",
        csrf,
        params.provider.replace(':', "_"),
        tenant_name.replace(':', "_")
    );

    let config = oidc.config();
    let auth_url = format!(
        "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}&response_mode=query",
        auth_endpoint,
        urlencoding::encode(&config.client_id),
        urlencoding::encode(&callback_url),
        urlencoding::encode(&config.scopes),
        urlencoding::encode(&state_value),
    );

    debug!(
        "OIDC authorize redirect (provider={}, tenant={}): {}",
        params.provider, tenant_name, auth_url
    );

    let state_cookie =
        format!("oidc-state={state_value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600");

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, auth_url)
        .header(header::SET_COOKIE, state_cookie)
        .body(axum::body::Body::empty())
        .unwrap()
}

/// Callback query params from OIDC provider
#[derive(Deserialize)]
pub struct OidcCallbackParams {
    pub code: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

/// GET /_console/api/oidc/callback — handle OIDC provider redirect
pub async fn oidc_callback(
    State(state): State<Arc<ConsoleOidcState>>,
    listener: Option<Extension<ListenerKind>>,
    headers: HeaderMap,
    Query(params): Query<OidcCallbackParams>,
) -> Response {
    // Check for error from provider
    if let Some(ref err) = params.error {
        warn!(
            "OIDC callback error: {} {:?}",
            err, params.error_description
        );
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(
                header::LOCATION,
                format!(
                    "/_console/?error={}",
                    urlencoding::encode(params.error_description.as_deref().unwrap_or(err))
                ),
            )
            .body(axum::body::Body::empty())
            .unwrap();
    }

    // Validate CSRF state
    let state_cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix("oidc-state=").map(String::from)
            })
        })
        .unwrap_or_default();

    if state_cookie.is_empty() || state_cookie != params.state {
        warn!("OIDC callback: state mismatch");
        return Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/_console/?error=Invalid+state")
            .body(axum::body::Body::empty())
            .unwrap();
    }

    // Parse state: "csrf:provider:tenant"
    let state_parts: Vec<&str> = params.state.splitn(3, ':').collect();
    let provider_name = state_parts.get(1).unwrap_or(&"").to_string();
    let tenant_from_state = state_parts.get(2).unwrap_or(&"").to_string();

    // Resolve OIDC provider (same logic as authorize). Also captures
    // the provider's `system_admin` flag — when true, a user
    // authenticated through this provider lands on the system-admin
    // console even if no tenant maps to the provider.
    let (oidc, provider_is_system_admin, tenancy) = if !provider_name.is_empty()
        && provider_name != "system"
    {
        let mut client = state.meta_client.clone();
        let config_key = format!("identity/openid/{provider_name}");
        match client
            .get_config(objectio_proto::metadata::GetConfigRequest { key: config_key })
            .await
        {
            Ok(resp) => {
                let entry = resp.into_inner().entry.unwrap_or_default();
                let config_json: Option<serde_json::Value> =
                    serde_json::from_slice(&entry.value).ok();
                let system_admin = config_json
                    .as_ref()
                    .and_then(|c| c.get("system_admin"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let tenancy = config_json
                    .as_ref()
                    .map(ProviderTenancy::from_config)
                    .unwrap_or_else(|| ProviderTenancy::from_config(&serde_json::json!({})));
                match config_json.and_then(|c| build_oidc_provider_from_config(&c)) {
                    Some(p) => (p, system_admin, tenancy),
                    None => {
                        return Response::builder()
                            .status(StatusCode::FOUND)
                            .header(header::LOCATION, "/_console/?error=Invalid+provider+config")
                            .body(axum::body::Body::empty())
                            .unwrap();
                    }
                }
            }
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header(header::LOCATION, "/_console/?error=Provider+not+found")
                    .body(axum::body::Body::empty())
                    .unwrap();
            }
        }
    } else {
        // Global provider from --oidc-* CLI args is implicitly
        // system-admin scoped.
        match state.oidc_provider.as_ref() {
            // A provider configured from CLI flags has no stored document, so
            // it is single-tenant with no self-registration.
            Some(p) => (
                (**p).clone(),
                true,
                ProviderTenancy::from_config(&serde_json::json!({})),
            ),
            None => {
                return (StatusCode::BAD_REQUEST, "OIDC not configured").into_response();
            }
        }
    };

    // Exchange authorization code for tokens
    let callback_url = format!("{}/_console/api/oidc/callback", state.external_endpoint);
    let token_resp = match oidc
        .exchange_authorization_code(&params.code, &callback_url)
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            warn!("OIDC token exchange failed: {e}");
            return Response::builder()
                .status(StatusCode::FOUND)
                .header(
                    header::LOCATION,
                    format!(
                        "/_console/?error={}",
                        urlencoding::encode(&format!("Token exchange failed: {e}"))
                    ),
                )
                .body(axum::body::Body::empty())
                .unwrap();
        }
    };

    // Validate the token and extract identity
    // Try id_token first (has user claims), fall back to access_token
    let token_to_validate = token_resp
        .id_token
        .as_deref()
        .unwrap_or(&token_resp.access_token);

    let (user_id, groups, upstream_tid) = match oidc.validate_token(token_to_validate).await {
        Ok(claims) => {
            let sub = claims
                .extra
                .get("preferred_username")
                .or(claims.extra.get("email"))
                .and_then(|v| v.as_str())
                .unwrap_or(&claims.sub)
                .to_string();
            let groups = oidc.extract_groups(&claims);
            // Present on Entra tokens; absent elsewhere, in which case there
            // is no upstream tenant to key self-registration on.
            let tid = objectio_auth::OidcProvider::tenant_id(&claims);
            (sub, groups, tid)
        }
        Err(e) => {
            warn!("OIDC token validation failed: {e}");
            return Response::builder()
                .status(StatusCode::FOUND)
                .header(header::LOCATION, "/_console/?error=Token+validation+failed")
                .body(axum::body::Body::empty())
                .unwrap();
        }
    };

    // Resolve tenant: from state, or look up which tenant uses this
    // provider. If the provider is flagged as system_admin AND no
    // tenant maps to it, fall through to system-admin login instead
    // of erroring — that's the new behavior set by the "Allow
    // system-admin SSO" checkbox on the Identity page.
    let tenant = if !tenant_from_state.is_empty() {
        tenant_from_state
    } else if tenancy.multi_tenant && !provider_name.is_empty() && provider_name != "system" {
        // Multi-tenant provider: the ObjectIO tenant follows the *upstream*
        // tenant the user signed in from, and is created on first contact.
        // Without a `tid` there is nothing to key on, so the login is refused
        // rather than silently landing everyone in one shared tenant.
        let Some(tid) = upstream_tid.clone() else {
            warn!(
                "provider '{provider_name}' is multi-tenant but the token carries no \
                 usable tid — login denied"
            );
            return Response::builder()
                .status(StatusCode::FOUND)
                .header(
                    header::LOCATION,
                    "/_console/?error=Token+has+no+tenant+claim",
                )
                .body(axum::body::Body::empty())
                .unwrap();
        };
        let mut t_client = state.meta_client.clone();
        match resolve_or_register_tenant(&mut t_client, &tenancy, &provider_name, &tid, &user_id)
            .await
        {
            Ok(name) => name,
            Err(e) => {
                warn!("tenant self-registration failed for tid={tid}: {e}");
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header(
                        header::LOCATION,
                        format!("/_console/?error={}", urlencoding::encode(&e)),
                    )
                    .body(axum::body::Body::empty())
                    .unwrap();
            }
        }
    } else if !provider_name.is_empty() && provider_name != "system" {
        // Single-tenant provider: exactly one tenant is bound to it, and
        // nothing is created automatically.
        let mut t_client = state.meta_client.clone();
        let resolved = if let Ok(resp) = t_client
            .list_tenants(objectio_proto::metadata::ListTenantsRequest {})
            .await
        {
            resp.into_inner()
                .tenants
                .iter()
                .find(|t| t.oidc_provider == provider_name)
                .map(|t| t.name.clone())
        } else {
            None
        };
        match resolved {
            Some(t) => t,
            None if provider_is_system_admin => {
                // Intentional: operator enabled "Allow system-admin SSO".
                String::new()
            }
            None => {
                warn!(
                    "OIDC provider '{}' not mapped to any tenant and not flagged \
                     system_admin — login denied",
                    provider_name
                );
                return Response::builder()
                    .status(StatusCode::FOUND)
                    .header(
                        header::LOCATION,
                        "/_console/?error=No+tenant+configured+for+this+provider",
                    )
                    .body(axum::body::Body::empty())
                    .unwrap();
            }
        }
    } else {
        String::new() // system admin (global SSO)
    };

    // Auto-provision OIDC user in meta service (idempotent)
    let mut meta = state.meta_client.clone();
    let provisioned_user_id = match meta
        .create_user(objectio_proto::metadata::CreateUserRequest {
            display_name: user_id.clone(),
            email: String::new(),
            tenant: tenant.clone(),
        })
        .await
    {
        Ok(resp) => resp
            .into_inner()
            .user
            .map(|u| u.user_id)
            .unwrap_or(user_id.clone()),
        Err(e) => {
            // Already exists — look up by display name
            if e.code() == tonic::Code::AlreadyExists {
                // Find user by listing and matching display name
                if let Ok(resp) = meta
                    .list_users(objectio_proto::metadata::ListUsersRequest {
                        max_results: 1000,
                        marker: String::new(),
                    })
                    .await
                {
                    resp.into_inner()
                        .users
                        .iter()
                        .find(|u| u.display_name == user_id)
                        .map(|u| u.user_id.clone())
                        .unwrap_or(user_id.clone())
                } else {
                    user_id.clone()
                }
            } else {
                debug!("Failed to auto-provision OIDC user: {e}");
                user_id.clone()
            }
        }
    };

    // Promote to tenant admin when the token carries the provider's configured
    // admin role. Done after provisioning so the ARN exists, and on every
    // login so a change in the customer's IdP takes effect on their next
    // sign-in rather than needing us to touch anything.
    if !tenant.is_empty() {
        let user_arn = format!("arn:objectio:iam::{tenant}:user/{user_id}");
        apply_tenant_admin_role(&mut meta, &tenancy, &tenant, &user_arn, &groups).await;
    }

    // Per-listener audience gate (mirror of the AK/SK login gate in
    // `console_login`). The redirect-based OIDC flow can land on
    // either the ops or tenant listener depending on which "Sign in"
    // button the user clicked; the resolved tenant tells us where
    // the resulting session would be valid. If the listener and the
    // tenant don't match, redirect back to the SPA with an error
    // instead of minting a usable cross-portal session.
    if let Some(Extension(kind)) = listener {
        let mismatch = match kind {
            ListenerKind::OpsConsole => !tenant.is_empty(),
            ListenerKind::TenantConsole => tenant.is_empty(),
            _ => false,
        };
        if mismatch {
            warn!(
                "OIDC callback refused on {:?}: resolved tenant='{}' does not match listener audience",
                kind, tenant
            );
            let msg = if tenant.is_empty() {
                "System-admin SSO is only on the ops console"
            } else {
                "Tenant SSO is only on the tenant console"
            };
            return Response::builder()
                .status(StatusCode::FOUND)
                .header(
                    header::LOCATION,
                    format!("/_console/?error={}", urlencoding::encode(msg)),
                )
                .body(axum::body::Body::empty())
                .unwrap();
        }
    }

    // Build session cookie (same format as AK/SK login)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires = now + SESSION_TTL_SECS;
    // tenant already resolved above

    let payload = format!("{provisioned_user_id}|oidc|{tenant}|{expires}");
    let sig = sign_payload(&payload);
    let token = format!("{payload}|{sig}");
    let token_b64 = base64_encode(&token);

    let session_cookie = format!(
        "objectio-session={token_b64}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECS}"
    );

    // Clear state cookie + set session cookie + redirect to console
    let clear_state = "oidc-state=; Path=/; HttpOnly; Max-Age=0";

    debug!(
        "OIDC login successful: oidc_sub={}, provisioned_id={}",
        user_id, provisioned_user_id
    );

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, "/_console/")
        .header(header::SET_COOKIE, session_cookie)
        .header("Set-Cookie", clear_state)
        .body(axum::body::Body::empty())
        .unwrap()
}

#[cfg(test)]
mod audience_tests {
    use super::*;

    #[test]
    fn path_identifies_the_surface() {
        assert_eq!(
            console_audience("/_console/admin/users", None),
            ConsoleAudience::Ops
        );
        assert_eq!(
            console_audience("/_console/tenant/buckets", None),
            ConsoleAudience::Tenant
        );
        assert_eq!(
            console_audience("/_console/", None),
            ConsoleAudience::Unscoped
        );
    }

    #[test]
    fn listener_still_works_when_there_is_no_path_signal() {
        assert_eq!(
            console_audience("/", Some(ListenerKind::OpsConsole)),
            ConsoleAudience::Ops
        );
        assert_eq!(
            console_audience("/", Some(ListenerKind::TenantConsole)),
            ConsoleAudience::Tenant
        );
        // The admin API listener is gated like the operator surface.
        assert_eq!(
            console_audience("/", Some(ListenerKind::AdminApi)),
            ConsoleAudience::Ops
        );
        // Legacy deliberately gates nothing.
        assert_eq!(
            console_audience("/", Some(ListenerKind::Legacy)),
            ConsoleAudience::Unscoped
        );
    }

    /// The path is the more specific signal, so it wins. This is what lets a
    /// single-port deployment host both surfaces on one listener.
    #[test]
    fn path_wins_over_the_listener() {
        assert_eq!(
            console_audience("/_console/tenant/x", Some(ListenerKind::OpsConsole)),
            ConsoleAudience::Tenant
        );
        assert_eq!(
            console_audience("/_console/admin/x", Some(ListenerKind::Legacy)),
            ConsoleAudience::Ops
        );
    }
}

#[cfg(test)]
mod tenancy_tests {
    use super::*;

    #[test]
    fn tenancy_defaults_to_single_with_a_2gb_allowance() {
        let t = ProviderTenancy::from_config(&serde_json::json!({}));
        assert!(
            !t.multi_tenant,
            "a provider is single-tenant unless it says otherwise"
        );
        assert_eq!(t.quota_bytes, 2 * 1024 * 1024 * 1024);
        assert!(t.tenant_admin_role.is_empty());
        // No allowlist means open registration, which is what `common` implies.
        assert!(t.allowed_tids.is_empty());
        assert!(t.admits("any-tid"));
    }

    #[test]
    fn multi_tenant_is_opt_in_and_case_insensitive() {
        assert!(
            ProviderTenancy::from_config(&serde_json::json!({"tenancy": "multi"})).multi_tenant
        );
        assert!(
            ProviderTenancy::from_config(&serde_json::json!({"tenancy": "MULTI"})).multi_tenant
        );
        assert!(
            !ProviderTenancy::from_config(&serde_json::json!({"tenancy": "single"})).multi_tenant
        );
    }

    #[test]
    fn an_allowlist_closes_registration_to_everyone_else() {
        let t = ProviderTenancy::from_config(&serde_json::json!({
            "tenancy": "multi",
            "allowed_tids": ["aaa", "bbb"]
        }));
        assert!(t.admits("aaa"));
        assert!(!t.admits("ccc"));
    }

    #[test]
    fn quota_is_configurable_per_provider() {
        let t = ProviderTenancy::from_config(&serde_json::json!({"tenant_quota_bytes": 5000}));
        assert_eq!(t.quota_bytes, 5000);
        // Explicit zero means unlimited, and must not be read as "unset".
        let t = ProviderTenancy::from_config(&serde_json::json!({"tenant_quota_bytes": 0}));
        assert_eq!(t.quota_bytes, 0);
    }

    #[test]
    fn tenant_name_comes_from_the_sign_in_domain() {
        assert_eq!(derive_tenant_name("alice@acme.com", "TID"), "acme.com");
        assert_eq!(
            derive_tenant_name("bob@sub.example.co.uk", "TID"),
            "sub.example.co.uk"
        );
    }

    #[test]
    fn tenant_name_falls_back_to_the_tid_when_there_is_no_domain() {
        // No domain at all, or something that is not domain-shaped.
        assert_eq!(derive_tenant_name("alice", "the-tid"), "the-tid");
        assert_eq!(derive_tenant_name("alice@localhost", "the-tid"), "the-tid");
    }

    #[test]
    fn tenant_name_is_sanitised() {
        // Whatever the IdP sends, the name stays to a safe character set.
        assert_eq!(derive_tenant_name("a@AC ME.com", "t"), "ac-me.com");
        assert_eq!(derive_tenant_name("a@ac/me.com", "t"), "ac-me.com");
    }
}
