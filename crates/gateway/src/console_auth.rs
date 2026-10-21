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
pub(crate) fn build_oidc_provider_from_config(
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

    // Match on the immutable upstream id, never the name; and only a tenant
    // this provider serves.
    if let Some(t) = existing
        .iter()
        .find(|t| t.labels.get(OIDC_TID_LABEL).is_some_and(|v| v == tid))
    {
        if !provider_binds_tenant(provider_name, t) {
            return Err(format!(
                "upstream tenant {tid} is registered through another provider"
            ));
        }
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

/// Query for `GET /_console/api/oidc/enabled`.
#[derive(Debug, Default, serde::Deserialize)]
pub struct EnabledParams {
    /// `signup` lists the providers an organisation can register through,
    /// rather than the providers valid for signing in to this surface.
    #[serde(default)]
    pub purpose: String,
}

/// Base path of a console surface, with a trailing slash.
///
/// Every redirect out of the OIDC flow has to land on a real surface. There is
/// no bundle at `/_console/` — the build produces the operator and tenant
/// bundles only — so sending anyone there yields a blank page.
#[must_use]
pub fn console_base(audience: ConsoleAudience) -> &'static str {
    match audience {
        ConsoleAudience::Tenant => "/_console/tenant/",
        // An unscoped request has no surface of its own; the operator console
        // is the safe landing place, and a tenant session that reaches it is
        // refused by the audience gate rather than silently accepted.
        ConsoleAudience::Ops | ConsoleAudience::Unscoped => "/_console/admin/",
    }
}

/// Where a completed login should land, given the tenant it resolved to.
///
/// Driven by the session that was actually minted rather than by where the
/// flow began: a tenant login belongs on the tenant console even if it was
/// started from an operator URL, and vice versa.
#[must_use]
pub fn landing_for_tenant(tenant: &str) -> &'static str {
    if tenant.is_empty() {
        "/_console/admin/"
    } else {
        "/_console/tenant/"
    }
}

/// Which console surface a request belongs to.
///
/// Two signals can say this now. A dedicated listener carries a
/// [`ListenerKind`]; a single-port deployment distinguishes the surfaces by
/// path instead (`/_console/admin` vs `/_console/tenant`). The path is the
/// more specific of the two, so it wins where both are present — on the
/// combined listener the path is the *only* signal, since `ListenerKind::Combined`
/// deliberately gates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleAudience {
    /// Operator surface: system-admin sessions only.
    Ops,
    /// Self-service surface: tenant sessions only.
    Tenant,
    /// Nothing to enforce: the combined listener, or a non-console one.
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
    /// `--listen` in single-port mode (the default) — one port carrying
    /// everything. No login restrictions.
    Combined,
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

/// The key console session tokens are signed with: derived from the
/// cluster's secret at startup (`set_session_key`), so every gateway
/// accepts every gateway's sessions. It was a constant in this source file.
static SESSION_KEY: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

/// Set the session signing key, once, at startup.
pub fn set_session_key(key: Vec<u8>) {
    let _ = SESSION_KEY.set(key);
}

fn session_key() -> &'static [u8] {
    // Unset (a test, or a gateway not started through `run`): a random key
    // for this process, never a guessable one.
    SESSION_KEY.get_or_init(|| {
        let mut k = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut k);
        k
    })
}

/// Session token validity: 24 hours
const SESSION_TTL_SECS: u64 = 86400;

/// How long a sign-on may take between leaving for the provider and coming
/// back: the life of its `state`.
const OIDC_STATE_TTL_SECS: u64 = 600;

/// What each signed value is for, mixed into its MAC: a value signed for one
/// purpose is never accepted for another (an OAuth `state` as a session).
const SESSION_PURPOSE: &str = "console-session";
const OIDC_STATE_PURPOSE: &str = "oidc-state";

/// What a console session carries. Signed as a whole, so none of it can be
/// changed without the session key.
#[derive(Serialize, Deserialize)]
struct SessionClaims {
    /// The user's id.
    u: String,
    /// The access key the session was opened with; `oidc` for a sign-on.
    k: String,
    /// The user's tenant; empty for the system scope.
    t: String,
    /// The user's ARN.
    a: String,
    /// Whether the session acts as a system administrator. Decided at
    /// sign-in: the system admin's own keys, or the operator's identity
    /// provider. A system-scope user is not one by being in the system
    /// scope.
    sa: bool,
    /// Expiry, Unix seconds.
    exp: u64,
}

/// What a sign-on's OAuth `state` carries through the provider and back.
/// Signed, so the provider and tenant the callback acts on are the ones
/// this gateway chose, not whatever came back in the URL.
#[derive(Serialize, Deserialize)]
struct OidcState {
    /// Random: ties the callback to the browser that started the flow,
    /// through the `oidc-state` cookie.
    n: String,
    /// The provider's name; `system` for the gateway's `--oidc-*` one.
    p: String,
    /// The tenant the user asked to sign in to; empty for none.
    t: String,
    /// Expiry, Unix seconds.
    exp: u64,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn mac(purpose: &str, body: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(session_key()).expect("HMAC key");
    mac.update(purpose.as_bytes());
    mac.update(&[0]);
    mac.update(body.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// `value` as `base64url(json).hex(mac)`, signed for `purpose`.
fn seal<T: Serialize>(purpose: &str, value: &T) -> String {
    use base64::Engine;
    let json = serde_json::to_vec(value).unwrap_or_default();
    let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
    let sig = mac(purpose, &body);
    format!("{body}.{sig}")
}

/// What [`seal`] made for `purpose`, if `token` is one and is unchanged.
fn unseal<T: serde::de::DeserializeOwned>(purpose: &str, token: &str) -> Option<T> {
    use base64::Engine;
    let (body, sig) = token.rsplit_once('.')?;
    if !constant_time_eq(sig.as_bytes(), mac(purpose, body).as_bytes()) {
        return None;
    }
    let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body)
        .ok()?;
    serde_json::from_slice(&json).ok()
}

/// A session token for this user, and when it expires.
fn mint_session(
    user_id: &str,
    access_key: &str,
    tenant: &str,
    arn: &str,
    system_admin: bool,
) -> (String, u64) {
    let exp = now_secs() + SESSION_TTL_SECS;
    let token = seal(
        SESSION_PURPOSE,
        &SessionClaims {
            u: user_id.to_string(),
            k: access_key.to_string(),
            t: tenant.to_string(),
            a: arn.to_string(),
            sa: system_admin,
            exp,
        },
    );
    (token, exp)
}

/// The session `token` stands for, if it is genuine and unexpired.
fn open_session(token: &str) -> Option<SessionInfo> {
    let c: SessionClaims = unseal(SESSION_PURPOSE, token)?;
    if now_secs() > c.exp {
        return None;
    }
    Some(SessionInfo {
        user: c.u,
        access_key: c.k,
        expires_at: c.exp,
        tenant: c.t,
        arn: c.a,
        system_admin: c.sa,
        display_name: String::new(),
        email: String::new(),
    })
}

/// A fresh, signed `state` for a sign-on through `provider` to `tenant`.
fn seal_oidc_state(provider: &str, tenant: &str) -> String {
    seal(
        OIDC_STATE_PURPOSE,
        &OidcState {
            n: format!("{:x}", uuid::Uuid::new_v4().as_u128()),
            p: provider.to_string(),
            t: tenant.to_string(),
            exp: now_secs() + OIDC_STATE_TTL_SECS,
        },
    )
}

/// The `state` this gateway issued, if `value` is one, unchanged and
/// unexpired.
fn open_oidc_state(value: &str) -> Option<OidcState> {
    let s: OidcState = unseal(OIDC_STATE_PURPOSE, value)?;
    (now_secs() <= s.exp).then_some(s)
}

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
    /// The user's ARN, as it was at sign-in.
    pub arn: String,
    /// Whether the session acts as a system administrator (see
    /// [`SessionClaims::sa`]).
    pub system_admin: bool,
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

    if !constant_time_eq(
        access_key_meta.secret_access_key.as_bytes(),
        body.secret_key.as_bytes(),
    ) {
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    }

    let user_id = access_key_meta.user_id;
    let Some(user) = resp.user else {
        return (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response();
    };
    let (tenant, display_name, email, arn) = (user.tenant, user.display_name, user.email, user.arn);
    // Known by its ARN, as over SigV4: not by having no tenant.
    let system_admin = arn == objectio_auth::SYSTEM_ADMIN_USER_ARN;
    if !tenant.is_empty() {
        match tenant_open(&mut client, &tenant).await {
            Ok(true) => {}
            Ok(false) => {
                warn!("console login refused: tenant '{tenant}' is disabled (user={user_id})");
                return (StatusCode::FORBIDDEN, "This tenant is disabled").into_response();
            }
            Err(e) => return crate::admin::meta_failure(&e),
        }
    }

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

    let (token, expires) = mint_session(&user_id, &body.access_key, &tenant, &arn, system_admin);
    let cookie = format!(
        "objectio-session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL_SECS}"
    );

    let session = SessionInfo {
        user: user_id,
        access_key: body.access_key,
        expires_at: expires,
        tenant: tenant.clone(),
        arn,
        system_admin,
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
    open_session(token_b64)
}

/// Refuse a request made with a console session of a tenant that is
/// disabled or no longer exists, within the same bound as a key of it
/// ([`crate::auth_middleware::AuthState::admit_tenant`]). A session is
/// signed and carries its tenant, so without this it outlived the tenant's
/// disabling by up to its 24 hours.
///
/// Runs inside the optional SigV4 layer: a request it authenticated was
/// admitted or refused there, and its session cookie, if any, is not what
/// it acts with. Signing in and out are let through: sign-in decides for
/// itself and refuses a disabled tenant.
pub async fn session_tenant_gate(
    State(auth): State<Arc<crate::auth_middleware::AuthState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let path = request.uri().path();
    let signs_in_or_out = path == "/_console/api/login" || path == "/_console/api/logout";
    let signed = request
        .extensions()
        .get::<objectio_auth::AuthResult>()
        .is_some_and(|a| a.auth_mode != objectio_auth::AuthMode::Anonymous);
    if !signs_in_or_out
        && !signed
        && let Some(session) = validate_session_from_headers(request.headers())
        && let Err(e) = auth
            .admit_tenant(
                &session.tenant,
                &format!("console session of user {}", session.user),
            )
            .await
    {
        return e.into_response();
    }
    next.run(request).await
}

/// Equal, compared in time that doesn't depend on where they differ.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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

    // Verify the key belongs to this user first; unable to tell, delete
    // nothing.
    let mut client = state.meta_client.clone();
    let owned = match client
        .list_access_keys(objectio_proto::metadata::ListAccessKeysRequest {
            user_id: session.user.clone(),
        })
        .await
    {
        Ok(resp) => resp.into_inner().access_keys,
        Err(e) => return crate::admin::meta_failure(&e),
    };
    if !owned.iter().any(|k| k.access_key_id == key_id) {
        return (StatusCode::FORBIDDEN, "Key does not belong to you").into_response();
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
/// - **Combined / AdminApi / Data** return everything (as before the split
///   behavior preserved).
pub async fn oidc_enabled(
    State(state): State<Arc<ConsoleOidcState>>,
    listener: Option<Extension<ListenerKind>>,
    Query(params): Query<EnabledParams>,
) -> Json<serde_json::Value> {
    let kind = listener.map(|l| l.0).unwrap_or(ListenerKind::Combined);

    // `?purpose=signup` asks a different question: not "who may sign in here"
    // but "which providers can an organisation register through". Only
    // multi-tenant providers can, since registration keys on the upstream
    // tenant in the token. Without this the registration screen has nothing
    // to offer — the tenant console lists no providers at all, and the
    // tenant-scoped SSO button needs a tenant that by definition does not
    // exist yet.
    let signup = params.purpose.eq_ignore_ascii_case("signup");

    if kind == ListenerKind::TenantConsole && !signup {
        return Json(serde_json::json!({"enabled": false, "providers": []}));
    }

    let only_system_admin = !signup && kind == ListenerKind::OpsConsole;
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
                // Registration is only possible through a provider that
                // federates many upstream tenants.
                if signup && !ProviderTenancy::from_config(&config).multi_tenant {
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
    // A provider from CLI flags has no stored document and is single-tenant,
    // so it can never be a registration route.
    let surface_global = has_global && !signup && !matches!(kind, ListenerKind::TenantConsole);
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
/// `/_console/?tenant=acme`, the page hits this endpoint, and we
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

/// Whether the provider stored as `provider` signs in users of `tenant`: the
/// tenant's own `t-<tenant>`, or the provider the tenant names. The same
/// rule STS applies to a tenant's roles.
#[must_use]
pub fn provider_binds_tenant(
    provider: &str,
    tenant: &objectio_proto::metadata::TenantConfig,
) -> bool {
    provider == format!("t-{}", tenant.name.to_lowercase())
        || (!tenant.oidc_provider.is_empty() && tenant.oidc_provider == provider)
}

/// The tenant a sign-on through a single-tenant provider lands in, given
/// the tenants the provider is bound to and the one the user asked for
/// (empty for none). Empty is the system scope, which only a system
/// provider bound to no tenant reaches.
///
/// # Errors
///
/// The message to show the user, when the provider does not serve the
/// tenant asked for, serves none and is not a system provider, or serves
/// several and none was asked for.
pub fn choose_tenant(
    bound: &[String],
    requested: &str,
    system_provider: bool,
) -> Result<String, &'static str> {
    if !requested.is_empty() {
        return if bound.iter().any(|t| t == requested) {
            Ok(requested.to_string())
        } else {
            Err("This identity provider does not sign in to that tenant")
        };
    }
    match bound {
        [only] => Ok(only.clone()),
        [] if system_provider => Ok(String::new()),
        [] => Err("No tenant configured for this provider"),
        _ => Err("This identity provider serves several tenants: sign in from your tenant's page"),
    }
}

/// Who a validated token says the user is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedIdentity {
    /// The token's `iss`: validation has checked it is the provider's.
    pub issuer: String,
    /// The token's `sub`: with the issuer, what identifies the user.
    pub subject: String,
    /// The name a user created for it is given: `preferred_username`, else
    /// the email, else the subject. Only a label: never used to find a user.
    pub name: String,
}

impl FederatedIdentity {
    /// The identity in `claims`, if they carry an issuer and a subject.
    #[must_use]
    pub fn from_claims(claims: &objectio_auth::Claims) -> Option<Self> {
        let issuer = claims
            .extra
            .get("iss")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())?
            .to_string();
        if claims.sub.is_empty() {
            return None;
        }
        let name = claims
            .extra
            .get("preferred_username")
            .and_then(|v| v.as_str())
            .or(claims.email.as_deref())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(&claims.sub)
            .to_string();
        Some(Self {
            issuer,
            subject: claims.sub.clone(),
            name,
        })
    }

    /// Whether `user` is the user of this identity in `tenant`.
    #[must_use]
    pub fn is(&self, user: &objectio_proto::metadata::UserMeta, tenant: &str) -> bool {
        !user.user_id.is_empty()
            && user.federated_issuer == self.issuer
            && user.federated_subject == self.subject
            && user.tenant == tenant
    }
}

/// A provider a console sign-on goes through.
struct LoginProvider {
    /// As stored (`identity/openid/<name>`); `system` for the gateway's
    /// `--oidc-*` provider.
    name: String,
    oidc: objectio_auth::OidcProvider,
    /// The gateway's own `--oidc-*` provider.
    global: bool,
    /// Signs in system administrators: the gateway's own provider, or a
    /// stored one with `system_admin`.
    system_admin: bool,
    tenancy: ProviderTenancy,
}

/// The provider named `name`, if it exists and is enabled.
async fn load_login_provider(
    state: &ConsoleOidcState,
    name: &str,
) -> Result<LoginProvider, (StatusCode, &'static str)> {
    if name.is_empty() || name == "system" {
        // A provider from CLI flags has no stored document: single-tenant,
        // no self-registration, and the operator's own.
        return state
            .oidc_provider
            .as_ref()
            .map(|p| LoginProvider {
                name: "system".to_string(),
                oidc: (**p).clone(),
                global: true,
                system_admin: true,
                tenancy: ProviderTenancy::from_config(&serde_json::json!({})),
            })
            .ok_or((StatusCode::BAD_REQUEST, "OIDC not configured"));
    }
    let resp = state
        .meta_client
        .clone()
        .get_config(objectio_proto::metadata::GetConfigRequest {
            key: format!("identity/openid/{name}"),
        })
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "OIDC provider not found"))?
        .into_inner();
    let entry = resp
        .entry
        .filter(|_| resp.found)
        .ok_or((StatusCode::NOT_FOUND, "OIDC provider not found"))?;
    let config: serde_json::Value = serde_json::from_slice(&entry.value)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid OIDC config"))?;
    if !config
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(true)
    {
        return Err((StatusCode::BAD_REQUEST, "OIDC provider is disabled"));
    }
    let oidc = build_oidc_provider_from_config(&config)
        .ok_or((StatusCode::BAD_REQUEST, "Invalid OIDC config"))?;
    Ok(LoginProvider {
        name: name.to_string(),
        oidc,
        global: false,
        system_admin: config
            .get("system_admin")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        tenancy: ProviderTenancy::from_config(&config),
    })
}

/// The tenant a sign-on through `provider` lands in (empty: the system
/// scope). Always one the provider is bound to; `requested`, the tenant
/// the user started from, only chooses among those.
async fn resolve_login_tenant(
    state: &ConsoleOidcState,
    provider: &LoginProvider,
    requested: &str,
    upstream_tid: Option<String>,
    upstream_user: &str,
) -> Result<String, String> {
    if provider.global {
        return if requested.is_empty() {
            Ok(String::new())
        } else {
            Err("The system identity provider does not sign in to a tenant".to_string())
        };
    }
    let mut meta = state.meta_client.clone();
    if provider.tenancy.multi_tenant {
        // The ObjectIO tenant follows the *upstream* tenant the user signed
        // in from, and is created on first contact. Without a `tid` there is
        // nothing to key on, so the login is refused rather than landing
        // everyone in one shared tenant.
        let Some(tid) = upstream_tid else {
            warn!(
                "provider '{}' is multi-tenant but the token carries no usable tid — login denied",
                provider.name
            );
            return Err("Token has no tenant claim".to_string());
        };
        let name = resolve_or_register_tenant(
            &mut meta,
            &provider.tenancy,
            &provider.name,
            &tid,
            upstream_user,
        )
        .await?;
        if !requested.is_empty() && requested != name {
            return Err("This sign-in belongs to another tenant".to_string());
        }
        return Ok(name);
    }
    let tenants = meta
        .list_tenants(objectio_proto::metadata::ListTenantsRequest {})
        .await
        .map_err(|_| "Tenant lookup failed".to_string())?
        .into_inner()
        .tenants;
    let bound: Vec<String> = tenants
        .iter()
        .filter(|t| provider_binds_tenant(&provider.name, t))
        .map(|t| t.name.clone())
        .collect();
    choose_tenant(&bound, requested, provider.system_admin).map_err(|e| {
        warn!(
            "OIDC sign-in through '{}' refused (tenant asked for: '{requested}'): {e}",
            provider.name
        );
        e.to_string()
    })
}

/// The user `identity` signs in as in `tenant`: the one created for it,
/// created now on its first sign-in.
async fn provision_federated_user(
    meta: &mut objectio_proto::metadata::metadata_service_client::MetadataServiceClient<
        tonic::transport::Channel,
    >,
    identity: &FederatedIdentity,
    tenant: &str,
) -> Result<objectio_proto::metadata::UserMeta, String> {
    let user = match meta
        .create_user(objectio_proto::metadata::CreateUserRequest {
            display_name: identity.name.clone(),
            tenant: tenant.to_string(),
            federated_issuer: identity.issuer.clone(),
            federated_subject: identity.subject.clone(),
            ..Default::default()
        })
        .await
    {
        Ok(resp) => resp.into_inner().user.unwrap_or_default(),
        Err(e) if e.code() == tonic::Code::AlreadyExists => {
            // Another user, made some other way or for another sign-on, has
            // this name. Taking it over would sign this person in as them.
            warn!(
                "OIDC sign-in refused: the name '{}' (iss={}, sub={}) belongs to another user",
                identity.name, identity.issuer, identity.subject
            );
            return Err("Another user already has this name: ask an administrator".to_string());
        }
        Err(e) if e.code() == tonic::Code::FailedPrecondition => {
            warn!("OIDC sign-in refused: {}", e.message());
            return Err(e.message().to_string());
        }
        Err(e) => {
            warn!("OIDC sign-in: could not provision the user: {e}");
            return Err("Could not create the user".to_string());
        }
    };
    // Whatever came back, only the user bound to this sign-on is signed in as.
    if !identity.is(&user, tenant) {
        warn!(
            "OIDC sign-in refused: meta answered user '{}', which is not bound to iss={}, sub={}",
            user.user_id, identity.issuer, identity.subject
        );
        return Err("Could not create the user".to_string());
    }
    if user.status != objectio_proto::metadata::UserStatus::UserActive as i32 {
        return Err("This user is not active".to_string());
    }
    Ok(user)
}

/// Whether `tenant` (non-empty) may be signed in to: it exists and is
/// enabled. A disabled tenant's users sign in to nothing.
///
/// # Errors
///
/// Meta could not say.
pub(crate) async fn tenant_open(
    meta: &mut objectio_proto::metadata::metadata_service_client::MetadataServiceClient<
        tonic::transport::Channel,
    >,
    tenant: &str,
) -> Result<bool, tonic::Status> {
    let r = meta
        .get_tenant(objectio_proto::metadata::GetTenantRequest {
            name: tenant.to_string(),
        })
        .await?
        .into_inner();
    Ok(crate::auth_middleware::tenant_is_open(&r))
}

/// Back to the console the flow started on, with `msg` to show.
fn login_error(base: &str, msg: &str) -> Response {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(
            header::LOCATION,
            format!("{base}?error={}", urlencoding::encode(msg)),
        )
        .body(axum::body::Body::empty())
        .unwrap()
}

/// GET /_console/api/oidc/authorize — redirect to OIDC provider
pub async fn oidc_authorize(
    State(state): State<Arc<ConsoleOidcState>>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    // The provider: by name, the tenant's, or the gateway's own.
    let provider_name = if !params.provider.is_empty() {
        params.provider.clone()
    } else if !params.tenant.is_empty() {
        let tenant = match state
            .meta_client
            .clone()
            .get_tenant(objectio_proto::metadata::GetTenantRequest {
                name: params.tenant.clone(),
            })
            .await
        {
            Ok(resp) => resp.into_inner().tenant.unwrap_or_default(),
            Err(_) => return (StatusCode::NOT_FOUND, "Tenant not found").into_response(),
        };
        if tenant.oidc_provider.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                "Tenant has no OIDC provider configured",
            )
                .into_response();
        }
        tenant.oidc_provider
    } else {
        "system".to_string()
    };
    let provider = match load_login_provider(&state, &provider_name).await {
        Ok(p) => p,
        Err((status, msg)) => return (status, msg).into_response(),
    };
    let oidc = &provider.oidc;

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

    // Provider and tenant travel in a signed state: the callback trusts only
    // what this gateway put there.
    let state_value = seal_oidc_state(&provider.name, &params.tenant);

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
        provider.name, params.tenant, auth_url
    );

    let state_cookie = format!(
        "oidc-state={state_value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={OIDC_STATE_TTL_SECS}"
    );

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
    /// Absent when the provider is reporting a failure rather than returning a
    /// grant — a cancelled consent screen sends `error` and no `code`. Required
    /// here, that made the whole request fail to deserialize with a 400 and a
    /// serde message, so the error branch below could never run.
    #[serde(default)]
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
    // The provider redirects to one fixed callback regardless of which console
    // the user started on, so the surface is recovered from the Referer. Every
    // error below returns them to where they came from instead of a path that
    // serves nothing.
    let referer = headers
        .get(header::REFERER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let base = console_base(console_audience(referer, listener.as_ref().map(|l| l.0)));

    // A callback with neither a grant nor an error is not something we can
    // act on; say so rather than attempting an exchange with an empty code.
    if params.code.is_empty() && params.error.is_none() {
        warn!("OIDC callback carried neither code nor error");
        return login_error(base, "Sign-in did not return a result");
    }

    // Check for error from provider
    if let Some(ref err) = params.error {
        warn!(
            "OIDC callback error: {} {:?}",
            err, params.error_description
        );
        return login_error(base, params.error_description.as_deref().unwrap_or(err));
    }

    // The state must be the one this browser was handed (the cookie), and one
    // this gateway signed.
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
    if state_cookie.is_empty()
        || !constant_time_eq(state_cookie.as_bytes(), params.state.as_bytes())
    {
        warn!("OIDC callback: state mismatch");
        return login_error(base, "Invalid state");
    }
    let Some(flow) = open_oidc_state(&params.state) else {
        warn!("OIDC callback: state not signed by this cluster, or expired");
        return login_error(base, "Invalid state");
    };

    let provider = match load_login_provider(&state, &flow.p).await {
        Ok(p) => p,
        Err((_, msg)) => return login_error(base, msg),
    };

    // Exchange authorization code for tokens
    let callback_url = format!("{}/_console/api/oidc/callback", state.external_endpoint);
    let token_resp = match provider
        .oidc
        .exchange_authorization_code(&params.code, &callback_url)
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            warn!("OIDC token exchange failed: {e}");
            return login_error(base, &format!("Token exchange failed: {e}"));
        }
    };

    // Validate the token and extract identity
    // Try id_token first (has user claims), fall back to access_token
    let token_to_validate = token_resp
        .id_token
        .as_deref()
        .unwrap_or(&token_resp.access_token);

    // Validation checks the signature, the audience, and that `iss` is this
    // provider's issuer.
    let (identity, groups, upstream_tid) =
        match provider.oidc.validate_token(token_to_validate).await {
            Ok(claims) => {
                let Some(identity) = FederatedIdentity::from_claims(&claims) else {
                    warn!("OIDC token has no issuer or subject");
                    return login_error(base, "Token validation failed");
                };
                let groups = provider.oidc.extract_groups(&claims);
                // Present on Entra tokens; absent elsewhere, in which case there
                // is no upstream tenant to key self-registration on.
                let tid = objectio_auth::OidcProvider::tenant_id(&claims);
                (identity, groups, tid)
            }
            Err(e) => {
                warn!("OIDC token validation failed: {e}");
                return login_error(base, "Token validation failed");
            }
        };

    let tenant = match resolve_login_tenant(
        &state,
        &provider,
        &flow.t,
        upstream_tid,
        &identity.name,
    )
    .await
    {
        Ok(t) => t,
        Err(e) => return login_error(base, &e),
    };

    let mut meta = state.meta_client.clone();
    if !tenant.is_empty() {
        match tenant_open(&mut meta, &tenant).await {
            Ok(true) => {}
            Ok(false) => {
                warn!("OIDC sign-in refused: tenant '{tenant}' is disabled");
                return login_error(base, "This tenant is disabled");
            }
            Err(e) => {
                warn!("OIDC sign-in: tenant lookup failed: {e}");
                return login_error(base, "Tenant lookup failed");
            }
        }
    }
    let user = match provision_federated_user(&mut meta, &identity, &tenant).await {
        Ok(u) => u,
        Err(e) => return login_error(base, &e),
    };

    // Promote to tenant admin when the token carries the provider's configured
    // admin role. Done after provisioning so the ARN exists, and on every
    // login so a change in the customer's IdP takes effect on their next
    // sign-in rather than needing us to touch anything. The provider is one
    // bound to this tenant, so its role claim is the tenant's to give.
    if !tenant.is_empty() {
        apply_tenant_admin_role(&mut meta, &provider.tenancy, &tenant, &user.arn, &groups).await;
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
            return login_error(base, msg);
        }
    }

    // The operator's identity provider signs in system administrators: the
    // system scope is reached only through one (`resolve_login_tenant`).
    let system_admin = tenant.is_empty() && provider.system_admin;
    let (token, _) = mint_session(&user.user_id, "oidc", &tenant, &user.arn, system_admin);
    let session_cookie = format!(
        "objectio-session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECS}"
    );

    // Clear state cookie + set session cookie + redirect to console
    let clear_state = "oidc-state=; Path=/; HttpOnly; Max-Age=0";

    debug!(
        "OIDC login successful: iss={}, sub={}, user={}, tenant={}",
        identity.issuer, identity.subject, user.user_id, tenant
    );

    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, landing_for_tenant(&tenant))
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
        // Combined deliberately gates nothing.
        assert_eq!(
            console_audience("/", Some(ListenerKind::Combined)),
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
            console_audience("/_console/admin/x", Some(ListenerKind::Combined)),
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

#[cfg(test)]
mod landing_tests {
    use super::*;

    /// Every redirect out of the OIDC flow must reach a surface that actually
    /// has a bundle. `/_console/` does not.
    #[test]
    fn a_base_is_always_a_real_surface() {
        for a in [
            ConsoleAudience::Ops,
            ConsoleAudience::Tenant,
            ConsoleAudience::Unscoped,
        ] {
            let b = console_base(a);
            assert!(b.ends_with('/'), "{b} must end with a slash");
            assert!(
                b == "/_console/admin/" || b == "/_console/tenant/",
                "{b} is not a served surface"
            );
        }
    }

    #[test]
    fn landing_follows_the_session_that_was_minted() {
        // A system-admin session has no tenant and belongs on the operator
        // console; anything else belongs on the tenant console.
        assert_eq!(landing_for_tenant(""), "/_console/admin/");
        assert_eq!(landing_for_tenant("acme"), "/_console/tenant/");
    }

    #[test]
    fn errors_return_to_the_console_the_flow_started_on() {
        assert_eq!(
            console_base(console_audience("/_console/tenant/signup", None)),
            "/_console/tenant/"
        );
        assert_eq!(
            console_base(console_audience("/_console/admin/", None)),
            "/_console/admin/"
        );
        // No usable referer still lands somewhere real.
        assert_eq!(console_base(console_audience("", None)), "/_console/admin/");
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;
    use base64::Engine;

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// `token` with its signed body changed by `edit`, and its signature
    /// kept.
    fn tampered(token: &str, edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let (body, sig) = token.rsplit_once('.').unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&B64.decode(body).unwrap()).unwrap();
        edit(&mut v);
        format!("{}.{sig}", B64.encode(v.to_string()))
    }

    #[test]
    fn the_state_carries_the_provider_and_tenant_it_was_issued_for() {
        let s = seal_oidc_state("t-acme", "acme");
        let opened = open_oidc_state(&s).unwrap();
        assert_eq!((opened.p.as_str(), opened.t.as_str()), ("t-acme", "acme"));
        // Two flows never share a state.
        assert_ne!(s, seal_oidc_state("t-acme", "acme"));
    }

    #[test]
    fn a_state_with_another_tenant_or_provider_is_refused() {
        let s = seal_oidc_state("t-acme", "acme");
        assert!(open_oidc_state(&tampered(&s, |v| v["t"] = "other".into())).is_none());
        assert!(open_oidc_state(&tampered(&s, |v| v["p"] = "system".into())).is_none());
        // The shape the state used to have, unsigned.
        assert!(open_oidc_state("abc:t-acme:other").is_none());
        assert!(open_oidc_state("").is_none());
    }

    #[test]
    fn an_expired_state_is_refused() {
        let s = seal(
            OIDC_STATE_PURPOSE,
            &OidcState {
                n: "n".into(),
                p: "t-acme".into(),
                t: "acme".into(),
                exp: now_secs() - 1,
            },
        );
        assert!(open_oidc_state(&s).is_none());
    }

    #[test]
    fn a_state_is_never_a_session_nor_a_session_a_state() {
        let (session, _) = mint_session("u", "oidc", "acme", "arn", false);
        assert!(open_oidc_state(&session).is_none());
        // Same fields, signed for the other purpose.
        let as_state = seal(
            OIDC_STATE_PURPOSE,
            &SessionClaims {
                u: "u".into(),
                k: "oidc".into(),
                t: String::new(),
                a: "arn".into(),
                sa: true,
                exp: now_secs() + 60,
            },
        );
        assert!(open_session(&as_state).is_none());
    }

    #[test]
    fn a_session_carries_the_arn_and_whether_it_is_the_system_admin() {
        let (token, _) = mint_session("u1", "AK", "", "arn:objectio:iam::user/ops", false);
        let s = open_session(&token).unwrap();
        assert_eq!(s.arn, "arn:objectio:iam::user/ops");
        assert!(!s.system_admin);
        assert!(s.tenant.is_empty());
        // Neither can be raised without the key.
        assert!(open_session(&tampered(&token, |v| v["sa"] = true.into())).is_none());
        assert!(open_session(&tampered(&token, |v| v["a"] = SYSTEM_ADMIN_ARN.into())).is_none());
    }

    const SYSTEM_ADMIN_ARN: &str = objectio_auth::SYSTEM_ADMIN_USER_ARN;

    /// A system-scope user is not the system admin for being in the system
    /// scope; the system admin's ARN or a system sign-in is.
    #[test]
    fn the_system_scope_alone_is_not_the_system_admin() {
        let caller = |arn: &str, sa: bool| crate::admin::CallerIdentity {
            user_id: "u".into(),
            user_arn: arn.into(),
            tenant: String::new(),
            authenticated: true,
            session_system_admin: sa,
        };
        assert!(!crate::admin::is_system_admin(&caller(
            "arn:objectio:iam::user/ops",
            false
        )));
        assert!(!crate::admin::is_system_admin(&caller("", false)));
        assert!(crate::admin::is_system_admin(&caller(
            SYSTEM_ADMIN_ARN,
            false
        )));
        assert!(crate::admin::is_system_admin(&caller(
            "arn:objectio:iam::user/alice",
            true
        )));
        let mut nobody = caller(SYSTEM_ADMIN_ARN, true);
        nobody.authenticated = false;
        assert!(!crate::admin::is_system_admin(&nobody));
    }

    fn tenant(name: &str, provider: &str) -> objectio_proto::metadata::TenantConfig {
        objectio_proto::metadata::TenantConfig {
            name: name.into(),
            oidc_provider: provider.into(),
            ..Default::default()
        }
    }

    #[test]
    fn a_provider_is_bound_to_its_own_tenant_and_the_tenants_naming_it() {
        assert!(provider_binds_tenant("t-acme", &tenant("acme", "")));
        assert!(provider_binds_tenant("t-acme", &tenant("Acme", "")));
        assert!(provider_binds_tenant("corp", &tenant("acme", "corp")));
        assert!(!provider_binds_tenant("t-acme", &tenant("other", "")));
        assert!(!provider_binds_tenant("t-acme", &tenant("other", "corp")));
        assert!(!provider_binds_tenant("", &tenant("other", "")));
    }

    #[test]
    fn a_tenant_provider_signs_in_only_to_a_tenant_it_is_bound_to() {
        let bound = vec!["acme".to_string()];
        assert_eq!(choose_tenant(&bound, "", false).unwrap(), "acme");
        assert_eq!(choose_tenant(&bound, "acme", false).unwrap(), "acme");
        // Asking for another tenant does not get it.
        assert!(choose_tenant(&bound, "other", false).is_err());
        assert!(choose_tenant(&bound, "other", true).is_err());
        // Bound to no tenant: the system scope, for a system provider only.
        assert_eq!(choose_tenant(&[], "", true).unwrap(), "");
        assert!(choose_tenant(&[], "", false).is_err());
        assert!(choose_tenant(&[], "acme", true).is_err());
        // Bound to several: the user says which, and it must be one of them.
        let two = vec!["a".to_string(), "b".to_string()];
        assert!(choose_tenant(&two, "", false).is_err());
        assert_eq!(choose_tenant(&two, "b", false).unwrap(), "b");
    }

    fn claims(extra: serde_json::Value, email: Option<&str>) -> objectio_auth::Claims {
        objectio_auth::Claims {
            sub: "sub-1".into(),
            email: email.map(Into::into),
            name: None,
            exp: 0,
            extra: serde_json::from_value(extra).unwrap(),
        }
    }

    #[test]
    fn an_identity_is_its_issuer_and_subject_and_the_name_only_labels_it() {
        let id = FederatedIdentity::from_claims(&claims(
            serde_json::json!({"iss": "https://idp", "preferred_username": "admin"}),
            Some("a@x.io"),
        ))
        .unwrap();
        assert_eq!(
            (id.issuer.as_str(), id.subject.as_str(), id.name.as_str()),
            ("https://idp", "sub-1", "admin")
        );
        let by_email = FederatedIdentity::from_claims(&claims(
            serde_json::json!({"iss": "https://idp"}),
            Some("a@x.io"),
        ))
        .unwrap();
        assert_eq!(by_email.name, "a@x.io");
        let by_sub = FederatedIdentity::from_claims(&claims(
            serde_json::json!({"iss": "https://idp"}),
            None,
        ))
        .unwrap();
        assert_eq!(by_sub.name, "sub-1");
        // No issuer: nothing to bind to.
        assert!(
            FederatedIdentity::from_claims(&claims(
                serde_json::json!({"preferred_username": "admin"}),
                None
            ))
            .is_none()
        );

        // The user for it is the one bound to it, in that tenant; a user of
        // the same name is not.
        let user = |iss: &str, sub: &str, tenant: &str| objectio_proto::metadata::UserMeta {
            user_id: "id".into(),
            display_name: "admin".into(),
            tenant: tenant.into(),
            federated_issuer: iss.into(),
            federated_subject: sub.into(),
            ..Default::default()
        };
        assert!(id.is(&user("https://idp", "sub-1", "acme"), "acme"));
        assert!(!id.is(&user("", "", "acme"), "acme"));
        assert!(!id.is(&user("https://other", "sub-1", "acme"), "acme"));
        assert!(!id.is(&user("https://idp", "sub-2", "acme"), "acme"));
        assert!(!id.is(&user("https://idp", "sub-1", "other"), "acme"));
    }
}

#[cfg(test)]
mod session_gate_tests {
    use super::*;
    use crate::auth_middleware::{AuthState, CachedTenant};
    use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
    use tower::ServiceExt as _;

    /// A router answering 200 behind the gate, whose meta is never reached:
    /// a check that has to ask is refused as unavailable (503).
    fn gated(auth: &Arc<AuthState>, signed_as: Option<&'static str>) -> axum::Router {
        let router = axum::Router::new()
            .route("/_admin/buckets", axum::routing::get(|| async { "ok" }))
            .route(
                "/_console/api/login",
                axum::routing::post(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(auth),
                session_tenant_gate,
            ));
        // What the SigV4 layer outside the gate leaves on a request it
        // authenticated.
        match signed_as {
            Some(tenant) => router.layer(axum::middleware::from_fn(
                move |mut r: axum::extract::Request, next: axum::middleware::Next| async move {
                    r.extensions_mut().insert(objectio_auth::AuthResult {
                        user_id: "u".into(),
                        tenant: tenant.into(),
                        auth_mode: objectio_auth::AuthMode::Permanent,
                        ..Default::default()
                    });
                    next.run(r).await
                },
            )),
            None => router,
        }
    }

    fn auth_state() -> Arc<AuthState> {
        let channel = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        Arc::new(AuthState::new(
            MetadataServiceClient::new(channel),
            "us-east-1",
        ))
    }

    fn tenant(auth: &AuthState, name: &str, open: bool) {
        auth.tenant_cache.write().insert(
            name.to_string(),
            CachedTenant {
                open,
                cached_at: std::time::Instant::now(),
            },
        );
    }

    async fn status(router: axum::Router, method: &str, path: &str, tenant: &str) -> StatusCode {
        let (session, _) = mint_session("u1", "AKID", tenant, "arn", tenant.is_empty());
        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header(header::COOKIE, format!("objectio-session={session}"))
            .body(axum::body::Body::empty())
            .unwrap();
        router.oneshot(request).await.unwrap().status()
    }

    #[tokio::test]
    async fn a_session_of_a_disabled_tenant_is_refused_and_restored_with_it() {
        let auth = auth_state();
        tenant(&auth, "acme", false);
        let s = status(gated(&auth, None), "GET", "/_admin/buckets", "acme").await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        tenant(&auth, "acme", true);
        let s = status(gated(&auth, None), "GET", "/_admin/buckets", "acme").await;
        assert_eq!(s, StatusCode::OK);
    }

    #[tokio::test]
    async fn a_system_session_asks_nothing() {
        let auth = auth_state();
        let s = status(gated(&auth, None), "GET", "/_admin/buckets", "").await;
        assert_eq!(s, StatusCode::OK);
    }

    #[tokio::test]
    async fn signing_in_is_left_to_sign_in() {
        let auth = auth_state();
        tenant(&auth, "acme", false);
        let s = status(gated(&auth, None), "POST", "/_console/api/login", "acme").await;
        assert_eq!(s, StatusCode::OK);
    }

    /// A signed request was admitted by the SigV4 layer: a stale cookie of
    /// a disabled tenant riding along is not what it acts with.
    #[tokio::test]
    async fn a_signed_request_is_the_sigv4_layers_to_decide() {
        let auth = auth_state();
        tenant(&auth, "acme", false);
        let s = status(gated(&auth, Some("")), "GET", "/_admin/buckets", "acme").await;
        assert_eq!(s, StatusCode::OK);
    }
}
