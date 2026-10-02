//! STS `AssumeRoleWithWebIdentity`: an OIDC token for temporary S3
//! credentials of a role.
//!
//! The request is unsigned (`POST /` with a form body, as AWS SDKs send it);
//! the token is the proof. Which identity providers may vouch for a role
//! depends on the role's scope:
//!
//! - a **system** role: only the operator's providers (the gateway's
//!   `--oidc-*` provider, and stored providers marked `system_admin`);
//! - a **tenant's** role: only that tenant's own provider
//!   (`identity/openid/t-<tenant>`, or the one bound to the tenant). A
//!   multi-tenant provider vouches only for the tenant of the token's
//!   upstream organisation.
//!
//! Then the role's trust policy decides, with the token's claims as
//! condition keys (`<issuer>:sub`, `<issuer>:aud`, `<issuer>:groups`, ...).
//! The credentials carry the role's tenant and its attached policies, and
//! no more: the tenant boundary applies to them as to any of its users.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use objectio_auth::policy::RequestContext;
use objectio_auth::{BucketPolicy, PolicyDecision, PolicyEvaluator};
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use tonic::transport::Channel;
use tracing::{info, warn};

/// What the STS endpoint needs.
pub struct StsState {
    pub meta_client: MetadataServiceClient<Channel>,
    /// The operator's provider from the gateway's `--oidc-*` flags.
    pub system_oidc: Option<Arc<objectio_auth::OidcProvider>>,
    pub sts: objectio_auth::sts::StsProvider,
}

const DEFAULT_SESSION_SECS: u64 = 3600;
const MIN_SESSION_SECS: u64 = 900;
const MAX_SESSION_SECS: u64 = 12 * 3600;

/// An STS error document, as AWS's STS answers.
fn sts_error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ErrorResponse \
         xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><Error><Type>Sender</Type>\
         <Code>{}</Code><Message>{}</Message></Error></ErrorResponse>",
        quick_xml::escape::escape(code),
        quick_xml::escape::escape(message)
    );
    (status, [(header::CONTENT_TYPE, "text/xml")], body).into_response()
}

fn denied(message: &str) -> Response {
    sts_error(StatusCode::FORBIDDEN, "AccessDenied", message)
}

/// A form-encoded body (and query string) as a map.
fn form(body: &[u8], query: Option<&str>) -> HashMap<String, String> {
    let decode = |s: &str| {
        urlencoding::decode(&s.replace('+', " "))
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_default()
    };
    let mut out = HashMap::new();
    for part in query
        .unwrap_or_default()
        .split('&')
        .chain(std::str::from_utf8(body).unwrap_or_default().split('&'))
    {
        if let Some((k, v)) = part.split_once('=') {
            out.insert(decode(k), decode(v));
        }
    }
    out
}

/// `(tenant, role name)` from a role ARN: `arn:obio:iam::<tenant|objectio>:role/<name>`
/// (`arn:aws:` accepted, as SDKs write it).
fn parse_role_arn(arn: &str) -> Option<(String, String)> {
    let rest = arn
        .strip_prefix("arn:obio:iam::")
        .or_else(|| arn.strip_prefix("arn:aws:iam::"))?;
    let (account, name) = rest.split_once(":role/")?;
    if name.is_empty() || name.contains('/') {
        return None;
    }
    let tenant = if account == "objectio" { "" } else { account };
    Some((tenant.to_string(), name.to_string()))
}

fn iam_key(tenant: &str, name: &str) -> String {
    if tenant.is_empty() {
        name.to_string()
    } else {
        format!("{tenant}/{name}")
    }
}

/// A provider that may vouch for a role, and what it requires of a token.
struct Candidate {
    name: String,
    provider: Arc<objectio_auth::OidcProvider>,
    /// For a multi-tenant provider: the upstream tenant id (`tid`) the
    /// token must carry, the one this ObjectIO tenant was registered for.
    required_tid: Option<String>,
}

/// The providers that may vouch for a role in `tenant`.
async fn candidates(state: &StsState, tenant: &str) -> Vec<Candidate> {
    let mut meta = state.meta_client.clone();
    let configs: Vec<(String, serde_json::Value)> = meta
        .list_config(objectio_proto::metadata::ListConfigRequest {
            prefix: "identity/openid/".to_string(),
        })
        .await
        .map(|r| r.into_inner().entries)
        .unwrap_or_default()
        .into_iter()
        .filter_map(|e| {
            let name = e.key.strip_prefix("identity/openid/")?.to_string();
            let config: serde_json::Value = serde_json::from_slice(&e.value).ok()?;
            config
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true)
                .then_some((name, config))
        })
        .collect();
    let build = |name: &str, config: &serde_json::Value, required_tid: Option<String>| {
        crate::console_auth::build_oidc_provider_from_config(config).map(|p| Candidate {
            name: name.to_string(),
            provider: Arc::new(p),
            required_tid,
        })
    };

    if tenant.is_empty() {
        let mut out: Vec<Candidate> = state
            .system_oidc
            .iter()
            .map(|p| Candidate {
                name: "system".to_string(),
                provider: Arc::clone(p),
                required_tid: None,
            })
            .collect();
        out.extend(configs.iter().filter_map(|(name, config)| {
            let system = config
                .get("system_admin")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if system {
                build(name, config, None)
            } else {
                None
            }
        }));
        return out;
    }

    let tenant_config = meta
        .get_tenant(objectio_proto::metadata::GetTenantRequest {
            name: tenant.to_string(),
        })
        .await
        .ok()
        .and_then(|r| r.into_inner().tenant);
    let own = format!("t-{}", tenant.to_lowercase());
    let bound = tenant_config
        .as_ref()
        .map(|t| t.oidc_provider.clone())
        .unwrap_or_default();
    let upstream_tid = tenant_config
        .as_ref()
        .and_then(|t| t.labels.get(crate::console_auth::OIDC_TID_LABEL).cloned());
    configs
        .iter()
        .filter(|(name, _)| *name == own || (!bound.is_empty() && *name == bound))
        .filter_map(|(name, config)| {
            let multi = crate::console_auth::ProviderTenancy::from_config(config).multi_tenant;
            if multi {
                // Only for the tenant its upstream organisation registered.
                let tid = upstream_tid.clone()?;
                build(name, config, Some(tid))
            } else {
                build(name, config, None)
            }
        })
        .collect()
}

/// `POST /` (or `GET /?Action=…`): STS.
pub async fn sts_handler(
    State(state): State<Arc<StsState>>,
    uri: axum::http::Uri,
    _headers: HeaderMap,
    body: Bytes,
) -> Response {
    let params = form(&body, uri.query());
    match params.get("Action").map(String::as_str) {
        Some("AssumeRoleWithWebIdentity") => assume_role_with_web_identity(&state, &params).await,
        Some(other) => sts_error(
            StatusCode::BAD_REQUEST,
            "InvalidAction",
            &format!("{other} is not supported"),
        ),
        None => sts_error(
            StatusCode::BAD_REQUEST,
            "MissingAction",
            "Action is required",
        ),
    }
}

/// Route an unsigned `POST /` to STS ahead of SigV4.
///
/// STS shares the S3 endpoint, as AWS SDKs expect when pointed at a custom
/// endpoint. Its requests carry no signature (the web identity token is the
/// proof), so they are taken here, before `auth_layer` would refuse them;
/// anything signed or presigned goes on to S3 untouched.
pub async fn sts_layer(
    State(state): State<Arc<StsState>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let unsigned_post_root = request.method() == axum::http::Method::POST
        && request.uri().path() == "/"
        && request.headers().get(header::AUTHORIZATION).is_none()
        && !request
            .uri()
            .query()
            .is_some_and(|q| q.contains("X-Amz-Signature") || q.contains("Signature="));
    if !unsigned_post_root {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let Ok(body) = axum::body::to_bytes(body, 64 * 1024).await else {
        return sts_error(
            StatusCode::BAD_REQUEST,
            "ValidationError",
            "request too large",
        );
    };
    sts_handler(State(state), parts.uri, parts.headers, body).await
}

#[allow(clippy::too_many_lines)]
async fn assume_role_with_web_identity(state: &StsState, p: &HashMap<String, String>) -> Response {
    let get = |k: &str| p.get(k).map(String::as_str).unwrap_or_default();
    let (role_arn, token, session) = (
        get("RoleArn"),
        get("WebIdentityToken"),
        get("RoleSessionName"),
    );
    if token.is_empty() {
        return sts_error(
            StatusCode::BAD_REQUEST,
            "MissingParameter",
            "WebIdentityToken is required",
        );
    }
    if session.len() < 2
        || session.len() > 64
        || !session
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_+=,.@-".contains(c))
    {
        return sts_error(
            StatusCode::BAD_REQUEST,
            "ValidationError",
            "RoleSessionName must be 2-64 characters of [\\w+=,.@-]",
        );
    }
    let Some((tenant, role_name)) = parse_role_arn(role_arn) else {
        return sts_error(
            StatusCode::BAD_REQUEST,
            "ValidationError",
            "RoleArn is not a role ARN",
        );
    };

    let mut meta = state.meta_client.clone();
    let role = match meta
        .get_role(objectio_proto::metadata::GetRoleRequest {
            name: iam_key(&tenant, &role_name),
        })
        .await
    {
        Ok(r) => {
            let r = r.into_inner();
            match r.role.filter(|_| r.found) {
                Some(role) => role,
                // Same answer as a refused token: no probing for role names.
                None => return denied("Not authorized to perform sts:AssumeRoleWithWebIdentity"),
            }
        }
        Err(e) => {
            return sts_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ServiceUnavailable",
                e.message(),
            );
        }
    };

    // A token from one of the providers allowed for this role's scope.
    let mut accepted = None;
    for c in candidates(state, &tenant).await {
        match c.provider.validate_token(token).await {
            Ok(claims) => {
                if let Some(tid) = &c.required_tid
                    && objectio_auth::OidcProvider::tenant_id(&claims).as_deref() != Some(tid)
                {
                    continue;
                }
                accepted = Some((c, claims));
                break;
            }
            Err(objectio_auth::AuthProviderError::TokenExpired) => {
                return sts_error(
                    StatusCode::BAD_REQUEST,
                    "ExpiredTokenException",
                    "the token has expired",
                );
            }
            Err(_) => {}
        }
    }
    let Some((candidate, claims)) = accepted else {
        warn!("sts: no provider for {role_arn} accepted the token");
        return sts_error(
            StatusCode::BAD_REQUEST,
            "InvalidIdentityToken",
            "the token is not from an identity provider this role's scope trusts",
        );
    };

    // The trust policy, with the token's claims as condition keys.
    let issuer = candidate
        .provider
        .config()
        .issuer_url
        .trim_end_matches('/')
        .to_string();
    let issuer_key = issuer
        .strip_prefix("https://")
        .or_else(|| issuer.strip_prefix("http://"))
        .unwrap_or(&issuer)
        .to_string();
    let Ok(trust) = BucketPolicy::from_trust_json(&role.trust_policy_json) else {
        return denied("the role's trust policy is invalid");
    };
    let mut ctx = RequestContext::new(
        format!("Federated:{issuer_key}"),
        "sts:AssumeRoleWithWebIdentity",
        &role.arn,
    )
    .with_variable(format!("{issuer_key}:sub"), claims.sub.clone());
    for (claim, value) in &claims.extra {
        let values: Vec<String> = match value {
            serde_json::Value::String(s) => vec![s.clone()],
            serde_json::Value::Array(a) => a
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            serde_json::Value::Bool(b) => vec![b.to_string()],
            serde_json::Value::Number(n) => vec![n.to_string()],
            _ => continue,
        };
        ctx = ctx.with_multi_variable(format!("{issuer_key}:{claim}"), values);
    }
    if let Some(email) = &claims.email {
        ctx = ctx.with_variable(format!("{issuer_key}:email"), email.clone());
    }
    ctx = ctx.with_multi_variable(
        format!("{issuer_key}:groups"),
        candidate.provider.extract_groups(&claims),
    );
    if PolicyEvaluator::new().evaluate(&trust, &ctx) != PolicyDecision::Allow {
        info!(
            "sts: {role_arn} refused for {} from {} by its trust policy",
            claims.sub, candidate.name
        );
        return denied("Not authorized to perform sts:AssumeRoleWithWebIdentity");
    }

    // How long: asked for, within the role's limit.
    let limit = match u64::from(role.max_session_seconds) {
        0 => DEFAULT_SESSION_SECS,
        m => m.clamp(MIN_SESSION_SECS, MAX_SESSION_SECS),
    };
    let duration = match p.get("DurationSeconds") {
        None => DEFAULT_SESSION_SECS.min(limit),
        Some(d) => match d.parse::<u64>() {
            Ok(d) if (MIN_SESSION_SECS..=limit).contains(&d) => d,
            _ => {
                return sts_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    &format!("DurationSeconds must be between {MIN_SESSION_SECS} and {limit}"),
                );
            }
        },
    };

    let account = if tenant.is_empty() {
        "objectio"
    } else {
        &tenant
    };
    let session_arn = format!("arn:obio:sts::{account}:assumed-role/{role_name}/{session}");
    let creds = state.sts.issue_for(
        &session_arn,
        "",
        objectio_auth::Operation::ReadWrite,
        Duration::from_secs(duration),
    );
    let expiration = i64::try_from(creds.expires_at)
        .ok()
        .and_then(|s| chrono::DateTime::from_timestamp(s, 0))
        .map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default();
    info!(
        "sts: {} assumed {} as {session_arn} via {}",
        claims.sub, role.arn, candidate.name
    );

    let esc = |s: &str| quick_xml::escape::escape(s).into_owned();
    let audience = claims
        .extra
        .get("aud")
        .map(|a| a.as_str().map_or_else(|| a.to_string(), str::to_string))
        .unwrap_or_default();
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <AssumeRoleWithWebIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
         <AssumeRoleWithWebIdentityResult>\
         <Credentials><AccessKeyId>{}</AccessKeyId><SecretAccessKey>{}</SecretAccessKey>\
         <SessionToken>{}</SessionToken><Expiration>{}</Expiration></Credentials>\
         <AssumedRoleUser><Arn>{}</Arn><AssumedRoleId>{}:{}</AssumedRoleId></AssumedRoleUser>\
         <SubjectFromWebIdentityToken>{}</SubjectFromWebIdentityToken>\
         <Provider>{}</Provider><Audience>{}</Audience>\
         </AssumeRoleWithWebIdentityResult>\
         <ResponseMetadata><RequestId>{}</RequestId></ResponseMetadata>\
         </AssumeRoleWithWebIdentityResponse>",
        esc(&creds.access_key_id),
        esc(&creds.secret_access_key),
        esc(&creds.session_token),
        expiration,
        esc(&session_arn),
        esc(&role.name),
        esc(session),
        esc(&claims.sub),
        esc(&issuer),
        esc(&audience),
        uuid::Uuid::new_v4(),
    );
    (StatusCode::OK, [(header::CONTENT_TYPE, "text/xml")], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::parse_role_arn;

    #[test]
    fn role_arns_name_a_tenant_or_the_system() {
        assert_eq!(
            parse_role_arn("arn:obio:iam::acme:role/ci"),
            Some(("acme".into(), "ci".into()))
        );
        assert_eq!(
            parse_role_arn("arn:aws:iam::objectio:role/ops"),
            Some((String::new(), "ops".into()))
        );
        assert_eq!(parse_role_arn("arn:obio:iam::acme:user/ci"), None);
        assert_eq!(parse_role_arn("arn:obio:iam::acme:role/a/b"), None);
    }
}
