//! Authentication middleware for the S3 gateway
//!
//! This module provides axum middleware for AWS Signature V4 and V2 authentication.
//! Credentials are fetched from the metadata service for persistence.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use objectio_auth::{AuthResult, CredentialScope, Operation};
use objectio_proto::metadata::{
    GetAccessKeyForAuthRequest, GetUserGroupsRequest, KeyOperation,
    metadata_service_client::MetadataServiceClient,
};
use parking_lot::RwLock;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tonic::transport::Channel;
use tracing::{debug, warn};

type HmacSha256 = Hmac<Sha256>;

/// Cached credential for SigV4 verification
#[derive(Clone)]
pub struct CachedCredential {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub user_id: String,
    pub user_arn: String,
    pub tenant: String,
    /// Bucket/prefix restriction carried by this key. `None` when the key is
    /// unscoped and read-write, which is the common case.
    pub scope: Option<CredentialScope>,
    pub cached_at: std::time::Instant,
}

/// Build a [`CredentialScope`] from the wire representation, collapsing the
/// "no restriction at all" case to `None` so the hot path can skip it.
fn credential_scope(scope: &str, operation: i32) -> Option<CredentialScope> {
    let operation = if operation == KeyOperation::KeyOpRead as i32 {
        Operation::Read
    } else {
        Operation::ReadWrite
    };
    let scope = CredentialScope {
        scope: scope.to_string(),
        operation,
    };
    (!scope.is_unrestricted()).then_some(scope)
}

/// Authentication state shared across requests
pub struct AuthState {
    /// Metadata service client for credential lookup
    pub meta_client: MetadataServiceClient<Channel>,
    /// Credential cache (access_key_id -> credential)
    pub credential_cache: RwLock<HashMap<String, CachedCredential>>,
    /// Cache TTL in seconds
    pub cache_ttl_secs: u64,
    /// AWS region for SigV4 verification
    pub region: String,
    /// STS provider for validating temporary credentials
    pub sts_provider: Option<objectio_auth::sts::StsProvider>,
}

impl AuthState {
    /// Create a new auth state
    pub fn new(meta_client: MetadataServiceClient<Channel>, region: impl Into<String>) -> Self {
        Self {
            meta_client,
            credential_cache: RwLock::new(HashMap::new()),
            // How long a suspended user or a deactivated or deleted key
            // still works on a gateway. It was 5 minutes.
            cache_ttl_secs: 15,
            region: region.into(),
            sts_provider: None,
        }
    }

    /// Set the STS provider for validating temporary credentials
    pub fn with_sts(mut self, sts: objectio_auth::sts::StsProvider) -> Self {
        self.sts_provider = Some(sts);
        self
    }

    /// Look up the IAM groups a user belongs to. Returns parallel
    /// (group_arns, group_ids) vectors. Called by every auth path so
    /// policies attached to a group cascade to its members regardless
    /// of how the user authenticated (SigV4, OIDC, or session cookie).
    /// Failures are logged and swallowed — group memberships are an
    /// optimization, not a hard requirement.
    pub async fn lookup_user_groups(&self, user_id: &str) -> (Vec<String>, Vec<String>) {
        if user_id.is_empty() {
            return (Vec::new(), Vec::new());
        }
        let mut client = self.meta_client.clone();
        match client
            .get_user_groups(GetUserGroupsRequest {
                user_id: user_id.to_string(),
            })
            .await
        {
            Ok(r) => {
                let groups = r.into_inner().groups;
                let arns = groups.iter().map(|g| g.arn.clone()).collect();
                let ids = groups.iter().map(|g| g.group_id.clone()).collect();
                (arns, ids)
            }
            Err(e) => {
                debug!("get_user_groups for {user_id} failed: {e}");
                (Vec::new(), Vec::new())
            }
        }
    }

    /// Drop one key from the cache, so a change to it holds here at once
    /// (other gateways pick it up within the cache TTL).
    pub fn forget_key(&self, access_key_id: &str) {
        self.credential_cache.write().remove(access_key_id);
    }

    /// Drop every cached key of one user.
    pub fn forget_user(&self, user_id: &str) {
        self.credential_cache
            .write()
            .retain(|_, c| c.user_id != user_id);
    }

    /// Look up credentials from cache or metadata service
    pub async fn lookup_credential(
        &self,
        access_key_id: &str,
    ) -> Result<CachedCredential, AuthError> {
        // Check cache first
        {
            let cache = self.credential_cache.read();
            if let Some(cred) = cache.get(access_key_id)
                && cred.cached_at.elapsed().as_secs() < self.cache_ttl_secs
            {
                return Ok(cred.clone());
            }
        }

        // Fetch from metadata service
        let mut client = self.meta_client.clone();
        let response = client
            .get_access_key_for_auth(GetAccessKeyForAuthRequest {
                access_key_id: access_key_id.to_string(),
            })
            .await
            .map_err(|e| {
                warn!("Failed to fetch credential from metadata service: {}", e);
                match e.code() {
                    // Meta answered: the key is not one it accepts.
                    tonic::Code::NotFound
                    | tonic::Code::PermissionDenied
                    | tonic::Code::Unauthenticated
                    | tonic::Code::InvalidArgument => {
                        AuthError::AccessDenied(format!("credential lookup failed: {e}"))
                    }
                    // No answer: unknown, not refused.
                    _ => AuthError::Unavailable(format!("credential lookup failed: {e}; retry")),
                }
            })?;

        let inner = response.into_inner();
        let access_key = inner
            .access_key
            .ok_or_else(|| AuthError::AccessDenied("access key not found".to_string()))?;
        let user = inner
            .user
            .ok_or_else(|| AuthError::AccessDenied("user not found".to_string()))?;

        let cred = CachedCredential {
            access_key_id: access_key.access_key_id.clone(),
            secret_access_key: access_key.secret_access_key,
            user_id: user.user_id.clone(),
            user_arn: user.arn,
            tenant: user.tenant,
            scope: credential_scope(&access_key.scope, access_key.operation),
            cached_at: std::time::Instant::now(),
        };

        // Update cache
        self.credential_cache
            .write()
            .insert(access_key.access_key_id, cred.clone());

        Ok(cred)
    }
}

/// Authentication middleware layer
/// Run `auth_layer` only when the request carries an `authorization` header.
///
/// Useful for routes (e.g. the admin API) that also accept a session cookie
/// — if the caller uses SigV4 we want their identity on the request, but a
/// cookie-only request should pass through untouched so the handler can do
/// its own session check.
pub async fn optional_auth_layer(
    state: State<Arc<AuthState>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, AuthError> {
    // A presigned URL carries its credentials in the query string and has no
    // Authorization header by construction, so testing for the header alone
    // let one through unauthenticated here.
    let presigned = request
        .uri()
        .query()
        .is_some_and(|q| parse_presigned_query(q).is_some() || is_presigned_v2(q));
    if presigned || request.headers().get("authorization").is_some() {
        auth_layer(state, request, next).await
    } else {
        Ok(next.run(request).await)
    }
}

pub async fn auth_layer(
    State(auth_state): State<Arc<AuthState>>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, AuthError> {
    let path = request.uri().path();

    // Skip auth for health checks and metrics
    if path == "/health" || path == "/_ready" || path == "/metrics" || path == "/_status" {
        return Ok(next.run(request).await);
    }

    // A presigned URL puts its credentials in the query string and cannot
    // carry an Authorization header — the client is handed a URL, not a
    // request. Check for one before concluding the request is unauthenticated.
    if request.uri().query().is_some_and(is_presigned_v2) {
        return Err(AuthError::UnsupportedSigV2);
    }
    if let Some(presigned) = request.uri().query().and_then(parse_presigned_query) {
        let presigned = presigned?;
        return run_presigned(auth_state, presigned, request, next).await;
    }

    // No signature at all: an anonymous request. It carries no identity,
    // and authorization lets it reach only what a bucket policy grants to
    // everyone, where public access isn't blocked.
    let Some(auth_header) = request.headers().get("authorization") else {
        crate::audit::attach(
            &mut request,
            AuthResult {
                user_id: String::new(),
                user_arn: crate::authz::ANONYMOUS_PRINCIPAL.to_string(),
                access_key_id: String::new(),
                group_arns: Vec::new(),
                group_ids: Vec::new(),
                tenant: String::new(),
                auth_mode: objectio_auth::AuthMode::Anonymous,
                scope: None,
                source_ip: None,
                source_endpoint: None,
            },
        );
        return Ok(next.run(request).await);
    };
    let auth_header = auth_header
        .to_str()
        .map_err(|_| AuthError::AccessDenied("invalid authorization header".to_string()))?;

    let parsed = parse_authorization_header(auth_header)?;

    // Check for STS temporary credentials (ASIA* access key + X-Amz-Security-Token)
    let access_key_id = parsed.access_key_id();
    let session_token = request
        .headers()
        .get("x-amz-security-token")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    if access_key_id.starts_with("ASIA") {
        let (cred, auth_result) =
            sts_session(&auth_state, access_key_id, session_token.as_deref())?;
        // The SAME SigV4 verify path as permanent keys — without this the
        // session token is the only proof, which is replayable.
        verify_request_v4(
            &request,
            &parsed.signed_headers,
            &parsed.signature,
            &cred,
            &auth_state.region,
        )?;
        debug!("STS auth ok: user_arn={}", auth_result.user_arn);
        crate::audit::attach(&mut request, auth_result);
        return Ok(next.run(request).await);
    }

    // Fetch credentials from metadata service (permanent keys)
    let cred = auth_state.lookup_credential(access_key_id).await?;

    // Verify the signature based on auth version
    let mut auth_result = verify_request_v4(
        &request,
        &parsed.signed_headers,
        &parsed.signature,
        &cred,
        &auth_state.region,
    )?;

    // Stitch IAM group memberships onto the AuthResult so policies attached
    // to a group cascade to its members. Mirrors the OIDC bridge — same
    // semantics, different identity source.
    let (g_arns, g_ids) = auth_state.lookup_user_groups(&auth_result.user_id).await;
    auth_result.group_arns = g_arns;
    auth_result.group_ids = g_ids;

    debug!(
        "Authenticated user: {} (key: {}, groups={})",
        auth_result.user_id,
        auth_result.access_key_id,
        auth_result.group_ids.len()
    );

    // Store auth result in request extensions for handlers to access
    crate::audit::attach(&mut request, auth_result);
    Ok(next.run(request).await)
}

/// A temporary key's signing secret and the identity it carries.
///
/// `access_key_id` is an `ASIA…` key and `token` its session token. The
/// secret is derived from the key, so the caller still has to verify a
/// signature with it: the token alone proves nothing. A role's session gets
/// the role as its principal and the role's tenant; any other session is a
/// scoped STS credential with no tenant.
pub(crate) fn sts_session(
    auth_state: &AuthState,
    access_key_id: &str,
    token: Option<&str>,
) -> Result<(CachedCredential, AuthResult), AuthError> {
    let Some(token) = token else {
        return Err(AuthError::AccessDenied(
            "temporary credentials require X-Amz-Security-Token".to_string(),
        ));
    };
    let Some(sts) = &auth_state.sts_provider else {
        return Err(AuthError::AccessDenied(
            "STS credential vending is not configured on this gateway".to_string(),
        ));
    };
    let session_info = sts
        .validate(token)
        .ok_or_else(|| AuthError::AccessDenied("invalid or expired session token".to_string()))?;
    // A role's session: "arn:obio:sts::<tenant|objectio>:assumed-role/<role>/<session>".
    let role = session_info
        .user_arn
        .strip_prefix("arn:obio:sts::")
        .and_then(|r| r.split_once(":assumed-role/"))
        .and_then(|(account, rest)| {
            let role = rest.split('/').next()?;
            let tenant = if account == "objectio" { "" } else { account };
            Some((tenant.to_string(), role.to_string()))
        });

    let cred = CachedCredential {
        access_key_id: access_key_id.to_string(),
        secret_access_key: sts.derive_secret(access_key_id),
        user_id: session_info.user_arn.clone(),
        user_arn: session_info.user_arn.clone(),
        tenant: String::new(),
        scope: Some(CredentialScope {
            scope: session_info.scope.clone(),
            operation: session_info.operation,
        }),
        cached_at: std::time::Instant::now(),
    };
    let auth_result = if let Some((tenant, role)) = role {
        // The role's policies decide; the tenant boundary holds.
        let key = if tenant.is_empty() {
            role
        } else {
            format!("{tenant}/{role}")
        };
        AuthResult {
            user_id: format!("role:{key}"),
            user_arn: session_info.user_arn,
            access_key_id: access_key_id.to_string(),
            group_arns: Vec::new(),
            group_ids: Vec::new(),
            tenant,
            auth_mode: objectio_auth::AuthMode::AssumedRole,
            scope: None,
            source_ip: None,
            source_endpoint: None,
        }
    } else {
        AuthResult {
            user_id: session_info.user_arn.clone(),
            user_arn: session_info.user_arn,
            access_key_id: access_key_id.to_string(),
            group_arns: Vec::new(),
            group_ids: Vec::new(),
            tenant: String::new(),
            auth_mode: objectio_auth::AuthMode::Sts,
            scope: cred.scope.clone(),
            source_ip: None,
            source_endpoint: None,
        }
    };
    Ok((cred, auth_result))
}

/// Authenticate a presigned request and run the handler.
///
/// Split out of `auth_layer` so the two credential sources stay legible; it
/// resolves the key the same way the header path does, including STS session
/// tokens, and hands the handler the same `AuthResult`. Everything downstream
/// — bucket policy, credential scope, tenancy — therefore applies to a
/// presigned request exactly as it does to a signed one.
async fn run_presigned(
    auth_state: Arc<AuthState>,
    presigned: PresignedAuth,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, AuthError> {
    // A session key is resolved exactly as a header-signed one is: a role's
    // session takes the role (its policies, its tenant boundary). This path
    // used to make every session a tenant-less STS credential, so a URL
    // presigned with a role's keys skipped the tenant boundary and the
    // role's policies alike.
    let auth_result = if presigned.access_key_id.starts_with("ASIA") {
        let (cred, session) = sts_session(
            &auth_state,
            &presigned.access_key_id,
            presigned.session_token.as_deref(),
        )?;
        // The signature proves the caller holds the session's secret.
        verify_presigned_v4(&request, &presigned, &cred)?;
        session
    } else {
        let cred = auth_state
            .lookup_credential(&presigned.access_key_id)
            .await?;
        let mut auth_result = verify_presigned_v4(&request, &presigned, &cred)?;
        let (g_arns, g_ids) = auth_state.lookup_user_groups(&auth_result.user_id).await;
        auth_result.group_arns = g_arns;
        auth_result.group_ids = g_ids;
        auth_result
    };

    debug!(
        "Authenticated presigned request: {} (key: {})",
        auth_result.user_id, auth_result.access_key_id
    );

    crate::audit::attach(&mut request, auth_result);
    Ok(next.run(request).await)
}

/// A request authenticated by SigV4 query parameters — a presigned URL.
///
/// The gateway could already *generate* these (Delta Sharing hands them to
/// recipients) but had no path to verify one, so every presigned URL it issued
/// was refused by the server that issued it. Any client that is handed a URL
/// rather than making a request — git-lfs, a browser, `curl -O` — has no way
/// to send an `Authorization` header, so this is the only way bytes move
/// without proxying them all through something that can sign.
pub struct PresignedAuth {
    pub access_key_id: String,
    /// The scope exactly as the client signed it: `20260917/us-east-1/s3/aws4_request`.
    pub credential_scope: String,
    pub date_stamp: String,
    pub region: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
    /// `X-Amz-Date`, in the `20260917T063018Z` form.
    pub date_str: String,
    pub expires_secs: i64,
    pub session_token: Option<String>,
}

/// The longest link AWS will issue, and the longest this will honour.
const MAX_PRESIGN_EXPIRY_SECS: i64 = 7 * 24 * 60 * 60;

/// Pull one query parameter out, percent-decoded.
fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        // Parameter *names* can be encoded too, though in practice these are
        // not. Decode both sides so a conforming client is never turned away.
        if String::from_utf8_lossy(&url_decode(k)).eq_ignore_ascii_case(name) {
            Some(String::from_utf8_lossy(&url_decode(v)).into_owned())
        } else {
            None
        }
    })
}

/// Read SigV4 query-string credentials off a request.
///
/// `None` means this is not a presigned request and the caller should look for
/// an `Authorization` header instead. `Some(Err(..))` means it announced itself
/// as one and is malformed, which is worth saying rather than falling through
/// to "missing authorization header".
pub fn is_presigned_v2(query: &str) -> bool {
    let has = |name: &str| {
        query
            .split('&')
            .any(|p| p.split('=').next().is_some_and(|k| k == name))
    };
    has("AWSAccessKeyId") && has("Signature")
}

pub fn parse_presigned_query(query: &str) -> Option<Result<PresignedAuth, AuthError>> {
    // `X-Amz-Signature` is the marker: `X-Amz-Algorithm` alone also appears in
    // POST policy form uploads, which are a different mechanism.
    let signature = query_param(query, "x-amz-signature")?;

    Some((|| {
        let algorithm = query_param(query, "x-amz-algorithm").ok_or_else(|| {
            AuthError::AccessDenied("presigned URL is missing X-Amz-Algorithm".to_string())
        })?;
        if algorithm != "AWS4-HMAC-SHA256" {
            return Err(AuthError::AccessDenied(format!(
                "unsupported presigned algorithm: {algorithm}"
            )));
        }

        let credential = query_param(query, "x-amz-credential").ok_or_else(|| {
            AuthError::AccessDenied("presigned URL is missing X-Amz-Credential".to_string())
        })?;
        // `AKID/20260917/us-east-1/s3/aws4_request`. The access key id itself
        // never contains a slash, so the first segment is unambiguous.
        let parts: Vec<&str> = credential.split('/').collect();
        if parts.len() != 5 || parts[4] != "aws4_request" || parts[3] != "s3" {
            return Err(AuthError::AccessDenied(format!(
                "malformed X-Amz-Credential: {credential}"
            )));
        }

        let date_str = query_param(query, "x-amz-date").ok_or_else(|| {
            AuthError::AccessDenied("presigned URL is missing X-Amz-Date".to_string())
        })?;

        // The scope's date must be the date it claims to have been signed on;
        // otherwise a signature from one day could be replayed under another
        // day's scope.
        if !date_str.starts_with(parts[1]) {
            return Err(AuthError::AccessDenied(
                "X-Amz-Credential scope date does not match X-Amz-Date".to_string(),
            ));
        }

        let expires_secs: i64 = query_param(query, "x-amz-expires")
            .ok_or_else(|| {
                AuthError::AccessDenied("presigned URL is missing X-Amz-Expires".to_string())
            })?
            .parse()
            .map_err(|_| {
                AuthError::AccessDenied("X-Amz-Expires is not a number of seconds".to_string())
            })?;
        if expires_secs <= 0 || expires_secs > MAX_PRESIGN_EXPIRY_SECS {
            return Err(AuthError::AccessDenied(format!(
                "X-Amz-Expires must be between 1 and {MAX_PRESIGN_EXPIRY_SECS} seconds"
            )));
        }

        let signed_headers: Vec<String> = query_param(query, "x-amz-signedheaders")
            .ok_or_else(|| {
                AuthError::AccessDenied("presigned URL is missing X-Amz-SignedHeaders".to_string())
            })?
            .split(';')
            .map(str::to_lowercase)
            .filter(|h| !h.is_empty())
            .collect();
        if signed_headers.is_empty() {
            return Err(AuthError::AccessDenied(
                "X-Amz-SignedHeaders is empty".to_string(),
            ));
        }

        Ok(PresignedAuth {
            access_key_id: parts[0].to_string(),
            credential_scope: parts[1..].join("/"),
            date_stamp: parts[1].to_string(),
            region: parts[2].to_string(),
            signed_headers,
            signature,
            date_str,
            expires_secs,
            session_token: query_param(query, "x-amz-security-token"),
        })
    })())
}

/// Canonical query string for a presigned request.
///
/// Identical to the header case except that `X-Amz-Signature` is left out —
/// it is the output of the computation, so it cannot also be an input.
/// Everything else, `X-Amz-Algorithm` and friends included, is signed.
fn build_canonical_query_string_presigned(query: &str) -> String {
    let filtered: Vec<&str> = query
        .split('&')
        .filter(|pair| {
            let name = pair.split_once('=').map_or(*pair, |(k, _)| k);
            !name.eq_ignore_ascii_case("X-Amz-Signature")
        })
        .collect();
    build_canonical_query_string(&filtered.join("&"))
}

/// Verify a presigned URL's signature and its expiry window.
pub fn verify_presigned_v4<B>(
    request: &Request<B>,
    presigned: &PresignedAuth,
    cred: &CachedCredential,
) -> Result<AuthResult, AuthError> {
    let signed_at = parse_date_v4(&presigned.date_str)?;
    let now = Utc::now();

    // A link is valid from when it was signed until `X-Amz-Expires` later.
    // This is not the header path's 15-minute skew window — the whole point of
    // a presigned URL is to outlive the moment it was made.
    let age = now.signed_duration_since(signed_at);
    if age.num_seconds() > presigned.expires_secs {
        return Err(AuthError::ExpiredToken(format!(
            "this presigned URL expired {} seconds ago",
            age.num_seconds() - presigned.expires_secs
        )));
    }
    // Allow a little skew the other way: a client whose clock runs fast would
    // otherwise sign a URL the server considers not yet valid.
    if age.num_minutes() < -15 {
        return Err(AuthError::RequestTimeTooSkewed);
    }

    let uri = request.uri();
    let path = uri.path();
    let canonical_uri = if path.is_empty() { "/" } else { path };
    let canonical_query = build_canonical_query_string_presigned(uri.query().unwrap_or(""));

    let mut headers_map: BTreeMap<String, String> = BTreeMap::new();
    for header_name in &presigned.signed_headers {
        let value = request
            .headers()
            .get(header_name.as_str())
            .ok_or_else(|| {
                AuthError::AccessDenied(format!(
                    "presigned URL signed header {header_name} is not on the request"
                ))
            })?
            .to_str()
            .map_err(|_| AuthError::AccessDenied("invalid header value".to_string()))?;
        headers_map.insert(header_name.clone(), value.trim().to_string());
    }
    let canonical_headers: String = headers_map
        .iter()
        .map(|(k, v)| format!("{k}:{v}\n"))
        .collect();

    // A presigned S3 request signs `UNSIGNED-PAYLOAD` rather than a body hash:
    // the URL is built before the body exists, and for a GET there is no body
    // at all. A client that chooses to sign the payload says so by putting
    // x-amz-content-sha256 in SignedHeaders, and then its value is used.
    let payload_hash = if presigned
        .signed_headers
        .iter()
        .any(|h| h == "x-amz-content-sha256")
    {
        request
            .headers()
            .get("x-amz-content-sha256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("UNSIGNED-PAYLOAD")
            .to_string()
    } else {
        "UNSIGNED-PAYLOAD".to_string()
    };

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        request.method().as_str(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        presigned.signed_headers.join(";"),
        payload_hash
    );

    // The scope is used exactly as the client signed it. It is already pinned
    // to `s3`/`aws4_request` by the parser and its date to X-Amz-Date; the
    // region is the client's, because a signature made with a different region
    // still proves possession of the secret, and refusing it only produces a
    // failure that reads like bad credentials.
    let string_to_sign = build_string_to_sign(
        &canonical_request,
        &presigned.date_str,
        &presigned.credential_scope,
    );
    let signing_key = derive_signing_key(
        &cred.secret_access_key,
        &presigned.date_stamp,
        &presigned.region,
        "s3",
    );
    let calculated = calculate_signature_v4(&signing_key, &string_to_sign);

    if !constant_time_eq(&calculated, &presigned.signature) {
        warn!(
            method = %request.method(),
            uri = %request.uri(),
            calculated = %calculated,
            provided = %presigned.signature,
            canonical_request = %canonical_request,
            "presigned SigV4 mismatch"
        );
        return Err(AuthError::SignatureDoesNotMatch);
    }

    Ok(AuthResult {
        user_id: cred.user_id.clone(),
        user_arn: cred.user_arn.clone(),
        access_key_id: cred.access_key_id.clone(),
        group_arns: Vec::new(),
        group_ids: Vec::new(),
        tenant: cred.tenant.clone(),
        auth_mode: objectio_auth::AuthMode::Permanent,
        scope: cred.scope.clone(),
        source_ip: None,
        source_endpoint: None,
    })
}

/// A parsed SigV4 Authorization header.
pub struct ParsedAuth {
    pub access_key_id: String,
    pub signed_headers: Vec<String>,
    pub signature: String,
}

impl ParsedAuth {
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }
}

/// Parse the Authorization header. SigV4 only: SigV2 ("AWS key:sig") is
/// refused with [`AuthError::UnsupportedSigV2`], as S3 refuses it on every
/// bucket created since June 2020.
pub fn parse_authorization_header(header: &str) -> Result<ParsedAuth, AuthError> {
    if header.starts_with("AWS4-HMAC-SHA256") {
        // SigV4 format: AWS4-HMAC-SHA256 Credential=AKID/date/region/service/aws4_request,
        //               SignedHeaders=host;x-amz-date, Signature=xxx
        let re = Regex::new(
            r"AWS4-HMAC-SHA256\s+Credential=([^/]+)/[^,]+,\s*SignedHeaders=([^,]+),\s*Signature=(\w+)"
        ).unwrap();

        let captures = re.captures(header).ok_or_else(|| {
            AuthError::AccessDenied("invalid authorization header format".to_string())
        })?;

        Ok(ParsedAuth {
            access_key_id: captures.get(1).unwrap().as_str().to_string(),
            signed_headers: captures
                .get(2)
                .unwrap()
                .as_str()
                .split(';')
                .map(|s| s.to_lowercase())
                .collect(),
            signature: captures.get(3).unwrap().as_str().to_string(),
        })
    } else if header.starts_with("AWS ") {
        Err(AuthError::UnsupportedSigV2)
    } else {
        Err(AuthError::AccessDenied(
            "unsupported signature version".to_string(),
        ))
    }
}

/// Verify SigV4 request signature
pub fn verify_request_v4<B>(
    request: &Request<B>,
    signed_headers: &[String],
    signature: &str,
    cred: &CachedCredential,
    region: &str,
) -> Result<AuthResult, AuthError> {
    // Get the request date
    let date_str = get_request_date(request)?;
    let date = parse_date_v4(&date_str)?;

    // Check if request is not too old (allow 15 minutes)
    let now = Utc::now();
    let diff = now.signed_duration_since(date);
    if diff.num_minutes().abs() > 15 {
        return Err(AuthError::RequestTimeTooSkewed);
    }

    // Build canonical request
    let canonical_request = build_canonical_request(request, signed_headers)?;

    // Build string to sign
    let date_stamp = date.format("%Y%m%d").to_string();
    let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, region);
    let string_to_sign = build_string_to_sign(&canonical_request, &date_str, &credential_scope);

    // Calculate signature
    let signing_key = derive_signing_key(&cred.secret_access_key, &date_stamp, region, "s3");
    let calculated_signature = calculate_signature_v4(&signing_key, &string_to_sign);

    // Compare signatures using constant-time comparison
    if !constant_time_eq(&calculated_signature, signature) {
        // Temporarily elevated from debug → warn while we diagnose proxy
        // interference (Cloudflare/nginx rewriting path/host for some verbs).
        // Dump the canonical request we computed alongside the raw incoming
        // headers so we can spot exactly what doesn't match.
        let incoming: Vec<String> = request
            .headers()
            .iter()
            .map(|(k, v)| format!("{}={}", k.as_str(), v.to_str().unwrap_or("<non-utf8>")))
            .collect();
        warn!(
            method = %request.method(),
            uri = %request.uri(),
            calculated = %calculated_signature,
            provided = %signature,
            signed_headers = %signed_headers.join(";"),
            incoming_headers = ?incoming,
            canonical_request = %canonical_request,
            string_to_sign = %string_to_sign,
            "SigV4 mismatch"
        );
        return Err(AuthError::SignatureDoesNotMatch);
    }

    Ok(AuthResult {
        user_id: cred.user_id.clone(),
        user_arn: cred.user_arn.clone(),
        access_key_id: cred.access_key_id.clone(),
        group_arns: Vec::new(),
        group_ids: Vec::new(),
        tenant: cred.tenant.clone(),
        auth_mode: objectio_auth::AuthMode::Permanent,
        scope: cred.scope.clone(),
        source_ip: None,
        source_endpoint: None,
    })
}

/// Get the request date from headers
fn get_request_date<B>(request: &Request<B>) -> Result<String, AuthError> {
    if let Some(date) = request.headers().get("x-amz-date") {
        return date
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| AuthError::AccessDenied("invalid date format".to_string()));
    }
    // Without X-Amz-Date, SigV4 signs the Date header (RFC 1123); the
    // string to sign still carries the time in ISO 8601 basic form.
    if let Some(date) = request.headers().get("date") {
        return date
            .to_str()
            .ok()
            .and_then(|s| DateTime::parse_from_rfc2822(s.trim()).ok())
            .map(|d| d.with_timezone(&Utc).format("%Y%m%dT%H%M%SZ").to_string())
            .ok_or_else(|| AuthError::AccessDenied("invalid date format".to_string()));
    }
    Err(AuthError::AccessDenied("missing date header".to_string()))
}

/// A header value as the text a client signed. HTTP carries bytes: a UTF-8
/// client sends a non-ASCII x-amz-meta value as UTF-8, Python's http.client
/// as Latin-1. `to_str` refuses both.
pub fn header_text(value: &http::HeaderValue) -> String {
    let bytes = value.as_bytes();
    std::str::from_utf8(bytes).map_or_else(
        |_| bytes.iter().map(|&b| char::from(b)).collect(),
        str::to_string,
    )
}

/// Parse ISO8601 date format for SigV4
fn parse_date_v4(date_str: &str) -> Result<DateTime<Utc>, AuthError> {
    NaiveDateTime::parse_from_str(date_str, "%Y%m%dT%H%M%SZ")
        .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
        .map_err(|_| AuthError::AccessDenied("invalid date format".to_string()))
}

/// Build the canonical request string
fn build_canonical_request<B>(
    request: &Request<B>,
    signed_headers: &[String],
) -> Result<String, AuthError> {
    let method = request.method().as_str();
    let uri = request.uri();
    let path = uri.path();

    let canonical_uri = if path.is_empty() { "/" } else { path };
    let canonical_query = build_canonical_query_string(uri.query().unwrap_or(""));

    let mut headers_map: BTreeMap<String, String> = BTreeMap::new();
    for header_name in signed_headers {
        let value = match request.headers().get(header_name.as_str()) {
            Some(v) => header_text(v),
            None => {
                // Diagnostic dump: when a signed header is missing, log the
                // full SignedHeaders list and every header actually on the
                // arriving request so we can tell whether a proxy/CDN (CF,
                // nginx ingress) stripped it in flight.
                let incoming: Vec<String> = request
                    .headers()
                    .iter()
                    .map(|(k, v)| format!("{}={}", k.as_str(), v.to_str().unwrap_or("<non-utf8>")))
                    .collect();
                warn!(
                    method = %method,
                    path = %path,
                    missing = %header_name,
                    signed_headers = %signed_headers.join(";"),
                    incoming_headers = ?incoming,
                    "SigV4: signed header missing from arriving request — a proxy likely stripped it"
                );
                return Err(AuthError::AccessDenied(format!(
                    "missing signed header: {}",
                    header_name
                )));
            }
        };
        headers_map.insert(header_name.clone(), value.trim().to_string());
    }

    let canonical_headers: String = headers_map
        .iter()
        .map(|(k, v)| format!("{}:{}\n", k, v))
        .collect();

    let signed_headers_str = signed_headers.join(";");

    let payload_hash = request
        .headers()
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("UNSIGNED-PAYLOAD")
        .to_string();

    Ok(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method, canonical_uri, canonical_query, canonical_headers, signed_headers_str, payload_hash
    ))
}

/// Build canonical query string
fn build_canonical_query_string(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }

    let mut params: Vec<(String, String)> = query
        .split('&')
        .filter_map(|param| {
            let mut parts = param.splitn(2, '=');
            let key = parts.next()?;
            let value = parts.next().unwrap_or("");
            Some((url_encode(&url_decode(key)), url_encode(&url_decode(value))))
        })
        .collect();

    params.sort_by(|a, b| a.0.cmp(&b.0));

    params
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("&")
}

/// Build the string to sign
fn build_string_to_sign(canonical_request: &str, date_str: &str, credential_scope: &str) -> String {
    let canonical_request_hash = hex_sha256(canonical_request.as_bytes());
    format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        date_str, credential_scope, canonical_request_hash
    )
}

/// Derive the signing key
pub(crate) fn derive_signing_key(
    secret_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Vec<u8> {
    let k_secret = format!("AWS4{}", secret_key);
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Calculate the SigV4 signature
pub(crate) fn calculate_signature_v4(signing_key: &[u8], string_to_sign: &str) -> String {
    hex::encode(hmac_sha256(signing_key, string_to_sign.as_bytes()))
}

/// Calculate HMAC-SHA256
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Calculate SHA256 and return hex string
fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// URL encode a string (AWS style)
/// Percent-encode bytes with AWS's unreserved set (`A-Za-z0-9-_.~`).
///
/// Takes bytes, not a string, because percent-encoding is a byte encoding.
fn url_encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                use std::fmt::Write as _;
                let _ = write!(result, "%{b:02X}");
            }
        }
    }
    result
}

/// Percent-decode to bytes.
///
/// This used to decode into a `String`, pushing each decoded byte as a `char`.
/// Percent-encoding is a byte encoding: `%C3%A9` is two bytes that together
/// are one character, and turning them into two `char`s and re-encoding gives
/// four bytes. Canonicalising `caf%C3%A9` therefore produced
/// `caf%C3%83%C2%A9`, so the gateway signed a different canonical query string
/// than the client did and every request carrying a non-ASCII query parameter
/// failed with `SignatureDoesNotMatch` — which reads like bad credentials
/// rather than a listing whose prefix has an accent in it.
///
/// `+` still decodes to a space. That is the form-encoding convention rather
/// than the URI one, and AWS SDKs send `%20`, but changing it would alter the
/// canonical form of any request that does arrive with a bare `+`.
fn url_decode(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut result = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 3 <= bytes.len() => {
                let hex = &bytes[i + 1..i + 3];
                match std::str::from_utf8(hex)
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok())
                {
                    Some(byte) => {
                        result.push(byte);
                        i += 3;
                    }
                    // Not a valid escape — keep the literal `%` and carry on,
                    // so a stray one does not swallow the next two bytes.
                    None => {
                        result.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                result.push(b' ');
                i += 1;
            }
            b => {
                result.push(b);
                i += 1;
            }
        }
    }
    result
}

/// Constant-time string comparison to prevent timing attacks
pub(crate) fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        result |= x ^ y;
    }
    result == 0
}

/// Authentication error response
#[derive(Debug)]
pub enum AuthError {
    /// Missing or invalid credentials
    AccessDenied(String),
    /// Signature does not match
    SignatureDoesNotMatch,
    /// Request has expired
    RequestTimeTooSkewed,
    /// A presigned URL is past its `X-Amz-Expires` window
    ExpiredToken(String),
    /// Signed with SigV2 (header or presigned URL), which is not accepted.
    UnsupportedSigV2,
    /// Internal error
    #[allow(dead_code)]
    InternalError,
    /// The credential couldn't be looked up (meta unreachable, electing):
    /// 503, which clients retry. A 403 here told them the key was refused.
    Unavailable(String),
}

impl AuthError {
    /// Bounded reason for `objectio_auth_failures_total`.
    fn metric_reason(&self) -> &'static str {
        match self {
            AuthError::AccessDenied(msg) => {
                let m = msg.to_ascii_lowercase();
                if m.contains("not found") {
                    "unknown_key"
                } else if m.contains("expired") || m.contains("session token") {
                    "expired"
                } else if m.contains("missing") {
                    "missing_credentials"
                } else if m.contains("invalid") || m.contains("format") {
                    "malformed"
                } else {
                    "denied"
                }
            }
            AuthError::SignatureDoesNotMatch => "signature",
            AuthError::RequestTimeTooSkewed => "clock_skew",
            AuthError::ExpiredToken(_) => "expired",
            AuthError::UnsupportedSigV2 => "sigv2",
            AuthError::InternalError => "internal",
            AuthError::Unavailable(_) => "unavailable",
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        // Every refusal from the auth layers ends up here.
        crate::gateway_metrics::record_auth_failure(self.metric_reason());
        let (status, error_code, message) = match self {
            AuthError::AccessDenied(msg) => (StatusCode::FORBIDDEN, "AccessDenied", msg),
            AuthError::Unavailable(msg) => {
                (StatusCode::SERVICE_UNAVAILABLE, "ServiceUnavailable", msg)
            }
            AuthError::SignatureDoesNotMatch => (
                StatusCode::FORBIDDEN,
                "SignatureDoesNotMatch",
                "The request signature we calculated does not match the signature you provided."
                    .to_string(),
            ),
            AuthError::RequestTimeTooSkewed => (
                StatusCode::FORBIDDEN,
                "RequestTimeTooSkewed",
                "The difference between the request time and the server's time is too large."
                    .to_string(),
            ),
            // AWS answers an expired presigned URL with this code, and clients
            // key off it to decide whether to ask for a fresh link rather than
            // to report a permissions problem.
            AuthError::ExpiredToken(msg) => (StatusCode::FORBIDDEN, "ExpiredToken", msg),
            // S3's own answer to SigV2 on a bucket that doesn't take it,
            // plus what to change: boto3 still presigns with SigV2 for a
            // custom endpoint unless told otherwise.
            AuthError::UnsupportedSigV2 => (
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "The authorization mechanism you have provided is not supported. Please use \
                 AWS4-HMAC-SHA256 (Signature Version 4). For boto3 presigned URLs, create the \
                 client with botocore.config.Config(signature_version=\"s3v4\")."
                    .to_string(),
            ),
            AuthError::InternalError => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "We encountered an internal error. Please try again.".to_string(),
            ),
        };

        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>{}</Code>
    <Message>{}</Message>
    <RequestId>{}</RequestId>
</Error>"#,
            error_code,
            message,
            crate::audit::request_id().unwrap_or_default()
        );

        Response::builder()
            .status(status)
            .header("Content-Type", "application/xml")
            .extension(crate::gateway_metrics::S3ErrorCode(error_code.to_string()))
            .body(Body::from(xml))
            .unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap()
            })
    }
}

/// Extension trait for getting auth result from request
#[allow(dead_code)]
pub trait AuthExt {
    /// Get the authenticated user's result from request extensions
    fn auth_result(&self) -> Option<&AuthResult>;
}

impl<B> AuthExt for Request<B> {
    fn auth_result(&self) -> Option<&AuthResult> {
        self.extensions().get::<AuthResult>()
    }
}

#[cfg(test)]
mod sigv4_tests {
    use super::{
        AuthError, build_canonical_query_string, build_string_to_sign, calculate_signature_v4,
        constant_time_eq, derive_signing_key, hex_sha256, is_presigned_v2,
        parse_authorization_header, url_decode, url_encode,
    };

    // ── AWS's own published vectors ───────────────────────────────────────
    //
    // The signing chain had no tests at all. These are the worked example
    // from the Signature Version 4 documentation, so they check this
    // implementation against AWS rather than against itself.

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

    #[test]
    fn the_signing_key_matches_awss_published_derivation() {
        assert_eq!(
            hex::encode(derive_signing_key(SECRET, "20150830", "us-east-1", "iam")),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
    }

    #[test]
    fn the_signature_matches_awss_worked_example() {
        let canonical_request = [
            "GET",
            "/",
            "Action=ListUsers&Version=2010-05-08",
            "content-type:application/x-www-form-urlencoded; charset=utf-8",
            "host:iam.amazonaws.com",
            "x-amz-date:20150830T123600Z",
            "",
            "content-type;host;x-amz-date",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ]
        .join("\n");

        let sts = build_string_to_sign(
            &canonical_request,
            "20150830T123600Z",
            "20150830/us-east-1/iam/aws4_request",
        );
        let key = derive_signing_key(SECRET, "20150830", "us-east-1", "iam");

        assert_eq!(
            calculate_signature_v4(&key, &sts),
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn the_empty_payload_hash_is_the_one_every_client_sends() {
        assert_eq!(
            hex_sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// Each step of the derivation must actually depend on its input.
    ///
    /// A key that ignored the date would make every signature valid forever;
    /// one that ignored the region or service would make a signature for any
    /// other service valid here.
    #[test]
    fn every_element_of_the_scope_changes_the_signing_key() {
        let base = derive_signing_key(SECRET, "20150830", "us-east-1", "s3");
        for other in [
            derive_signing_key(SECRET, "20150831", "us-east-1", "s3"),
            derive_signing_key(SECRET, "20150830", "us-west-2", "s3"),
            derive_signing_key(SECRET, "20150830", "us-east-1", "iam"),
            derive_signing_key("another-secret", "20150830", "us-east-1", "s3"),
        ] {
            assert_ne!(base, other, "the signing key ignored part of its scope");
        }
    }

    // ── Percent-coding ────────────────────────────────────────────────────

    /// A non-ASCII query parameter must canonicalise to what the client signed.
    ///
    /// `url_decode` used to push each decoded byte as a `char`, so `%C3%A9` —
    /// two bytes that are one character — became two characters and re-encoded
    /// as four bytes. `caf%C3%A9` canonicalised to `caf%C3%83%C2%A9`, the
    /// gateway signed a different string than the client, and
    /// `aws s3 ls --prefix "café/"` came back `SignatureDoesNotMatch`.
    #[test]
    fn a_non_ascii_parameter_canonicalises_to_itself() {
        for encoded in ["caf%C3%A9", "%E6%97%A5%E6%9C%AC", "%F0%9F%93%81"] {
            assert_eq!(
                url_encode(&url_decode(encoded)),
                encoded,
                "{encoded} did not survive canonicalisation"
            );
        }
    }

    #[test]
    fn unreserved_characters_are_left_alone() {
        let plain = "abcXYZ019-_.~";
        assert_eq!(url_encode(plain.as_bytes()), plain);
        assert_eq!(url_encode(&url_decode(plain)), plain);
    }

    #[test]
    fn reserved_characters_are_escaped_uppercase() {
        // AWS canonicalisation requires uppercase hex; %2f and %2F are the
        // same byte but not the same string to sign.
        assert_eq!(url_encode(b"/"), "%2F");
        assert_eq!(url_encode(b" "), "%20");
        assert_eq!(url_encode(b"="), "%3D");
    }

    #[test]
    fn a_stray_percent_does_not_swallow_the_bytes_after_it() {
        assert_eq!(url_decode("100%"), b"100%");
        assert_eq!(url_decode("%zz"), b"%zz");
        assert_eq!(url_decode("a%2"), b"a%2");
    }

    #[test]
    fn an_encoded_percent_decodes_to_one_percent() {
        assert_eq!(url_decode("100%25"), b"100%");
        assert_eq!(url_encode(&url_decode("100%25")), "100%25");
    }

    // ── Canonical query string ────────────────────────────────────────────

    #[test]
    fn query_parameters_are_sorted_by_name() {
        // The client sorts before signing; if the gateway does not, any
        // request with more than one parameter fails.
        assert_eq!(
            build_canonical_query_string("version=2&action=list&bucket=b"),
            "action=list&bucket=b&version=2"
        );
    }

    #[test]
    fn a_valueless_parameter_keeps_its_equals_sign() {
        // `?uploads` is how multipart is initiated, and AWS canonicalises it
        // as `uploads=`.
        assert_eq!(build_canonical_query_string("uploads"), "uploads=");
        assert_eq!(
            build_canonical_query_string("uploads&partNumber=1"),
            "partNumber=1&uploads="
        );
    }

    #[test]
    fn an_empty_query_is_an_empty_string() {
        assert_eq!(build_canonical_query_string(""), "");
    }

    #[test]
    fn a_non_ascii_prefix_survives_the_canonical_query_string() {
        assert_eq!(
            build_canonical_query_string("prefix=caf%C3%A9%2F&max-keys=100"),
            "max-keys=100&prefix=caf%C3%A9%2F"
        );
    }

    // ── Authorization header ──────────────────────────────────────────────

    #[test]
    fn a_sigv4_header_yields_its_key_headers_and_signature() {
        let header = "AWS4-HMAC-SHA256 \
                      Credential=AKIDEXAMPLE/20150830/us-east-1/s3/aws4_request, \
                      SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
                      Signature=deadbeef";
        let parsed = parse_authorization_header(header).expect("parse");
        assert_eq!(parsed.access_key_id, "AKIDEXAMPLE");
        assert_eq!(
            parsed.signed_headers,
            vec!["host", "x-amz-content-sha256", "x-amz-date"]
        );
        assert_eq!(parsed.signature, "deadbeef");
    }

    /// Signed header names are matched against the request case-insensitively,
    /// so they are lowercased on the way in.
    #[test]
    fn signed_header_names_are_lowercased() {
        let header = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/s3/aws4_request, \
                      SignedHeaders=Host;X-Amz-Date, Signature=abc123";
        let parsed = parse_authorization_header(header).expect("parse");
        assert_eq!(parsed.signed_headers, vec!["host", "x-amz-date"]);
    }

    /// SigV2, in a header or a presigned URL, is refused as such, so the
    /// client is told what to change rather than that its key is wrong.
    #[test]
    fn sigv2_is_refused_with_its_own_error() {
        assert!(matches!(
            parse_authorization_header("AWS AKIDEXAMPLE:c2lnbmF0dXJl"),
            Err(AuthError::UnsupportedSigV2)
        ));
        assert!(is_presigned_v2(
            "AWSAccessKeyId=AKID&Signature=abc%3D&Expires=1790914946"
        ));
        assert!(!is_presigned_v2(
            "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=a&X-Amz-Signature=b"
        ));
        assert!(!is_presigned_v2("versioning"));
    }

    #[test]
    fn a_header_that_is_not_a_signature_is_refused() {
        for header in [
            "",
            "Bearer token",
            "Basic dXNlcjpwYXNz",
            "AWS4-HMAC-SHA256 nonsense",
            "AWS no-colon-here",
        ] {
            assert!(
                parse_authorization_header(header).is_err(),
                "{header:?} was accepted as an authorization header"
            );
        }
    }

    // ── Comparison ────────────────────────────────────────────────────────

    #[test]
    fn signatures_compare_equal_only_when_they_are_equal() {
        let sig = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7";
        assert!(constant_time_eq(sig, sig));
        assert!(!constant_time_eq(sig, &sig.replace("5d672d79", "5d672d78")));
        assert!(!constant_time_eq(sig, &sig[..sig.len() - 1]));
        assert!(!constant_time_eq(sig, ""));
        assert!(constant_time_eq("", ""));
    }

    /// Case matters: hex signatures are lowercase, and treating the two as
    /// equal would widen what counts as a valid signature.
    #[test]
    fn signature_comparison_is_case_sensitive() {
        assert!(!constant_time_eq("deadbeef", "DEADBEEF"));
    }
}
