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
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, NaiveDateTime, Utc};
use hmac::{Hmac, Mac};
use objectio_auth::{AuthResult, CredentialScope, Operation};
use objectio_proto::metadata::{
    GetAccessKeyForAuthRequest, GetUserGroupsRequest, KeyOperation,
    metadata_service_client::MetadataServiceClient,
};
use parking_lot::RwLock;
use regex::Regex;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tonic::transport::Channel;
use tracing::{debug, warn};

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

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
            cache_ttl_secs: 300, // 5 minutes
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
                AuthError::AccessDenied(format!("credential lookup failed: {}", e))
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
    if request.headers().get("authorization").is_some() {
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
    if path == "/health" || path == "/metrics" || path == "/_status" {
        return Ok(next.run(request).await);
    }

    // Parse authorization header to get access key ID
    let auth_header = request
        .headers()
        .get("authorization")
        .ok_or(AuthError::AccessDenied(
            "missing authorization header".to_string(),
        ))?
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
        let Some(token) = &session_token else {
            return Err(AuthError::AccessDenied(
                "temporary credentials require X-Amz-Security-Token".to_string(),
            ));
        };
        let Some(sts) = &auth_state.sts_provider else {
            return Err(AuthError::AccessDenied(
                "STS credential vending is not configured on this gateway".to_string(),
            ));
        };
        let session_info = sts.validate(token).ok_or_else(|| {
            AuthError::AccessDenied("invalid or expired session token".to_string())
        })?;

        // Recover the derived secret and run the SAME SigV4 verify path as
        // permanent keys — without this the session token is the only
        // proof, which is replayable.
        let derived_secret = sts.derive_secret(access_key_id);
        let cred = CachedCredential {
            access_key_id: access_key_id.to_string(),
            secret_access_key: derived_secret,
            user_id: session_info.user_arn.clone(),
            user_arn: session_info.user_arn.clone(),
            tenant: String::new(),
            scope: Some(CredentialScope {
                scope: session_info.scope.clone(),
                operation: session_info.operation,
            }),
            cached_at: std::time::Instant::now(),
        };
        match &parsed {
            ParsedAuth::V4 {
                signed_headers,
                signature,
                ..
            } => {
                verify_request_v4(
                    &request,
                    signed_headers,
                    signature,
                    &cred,
                    &auth_state.region,
                )?;
            }
            ParsedAuth::V2 { signature, .. } => {
                verify_request_v2(&request, signature, &cred)?;
            }
        }

        debug!(
            "STS auth ok: user_arn={} scope={} op={:?}",
            session_info.user_arn, session_info.scope, session_info.operation
        );
        let auth_result = AuthResult {
            user_id: session_info.user_arn.clone(),
            user_arn: session_info.user_arn,
            access_key_id: access_key_id.to_string(),
            group_arns: Vec::new(),
            group_ids: Vec::new(),
            tenant: String::new(),
            auth_mode: objectio_auth::AuthMode::Sts,
            scope: cred.scope.clone(),
        };
        request.extensions_mut().insert(auth_result);
        return Ok(next.run(request).await);
    }

    // Fetch credentials from metadata service (permanent keys)
    let cred = auth_state.lookup_credential(access_key_id).await?;

    // Verify the signature based on auth version
    let mut auth_result = match &parsed {
        ParsedAuth::V4 {
            signed_headers,
            signature,
            ..
        } => verify_request_v4(
            &request,
            signed_headers,
            signature,
            &cred,
            &auth_state.region,
        )?,
        ParsedAuth::V2 { signature, .. } => verify_request_v2(&request, signature, &cred)?,
    };

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
    request.extensions_mut().insert(auth_result);
    Ok(next.run(request).await)
}

/// Parsed authorization header (supports both V4 and V2)
pub enum ParsedAuth {
    V4 {
        access_key_id: String,
        signed_headers: Vec<String>,
        signature: String,
    },
    V2 {
        access_key_id: String,
        signature: String,
    },
}

impl ParsedAuth {
    pub fn access_key_id(&self) -> &str {
        match self {
            ParsedAuth::V4 { access_key_id, .. } => access_key_id,
            ParsedAuth::V2 { access_key_id, .. } => access_key_id,
        }
    }
}

/// Parse the Authorization header (supports both SigV4 and SigV2)
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

        Ok(ParsedAuth::V4 {
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
    } else if let Some(credentials) = header.strip_prefix("AWS ") {
        // SigV2 format: AWS AccessKeyId:Signature
        let parts: Vec<&str> = credentials.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(AuthError::AccessDenied(
                "invalid SigV2 authorization header".to_string(),
            ));
        }

        debug!("Using SigV2 authentication (legacy)");
        Ok(ParsedAuth::V2 {
            access_key_id: parts[0].to_string(),
            signature: parts[1].to_string(),
        })
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
    })
}

/// Sub-resources that should be included in the canonical resource for SigV2
const SIGV2_SUB_RESOURCES: &[&str] = &[
    "acl",
    "cors",
    "delete",
    "lifecycle",
    "location",
    "logging",
    "notification",
    "partNumber",
    "policy",
    "requestPayment",
    "response-cache-control",
    "response-content-disposition",
    "response-content-encoding",
    "response-content-language",
    "response-content-type",
    "response-expires",
    "restore",
    "tagging",
    "torrent",
    "uploadId",
    "uploads",
    "versionId",
    "versioning",
    "versions",
    "website",
];

/// Verify SigV2 request signature
pub fn verify_request_v2<B>(
    request: &Request<B>,
    signature: &str,
    cred: &CachedCredential,
) -> Result<AuthResult, AuthError> {
    // Get the request date
    let date_str = get_request_date(request)?;

    // Try to parse and validate date
    if let Ok(date) = parse_date_v2(&date_str) {
        let now = Utc::now();
        let diff = now.signed_duration_since(date);
        if diff.num_minutes().abs() > 15 {
            return Err(AuthError::RequestTimeTooSkewed);
        }
    }

    // Build string to sign for SigV2
    let string_to_sign = build_string_to_sign_v2(request, &date_str)?;

    // Calculate signature using HMAC-SHA1
    let calculated_signature = calculate_signature_v2(&cred.secret_access_key, &string_to_sign);

    // Compare signatures
    if !constant_time_eq(&calculated_signature, signature) {
        debug!(
            "SigV2 mismatch:\n  String to Sign:\n{}\n  Calculated: {}\n  Provided: {}",
            string_to_sign, calculated_signature, signature
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
    })
}

/// Build string to sign for SigV2
fn build_string_to_sign_v2<B>(request: &Request<B>, date_str: &str) -> Result<String, AuthError> {
    let method = request.method().as_str();

    // Get Content-MD5 header (empty if not present)
    let content_md5 = request
        .headers()
        .get("content-md5")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Get Content-Type header (empty if not present)
    let content_type = request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Use x-amz-date if present, otherwise use Date header value
    let date_field = if request.headers().contains_key("x-amz-date") {
        ""
    } else {
        date_str
    };

    // Build canonicalized AMZ headers
    let canonicalized_amz_headers = build_canonicalized_amz_headers(request);

    // Build canonicalized resource
    let canonicalized_resource = build_canonicalized_resource_v2(request);

    Ok(format!(
        "{}\n{}\n{}\n{}\n{}{}",
        method,
        content_md5,
        content_type,
        date_field,
        canonicalized_amz_headers,
        canonicalized_resource
    ))
}

/// Build canonicalized AMZ headers for SigV2
fn build_canonicalized_amz_headers<B>(request: &Request<B>) -> String {
    let mut amz_headers: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (name, value) in request.headers().iter() {
        let name_lower = name.as_str().to_lowercase();
        if name_lower.starts_with("x-amz-")
            && let Ok(value_str) = value.to_str()
        {
            let trimmed = value_str.split_whitespace().collect::<Vec<_>>().join(" ");
            amz_headers.entry(name_lower).or_default().push(trimmed);
        }
    }

    let mut result = String::new();
    for (name, values) in amz_headers {
        result.push_str(&format!("{}:{}\n", name, values.join(",")));
    }
    result
}

/// Build canonicalized resource for SigV2
fn build_canonicalized_resource_v2<B>(request: &Request<B>) -> String {
    let uri = request.uri();
    let path = uri.path();

    let mut resource = if path.is_empty() {
        "/".to_string()
    } else {
        path.to_string()
    };

    // Add sub-resources if present in query string
    if let Some(query) = uri.query() {
        let mut sub_resources: Vec<(String, Option<String>)> = Vec::new();

        for param in query.split('&') {
            let mut parts = param.splitn(2, '=');
            let key = parts.next().unwrap_or("");
            let value = parts.next();

            if SIGV2_SUB_RESOURCES.contains(&key) {
                sub_resources.push((key.to_string(), value.map(|s| s.to_string())));
            }
        }

        if !sub_resources.is_empty() {
            sub_resources.sort_by(|a, b| a.0.cmp(&b.0));

            let sub_resource_str: Vec<String> = sub_resources
                .into_iter()
                .map(|(k, v)| {
                    if let Some(val) = v {
                        format!("{}={}", k, val)
                    } else {
                        k
                    }
                })
                .collect();

            resource.push('?');
            resource.push_str(&sub_resource_str.join("&"));
        }
    }

    resource
}

/// Calculate SigV2 signature using HMAC-SHA1
fn calculate_signature_v2(secret_key: &str, string_to_sign: &str) -> String {
    let mut mac =
        HmacSha1::new_from_slice(secret_key.as_bytes()).expect("HMAC can take key of any size");
    mac.update(string_to_sign.as_bytes());
    let result = mac.finalize().into_bytes();
    BASE64.encode(result)
}

/// Parse date for SigV2 (supports multiple formats)
fn parse_date_v2(date_str: &str) -> Result<DateTime<Utc>, AuthError> {
    // Try RFC 2822 format first
    if let Ok(dt) = DateTime::parse_from_rfc2822(date_str) {
        return Ok(dt.with_timezone(&Utc));
    }

    // Try ISO 8601 format
    if let Ok(dt) = NaiveDateTime::parse_from_str(date_str, "%Y%m%dT%H%M%SZ") {
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
    }

    // Try common HTTP date format
    if let Ok(dt) = NaiveDateTime::parse_from_str(date_str, "%a, %d %b %Y %H:%M:%S GMT") {
        return Ok(DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));
    }

    Err(AuthError::AccessDenied("invalid date format".to_string()))
}

/// Get the request date from headers
fn get_request_date<B>(request: &Request<B>) -> Result<String, AuthError> {
    if let Some(date) = request.headers().get("x-amz-date") {
        return date
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| AuthError::AccessDenied("invalid date format".to_string()));
    }
    if let Some(date) = request.headers().get("date") {
        return date
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| AuthError::AccessDenied("invalid date format".to_string()));
    }
    Err(AuthError::AccessDenied("missing date header".to_string()))
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
            Some(v) => v
                .to_str()
                .map_err(|_| AuthError::AccessDenied("invalid header value".to_string()))?,
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
fn derive_signing_key(secret_key: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_secret = format!("AWS4{}", secret_key);
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Calculate the SigV4 signature
fn calculate_signature_v4(signing_key: &[u8], string_to_sign: &str) -> String {
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
fn constant_time_eq(a: &str, b: &str) -> bool {
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
    /// Internal error
    #[allow(dead_code)]
    InternalError,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_code, message) = match self {
            AuthError::AccessDenied(msg) => (StatusCode::FORBIDDEN, "AccessDenied", msg),
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
    <RequestId>unknown</RequestId>
</Error>"#,
            error_code, message
        );

        Response::builder()
            .status(status)
            .header("Content-Type", "application/xml")
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
        ParsedAuth, build_canonical_query_string, build_string_to_sign, calculate_signature_v4,
        constant_time_eq, derive_signing_key, hex_sha256, parse_authorization_header, url_decode,
        url_encode,
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
        match parse_authorization_header(header).expect("parse") {
            ParsedAuth::V4 {
                access_key_id,
                signed_headers,
                signature,
            } => {
                assert_eq!(access_key_id, "AKIDEXAMPLE");
                assert_eq!(
                    signed_headers,
                    vec!["host", "x-amz-content-sha256", "x-amz-date"]
                );
                assert_eq!(signature, "deadbeef");
            }
            ParsedAuth::V2 { .. } => panic!("parsed a SigV4 header as SigV2"),
        }
    }

    /// Signed header names are matched against the request case-insensitively,
    /// so they are lowercased on the way in.
    #[test]
    fn signed_header_names_are_lowercased() {
        let header = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/s3/aws4_request, \
                      SignedHeaders=Host;X-Amz-Date, Signature=abc123";
        match parse_authorization_header(header).expect("parse") {
            ParsedAuth::V4 { signed_headers, .. } => {
                assert_eq!(signed_headers, vec!["host", "x-amz-date"]);
            }
            ParsedAuth::V2 { .. } => panic!("wrong variant"),
        }
    }

    #[test]
    fn a_sigv2_header_splits_on_the_first_colon_only() {
        // A secret-derived signature is base64 and can itself contain no
        // colon, but the key id must not be allowed to eat one either.
        match parse_authorization_header("AWS AKIDEXAMPLE:abc:def").expect("parse") {
            ParsedAuth::V2 {
                access_key_id,
                signature,
            } => {
                assert_eq!(access_key_id, "AKIDEXAMPLE");
                assert_eq!(signature, "abc:def");
            }
            ParsedAuth::V4 { .. } => panic!("parsed a SigV2 header as SigV4"),
        }
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
