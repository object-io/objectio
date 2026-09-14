//! Centralized S3 authorization.
//!
//! Every S3 route is authorized here, in one middleware, rather than by
//! per-handler calls. The handler-side pattern this replaces covered 7 of 25
//! handlers and left whole routes unguarded — most importantly the multipart
//! upload path, which had no check at all, so any valid key could write into
//! any bucket once a client crossed the 8 MB threshold and switched to
//! multipart.
//!
//! The layer runs immediately after [`crate::auth_middleware::auth_layer`], so
//! the caller's identity is already on the request. It maps method + path +
//! query onto an S3 action and a resource ARN, then evaluates the target
//! bucket's policy against them.
//!
//! Only path-style addressing (`/{bucket}/{key…}`) is handled — the gateway
//! has no virtual-hosted-style rewrite, so there is no host-derived bucket to
//! consider.
//!
//! ## Semantics
//!
//! This preserves the previous authorization *outcome* exactly — an explicit
//! `Deny` in a bucket policy blocks, everything else allows — and only widens
//! where it is applied. Turning "no policy anywhere" into owner-only, and
//! folding in identity policies and per-key scopes, change the default and
//! land separately; keeping them out keeps this coverage fix reviewable on
//! its own.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use objectio_auth::{
    AuthResult,
    policy::{BucketPolicy, PolicyDecision, RequestContext},
};
use objectio_proto::metadata::{
    GetBucketPolicyRequest, GetBucketRequest, GetPolicyRequest, ListAttachedPoliciesRequest,
};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, warn};

use crate::s3::{AppState, S3Error, build_s3_arn, sse_condition_vars};

/// How long a fetched bucket policy stays usable before it is re-read from
/// meta. Short, because this is the window in which a policy change has not
/// taken effect yet; long enough that a hot bucket costs one meta RPC per
/// window instead of one per request.
pub const POLICY_CACHE_TTL_SECS: u64 = 15;

/// What authorization a request needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authz {
    /// Nothing to evaluate — service-level routes with no bucket.
    Skip,
    /// The handler runs a finer-grained check of its own. Batch delete uses
    /// this: S3 requires per-key `AccessDenied` entries inside a 200 response
    /// rather than a single 403 for the whole request.
    DeferToHandler,
    /// Evaluate `action` against this bucket (and key, when object-scoped).
    Check {
        action: &'static str,
        bucket: String,
        key: Option<String>,
    },
}

/// Percent-decode one path segment. Falls back to the raw text when the
/// escape sequence is not valid UTF-8, matching how axum's `Path` extractor
/// surfaces the same input to handlers.
fn decode(segment: &str) -> String {
    urlencoding::decode(segment).map_or_else(|_| segment.to_string(), |s| s.into_owned())
}

/// Is `name` present as a query parameter? S3 sub-resources are signalled by
/// presence alone (`?uploads`, `?policy`), so the value is irrelevant.
fn has(query: &str, name: &str) -> bool {
    query
        .split('&')
        .any(|pair| pair.split('=').next().unwrap_or("") == name)
}

/// Map an incoming request onto the S3 action and resource it needs.
pub fn classify(method: &Method, path: &str, query: &str) -> Authz {
    let trimmed = path.trim_start_matches('/');

    // `GET /` (ListAllMyBuckets) is already tenant-filtered by the handler and
    // has no bucket to evaluate against; `/health` is deliberately open.
    if trimmed.is_empty() || trimmed == "health" {
        return Authz::Skip;
    }

    let (raw_bucket, raw_key) = trimmed.split_once('/').unwrap_or((trimmed, ""));
    let bucket = decode(raw_bucket);

    // A trailing slash (`/{bucket}/`) routes to the bucket handlers.
    if raw_key.is_empty() {
        classify_bucket(method, bucket, query)
    } else {
        classify_object(method, bucket, decode(raw_key), query)
    }
}

fn classify_bucket(method: &Method, bucket: String, query: &str) -> Authz {
    let action = match *method {
        Method::PUT => {
            if has(query, "policy") {
                "s3:PutBucketPolicy"
            } else if has(query, "versioning") {
                "s3:PutBucketVersioning"
            } else if has(query, "object-lock") {
                "s3:PutBucketObjectLockConfiguration"
            } else if has(query, "lifecycle") {
                "s3:PutLifecycleConfiguration"
            } else if has(query, "encryption") {
                "s3:PutEncryptionConfiguration"
            } else {
                "s3:CreateBucket"
            }
        }
        Method::DELETE => {
            if has(query, "policy") {
                "s3:DeleteBucketPolicy"
            } else if has(query, "lifecycle") {
                "s3:PutLifecycleConfiguration"
            } else if has(query, "encryption") {
                "s3:PutEncryptionConfiguration"
            } else {
                "s3:DeleteBucket"
            }
        }
        Method::HEAD => "s3:ListBucket",
        Method::GET => {
            if has(query, "policy") {
                "s3:GetBucketPolicy"
            } else if has(query, "versioning") {
                "s3:GetBucketVersioning"
            } else if has(query, "object-lock") {
                "s3:GetBucketObjectLockConfiguration"
            } else if has(query, "lifecycle") {
                "s3:GetLifecycleConfiguration"
            } else if has(query, "encryption") {
                "s3:GetEncryptionConfiguration"
            } else if has(query, "versions") {
                "s3:ListBucketVersions"
            } else if has(query, "uploads") {
                "s3:ListBucketMultipartUploads"
            } else {
                "s3:ListBucket"
            }
        }
        Method::POST => {
            if has(query, "delete") {
                return Authz::DeferToHandler;
            }
            // Prefix grep reads every object under a prefix. Evaluated at
            // bucket scope; per-key evaluation belongs with the
            // deny-by-default work, where a prefix-limited grant would
            // otherwise reject the whole scan.
            if has(query, "grep") {
                return Authz::Check {
                    action: "s3:GetObject",
                    bucket,
                    key: Some("*".to_string()),
                };
            }
            return Authz::Skip;
        }
        _ => return Authz::Skip,
    };

    Authz::Check {
        action,
        bucket,
        key: None,
    }
}

fn classify_object(method: &Method, bucket: String, key: String, query: &str) -> Authz {
    let action = match *method {
        // `?uploadId` + `?partNumber` is an UploadPart, which AWS authorizes
        // as s3:PutObject — same action as the plain write.
        Method::PUT => {
            if has(query, "retention") {
                "s3:PutObjectRetention"
            } else if has(query, "legal-hold") {
                "s3:PutObjectLegalHold"
            } else {
                "s3:PutObject"
            }
        }
        Method::GET => {
            if has(query, "retention") {
                "s3:GetObjectRetention"
            } else if has(query, "legal-hold") {
                "s3:GetObjectLegalHold"
            } else if has(query, "uploadId") {
                "s3:ListMultipartUploadParts"
            } else {
                "s3:GetObject"
            }
        }
        Method::HEAD => "s3:GetObject",
        Method::DELETE => {
            if has(query, "uploadId") {
                "s3:AbortMultipartUpload"
            } else {
                "s3:DeleteObject"
            }
        }
        // `?uploads` initiates and `?uploadId` completes a multipart upload;
        // both write the object. `?grep` reads it.
        Method::POST => {
            if has(query, "grep") {
                "s3:GetObject"
            } else {
                "s3:PutObject"
            }
        }
        _ => return Authz::Skip,
    };

    Authz::Check {
        action,
        bucket,
        key: Some(key),
    }
}

/// TTL cache backing every authorization decision.
///
/// Without it the chain would add three or more meta round-trips to every
/// object operation — bucket policy, bucket owner, and one lookup per attached
/// identity policy — including on each part of a multipart upload.
pub struct AuthzCache {
    buckets: RwLock<HashMap<String, BucketEntry>>,
    identities: RwLock<HashMap<String, IdentityEntry>>,
    ttl: Duration,
}

#[derive(Clone)]
struct BucketEntry {
    /// `None` means the bucket has no enforceable policy — either none is set
    /// or the stored JSON did not parse.
    policy: Option<Arc<BucketPolicy>>,
    /// `user_id` of the owner. Empty or `"default"` marks a bucket created
    /// before the gateway recorded real ownership.
    owner: String,
    cached_at: Instant,
}

/// Named, parsed policies attached to one principal.
type AttachedPolicies = Arc<Vec<(String, Arc<BucketPolicy>)>>;

/// Policies attached to one principal (a user or a group), already parsed.
#[derive(Clone)]
struct IdentityEntry {
    policies: AttachedPolicies,
    cached_at: Instant,
}

impl AuthzCache {
    #[must_use]
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            identities: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    fn bucket(&self, bucket: &str) -> Option<BucketEntry> {
        let entries = self.buckets.read();
        let entry = entries.get(bucket)?;
        (entry.cached_at.elapsed() < self.ttl).then(|| entry.clone())
    }

    fn put_bucket(&self, bucket: &str, entry: BucketEntry) {
        self.buckets.write().insert(bucket.to_string(), entry);
    }

    fn identity(&self, principal: &str) -> Option<AttachedPolicies> {
        let entries = self.identities.read();
        let entry = entries.get(principal)?;
        (entry.cached_at.elapsed() < self.ttl).then(|| Arc::clone(&entry.policies))
    }

    fn put_identity(&self, principal: &str, policies: AttachedPolicies) {
        self.identities.write().insert(
            principal.to_string(),
            IdentityEntry {
                policies,
                cached_at: Instant::now(),
            },
        );
    }

    /// Drop the cached entry for one bucket. Called when this gateway changes
    /// a bucket's policy or owner, so the writer sees its own change
    /// immediately; other gateways pick it up within [`POLICY_CACHE_TTL_SECS`].
    pub fn invalidate(&self, bucket: &str) {
        self.buckets.write().remove(bucket);
    }

    /// Drop the cached policies for one user or group, after an attach or
    /// detach.
    pub fn invalidate_identity(&self, principal: &str) {
        self.identities.write().remove(principal);
    }
}

impl Default for AuthzCache {
    fn default() -> Self {
        Self::new(POLICY_CACHE_TTL_SECS)
    }
}

/// Fetch a bucket's policy and owner, via the cache when it is warm.
///
/// Meta errors yield an empty entry rather than propagating: a metadata
/// hiccup must not start failing requests. An unreadable bucket therefore
/// looks unowned and unpoliced, which the chain treats as legacy.
async fn load_bucket(state: &AppState, bucket: &str) -> BucketEntry {
    if let Some(cached) = state.policy_cache.bucket(bucket) {
        return cached;
    }

    let mut client = state.meta_client.clone();

    let policy = match client
        .get_bucket_policy(GetBucketPolicyRequest {
            bucket: bucket.to_string(),
        })
        .await
    {
        Ok(response) => {
            let resp = response.into_inner();
            if resp.has_policy {
                match BucketPolicy::from_json(&resp.policy_json) {
                    Ok(policy) => Some(Arc::new(policy)),
                    Err(e) => {
                        error!("Failed to parse bucket policy for {bucket}: {e}");
                        None
                    }
                }
            } else {
                None
            }
        }
        Err(e) => {
            if e.code() != tonic::Code::NotFound {
                error!("Failed to fetch bucket policy for {bucket}: {e}");
            }
            None
        }
    };

    let owner = match client
        .get_bucket(GetBucketRequest {
            name: bucket.to_string(),
        })
        .await
    {
        Ok(response) => response
            .into_inner()
            .bucket
            .map(|b| b.owner)
            .unwrap_or_default(),
        Err(e) => {
            if e.code() != tonic::Code::NotFound {
                error!("Failed to fetch bucket meta for {bucket}: {e}");
            }
            String::new()
        }
    };

    let entry = BucketEntry {
        policy,
        owner,
        cached_at: Instant::now(),
    };
    state.policy_cache.put_bucket(bucket, entry.clone());
    entry
}

/// Load and parse every policy attached to one principal (user or group).
async fn load_identity_policies(
    state: &AppState,
    principal_id: &str,
    is_group: bool,
) -> AttachedPolicies {
    if principal_id.is_empty() {
        return Arc::new(Vec::new());
    }
    if let Some(cached) = state.policy_cache.identity(principal_id) {
        return cached;
    }

    let mut client = state.meta_client.clone();
    let request = if is_group {
        ListAttachedPoliciesRequest {
            user_id: String::new(),
            group_id: principal_id.to_string(),
        }
    } else {
        ListAttachedPoliciesRequest {
            user_id: principal_id.to_string(),
            group_id: String::new(),
        }
    };

    let names = match client.list_attached_policies(request).await {
        Ok(r) => r.into_inner().policy_names,
        Err(e) => {
            // Treated as "no attached policies". Combined with the ownership
            // fallback this fails closed for non-owners rather than opening up.
            error!("list_attached_policies for {principal_id} failed: {e}");
            Vec::new()
        }
    };

    let mut policies = Vec::with_capacity(names.len());
    for name in names {
        let Ok(resp) = client
            .get_policy(GetPolicyRequest { name: name.clone() })
            .await
        else {
            continue;
        };
        let inner = resp.into_inner();
        let Some(obj) = inner.policy.filter(|_| inner.found) else {
            continue;
        };
        match BucketPolicy::from_json(&obj.policy_json) {
            Ok(policy) => policies.push((name, Arc::new(policy))),
            Err(e) => warn!("attached policy '{name}' for {principal_id} failed to parse: {e}"),
        }
    }

    let policies = Arc::new(policies);
    state
        .policy_cache
        .put_identity(principal_id, Arc::clone(&policies));
    policies
}

/// Everything one authorization decision needs.
///
/// Grouped into a struct because the two resource identities differ: `key`
/// builds the policy resource ARN, while `scope_key` is what a credential
/// scope is tested against.
pub struct AuthzRequest<'a> {
    pub method: &'a Method,
    pub action: &'a str,
    pub bucket: &'a str,
    /// Object key when the request targets one; `None` for bucket-level
    /// requests, which get a bucket ARN.
    pub key: Option<&'a str>,
    /// Key used for scope containment. For bucket-level requests this is the
    /// `?prefix=` value, so a LIST narrower than the scope is admitted and a
    /// broader one is refused.
    pub scope_key: &'a str,
    pub headers: Option<&'a HeaderMap>,
}

/// Evaluate one request against the full chain.
///
/// Precedence, in order:
///
/// 1. explicit `Deny` in any identity policy or the bucket policy — terminal
/// 2. the credential's own scope, which can only narrow
/// 3. `Allow` in any identity policy or the bucket policy
/// 4. the caller owns the bucket, or is the system admin
/// 5. otherwise deny
///
/// Step 5 is the change from "no policy anywhere means everyone" to "no policy
/// anywhere means the owner". Buckets with no recorded owner are exempt while
/// `--authz-legacy-open-buckets` is set, so an existing deployment keeps
/// working until its owners are backfilled.
///
/// Returns `Some(response)` when the request must be rejected.
pub async fn authorize(
    state: &AppState,
    auth: &AuthResult,
    req: &AuthzRequest<'_>,
) -> Option<Response> {
    // Scope first. It needs no meta round-trip, and it can only ever reject,
    // so resolving it early skips policy loads for requests that cannot
    // succeed either way.
    if let Some(scope) = &auth.scope {
        let method = req.method.as_str();
        if !scope.allows(req.bucket, req.scope_key, method) {
            let reason = scope.denial_reason(req.bucket, req.scope_key, method);
            debug!(
                "Scope denied {} {} s3://{}/{}: {reason}",
                auth.access_key_id, method, req.bucket, req.scope_key
            );
            return Some(deny(&reason));
        }
    }

    // The system admin bypasses the chain, so a misconfigured policy can never
    // lock every operator out of the cluster.
    if auth.user_arn == crate::admin::SYSTEM_ADMIN_USER_ARN {
        return None;
    }

    let bucket = load_bucket(state, req.bucket).await;

    let resource = build_s3_arn(req.bucket, req.key);
    let mut context = RequestContext::new(&auth.user_arn, req.action, &resource);
    for (k, v) in sse_condition_vars(req.headers) {
        context = context.with_variable(k, v);
    }
    // Surface credential-type so policies can deny permanent-key direct
    // access while still allowing STS-vended sessions through.
    context = context.with_variable(
        "obio:CredentialType".to_string(),
        auth.auth_mode.as_str().to_string(),
    );

    let mut any_allow = false;

    // Identity policies: the user's own, plus every group it belongs to.
    let mut principals: Vec<(&str, bool)> = vec![(auth.user_id.as_str(), false)];
    principals.extend(auth.group_ids.iter().map(|g| (g.as_str(), true)));

    for (principal, is_group) in principals {
        for (name, policy) in load_identity_policies(state, principal, is_group)
            .await
            .iter()
        {
            match state.policy_evaluator.evaluate(policy, &context) {
                PolicyDecision::Deny => {
                    debug!(
                        "Identity policy '{name}' denied {} {} {}",
                        auth.user_arn, req.action, resource
                    );
                    return Some(deny(&format!(
                        "Action {} on {resource} denied by policy {name}",
                        req.action
                    )));
                }
                PolicyDecision::Allow => any_allow = true,
                PolicyDecision::ImplicitDeny => {}
            }
        }
    }

    if let Some(policy) = &bucket.policy {
        match state.policy_evaluator.evaluate(policy, &context) {
            PolicyDecision::Deny => {
                debug!(
                    "Bucket policy denied access: {} {} {}",
                    auth.user_arn, req.action, resource
                );
                return Some(deny("Access Denied by bucket policy"));
            }
            PolicyDecision::Allow => any_allow = true,
            PolicyDecision::ImplicitDeny => {}
        }
    }

    if any_allow {
        return None;
    }

    // Nothing granted it explicitly — fall back to ownership.
    if !bucket.owner.is_empty() && bucket.owner == auth.user_id {
        return None;
    }

    // A bucket with no recorded owner predates ownership tracking. Denying
    // those outright would lock an existing deployment out of every bucket it
    // already has, so they stay open until backfilled and the flag is cleared.
    if is_legacy_unowned(&bucket.owner) {
        if state.legacy_open_buckets {
            return None;
        }
        debug!(
            "Denying {} {} on unowned bucket {} (legacy-open disabled)",
            auth.user_arn, req.action, req.bucket
        );
    }

    Some(deny(&format!(
        "No policy allows {} on {resource}",
        req.action
    )))
}

/// Buckets created before the gateway recorded a real owner carry either an
/// empty owner or the literal placeholder `create_bucket` used to write.
fn is_legacy_unowned(owner: &str) -> bool {
    owner.is_empty() || owner == LEGACY_BUCKET_OWNER
}

/// The placeholder `create_bucket` wrote into every bucket before ownership
/// was tracked.
pub const LEGACY_BUCKET_OWNER: &str = "default";

fn deny(message: &str) -> Response {
    S3Error::xml_response("AccessDenied", message, StatusCode::FORBIDDEN)
}

/// Pull a single query parameter out of a raw query string, URL-decoded.
/// Used to read `?prefix=` for scope containment on bucket-level requests.
fn extract_query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == name).then(|| decode(v))
    })
}

/// The bucket named by an `s3://bucket/prefix/` scope URI.
///
/// Returns an empty string for a malformed scope, which matches no bucket —
/// the safe direction for a filter.
#[must_use]
pub fn scope_bucket(scope: &str) -> String {
    scope
        .strip_prefix("s3://")
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string()
}

/// Authorization middleware. Runs after `auth_layer`, before any handler.
pub async fn authz_layer(
    State(state): State<Arc<AppState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // No identity on the request means `--no-auth`, or a route that sits ahead
    // of the auth layer. Either way there is no principal to evaluate.
    let Some(auth) = request.extensions().get::<AuthResult>().cloned() else {
        return next.run(request).await;
    };

    let uri = request.uri().clone();
    let classification = classify(request.method(), uri.path(), uri.query().unwrap_or(""));

    let Authz::Check {
        action,
        bucket,
        key,
    } = classification
    else {
        return next.run(request).await;
    };

    // Object requests are contained by their own key; bucket requests by the
    // prefix they ask for, so a scoped key can LIST inside its scope but not
    // above it.
    let scope_key = key.clone().unwrap_or_else(|| {
        extract_query_param(uri.query().unwrap_or(""), "prefix").unwrap_or_default()
    });

    if let Some(deny) = authorize(
        &state,
        &auth,
        &AuthzRequest {
            method: request.method(),
            action,
            bucket: &bucket,
            key: key.as_deref(),
            scope_key: &scope_key,
            headers: Some(request.headers()),
        },
    )
    .await
    {
        return deny;
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_of(method: Method, path: &str, query: &str) -> (&'static str, String, Option<String>) {
        match classify(&method, path, query) {
            Authz::Check {
                action,
                bucket,
                key,
            } => (action, bucket, key),
            other => panic!("expected Check, got {other:?}"),
        }
    }

    #[test]
    fn service_routes_need_no_bucket_policy() {
        assert_eq!(classify(&Method::GET, "/", ""), Authz::Skip);
        assert_eq!(classify(&Method::GET, "/health", ""), Authz::Skip);
    }

    #[test]
    fn bucket_subresources_map_to_distinct_actions() {
        assert_eq!(check_of(Method::GET, "/b", "").0, "s3:ListBucket");
        assert_eq!(check_of(Method::HEAD, "/b", "").0, "s3:ListBucket");
        assert_eq!(
            check_of(Method::GET, "/b", "policy").0,
            "s3:GetBucketPolicy"
        );
        assert_eq!(
            check_of(Method::PUT, "/b", "policy").0,
            "s3:PutBucketPolicy"
        );
        assert_eq!(
            check_of(Method::DELETE, "/b", "policy").0,
            "s3:DeleteBucketPolicy"
        );
        assert_eq!(check_of(Method::PUT, "/b", "").0, "s3:CreateBucket");
        assert_eq!(check_of(Method::DELETE, "/b", "").0, "s3:DeleteBucket");
        assert_eq!(
            check_of(Method::GET, "/b", "uploads").0,
            "s3:ListBucketMultipartUploads"
        );
    }

    #[test]
    fn trailing_slash_is_a_bucket_request() {
        let (action, bucket, key) = check_of(Method::GET, "/b/", "");
        assert_eq!(action, "s3:ListBucket");
        assert_eq!(bucket, "b");
        assert_eq!(key, None);
    }

    #[test]
    fn object_routes_carry_the_key() {
        let (action, bucket, key) = check_of(Method::GET, "/b/a/deep/key.txt", "");
        assert_eq!(action, "s3:GetObject");
        assert_eq!(bucket, "b");
        assert_eq!(key.as_deref(), Some("a/deep/key.txt"));
        assert_eq!(check_of(Method::HEAD, "/b/k", "").0, "s3:GetObject");
        assert_eq!(check_of(Method::PUT, "/b/k", "").0, "s3:PutObject");
        assert_eq!(check_of(Method::DELETE, "/b/k", "").0, "s3:DeleteObject");
    }

    /// The gap this middleware exists to close: every multipart verb now maps
    /// onto a real action instead of reaching the handler unchecked.
    #[test]
    fn multipart_upload_path_is_authorized() {
        assert_eq!(check_of(Method::POST, "/b/k", "uploads").0, "s3:PutObject");
        assert_eq!(
            check_of(Method::PUT, "/b/k", "partNumber=1&uploadId=abc").0,
            "s3:PutObject"
        );
        assert_eq!(
            check_of(Method::POST, "/b/k", "uploadId=abc").0,
            "s3:PutObject"
        );
        assert_eq!(
            check_of(Method::DELETE, "/b/k", "uploadId=abc").0,
            "s3:AbortMultipartUpload"
        );
        assert_eq!(
            check_of(Method::GET, "/b/k", "uploadId=abc").0,
            "s3:ListMultipartUploadParts"
        );
    }

    #[test]
    fn object_lock_subresources_are_distinct_from_the_object() {
        assert_eq!(
            check_of(Method::PUT, "/b/k", "retention").0,
            "s3:PutObjectRetention"
        );
        assert_eq!(
            check_of(Method::GET, "/b/k", "legal-hold").0,
            "s3:GetObjectLegalHold"
        );
    }

    #[test]
    fn batch_delete_defers_to_the_per_key_loop() {
        assert_eq!(
            classify(&Method::POST, "/b", "delete"),
            Authz::DeferToHandler
        );
    }

    #[test]
    fn prefix_grep_is_a_bucket_wide_read() {
        let (action, bucket, key) = check_of(Method::POST, "/b", "grep");
        assert_eq!(action, "s3:GetObject");
        assert_eq!(bucket, "b");
        assert_eq!(key.as_deref(), Some("*"));
    }

    #[test]
    fn percent_encoded_keys_are_decoded_to_match_policy_resources() {
        let (_, bucket, key) = check_of(Method::GET, "/my%20bucket/a%2Fb%20c.txt", "");
        assert_eq!(bucket, "my bucket");
        assert_eq!(key.as_deref(), Some("a/b c.txt"));
    }

    #[test]
    fn query_matching_is_on_the_name_not_the_value() {
        // `?prefix=policy` must not be read as the `?policy` sub-resource.
        assert_eq!(
            check_of(Method::GET, "/b", "prefix=policy").0,
            "s3:ListBucket"
        );
        assert!(has("a=1&uploads&b=2", "uploads"));
        assert!(!has("uploadsX=1", "uploads"));
    }

    #[test]
    fn scope_bucket_extracts_the_bucket_or_nothing() {
        assert_eq!(scope_bucket("s3://reports/2026/"), "reports");
        assert_eq!(scope_bucket("s3://reports"), "reports");
        // Malformed scopes match no bucket rather than every bucket.
        assert_eq!(scope_bucket("reports/2026"), "");
        assert_eq!(scope_bucket(""), "");
    }

    #[test]
    fn prefix_is_the_scope_key_for_bucket_listings() {
        assert_eq!(
            extract_query_param("list-type=2&prefix=logs%2F2026%2F", "prefix").as_deref(),
            Some("logs/2026/")
        );
        assert_eq!(extract_query_param("list-type=2", "prefix"), None);
        // Name match, not substring: `?myprefix=` is not `?prefix=`.
        assert_eq!(extract_query_param("myprefix=x", "prefix"), None);
    }

    /// The classifier feeds scope enforcement, so the key it reports for an
    /// object request is exactly what the scope is tested against.
    #[test]
    fn object_key_is_the_scope_key() {
        let (_, bucket, key) = check_of(Method::PUT, "/reports/2026/q1.csv", "");
        assert_eq!(bucket, "reports");
        let scope = objectio_auth::CredentialScope {
            scope: "s3://reports/2026/".to_string(),
            operation: objectio_auth::Operation::ReadWrite,
        };
        assert!(scope.allows(&bucket, key.as_deref().unwrap(), "PUT"));

        let (_, other_bucket, other_key) = check_of(Method::PUT, "/payroll/2026/q1.csv", "");
        assert!(!scope.allows(&other_bucket, other_key.as_deref().unwrap(), "PUT"));
    }

    /// A multipart write is classified as PUT/POST, so a read-only key is
    /// refused on it the same way it is on a simple PUT.
    #[test]
    fn read_only_scope_blocks_the_multipart_verbs() {
        let ro = objectio_auth::CredentialScope {
            scope: "s3://data/".to_string(),
            operation: objectio_auth::Operation::Read,
        };
        for (method, query) in [
            (Method::POST, "uploads"),
            (Method::PUT, "partNumber=1&uploadId=x"),
            (Method::POST, "uploadId=x"),
        ] {
            let (_, bucket, key) = check_of(method.clone(), "/data/big.bin", query);
            assert!(
                !ro.allows(&bucket, key.as_deref().unwrap(), method.as_str()),
                "read-only key must not {method} ?{query}"
            );
        }
        let (_, bucket, key) = check_of(Method::GET, "/data/big.bin", "");
        assert!(ro.allows(&bucket, key.as_deref().unwrap(), "GET"));
    }

    fn empty_entry() -> BucketEntry {
        BucketEntry {
            policy: None,
            owner: "u1".to_string(),
            cached_at: Instant::now(),
        }
    }

    #[test]
    fn bucket_cache_returns_within_ttl_and_expires_after() {
        let cache = AuthzCache::new(60);
        assert!(cache.bucket("b").is_none());
        cache.put_bucket("b", empty_entry());
        assert_eq!(cache.bucket("b").unwrap().owner, "u1");
        cache.invalidate("b");
        assert!(cache.bucket("b").is_none());

        let expired = AuthzCache::new(0);
        expired.put_bucket("b", empty_entry());
        assert!(expired.bucket("b").is_none());
    }

    #[test]
    fn identity_cache_is_invalidated_independently_of_buckets() {
        let cache = AuthzCache::new(60);
        cache.put_bucket("b", empty_entry());
        cache.put_identity("u1", Arc::new(Vec::new()));
        assert!(cache.identity("u1").is_some());

        // Invalidating a bucket must not drop attached-policy entries.
        cache.invalidate("b");
        assert!(cache.identity("u1").is_some());

        cache.invalidate_identity("u1");
        assert!(cache.identity("u1").is_none());
    }

    #[test]
    fn unowned_buckets_are_recognised_as_legacy() {
        assert!(is_legacy_unowned(""));
        // The literal placeholder create_bucket used before ownership existed.
        assert!(is_legacy_unowned(LEGACY_BUCKET_OWNER));
        assert!(!is_legacy_unowned("a86f2e87-0c38-47b4-9c04-9048720683e5"));
    }
}
