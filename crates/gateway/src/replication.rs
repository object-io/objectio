//! Bucket replication: every new version written to a bucket, copied to a
//! bucket on another ObjectIO cluster (architecture/design/
//! s3/bucket-replication.md).
//!
//! - **Targets** (`/_admin/replication/targets`): the remote cluster's
//!   endpoint and bucket, and credentials holding `s3:ReplicateObject` there.
//!   Kept in meta's replicated config, per tenant: a bucket's rules name
//!   only its tenant's targets, which that tenant's admin manages.
//! - **Rules** (`?replication`, AWS's `ReplicationConfiguration`): which
//!   objects go to which target. A bucket setting; the bucket must be
//!   versioned.
//! - **Marking:** a version a rule covers is committed with the target
//!   marked `PENDING` in its `ObjectMeta` — in the same write, so no version
//!   is ever committed and forgotten.
//! - **Sending:** at once, by the gateway that took the write (the fast
//!   path, an in-memory queue); and by the scanner, which one gateway at a
//!   time runs (a meta lease) and which finds every version still `PENDING`
//!   or `FAILED`, whatever happened to the fast path.
//! - **Replicas:** the target stores a version sent to it under the
//!   source's version id and ETag, marked a replica, and never replicates
//!   it again. Sending a version the target holds already does nothing, so a
//!   send repeated after a crash can't duplicate it.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use objectio_auth::AuthResult;
use objectio_proto::metadata::{
    AcquireLeaseRequest, GetBucketSettingRequest, GetConfigRequest, ListBucketsRequest,
    ListConfigRequest, ObjectMeta, PutBucketSettingRequest, SetConfigRequest,
};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::s3::{AppState, S3Error};

pub const PENDING: &str = "PENDING";
pub const COMPLETED: &str = "COMPLETED";
pub const FAILED: &str = "FAILED";

/// On a replica PUT, DELETE or CreateMultipartUpload: the version id the
/// source gave it, which the replica keeps.
pub const REPLICA_VERSION: &str = "x-objectio-replica-version-id";
/// The source's ETag, which the replica keeps (a multipart replica's parts
/// need not be the source's, so it can't be recomputed).
pub const REPLICA_ETAG: &str = "x-objectio-replica-etag";
/// The source cluster, recorded on the replica.
pub const REPLICA_OF: &str = "x-objectio-replica-of";

/// Upload metadata keys a replica multipart upload carries until
/// CompleteMultipartUpload (as tags are carried).
pub const UPLOAD_REPLICA_VERSION: &str = "objectio replica-version";
pub const UPLOAD_REPLICA_ETAG: &str = "objectio replica-etag";
pub const UPLOAD_REPLICA_OF: &str = "objectio replica-of";

/// Objects above this are sent as a multipart upload, a part at a time.
const SINGLE_PUT_MAX: u64 = 64 << 20;
const PART_SIZE: u64 = 16 << 20;

const SETTING: &str = "replication";
const TARGET_PREFIX: &str = "replication/target/";
const LEASE: &str = "replication";
const PAGE: u32 = 1000;

// ── Targets ─────────────────────────────────────────────────────────────
//
// A target belongs to a tenant (empty: the system's), and a bucket's rules
// can name only its own tenant's targets: a target holds credentials to a
// remote bucket, and one tenant must not be able to write into another's.
// A tenant's admin manages its targets, the system admin any tenant's. A
// target a tenant's admin sets must be an https endpoint on a host the
// operator allows tenants (`/_admin/replication/settings`), as for audit
// webhooks: otherwise a tenant could make the gateway send requests to
// addresses inside the cluster.

/// A remote cluster and bucket to replicate to.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    /// `http(s)://host:port` of the target's S3 endpoint.
    pub endpoint: String,
    pub bucket: String,
    #[serde(default = "default_region")]
    pub region: String,
    pub access_key: String,
    /// Kept in meta, as users' secret keys are.
    pub secret_key: String,
    /// The tenant it belongs to (empty: the system's). Set by the gateway.
    #[serde(default)]
    pub tenant: String,
    /// Set by the system admin: exempt from the tenant host allowlist.
    #[serde(default)]
    pub operator: bool,
}

fn default_region() -> String {
    "us-east-1".to_string()
}

impl Target {
    /// As listed: the secret never leaves the cluster.
    fn redacted(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "tenant": self.tenant,
            "endpoint": self.endpoint,
            "bucket": self.bucket,
            "region": self.region,
            "access_key": self.access_key,
        })
    }
}

/// The operator's replication settings.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Settings {
    /// Hosts a tenant's targets may be on (`host`, `host:port`, or
    /// `*.domain`). Empty: tenants' admins can't set targets.
    #[serde(default)]
    pub allowed_tenant_hosts: Vec<String>,
}

const SETTINGS_KEY: &str = "replication/settings";
const TENANT_TARGET_PREFIX: &str = "replication/tenant/";

/// What a target is called in a refusal.
const WHAT: &str = "replication target";

/// Where a tenant's targets are kept: the system's under
/// `replication/target/`, a tenant's under `replication/tenant/<t>/target/`.
fn targets_prefix(tenant: &str) -> String {
    if tenant.is_empty() {
        TARGET_PREFIX.to_string()
    } else {
        format!("{TENANT_TARGET_PREFIX}{tenant}/target/")
    }
}

fn target_key(tenant: &str, name: &str) -> String {
    format!("{}{name}", targets_prefix(tenant))
}

/// The target cache's key.
fn cache_key(tenant: &str, name: &str) -> String {
    format!("{tenant}/{name}")
}

#[allow(clippy::result_large_err)]
fn admin_only(auth: &Option<Extension<AuthResult>>, headers: &HeaderMap) -> Result<(), Response> {
    let caller = crate::admin::extract_caller(auth, headers);
    if crate::admin::is_system_admin(&caller) {
        Ok(())
    } else {
        Err((StatusCode::FORBIDDEN, "system admin only").into_response())
    }
}

fn admin_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

/// `POST /_admin/replication/targets[?tenant=]` — create or replace a
/// target: the system admin's in any tenant, a tenant admin's in its own.
pub async fn admin_put_target(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    Json(mut target): Json<Target>,
) -> Response {
    let requested = params
        .get("tenant")
        .map(String::as_str)
        .or(Some(target.tenant.as_str()));
    let admin = match crate::iam_admin::admin_in(&state, &auth, &headers, requested).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    target.tenant = admin.tenant;
    target.operator = admin.system;
    let name_ok = !target.name.is_empty()
        && target
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !name_ok {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "name: letters, digits, '-' and '_'",
        );
    }
    if !(target.endpoint.starts_with("http://") || target.endpoint.starts_with("https://")) {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "endpoint must be http(s)://host[:port]",
        );
    }
    if target.bucket.is_empty() || target.access_key.is_empty() || target.secret_key.is_empty() {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "bucket, access_key and secret_key are required",
        );
    }
    if !target.operator {
        let allowed = match settings(&state, true).await {
            Ok(s) => s.allowed_tenant_hosts,
            Err(e) => return admin_error(StatusCode::SERVICE_UNAVAILABLE, &e),
        };
        if let Err(e) = crate::audit::tenant_url_allowed(&target.endpoint, &allowed, WHAT) {
            return admin_error(StatusCode::BAD_REQUEST, &e);
        }
    }
    let value = serde_json::to_vec(&target).unwrap_or_default();
    match state
        .meta_client
        .clone()
        .set_config(SetConfigRequest {
            key: target_key(&target.tenant, &target.name),
            value,
            updated_by: crate::admin::extract_caller(&auth, &headers).user_id,
        })
        .await
    {
        Ok(_) => {
            state
                .replication
                .targets
                .write()
                .remove(&cache_key(&target.tenant, &target.name));
            Json(target.redacted()).into_response()
        }
        Err(e) => admin_error(StatusCode::SERVICE_UNAVAILABLE, e.message()),
    }
}

/// `GET /_admin/replication/targets[?tenant=]` — a tenant's targets (the
/// caller's own, for a tenant admin), without secrets.
pub async fn admin_list_targets(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let admin = match crate::iam_admin::admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    match list_targets(&state, &admin.tenant).await {
        Ok(targets) => Json(serde_json::json!({
            "tenant": admin.tenant,
            "targets": targets.iter().map(Target::redacted).collect::<Vec<_>>()
        }))
        .into_response(),
        Err(e) => admin_error(StatusCode::SERVICE_UNAVAILABLE, &e),
    }
}

/// `DELETE /_admin/replication/targets/{name}[?tenant=]`.
pub async fn admin_delete_target(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let admin = match crate::iam_admin::admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    match state
        .meta_client
        .clone()
        .delete_config(objectio_proto::metadata::DeleteConfigRequest {
            key: target_key(&admin.tenant, &name),
        })
        .await
    {
        Ok(_) => {
            state
                .replication
                .targets
                .write()
                .remove(&cache_key(&admin.tenant, &name));
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => admin_error(StatusCode::SERVICE_UNAVAILABLE, e.message()),
    }
}

/// `GET /_admin/replication/settings` (system admin).
pub async fn admin_get_settings(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
) -> Response {
    if let Err(r) = admin_only(&auth, &headers) {
        return r;
    }
    match settings(&state, true).await {
        Ok(s) => Json(s).into_response(),
        Err(e) => admin_error(StatusCode::SERVICE_UNAVAILABLE, &e),
    }
}

/// `PUT /_admin/replication/settings` (system admin).
pub async fn admin_put_settings(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Json(new): Json<Settings>,
) -> Response {
    if let Err(r) = admin_only(&auth, &headers) {
        return r;
    }
    match state
        .meta_client
        .clone()
        .set_config(SetConfigRequest {
            key: SETTINGS_KEY.to_string(),
            value: serde_json::to_vec(&new).unwrap_or_default(),
            updated_by: crate::admin::extract_caller(&auth, &headers).user_id,
        })
        .await
    {
        Ok(_) => {
            *state.replication.settings.write() = Some((new.clone(), Instant::now()));
            Json(new).into_response()
        }
        Err(e) => admin_error(StatusCode::SERVICE_UNAVAILABLE, e.message()),
    }
}

/// The operator's settings, from the cache unless `fresh`.
async fn settings(state: &AppState, fresh: bool) -> Result<Settings, String> {
    if !fresh
        && let Some((s, at)) = state.replication.settings.read().as_ref()
        && at.elapsed() < CACHE_TTL
    {
        return Ok(s.clone());
    }
    let resp = state
        .meta_client
        .clone()
        .get_config(GetConfigRequest {
            key: SETTINGS_KEY.to_string(),
        })
        .await
        .map_err(|e| e.message().to_string())?
        .into_inner();
    let s: Settings = resp
        .entry
        .filter(|_| resp.found)
        .and_then(|e| serde_json::from_slice(&e.value).ok())
        .unwrap_or_default();
    *state.replication.settings.write() = Some((s.clone(), Instant::now()));
    Ok(s)
}

async fn list_targets(state: &AppState, tenant: &str) -> Result<Vec<Target>, String> {
    let entries = state
        .meta_client
        .clone()
        .list_config(ListConfigRequest {
            prefix: targets_prefix(tenant),
        })
        .await
        .map_err(|e| e.message().to_string())?
        .into_inner()
        .entries;
    Ok(entries
        .iter()
        .filter_map(|e| serde_json::from_slice(&e.value).ok())
        .collect())
}

/// A target of `tenant`'s by name, from the cache or meta.
async fn target(state: &AppState, tenant: &str, name: &str) -> Result<Target, String> {
    let key = cache_key(tenant, name);
    if let Some((t, at)) = state.replication.targets.read().get(&key)
        && at.elapsed() < CACHE_TTL
    {
        return Ok(t.clone());
    }
    let resp = state
        .meta_client
        .clone()
        .get_config(GetConfigRequest {
            key: target_key(tenant, name),
        })
        .await
        .map_err(|e| e.message().to_string())?
        .into_inner();
    let mut t: Target = resp
        .entry
        .filter(|_| resp.found)
        .and_then(|e| serde_json::from_slice(&e.value).ok())
        .ok_or_else(|| {
            if tenant.is_empty() {
                format!("no replication target '{name}'")
            } else {
                format!("no replication target '{name}' in tenant '{tenant}'")
            }
        })?;
    // Where it is stored decides whose it is, whatever it says.
    t.tenant = tenant.to_string();
    state
        .replication
        .targets
        .write()
        .insert(key, (t.clone(), Instant::now()));
    Ok(t)
}

/// The tenant a bucket belongs to, from the cache or meta.
async fn bucket_tenant(state: &AppState, bucket: &str) -> Result<String, String> {
    if let Some((t, at)) = state.replication.tenants.read().get(bucket)
        && at.elapsed() < CACHE_TTL
    {
        return Ok(t.clone());
    }
    let tenant = state
        .meta_client
        .clone()
        .get_bucket(objectio_proto::metadata::GetBucketRequest {
            name: bucket.to_string(),
        })
        .await
        .map_err(|e| format!("bucket {bucket}: {}", e.message()))?
        .into_inner()
        .bucket
        .map(|b| b.tenant)
        .unwrap_or_default();
    state
        .replication
        .tenants
        .write()
        .insert(bucket.to_string(), (tenant.clone(), Instant::now()));
    Ok(tenant)
}

/// The target a version of `bucket` goes to: `name` among the bucket's
/// tenant's targets, and, if its tenant's admin set it, still on a host
/// the operator allows (the list may have shrunk since).
async fn bucket_target(state: &AppState, bucket: &str, name: &str) -> Result<Target, String> {
    let tenant = bucket_tenant(state, bucket).await?;
    let t = target(state, &tenant, name).await?;
    if !t.operator {
        let allowed = settings(state, false).await?.allowed_tenant_hosts;
        crate::audit::tenant_url_allowed(&t.endpoint, &allowed, WHAT)?;
    }
    Ok(t)
}

// ── Rules ───────────────────────────────────────────────────────────────

/// One replication rule, as stored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub priority: i64,
    pub enabled: bool,
    pub prefix: String,
    pub tags: Vec<(String, String)>,
    pub delete_markers: bool,
    pub target: String,
}

impl Rule {
    fn covers(&self, object: &ObjectMeta) -> bool {
        self.enabled
            && object.key.starts_with(&self.prefix)
            && if object.is_delete_marker {
                // A marker has no tags: only a rule without tag filters, and
                // one that asks for markers, covers it.
                self.delete_markers && self.tags.is_empty()
            } else {
                self.tags.iter().all(|(k, v)| object.tags.get(k) == Some(v))
            }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename = "ReplicationConfiguration")]
struct ConfigXml {
    #[serde(rename = "Role", default, skip_serializing_if = "String::is_empty")]
    role: String,
    #[serde(rename = "Rule", default)]
    rules: Vec<RuleXml>,
}

#[derive(Deserialize, Serialize)]
struct RuleXml {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(rename = "Priority", default)]
    priority: i64,
    #[serde(rename = "Status")]
    status: String,
    #[serde(rename = "Prefix", default, skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(rename = "Filter", default, skip_serializing_if = "Option::is_none")]
    filter: Option<FilterXml>,
    #[serde(
        rename = "DeleteMarkerReplication",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    delete_markers: Option<StatusXml>,
    #[serde(rename = "Destination")]
    destination: DestinationXml,
}

#[derive(Deserialize, Serialize, Default)]
struct FilterXml {
    #[serde(rename = "Prefix", default, skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(rename = "Tag", default, skip_serializing_if = "Option::is_none")]
    tag: Option<TagXml>,
    #[serde(rename = "And", default, skip_serializing_if = "Option::is_none")]
    and: Option<AndXml>,
}

#[derive(Deserialize, Serialize, Default)]
struct AndXml {
    #[serde(rename = "Prefix", default, skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(rename = "Tag", default)]
    tags: Vec<TagXml>,
}

#[derive(Deserialize, Serialize, Clone)]
struct TagXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Value", default)]
    value: String,
}

#[derive(Deserialize, Serialize)]
struct StatusXml {
    #[serde(rename = "Status")]
    status: String,
}

#[derive(Deserialize, Serialize)]
struct DestinationXml {
    /// `arn:obio:replication:::<target>` (or `arn:aws:s3:::<target>`, as
    /// SDKs write a bucket): the target by name.
    #[serde(rename = "Bucket")]
    bucket: String,
}

const TARGET_ARN: &str = "arn:obio:replication:::";

fn malformed(message: &str) -> Response {
    S3Error::xml_response("MalformedXML", message, StatusCode::BAD_REQUEST)
}

#[allow(clippy::result_large_err)]
fn enabled(status: &str) -> Result<bool, Response> {
    match status {
        "Enabled" => Ok(true),
        "Disabled" => Ok(false),
        other => Err(malformed(&format!(
            "Status must be Enabled or Disabled, not {other:?}"
        ))),
    }
}

/// Parse a `ReplicationConfiguration`.
#[allow(clippy::result_large_err)]
fn parse(body: &[u8]) -> Result<Vec<Rule>, Response> {
    let doc: ConfigXml = quick_xml::de::from_reader(body)
        .map_err(|e| malformed(&format!("The XML you provided was not well-formed: {e}")))?;
    if doc.rules.is_empty() {
        return Err(malformed(
            "A replication configuration needs at least one Rule",
        ));
    }
    let mut ids = BTreeSet::new();
    let mut rules = Vec::new();
    for (i, r) in doc.rules.into_iter().enumerate() {
        let id = if r.id.is_empty() {
            format!("rule-{}", i + 1)
        } else {
            r.id
        };
        if !ids.insert(id.clone()) {
            return Err(S3Error::xml_response(
                "InvalidArgument",
                &format!("Rule ID {id:?} is used twice"),
                StatusCode::BAD_REQUEST,
            ));
        }
        let filter = r.filter.unwrap_or_default();
        let (prefix, tags) = match (filter.and, filter.tag) {
            (Some(and), _) => (and.prefix.unwrap_or_default(), and.tags),
            (None, Some(tag)) => (filter.prefix.unwrap_or_default(), vec![tag]),
            (None, None) => (filter.prefix.or(r.prefix).unwrap_or_default(), Vec::new()),
        };
        let target = r
            .destination
            .bucket
            .strip_prefix(TARGET_ARN)
            .or_else(|| r.destination.bucket.strip_prefix("arn:aws:s3:::"))
            .unwrap_or(&r.destination.bucket)
            .to_string();
        if target.is_empty() {
            return Err(malformed("Destination Bucket names no target"));
        }
        rules.push(Rule {
            id,
            priority: r.priority,
            enabled: enabled(&r.status)?,
            prefix,
            tags: tags.into_iter().map(|t| (t.key, t.value)).collect(),
            delete_markers: match r.delete_markers {
                Some(s) => enabled(&s.status)?,
                None => false,
            },
            target,
        });
    }
    Ok(rules)
}

fn render(rules: &[Rule]) -> String {
    let doc = ConfigXml {
        role: String::new(),
        rules: rules
            .iter()
            .map(|r| RuleXml {
                id: r.id.clone(),
                priority: r.priority,
                status: if r.enabled { "Enabled" } else { "Disabled" }.to_string(),
                prefix: None,
                filter: Some(FilterXml {
                    prefix: None,
                    tag: None,
                    and: Some(AndXml {
                        prefix: Some(r.prefix.clone()),
                        tags: r
                            .tags
                            .iter()
                            .map(|(k, v)| TagXml {
                                key: k.clone(),
                                value: v.clone(),
                            })
                            .collect(),
                    }),
                }),
                delete_markers: Some(StatusXml {
                    status: if r.delete_markers {
                        "Enabled"
                    } else {
                        "Disabled"
                    }
                    .to_string(),
                }),
                destination: DestinationXml {
                    bucket: format!("{TARGET_ARN}{}", r.target),
                },
            })
            .collect(),
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        quick_xml::se::to_string(&doc).unwrap_or_default()
    )
}

/// `PUT /{bucket}?replication`
pub async fn put_config(state: &AppState, bucket: &str, body: &[u8]) -> Response {
    if let Err(r) = crate::s3::bucket_owner(state, bucket).await {
        return r;
    }
    let rules = match parse(body) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    // A replica keeps its source's version id: both buckets versioned.
    let versioned = state
        .meta_client
        .clone()
        .get_bucket_versioning(objectio_proto::metadata::GetBucketVersioningRequest {
            bucket: bucket.to_string(),
        })
        .await
        .is_ok_and(|r| {
            r.into_inner().state() == objectio_proto::metadata::VersioningState::VersioningEnabled
        });
    if !versioned {
        return S3Error::xml_response(
            "InvalidRequest",
            "Versioning must be 'Enabled' on the bucket to apply a replication configuration",
            StatusCode::BAD_REQUEST,
        );
    }
    for r in &rules {
        if let Err(e) = bucket_target(state, bucket, &r.target).await {
            return S3Error::xml_response("InvalidArgument", &e, StatusCode::BAD_REQUEST);
        }
    }
    write_config(state, bucket, Some(&rules)).await
}

/// `GET /{bucket}?replication`
pub async fn get_config(state: &AppState, bucket: &str) -> Response {
    if let Err(r) = crate::s3::bucket_owner(state, bucket).await {
        return r;
    }
    match bucket_rules(state, bucket).await {
        Some(rules) => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/xml")
            .body(Body::from(render(&rules)))
            .unwrap_or_default(),
        None => S3Error::xml_response(
            "ReplicationConfigurationNotFoundError",
            "The replication configuration was not found",
            StatusCode::NOT_FOUND,
        ),
    }
}

/// `DELETE /{bucket}?replication`
pub async fn delete_config(state: &AppState, bucket: &str) -> Response {
    if let Err(r) = crate::s3::bucket_owner(state, bucket).await {
        return r;
    }
    write_config(state, bucket, None).await
}

async fn write_config(state: &AppState, bucket: &str, rules: Option<&Vec<Rule>>) -> Response {
    let result = state
        .meta_client
        .clone()
        .put_bucket_setting(PutBucketSettingRequest {
            bucket: bucket.to_string(),
            name: SETTING.to_string(),
            value: rules
                .map(|r| serde_json::to_vec(r).unwrap_or_default())
                .unwrap_or_default(),
            delete: rules.is_none(),
        })
        .await;
    state.replication.rules.write().remove(bucket);
    match result {
        Ok(_) if rules.is_some() => StatusCode::OK.into_response(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => crate::s3::meta_failure(&e, "replication configuration"),
    }
}

/// How long cached rules and targets are trusted: another gateway's change
/// shows within it.
const CACHE_TTL: Duration = Duration::from_secs(10);

/// A bucket's rules, from the cache or meta; `None` when it has none.
async fn bucket_rules(state: &AppState, bucket: &str) -> Option<Arc<Vec<Rule>>> {
    if let Some((rules, at)) = state.replication.rules.read().get(bucket)
        && at.elapsed() < CACHE_TTL
    {
        return rules.clone();
    }
    let resp = state
        .meta_client
        .clone()
        .get_bucket_setting(GetBucketSettingRequest {
            bucket: bucket.to_string(),
            name: SETTING.to_string(),
        })
        .await
        .ok()?
        .into_inner();
    let rules: Option<Arc<Vec<Rule>>> = resp
        .found
        .then(|| serde_json::from_slice::<Vec<Rule>>(&resp.value).ok())
        .flatten()
        .filter(|r| !r.is_empty())
        .map(Arc::new);
    state
        .replication
        .rules
        .write()
        .insert(bucket.to_string(), (rules.clone(), Instant::now()));
    rules
}

// ── Marking ─────────────────────────────────────────────────────────────

/// Mark `object` (a new version, about to be committed) `PENDING` for every
/// target a rule of its bucket sends it to. A replica is never marked (it
/// came from elsewhere), nor an SSE-C object (its key isn't ours to send,
/// as in S3), nor an unversioned one.
///
/// If the rules can't be read, the version is committed unmarked: the
/// write isn't refused for want of replication, and the gap shows in the
/// scanner's log. (A resync marks it later.)
pub async fn mark(state: &AppState, object: &mut ObjectMeta) {
    let sse_c = object.encryption_algorithm == objectio_proto::metadata::SseAlgorithm::SseC as i32;
    if !object.replica_of.is_empty() || sse_c || object.version_id.is_empty() {
        return;
    }
    let Some(rules) = bucket_rules(state, &object.bucket).await else {
        return;
    };
    let mut targets: Vec<&Rule> = rules.iter().filter(|r| r.covers(object)).collect();
    targets.sort_by_key(|r| std::cmp::Reverse(r.priority));
    for r in targets {
        object
            .replication
            .entry(r.target.clone())
            .or_insert_with(|| PENDING.to_string());
    }
}

/// `x-amz-replication-status` for `object`: `REPLICA`, or the least
/// advanced of its targets' (any `FAILED`, then any `PENDING`, else
/// `COMPLETED`); none when it isn't replicated.
#[must_use]
pub fn status_header(object: &ObjectMeta) -> Option<&'static str> {
    if !object.replica_of.is_empty() {
        return Some("REPLICA");
    }
    let states: Vec<&str> = object.replication.values().map(String::as_str).collect();
    if states.is_empty() {
        None
    } else if states.contains(&FAILED) {
        Some(FAILED)
    } else if states.contains(&PENDING) {
        Some(PENDING)
    } else {
        Some(COMPLETED)
    }
}

// ── State ───────────────────────────────────────────────────────────────

/// A version to send to one target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Job {
    bucket: String,
    key: String,
    version_id: String,
    target: String,
}

type CachedRules = (Option<Arc<Vec<Rule>>>, Instant);

/// Replication's per-gateway state: caches, the fast-path queue, retry
/// backoff, and what the last scan found.
pub struct Replication {
    rules: RwLock<HashMap<String, CachedRules>>,
    /// By `tenant/name`.
    targets: RwLock<HashMap<String, (Target, Instant)>>,
    /// Buckets' tenants.
    tenants: RwLock<HashMap<String, (String, Instant)>>,
    settings: RwLock<Option<(Settings, Instant)>>,
    queue: tokio::sync::mpsc::Sender<Job>,
    queue_rx: Mutex<Option<tokio::sync::mpsc::Receiver<Job>>>,
    /// Failed sends: attempts so far, and when the next may be made.
    backoff: Mutex<HashMap<Job, (u32, Instant)>>,
    /// Sends the fast path may have in flight.
    in_flight: Arc<tokio::sync::Semaphore>,
}

/// The fast path's queue. Past it, versions wait for the scanner.
const QUEUE: usize = 10_000;

impl Default for Replication {
    fn default() -> Self {
        let (queue, rx) = tokio::sync::mpsc::channel(QUEUE);
        Self {
            rules: RwLock::default(),
            targets: RwLock::default(),
            tenants: RwLock::default(),
            settings: RwLock::default(),
            queue,
            queue_rx: Mutex::new(Some(rx)),
            backoff: Mutex::default(),
            in_flight: Arc::new(tokio::sync::Semaphore::new(8)),
        }
    }
}

impl Replication {
    /// Drop a bucket's cached rules: this gateway changed them.
    pub fn forget_bucket(&self, bucket: &str) {
        self.rules.write().remove(bucket);
    }
}

static SENT: std::sync::LazyLock<objectio_common::histogram::CounterVec> =
    std::sync::LazyLock::new(objectio_common::histogram::CounterVec::new);
static BYTES: std::sync::LazyLock<objectio_common::histogram::CounterVec> =
    std::sync::LazyLock::new(objectio_common::histogram::CounterVec::new);
/// Per target, from the last scan: versions not yet sent, and the oldest
/// one's age.
static BACKLOG: std::sync::LazyLock<Mutex<HashMap<String, (u64, Duration)>>> =
    std::sync::LazyLock::new(Mutex::default);

/// Prometheus lines for `/metrics`.
pub fn render_metrics(out: &mut String) {
    use std::fmt::Write as _;
    SENT.render(
        out,
        "objectio_replication_sent_total",
        "Versions sent to replication targets, by target and result",
    );
    BYTES.render(
        out,
        "objectio_replication_bytes_total",
        "Bytes sent to replication targets",
    );
    let backlog = BACKLOG.lock();
    let _ = writeln!(
        out,
        "# HELP objectio_replication_backlog Versions not yet replicated to a target, at the last scan\n\
         # TYPE objectio_replication_backlog gauge"
    );
    for (target, (n, _)) in backlog.iter() {
        let _ = writeln!(
            out,
            "objectio_replication_backlog{{target=\"{target}\"}} {n}"
        );
    }
    let _ = writeln!(
        out,
        "# HELP objectio_replication_lag_seconds Age of the oldest version not yet replicated to a target, at the last scan\n\
         # TYPE objectio_replication_lag_seconds gauge"
    );
    for (target, (_, lag)) in backlog.iter() {
        let _ = writeln!(
            out,
            "objectio_replication_lag_seconds{{target=\"{target}\"}} {}",
            lag.as_secs()
        );
    }
}

/// Queue `object`'s marked targets for sending now. Dropped if the queue is
/// full: the scanner sends them.
pub fn enqueue(state: &AppState, object: &ObjectMeta) {
    for (target, status) in &object.replication {
        if status != COMPLETED {
            let _ = state.replication.queue.try_send(Job {
                bucket: object.bucket.clone(),
                key: object.key.clone(),
                version_id: object.version_id.clone(),
                target: target.clone(),
            });
        }
    }
}

// ── Workers ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// How often the scanner looks for versions not yet sent.
    pub scan_every: Duration,
    /// Send queued versions at once (off only in tests, standing for a
    /// gateway that died before it could).
    pub fast_path: bool,
}

/// Start the fast path and the scanner. Every gateway runs both; a lease
/// in meta lets one scan at a time.
pub fn spawn(state: Arc<AppState>, timing: Timing) {
    let Some(mut rx) = state.replication.queue_rx.lock().take() else {
        return;
    };
    let fast = Arc::clone(&state);
    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            if !timing.fast_path {
                continue;
            }
            let Ok(permit) = Arc::clone(&fast.replication.in_flight)
                .acquire_owned()
                .await
            else {
                return;
            };
            let state = Arc::clone(&fast);
            tokio::spawn(async move {
                let _permit = permit;
                send_and_record(&state, &job).await;
            });
        }
    });
    tokio::spawn(async move {
        let holder = uuid::Uuid::new_v4().to_string();
        info!(
            "Replication scanner started (every {}s)",
            timing.scan_every.as_secs()
        );
        let mut ticker = tokio::time::interval(timing.scan_every);
        loop {
            ticker.tick().await;
            if !lease(&state, &holder, timing).await {
                continue;
            }
            scan(&state, &holder, timing).await;
        }
    });
}

async fn lease(state: &AppState, holder: &str, timing: Timing) -> bool {
    let ttl = (timing.scan_every.as_secs() * 3).max(60);
    state
        .meta_client
        .clone()
        .acquire_lease(AcquireLeaseRequest {
            name: LEASE.to_string(),
            holder: holder.to_string(),
            ttl_secs: ttl,
            release: false,
        })
        .await
        .is_ok_and(|r| r.into_inner().acquired)
}

/// One pass over every bucket with rules: send each version a target
/// hasn't got yet, oldest first, and record the backlog.
async fn scan(state: &Arc<AppState>, holder: &str, timing: Timing) {
    let buckets = match state
        .meta_client
        .clone()
        .list_buckets(ListBucketsRequest::default())
        .await
    {
        Ok(r) => r.into_inner().buckets,
        Err(e) => {
            warn!("replication: cannot list buckets: {e}");
            return;
        }
    };
    let mut backlog: HashMap<String, (u64, Duration)> = HashMap::new();
    for b in buckets {
        if bucket_rules(state, &b.name).await.is_none() {
            continue;
        }
        if !lease(state, holder, timing).await {
            return;
        }
        if let Err(e) = scan_bucket(state, &b.name, &mut backlog).await {
            warn!("replication: bucket {}: {e}", b.name);
        }
    }
    *BACKLOG.lock() = backlog;
}

async fn scan_bucket(
    state: &Arc<AppState>,
    bucket: &str,
    backlog: &mut HashMap<String, (u64, Duration)>,
) -> Result<(), String> {
    let now = crate::lifecycle::now_ms();
    let mut marker = String::new();
    loop {
        let (found, more) = crate::s3::gather_versions(state, bucket, "", &marker, "", PAGE)
            .await
            .map_err(|r| format!("listing failed ({})", r.status()))?;
        let mut last = None;
        for (key, mut versions) in found {
            if !marker.is_empty() && key <= marker {
                continue;
            }
            last = Some(key.clone());
            crate::s3::sort_versions(&mut versions);
            // Oldest first, so a target receives a key's versions in order.
            for v in versions.iter().rev() {
                for (target, status) in &v.replication {
                    if status == COMPLETED {
                        continue;
                    }
                    let age =
                        Duration::from_millis(now.saturating_sub(crate::s3::version_time_ms(v)));
                    let entry = backlog.entry(target.clone()).or_default();
                    entry.0 += 1;
                    entry.1 = entry.1.max(age);
                    let job = Job {
                        bucket: bucket.to_string(),
                        key: key.clone(),
                        version_id: v.version_id.clone(),
                        target: target.clone(),
                    };
                    let due = state
                        .replication
                        .backoff
                        .lock()
                        .get(&job)
                        .is_none_or(|(_, next)| Instant::now() >= *next);
                    if due && send_and_record(state, &job).await {
                        entry.0 -= 1;
                    }
                }
            }
        }
        match last {
            Some(k) if more => marker = k,
            _ => return Ok(()),
        }
    }
}

/// Send `job` and record the outcome on the version: `COMPLETED`, or
/// `FAILED` with a retry scheduled. Whether it was sent.
async fn send_and_record(state: &Arc<AppState>, job: &Job) -> bool {
    let started = Instant::now();
    match send(state, job).await {
        Ok(Sent::Done(bytes)) => {
            SENT.inc(&format!("target=\"{}\",result=\"ok\"", job.target));
            BYTES.add(&format!("target=\"{}\"", job.target), bytes);
            state.replication.backoff.lock().remove(job);
            record(state, job, COMPLETED).await;
            debug!(
                "replication: {}/{} {} → {} in {:?}",
                job.bucket,
                job.key,
                job.version_id,
                job.target,
                started.elapsed()
            );
            true
        }
        Ok(Sent::Gone) => {
            state.replication.backoff.lock().remove(job);
            true
        }
        Err(e) => {
            SENT.inc(&format!("target=\"{}\",result=\"error\"", job.target));
            warn!(
                "replication: {}/{} {} → {}: {e}",
                job.bucket, job.key, job.version_id, job.target
            );
            {
                let mut backoff = state.replication.backoff.lock();
                let attempts = backoff.get(job).map_or(0, |(a, _)| *a) + 1;
                let wait = Duration::from_secs((1u64 << attempts.min(9)).min(300));
                backoff.insert(job.clone(), (attempts, Instant::now() + wait));
            }
            record(state, job, FAILED).await;
            false
        }
    }
}

/// Record `status` for the job's target on every copy of the version,
/// changing nothing else on it (the OSD merges just the status).
async fn record(state: &AppState, job: &Job, status: &str) {
    let Ok(nodes) = crate::s3::get_placement_nodes_for_object(state, &job.bucket, &job.key).await
    else {
        return;
    };
    let Ok(Some(version)) = crate::osd_pool::get_object_version_meta_from_any(
        &state.osd_pool,
        &nodes,
        &job.bucket,
        &job.key,
        &job.version_id,
    )
    .await
    else {
        return;
    };
    if version.replication.get(&job.target).map(String::as_str) == Some(status) {
        return;
    }
    if let Err(e) = crate::osd_pool::set_replication_status(
        &state.osd_pool,
        &nodes,
        &version,
        &job.target,
        status,
    )
    .await
    {
        // Left as it was: the scanner sends it again, which the target
        // takes as a repeat.
        warn!(
            "replication: recording {status} for {}/{} {}: {e}",
            job.bucket, job.key, job.version_id
        );
    }
}

// ── Sending ─────────────────────────────────────────────────────────────

enum Sent {
    /// The target has it now; this many bytes went.
    Done(u64),
    /// The version is gone (deleted since): nothing to send.
    Gone,
}

fn http() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .build()
            .unwrap_or_default()
    })
}

async fn send(state: &Arc<AppState>, job: &Job) -> Result<Sent, String> {
    let nodes = crate::s3::get_placement_nodes_for_object(state, &job.bucket, &job.key)
        .await
        .map_err(|r| format!("placement ({})", r.status()))?;
    let Some(version) = crate::osd_pool::get_object_version_meta_from_any(
        &state.osd_pool,
        &nodes,
        &job.bucket,
        &job.key,
        &job.version_id,
    )
    .await
    .map_err(|e| format!("reading the version: {e}"))?
    else {
        return Ok(Sent::Gone);
    };
    if version.replication.get(&job.target).map(String::as_str) == Some(COMPLETED) {
        return Ok(Sent::Done(0));
    }
    let target = bucket_target(state, &job.bucket, &job.target).await?;
    let replica = replica_headers(&version);

    if version.is_delete_marker {
        call(&target, "DELETE", &job.key, &[], &replica, &[]).await?;
        return Ok(Sent::Done(0));
    }
    let mut headers = object_headers(&version);
    headers.extend(replica);
    if version.size <= SINGLE_PUT_MAX {
        let body = read(state, job, None).await?;
        if body.len() as u64 != version.size {
            return Err(format!(
                "read {} bytes of a {}-byte version",
                body.len(),
                version.size
            ));
        }
        call(&target, "PUT", &job.key, &[], &headers, &body).await?;
        return Ok(Sent::Done(version.size));
    }
    send_multipart(state, job, &target, &version, &headers).await?;
    Ok(Sent::Done(version.size))
}

/// A replica's identity: the source's version id and ETag, and who sent it.
fn replica_headers(version: &ObjectMeta) -> Vec<(String, String)> {
    vec![
        (REPLICA_VERSION.to_string(), version.version_id.clone()),
        (REPLICA_ETAG.to_string(), version.etag.clone()),
        (REPLICA_OF.to_string(), "source".to_string()),
    ]
}

/// The headers that recreate the version's metadata on the target.
fn object_headers(version: &ObjectMeta) -> Vec<(String, String)> {
    let mut h = Vec::new();
    if !version.content_type.is_empty() {
        h.push(("content-type".to_string(), version.content_type.clone()));
    }
    for (k, v) in &version.user_metadata {
        if let Some(name) = k.strip_prefix(crate::s3::STORED_HEADER_PREFIX) {
            h.push((name.to_string(), v.clone()));
        } else if !k.starts_with("objectio ") {
            h.push((format!("x-amz-meta-{k}"), v.clone()));
        }
    }
    if !version.tags.is_empty() {
        h.push((
            "x-amz-tagging".to_string(),
            crate::s3::encode_tagging(&version.tags),
        ));
    }
    if let Some(r) = &version.retention {
        let mode = match r.mode {
            1 => Some("GOVERNANCE"),
            2 => Some("COMPLIANCE"),
            _ => None,
        };
        if let Some(mode) = mode {
            h.push(("x-amz-object-lock-mode".to_string(), mode.to_string()));
            h.push((
                "x-amz-object-lock-retain-until-date".to_string(),
                chrono::DateTime::<chrono::Utc>::from_timestamp(
                    i64::try_from(r.retain_until_date).unwrap_or(0),
                    0,
                )
                .map(|d| d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
                .unwrap_or_default(),
            ));
        }
    }
    if version.legal_hold.as_ref().is_some_and(|l| l.status) {
        h.push(("x-amz-object-lock-legal-hold".to_string(), "ON".to_string()));
    }
    match objectio_proto::metadata::SseAlgorithm::try_from(version.encryption_algorithm) {
        Ok(objectio_proto::metadata::SseAlgorithm::SseS3) => {
            h.push((
                "x-amz-server-side-encryption".to_string(),
                "AES256".to_string(),
            ));
        }
        Ok(objectio_proto::metadata::SseAlgorithm::SseKms) => {
            h.push((
                "x-amz-server-side-encryption".to_string(),
                "aws:kms".to_string(),
            ));
            h.push((
                "x-amz-server-side-encryption-aws-kms-key-id".to_string(),
                version.kms_key_id.clone(),
            ));
        }
        _ => {}
    }
    h
}

/// The version's bytes, or `range` of them, as a GET by version id reads
/// them (decrypted, checked against their checksums).
async fn read(
    state: &Arc<AppState>,
    job: &Job,
    range: Option<(u64, u64)>,
) -> Result<bytes::Bytes, String> {
    let mut headers = HeaderMap::new();
    if let Some((from, to)) = range {
        headers.insert(
            axum::http::header::RANGE,
            axum::http::HeaderValue::from_str(&format!("bytes={from}-{to}"))
                .map_err(|e| e.to_string())?,
        );
    }
    let resp = crate::s3::get_object_version(
        Arc::clone(state),
        job.bucket.clone(),
        job.key.clone(),
        Some(job.version_id.clone()),
        headers,
    )
    .await;
    if !resp.status().is_success() {
        return Err(format!("reading it: {}", resp.status()));
    }
    axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .map_err(|e| format!("reading it: {e}"))
}

async fn send_multipart(
    state: &Arc<AppState>,
    job: &Job,
    target: &Target,
    version: &ObjectMeta,
    headers: &[(String, String)],
) -> Result<(), String> {
    let created = call(target, "POST", &job.key, &[("uploads", "")], headers, &[]).await?;
    let Some(upload) = created
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .map(str::to_string)
    else {
        // A success with no upload: the target holds this version already.
        return Ok(());
    };
    let result = async {
        let mut parts = String::new();
        let mut offset = 0u64;
        let mut n = 1u32;
        while offset < version.size {
            let end = (offset + PART_SIZE).min(version.size) - 1;
            let body = read(state, job, Some((offset, end))).await?;
            if body.len() as u64 != end - offset + 1 {
                return Err(format!("read {} bytes of part {n}", body.len()));
            }
            let number = n.to_string();
            let etag = call_header(
                target,
                "PUT",
                &job.key,
                &[("partNumber", &number), ("uploadId", &upload)],
                &[],
                &body,
                "etag",
            )
            .await?;
            use std::fmt::Write as _;
            let _ = write!(
                parts,
                "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
            );
            offset = end + 1;
            n += 1;
        }
        let complete = format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>");
        call(
            target,
            "POST",
            &job.key,
            &[("uploadId", &upload)],
            &[],
            complete.as_bytes(),
        )
        .await
        .map(drop)
    }
    .await;
    if result.is_err() {
        let _ = call(
            target,
            "DELETE",
            &job.key,
            &[("uploadId", &upload)],
            &[],
            &[],
        )
        .await;
    }
    result
}

/// A signed request to the target bucket; the response body on success.
async fn call(
    target: &Target,
    method: &str,
    key: &str,
    query: &[(&str, &str)],
    headers: &[(String, String)],
    body: &[u8],
) -> Result<String, String> {
    let resp = request(target, method, key, query, headers, body).await?;
    resp.text().await.map_err(|e| e.to_string())
}

/// As [`call`], returning one response header.
async fn call_header(
    target: &Target,
    method: &str,
    key: &str,
    query: &[(&str, &str)],
    headers: &[(String, String)],
    body: &[u8],
    name: &str,
) -> Result<String, String> {
    let resp = request(target, method, key, query, headers, body).await?;
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| format!("the target sent no {name}"))
}

async fn request(
    target: &Target,
    method: &str,
    key: &str,
    query: &[(&str, &str)],
    headers: &[(String, String)],
    body: &[u8],
) -> Result<reqwest::Response, String> {
    use objectio_auth::signer::{Request as SignRequest, Signer, escape_path, escape_segment};
    let base = target.endpoint.trim_end_matches('/');
    let host = base
        .split("://")
        .nth(1)
        .unwrap_or(base)
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string();
    let path = format!("/{}/{}", escape_segment(&target.bucket), escape_path(key));
    let query: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    let content_type = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        .map(|(_, v)| v.as_str());
    let signed = Signer {
        access_key: &target.access_key,
        secret_key: &target.secret_key,
        region: &target.region,
    }
    .sign(
        &SignRequest {
            method,
            host: &host,
            path: &path,
            query: &query,
            content_type,
            body,
        },
        chrono::Utc::now(),
    );
    let qs = objectio_auth::signer::canonical_query(&query);
    let url = if qs.is_empty() {
        format!("{base}{path}")
    } else {
        format!("{base}{path}?{qs}")
    };
    let mut req = http().request(method.parse().map_err(|e| format!("{e}"))?, url);
    for (k, v) in signed {
        req = req.header(k, v);
    }
    for (k, v) in headers {
        let Ok(value) = reqwest::header::HeaderValue::from_bytes(v.as_bytes()) else {
            continue;
        };
        req = req.header(k.as_str(), value);
    }
    if !body.is_empty() {
        req = req.body(body.to_vec());
    }
    let resp = req.send().await.map_err(|e| format!("the target: {e}"))?;
    if resp.status().is_success() {
        Ok(resp)
    } else {
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        let code = text
            .split("<Code>")
            .nth(1)
            .and_then(|s| s.split("</Code>").next())
            .unwrap_or("");
        Err(format!("the target answered {status} {code}"))
    }
}

// ── The target's side: storing replicas ────────────────────────────────

/// What a replica write carries.
#[derive(Debug, Clone)]
pub struct Replica {
    pub version_id: String,
    pub etag: String,
    pub of: String,
}

/// May the caller write replicas here? `s3:ReplicateObject` (or
/// `s3:ReplicateDelete`), on top of the ordinary write it is.
async fn authorize_replica(
    state: &AppState,
    auth: &Option<Extension<AuthResult>>,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    action: &'static str,
) -> Result<(), Response> {
    let Some(Extension(auth)) = auth else {
        return Ok(()); // --no-auth
    };
    match crate::authz::authorize(
        state,
        auth,
        &crate::authz::AuthzRequest {
            method: &axum::http::Method::PUT,
            action,
            bucket,
            key: Some(key),
            scope_key: key,
            headers: Some(headers),
        },
    )
    .await
    {
        Some(denied) => Err(denied),
        None => Ok(()),
    }
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Checks common to a replica PUT and DELETE: the version id is one, and
/// the bucket keeps versions.
#[allow(clippy::result_large_err)]
fn replica_basics(version_id: &str, versioning_enabled: bool) -> Result<(), Response> {
    if uuid::Uuid::parse_str(version_id).is_err() {
        return Err(S3Error::xml_response(
            "InvalidArgument",
            "the replica's version id is not one",
            StatusCode::BAD_REQUEST,
        ));
    }
    if !versioning_enabled {
        return Err(S3Error::xml_response(
            "InvalidRequest",
            "replicas are written only to a bucket with versioning enabled",
            StatusCode::BAD_REQUEST,
        ));
    }
    Ok(())
}

/// The version `bucket/key` holds under `version_id` already, if any.
async fn held(state: &AppState, bucket: &str, key: &str, version_id: &str) -> Option<ObjectMeta> {
    let nodes = crate::s3::get_placement_nodes_for_object(state, bucket, key)
        .await
        .ok()?;
    crate::osd_pool::get_object_version_meta_from_any(
        &state.osd_pool,
        &nodes,
        bucket,
        key,
        version_id,
    )
    .await
    .ok()
    .flatten()
}

/// A PUT (or CreateMultipartUpload) carrying a replica's version id: who
/// may send it, and whether this bucket holds it already. `Ok(None)`: not a
/// replica. `Err`: the answer to give instead — a 200 for a repeat of a
/// version held already, byte for byte (same ETag), so a send repeated
/// after a crash stores nothing twice.
pub async fn replica_request(
    state: &AppState,
    auth: &Option<Extension<AuthResult>>,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    versioning_enabled: bool,
) -> Result<Option<Replica>, Response> {
    let Some(version_id) = header(headers, REPLICA_VERSION) else {
        return Ok(None);
    };
    authorize_replica(state, auth, bucket, key, headers, "s3:ReplicateObject").await?;
    replica_basics(&version_id, versioning_enabled)?;
    let etag = header(headers, REPLICA_ETAG).unwrap_or_default();
    if let Some(v) = held(state, bucket, key, &version_id).await {
        if v.etag == etag && !v.is_delete_marker {
            return Err(Response::builder()
                .status(StatusCode::OK)
                .header("ETag", &v.etag)
                .header("x-amz-version-id", &version_id)
                .body(Body::empty())
                .unwrap_or_default());
        }
        return Err(S3Error::xml_response(
            "OperationAborted",
            "this bucket holds a different version under the replica's version id",
            StatusCode::CONFLICT,
        ));
    }
    Ok(Some(Replica {
        version_id,
        etag,
        of: header(headers, REPLICA_OF).unwrap_or_else(|| "replica".to_string()),
    }))
}

/// A DELETE carrying a replica's version id: store the source's delete
/// marker under its version id. `None`: not a replica delete.
pub async fn replica_delete(
    state: &Arc<AppState>,
    auth: &Option<Extension<AuthResult>>,
    bucket: &str,
    key: &str,
    headers: &HeaderMap,
    versioning_enabled: bool,
) -> Option<Response> {
    let version_id = header(headers, REPLICA_VERSION)?;
    let answer = |version_id: &str| {
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header("x-amz-version-id", version_id)
            .header("x-amz-delete-marker", "true")
            .body(Body::empty())
            .unwrap_or_default()
    };
    if let Err(r) = authorize_replica(state, auth, bucket, key, headers, "s3:ReplicateDelete").await
    {
        return Some(r);
    }
    if let Err(r) = replica_basics(&version_id, versioning_enabled) {
        return Some(r);
    }
    if let Some(v) = held(state, bucket, key, &version_id).await {
        return Some(if v.is_delete_marker {
            answer(&version_id)
        } else {
            S3Error::xml_response(
                "OperationAborted",
                "this bucket holds a different version under the replica's version id",
                StatusCode::CONFLICT,
            )
        });
    }
    let nodes = match crate::s3::get_placement_nodes_for_object(state, bucket, key).await {
        Ok(n) => n,
        Err(r) => return Some(r),
    };
    let now = crate::lifecycle::now_ms() / 1000;
    let marker = ObjectMeta {
        bucket: bucket.to_string(),
        key: key.to_string(),
        object_id: uuid::Uuid::now_v7().as_bytes().to_vec(),
        version_id: version_id.clone(),
        is_delete_marker: true,
        created_at: now,
        modified_at: now,
        replica_of: header(headers, REPLICA_OF).unwrap_or_else(|| "replica".to_string()),
        ..Default::default()
    };
    if let Err(e) = crate::osd_pool::put_object_meta_with(
        &state.osd_pool,
        &nodes,
        bucket,
        key,
        marker,
        crate::osd_pool::MetaWrite {
            versioning_enabled: true,
            keep_newer_current: true,
            ..Default::default()
        },
    )
    .await
    {
        return Some(S3Error::xml_response(
            "ServiceUnavailable",
            &format!("storing the replica's delete marker: {}", e.error),
            StatusCode::SERVICE_UNAVAILABLE,
        ));
    }
    crate::s3::sync_listing(state, &nodes, bucket, key).await;
    Some(answer(&version_id))
}
