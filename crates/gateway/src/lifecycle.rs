//! Bucket lifecycle: S3's `?lifecycle` configuration, and the worker that
//! carries it out.
//!
//! ## Rules
//!
//! A rule has a filter — a prefix, tags, object size bounds, or all of them
//! (`<And>`) — and one or more actions:
//!
//! - `Expiration` `Days` / `Date`: the current version expires. In an
//!   unversioned bucket it is deleted; in a versioned (or suspended) one a
//!   delete marker is put on top, exactly as a DELETE without a version id.
//! - `Expiration` `ExpiredObjectDeleteMarker` (also implied by `Days` in a
//!   versioned bucket): a delete marker that is the key's only version left
//!   is removed. One with versions behind it is never removed — that would
//!   bring a deleted object back.
//! - `NoncurrentVersionExpiration` `NoncurrentDays`, `NewerNoncurrentVersions`:
//!   a noncurrent version is deleted once it has been noncurrent that long,
//!   keeping the newest N noncurrent versions whatever their age.
//! - `AbortIncompleteMultipartUpload` `DaysAfterInitiation`.
//!
//! Transitions are refused (`InvalidStorageClass`): there is one storage
//! class.
//!
//! ## The worker
//!
//! Every action goes through the same code as the S3 request it stands for
//! (`s3::delete_object`), so lifecycle can never do what a client couldn't:
//! Object Lock retention and legal holds are honoured (a locked version is
//! left alone and counted), the listing is kept, and space is reclaimed.
//! Every action is an audit event, by principal `lifecycle:<rule id>`.
//!
//! One gateway scans at a time: each takes a lease from meta before a scan
//! and renews it as it goes, so two never act on the same key at once, and
//! another takes over within the lease's time if the scanning one dies.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use objectio_proto::metadata::ObjectMeta;
use objectio_proto::metadata::{
    AcquireLeaseRequest, DeleteBucketLifecycleRequest, GetBucketLifecycleRequest,
    LifecycleConfiguration as ProtoConfig, LifecycleRule as ProtoRule, ListBucketsRequest,
    PutBucketLifecycleRequest,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::s3::{AppState, S3Error};

const MAX_RULES: usize = 1000;
const LEASE: &str = "lifecycle";
const PAGE: u32 = 1000;

/// When the worker runs and how long a lifecycle "day" is (shortened only
/// for testing, as `rgw_lc_debug_interval` is for Ceph).
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub interval: Duration,
    pub day: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(3600),
            day: Duration::from_secs(86_400),
        }
    }
}

// ── The S3 document ─────────────────────────────────────────────────────

#[derive(Deserialize, Serialize, Default)]
#[serde(rename = "LifecycleConfiguration")]
struct ConfigXml {
    #[serde(rename = "Rule", default)]
    rules: Vec<RuleXml>,
}

#[derive(Deserialize, Serialize, Default, Clone)]
struct RuleXml {
    #[serde(rename = "ID", default, skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(rename = "Filter", default, skip_serializing_if = "Option::is_none")]
    filter: Option<FilterXml>,
    /// The legacy top-level prefix (no `<Filter>`).
    #[serde(rename = "Prefix", default, skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(rename = "Status")]
    status: String,
    #[serde(
        rename = "Expiration",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    expiration: Option<ExpirationXml>,
    #[serde(
        rename = "NoncurrentVersionExpiration",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    noncurrent: Option<NoncurrentXml>,
    #[serde(
        rename = "AbortIncompleteMultipartUpload",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    abort: Option<AbortXml>,
    #[serde(rename = "Transition", default, skip_serializing)]
    transition: Option<serde::de::IgnoredAny>,
    #[serde(rename = "NoncurrentVersionTransition", default, skip_serializing)]
    noncurrent_transition: Option<serde::de::IgnoredAny>,
}

#[derive(Deserialize, Serialize, Default, Clone)]
struct FilterXml {
    #[serde(rename = "Prefix", default, skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(rename = "Tag", default, skip_serializing_if = "Option::is_none")]
    tag: Option<TagXml>,
    #[serde(
        rename = "ObjectSizeGreaterThan",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    size_gt: Option<u64>,
    #[serde(
        rename = "ObjectSizeLessThan",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    size_lt: Option<u64>,
    #[serde(rename = "And", default, skip_serializing_if = "Option::is_none")]
    and: Option<AndXml>,
}

#[derive(Deserialize, Serialize, Default, Clone)]
struct AndXml {
    #[serde(rename = "Prefix", default, skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
    #[serde(rename = "Tag", default, skip_serializing_if = "Vec::is_empty")]
    tags: Vec<TagXml>,
    #[serde(
        rename = "ObjectSizeGreaterThan",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    size_gt: Option<u64>,
    #[serde(
        rename = "ObjectSizeLessThan",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    size_lt: Option<u64>,
}

#[derive(Deserialize, Serialize, Clone)]
struct TagXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Value", default)]
    value: String,
}

#[derive(Deserialize, Serialize, Default, Clone)]
struct ExpirationXml {
    #[serde(rename = "Days", default, skip_serializing_if = "Option::is_none")]
    days: Option<i64>,
    #[serde(rename = "Date", default, skip_serializing_if = "Option::is_none")]
    date: Option<String>,
    #[serde(
        rename = "ExpiredObjectDeleteMarker",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    expired_object_delete_marker: Option<bool>,
}

#[derive(Deserialize, Serialize, Default, Clone)]
struct NoncurrentXml {
    #[serde(
        rename = "NoncurrentDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    days: Option<i64>,
    #[serde(
        rename = "NewerNoncurrentVersions",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    newer: Option<i64>,
}

#[derive(Deserialize, Serialize, Default, Clone)]
struct AbortXml {
    #[serde(
        rename = "DaysAfterInitiation",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    days: Option<i64>,
}

/// A refusal of a configuration, as S3 words it.
struct Invalid {
    code: &'static str,
    message: String,
}

fn invalid(code: &'static str, message: impl Into<String>) -> Invalid {
    Invalid {
        code,
        message: message.into(),
    }
}

/// Midnight UTC of `date`, in unix seconds: S3 takes a date or an ISO 8601
/// time, and only midnight.
fn parse_date(date: &str) -> Result<u64, Invalid> {
    let at = chrono::DateTime::parse_from_rfc3339(date.trim())
        .map(|d| d.with_timezone(&chrono::Utc))
        .or_else(|_| {
            chrono::NaiveDate::parse_from_str(date.trim(), "%Y-%m-%d")
                .map(|d| d.and_hms_opt(0, 0, 0).unwrap_or_default().and_utc())
        })
        .map_err(|_| invalid("InvalidArgument", "'Date' must be in ISO 8601 format"))?;
    if at.timestamp() % 86_400 != 0 {
        return Err(invalid("InvalidArgument", "'Date' must be at midnight GMT"));
    }
    u64::try_from(at.timestamp()).map_err(|_| invalid("InvalidArgument", "'Date' is out of range"))
}

fn positive(v: Option<i64>, what: &str) -> Result<u32, Invalid> {
    match v {
        None => Ok(0),
        Some(d) if d > 0 => u32::try_from(d)
            .map_err(|_| invalid("InvalidArgument", format!("'{what}' is too large"))),
        Some(_) => Err(invalid(
            "InvalidArgument",
            format!("'{what}' must be a positive integer"),
        )),
    }
}

/// The rules of a `LifecycleConfiguration` document, checked as S3 checks
/// them.
fn parse(body: &[u8]) -> Result<Vec<ProtoRule>, Invalid> {
    let doc: ConfigXml = quick_xml::de::from_reader(body).map_err(|e| {
        invalid(
            "MalformedXML",
            format!("The XML you provided was not well-formed: {e}"),
        )
    })?;
    if doc.rules.is_empty() || doc.rules.len() > MAX_RULES {
        return Err(invalid(
            "MalformedXML",
            format!("A lifecycle configuration has 1 to {MAX_RULES} rules"),
        ));
    }
    let mut ids = HashSet::new();
    let mut out = Vec::with_capacity(doc.rules.len());
    for (i, r) in doc.rules.into_iter().enumerate() {
        let id =
            r.id.clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("rule-{}", i + 1));
        if id.len() > 255 {
            return Err(invalid(
                "InvalidArgument",
                "ID length should not exceed allowed limit of 255",
            ));
        }
        if !ids.insert(id.clone()) {
            return Err(invalid(
                "InvalidArgument",
                "Rule ID must be unique. Found same ID for more than one rule",
            ));
        }
        let enabled = match r.status.as_str() {
            "Enabled" => true,
            "Disabled" => false,
            _ => {
                return Err(invalid(
                    "MalformedXML",
                    "Status must be Enabled or Disabled",
                ));
            }
        };
        if r.transition.is_some() || r.noncurrent_transition.is_some() {
            return Err(invalid(
                "InvalidStorageClass",
                "The storage class you specified is not valid: this cluster has one storage class",
            ));
        }
        if r.filter.is_some() && r.prefix.is_some() {
            return Err(invalid(
                "MalformedXML",
                "A rule has a Filter or a Prefix, not both",
            ));
        }
        if r.filter.is_none() && r.prefix.is_none() {
            return Err(invalid(
                "MalformedXML",
                "A rule must have a Filter (or a Prefix)",
            ));
        }
        let mut rule = ProtoRule {
            id,
            enabled,
            has_filter: r.filter.is_some(),
            prefix: r.prefix.clone().unwrap_or_default(),
            ..ProtoRule::default()
        };
        if let Some(f) = &r.filter {
            let parts = [
                f.prefix.is_some(),
                f.tag.is_some(),
                f.size_gt.is_some() || f.size_lt.is_some(),
                f.and.is_some(),
            ]
            .iter()
            .filter(|p| **p)
            .count();
            // A single condition, or several inside <And>; "" (empty filter)
            // means every object.
            if parts > 1 && !(f.and.is_none() && f.tag.is_none() && f.prefix.is_none()) {
                return Err(invalid(
                    "MalformedXML",
                    "Several filter conditions go inside <And>",
                ));
            }
            rule.prefix = f.prefix.clone().unwrap_or_default();
            if let Some(t) = &f.tag {
                rule.filter_tags.insert(t.key.clone(), t.value.clone());
            }
            rule.object_size_greater_than = f.size_gt.unwrap_or(0);
            rule.object_size_less_than = f.size_lt.unwrap_or(0);
            if let Some(a) = &f.and {
                rule.prefix = a.prefix.clone().unwrap_or_default();
                for t in &a.tags {
                    if rule
                        .filter_tags
                        .insert(t.key.clone(), t.value.clone())
                        .is_some()
                    {
                        return Err(invalid(
                            "InvalidRequest",
                            "Duplicate Tag Keys are not allowed",
                        ));
                    }
                }
                rule.object_size_greater_than = a.size_gt.unwrap_or(0);
                rule.object_size_less_than = a.size_lt.unwrap_or(0);
            }
            if rule.object_size_less_than > 0
                && rule.object_size_greater_than >= rule.object_size_less_than
            {
                return Err(invalid(
                    "InvalidArgument",
                    "ObjectSizeGreaterThan must be less than ObjectSizeLessThan",
                ));
            }
        }
        if let Some(e) = &r.expiration {
            let set = [
                e.days.is_some(),
                e.date.is_some(),
                e.expired_object_delete_marker.is_some(),
            ]
            .iter()
            .filter(|p| **p)
            .count();
            if set != 1 {
                return Err(invalid(
                    "MalformedXML",
                    "Expiration has exactly one of Days, Date or ExpiredObjectDeleteMarker",
                ));
            }
            rule.expiration_days = positive(e.days, "Days")?;
            if let Some(d) = &e.date {
                rule.expiration_date = parse_date(d)?;
            }
            rule.expired_object_delete_marker = e.expired_object_delete_marker.unwrap_or(false);
            if rule.expired_object_delete_marker && !rule.filter_tags.is_empty() {
                return Err(invalid(
                    "InvalidRequest",
                    "ExpiredObjectDeleteMarker cannot be specified with object tags",
                ));
            }
        }
        if let Some(n) = &r.noncurrent {
            rule.noncurrent_version_expiration_days = positive(n.days, "NoncurrentDays")?;
            if rule.noncurrent_version_expiration_days == 0 {
                return Err(invalid(
                    "MalformedXML",
                    "NoncurrentVersionExpiration needs NoncurrentDays",
                ));
            }
            rule.newer_noncurrent_versions = match n.newer {
                None => 0,
                Some(v) if (1..=100).contains(&v) => u32::try_from(v).unwrap_or(0),
                Some(_) => {
                    return Err(invalid(
                        "InvalidArgument",
                        "NewerNoncurrentVersions must be between 1 and 100",
                    ));
                }
            };
        }
        if let Some(a) = &r.abort {
            rule.abort_incomplete_multipart_upload_days = positive(a.days, "DaysAfterInitiation")?;
            if !rule.filter_tags.is_empty() {
                return Err(invalid(
                    "InvalidRequest",
                    "AbortIncompleteMultipartUpload cannot be specified with object tags",
                ));
            }
        }
        let acts = rule.expiration_days > 0
            || rule.expiration_date > 0
            || rule.expired_object_delete_marker
            || rule.noncurrent_version_expiration_days > 0
            || rule.abort_incomplete_multipart_upload_days > 0;
        if !acts {
            return Err(invalid(
                "InvalidRequest",
                "At least one action needs to be specified in a rule",
            ));
        }
        out.push(rule);
    }
    Ok(out)
}

/// The stored rules as S3's document, as they were written.
fn render(rules: &[ProtoRule]) -> String {
    let rules: Vec<RuleXml> = rules
        .iter()
        .map(|r| {
            let tags: Vec<TagXml> = {
                let mut t: Vec<TagXml> = r
                    .filter_tags
                    .iter()
                    .map(|(k, v)| TagXml {
                        key: k.clone(),
                        value: v.clone(),
                    })
                    .collect();
                t.sort_by(|a, b| a.key.cmp(&b.key));
                t
            };
            let (gt, lt) = (
                Some(r.object_size_greater_than).filter(|v| *v > 0),
                Some(r.object_size_less_than).filter(|v| *v > 0),
            );
            let conditions = usize::from(!r.prefix.is_empty())
                + tags.len()
                + usize::from(gt.is_some())
                + usize::from(lt.is_some());
            let filter = r.has_filter.then(|| {
                if conditions > 1 {
                    FilterXml {
                        and: Some(AndXml {
                            prefix: Some(r.prefix.clone()).filter(|p| !p.is_empty()),
                            tags: tags.clone(),
                            size_gt: gt,
                            size_lt: lt,
                        }),
                        ..FilterXml::default()
                    }
                } else {
                    FilterXml {
                        prefix: Some(r.prefix.clone()).filter(|p| !p.is_empty()),
                        tag: tags.first().cloned(),
                        size_gt: gt,
                        size_lt: lt,
                        and: None,
                    }
                }
            });
            let expiration = if r.expiration_days > 0 {
                Some(ExpirationXml {
                    days: Some(i64::from(r.expiration_days)),
                    ..Default::default()
                })
            } else if r.expiration_date > 0 {
                Some(ExpirationXml {
                    date: chrono::DateTime::from_timestamp(
                        i64::try_from(r.expiration_date).unwrap_or(0),
                        0,
                    )
                    .map(|d| d.format("%Y-%m-%dT%H:%M:%S.000Z").to_string()),
                    ..Default::default()
                })
            } else if r.expired_object_delete_marker {
                Some(ExpirationXml {
                    expired_object_delete_marker: Some(true),
                    ..Default::default()
                })
            } else {
                None
            };
            RuleXml {
                id: Some(r.id.clone()),
                prefix: (!r.has_filter).then(|| r.prefix.clone()),
                filter,
                status: if r.enabled { "Enabled" } else { "Disabled" }.to_string(),
                expiration,
                noncurrent: (r.noncurrent_version_expiration_days > 0).then(|| NoncurrentXml {
                    days: Some(i64::from(r.noncurrent_version_expiration_days)),
                    newer: Some(i64::from(r.newer_noncurrent_versions)).filter(|n| *n > 0),
                }),
                abort: (r.abort_incomplete_multipart_upload_days > 0).then(|| AbortXml {
                    days: Some(i64::from(r.abort_incomplete_multipart_upload_days)),
                }),
                transition: None,
                noncurrent_transition: None,
            }
        })
        .collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{}",
        quick_xml::se::to_string(&ConfigXml { rules })
            .unwrap_or_default()
            .replacen(
                "<LifecycleConfiguration>",
                "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
                1
            )
    )
}

fn meta_error(e: &tonic::Status) -> Response {
    if e.code() == tonic::Code::NotFound {
        S3Error::xml_response(
            "NoSuchBucket",
            "The specified bucket does not exist",
            StatusCode::NOT_FOUND,
        )
    } else {
        // 503 when meta was unavailable (retry), as every S3 call answers.
        S3Error::from_status(e)
    }
}

/// `PUT /{bucket}?lifecycle`
pub async fn put_config(state: &AppState, bucket: &str, body: &[u8]) -> Response {
    if let Err(r) = crate::s3::bucket_owner(state, bucket).await {
        return r;
    }
    let rules = match parse(body) {
        Ok(r) => r,
        Err(e) => {
            return S3Error::xml_response(e.code, &e.message, StatusCode::BAD_REQUEST);
        }
    };
    match state
        .meta_client
        .clone()
        .put_bucket_lifecycle(PutBucketLifecycleRequest {
            bucket: bucket.to_string(),
            config: Some(ProtoConfig { rules }),
        })
        .await
        .inspect(|_| state.policy_cache.lifecycle.invalidate(bucket))
    {
        Ok(_) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::empty())
            .unwrap(),
        Err(e) => meta_error(&e),
    }
}

/// `GET /{bucket}?lifecycle`
pub async fn get_config(state: &AppState, bucket: &str) -> Response {
    if let Err(r) = crate::s3::bucket_owner(state, bucket).await {
        return r;
    }
    match state
        .meta_client
        .clone()
        .get_bucket_lifecycle(GetBucketLifecycleRequest {
            bucket: bucket.to_string(),
        })
        .await
    {
        Ok(r) => {
            let r = r.into_inner();
            match r.config.filter(|c| r.found && !c.rules.is_empty()) {
                Some(c) => Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/xml")
                    .body(Body::from(render(&c.rules)))
                    .unwrap(),
                None => S3Error::xml_response(
                    "NoSuchLifecycleConfiguration",
                    "The lifecycle configuration does not exist",
                    StatusCode::NOT_FOUND,
                ),
            }
        }
        Err(e) => meta_error(&e),
    }
}

/// `DELETE /{bucket}?lifecycle`
pub async fn delete_config(state: &AppState, bucket: &str) -> Response {
    if let Err(r) = crate::s3::bucket_owner(state, bucket).await {
        return r;
    }
    match state
        .meta_client
        .clone()
        .delete_bucket_lifecycle(DeleteBucketLifecycleRequest {
            bucket: bucket.to_string(),
        })
        .await
        .inspect(|_| state.policy_cache.lifecycle.invalidate(bucket))
    {
        Ok(_) => Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(Body::empty())
            .unwrap(),
        Err(e) => meta_error(&e),
    }
}

// ── x-amz-expiration ────────────────────────────────────────────────────

/// Buckets past this many cached rule sets are dropped from the cache.
const MAX_CACHED_BUCKETS: usize = 10_000;

/// Each bucket's lifecycle rules (`None`: it has none), cached for the
/// `x-amz-expiration` header so a GET or HEAD doesn't ask meta. This
/// gateway's own changes invalidate it; others' show within the TTL.
type CachedRules = (Option<Arc<Vec<ProtoRule>>>, Instant);

pub struct RulesCache {
    entries: parking_lot::RwLock<HashMap<String, CachedRules>>,
    ttl: Duration,
}

impl RulesCache {
    #[must_use]
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: parking_lot::RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    pub fn invalidate(&self, bucket: &str) {
        self.entries.write().remove(bucket);
    }
}

/// A bucket's rules, from the cache or meta. `None` when it has none, or
/// they can't be read now (the header is then left out, never guessed).
async fn bucket_rules(state: &AppState, bucket: &str) -> Option<Arc<Vec<ProtoRule>>> {
    let cache = &state.policy_cache.lifecycle;
    if let Some((rules, at)) = cache.entries.read().get(bucket)
        && at.elapsed() < cache.ttl
    {
        return rules.clone();
    }
    let resp = state
        .meta_client
        .clone()
        .get_bucket_lifecycle(GetBucketLifecycleRequest {
            bucket: bucket.to_string(),
        })
        .await
        .ok()?
        .into_inner();
    let rules = resp
        .config
        .filter(|c| resp.found && !c.rules.is_empty())
        .map(|c| Arc::new(c.rules));
    let mut entries = cache.entries.write();
    if entries.len() >= MAX_CACHED_BUCKETS {
        entries.clear();
    }
    entries.insert(bucket.to_string(), (rules.clone(), Instant::now()));
    rules
}

/// When `object` (a current version, made at `made_ms`) expires under
/// `rules`, and by which rule: the earliest of the enabled expiration rules
/// that filter it in. A `Days` rule expires it at the first UTC midnight at
/// least that many days after it was made, as S3 computes it. (The
/// worker's test-only day length doesn't change this.)
fn expiry(rules: &[ProtoRule], object: &ObjectMeta, made_ms: u64) -> Option<(u64, String)> {
    const DAY: u64 = 86_400;
    rules
        .iter()
        .filter(|r| r.enabled && matches(r, object))
        .filter_map(|r| {
            let at = if r.expiration_days > 0 {
                let after = made_ms / 1000 + u64::from(r.expiration_days) * DAY;
                after.div_ceil(DAY) * DAY
            } else if r.expiration_date > 0 {
                r.expiration_date
            } else {
                return None;
            };
            Some((at, r.id.clone()))
        })
        .min_by_key(|(at, _)| *at)
}

/// The `x-amz-expiration` header for `object` in `bucket`, if a lifecycle
/// rule will expire it: `expiry-date="<HTTP date>", rule-id="<id>"`.
pub async fn expiration_header(
    state: &AppState,
    bucket: &str,
    object: &ObjectMeta,
    made_ms: u64,
) -> Option<axum::http::HeaderValue> {
    if object.is_delete_marker {
        return None;
    }
    let rules = bucket_rules(state, bucket).await?;
    let (at, rule) = expiry(&rules, object, made_ms)?;
    let date = chrono::DateTime::<chrono::Utc>::from_timestamp(i64::try_from(at).ok()?, 0)?
        .format("%a, %d %b %Y %H:%M:%S GMT");
    axum::http::HeaderValue::from_str(&format!("expiry-date=\"{date}\", rule-id=\"{rule}\"")).ok()
}

// ── Matching ────────────────────────────────────────────────────────────

/// Whether `v` (an object version, not a delete marker) is one `rule`
/// filters in.
fn matches(rule: &ProtoRule, v: &ObjectMeta) -> bool {
    v.key.starts_with(&rule.prefix)
        && rule
            .filter_tags
            .iter()
            .all(|(k, val)| v.tags.get(k) == Some(val))
        && (rule.object_size_greater_than == 0 || v.size > rule.object_size_greater_than)
        && (rule.object_size_less_than == 0 || v.size < rule.object_size_less_than)
}

/// Whether a delete marker for `key` falls under `rule`: markers have no
/// tags or size, so only a prefix-only rule covers them.
fn matches_marker(rule: &ProtoRule, key: &str) -> bool {
    key.starts_with(&rule.prefix)
        && rule.filter_tags.is_empty()
        && rule.object_size_greater_than == 0
        && rule.object_size_less_than == 0
}

/// What lifecycle does to one key.
#[derive(Debug, PartialEq, Eq)]
enum Action {
    /// Expire the current version (rule id).
    Expire(String),
    /// Remove the delete marker that is the key's only version.
    RemoveMarker(String, String),
    /// Delete a noncurrent version (rule id, version id).
    DeleteNoncurrent(String, String),
}

/// The actions due for one key, given its versions newest first, at
/// `now_ms`, with a lifecycle day of `day_ms`.
fn due(
    rules: &[ProtoRule],
    versions: &[ObjectMeta],
    now_ms: u64,
    day_ms: u64,
    versioned: bool,
) -> Vec<Action> {
    let Some(current) = versions.first() else {
        return Vec::new();
    };
    let enabled = || rules.iter().filter(|r| r.enabled);
    let mut out = Vec::new();
    let age_ms = |v: &ObjectMeta| now_ms.saturating_sub(crate::s3::version_time_ms(v));

    if current.is_delete_marker {
        // A marker alone: nothing behind it to bring back.
        if versions.len() == 1
            && let Some(r) = enabled().find(|r| {
                // ExpiredObjectDeleteMarker: whenever it's alone. Days in
                // a versioned bucket: once the marker is that old too.
                (r.expired_object_delete_marker
                    || (versioned
                        && r.expiration_days > 0
                        && age_ms(current) >= u64::from(r.expiration_days) * day_ms))
                    && matches_marker(r, &current.key)
            })
        {
            out.push(Action::RemoveMarker(
                r.id.clone(),
                current.version_id.clone(),
            ));
        }
    } else if let Some(r) = enabled().find(|r| {
        matches(r, current)
            && ((r.expiration_days > 0 && age_ms(current) >= u64::from(r.expiration_days) * day_ms)
                || (r.expiration_date > 0 && now_ms >= r.expiration_date * 1000))
    }) {
        out.push(Action::Expire(r.id.clone()));
    }

    // Noncurrent versions: each became noncurrent when the next newer one
    // was written.
    for rule in enabled().filter(|r| r.noncurrent_version_expiration_days > 0) {
        let mut kept = 0u32;
        for (i, v) in versions.iter().enumerate().skip(1) {
            let filtered_in = if v.is_delete_marker {
                matches_marker(rule, &v.key)
            } else {
                matches(rule, v)
            };
            if !filtered_in {
                continue;
            }
            if kept < rule.newer_noncurrent_versions {
                kept += 1;
                continue;
            }
            let since = crate::s3::version_time_ms(&versions[i - 1]);
            let noncurrent_for = now_ms.saturating_sub(since);
            if noncurrent_for >= u64::from(rule.noncurrent_version_expiration_days) * day_ms
                && !out
                    .iter()
                    .any(|a| matches!(a, Action::DeleteNoncurrent(_, id) if *id == v.version_id))
            {
                out.push(Action::DeleteNoncurrent(
                    rule.id.clone(),
                    v.version_id.clone(),
                ));
            }
        }
    }
    out
}

// ── The worker ──────────────────────────────────────────────────────────

/// Start the lifecycle worker. Every gateway runs one; the lease lets one
/// scan at a time.
pub fn spawn_worker(state: Arc<AppState>, timing: Timing) {
    tokio::spawn(async move {
        let holder = uuid::Uuid::new_v4().to_string();
        info!(
            "Lifecycle worker started (interval={}s, day={}s)",
            timing.interval.as_secs(),
            timing.day.as_secs()
        );
        // Let the cluster settle first.
        tokio::time::sleep(timing.interval.min(Duration::from_secs(60))).await;
        let mut ticker = tokio::time::interval(timing.interval);
        loop {
            ticker.tick().await;
            if !lease(&state, &holder, timing).await {
                debug!("lifecycle: another gateway holds the lease");
                continue;
            }
            let started = std::time::Instant::now();
            let ok = scan(&state, &holder, timing).await;
            crate::gateway_metrics::record_lifecycle_scan(started.elapsed(), ok);
        }
    });
}

/// Take or renew the lease, long enough to outlast a scan step.
async fn lease(state: &AppState, holder: &str, timing: Timing) -> bool {
    let ttl = (timing.interval.as_secs() * 2).max(120);
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

pub(crate) fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// One pass over every bucket with rules. False if it stopped early.
async fn scan(state: &Arc<AppState>, holder: &str, timing: Timing) -> bool {
    let buckets = match state
        .meta_client
        .clone()
        .list_buckets(ListBucketsRequest::default())
        .await
    {
        Ok(r) => r.into_inner().buckets,
        Err(e) => {
            error!("lifecycle: cannot list buckets: {e}");
            return false;
        }
    };
    let day_ms = u64::try_from(timing.day.as_millis())
        .unwrap_or(86_400_000)
        .max(1);
    for b in buckets {
        // Still ours? Another gateway may have taken over (we were slow).
        if !lease(state, holder, timing).await {
            warn!("lifecycle: lost the lease mid-scan; stopping");
            return false;
        }
        let rules = match state
            .meta_client
            .clone()
            .get_bucket_lifecycle(GetBucketLifecycleRequest {
                bucket: b.name.clone(),
            })
            .await
        {
            Ok(r) => {
                let r = r.into_inner();
                r.config
                    .filter(|_| r.found)
                    .map(|c| c.rules)
                    .unwrap_or_default()
            }
            Err(_) => continue,
        };
        if !rules.iter().any(|r| r.enabled) {
            continue;
        }
        if let Err(e) = scan_bucket(state, &b.name, &b.tenant, &rules, day_ms).await {
            warn!("lifecycle: bucket {}: {e}", b.name);
        }
        abort_uploads(state, &b.name, &b.tenant, &rules, day_ms).await;
    }
    true
}

async fn scan_bucket(
    state: &Arc<AppState>,
    bucket: &str,
    tenant: &str,
    rules: &[ProtoRule],
    day_ms: u64,
) -> Result<(), String> {
    let versioning = state
        .meta_client
        .clone()
        .get_bucket_versioning(objectio_proto::metadata::GetBucketVersioningRequest {
            bucket: bucket.to_string(),
        })
        .await
        .map_err(|e| e.to_string())?
        .into_inner()
        .state();
    let versioned = versioning != objectio_proto::metadata::VersioningState::VersioningDisabled;
    // List from the longest prefix every enabled rule shares.
    let prefix = common_prefix(
        rules
            .iter()
            .filter(|r| r.enabled)
            .map(|r| r.prefix.as_str()),
    );
    let mut marker = String::new();
    loop {
        let (found, more) = crate::s3::gather_versions(state, bucket, &prefix, &marker, "", PAGE)
            .await
            .map_err(|r| format!("listing failed ({})", r.status()))?;
        let mut last = None;
        for (key, mut versions) in found {
            if !marker.is_empty() && key <= marker {
                continue;
            }
            crate::s3::sort_versions(&mut versions);
            for action in due(rules, &versions, now_ms(), day_ms, versioned) {
                act(state, bucket, tenant, &key, action).await;
            }
            last = Some(key);
        }
        match last {
            Some(k) if more => marker = k,
            _ => return Ok(()),
        }
    }
}

fn common_prefix<'a>(mut prefixes: impl Iterator<Item = &'a str>) -> String {
    let Some(first) = prefixes.next() else {
        return String::new();
    };
    let mut common = first.to_string();
    for p in prefixes {
        let n = common
            .char_indices()
            .zip(p.chars())
            .take_while(|((_, a), b)| a == b)
            .count();
        common = common.chars().take(n).collect();
    }
    common
}

/// Carry out one action through the S3 delete path.
async fn act(state: &Arc<AppState>, bucket: &str, tenant: &str, key: &str, action: Action) {
    let (rule, version, kind, s3_action) = match &action {
        Action::Expire(r) => (r, None, "expire", "s3:DeleteObject"),
        Action::RemoveMarker(r, v) => (
            r,
            Some(v.clone()),
            "delete_marker",
            "s3:DeleteObjectVersion",
        ),
        Action::DeleteNoncurrent(r, v) => {
            (r, Some(v.clone()), "noncurrent", "s3:DeleteObjectVersion")
        }
    };
    let version_label = version
        .as_deref()
        .map(|v| crate::s3::version_label(v).to_string());
    let resp = crate::s3::delete_object(
        State(Arc::clone(state)),
        Path((bucket.to_string(), key.to_string())),
        None,
        version_label.clone(),
        HeaderMap::new(),
    )
    .await;
    let status = resp.status();
    let ok = status.is_success();
    if status == StatusCode::FORBIDDEN {
        // Object Lock: retention or a legal hold. Left alone, as it must be.
        crate::gateway_metrics::record_lifecycle("locked", true);
        debug!("lifecycle: {bucket}/{key} is locked; left alone (rule {rule})");
    } else {
        crate::gateway_metrics::record_lifecycle(kind, ok);
    }
    if !ok && status != StatusCode::FORBIDDEN {
        warn!("lifecycle: {kind} {bucket}/{key} failed: {status}");
    }
    state.auditor.record_internal(crate::audit::InternalAction {
        principal: format!("lifecycle:{rule}"),
        auth: "Lifecycle",
        method: "DELETE",
        action: s3_action,
        bucket,
        bucket_tenant: tenant,
        key: Some(key),
        version_id: version_label.as_deref(),
        status: status.as_u16(),
    });
}

async fn abort_uploads(
    state: &Arc<AppState>,
    bucket: &str,
    tenant: &str,
    rules: &[ProtoRule],
    day_ms: u64,
) {
    let now_s = now_ms() / 1000;
    let day_s = (day_ms / 1000).max(1);
    let mut client = state.meta_client.clone();
    for rule in rules
        .iter()
        .filter(|r| r.enabled && r.abort_incomplete_multipart_upload_days > 0)
    {
        let mut key_marker = String::new();
        let mut upload_marker = String::new();
        loop {
            let Ok(page) = client
                .list_multipart_uploads(objectio_proto::metadata::ListMultipartUploadsRequest {
                    bucket: bucket.to_string(),
                    prefix: rule.prefix.clone(),
                    max_uploads: 1000,
                    key_marker: key_marker.clone(),
                    upload_id_marker: upload_marker.clone(),
                })
                .await
            else {
                break;
            };
            let page = page.into_inner();
            for upload in &page.uploads {
                if now_s.saturating_sub(upload.initiated)
                    < u64::from(rule.abort_incomplete_multipart_upload_days) * day_s
                {
                    continue;
                }
                let aborted = client
                    .abort_multipart_upload(objectio_proto::metadata::AbortMultipartUploadRequest {
                        bucket: bucket.to_string(),
                        key: upload.key.clone(),
                        upload_id: upload.upload_id.clone(),
                    })
                    .await;
                crate::gateway_metrics::record_lifecycle("abort_upload", aborted.is_ok());
                let status = if aborted.is_ok() { 204 } else { 500 };
                if let Ok(aborted) = aborted {
                    // Meta hands back the parts it dropped; nothing refers to
                    // them once it has.
                    crate::osd_pool::reclaim_shards(
                        &state.osd_pool,
                        &mut client,
                        crate::osd_pool::stripe_targets(&aborted.into_inner().stripes),
                        crate::osd_pool::Reclaim::Abort,
                    )
                    .await;
                }
                state.auditor.record_internal(crate::audit::InternalAction {
                    principal: format!("lifecycle:{}", rule.id),
                    auth: "Lifecycle",
                    method: "DELETE",
                    action: "s3:AbortMultipartUpload",
                    bucket,
                    bucket_tenant: tenant,
                    key: Some(&upload.key),
                    version_id: None,
                    status,
                });
            }
            if !page.is_truncated {
                break;
            }
            key_marker = page.next_key_marker;
            upload_marker = page.next_upload_id_marker;
            if key_marker.is_empty() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(xml: &str) -> Vec<ProtoRule> {
        parse(xml.as_bytes()).unwrap_or_else(|e| panic!("{}: {}", e.code, e.message))
    }

    fn refused(xml: &str) -> &'static str {
        match parse(xml.as_bytes()) {
            Ok(_) => "accepted",
            Err(e) => e.code,
        }
    }

    const DAY: u64 = 86_400_000;

    fn v(key: &str, vid: &str, at_day: u64, marker: bool) -> ObjectMeta {
        ObjectMeta {
            key: key.into(),
            version_id: vid.into(),
            is_delete_marker: marker,
            modified_at: at_day * 86_400,
            created_at: at_day * 86_400,
            size: 10,
            ..ObjectMeta::default()
        }
    }

    /// `x-amz-expiration`: the earliest matching rule, a `Days` rule rounded
    /// up to the next UTC midnight; rules that don't filter it in, or are
    /// disabled, don't count.
    #[test]
    fn an_object_expires_at_the_midnight_after_its_days() {
        let all = rules(
            "<LifecycleConfiguration>\
             <Rule><ID>late</ID><Filter/><Status>Enabled</Status><Expiration><Days>5</Days></Expiration></Rule>\
             <Rule><ID>logs</ID><Filter><Prefix>logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>\
             <Rule><ID>off</ID><Filter/><Status>Disabled</Status><Expiration><Days>1</Days></Expiration></Rule>\
             <Rule><ID>old</ID><Filter/><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>\
             </LifecycleConfiguration>",
        );
        // Made on day 10 at 13:00.
        let made_ms = 10 * DAY + 13 * 3_600_000;
        let log = v("logs/a", "", 10, false);
        assert_eq!(
            expiry(&all, &log, made_ms),
            Some((12 * 86_400, "logs".to_string())),
            "day 11 13:00, rounded up to day 12 00:00"
        );
        let other = v("data/a", "", 10, false);
        assert_eq!(
            expiry(&all, &other, made_ms),
            Some((16 * 86_400, "late".to_string()))
        );
        // Made exactly at midnight: already on a midnight, not a day later.
        assert_eq!(
            expiry(&all, &log, 10 * DAY),
            Some((11 * 86_400, "logs".to_string()))
        );
        let none = rules(
            "<LifecycleConfiguration><Rule><ID>off</ID><Filter/><Status>Disabled</Status>\
             <Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>",
        );
        assert_eq!(expiry(&none, &other, made_ms), None);
    }

    #[test]
    fn documents_are_checked_as_s3_checks_them() {
        let ok = "<LifecycleConfiguration><Rule><ID>r</ID><Filter><Prefix>logs/</Prefix></Filter>\
                  <Status>Enabled</Status><Expiration><Days>3</Days></Expiration></Rule></LifecycleConfiguration>";
        assert_eq!(rules(ok)[0].expiration_days, 3);
        let wrap = |rule: &str| {
            format!("<LifecycleConfiguration><Rule>{rule}</Rule></LifecycleConfiguration>")
        };
        assert_eq!(
            refused(&wrap(
                "<ID>r</ID><Filter/><Status>On</Status><Expiration><Days>1</Days></Expiration>"
            )),
            "MalformedXML"
        );
        assert_eq!(
            refused(&wrap(
                "<ID>r</ID><Filter/><Status>Enabled</Status><Expiration><Days>0</Days></Expiration>"
            )),
            "InvalidArgument"
        );
        assert_eq!(
            refused(&wrap("<ID>r</ID><Filter/><Status>Enabled</Status>")),
            "InvalidRequest"
        );
        assert_eq!(
            refused(&wrap(
                "<ID>r</ID><Status>Enabled</Status><Expiration><Days>1</Days></Expiration>"
            )),
            "MalformedXML"
        );
        assert_eq!(
            refused(&wrap(
                "<ID>r</ID><Filter/><Status>Enabled</Status><Expiration><Date>2026-01-01T10:00:00Z</Date></Expiration>"
            )),
            "InvalidArgument"
        );
        assert_eq!(
            refused(&wrap(
                "<ID>r</ID><Filter/><Status>Enabled</Status><Transition><Days>1</Days><StorageClass>GLACIER</StorageClass></Transition>"
            )),
            "InvalidStorageClass"
        );
        let two = "<LifecycleConfiguration><Rule><ID>r</ID><Filter/><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>\
                   <Rule><ID>r</ID><Filter/><Status>Enabled</Status><Expiration><Days>2</Days></Expiration></Rule></LifecycleConfiguration>";
        assert_eq!(refused(two), "InvalidArgument");
    }

    #[test]
    fn a_document_reads_back_as_written() {
        let xml = "<LifecycleConfiguration><Rule><ID>r</ID><Filter><And><Prefix>a/</Prefix>\
                   <Tag><Key>k</Key><Value>v</Value></Tag></And></Filter><Status>Enabled</Status>\
                   <NoncurrentVersionExpiration><NoncurrentDays>2</NoncurrentDays>\
                   <NewerNoncurrentVersions>3</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule>\
                   <Rule><ID>legacy</ID><Prefix>x/</Prefix><Status>Disabled</Status>\
                   <Expiration><Date>2030-01-01T00:00:00.000Z</Date></Expiration></Rule></LifecycleConfiguration>";
        let parsed = rules(xml);
        let again = rules(&render(&parsed));
        assert_eq!(parsed, again);
        let out = render(&parsed);
        assert!(
            out.contains("<And><Prefix>a/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And>"),
            "{out}"
        );
        assert!(
            out.contains("<Prefix>x/</Prefix>") && out.contains("2030-01-01T00:00:00.000Z"),
            "{out}"
        );
    }

    #[test]
    fn the_current_version_expires_after_its_days() {
        let r = rules(
            "<LifecycleConfiguration><Rule><ID>e</ID><Filter><Prefix>logs/</Prefix></Filter>\
                       <Status>Enabled</Status><Expiration><Days>3</Days></Expiration></Rule></LifecycleConfiguration>",
        );
        let versions = vec![v("logs/a", "v1", 10, false)];
        assert!(due(&r, &versions, 12 * DAY, DAY, false).is_empty());
        assert_eq!(
            due(&r, &versions, 13 * DAY, DAY, false),
            vec![Action::Expire("e".into())]
        );
        // Outside the prefix: never.
        assert!(due(&r, &[v("data/a", "v1", 0, false)], 100 * DAY, DAY, false).is_empty());
    }

    #[test]
    fn a_marker_is_removed_only_when_nothing_is_behind_it() {
        let r = rules(
            "<LifecycleConfiguration><Rule><ID>m</ID><Filter/><Status>Enabled</Status>\
                       <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule></LifecycleConfiguration>",
        );
        let alone = vec![v("k", "dm", 5, true)];
        assert_eq!(
            due(&r, &alone, 6 * DAY, DAY, true),
            vec![Action::RemoveMarker("m".into(), "dm".into())]
        );
        // Versions behind it: removing it would bring the object back.
        let behind = vec![v("k", "dm", 5, true), v("k", "v1", 1, false)];
        assert!(due(&r, &behind, 600 * DAY, DAY, true).is_empty());
    }

    #[test]
    fn noncurrent_versions_expire_by_how_long_they_have_been_noncurrent() {
        let r = rules(
            "<LifecycleConfiguration><Rule><ID>n</ID><Filter/><Status>Enabled</Status>\
                       <NoncurrentVersionExpiration><NoncurrentDays>2</NoncurrentDays>\
                       <NewerNoncurrentVersions>1</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>",
        );
        // v4 current (day 10); v3 noncurrent since day 10; v2 since day 6;
        // v1 since day 3.
        let versions = vec![
            v("k", "v4", 10, false),
            v("k", "v3", 6, false),
            v("k", "v2", 3, false),
            v("k", "v1", 1, false),
        ];
        let acts = due(&r, &versions, 11 * DAY, DAY, true);
        // v3 is the newest noncurrent: kept. v2 noncurrent 5 days, v1 8: go.
        assert_eq!(
            acts,
            vec![
                Action::DeleteNoncurrent("n".into(), "v2".into()),
                Action::DeleteNoncurrent("n".into(), "v1".into()),
            ]
        );
        // The current version is never touched by a noncurrent rule.
        assert!(
            !acts
                .iter()
                .any(|a| matches!(a, Action::DeleteNoncurrent(_, id) if id == "v4"))
        );
    }

    #[test]
    fn tag_and_size_filters_pick_what_they_name() {
        let r = rules(
            "<LifecycleConfiguration><Rule><ID>t</ID><Filter><And><Tag><Key>tier</Key><Value>tmp</Value></Tag>\
                       <ObjectSizeGreaterThan>5</ObjectSizeGreaterThan></And></Filter><Status>Enabled</Status>\
                       <Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>",
        );
        let mut tagged = v("a", "v1", 0, false);
        tagged.tags.insert("tier".into(), "tmp".into());
        assert_eq!(due(&r, &[tagged.clone()], 5 * DAY, DAY, false).len(), 1);
        tagged.size = 3;
        assert!(due(&r, &[tagged], 5 * DAY, DAY, false).is_empty());
        assert!(due(&r, &[v("a", "v1", 0, false)], 5 * DAY, DAY, false).is_empty());
    }

    #[test]
    fn days_remove_a_lone_marker_only_once_it_is_that_old() {
        let r = rules(
            "<LifecycleConfiguration><Rule><ID>d</ID><Filter/><Status>Enabled</Status>\
                       <Expiration><Days>5</Days></Expiration></Rule></LifecycleConfiguration>",
        );
        let alone = vec![v("k", "dm", 10, true)];
        assert!(due(&r, &alone, 12 * DAY, DAY, true).is_empty());
        assert_eq!(
            due(&r, &alone, 15 * DAY, DAY, true),
            vec![Action::RemoveMarker("d".into(), "dm".into())]
        );
    }
}
