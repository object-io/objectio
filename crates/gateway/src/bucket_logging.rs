//! Bucket logging (`?logging`, A12): every request on a bucket, as a line
//! of S3's server access log format, delivered as objects into a target
//! bucket.
//!
//! - **Configuration** (`PutBucketLogging`, `GetBucketLogging`): the target
//!   bucket, a prefix and the key format (`SimplePrefix`, the default, or
//!   `PartitionedPrefix`). A bucket setting in meta (through Raft), cached
//!   by each gateway for [`CACHE_TTL`]. Only the bucket's owner (or the
//!   system admin) sets it, as in S3. An empty `BucketLoggingStatus` turns
//!   logging off.
//! - **Consent:** the target must be in the source bucket's tenant (or the
//!   system's), and its bucket policy must let the logging service write
//!   there: `s3:PutObject` for `Service: logging.s3.amazonaws.com` on
//!   `<target>/<prefix>`, with `aws:SourceArn` (the source bucket) and
//!   `aws:SourceAccount` (its owner) as conditions — S3's rule. Checked
//!   when logging is configured and again on every delivery: a target
//!   whose policy no longer allows it gets nothing.
//! - **Recording** (`record`): the audit layer, which sees every request,
//!   hands each one on a logged bucket over once its response is sent. The
//!   record is appended to a spool on the gateway's disk (the audit spool's
//!   format, `crate::audit_spool`), so a gateway killed loses none, and a
//!   request never waits for its delivery.
//! - **Delivery** (`delivery`): records are batched by target and written
//!   as one object per batch, named `<prefix>YYYY-mm-DD-HH-MM-SS-<unique>`
//!   (or partitioned:
//!   `<prefix><owner>/<region>/<bucket>/YYYY/MM/DD/YYYY-MM-DD-HH-MM-SS-<unique>`),
//!   once a batch's first record is [`Timing::roll`] old or it holds
//!   [`Timing::max_records`].

mod delivery;
mod record;

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use objectio_auth::AuthResult;
use objectio_auth::policy::{BucketPolicy, PolicyDecision, PolicyEvaluator, RequestContext};
use objectio_common::histogram::CounterVec;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::metadata::{
    GetBucketPolicyRequest, GetBucketRequest, GetBucketSettingRequest, PutBucketSettingRequest,
};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tonic::transport::Channel;
use tracing::warn;

use crate::audit_spool::Spool;
use crate::s3::{AppState, S3Error};

pub use delivery::spawn as spawn_delivery;
pub use record::{Answer, Captured, Pending, Record};

/// The bucket setting holding a bucket's configuration.
const SETTING: &str = "logging";
/// The principal a target's policy names to let logs in.
pub const SERVICE: &str = "logging.s3.amazonaws.com";
/// How long a cached configuration is trusted before it is read again (in
/// the background: requests go on using the one they have).
const CACHE_TTL: Duration = Duration::from_secs(10);
/// The longest prefix: a log object's key adds up to ~200 bytes to it, and
/// keys are at most 1024.
const MAX_PREFIX: usize = 512;
/// Buckets whose configuration a gateway keeps.
const MAX_CACHED: usize = 100_000;

static DELIVERED: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static DROPPED: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static FAILURES: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);

/// The bucket logging metrics, for `/metrics`.
pub fn render_metrics(out: &mut String) {
    DELIVERED.render(
        out,
        "objectio_bucket_logging_records_total",
        "Access-log records delivered into target buckets",
    );
    DROPPED.render(
        out,
        "objectio_bucket_logging_dropped_total",
        "Access-log records not delivered, by reason",
    );
    FAILURES.render(
        out,
        "objectio_bucket_logging_delivery_failures_total",
        "Failed attempts to write a log object (retried)",
    );
}

fn reason(r: &str) -> String {
    format!("reason=\"{r}\"")
}

// ── Configuration ───────────────────────────────────────────────────────

/// How log objects are named.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeyFormat {
    /// `<prefix>YYYY-mm-DD-HH-MM-SS-<unique>`
    Simple,
    /// `<prefix><owner>/<region>/<bucket>/YYYY/MM/DD/...`, dated by the
    /// first event's time or by delivery.
    Partitioned { event_time: bool },
}

/// A bucket's logging configuration, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    pub target_bucket: String,
    pub target_prefix: String,
    pub key_format: KeyFormat,
    /// The source bucket's owner (`aws:SourceAccount`, the log lines'
    /// bucket owner) and tenant, when logging was configured.
    pub source_owner: String,
    pub source_tenant: String,
    /// When the configuration last changed (Unix seconds):
    /// `Last-Modified` on `GetBucketLogging`.
    pub modified: i64,
}

impl Config {
    /// The same configuration, whenever it was made.
    fn same(&self, other: &Self) -> bool {
        Self {
            modified: 0,
            ..self.clone()
        } == Self {
            modified: 0,
            ..other.clone()
        }
    }
}

#[derive(Deserialize)]
#[serde(rename = "BucketLoggingStatus")]
struct StatusXml {
    #[serde(rename = "LoggingEnabled", default)]
    enabled: Option<EnabledXml>,
}

#[derive(Deserialize)]
struct EnabledXml {
    #[serde(rename = "TargetBucket", default)]
    target_bucket: String,
    #[serde(rename = "TargetPrefix", default)]
    target_prefix: String,
    #[serde(rename = "TargetObjectKeyFormat", default)]
    key_format: Option<KeyFormatXml>,
    // TargetGrants are accepted and ignored: ACLs are off (every bucket is
    // BucketOwnerEnforced); who reads the logs is the target's policy.
}

#[derive(Deserialize)]
struct KeyFormatXml {
    #[serde(rename = "PartitionedPrefix", default)]
    partitioned: Option<PartitionedXml>,
}

#[derive(Deserialize)]
struct PartitionedXml {
    #[serde(rename = "PartitionDateSource", default)]
    source: String,
}

/// What a `BucketLoggingStatus` asks for: `None` turns logging off.
#[derive(Debug, PartialEq, Eq)]
struct Wanted {
    target_bucket: String,
    target_prefix: String,
    key_format: KeyFormat,
}

fn malformed(msg: &str) -> Response {
    S3Error::xml_response("MalformedXML", msg, StatusCode::BAD_REQUEST)
}

fn invalid(msg: &str) -> Response {
    S3Error::xml_response("InvalidArgument", msg, StatusCode::BAD_REQUEST)
}

#[allow(clippy::result_large_err)] // Err is the refusal, built once per request.
fn parse(body: &[u8]) -> Result<Option<Wanted>, Response> {
    let doc: StatusXml = quick_xml::de::from_reader(body)
        .map_err(|e| malformed(&format!("The XML you provided was not well-formed: {e}")))?;
    let Some(e) = doc.enabled else {
        return Ok(None);
    };
    let target_bucket = e.target_bucket.trim().to_string();
    if target_bucket.is_empty() {
        return Err(malformed("LoggingEnabled needs a TargetBucket"));
    }
    if e.target_prefix.len() > MAX_PREFIX {
        return Err(invalid(&format!(
            "TargetPrefix is longer than {MAX_PREFIX} bytes"
        )));
    }
    if e.target_prefix.chars().any(char::is_control) {
        return Err(invalid("TargetPrefix has control characters"));
    }
    let key_format = match e.key_format.and_then(|k| k.partitioned) {
        None => KeyFormat::Simple,
        Some(p) => match p.source.as_str() {
            "EventTime" => KeyFormat::Partitioned { event_time: true },
            "DeliveryTime" | "" => KeyFormat::Partitioned { event_time: false },
            other => {
                return Err(malformed(&format!(
                    "PartitionDateSource must be EventTime or DeliveryTime, not {other:?}"
                )));
            }
        },
    };
    Ok(Some(Wanted {
        target_bucket,
        target_prefix: e.target_prefix,
        key_format,
    }))
}

fn render(config: Option<&Config>) -> String {
    let esc = |s: &str| quick_xml::escape::escape(s).into_owned();
    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
    );
    if let Some(c) = config {
        let format = match c.key_format {
            KeyFormat::Simple => "<SimplePrefix></SimplePrefix>".to_string(),
            KeyFormat::Partitioned { event_time } => format!(
                "<PartitionedPrefix><PartitionDateSource>{}</PartitionDateSource></PartitionedPrefix>",
                if event_time {
                    "EventTime"
                } else {
                    "DeliveryTime"
                }
            ),
        };
        xml.push_str(&format!(
            "<LoggingEnabled><TargetBucket>{}</TargetBucket><TargetPrefix>{}</TargetPrefix>\
             <TargetObjectKeyFormat>{format}</TargetObjectKeyFormat></LoggingEnabled>",
            esc(&c.target_bucket),
            esc(&c.target_prefix),
        ));
    }
    xml.push_str("</BucketLoggingStatus>");
    xml
}

// ── Consent ─────────────────────────────────────────────────────────────

/// Why a target can't take a source's logs.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// No such bucket.
    NoTarget,
    /// In another tenant (not the source's, not the system's).
    OtherTenant,
    /// Its policy doesn't let the logging service write there.
    Denied,
    /// Meta couldn't say.
    Unavailable(tonic::Status),
}

/// Whether `policy` lets the logging service put objects under
/// `target/prefix` for `source` (owned by `owner`).
pub(crate) fn policy_allows(
    policy: Option<&BucketPolicy>,
    target: &str,
    prefix: &str,
    source: &str,
    owner: &str,
) -> bool {
    let Some(policy) = policy else {
        return false;
    };
    // Only an Allow that names the service lets logs in: a grant to
    // everyone (`"*"`) is a grant to callers, not consent to take another
    // bucket's logs. Every Deny still applies.
    let service = format!("Service:{SERVICE}");
    let policy = BucketPolicy {
        statements: policy
            .statements
            .iter()
            .filter(|s| {
                s.effect == objectio_auth::policy::Effect::Deny
                    || matches!(&s.principal,
                        objectio_auth::policy::Principal::OBIO(names) if names.contains(&service))
            })
            .cloned()
            .collect(),
        ..policy.clone()
    };
    let policy = &policy;
    let context = RequestContext::new(
        format!("Service:{SERVICE}"),
        "s3:PutObject",
        format!("arn:obio:s3:::{target}/{prefix}"),
    )
    .with_multi_variable(
        "aws:SourceArn",
        vec![
            format!("arn:aws:s3:::{source}"),
            format!("arn:obio:s3:::{source}"),
        ],
    )
    .with_variable("aws:SourceAccount", owner);
    PolicyEvaluator::new().evaluate(policy, &context) == PolicyDecision::Allow
}

/// Whether `target` takes logs under `prefix` from `source` (owned by
/// `owner` in `tenant`).
pub(crate) async fn check_target(
    meta: &MetadataServiceClient<Channel>,
    target: &str,
    prefix: &str,
    source: &str,
    owner: &str,
    tenant: &str,
) -> Result<(), Refusal> {
    let mut meta = meta.clone();
    let bucket = match meta
        .get_bucket(GetBucketRequest {
            name: target.to_string(),
        })
        .await
    {
        Ok(r) => r.into_inner().bucket.ok_or(Refusal::NoTarget)?,
        Err(e) if e.code() == tonic::Code::NotFound => return Err(Refusal::NoTarget),
        Err(e) => return Err(Refusal::Unavailable(e)),
    };
    if !bucket.tenant.is_empty() && bucket.tenant != tenant {
        return Err(Refusal::OtherTenant);
    }
    let policy = match meta
        .get_bucket_policy(GetBucketPolicyRequest {
            bucket: target.to_string(),
        })
        .await
    {
        Ok(r) => {
            let r = r.into_inner();
            r.has_policy
                .then(|| BucketPolicy::from_json(&r.policy_json).ok())
                .flatten()
        }
        Err(e) if e.code() == tonic::Code::NotFound => return Err(Refusal::NoTarget),
        Err(e) => return Err(Refusal::Unavailable(e)),
    };
    if policy_allows(policy.as_ref(), target, prefix, source, owner) {
        Ok(())
    } else {
        Err(Refusal::Denied)
    }
}

// ── The logger ──────────────────────────────────────────────────────────

/// When a batch of records becomes a log object.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// A batch is written once its first record is this old...
    pub roll: Duration,
    /// ...or it holds this many records.
    pub max_records: usize,
}

struct Cached {
    config: Option<Arc<Config>>,
    fetched: Instant,
}

/// Each gateway's bucket logging: the configurations it has read, and the
/// spool records go to.
pub struct Logger {
    meta: MetadataServiceClient<Channel>,
    spool: Option<Arc<Spool>>,
    cache: RwLock<HashMap<String, Cached>>,
    refreshing: Mutex<HashSet<String>>,
    timing: Timing,
    /// The region partitioned keys name.
    region: String,
    /// Shutting down: every batch is due now.
    draining: AtomicBool,
}

/// The delivery's cursor in the spool.
const CURSOR: &str = "delivery";

impl Logger {
    /// A logger spooling to `spool`. Without one, records are dropped (and
    /// counted), and `PutBucketLogging` is refused on this gateway.
    #[must_use]
    pub fn new(
        meta: MetadataServiceClient<Channel>,
        spool: Option<Arc<Spool>>,
        timing: Timing,
        region: String,
    ) -> Arc<Self> {
        if let Some(s) = &spool {
            // Pin the cursor now, so what is recorded before the delivery
            // starts is delivered.
            s.cursor(CURSOR);
        } else {
            warn!(
                "bucket logging: no spool (--bucket-log-spool or --audit-spool); \
                 this gateway refuses PutBucketLogging and drops records"
            );
        }
        Arc::new(Self {
            meta,
            spool,
            cache: RwLock::new(HashMap::new()),
            refreshing: Mutex::new(HashSet::new()),
            timing,
            region,
            draining: AtomicBool::new(false),
        })
    }

    async fn fetch(
        meta: &MetadataServiceClient<Channel>,
        bucket: &str,
    ) -> Result<Option<Arc<Config>>, tonic::Status> {
        match meta
            .clone()
            .get_bucket_setting(GetBucketSettingRequest {
                bucket: bucket.to_string(),
                name: SETTING.to_string(),
            })
            .await
        {
            Ok(r) => {
                let r = r.into_inner();
                Ok(r.found
                    .then(|| serde_json::from_slice::<Config>(&r.value).ok())
                    .flatten()
                    .map(Arc::new))
            }
            Err(e) if e.code() == tonic::Code::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// `bucket`'s configuration, `None` when it isn't logged. A cached one
    /// past its time is used while it is read again in the background; one
    /// never read is read now (once per bucket per gateway).
    pub async fn config(self: &Arc<Self>, bucket: &str) -> Option<Arc<Config>> {
        let stale = {
            let cache = self.cache.read();
            match cache.get(bucket) {
                Some(c) if c.fetched.elapsed() < CACHE_TTL => return c.config.clone(),
                Some(c) => Some(c.config.clone()),
                None => None,
            }
        };
        if let Some(config) = stale {
            if self.refreshing.lock().insert(bucket.to_string()) {
                let this = Arc::clone(self);
                let bucket = bucket.to_string();
                tokio::spawn(async move {
                    if let Ok(c) = Self::fetch(&this.meta, &bucket).await {
                        this.set_cached(&bucket, c);
                    }
                    this.refreshing.lock().remove(&bucket);
                });
            }
            return config;
        }
        match tokio::time::timeout(Duration::from_secs(5), Self::fetch(&self.meta, bucket)).await {
            Ok(Ok(c)) => {
                self.set_cached(bucket, c.clone());
                c
            }
            Ok(Err(e)) => {
                warn!("bucket logging: cannot read {bucket}'s configuration: {e}");
                DROPPED.inc(&reason("lookup-failed"));
                None
            }
            Err(_) => {
                warn!("bucket logging: reading {bucket}'s configuration timed out");
                DROPPED.inc(&reason("lookup-failed"));
                None
            }
        }
    }

    fn set_cached(&self, bucket: &str, config: Option<Arc<Config>>) {
        let mut cache = self.cache.write();
        // Bounded: past this many buckets, start over (each is read again
        // on its next request).
        if cache.len() >= MAX_CACHED && !cache.contains_key(bucket) {
            cache.clear();
        }
        cache.insert(
            bucket.to_string(),
            Cached {
                config,
                fetched: Instant::now(),
            },
        );
    }

    /// Spool one record. Never waits on anything but the local write.
    pub fn append(&self, record: &Record) {
        let Some(spool) = &self.spool else {
            DROPPED.inc(&reason("no-spool"));
            return;
        };
        let ok = serde_json::to_vec(record).is_ok_and(|line| spool.append(&line));
        if !ok {
            DROPPED.inc(&reason("spool-full"));
        }
    }

    /// On the way out: every batch is written now; wait up to `within` for
    /// the spool to be delivered (what isn't stays in it for the next
    /// start).
    pub async fn drain(&self, within: Duration) {
        let Some(spool) = &self.spool else {
            return;
        };
        self.draining.store(true, Ordering::Relaxed);
        spool.sync();
        let end = *spool.durable().borrow();
        let deadline = Instant::now() + within;
        while !spool.caught_up(end) {
            if Instant::now() > deadline {
                warn!(
                    "bucket logging: shutting down with {} bytes not yet delivered (kept in the spool)",
                    spool.bytes()
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

// ── The API ─────────────────────────────────────────────────────────────

fn ok_xml(xml: String, modified: Option<i64>) -> Response {
    let mut r = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/xml");
    if let Some(at) = modified.and_then(|m| chrono::DateTime::from_timestamp(m, 0)) {
        r = r.header(
            "Last-Modified",
            at.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        );
    }
    r.body(Body::from(xml)).unwrap_or_default()
}

/// `GET /{bucket}?logging`
pub async fn get_config(state: &AppState, bucket: &str) -> Response {
    if let Err(r) = crate::s3::bucket_owner(state, bucket).await {
        return r;
    }
    match Logger::fetch(&state.meta_client, bucket).await {
        Ok(c) => ok_xml(render(c.as_deref()), c.map(|c| c.modified)),
        Err(e) => crate::s3::meta_failure(&e, "bucket logging configuration"),
    }
}

/// `PUT /{bucket}?logging`: set the configuration, or with an empty
/// `BucketLoggingStatus` remove it.
pub async fn put_config(
    state: &AppState,
    bucket: &str,
    auth: Option<&AuthResult>,
    body: &[u8],
) -> Response {
    let source = match state
        .meta_client
        .clone()
        .get_bucket(GetBucketRequest {
            name: bucket.to_string(),
        })
        .await
    {
        Ok(r) => r.into_inner().bucket.unwrap_or_default(),
        Err(e) if e.code() == tonic::Code::NotFound => {
            return S3Error::xml_response(
                "NoSuchBucket",
                "The specified bucket does not exist",
                StatusCode::NOT_FOUND,
            );
        }
        Err(e) => return S3Error::from_status(&e),
    };
    // Only the bucket's owner, as in S3 (a policy can't hand it to anyone
    // else): it decides where the bucket's access records go.
    if let Some(a) = auth
        && a.user_arn != crate::admin::SYSTEM_ADMIN_USER_ARN
        && a.user_id != source.owner
    {
        return S3Error::xml_response(
            "AccessDenied",
            "Only the bucket owner can configure its logging",
            StatusCode::FORBIDDEN,
        );
    }
    let wanted = match parse(body) {
        Ok(w) => w,
        Err(r) => return r,
    };
    let logger = state.auditor.bucket_logging();
    let Some(wanted) = wanted else {
        return store(state, logger, bucket, None).await;
    };
    if logger.is_none_or(|l| l.spool.is_none()) {
        return S3Error::xml_response(
            "InvalidRequest",
            "Bucket logging is off on this gateway: it has no spool to keep records in",
            StatusCode::BAD_REQUEST,
        );
    }
    if wanted.target_bucket == bucket {
        return invalid("A bucket can't be its own logging target");
    }
    match check_target(
        &state.meta_client,
        &wanted.target_bucket,
        &wanted.target_prefix,
        bucket,
        &source.owner,
        &source.tenant,
    )
    .await
    {
        Ok(()) => {}
        Err(Refusal::NoTarget) => {
            return S3Error::xml_response(
                "InvalidTargetBucketForLogging",
                "The target bucket for logging does not exist",
                StatusCode::BAD_REQUEST,
            );
        }
        Err(Refusal::OtherTenant) => {
            return S3Error::xml_response(
                "InvalidTargetBucketForLogging",
                "The target bucket for logging must be in the source bucket's tenant",
                StatusCode::BAD_REQUEST,
            );
        }
        Err(Refusal::Denied) => {
            return S3Error::xml_response(
                "AccessDenied",
                &format!(
                    "Logging bucket {}'s policy does not allow {SERVICE} to put objects under {:?} for {bucket}",
                    wanted.target_bucket, wanted.target_prefix
                ),
                StatusCode::FORBIDDEN,
            );
        }
        Err(Refusal::Unavailable(e)) => return S3Error::from_status(&e),
    }
    // A target that logs itself would make chains (and, logging into its
    // own source, records about records).
    match Logger::fetch(&state.meta_client, &wanted.target_bucket).await {
        Ok(Some(_)) => return invalid("The target bucket has logging enabled itself"),
        Ok(None) => {}
        Err(e) => return S3Error::from_status(&e),
    }
    let mut config = Config {
        target_bucket: wanted.target_bucket,
        target_prefix: wanted.target_prefix,
        key_format: wanted.key_format,
        source_owner: source.owner,
        source_tenant: source.tenant,
        modified: chrono::Utc::now().timestamp(),
    };
    // The same configuration set again keeps its time.
    if let Ok(Some(old)) = Logger::fetch(&state.meta_client, bucket).await
        && old.same(&config)
    {
        config.modified = old.modified;
    }
    store(state, logger, bucket, Some(config)).await
}

async fn store(
    state: &AppState,
    logger: Option<&Arc<Logger>>,
    bucket: &str,
    config: Option<Config>,
) -> Response {
    let result = state
        .meta_client
        .clone()
        .put_bucket_setting(PutBucketSettingRequest {
            bucket: bucket.to_string(),
            name: SETTING.to_string(),
            value: config
                .as_ref()
                .map(|c| serde_json::to_vec(c).unwrap_or_default())
                .unwrap_or_default(),
            delete: config.is_none(),
        })
        .await;
    match result {
        Ok(_) => {
            if let Some(l) = logger {
                l.set_cached(bucket, config.map(Arc::new));
            }
            StatusCode::OK.into_response()
        }
        Err(e) => crate::s3::meta_failure(&e, "bucket logging configuration"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_status_parses_to_what_it_asks_for() {
        let simple = br#"<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
            <LoggingEnabled><TargetBucket>logs</TargetBucket><TargetPrefix>log/</TargetPrefix>
            <TargetGrants><Grant><Grantee><ID>x</ID></Grantee><Permission>READ</Permission></Grant></TargetGrants>
            </LoggingEnabled></BucketLoggingStatus>"#;
        assert_eq!(
            parse(simple).unwrap(),
            Some(Wanted {
                target_bucket: "logs".into(),
                target_prefix: "log/".into(),
                key_format: KeyFormat::Simple,
            })
        );
        let partitioned = br"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket>
            <TargetPrefix></TargetPrefix><TargetObjectKeyFormat><PartitionedPrefix>
            <PartitionDateSource>EventTime</PartitionDateSource></PartitionedPrefix>
            </TargetObjectKeyFormat></LoggingEnabled></BucketLoggingStatus>";
        assert_eq!(
            parse(partitioned).unwrap().unwrap().key_format,
            KeyFormat::Partitioned { event_time: true }
        );
        let simple_format = br"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logs</TargetBucket>
            <TargetPrefix>p</TargetPrefix><TargetObjectKeyFormat><SimplePrefix/></TargetObjectKeyFormat>
            </LoggingEnabled></BucketLoggingStatus>";
        assert_eq!(
            parse(simple_format).unwrap().unwrap().key_format,
            KeyFormat::Simple
        );
        let off = br#"<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>"#;
        assert_eq!(parse(off).unwrap(), None);
    }

    #[test]
    fn a_bad_status_is_refused() {
        let status = |r: Response| r.status();
        let no_target = br"<BucketLoggingStatus><LoggingEnabled><TargetPrefix>p</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
        assert_eq!(
            status(parse(no_target).unwrap_err()),
            StatusCode::BAD_REQUEST
        );
        let bad_source = br"<BucketLoggingStatus><LoggingEnabled><TargetBucket>l</TargetBucket>
            <TargetObjectKeyFormat><PartitionedPrefix><PartitionDateSource>kaboom</PartitionDateSource>
            </PartitionedPrefix></TargetObjectKeyFormat></LoggingEnabled></BucketLoggingStatus>";
        assert_eq!(
            status(parse(bad_source).unwrap_err()),
            StatusCode::BAD_REQUEST
        );
        let long = format!(
            "<BucketLoggingStatus><LoggingEnabled><TargetBucket>l</TargetBucket><TargetPrefix>{}</TargetPrefix></LoggingEnabled></BucketLoggingStatus>",
            "p".repeat(MAX_PREFIX + 1)
        );
        assert_eq!(
            status(parse(long.as_bytes()).unwrap_err()),
            StatusCode::BAD_REQUEST
        );
        assert!(parse(b"not xml").is_err());
    }

    #[test]
    fn a_configuration_reads_back_as_it_was_set() {
        let c = Config {
            target_bucket: "logs".into(),
            target_prefix: "a&b/".into(),
            key_format: KeyFormat::Partitioned { event_time: false },
            source_owner: "o".into(),
            source_tenant: "t".into(),
            modified: 0,
        };
        let xml = render(Some(&c));
        let back = parse(xml.as_bytes()).unwrap().unwrap();
        assert_eq!(back.target_bucket, "logs");
        assert_eq!(back.target_prefix, "a&b/");
        assert_eq!(back.key_format, c.key_format);
        assert_eq!(parse(render(None).as_bytes()).unwrap(), None);
    }

    fn policy(json: serde_json::Value) -> BucketPolicy {
        BucketPolicy::from_json(&json.to_string()).unwrap()
    }

    fn statement(
        principal: serde_json::Value,
        action: &str,
        resource: &str,
        source_arn: &str,
        account: &str,
    ) -> serde_json::Value {
        serde_json::json!({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Principal": principal,
            "Action": [action],
            "Resource": resource,
            "Condition": {
                "ArnLike": {"aws:SourceArn": source_arn},
                "StringEquals": {"aws:SourceAccount": account}
            }
        }]})
    }

    /// S3's rule: the target's policy names the logging service, PutObject,
    /// the prefix, the source bucket and its owner. Anything else is a
    /// refusal.
    #[test]
    fn only_a_policy_naming_the_service_source_and_prefix_lets_logs_in() {
        let svc = serde_json::json!({"Service": SERVICE});
        let ok = |p: &BucketPolicy| policy_allows(Some(p), "logs", "log/", "src", "owner");
        assert!(ok(&policy(statement(
            svc.clone(),
            "s3:PutObject",
            "arn:aws:s3:::logs/log/",
            "arn:aws:s3:::src",
            "owner"
        ))));
        assert!(ok(&policy(statement(
            svc.clone(),
            "s3:PutObject",
            "arn:aws:s3:::logs/*",
            "arn:aws:s3:::*",
            "owner"
        ))));
        assert!(!policy_allows(None, "logs", "log/", "src", "owner"));
        for p in [
            statement(
                serde_json::json!({"AWS": "*"}),
                "s3:PutObject",
                "arn:aws:s3:::logs/log/",
                "arn:aws:s3:::src",
                "owner",
            ),
            statement(
                serde_json::json!({"Service": "other.amazonaws.com"}),
                "s3:PutObject",
                "arn:aws:s3:::logs/log/",
                "arn:aws:s3:::src",
                "owner",
            ),
            statement(
                svc.clone(),
                "s3:GetObject",
                "arn:aws:s3:::logs/log/",
                "arn:aws:s3:::src",
                "owner",
            ),
            statement(
                svc.clone(),
                "s3:PutObject",
                "arn:aws:s3:::logs/kaboom",
                "arn:aws:s3:::src",
                "owner",
            ),
            statement(
                svc.clone(),
                "s3:PutObject",
                "arn:aws:s3:::logs/log/",
                "arn:aws:s3:::kaboom",
                "owner",
            ),
            statement(
                svc,
                "s3:PutObject",
                "arn:aws:s3:::logs/log/",
                "arn:aws:s3:::src",
                "kaboom",
            ),
        ] {
            assert!(!ok(&policy(p.clone())), "{p}");
        }
    }
}
