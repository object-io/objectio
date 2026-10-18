//! One access-log record: what a request on a logged bucket leaves behind,
//! as a line of AWS's server access log format (26 space-separated fields,
//! <https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html>).
//!
//! A request is captured before it runs ([`Captured::of`]: what the client
//! sent), resolved once the handler has answered ([`Captured::resolve`]:
//! whether its bucket is logged, the status, the version), and finished when
//! the response body has gone out ([`Pending::finish`]: bytes sent, total
//! time), which is when the record is spooled.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::http::{HeaderMap, Method};
use axum::response::Response;
use serde::{Deserialize, Serialize};

use super::{Config, KeyFormat, Logger};

/// A record as the spool holds it: the line, and where it goes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Target bucket.
    pub tb: String,
    /// Target prefix.
    pub tp: String,
    pub kf: KeyFormat,
    /// Source bucket, its owner and its tenant: what the target's consent
    /// is checked against when the record is delivered.
    pub sb: String,
    pub so: String,
    pub st: String,
    /// When the request arrived (Unix seconds): a partition's date when
    /// partitioned by event time.
    pub at: i64,
    pub line: String,
}

/// What is known of a request before it runs.
pub struct Captured {
    received: chrono::DateTime<chrono::Utc>,
    method: Method,
    bucket: String,
    key: Option<String>,
    query: String,
    uri: String,
    host: String,
    referer: String,
    user_agent: String,
    remote_ip: Option<IpAddr>,
    copy: bool,
    /// A copy's source bucket, key and version (`x-amz-copy-source`): its
    /// bucket, when logged, gets a `REST.COPY.OBJECT_GET` record, as in S3.
    copy_source: Option<(String, String, String)>,
    auth_type: &'static str,
    sig_version: &'static str,
    request_size: Option<u64>,
}

/// The bucket and key a path names (decoded), or `None` for a path that
/// names no bucket (`/`, the gateway's own `/_…` endpoints).
fn bucket_and_key(path: &str) -> Option<(String, Option<String>)> {
    let trimmed = path.trim_start_matches('/');
    let (bucket, key) = trimmed.split_once('/').unwrap_or((trimmed, ""));
    if bucket.is_empty() || bucket.starts_with('_') {
        return None;
    }
    let decode =
        |s: &str| urlencoding::decode(s).map_or_else(|_| s.to_string(), |d| d.into_owned());
    Some((decode(bucket), (!key.is_empty()).then(|| decode(key))))
}

fn has(query: &str, name: &str) -> bool {
    query
        .split('&')
        .any(|pair| pair.split('=').next().unwrap_or_default() == name)
}

/// How the request was signed: (`AuthType`, `SignatureVersion`).
fn auth_of(headers: &HeaderMap, query: &str) -> (&'static str, &'static str) {
    if let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        return if auth.starts_with("AWS4-") {
            ("AuthHeader", "SigV4")
        } else if auth.starts_with("AWS ") {
            ("AuthHeader", "SigV2")
        } else {
            ("AuthHeader", "-")
        };
    }
    let lower = query.to_ascii_lowercase();
    if has(&lower, "x-amz-signature") {
        ("QueryString", "SigV4")
    } else if has(&lower, "signature") {
        ("QueryString", "SigV2")
    } else {
        ("-", "-")
    }
}

/// The operation, as AWS's access log names it: `REST.PUT.OBJECT`,
/// `REST.GET.BUCKET`, `REST.COPY.OBJECT`, `REST.POST.UPLOADS`, ...
pub fn operation(method: &Method, object: bool, query: &str, copy: bool) -> String {
    let m = method.as_str();
    let resource = if object {
        match *method {
            Method::PUT if has(query, "uploadId") => {
                return if copy {
                    "REST.COPY.PART".into()
                } else {
                    "REST.PUT.PART".into()
                };
            }
            Method::PUT if copy && !has(query, "tagging") && !has(query, "acl") => {
                return "REST.COPY.OBJECT".into();
            }
            Method::POST if has(query, "uploads") => "UPLOADS",
            Method::POST | Method::GET | Method::DELETE if has(query, "uploadId") => "UPLOAD",
            Method::POST if has(query, "restore") => "RESTORE",
            _ if has(query, "tagging") => "OBJECT_TAGGING",
            _ if has(query, "acl") => "ACL",
            _ if has(query, "retention") => "RETENTION",
            _ if has(query, "legal-hold") => "LEGAL_HOLD",
            _ if has(query, "attributes") => "OBJECT_ATTRIBUTES",
            _ => "OBJECT",
        }
    } else {
        const SUBRESOURCES: [(&str, &str); 20] = [
            ("delete", "MULTI_OBJECT_DELETE"),
            ("logging", "LOGGING_STATUS"),
            ("policyStatus", "BUCKETPOLICYSTATUS"),
            ("policy", "BUCKETPOLICY"),
            ("versioning", "VERSIONING"),
            ("versions", "BUCKETVERSIONS"),
            ("uploads", "UPLOADS"),
            ("lifecycle", "LIFECYCLE"),
            ("cors", "CORS"),
            ("tagging", "TAGGING"),
            ("encryption", "ENCRYPTION"),
            ("acl", "ACL"),
            ("location", "LOCATION"),
            ("object-lock", "OBJECT_LOCK_CONFIGURATION"),
            ("publicAccessBlock", "PUBLIC_ACCESS_BLOCK"),
            ("ownershipControls", "OWNERSHIP_CONTROLS"),
            ("replication", "REPLICATION"),
            ("notification", "NOTIFICATION"),
            ("website", "WEBSITE"),
            ("requestPayment", "REQUEST_PAYMENT"),
        ];
        SUBRESOURCES
            .iter()
            .find(|(name, _)| has(query, name))
            .map_or("BUCKET", |(_, op)| op)
    };
    format!("REST.{m}.{resource}")
}

/// An unquoted field: `-` when empty, and nothing in it that would split it
/// or be read as a quote or a bracket.
fn token(s: &str) -> String {
    if s.is_empty() {
        return "-".into();
    }
    escape(s, true)
}

/// A quoted field (`"GET /b/k HTTP/1.1"`): `"-"` when empty.
fn quoted(s: &str) -> String {
    if s.is_empty() {
        return "\"-\"".into();
    }
    format!("\"{}\"", escape(s, false))
}

fn escape(s: &str, spaces: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ' ' if spaces => out.push_str("%20"),
            '"' => out.push_str("%22"),
            '[' => out.push_str("%5B"),
            ']' => out.push_str("%5D"),
            '\\' => out.push_str("%5C"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// A key as the log shows it: URL-encoded, its slashes kept.
fn log_key(key: &str) -> String {
    urlencoding::encode(key).replace("%2F", "/")
}

fn number(n: Option<u64>) -> String {
    match n {
        Some(n) if n > 0 => n.to_string(),
        _ => "-".into(),
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
}

/// `x-amz-copy-source` (`[/]bucket/key[?versionId=v]`, URL-encoded) as
/// bucket, key and version.
fn copy_source(header: &str) -> Option<(String, String, String)> {
    if header.is_empty() {
        return None;
    }
    let (path, version) = header
        .split_once("?versionId=")
        .map_or((header, ""), |(p, v)| (p, v));
    let path = urlencoding::decode(path).map_or_else(|_| path.to_string(), |d| d.into_owned());
    let (bucket, key) = path.trim_start_matches('/').split_once('/')?;
    Some((bucket.to_string(), key.to_string(), version.to_string()))
}

impl Captured {
    /// Capture `request` (its query already stripped of credentials), when
    /// it names a bucket.
    pub fn of(request: &Request, redacted_query: &str, remote_ip: Option<IpAddr>) -> Option<Self> {
        let (bucket, key) = bucket_and_key(request.uri().path())?;
        let headers = request.headers();
        let raw_query = request.uri().query().unwrap_or_default();
        let (auth_type, sig_version) = auth_of(headers, raw_query);
        let path = request.uri().path();
        let uri = if redacted_query.is_empty() {
            format!("{} {path} {:?}", request.method(), request.version())
        } else {
            format!(
                "{} {path}?{redacted_query} {:?}",
                request.method(),
                request.version()
            )
        };
        let size = header(headers, "x-amz-decoded-content-length")
            .parse()
            .ok()
            .or_else(|| header(headers, "content-length").parse().ok());
        Some(Self {
            received: chrono::Utc::now(),
            method: request.method().clone(),
            bucket,
            key,
            query: raw_query.to_string(),
            uri,
            host: header(headers, "host").to_string(),
            referer: header(headers, "referer").to_string(),
            user_agent: header(headers, "user-agent").to_string(),
            remote_ip,
            copy: headers.contains_key("x-amz-copy-source"),
            copy_source: copy_source(header(headers, "x-amz-copy-source")),
            auth_type,
            sig_version,
            request_size: size,
        })
    }

    /// The bucket the request names.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    /// Once the handler has answered: the record, if the bucket is logged.
    /// `bucket_tenant` is the tenant authorization found the bucket in
    /// (when it looked): a record is never written for a bucket that is no
    /// longer the one the configuration was made for.
    #[allow(clippy::too_many_arguments)]
    pub async fn resolve(
        self,
        logger: &Arc<Logger>,
        requester: &str,
        anonymous: bool,
        bucket_tenant: Option<&str>,
        deleted: Vec<(String, Option<String>)>,
        answer: Answer,
        request_id: &str,
        turnaround: Duration,
    ) -> Option<Pending> {
        // No bucket, nothing to log it into (and no lookup for every name
        // a client makes up).
        if answer.error_code == "NoSuchBucket" {
            return None;
        }
        let config = logger
            .config(&self.bucket)
            .await
            .filter(|c| bucket_tenant.is_none_or(|t| t == c.source_tenant));
        let source = match &self.copy_source {
            Some((bucket, _, _)) => logger.config(bucket).await,
            None => None,
        };
        if config.is_none() && source.is_none() {
            return None;
        }
        let Answer {
            status,
            error_code,
            version,
            content_range,
            content_length,
        } = answer;
        let version = if version.is_empty() {
            self.query
                .split('&')
                .find_map(|p| p.strip_prefix("versionId="))
                .map(|v| urlencoding::decode(v).map_or_else(|_| v.to_string(), |d| d.into_owned()))
                .unwrap_or_default()
        } else {
            version
        };
        let object = self.key.is_some();
        let object_size = match self.method {
            Method::GET | Method::HEAD if object && status < 300 => content_range
                .rsplit_once('/')
                .and_then(|(_, total)| total.parse().ok())
                .or_else(|| content_length.parse().ok()),
            Method::PUT | Method::POST if object && status < 300 => self.request_size,
            _ => None,
        };
        let operation = operation(&self.method, object, &self.query, self.copy);
        let (auth_type, sig_version) = if anonymous {
            ("-", "-")
        } else {
            (self.auth_type, self.sig_version)
        };
        let fields = Fields {
            owner: String::new(),
            bucket: self.bucket,
            time: self.received.format("%d/%b/%Y:%H:%M:%S %z").to_string(),
            remote_ip: self.remote_ip.map(|ip| ip.to_string()).unwrap_or_default(),
            requester: if anonymous {
                String::new()
            } else {
                requester.to_string()
            },
            request_id: request_id.to_string(),
            operation,
            key: self.key.unwrap_or_default(),
            uri: self.uri,
            status,
            error_code,
            object_size,
            turnaround_ms: u64::try_from(turnaround.as_millis()).unwrap_or(u64::MAX),
            referer: self.referer,
            user_agent: self.user_agent,
            version,
            sig_version,
            auth_type,
            host: self.host,
        };
        let mut lines = Vec::with_capacity(1);
        if let (Some(config), Some((bucket, key, version))) = (source, self.copy_source) {
            let mut f = fields.clone();
            f.owner.clone_from(&config.source_owner);
            f.bucket = bucket;
            f.key = key;
            f.version = version;
            f.object_size = None;
            f.operation = if f.operation == "REST.COPY.PART" {
                "REST.COPY.PART_GET".into()
            } else {
                "REST.COPY.OBJECT_GET".into()
            };
            lines.push(Line {
                config,
                fields: f,
                sent: false,
            });
        }
        let deleted = if let Some(config) = config {
            let mut f = fields;
            f.owner.clone_from(&config.source_owner);
            lines.insert(
                0,
                Line {
                    config,
                    fields: f,
                    sent: true,
                },
            );
            deleted
        } else {
            Vec::new()
        };
        Some(Pending {
            logger: Arc::clone(logger),
            at: self.received.timestamp(),
            lines,
            deleted,
        })
    }
}

/// One line of a request's, and the bucket it is for.
struct Line {
    config: Arc<Config>,
    fields: Fields,
    /// The request's own line (the bytes it sent are its).
    sent: bool,
}

/// What the handler answered, as far as the log line goes.
pub struct Answer {
    status: u16,
    error_code: String,
    version: String,
    content_range: String,
    content_length: String,
}

impl Answer {
    #[must_use]
    pub fn of(response: &Response) -> Self {
        let headers = response.headers();
        Self {
            status: response.status().as_u16(),
            error_code: response
                .extensions()
                .get::<crate::gateway_metrics::S3ErrorCode>()
                .map(|c| c.0.clone())
                .unwrap_or_default(),
            version: header(headers, "x-amz-version-id").to_string(),
            content_range: header(headers, "content-range").to_string(),
            content_length: header(headers, "content-length").to_string(),
        }
    }
}

/// The fields of one line.
#[derive(Debug, Clone, Default)]
pub struct Fields {
    pub owner: String,
    pub bucket: String,
    /// `06/Feb/2019:00:00:38 +0000`
    pub time: String,
    pub remote_ip: String,
    pub requester: String,
    pub request_id: String,
    pub operation: String,
    pub key: String,
    pub uri: String,
    pub status: u16,
    pub error_code: String,
    pub object_size: Option<u64>,
    pub turnaround_ms: u64,
    pub referer: String,
    pub user_agent: String,
    pub version: String,
    pub sig_version: &'static str,
    pub auth_type: &'static str,
    pub host: String,
}

impl Fields {
    /// The line, with what is only known at the end: bytes sent and total
    /// time.
    pub fn line(&self, bytes_sent: u64, total_ms: u64) -> String {
        let key = if self.key.is_empty() {
            "-".to_string()
        } else {
            token(&log_key(&self.key))
        };
        [
            token(&self.owner),
            token(&self.bucket),
            format!("[{}]", self.time),
            token(&self.remote_ip),
            token(&self.requester),
            token(&self.request_id),
            token(&self.operation),
            key,
            quoted(&self.uri),
            self.status.to_string(),
            token(&self.error_code),
            number(Some(bytes_sent)),
            number(self.object_size),
            total_ms.to_string(),
            self.turnaround_ms.to_string(),
            quoted(&self.referer),
            quoted(&self.user_agent),
            token(&self.version),
            // Host Id, cipher suite: not recorded.
            "-".to_string(),
            token(self.sig_version),
            "-".to_string(),
            token(self.auth_type),
            token(&self.host),
            // TLS version, access point ARN: none; ACLs are never what
            // grants access (BucketOwnerEnforced), so "ACL required" is "-".
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
        ]
        .join(" ")
    }
}

/// A record waiting for its response body to finish.
pub struct Pending {
    logger: Arc<Logger>,
    at: i64,
    /// The request's line first (when its bucket is logged), then a copy's
    /// source's.
    lines: Vec<Line>,
    /// A batch delete's keys: each also gets a `BATCH.DELETE.OBJECT` line,
    /// as in S3.
    deleted: Vec<(String, Option<String>)>,
}

impl Pending {
    /// The response is over: spool the records (and a batch delete's
    /// per-key records).
    pub fn finish(self, bytes_sent: u64, total: Duration) {
        let total_ms = u64::try_from(total.as_millis()).unwrap_or(u64::MAX);
        let record = |c: &Config, f: &Fields, line: String| Record {
            tb: c.target_bucket.clone(),
            tp: c.target_prefix.clone(),
            kf: c.key_format.clone(),
            sb: f.bucket.clone(),
            so: c.source_owner.clone(),
            st: c.source_tenant.clone(),
            at: self.at,
            line,
        };
        for l in &self.lines {
            let sent = if l.sent { bytes_sent } else { 0 };
            self.logger
                .append(&record(&l.config, &l.fields, l.fields.line(sent, total_ms)));
        }
        let Some(main) = self.lines.first().filter(|l| l.sent) else {
            return;
        };
        for (key, version) in &self.deleted {
            let mut f = main.fields.clone();
            f.operation = "BATCH.DELETE.OBJECT".into();
            f.key.clone_from(key);
            f.version = version.clone().unwrap_or_default();
            f.object_size = None;
            f.error_code.clear();
            f.status = 204;
            self.logger
                .append(&record(&main.config, &f, f.line(0, total_ms)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parse ceph's s3-tests does of a line: brackets read as quotes,
    /// then split shell-style.
    fn split(line: &str) -> Vec<String> {
        let line = line.replace(['[', ']'], "\"");
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut quoted = false;
        let mut any = false;
        for c in line.chars() {
            match c {
                '"' => {
                    quoted = !quoted;
                    any = true;
                }
                ' ' if !quoted => {
                    if any {
                        out.push(std::mem::take(&mut cur));
                        any = false;
                    }
                }
                c => {
                    cur.push(c);
                    any = true;
                }
            }
        }
        if any {
            out.push(cur);
        }
        out
    }

    fn fields() -> Fields {
        Fields {
            owner: "owner-id".into(),
            bucket: "src".into(),
            time: "05/Oct/2026:10:00:00 +0000".into(),
            remote_ip: "10.0.0.1".into(),
            requester: "arn:obio:iam::t:user/alice".into(),
            request_id: "ABC123".into(),
            operation: "REST.PUT.OBJECT".into(),
            key: "dir/a key \"quoted\" [x].txt".into(),
            uri: "PUT /src/dir/a%20key HTTP/1.1".into(),
            status: 200,
            error_code: String::new(),
            object_size: Some(42),
            turnaround_ms: 3,
            referer: String::new(),
            user_agent: "Boto3/1.35 \"odd\" agent [x]".into(),
            version: String::new(),
            sig_version: "SigV4",
            auth_type: "AuthHeader",
            host: "localhost:9000".into(),
        }
    }

    /// A line is 26 fields however odd the key or user agent, in AWS's
    /// order, with `-` for what is empty.
    #[test]
    fn a_line_has_the_26_fields_of_the_aws_format() {
        let line = fields().line(0, 7);
        let f = split(&line);
        assert_eq!(f.len(), 26, "{line}");
        assert_eq!(f[0], "owner-id");
        assert_eq!(f[1], "src");
        assert_eq!(f[2], "05/Oct/2026:10:00:00 +0000");
        assert_eq!(f[4], "arn:obio:iam::t:user/alice");
        assert_eq!(f[5], "ABC123");
        assert_eq!(f[6], "REST.PUT.OBJECT");
        assert_eq!(f[7], "dir/a%20key%20%22quoted%22%20%5Bx%5D.txt");
        assert_eq!(f[8], "PUT /src/dir/a%20key HTTP/1.1");
        assert_eq!(f[9], "200");
        assert_eq!(f[10], "-");
        assert_eq!(f[11], "-", "nothing sent");
        assert_eq!(f[12], "42");
        assert_eq!(f[13], "7");
        assert_eq!(f[14], "3");
        assert_eq!(f[15], "-");
        assert_eq!(f[17], "-", "no version");
        assert_eq!(f[19], "SigV4");
        assert_eq!(f[21], "AuthHeader");
        assert_eq!(f[22], "localhost:9000");
        assert_eq!(f[25], "-");
    }

    #[test]
    fn operations_are_named_as_s3_names_them() {
        let op = |m: Method, object: bool, q: &str, copy: bool| operation(&m, object, q, copy);
        assert_eq!(op(Method::PUT, true, "", false), "REST.PUT.OBJECT");
        assert_eq!(op(Method::PUT, true, "", true), "REST.COPY.OBJECT");
        assert_eq!(
            op(Method::PUT, true, "partNumber=1&uploadId=u", false),
            "REST.PUT.PART"
        );
        assert_eq!(
            op(Method::PUT, true, "partNumber=1&uploadId=u", true),
            "REST.COPY.PART"
        );
        assert_eq!(
            op(Method::POST, true, "uploads", false),
            "REST.POST.UPLOADS"
        );
        assert_eq!(
            op(Method::POST, true, "uploadId=u", false),
            "REST.POST.UPLOAD"
        );
        assert_eq!(
            op(Method::DELETE, true, "uploadId=u", false),
            "REST.DELETE.UPLOAD"
        );
        assert_eq!(op(Method::GET, true, "", false), "REST.GET.OBJECT");
        assert_eq!(op(Method::HEAD, true, "", false), "REST.HEAD.OBJECT");
        assert_eq!(
            op(Method::DELETE, true, "versionId=v", false),
            "REST.DELETE.OBJECT"
        );
        assert_eq!(
            op(Method::PUT, true, "tagging", false),
            "REST.PUT.OBJECT_TAGGING"
        );
        assert_eq!(
            op(Method::PUT, true, "legal-hold", false),
            "REST.PUT.LEGAL_HOLD"
        );
        assert_eq!(
            op(Method::GET, false, "list-type=2", false),
            "REST.GET.BUCKET"
        );
        assert_eq!(
            op(Method::PUT, false, "logging", false),
            "REST.PUT.LOGGING_STATUS"
        );
        assert_eq!(
            op(Method::POST, false, "delete", false),
            "REST.POST.MULTI_OBJECT_DELETE"
        );
        assert_eq!(
            op(Method::GET, false, "versions", false),
            "REST.GET.BUCKETVERSIONS"
        );
        assert_eq!(
            op(Method::GET, false, "policy", false),
            "REST.GET.BUCKETPOLICY"
        );
        assert_eq!(op(Method::HEAD, false, "", false), "REST.HEAD.BUCKET");
    }

    #[test]
    fn the_signature_says_how_a_request_authenticated() {
        let mut h = HeaderMap::new();
        assert_eq!(auth_of(&h, ""), ("-", "-"));
        assert_eq!(
            auth_of(&h, "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=abc"),
            ("QueryString", "SigV4")
        );
        assert_eq!(
            auth_of(&h, "AWSAccessKeyId=a&Signature=s&Expires=1"),
            ("QueryString", "SigV2")
        );
        h.insert(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=x".parse().unwrap(),
        );
        assert_eq!(auth_of(&h, ""), ("AuthHeader", "SigV4"));
    }

    #[test]
    fn a_copy_names_its_source() {
        assert_eq!(copy_source(""), None);
        assert_eq!(
            copy_source("/src/a%20b/c?versionId=v1"),
            Some(("src".into(), "a b/c".into(), "v1".into()))
        );
        assert_eq!(
            copy_source("src/k"),
            Some(("src".into(), "k".into(), String::new()))
        );
    }

    #[test]
    fn only_paths_naming_a_bucket_are_logged() {
        assert_eq!(bucket_and_key("/"), None);
        assert_eq!(bucket_and_key("/_admin/users"), None);
        assert_eq!(bucket_and_key("/b"), Some(("b".into(), None)));
        assert_eq!(bucket_and_key("/b/"), Some(("b".into(), None)));
        assert_eq!(
            bucket_and_key("/b/a%20b/c"),
            Some(("b".into(), Some("a b/c".into())))
        );
    }
}
