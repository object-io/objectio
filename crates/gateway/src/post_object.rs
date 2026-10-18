//! Browser uploads: S3's POST Object, an HTML form posted to `/{bucket}`.
//!
//! A form upload carries no `Authorization` header — its credentials are
//! form fields — so it is taken here, ahead of the SigV4 layer, the way
//! `sts_api::sts_layer` takes STS. What it carries:
//!
//! - **Signed**: `policy` (base64 JSON: an expiration and conditions every
//!   other field must meet), signed with SigV4 (`x-amz-algorithm`,
//!   `x-amz-credential`, `x-amz-date`, `x-amz-signature`, and
//!   `x-amz-security-token` for temporary credentials). The signature is
//!   HMAC-SHA256 of the base64 policy under the credential's signing key.
//! - **Unsigned**: no policy and no signature — an anonymous upload, which
//!   only a bucket policy granting everyone `s3:PutObject` lets in (and
//!   Block Public Access shuts off).
//!
//! Either way the upload is then authorized as `s3:PutObject` on the
//! bucket and key by `authz::authorize` — credential scope, tenant
//! boundary, identity and bucket policies, public access block — and
//! written through `s3::put_object`, the same path a PUT takes, so it gets
//! the bucket's default encryption, object lock defaults, versioning and
//! checksums as a PUT would.
//!
//! The form is read as a stream. Everything before the file (bounded at
//! [`MAX_FIELDS_BYTES`]) is read and checked first — signature, policy,
//! authorization — so nothing is read of a file that won't be accepted; the
//! file is then read up to the smaller of the policy's
//! `content-length-range` maximum and the single-PUT limit, and no further.

// Every refusal here is a finished S3 error response, built once per request.
#![allow(clippy::result_large_err)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::{Path, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use bytes::BytesMut;
use chrono::{DateTime, NaiveDateTime, Utc};
use futures::StreamExt as _;
use objectio_auth::{AuthMode, AuthResult};
use serde::Deserialize;
use tracing::debug;

use crate::auth_middleware::AuthError;
use crate::s3::{AppState, S3Error};

/// The largest file a form may upload: the single-PUT limit (the body
/// limit on the S3 routes in `lib.rs`). Larger objects need multipart.
pub const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;
/// Everything before the file: the fields, their part headers and the
/// boundaries between them.
pub const MAX_FIELDS_BYTES: usize = 64 * 1024;
const MAX_FIELDS: usize = 200;
const MAX_PART_HEADER_BYTES: usize = 8 * 1024;
const MAX_KEY_BYTES: usize = 1024;

/// What the form layer needs.
pub struct PostObjectState {
    pub app: Arc<AppState>,
    /// `false` under `--no-auth`: a signed form is still checked, but an
    /// upload isn't authorized (as nothing else is).
    pub auth_enabled: bool,
}

fn bad_request(code: &str, message: &str) -> Response {
    S3Error::xml_response(code, message, StatusCode::BAD_REQUEST)
}

fn invalid_argument(message: &str) -> Response {
    bad_request("InvalidArgument", message)
}

fn policy_denied(message: &str) -> Response {
    crate::gateway_metrics::record_auth_failure("policy");
    S3Error::xml_response(
        "AccessDenied",
        &format!("Invalid according to Policy: {message}"),
        StatusCode::FORBIDDEN,
    )
}

fn missing_field(name: &str) -> Response {
    invalid_argument(&format!(
        "Bucket POST must contain a field named '{name}'.  If it is specified, please check \
         the order of the fields."
    ))
}

fn too_large() -> Response {
    bad_request(
        "EntityTooLarge",
        "Your proposed upload exceeds the maximum allowed size",
    )
}

// ── Recognising a form upload ───────────────────────────────────────────

/// A form upload: `POST /{bucket}` (no sub-resource) with a
/// `multipart/form-data` body. Its bucket, and its boundary if the
/// content type names one.
fn form_upload(request: &Request) -> Option<(String, Option<String>)> {
    if request.method() != Method::POST || request.uri().query().is_some_and(|q| !q.is_empty()) {
        return None;
    }
    let content_type = request.headers().get(header::CONTENT_TYPE)?.to_str().ok()?;
    let mut params = content_type.split(';');
    if !params
        .next()?
        .trim()
        .eq_ignore_ascii_case("multipart/form-data")
    {
        return None;
    }
    let path = request.uri().path().strip_prefix('/')?;
    let raw = path.strip_suffix('/').unwrap_or(path);
    if raw.is_empty() || raw.contains('/') {
        return None;
    }
    let bucket = urlencoding::decode(raw).ok()?.into_owned();
    let boundary = params.find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("boundary")
            .then(|| v.trim().trim_matches('"').to_string())
    });
    Some((bucket, boundary.filter(|b| (1..=70).contains(&b.len()))))
}

/// Take form uploads ahead of SigV4; anything else goes on untouched.
pub async fn post_object_layer(
    State(state): State<Arc<PostObjectState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some((bucket, boundary)) = form_upload(&request) else {
        return next.run(request).await;
    };
    let Some(boundary) = boundary else {
        return bad_request(
            "MalformedPOSTRequest",
            "The body of your POST request is not well-formed multipart/form-data.",
        );
    };
    match upload(&state, &bucket, &boundary, request).await {
        Ok(r) | Err(r) => r,
    }
}

// ── Reading the form ────────────────────────────────────────────────────

fn malformed_form() -> Response {
    bad_request(
        "MalformedPOSTRequest",
        "The body of your POST request is not well-formed multipart/form-data.",
    )
}

/// Reading a part's content ran past what it may hold.
enum ReadError {
    TooLarge,
    Failed(Response),
}

/// A `multipart/form-data` body, read part by part off the stream.
struct Multipart {
    body: axum::body::BodyDataStream,
    buf: BytesMut,
    /// `\r\n--boundary`: what ends a part's content.
    delimiter: Vec<u8>,
    finder: memchr::memmem::Finder<'static>,
    eof: bool,
}

/// One part's `Content-Disposition`: its field name and file name.
struct PartHeader {
    name: String,
    filename: Option<String>,
}

impl Multipart {
    fn new(body: Body, boundary: &str) -> Self {
        let delimiter = format!("\r\n--{boundary}").into_bytes();
        let finder = memchr::memmem::Finder::new(&delimiter).into_owned();
        // A leading CRLF lets the first boundary, which opens the body
        // without one, be found as any other delimiter.
        let mut buf = BytesMut::with_capacity(16 * 1024);
        buf.extend_from_slice(b"\r\n");
        Self {
            body: body.into_data_stream(),
            buf,
            delimiter,
            finder,
            eof: false,
        }
    }

    /// Append the next chunk. `false` at the end of the body.
    async fn fill(&mut self) -> Result<bool, Response> {
        if self.eof {
            return Ok(false);
        }
        match self.body.next().await {
            Some(Ok(chunk)) => {
                self.buf.extend_from_slice(&chunk);
                Ok(true)
            }
            Some(Err(_)) => Err(bad_request(
                "IncompleteBody",
                "You did not provide the number of bytes specified by the Content-Length \
                 HTTP header",
            )),
            None => {
                self.eof = true;
                Ok(false)
            }
        }
    }

    /// Bytes up to the next delimiter, which is consumed; at most `cap`.
    async fn until_delimiter(&mut self, cap: u64) -> Result<Bytes, ReadError> {
        let mut scanned = 0;
        loop {
            if let Some(at) = self.finder.find(&self.buf[scanned..]) {
                let at = scanned + at;
                if at as u64 > cap {
                    return Err(ReadError::TooLarge);
                }
                let content = self.buf.split_to(at).freeze();
                let _ = self.buf.split_to(self.delimiter.len());
                return Ok(content);
            }
            // A delimiter may straddle what's here and what's to come.
            scanned = self.buf.len().saturating_sub(self.delimiter.len() - 1);
            if scanned as u64 > cap {
                return Err(ReadError::TooLarge);
            }
            match self.fill().await {
                Ok(true) => {}
                Ok(false) => return Err(ReadError::Failed(malformed_form())),
                Err(r) => return Err(ReadError::Failed(r)),
            }
        }
    }

    /// Ensure `n` bytes are buffered. `false` if the body ends first.
    async fn need(&mut self, n: usize) -> Result<bool, Response> {
        while self.buf.len() < n {
            if !self.fill().await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// After a delimiter: `true` if a part follows, `false` at the close.
    async fn after_delimiter(&mut self) -> Result<bool, Response> {
        if !self.need(2).await? {
            return Err(malformed_form());
        }
        if self.buf.starts_with(b"--") {
            return Ok(false);
        }
        // Transport padding, then the line break.
        loop {
            let pad = self
                .buf
                .iter()
                .take_while(|b| **b == b' ' || **b == b'\t')
                .count();
            if pad > 64 {
                return Err(malformed_form());
            }
            if !self.need(pad + 2).await? {
                return Err(malformed_form());
            }
            if self.buf[pad] == b' ' || self.buf[pad] == b'\t' {
                continue;
            }
            if &self.buf[pad..pad + 2] != b"\r\n" {
                return Err(malformed_form());
            }
            let _ = self.buf.split_to(pad + 2);
            return Ok(true);
        }
    }

    /// Skip what precedes the first boundary. `false` for an empty form.
    async fn start(&mut self) -> Result<bool, Response> {
        match self.until_delimiter(MAX_FIELDS_BYTES as u64).await {
            Ok(_) => self.after_delimiter().await,
            Err(ReadError::TooLarge) => Err(malformed_form()),
            Err(ReadError::Failed(r)) => Err(r),
        }
    }

    /// A part's headers, up to and including the blank line.
    async fn part_header(&mut self) -> Result<PartHeader, Response> {
        let finder = memchr::memmem::Finder::new(b"\r\n\r\n");
        let end = loop {
            if self.buf.starts_with(b"\r\n") {
                break 0;
            }
            if let Some(at) = finder.find(&self.buf) {
                break at + 2;
            }
            if self.buf.len() > MAX_PART_HEADER_BYTES || !self.fill().await? {
                return Err(malformed_form());
            }
        };
        let raw = self.buf.split_to(end + 2);
        let text = std::str::from_utf8(&raw[..end]).map_err(|_| malformed_form())?;
        let disposition = text
            .split("\r\n")
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-disposition"))
            .map(|(_, value)| value);
        disposition
            .and_then(parse_disposition)
            .ok_or_else(malformed_form)
    }
}

/// `form-data; name="field"; filename="x.jpg"`: the name and file name.
fn parse_disposition(value: &str) -> Option<PartHeader> {
    let mut segments = Vec::new();
    let (mut current, mut quoted, mut escaped) = (String::new(), false, false);
    for c in value.chars() {
        match c {
            _ if escaped => {
                current.push(c);
                escaped = false;
            }
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => segments.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    segments.push(current);
    let mut segments = segments.into_iter();
    if !segments.next()?.trim().eq_ignore_ascii_case("form-data") {
        return None;
    }
    let (mut name, mut filename) = (None, None);
    for segment in segments {
        let Some((k, v)) = segment.split_once('=') else {
            continue;
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "name" => name = Some(v.trim().to_string()),
            "filename" => filename = Some(v.trim().to_string()),
            _ => {}
        }
    }
    Some(PartHeader {
        name: name.filter(|n| !n.is_empty())?,
        filename,
    })
}

/// The form's fields (names lowercased), read up to the file part.
struct Fields {
    values: HashMap<String, String>,
    /// The file part's file name.
    filename: Option<String>,
}

impl Fields {
    fn get(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }
}

async fn read_fields(form: &mut Multipart) -> Result<Fields, Response> {
    let no_file = || invalid_argument("POST requires exactly one file upload per request.");
    if !form.start().await? {
        return Err(no_file());
    }
    let mut values = HashMap::new();
    // Everything before the file counts against one budget.
    let mut used = 0usize;
    loop {
        let part = form.part_header().await?;
        let name = part.name.to_ascii_lowercase();
        if name == "file" {
            return Ok(Fields {
                values,
                filename: part.filename,
            });
        }
        used += name.len();
        let room = MAX_FIELDS_BYTES.saturating_sub(used);
        let value = match form.until_delimiter(room as u64).await {
            Ok(v) => v,
            Err(ReadError::TooLarge) => return Err(pre_data_too_large()),
            Err(ReadError::Failed(r)) => return Err(r),
        };
        used += value.len();
        let value = String::from_utf8(value.to_vec())
            .map_err(|_| invalid_argument(&format!("The value of field {name} is not UTF-8")))?;
        if values.insert(name.clone(), value).is_some() {
            return Err(invalid_argument(&format!(
                "Field {name} appears more than once"
            )));
        }
        if values.len() > MAX_FIELDS {
            return Err(pre_data_too_large());
        }
        if !form.after_delimiter().await? {
            return Err(no_file());
        }
    }
}

fn pre_data_too_large() -> Response {
    bad_request(
        "MaxPostPreDataLengthExceeded",
        "Your POST request fields preceding the upload file were too large.",
    )
}

// ── The policy ──────────────────────────────────────────────────────────

/// One condition of a POST policy.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Condition {
    Eq { field: String, value: String },
    StartsWith { field: String, prefix: String },
    LengthRange { min: u64, max: u64 },
}

#[derive(Debug)]
struct Policy {
    expiration: DateTime<Utc>,
    /// Each condition, with its text as the policy wrote it (for errors).
    conditions: Vec<(Condition, String)>,
}

fn invalid_policy(message: &str) -> Response {
    bad_request(
        "InvalidPolicyDocument",
        &format!("Invalid Policy: {message}"),
    )
}

/// A field a condition names: `$key` → `key`.
fn condition_field(s: &str) -> Option<String> {
    s.strip_prefix('$')
        .filter(|f| !f.is_empty())
        .map(str::to_ascii_lowercase)
}

fn length_bound(v: &serde_json::Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.trim().parse().ok())
}

impl Policy {
    fn parse(document: &[u8]) -> Result<Self, Response> {
        #[derive(Deserialize)]
        struct Raw {
            expiration: Option<String>,
            conditions: Option<Vec<serde_json::Value>>,
        }
        let raw: Raw =
            serde_json::from_slice(document).map_err(|_| invalid_policy("Invalid JSON."))?;
        let expiration = raw
            .expiration
            .ok_or_else(|| invalid_policy("Policy missing expiration."))?;
        let expiration = DateTime::parse_from_rfc3339(&expiration)
            .map_err(|_| invalid_policy("Invalid 'expiration' value: must be ISO 8601 UTC."))?
            .with_timezone(&Utc);
        let raw_conditions = raw
            .conditions
            .ok_or_else(|| invalid_policy("Policy missing conditions."))?;
        let mut conditions = Vec::with_capacity(raw_conditions.len());
        for c in raw_conditions {
            let text = c.to_string();
            let bad = || invalid_policy(&format!("Invalid Policy condition: {text}"));
            match &c {
                serde_json::Value::Object(map) if !map.is_empty() => {
                    for (field, value) in map {
                        let value = value.as_str().ok_or_else(bad)?;
                        conditions.push((
                            Condition::Eq {
                                field: field.to_ascii_lowercase(),
                                value: value.to_string(),
                            },
                            text.clone(),
                        ));
                    }
                }
                serde_json::Value::Array(items) if items.len() == 3 => {
                    let op = items[0].as_str().ok_or_else(bad)?.to_ascii_lowercase();
                    let condition = if op == "content-length-range" {
                        let (min, max) = (
                            length_bound(&items[1]).ok_or_else(bad)?,
                            length_bound(&items[2]).ok_or_else(bad)?,
                        );
                        if min > max {
                            return Err(bad());
                        }
                        Condition::LengthRange { min, max }
                    } else {
                        let field = items[1]
                            .as_str()
                            .and_then(condition_field)
                            .ok_or_else(bad)?;
                        let value = items[2].as_str().ok_or_else(bad)?.to_string();
                        match op.as_str() {
                            "eq" => Condition::Eq { field, value },
                            "starts-with" => Condition::StartsWith {
                                field,
                                prefix: value,
                            },
                            _ => return Err(bad()),
                        }
                    };
                    conditions.push((condition, text));
                }
                _ => return Err(bad()),
            }
        }
        Ok(Self {
            expiration,
            conditions,
        })
    }

    /// The fields' conformance: unexpired, every condition met, every field
    /// covered by one. `Err` is S3's reason, after "Invalid according to
    /// Policy: ".
    fn check(&self, fields: &Fields, bucket: &str, now: DateTime<Utc>) -> Result<(), String> {
        if now >= self.expiration {
            return Err("Policy expired.".to_string());
        }
        let value = |field: &str| -> String {
            if field == "bucket" {
                bucket.to_string()
            } else {
                fields.get(field).unwrap_or_default().to_string()
            }
        };
        for (condition, text) in &self.conditions {
            let met = match condition {
                Condition::Eq { field, value: want } => value(field) == *want,
                // A Content-Type of several values: each must start so.
                Condition::StartsWith { field, prefix } if field == "content-type" => value(field)
                    .split(',')
                    .all(|v| v.trim().starts_with(prefix.as_str())),
                Condition::StartsWith { field, prefix } => {
                    value(field).starts_with(prefix.as_str())
                }
                Condition::LengthRange { .. } => true,
            };
            if !met {
                return Err(format!("Policy Condition failed: {text}"));
            }
        }
        // Every field the form sent is one the policy speaks for.
        let mut names: Vec<&String> = fields.values.keys().collect();
        names.sort();
        for name in names {
            if exempt_from_policy(name) {
                continue;
            }
            let covered = self.conditions.iter().any(|(c, _)| match c {
                Condition::Eq { field, .. } | Condition::StartsWith { field, .. } => field == name,
                Condition::LengthRange { .. } => false,
            });
            if !covered {
                return Err(format!("Extra input fields: {name}"));
            }
        }
        Ok(())
    }

    /// The file size the policy allows: every range at once.
    fn length_range(&self) -> (u64, u64) {
        self.conditions
            .iter()
            .fold((0, u64::MAX), |(lo, hi), (c, _)| match c {
                Condition::LengthRange { min, max } => (lo.max(*min), hi.min(*max)),
                _ => (lo, hi),
            })
    }
}

/// Fields a policy needn't cover (S3's rule).
fn exempt_from_policy(name: &str) -> bool {
    matches!(name, "x-amz-signature" | "file" | "policy") || name.starts_with("x-ignore-")
}

// ── Authentication ──────────────────────────────────────────────────────

/// Who the form is from: a verified signature's key, or nobody.
async fn authenticate(
    state: &PostObjectState,
    fields: &Fields,
    bucket: &str,
) -> Result<(AuthResult, Option<Policy>), Response> {
    if fields.get("awsaccesskeyid").is_some() || fields.get("signature").is_some() {
        return Err(AuthError::UnsupportedSigV2.into_response());
    }
    let signed = [
        "policy",
        "x-amz-signature",
        "x-amz-credential",
        "x-amz-algorithm",
    ]
    .iter()
    .any(|f| fields.get(f).is_some());
    if !signed {
        return Ok((
            AuthResult {
                user_arn: crate::authz::ANONYMOUS_PRINCIPAL.to_string(),
                auth_mode: AuthMode::Anonymous,
                ..Default::default()
            },
            None,
        ));
    }
    let field = |name: &'static str| fields.get(name).ok_or_else(|| missing_field(name));
    let algorithm = field("x-amz-algorithm")?;
    if algorithm != "AWS4-HMAC-SHA256" {
        return Err(invalid_argument(&format!(
            "Unsupported x-amz-algorithm {algorithm}: only AWS4-HMAC-SHA256 is accepted"
        )));
    }
    let credential = field("x-amz-credential")?;
    let date = field("x-amz-date")?;
    let signature = field("x-amz-signature")?;
    let policy_b64 = field("policy")?;

    // `AKID/20261002/us-east-1/s3/aws4_request`; the date must be the
    // credential's.
    let parts: Vec<&str> = credential.split('/').collect();
    if parts.len() != 5 || parts[3] != "s3" || parts[4] != "aws4_request" || parts[0].is_empty() {
        return Err(invalid_argument(&format!(
            "Invalid x-amz-credential: {credential}"
        )));
    }
    if NaiveDateTime::parse_from_str(date, "%Y%m%dT%H%M%SZ").is_err() || !date.starts_with(parts[1])
    {
        return Err(invalid_argument(
            "x-amz-date must be the credential's date, as YYYYMMDDTHHMMSSZ",
        ));
    }
    let access_key_id = parts[0];
    let auth_state = &state.app.auth_state;
    let (secret, mut auth) = if access_key_id.starts_with("ASIA") {
        let (cred, auth) = crate::auth_middleware::sts_session(
            auth_state,
            access_key_id,
            fields.get("x-amz-security-token"),
        )
        .map_err(IntoResponse::into_response)?;
        (cred.secret_access_key, auth)
    } else {
        let cred = auth_state
            .lookup_credential(access_key_id)
            .await
            .map_err(IntoResponse::into_response)?;
        let auth = AuthResult {
            user_id: cred.user_id.clone(),
            user_arn: cred.user_arn.clone(),
            access_key_id: cred.access_key_id.clone(),
            tenant: cred.tenant.clone(),
            auth_mode: AuthMode::Permanent,
            scope: cred.scope.clone(),
            ..Default::default()
        };
        (cred.secret_access_key, auth)
    };

    let key = crate::auth_middleware::derive_signing_key(&secret, parts[1], parts[2], "s3");
    let expected = crate::auth_middleware::calculate_signature_v4(&key, policy_b64);
    if !crate::auth_middleware::constant_time_eq(&expected, signature) {
        debug!("POST policy signature mismatch for {access_key_id}");
        return Err(AuthError::SignatureDoesNotMatch.into_response());
    }

    // Only a verified policy is read.
    use base64::Engine as _;
    let document = base64::engine::general_purpose::STANDARD
        .decode(policy_b64.trim())
        .map_err(|_| invalid_policy("the policy is not base64."))?;
    let policy = Policy::parse(&document)?;
    policy
        .check(fields, bucket, Utc::now())
        .map_err(|m| policy_denied(&m))?;

    if auth.auth_mode == AuthMode::Permanent {
        let (arns, ids) = auth_state.lookup_user_groups(&auth.user_id).await;
        auth.group_arns = arns;
        auth.group_ids = ids;
    }
    Ok((auth, Some(policy)))
}

// ── The object ──────────────────────────────────────────────────────────

/// The key the form names, with `${filename}` replaced by the file's name.
fn object_key(template: &str, filename: Option<&str>) -> String {
    // Only the name: some browsers send the client's whole path.
    let name = filename
        .unwrap_or_default()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default();
    template.replace("${filename}", name)
}

/// Form fields that become the PUT's headers, under the same names.
const HEADER_FIELDS: &[&str] = &[
    "content-type",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "expires",
    "content-md5",
    "x-amz-storage-class",
    "x-amz-server-side-encryption",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-context",
    "x-amz-server-side-encryption-bucket-key-enabled",
    "x-amz-server-side-encryption-customer-algorithm",
    "x-amz-server-side-encryption-customer-key",
    "x-amz-server-side-encryption-customer-key-md5",
    "x-amz-object-lock-mode",
    "x-amz-object-lock-retain-until-date",
    "x-amz-object-lock-legal-hold",
    "x-amz-checksum-algorithm",
    "x-amz-checksum-crc32",
    "x-amz-checksum-crc32c",
    "x-amz-checksum-crc64nvme",
    "x-amz-checksum-sha1",
    "x-amz-checksum-sha256",
];

#[derive(Deserialize)]
struct TaggingXml {
    #[serde(rename = "TagSet", default)]
    tag_set: TagSetXml,
}

#[derive(Deserialize, Default)]
struct TagSetXml {
    #[serde(rename = "Tag", default)]
    tags: Vec<TagXml>,
}

#[derive(Deserialize)]
struct TagXml {
    #[serde(rename = "Key")]
    key: String,
    #[serde(rename = "Value", default)]
    value: String,
}

/// A `tagging` field (a `Tagging` document) as an `x-amz-tagging` value.
fn tagging_header(xml: &str) -> Result<String, Response> {
    let parsed: TaggingXml = quick_xml::de::from_str(xml).map_err(|_| {
        bad_request(
            "MalformedXML",
            "The tagging field is not a Tagging document",
        )
    })?;
    Ok(parsed
        .tag_set
        .tags
        .iter()
        .map(|t| {
            format!(
                "{}={}",
                urlencoding::encode(&t.key),
                urlencoding::encode(&t.value)
            )
        })
        .collect::<Vec<_>>()
        .join("&"))
}

/// The headers of the PUT the form amounts to: built from the fields
/// alone — never the POST's own headers, which no policy covers.
fn object_headers(fields: &Fields) -> Result<HeaderMap, Response> {
    // ACLs are owner-enforced: a form can ask for no more than the owner's.
    if let Some(acl) = fields.get("acl")
        && acl != "private"
        && acl != "bucket-owner-full-control"
    {
        return Err(bad_request(
            "AccessControlListNotSupported",
            "The bucket does not allow ACLs",
        ));
    }
    let mut headers = HeaderMap::new();
    for (name, value) in &fields.values {
        let meta = name.starts_with("x-amz-meta-");
        if !meta && !HEADER_FIELDS.contains(&name.as_str()) {
            continue;
        }
        // Metadata travels as header text, and is kept only as ASCII.
        if meta && !value.is_ascii() {
            return Err(invalid_argument(&format!(
                "The value of {name} must be ASCII"
            )));
        }
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| invalid_argument(&format!("Invalid field name {name}")))?;
        let header_value = HeaderValue::from_str(value)
            .map_err(|_| invalid_argument(&format!("Invalid value for field {name}")))?;
        headers.insert(header_name, header_value);
    }
    if let Some(tagging) = fields.get("tagging") {
        let value = HeaderValue::from_str(&tagging_header(tagging)?)
            .map_err(|_| invalid_argument("Invalid tagging"))?;
        headers.insert("x-amz-tagging", value);
    }
    Ok(headers)
}

/// The identity's origin, as `authz_layer` records it for any request.
fn with_origin(
    mut auth: AuthResult,
    app: &AppState,
    request_headers: &HeaderMap,
    peer: Option<std::net::SocketAddr>,
    endpoint: Option<String>,
) -> AuthResult {
    auth.source_ip = peer.map(|p| app.trusted_proxies.client_ip(p.ip(), request_headers));
    auth.source_endpoint = endpoint;
    auth
}

async fn upload(
    state: &PostObjectState,
    bucket: &str,
    boundary: &str,
    request: Request,
) -> Result<Response, Response> {
    let (parts, body) = request.into_parts();
    let peer = parts
        .extensions
        .get::<crate::origin::ClientAddr>()
        .map(|c| c.0);
    let endpoint = parts
        .extensions
        .get::<crate::origin::Endpoint>()
        .and_then(|e| e.0.clone());
    // A proxy's word on the scheme counts only from a trusted proxy.
    let https = peer.is_some_and(|p| state.app.trusted_proxies.trusts(p.ip()))
        && parts
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|p| p.eq_ignore_ascii_case("https"));

    let mut form = Multipart::new(body, boundary);
    let fields = read_fields(&mut form).await?;
    let template = fields.get("key").ok_or_else(|| missing_field("key"))?;
    let key = object_key(template, fields.filename.as_deref());
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(bad_request(
            "KeyTooLongError",
            "Your key is too long, or empty",
        ));
    }

    let (auth, policy) = authenticate(state, &fields, bucket).await?;
    let auth = with_origin(auth, &state.app, &parts.headers, peer, endpoint);
    crate::audit::note_identity(&auth);
    crate::audit::note_target("s3:PutObject", bucket, Some(&key));

    let mut put_headers = object_headers(&fields)?;
    if https {
        put_headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));
    }
    if state.auth_enabled
        && let Some(denied) = crate::authz::authorize(
            &state.app,
            &auth,
            &crate::authz::AuthzRequest {
                method: &Method::POST,
                action: "s3:PutObject",
                bucket,
                key: Some(&key),
                scope_key: &key,
                headers: Some(&put_headers),
            },
        )
        .await
    {
        return Err(denied);
    }

    // Only now is the file read, and no further than allowed.
    let (min, max) = policy.as_ref().map_or((0, u64::MAX), Policy::length_range);
    let cap = max.min(MAX_FILE_SIZE);
    let file = match form.until_delimiter(cap).await {
        Ok(f) => f,
        Err(ReadError::TooLarge) => return Err(too_large()),
        Err(ReadError::Failed(r)) => return Err(r),
    };
    if (file.len() as u64) < min {
        return Err(bad_request(
            "EntityTooSmall",
            "Your proposed upload is smaller than the minimum allowed size",
        ));
    }

    let auth_ext = state.auth_enabled.then_some(Extension(auth));
    let put = crate::s3::put_object(
        State(Arc::clone(&state.app)),
        Path((bucket.to_string(), key.clone())),
        auth_ext,
        put_headers,
        file,
    )
    .await;
    if put.status() != StatusCode::OK {
        return Err(put);
    }
    let host = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let location = format!(
        "{}://{host}/{}/{}",
        if https { "https" } else { "http" },
        urlencoding::encode(bucket),
        key.split('/')
            .map(|s| urlencoding::encode(s).into_owned())
            .collect::<Vec<_>>()
            .join("/")
    );
    Ok(respond(&fields, bucket, &key, &location, &put))
}

/// The answer S3 gives a form: a redirect, or an empty 200/204, or a 201
/// `PostResponse` — whichever the form asked for.
fn respond(fields: &Fields, bucket: &str, key: &str, location: &str, put: &Response) -> Response {
    let etag = put
        .headers()
        .get(header::ETAG)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let redirect = fields
        .get("success_action_redirect")
        .or_else(|| fields.get("redirect"))
        .and_then(|u| reqwest::Url::parse(u).ok())
        .filter(|u| matches!(u.scheme(), "http" | "https"));

    let mut response = if let Some(mut url) = redirect {
        url.query_pairs_mut()
            .append_pair("bucket", bucket)
            .append_pair("key", key)
            .append_pair("etag", &etag);
        let mut r = StatusCode::SEE_OTHER.into_response();
        if let Ok(v) = HeaderValue::from_str(url.as_str()) {
            r.headers_mut().insert(header::LOCATION, v);
        }
        r
    } else {
        match fields.get("success_action_status") {
            Some("200") => StatusCode::OK.into_response(),
            Some("201") => {
                let esc = |s: &str| quick_xml::escape::escape(s).into_owned();
                let body = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<PostResponse>\
                     <Location>{}</Location><Bucket>{}</Bucket><Key>{}</Key>\
                     <ETag>{}</ETag></PostResponse>",
                    esc(location),
                    esc(bucket),
                    esc(key),
                    esc(&etag)
                );
                (
                    StatusCode::CREATED,
                    [(header::CONTENT_TYPE, "application/xml")],
                    body,
                )
                    .into_response()
            }
            // S3's default, and its answer to any other value.
            _ => StatusCode::NO_CONTENT.into_response(),
        }
    };
    let out = response.headers_mut();
    if !out.contains_key(header::LOCATION)
        && let Ok(v) = HeaderValue::from_str(location)
    {
        out.insert(header::LOCATION, v);
    }
    for (name, value) in put.headers() {
        let n = name.as_str();
        if n == "etag"
            || n == "x-amz-version-id"
            || n.starts_with("x-amz-server-side-encryption")
            || n.starts_with("x-amz-checksum-")
        {
            out.insert(name.clone(), value.clone());
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fields(pairs: &[(&str, &str)]) -> Fields {
        Fields {
            values: pairs
                .iter()
                .map(|(k, v)| ((*k).to_ascii_lowercase(), (*v).to_string()))
                .collect(),
            filename: None,
        }
    }

    fn policy(conditions: serde_json::Value) -> Policy {
        Policy::parse(
            json!({"expiration": "2099-01-01T00:00:00.000Z", "conditions": conditions})
                .to_string()
                .as_bytes(),
        )
        .expect("policy")
    }

    const SIGNED: [(&str, &str); 4] = [
        ("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        ("x-amz-credential", "AK/20261002/us-east-1/s3/aws4_request"),
        ("x-amz-date", "20261002T000000Z"),
        ("x-amz-signature", "abc"),
    ];

    fn signed_conditions(extra: &[serde_json::Value]) -> serde_json::Value {
        let mut c = vec![
            json!({"x-amz-algorithm": "AWS4-HMAC-SHA256"}),
            json!({"x-amz-credential": "AK/20261002/us-east-1/s3/aws4_request"}),
            json!({"x-amz-date": "20261002T000000Z"}),
        ];
        c.extend_from_slice(extra);
        serde_json::Value::Array(c)
    }

    fn form(extra: &[(&str, &str)]) -> Fields {
        let mut all: Vec<(&str, &str)> = SIGNED.to_vec();
        all.extend_from_slice(extra);
        all.push(("policy", "x"));
        fields(&all)
    }

    #[test]
    fn conditions_hold_exactly_and_by_prefix() {
        let p = policy(signed_conditions(&[
            json!({"bucket": "photos"}),
            json!(["starts-with", "$key", "uploads/"]),
            json!(["eq", "$Content-Type", "image/png"]),
        ]));
        let f = form(&[("key", "uploads/cat.png"), ("Content-Type", "image/png")]);
        let now = Utc::now();
        assert_eq!(p.check(&f, "photos", now), Ok(()));
        // Another bucket.
        let err = p.check(&f, "other", now).unwrap_err();
        assert!(
            err.starts_with("Policy Condition failed: {\"bucket\""),
            "{err}"
        );
        // A key outside the prefix.
        let f2 = form(&[("key", "elsewhere/cat.png"), ("content-type", "image/png")]);
        let err = p.check(&f2, "photos", now).unwrap_err();
        assert!(err.contains("starts-with") && err.contains("$key"), "{err}");
        // Field names are case-insensitive; values are not.
        let f3 = form(&[("KEY", "uploads/a"), ("content-type", "Image/PNG")]);
        assert!(p.check(&f3, "photos", now).is_err());
    }

    #[test]
    fn an_empty_prefix_allows_anything_and_content_type_lists_are_checked_whole() {
        let p = policy(signed_conditions(&[
            json!(["starts-with", "$key", ""]),
            json!(["starts-with", "$content-type", "image/"]),
        ]));
        let now = Utc::now();
        let ok = form(&[
            ("key", "anything"),
            ("content-type", "image/png, image/jpeg"),
        ]);
        assert_eq!(p.check(&ok, "b", now), Ok(()));
        let bad = form(&[("key", "x"), ("content-type", "image/png, text/html")]);
        assert!(p.check(&bad, "b", now).is_err());
    }

    #[test]
    fn every_field_but_the_exempt_must_be_covered() {
        let p = policy(signed_conditions(&[json!(["starts-with", "$key", ""])]));
        let now = Utc::now();
        let f = form(&[
            ("key", "k"),
            ("x-ignore-tracking", "1"),
            ("file", "ignored"),
        ]);
        assert_eq!(p.check(&f, "b", now), Ok(()));
        let f = form(&[("key", "k"), ("x-amz-meta-owner", "eve")]);
        assert_eq!(
            p.check(&f, "b", now),
            Err("Extra input fields: x-amz-meta-owner".to_string())
        );
        // The signing fields are no exception.
        let p = policy(json!([["starts-with", "$key", ""]]));
        let err = p.check(&form(&[("key", "k")]), "b", now).unwrap_err();
        assert!(err.starts_with("Extra input fields: x-amz-"), "{err}");
    }

    #[test]
    fn an_expired_policy_is_refused() {
        let p = Policy::parse(
            br#"{"expiration": "2020-01-01T00:00:00Z", "conditions": [["starts-with", "$key", ""]]}"#,
        )
        .unwrap();
        assert_eq!(
            p.check(&fields(&[("key", "k")]), "b", Utc::now()),
            Err("Policy expired.".to_string())
        );
    }

    #[test]
    fn length_ranges_intersect() {
        let p = policy(json!([
            ["content-length-range", 10, 1000],
            ["content-length-range", "1", "500"],
        ]));
        assert_eq!(p.length_range(), (10, 500));
        assert_eq!(policy(json!([])).length_range(), (0, u64::MAX));
    }

    #[test]
    fn malformed_policies_are_refused() {
        for doc in [
            r#"{"conditions": []}"#,
            r#"{"expiration": "2099-01-01T00:00:00Z"}"#,
            r#"{"expiration": "tomorrow", "conditions": []}"#,
            r#"{"expiration": "2099-01-01T00:00:00Z", "conditions": [["matches", "$key", "x"]]}"#,
            r#"{"expiration": "2099-01-01T00:00:00Z", "conditions": [["eq", "key", "x"]]}"#,
            r#"{"expiration": "2099-01-01T00:00:00Z", "conditions": [["content-length-range", 5, 1]]}"#,
            r#"{"expiration": "2099-01-01T00:00:00Z", "conditions": ["key"]}"#,
            "not json",
        ] {
            assert!(Policy::parse(doc.as_bytes()).is_err(), "{doc}");
        }
    }

    #[test]
    fn the_filename_replaces_its_placeholder() {
        assert_eq!(object_key("up/${filename}", Some("cat.png")), "up/cat.png");
        assert_eq!(
            object_key("up/${filename}", Some("C:\\Users\\me\\cat.png")),
            "up/cat.png"
        );
        assert_eq!(object_key("up/${filename}", Some("../../x")), "up/x");
        assert_eq!(object_key("fixed", Some("cat.png")), "fixed");
        assert_eq!(object_key("up/${filename}", None), "up/");
    }

    #[test]
    fn content_disposition_names_the_field_and_file() {
        let p = parse_disposition(r#" form-data; name="file"; filename="a;b \"c\".png""#).unwrap();
        assert_eq!(p.name, "file");
        assert_eq!(p.filename.as_deref(), Some("a;b \"c\".png"));
        let p = parse_disposition("form-data; name=key").unwrap();
        assert_eq!((p.name.as_str(), p.filename), ("key", None));
        assert!(parse_disposition("attachment; name=\"x\"").is_none());
        assert!(parse_disposition("form-data; filename=\"x\"").is_none());
    }

    #[test]
    fn only_listed_fields_become_headers_and_acls_stay_private() {
        let f = fields(&[
            ("key", "k"),
            ("Content-Type", "text/plain"),
            ("x-amz-meta-Owner", "me"),
            ("x-amz-copy-source", "other/secret"),
            ("x-amz-server-side-encryption", "AES256"),
            ("acl", "private"),
        ]);
        let h = object_headers(&f).unwrap();
        assert_eq!(h["content-type"], "text/plain");
        assert_eq!(h["x-amz-meta-owner"], "me");
        assert_eq!(h["x-amz-server-side-encryption"], "AES256");
        assert!(h.get("x-amz-copy-source").is_none());
        assert!(h.get("key").is_none() && h.get("acl").is_none());
        let public = fields(&[("acl", "public-read")]);
        assert_eq!(
            object_headers(&public).unwrap_err().status(),
            StatusCode::BAD_REQUEST
        );
        let tagged = fields(&[(
            "tagging",
            "<Tagging><TagSet><Tag><Key>a b</Key><Value>1</Value></Tag></TagSet></Tagging>",
        )]);
        assert_eq!(object_headers(&tagged).unwrap()["x-amz-tagging"], "a%20b=1");
    }

    async fn parse(body: &str, boundary: &str) -> Result<(Fields, Bytes), String> {
        let mut form = Multipart::new(Body::from(body.to_string()), boundary);
        let fields = read_fields(&mut form)
            .await
            .map_err(|r| r.status().to_string())?;
        let file = match form.until_delimiter(1024).await {
            Ok(f) => f,
            Err(ReadError::TooLarge) => return Err("too large".into()),
            Err(ReadError::Failed(r)) => return Err(r.status().to_string()),
        };
        Ok((fields, file))
    }

    #[tokio::test]
    async fn a_form_is_read_up_to_its_file() {
        let body = "preamble\r\n--XyZ\r\nContent-Disposition: form-data; name=\"Key\"\r\n\r\n\
                    up/${filename}\r\n--XyZ  \r\ncontent-disposition: form-data; name=\"x-amz-meta-a\"\r\n\r\n\
                    line1\r\nline2\r\n--XyZ\r\nContent-Disposition: form-data; name=\"file\"; \
                    filename=\"f.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--XyZ\r\n\
                    world\r\n--XyZ--\r\n";
        let (fields, file) = parse(body, "XyZ").await.unwrap();
        assert_eq!(fields.get("key"), Some("up/${filename}"));
        assert_eq!(fields.get("x-amz-meta-a"), Some("line1\r\nline2"));
        assert_eq!(fields.filename.as_deref(), Some("f.txt"));
        // The file ends at the first delimiter; what follows is ignored.
        assert_eq!(&file[..], b"hello");
    }

    #[tokio::test]
    async fn malformed_and_oversized_forms_are_refused() {
        // No file part.
        let body = "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nk\r\n--b--\r\n";
        assert_eq!(
            parse(body, "b").await.err().as_deref(),
            Some("400 Bad Request")
        );
        // Truncated file.
        let body = "--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nabc";
        assert_eq!(
            parse(body, "b").await.err().as_deref(),
            Some("400 Bad Request")
        );
        // A file over the cap.
        let body = format!(
            "--b\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\n{}\r\n--b--",
            "x".repeat(2000)
        );
        assert_eq!(parse(&body, "b").await.err().as_deref(), Some("too large"));
        // A field over the pre-data budget.
        let body = format!(
            "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\n{}\r\n--b--",
            "x".repeat(MAX_FIELDS_BYTES + 10)
        );
        assert_eq!(
            parse(&body, "b").await.err().as_deref(),
            Some("400 Bad Request")
        );
        // The same field twice.
        let body = "--b\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\na\r\n\
                    --b\r\nContent-Disposition: form-data; name=\"KEY\"\r\n\r\nb\r\n--b--";
        assert_eq!(
            parse(body, "b").await.err().as_deref(),
            Some("400 Bad Request")
        );
    }

    #[test]
    fn only_a_multipart_post_to_a_bucket_is_a_form_upload() {
        let req = |method: Method, uri: &str, ct: &str| {
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, ct)
                .body(Body::empty())
                .unwrap()
        };
        let mp = "multipart/form-data; boundary=\"abc\"";
        assert_eq!(
            form_upload(&req(Method::POST, "/photos", mp)),
            Some(("photos".to_string(), Some("abc".to_string())))
        );
        assert!(form_upload(&req(Method::POST, "/photos/", mp)).is_some());
        assert!(form_upload(&req(Method::POST, "/photos?delete", mp)).is_none());
        assert!(form_upload(&req(Method::POST, "/photos/k", mp)).is_none());
        assert!(form_upload(&req(Method::POST, "/", mp)).is_none());
        assert!(form_upload(&req(Method::PUT, "/photos", mp)).is_none());
        assert!(form_upload(&req(Method::POST, "/photos", "application/xml")).is_none());
        assert_eq!(
            form_upload(&req(Method::POST, "/photos", "multipart/form-data")),
            Some(("photos".to_string(), None))
        );
    }
}
