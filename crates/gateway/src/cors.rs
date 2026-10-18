//! Cross-origin resource sharing, as S3 has it: a bucket's
//! `CORSConfiguration` says which web origins may use it from a browser.
//!
//! - `PUT/GET/DELETE /{bucket}?cors` manage the configuration, stored as the
//!   bucket setting `cors` (so it goes with the bucket). Authorized as
//!   `s3:PutBucketCORS` (PUT and DELETE) and `s3:GetBucketCORS`.
//! - A preflight (`OPTIONS /{bucket}[/{key}]`) is answered here without
//!   authentication — browsers never sign one — from the configuration
//!   alone: the first rule allowing the origin, the method and every
//!   requested header decides. It reveals nothing else about the bucket.
//! - An actual request carrying `Origin` gets the matching rule's
//!   `Access-Control-*` headers on its response, error responses included
//!   (a browser can't read an S3 error otherwise). The layer sits outside
//!   authentication for that reason; it only ever adds headers.
//!
//! Configurations are cached per bucket for [`crate::authz::POLICY_CACHE_TTL_SECS`]
//! (a request with `Origin` costs no meta round trip once warm), and
//! dropped at once on this gateway when its configuration changes.
//!
//! CORS is a browser's protection, not the bucket's: whatever a rule
//! allows, every request is still authenticated and authorized as usual.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use objectio_proto::metadata::{
    GetBucketRequest, GetBucketSettingRequest, PutBucketSettingRequest,
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::s3::{AppState, S3Error};

/// The bucket setting holding a bucket's CORS configuration.
pub const SETTING: &str = "cors";

/// S3's limit on rules in one configuration.
const MAX_RULES: usize = 100;
/// S3's limit on the size of the configuration document.
const MAX_CONFIG_BYTES: usize = 64 * 1024;
/// The methods a rule may allow.
const METHODS: [&str; 5] = ["GET", "PUT", "POST", "DELETE", "HEAD"];
/// Bucket entries kept at most; beyond it the cache is emptied (a flood of
/// made-up bucket names mustn't grow it without bound).
const MAX_CACHED_BUCKETS: usize = 10_000;

const VARY: &str = "Origin, Access-Control-Request-Headers, Access-Control-Request-Method";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorsRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    #[serde(default)]
    pub allowed_headers: Vec<String>,
    #[serde(default)]
    pub expose_headers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_age_seconds: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorsConfiguration {
    pub rules: Vec<CorsRule>,
}

/// Why a document was refused: `(code, message)`, both S3's.
type Refusal = (&'static str, String);

fn malformed() -> Refusal {
    (
        "MalformedXML",
        "The XML you provided was not well-formed or did not validate against our published schema"
            .to_string(),
    )
}

fn invalid(message: String) -> Refusal {
    ("InvalidRequest", message)
}

/// Text that can go back out in a header value: visible ASCII and spaces.
fn header_safe(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// A header name, or a pattern of one with wildcards: token characters.
fn header_name_pattern(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

impl CorsRule {
    fn validate(&self) -> Result<(), Refusal> {
        if self.allowed_origins.is_empty() || self.allowed_methods.is_empty() {
            return Err(malformed());
        }
        if self.id.as_ref().is_some_and(|id| id.len() > 255) {
            return Err(invalid(
                "The ID of a CORS rule must be at most 255 characters".to_string(),
            ));
        }
        for m in &self.allowed_methods {
            if !METHODS.contains(&m.as_str()) {
                return Err(invalid(format!(
                    "Found unsupported HTTP method in CORS config. Unsupported method is {m}"
                )));
            }
        }
        for o in &self.allowed_origins {
            if !header_safe(o) {
                return Err(invalid(format!("AllowedOrigin \"{o}\" is not valid.")));
            }
            if o.matches('*').count() > 1 {
                return Err(invalid(format!(
                    "AllowedOrigin \"{o}\" can not have more than one wildcard."
                )));
            }
        }
        for h in &self.allowed_headers {
            if !header_name_pattern(h) {
                return Err(invalid(format!("AllowedHeader \"{h}\" is not valid.")));
            }
            if h.matches('*').count() > 1 {
                return Err(invalid(format!(
                    "AllowedHeader \"{h}\" can not have more than one wildcard."
                )));
            }
        }
        for h in &self.expose_headers {
            if h.contains('*') {
                return Err(invalid(format!(
                    "ExposeHeader \"{h}\" contains wildcard. We currently do not support \
                     wildcard for ExposeHeader."
                )));
            }
            if !header_name_pattern(h) {
                return Err(invalid(format!("ExposeHeader \"{h}\" is not valid.")));
            }
        }
        Ok(())
    }

    /// The origin pattern of this rule that `origin` matches, if any.
    fn origin_match(&self, origin: &str) -> Option<&str> {
        self.allowed_origins
            .iter()
            .find(|p| wildcard_match(p, origin))
            .map(String::as_str)
    }

    fn allows_header(&self, name: &str) -> bool {
        self.allowed_headers.iter().any(|p| wildcard_match(p, name))
    }
}

/// `value` against `pattern`, which holds at most one `*` standing for any
/// run of characters. ASCII case-insensitive: header names are, and an
/// origin's scheme and host are.
fn wildcard_match(pattern: &str, value: &str) -> bool {
    let (p, v) = (pattern.as_bytes(), value.as_bytes());
    match pattern.find('*') {
        None => p.eq_ignore_ascii_case(v),
        Some(star) => {
            let (prefix, suffix) = (&p[..star], &p[star + 1..]);
            v.len() >= prefix.len() + suffix.len()
                && v[..prefix.len()].eq_ignore_ascii_case(prefix)
                && v[v.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        }
    }
}

/// The names in an `Access-Control-Request-Headers` value, lowercased.
fn requested_headers(value: Option<&str>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split(',')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect()
}

/// A rule that matched, and the origin pattern it matched with.
pub struct Matched<'a> {
    rule: &'a CorsRule,
    wildcard_origin: bool,
}

impl CorsConfiguration {
    /// Parse and validate a `CORSConfiguration` document as S3 does.
    pub fn from_xml(body: &[u8]) -> Result<Self, Refusal> {
        use quick_xml::events::Event;
        if body.len() > MAX_CONFIG_BYTES {
            return Err(invalid(format!(
                "The CORS configuration must be at most {MAX_CONFIG_BYTES} bytes"
            )));
        }
        let mut reader = quick_xml::Reader::from_reader(body);
        let mut buf = Vec::new();
        let mut path: Vec<Vec<u8>> = Vec::new();
        let mut text = String::new();
        let mut rules = Vec::new();
        let mut rule: Option<CorsRule> = None;
        let mut saw_root = false;
        loop {
            let event = reader.read_event_into(&mut buf).map_err(|_| malformed())?;
            match event {
                Event::Start(e) => {
                    let name = e.local_name().as_ref().to_vec();
                    match (path.len(), name.as_slice()) {
                        (0, b"CORSConfiguration") if !saw_root => saw_root = true,
                        (1, b"CORSRule") => rule = Some(CorsRule::default()),
                        (
                            2,
                            b"ID" | b"AllowedOrigin" | b"AllowedMethod" | b"AllowedHeader"
                            | b"ExposeHeader" | b"MaxAgeSeconds",
                        ) => {}
                        _ => return Err(malformed()),
                    }
                    path.push(name);
                    text.clear();
                }
                Event::Empty(_) => return Err(malformed()),
                Event::Text(t) => text.push_str(&t.unescape().map_err(|_| malformed())?),
                Event::CData(t) => {
                    text.push_str(std::str::from_utf8(&t.into_inner()).map_err(|_| malformed())?)
                }
                Event::End(_) => {
                    let name = path.pop().unwrap_or_default();
                    let value = std::mem::take(&mut text).trim().to_string();
                    if name == b"CORSRule" {
                        rules.push(rule.take().ok_or_else(malformed)?);
                        continue;
                    }
                    let Some(r) = rule.as_mut().filter(|_| path.len() == 2) else {
                        continue;
                    };
                    match name.as_slice() {
                        b"ID" if r.id.is_none() => r.id = Some(value),
                        b"AllowedOrigin" if !value.is_empty() => r.allowed_origins.push(value),
                        b"AllowedMethod" if !value.is_empty() => r.allowed_methods.push(value),
                        b"AllowedHeader" if !value.is_empty() => r.allowed_headers.push(value),
                        b"ExposeHeader" if !value.is_empty() => r.expose_headers.push(value),
                        b"MaxAgeSeconds" if r.max_age_seconds.is_none() => {
                            r.max_age_seconds = Some(value.parse().map_err(|_| malformed())?);
                        }
                        _ => return Err(malformed()),
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }
        if !saw_root || !path.is_empty() || rules.is_empty() {
            return Err(malformed());
        }
        if rules.len() > MAX_RULES {
            return Err(invalid(format!(
                "The number of CORS rules should not exceed allowed limit of {MAX_RULES} rules."
            )));
        }
        for r in &rules {
            r.validate()?;
        }
        Ok(Self { rules })
    }

    #[must_use]
    pub fn to_xml(&self) -> String {
        use std::fmt::Write as _;
        let esc = |s: &str| quick_xml::escape::escape(s).into_owned();
        let mut out = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <CORSConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">",
        );
        for r in &self.rules {
            out.push_str("<CORSRule>");
            if let Some(id) = &r.id {
                let _ = write!(out, "<ID>{}</ID>", esc(id));
            }
            for (tag, values) in [
                ("AllowedHeader", &r.allowed_headers),
                ("AllowedMethod", &r.allowed_methods),
                ("AllowedOrigin", &r.allowed_origins),
                ("ExposeHeader", &r.expose_headers),
            ] {
                for v in values {
                    let _ = write!(out, "<{tag}>{}</{tag}>", esc(v));
                }
            }
            if let Some(age) = r.max_age_seconds {
                let _ = write!(out, "<MaxAgeSeconds>{age}</MaxAgeSeconds>");
            }
            out.push_str("</CORSRule>");
        }
        out.push_str("</CORSConfiguration>");
        out
    }

    /// A stored configuration. Unreadable: none, which allows no origin —
    /// the safe reading of a setting that can't be understood.
    fn from_stored(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice::<Self>(bytes)
            .ok()
            .filter(|c| c.rules.iter().all(|r| r.validate().is_ok()))
    }

    fn to_stored(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }

    /// The first rule allowing `origin` to send `method` with every one of
    /// `headers` (lowercased names).
    #[must_use]
    pub fn find(&self, origin: &str, method: &str, headers: &[String]) -> Option<Matched<'_>> {
        self.rules.iter().find_map(|rule| {
            let pattern = rule.origin_match(origin)?;
            if !rule.allowed_methods.iter().any(|m| m == method) {
                return None;
            }
            if !headers.iter().all(|h| rule.allows_header(h)) {
                return None;
            }
            Some(Matched {
                rule,
                wildcard_origin: pattern == "*",
            })
        })
    }
}

/// Add a matched rule's headers to a response. `requested` is a
/// preflight's `Access-Control-Request-Headers`, echoed back.
fn apply(m: &Matched<'_>, origin: &str, requested: Option<&[String]>, headers: &mut HeaderMap) {
    let mut set = |name: &'static str, value: &str| {
        if let Ok(v) = HeaderValue::from_str(value) {
            headers.insert(name, v);
        }
    };
    if m.wildcard_origin {
        set("access-control-allow-origin", "*");
    } else {
        set("access-control-allow-origin", origin);
        set("access-control-allow-credentials", "true");
    }
    set(
        "access-control-allow-methods",
        &m.rule.allowed_methods.join(", "),
    );
    if let Some(requested) = requested.filter(|r| !r.is_empty()) {
        set("access-control-allow-headers", &requested.join(", "));
    }
    if !m.rule.expose_headers.is_empty() {
        set(
            "access-control-expose-headers",
            &m.rule.expose_headers.join(", "),
        );
    }
    if let Some(age) = m.rule.max_age_seconds {
        set("access-control-max-age", &age.to_string());
    }
    set("vary", VARY);
}

// ── Cache ───────────────────────────────────────────────────────────────

/// What a bucket's CORS amounts to.
#[derive(Clone)]
pub enum CorsEntry {
    /// The bucket doesn't exist.
    NoBucket,
    /// Its configuration, if it has one.
    Config(Option<Arc<CorsConfiguration>>),
}

/// Each bucket's CORS configuration, as last read from meta.
pub struct CorsCache {
    entries: RwLock<HashMap<String, (CorsEntry, Instant)>>,
    ttl: Duration,
}

impl CorsCache {
    #[must_use]
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    fn get(&self, bucket: &str) -> Option<CorsEntry> {
        let entries = self.entries.read();
        let (entry, at) = entries.get(bucket)?;
        (at.elapsed() < self.ttl).then(|| entry.clone())
    }

    fn put(&self, bucket: &str, entry: CorsEntry) {
        let mut entries = self.entries.write();
        if entries.len() >= MAX_CACHED_BUCKETS {
            let ttl = self.ttl;
            entries.retain(|_, (_, at)| at.elapsed() < ttl);
            if entries.len() >= MAX_CACHED_BUCKETS {
                entries.clear();
            }
        }
        entries.insert(bucket.to_string(), (entry, Instant::now()));
    }

    /// Drop one bucket's entry: its configuration, or the bucket, changed.
    pub fn invalidate(&self, bucket: &str) {
        self.entries.write().remove(bucket);
    }
}

impl Default for CorsCache {
    fn default() -> Self {
        Self::new(crate::authz::POLICY_CACHE_TTL_SECS)
    }
}

/// A bucket's CORS, via the cache. `None` when meta couldn't say (not
/// cached: the next request asks again).
async fn load(state: &AppState, bucket: &str) -> Option<CorsEntry> {
    let cache = &state.policy_cache.cors;
    if let Some(entry) = cache.get(bucket) {
        return Some(entry);
    }
    let mut meta = state.meta_client.clone();
    let exists = match meta
        .get_bucket(GetBucketRequest {
            name: bucket.to_string(),
        })
        .await
    {
        Ok(r) => r.into_inner().bucket.is_some(),
        Err(e) if e.code() == tonic::Code::NotFound => false,
        Err(_) => return None,
    };
    let entry = if exists {
        let setting = meta
            .get_bucket_setting(GetBucketSettingRequest {
                bucket: bucket.to_string(),
                name: SETTING.to_string(),
            })
            .await
            .ok()?
            .into_inner();
        CorsEntry::Config(
            setting
                .found
                .then(|| CorsConfiguration::from_stored(&setting.value))
                .flatten()
                .map(Arc::new),
        )
    } else {
        CorsEntry::NoBucket
    };
    cache.put(bucket, entry.clone());
    Some(entry)
}

// ── The configuration API ───────────────────────────────────────────────

fn refusal_response((code, message): Refusal) -> Response {
    S3Error::xml_response(code, &message, StatusCode::BAD_REQUEST)
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

/// `GET /{bucket}?cors`
pub async fn get_bucket(state: &AppState, bucket: &str) -> Response {
    if let Err(resp) = crate::s3::bucket_owner(state, bucket).await {
        return resp;
    }
    let setting = match state
        .meta_client
        .clone()
        .get_bucket_setting(GetBucketSettingRequest {
            bucket: bucket.to_string(),
            name: SETTING.to_string(),
        })
        .await
    {
        Ok(r) => r.into_inner(),
        Err(e) => return meta_error(&e),
    };
    match setting
        .found
        .then(|| CorsConfiguration::from_stored(&setting.value))
        .flatten()
    {
        Some(config) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/xml")
            .body(Body::from(config.to_xml()))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        None => S3Error::xml_response(
            "NoSuchCORSConfiguration",
            "The CORS configuration does not exist",
            StatusCode::NOT_FOUND,
        ),
    }
}

/// `PUT /{bucket}?cors`
pub async fn put_bucket(
    state: &AppState,
    bucket: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    // Content-MD5, when sent (S3 requires it; SDKs send it), must match.
    if let Some(md5) = headers.get("content-md5") {
        use base64::Engine as _;
        use md5::Digest as _;
        let sent = md5.to_str().ok().and_then(|v| {
            base64::engine::general_purpose::STANDARD
                .decode(v.trim())
                .ok()
        });
        if sent.as_deref() != Some(md5::Md5::digest(body).as_slice()) {
            return S3Error::xml_response(
                "BadDigest",
                "The Content-MD5 you specified did not match what we received.",
                StatusCode::BAD_REQUEST,
            );
        }
    }
    let config = match CorsConfiguration::from_xml(body) {
        Ok(c) => c,
        Err(r) => return refusal_response(r),
    };
    write_bucket(state, bucket, Some(&config)).await
}

/// `DELETE /{bucket}?cors`
pub async fn delete_bucket(state: &AppState, bucket: &str) -> Response {
    write_bucket(state, bucket, None).await
}

async fn write_bucket(
    state: &AppState,
    bucket: &str,
    config: Option<&CorsConfiguration>,
) -> Response {
    let result = state
        .meta_client
        .clone()
        .put_bucket_setting(PutBucketSettingRequest {
            bucket: bucket.to_string(),
            name: SETTING.to_string(),
            value: config.map(CorsConfiguration::to_stored).unwrap_or_default(),
            delete: config.is_none(),
        })
        .await;
    state.policy_cache.cors.invalidate(bucket);
    match result {
        Ok(_) if config.is_some() => StatusCode::OK.into_response(),
        Ok(_) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => meta_error(&e),
    }
}

// ── Preflight and actual requests ───────────────────────────────────────

/// The bucket a data-plane path names (`/{bucket}` or `/{bucket}/{key}`),
/// if it is a valid bucket name.
fn bucket_of(path: &str) -> Option<String> {
    let trimmed = path.strip_prefix('/')?;
    let raw = trimmed.split('/').next().unwrap_or_default();
    let bucket = urlencoding::decode(raw).ok()?;
    let b = bucket.as_bytes();
    let valid = (3..=63).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'.')
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric();
    // `/health` is the health check, not a bucket listing.
    (valid && path != "/health").then(|| bucket.into_owned())
}

fn forbidden(message: &str) -> Response {
    S3Error::xml_response("AccessForbidden", message, StatusCode::FORBIDDEN)
}

const NOT_ALLOWED: &str = "CORSResponse: This CORS request is not allowed. This is usually because \
     the evalution of Origin, request method / Access-Control-Request-Method or \
     Access-Control-Request-Headers are not whitelisted by the resource's CORS spec.";

/// Answer a preflight for `bucket` from its configuration.
async fn preflight(state: &AppState, bucket: &str, headers: &HeaderMap) -> Response {
    let get = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let Some(origin) = get("origin").filter(|o| !o.is_empty()) else {
        return S3Error::xml_response(
            "BadRequest",
            "Insufficient information. Origin request header needed.",
            StatusCode::BAD_REQUEST,
        );
    };
    let Some(method) = get("access-control-request-method").filter(|m| METHODS.contains(m)) else {
        return S3Error::xml_response(
            "BadRequest",
            &format!(
                "Invalid Access-Control-Request-Method: {}",
                get("access-control-request-method").unwrap_or("null")
            ),
            StatusCode::BAD_REQUEST,
        );
    };
    let requested = requested_headers(get("access-control-request-headers"));
    crate::audit::note_target("s3:PreflightRequest", bucket, None);
    let config = match load(state, bucket).await {
        None => {
            return S3Error::xml_response(
                "ServiceUnavailable",
                "Please reduce your request rate.",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }
        Some(CorsEntry::NoBucket) => {
            return S3Error::xml_response(
                "NoSuchBucket",
                "The specified bucket does not exist",
                StatusCode::NOT_FOUND,
            );
        }
        Some(CorsEntry::Config(None)) => {
            return forbidden("CORSResponse: CORS is not enabled for this bucket.");
        }
        Some(CorsEntry::Config(Some(c))) => c,
    };
    let Some(matched) = config.find(origin, method, &requested) else {
        return forbidden(NOT_ALLOWED);
    };
    let mut response = StatusCode::OK.into_response();
    apply(&matched, origin, Some(&requested), response.headers_mut());
    response
}

/// CORS on the S3 routes: preflights answered, actual requests' responses
/// given the matching rule's headers. Outside authentication (preflights
/// carry no credentials, and errors need the headers too).
pub async fn cors_layer(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(bucket) = bucket_of(request.uri().path()) else {
        return next.run(request).await;
    };
    if request.method() == Method::OPTIONS {
        return preflight(&state, &bucket, request.headers()).await;
    }
    let Some(origin) = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|o| !o.is_empty())
        .map(str::to_string)
    else {
        return next.run(request).await;
    };
    let method = request.method().as_str().to_string();
    let config = match load(&state, &bucket).await {
        Some(CorsEntry::Config(Some(c))) => Some(c),
        _ => None,
    };
    let mut response = next.run(request).await;
    if let Some(config) = config
        && let Some(matched) = config.find(&origin, &method, &[])
    {
        apply(&matched, &origin, None, response.headers_mut());
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(xml: &str) -> CorsConfiguration {
        CorsConfiguration::from_xml(xml.as_bytes()).expect("valid configuration")
    }

    const SAMPLE: &str = r#"<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        <CORSRule>
          <ID>app</ID>
          <AllowedOrigin>https://*.example.com</AllowedOrigin>
          <AllowedMethod>GET</AllowedMethod>
          <AllowedMethod>PUT</AllowedMethod>
          <AllowedHeader>Content-*</AllowedHeader>
          <AllowedHeader>x-amz-date</AllowedHeader>
          <ExposeHeader>ETag</ExposeHeader>
          <MaxAgeSeconds>3000</MaxAgeSeconds>
        </CORSRule>
        <CORSRule>
          <AllowedOrigin>*</AllowedOrigin>
          <AllowedMethod>GET</AllowedMethod>
        </CORSRule>
      </CORSConfiguration>"#;

    #[test]
    fn a_configuration_parses_and_round_trips() {
        let c = config(SAMPLE);
        assert_eq!(c.rules.len(), 2);
        assert_eq!(c.rules[0].id.as_deref(), Some("app"));
        assert_eq!(c.rules[0].allowed_methods, ["GET", "PUT"]);
        assert_eq!(c.rules[0].max_age_seconds, Some(3000));
        assert_eq!(config(&c.to_xml()), c);
        assert_eq!(CorsConfiguration::from_stored(&c.to_stored()), Some(c));
        assert_eq!(CorsConfiguration::from_stored(b"garbage"), None);
    }

    #[test]
    fn wildcard_origins_match_subdomains_and_nothing_else() {
        let c = config(SAMPLE);
        let m = c.find("https://app.example.com", "PUT", &[]).unwrap();
        assert_eq!(m.rule.id.as_deref(), Some("app"));
        assert!(!m.wildcard_origin);
        // Another scheme, a lookalike host, or a suffix past the domain:
        // only the catch-all GET rule, which doesn't allow PUT.
        for origin in [
            "http://app.example.com",
            "https://app.example.com.evil.org",
            "https://evilexample.com",
        ] {
            assert!(c.find(origin, "PUT", &[]).is_none(), "{origin}");
            assert!(c.find(origin, "GET", &[]).unwrap().wildcard_origin);
        }
        assert!(wildcard_match(
            "https://*.example.com",
            "https://A.Example.COM"
        ));
        assert!(!wildcard_match(
            "https://*.example.com",
            "https://.example.co"
        ));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("a*", "a"));
    }

    #[test]
    fn requested_headers_must_all_be_allowed_case_insensitively() {
        let c = config(SAMPLE);
        let origin = "https://app.example.com";
        let hs = requested_headers(Some("Content-Type, X-Amz-Date"));
        assert_eq!(hs, ["content-type", "x-amz-date"]);
        assert!(c.find(origin, "PUT", &hs).is_some());
        let hs = requested_headers(Some("content-type, authorization"));
        assert!(c.find(origin, "PUT", &hs).is_none());
        // The catch-all rule allows no headers at all.
        let hs = requested_headers(Some("x-amz-date"));
        assert!(c.find("https://other.org", "GET", &hs).is_none());
        assert!(c.find("https://other.org", "GET", &[]).is_some());
        assert!(c.find("https://other.org", "DELETE", &[]).is_none());
    }

    #[test]
    fn the_first_matching_rule_decides() {
        let c = config(
            "<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin>\
             <AllowedMethod>GET</AllowedMethod></CORSRule><CORSRule>\
             <AllowedOrigin>https://a.org</AllowedOrigin><AllowedMethod>GET</AllowedMethod>\
             <ExposeHeader>ETag</ExposeHeader></CORSRule></CORSConfiguration>",
        );
        let m = c.find("https://a.org", "GET", &[]).unwrap();
        assert!(m.wildcard_origin && m.rule.expose_headers.is_empty());
    }

    #[test]
    fn the_response_headers_follow_s3() {
        let c = config(SAMPLE);
        let mut h = HeaderMap::new();
        let m = c.find("https://app.example.com", "GET", &[]).unwrap();
        apply(
            &m,
            "https://app.example.com",
            Some(&["content-type".to_string()]),
            &mut h,
        );
        assert_eq!(h["access-control-allow-origin"], "https://app.example.com");
        assert_eq!(h["access-control-allow-credentials"], "true");
        assert_eq!(h["access-control-allow-methods"], "GET, PUT");
        assert_eq!(h["access-control-allow-headers"], "content-type");
        assert_eq!(h["access-control-expose-headers"], "ETag");
        assert_eq!(h["access-control-max-age"], "3000");
        assert_eq!(h["vary"], VARY);

        let mut h = HeaderMap::new();
        let m = c.find("https://other.org", "GET", &[]).unwrap();
        apply(&m, "https://other.org", None, &mut h);
        assert_eq!(h["access-control-allow-origin"], "*");
        assert!(h.get("access-control-allow-credentials").is_none());
        assert!(h.get("access-control-allow-headers").is_none());
    }

    #[test]
    fn invalid_configurations_are_refused_as_s3_refuses_them() {
        let rule = |body: &str| {
            CorsConfiguration::from_xml(
                format!("<CORSConfiguration><CORSRule>{body}</CORSRule></CORSConfiguration>")
                    .as_bytes(),
            )
            .map(|_| ())
            .map_err(|(code, _)| code)
        };
        let ok = "<AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod>";
        assert_eq!(rule(ok), Ok(()));
        assert_eq!(
            rule("<AllowedOrigin>*</AllowedOrigin><AllowedMethod>PATCH</AllowedMethod>"),
            Err("InvalidRequest")
        );
        assert_eq!(
            rule(
                "<AllowedOrigin>https://*.*.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod>"
            ),
            Err("InvalidRequest")
        );
        assert_eq!(
            rule(&format!("{ok}<AllowedHeader>x-*-*</AllowedHeader>")),
            Err("InvalidRequest")
        );
        assert_eq!(
            rule(&format!("{ok}<ExposeHeader>x-amz-*</ExposeHeader>")),
            Err("InvalidRequest")
        );
        assert_eq!(
            rule("<AllowedMethod>GET</AllowedMethod>"),
            Err("MalformedXML")
        );
        assert_eq!(
            rule("<AllowedOrigin>*</AllowedOrigin>"),
            Err("MalformedXML")
        );
        assert_eq!(
            rule(&format!("{ok}<MaxAgeSeconds>soon</MaxAgeSeconds>")),
            Err("MalformedXML")
        );
        assert_eq!(
            rule(&format!("{ok}<Unknown>x</Unknown>")),
            Err("MalformedXML")
        );
        assert_eq!(
            CorsConfiguration::from_xml(b"<CORSConfiguration></CORSConfiguration>")
                .map_err(|(c, _)| c),
            Err("MalformedXML")
        );
        assert_eq!(
            CorsConfiguration::from_xml(b"<Other><CORSRule/></Other>").map_err(|(c, _)| c),
            Err("MalformedXML")
        );
        let many = format!(
            "<CORSConfiguration>{}</CORSConfiguration>",
            format!("<CORSRule>{ok}</CORSRule>").repeat(101)
        );
        assert_eq!(
            CorsConfiguration::from_xml(many.as_bytes()).map_err(|(c, _)| c),
            Err("InvalidRequest")
        );
    }

    #[test]
    fn only_bucket_paths_are_cors_paths() {
        assert_eq!(bucket_of("/photos").as_deref(), Some("photos"));
        assert_eq!(bucket_of("/photos/a/b.jpg").as_deref(), Some("photos"));
        for path in ["/", "/health", "/_admin/users", "/_console/x", "/UPPER"] {
            assert_eq!(bucket_of(path), None, "{path}");
        }
    }

    #[test]
    fn the_cache_expires_and_invalidates() {
        let cache = CorsCache::new(60);
        cache.put("b", CorsEntry::NoBucket);
        assert!(matches!(cache.get("b"), Some(CorsEntry::NoBucket)));
        cache.invalidate("b");
        assert!(cache.get("b").is_none());
        let expired = CorsCache::new(0);
        expired.put("b", CorsEntry::Config(None));
        assert!(expired.get("b").is_none());
    }
}
