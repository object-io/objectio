//! A signed HTTP client for the gateway's management API.

use crate::config::Settings;
use crate::sigv4::{Request as SignRequest, Signer, canonical_query};
use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use std::time::Duration;

/// A non-2xx answer, with the server's own message.
#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub method: String,
    pub path: String,
    /// S3/STS error code from an XML error document; empty otherwise.
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.code.is_empty() {
            write!(
                f,
                "{} {}: {}: {}",
                self.method, self.path, self.status, self.message
            )
        } else {
            write!(
                f,
                "{} {}: {} {}: {}",
                self.method, self.path, self.status, self.code, self.message
            )
        }
    }
}

impl std::error::Error for ApiError {}

/// The text between `<tag>` and `</tag>`, first occurrence.
pub fn xml_tag(doc: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = doc.find(&open)? + open.len();
    let end = doc[start..].find(&close)? + start;
    Some(xml_unescape(doc[start..end].trim()))
}

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Build the error for a non-2xx answer: the JSON `message`/`error` field,
/// an XML error document's `Code`/`Message`, else the body as text.
pub fn api_error(status: u16, method: &str, path: &str, body: &[u8]) -> ApiError {
    let text = String::from_utf8_lossy(body).trim().to_string();
    let mut code = String::new();
    let mut message = text.clone();
    if let Ok(v) = serde_json::from_slice::<Value>(body) {
        if let Some(m) = v
            .get("message")
            .and_then(Value::as_str)
            .or_else(|| v.get("error").and_then(Value::as_str))
        {
            message = m.to_string();
        }
    } else if text.starts_with('<') {
        if let Some(c) = xml_tag(&text, "Code") {
            code = c;
        }
        if let Some(m) = xml_tag(&text, "Message") {
            message = m;
        }
    }
    if message.is_empty() {
        message = match status {
            401 => "authentication required".into(),
            403 => "forbidden".into(),
            404 => "not found".into(),
            _ => "(empty response)".into(),
        };
    }
    ApiError {
        status,
        method: method.to_string(),
        path: path.to_string(),
        code,
        message,
    }
}

/// A request body.
pub enum Body {
    Empty,
    Json(Value),
    Raw {
        bytes: Vec<u8>,
        content_type: String,
    },
}

/// A successful answer.
#[derive(Debug)]
pub struct Reply {
    pub bytes: Vec<u8>,
}

impl Reply {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }

    /// The body as JSON; an empty body is `null`.
    pub fn json(&self) -> Result<Value> {
        if self.bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&self.bytes).context("the server's answer is not JSON")
    }
}

pub struct ApiClient {
    pub settings: Settings,
    http: reqwest::Client,
}

impl ApiClient {
    pub fn new(settings: Settings) -> Result<Self> {
        reqwest::Url::parse(&settings.endpoint)
            .with_context(|| format!("bad endpoint {:?}", settings.endpoint))?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .context("building the HTTP client")?;
        Ok(Self { settings, http })
    }

    /// Send a signed request. `path` must already be escaped (see
    /// [`crate::sigv4::escape_path`]): it is signed and sent verbatim.
    pub async fn call(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: Body,
    ) -> Result<Reply> {
        self.send(method, path, query, body, true).await
    }

    /// Send without an Authorization header — what routes a POST to `/` to
    /// STS rather than S3.
    pub async fn call_unsigned(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: Body,
    ) -> Result<Reply> {
        self.send(method, path, query, body, false).await
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: Body,
        sign: bool,
    ) -> Result<Reply> {
        let (bytes, content_type) = match body {
            Body::Empty => (Vec::new(), None),
            Body::Json(v) => (
                serde_json::to_vec(&v).context("encoding request")?,
                Some("application/json".to_string()),
            ),
            Body::Raw {
                bytes,
                content_type,
            } => (bytes, Some(content_type)),
        };
        let qs = canonical_query(query);
        let url_text = if qs.is_empty() {
            format!("{}{path}", self.settings.endpoint)
        } else {
            format!("{}{path}?{qs}", self.settings.endpoint)
        };
        let url = reqwest::Url::parse(&url_text).with_context(|| format!("bad URL {url_text}"))?;
        let host = match (url.host_str(), url.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_string(),
            (None, _) => return Err(anyhow!("endpoint {} has no host", self.settings.endpoint)),
        };
        let m = reqwest::Method::from_bytes(method.as_bytes())
            .map_err(|_| anyhow!("bad method {method}"))?;
        let mut req = self.http.request(m, url);
        if let Some(ct) = &content_type {
            req = req.header("content-type", ct);
        }
        if sign {
            let (ak, sk) = self.settings.credentials.as_ref().ok_or_else(|| {
                anyhow!("this command needs credentials; see `obioctl configure`")
            })?;
            let signer = Signer {
                access_key: ak,
                secret_key: sk,
                region: &self.settings.region,
            };
            let headers = signer.sign(
                &SignRequest {
                    method,
                    host: &host,
                    path,
                    query,
                    content_type: content_type.as_deref(),
                    body: &bytes,
                },
                chrono::Utc::now(),
            );
            for (k, v) in headers {
                req = req.header(k, v);
            }
        }
        let resp = req
            .body(bytes)
            .send()
            .await
            .with_context(|| format!("{method} {}{path}", self.settings.endpoint))?;
        let status = resp.status().as_u16();
        let raw = resp.bytes().await.context("reading the response")?.to_vec();
        if !(200..300).contains(&status) {
            return Err(api_error(status, method, path, &raw).into());
        }
        Ok(Reply { bytes: raw })
    }

    pub async fn get(&self, path: &str, query: &[(String, String)]) -> Result<Value> {
        self.call("GET", path, query, Body::Empty).await?.json()
    }

    pub async fn send_json(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: Value,
    ) -> Result<Value> {
        self.call(method, path, query, Body::Json(body))
            .await?
            .json()
    }

    pub async fn delete(&self, path: &str, query: &[(String, String)]) -> Result<Value> {
        self.call("DELETE", path, query, Body::Empty).await?.json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_json_error_yields_its_message() {
        let e = api_error(403, "GET", "/_admin/x", br#"{"error":"not authorized"}"#);
        assert_eq!(e.message, "not authorized");
        let e = api_error(
            503,
            "GET",
            "/q",
            br#"{"error":"prometheus_not_configured","message":"no prometheus"}"#,
        );
        assert_eq!(e.message, "no prometheus");
    }

    #[test]
    fn an_xml_error_yields_code_and_message() {
        let e = api_error(
            404,
            "GET",
            "/b",
            b"<?xml version=\"1.0\"?><Error><Code>NoSuchLifecycleConfiguration</Code>\
              <Message>The lifecycle configuration does not exist</Message></Error>",
        );
        assert_eq!(e.code, "NoSuchLifecycleConfiguration");
        assert_eq!(e.message, "The lifecycle configuration does not exist");
        assert!(e.to_string().contains("404 NoSuchLifecycleConfiguration"));
    }

    #[test]
    fn plain_text_and_empty_bodies_still_say_something() {
        assert_eq!(
            api_error(400, "PUT", "/", b"Tenant not found").message,
            "Tenant not found"
        );
        assert_eq!(api_error(404, "GET", "/", b"").message, "not found");
    }

    #[test]
    fn xml_tags_are_unescaped() {
        assert_eq!(
            xml_tag("<a><B> x &amp; y </B></a>", "B").as_deref(),
            Some("x & y")
        );
        assert_eq!(xml_tag("<a/>", "B"), None);
    }
}
