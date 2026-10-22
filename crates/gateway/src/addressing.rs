//! Which bucket a request addresses: the one in its path (path-style,
//! `s3.example.com/bucket/key`) or the one in its host name (virtual-hosted
//! style, `bucket.s3.example.com/key`), as S3 reads them.
//!
//! The gateway is told its S3 domains (`--s3-domain`). A host that is
//! `<bucket>.<domain>` addresses that bucket, dotted names included: its
//! path is the key, and the request is rewritten to `/<bucket><path>` before
//! it is routed, so everything after (the routes, authorization and bucket
//! policies, CORS, metrics, the audit log) sees the one form. The client
//! signed the path it sent, so SigV4 is checked against that
//! ([`crate::origin::ClientUri`]). Every other host — a domain itself, an
//! address, `localhost`, a name under no domain — is path-style, as it
//! always was, and path-style keeps working with domains set, as on AWS.
//!
//! What can't be resolved is refused, never guessed:
//!
//! - a host under a domain whose bucket part isn't a bucket name
//!   (`InvalidBucketName`);
//! - on a path-style host, a bucket operation on `/` (`InvalidRequest`).
//!   Only a client that put the bucket in the host sends one — `PUT /` to
//!   create it, `GET /?list-type=2` to list it — and read path-style it
//!   would be a different request: the listing answered with the caller's
//!   buckets.
//!
//! The domains are not derived from `--external-endpoint`: that would make
//! every name under the endpoint's host a bucket, and gateways reached at
//! names under the service's own (`gw1.s3.example.com`) would break.
//! Without a domain, a request whose path-style reading is also a valid
//! request (`GET /`, anything on `/name`) can't be told from a
//! virtual-hosted one, and is read path-style.

use std::net::IpAddr;
use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, Method, StatusCode, Uri, header},
    middleware::Next,
    response::Response,
};

use crate::origin::ClientUri;
use crate::s3::S3Error;

/// The domains a host can name a bucket under, longest first, so that the
/// most specific matches: with `s3.example.com` and `example.com`,
/// `bkt.s3.example.com` is bucket `bkt`, not `bkt.s3`.
#[derive(Clone, Debug, Default)]
pub struct S3Domains(Arc<[String]>);

/// How a request's host addresses a bucket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Addressing {
    /// Through the path: its first segment, if any.
    Path,
    /// The host is `<bucket>.<domain>`.
    Virtual(String),
    /// The host is `<label>.<domain>`, and the label is no bucket name.
    BadBucket(String),
}

/// On a request whose bucket came from its host: which.
#[derive(Clone, Debug)]
pub struct VirtualHost(pub String);

/// On a request whose host is under a domain but names no valid bucket.
#[derive(Clone, Debug)]
struct Unresolved(String);

impl S3Domains {
    /// The domains given as `--s3-domain` values, each possibly a
    /// comma-separated list.
    ///
    /// # Errors
    /// A value that is not a plain DNS name: a URL, a name with a port, an
    /// address, a wildcard.
    pub fn parse(values: &[String]) -> Result<Self, String> {
        let mut out: Vec<String> = Vec::new();
        for given in values.iter().flat_map(|v| v.split(',')) {
            let domain = given.trim().trim_end_matches('.').to_ascii_lowercase();
            if domain.is_empty() {
                continue;
            }
            if domain.contains('/') {
                return Err(format!(
                    "--s3-domain {given}: a host name (s3.example.com), not a URL"
                ));
            }
            if domain.starts_with("*.") {
                return Err(format!(
                    "--s3-domain {given}: give the domain without the wildcard; \
                     every name under it addresses a bucket"
                ));
            }
            if domain.parse::<IpAddr>().is_ok() || domain.starts_with('[') {
                return Err(format!(
                    "--s3-domain {given}: an address has no names under it; give a DNS name"
                ));
            }
            if domain.contains(':') {
                return Err(format!(
                    "--s3-domain {given}: no port; a request's port is ignored when its \
                     host is matched"
                ));
            }
            if !dns_name(&domain) {
                return Err(format!("--s3-domain {given}: not a DNS name"));
            }
            if !out.contains(&domain) {
                out.push(domain);
            }
        }
        out.sort_by_key(|d| std::cmp::Reverse(d.len()));
        Ok(Self(out.into()))
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.0
    }

    /// How a request with this `Host` addresses its bucket. The port is
    /// ignored, and case: host names are case-insensitive, bucket names
    /// lowercase.
    #[must_use]
    pub fn resolve(&self, host: &str) -> Addressing {
        let Some(name) = host_name(host) else {
            return Addressing::Path;
        };
        for domain in self.0.iter() {
            if name == *domain {
                return Addressing::Path;
            }
            if let Some(label) = name
                .strip_suffix(domain.as_str())
                .and_then(|rest| rest.strip_suffix('.'))
            {
                return if objectio_common::BucketName::new(label).is_ok() {
                    Addressing::Virtual(label.to_string())
                } else {
                    Addressing::BadBucket(label.to_string())
                };
            }
        }
        Addressing::Path
    }
}

/// A DNS name: dot-separated labels of letters, digits and hyphens, none
/// empty, none starting or ending with a hyphen.
fn dns_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

/// The name in a `Host` value, lowercased, without its port or a trailing
/// dot; `None` for an address, which names no bucket.
fn host_name(host: &str) -> Option<String> {
    let host = host.trim();
    if host.starts_with('[') {
        return None; // An IPv6 literal.
    }
    let name = match host.rsplit_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    };
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(name)
}

/// The host a request was sent to: its `Host` header, or the URI's
/// authority (HTTP/2 carries it there).
fn request_host<B>(request: &axum::http::Request<B>) -> Option<String> {
    request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| request.uri().authority().map(ToString::to_string))
}

/// Before routing: a request whose host names its bucket is rewritten to
/// the path-style form, the URI it was sent with kept for its signature.
/// One whose host can't be resolved is marked, for [`refusal_layer`] to
/// refuse where the refusal is audited.
pub fn rewrite<B>(
    domains: &S3Domains,
    mut request: axum::http::Request<B>,
) -> axum::http::Request<B> {
    if domains.is_empty() {
        return request;
    }
    let Some(host) = request_host(&request) else {
        return request;
    };
    match domains.resolve(&host) {
        Addressing::Path => {}
        Addressing::BadBucket(label) => {
            request.extensions_mut().insert(Unresolved(label));
        }
        Addressing::Virtual(bucket) => {
            let sent = request.uri().clone();
            let path = match sent.path() {
                "" => "/",
                p => p,
            };
            let path_and_query = match sent.query() {
                Some(q) => format!("/{bucket}{path}?{q}"),
                None => format!("/{bucket}{path}"),
            };
            let mut parts = sent.clone().into_parts();
            // The bucket is a valid bucket name, so the path stays valid.
            let Ok(pq) = path_and_query.parse() else {
                return request;
            };
            parts.path_and_query = Some(pq);
            let Ok(routed) = Uri::from_parts(parts) else {
                return request;
            };
            *request.uri_mut() = routed;
            request.extensions_mut().insert(ClientUri(sent));
            request.extensions_mut().insert(VirtualHost(bucket));
        }
    }
    request
}

/// Refuse, with an S3 error, a request whose bucket can't be resolved: a
/// host under a domain that names no valid bucket, or a bucket operation
/// on `/` from a host that names no bucket.
pub async fn refusal_layer(
    State(domains): State<S3Domains>,
    request: Request,
    next: Next,
) -> Response {
    if let Some(Unresolved(label)) = request.extensions().get::<Unresolved>() {
        return S3Error::xml_response(
            "InvalidBucketName",
            &format!(
                "The host {} names bucket \"{label}\", which is not a valid bucket name",
                request_host(&request).unwrap_or_default()
            ),
            StatusCode::BAD_REQUEST,
        );
    }
    if request.extensions().get::<VirtualHost>().is_none()
        && request.uri().path() == "/"
        && needs_a_bucket(request.method(), request.uri().query(), request.headers())
    {
        let host = request_host(&request).unwrap_or_default();
        let message = if domains.is_empty() {
            "This is a bucket operation, but the request names no bucket in its path. \
             A client that puts the bucket in the host name (virtual-hosted style) \
             needs the gateway's S3 domain configured (--s3-domain); otherwise \
             address the bucket in the path: /<bucket>/<key>."
                .to_string()
        } else {
            format!(
                "This is a bucket operation, but the request names no bucket in its \
                 path, and its host {host} is not under this gateway's S3 domain ({}). \
                 Address the bucket in the path (/<bucket>/<key>), or in the host \
                 (<bucket>.<domain>).",
                domains.names().join(", ")
            )
        };
        return S3Error::xml_response("InvalidRequest", &message, StatusCode::BAD_REQUEST);
    }
    next.run(request).await
}

/// Whether a request on `/` is one only a bucket can take: anything but
/// ListBuckets (`GET /`, with its own parameters), the IAM and STS query
/// API (`Action=`), a presigned ListBuckets, and a CORS preflight.
fn needs_a_bucket(method: &Method, query: Option<&str>, headers: &HeaderMap) -> bool {
    let params: Vec<(&str, &str)> = query
        .unwrap_or_default()
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
        .collect();
    let has = |name: &str| params.iter().any(|(k, _)| *k == name);
    match *method {
        // HeadBucket: ListBuckets has no HEAD.
        Method::HEAD => true,
        Method::GET => {
            !has("Action")
                && params.iter().any(|(k, v)| match *k {
                    "max-buckets" | "continuation-token" | "prefix" | "bucket-region" => false,
                    // The SDKs that name the operation in the query.
                    "x-id" => *v != "ListBuckets",
                    k => !k.to_ascii_lowercase().starts_with("x-amz-"),
                })
        }
        // CreateBucket, DeleteBucket.
        Method::PUT | Method::DELETE => true,
        // DeleteObjects, and a browser's form upload (POST Object).
        Method::POST => {
            has("delete")
                || headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|t| {
                        t.split(';')
                            .next()
                            .is_some_and(|t| t.trim().eq_ignore_ascii_case("multipart/form-data"))
                    })
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains(list: &[&str]) -> S3Domains {
        S3Domains::parse(&list.iter().map(ToString::to_string).collect::<Vec<_>>()).unwrap()
    }

    fn virt(b: &str) -> Addressing {
        Addressing::Virtual(b.to_string())
    }

    #[test]
    fn a_bucket_label_in_front_of_a_domain_is_the_bucket() {
        let d = domains(&["s3.example.com"]);
        assert_eq!(d.resolve("photos.s3.example.com"), virt("photos"));
        assert_eq!(d.resolve("photos.s3.example.com:9000"), virt("photos"));
        // Host names are case-insensitive; a trailing dot is the same name.
        assert_eq!(d.resolve("Photos.S3.Example.COM."), virt("photos"));
        // Dotted bucket names are names.
        assert_eq!(d.resolve("my.photos.s3.example.com"), virt("my.photos"));
    }

    #[test]
    fn the_domain_itself_addresses_and_other_hosts_are_path_style() {
        let d = domains(&["s3.example.com"]);
        for host in [
            "s3.example.com",
            "s3.example.com:443",
            "127.0.0.1:9000",
            "10.1.2.3",
            "[::1]:9000",
            "localhost:9000",
            "objectio-gateway",
            "photos.other.example.com",
            // Only a whole label in front of the domain counts.
            "photoss3.example.com",
            "",
        ] {
            assert_eq!(d.resolve(host), Addressing::Path, "{host}");
        }
        assert_eq!(
            S3Domains::default().resolve("photos.s3.example.com"),
            Addressing::Path
        );
    }

    #[test]
    fn a_label_that_is_no_bucket_name_is_unresolved() {
        let d = domains(&["s3.example.com"]);
        for label in ["ab", "bad_name", "-x-y", "a..b", "192.168.1.1"] {
            assert_eq!(
                d.resolve(&format!("{label}.s3.example.com")),
                Addressing::BadBucket(label.to_string()),
                "{label}"
            );
        }
    }

    #[test]
    fn the_longest_domain_a_host_is_under_wins() {
        let d = domains(&["example.com", "s3.example.com"]);
        assert_eq!(d.resolve("bkt.s3.example.com"), virt("bkt"));
        assert_eq!(d.resolve("s3.example.com"), Addressing::Path);
        assert_eq!(d.resolve("bkt.example.com"), virt("bkt"));
        let d = domains(&["s3.example.com,s3.eu.example.com"]);
        assert_eq!(d.resolve("logs.s3.eu.example.com"), virt("logs"));
    }

    #[test]
    fn a_domain_must_be_a_plain_dns_name() {
        for bad in [
            "https://s3.example.com",
            "s3.example.com/x",
            "s3.example.com:9000",
            "*.s3.example.com",
            "10.0.0.1",
            "[::1]",
            "s3_example.com",
            "-s3.example.com",
            "a..b",
        ] {
            assert!(S3Domains::parse(&[bad.to_string()]).is_err(), "{bad}");
        }
        let d = domains(&[" S3.Example.com. ", "", "s3.example.com"]);
        assert_eq!(d.names(), ["s3.example.com"]);
    }

    fn rewritten(d: &S3Domains, host: &str, uri: &str) -> axum::http::Request<()> {
        let req = axum::http::Request::builder()
            .uri(uri)
            .header(header::HOST, host)
            .body(())
            .unwrap();
        rewrite(d, req)
    }

    #[test]
    fn a_virtual_hosted_request_is_routed_path_style_and_keeps_what_was_signed() {
        let d = domains(&["s3.example.com"]);
        let req = rewritten(&d, "photos.s3.example.com", "/a/b%20c.jpg?versionId=1");
        assert_eq!(req.uri(), "/photos/a/b%20c.jpg?versionId=1");
        assert_eq!(crate::origin::sent_uri(&req), "/a/b%20c.jpg?versionId=1");
        assert_eq!(req.extensions().get::<VirtualHost>().unwrap().0, "photos");

        // A bucket operation: the bucket's own path.
        let req = rewritten(&d, "photos.s3.example.com", "/?list-type=2");
        assert_eq!(req.uri(), "/photos/?list-type=2");
        assert_eq!(crate::origin::sent_uri(&req), "/?list-type=2");

        // Path-style is left alone, and so is everything without domains.
        let req = rewritten(&d, "s3.example.com", "/photos/a");
        assert_eq!(req.uri(), "/photos/a");
        assert!(req.extensions().get::<ClientUri>().is_none());
        let req = rewritten(&S3Domains::default(), "photos.s3.example.com", "/a");
        assert_eq!(req.uri(), "/a");
    }

    #[test]
    fn only_bucket_operations_on_root_need_a_bucket() {
        let none = HeaderMap::new();
        let needs = |m: Method, q: Option<&str>| needs_a_bucket(&m, q, &none);
        // ListBuckets, in every form a client sends it.
        assert!(!needs(Method::GET, None));
        assert!(!needs(Method::GET, Some("max-buckets=10&prefix=a")));
        assert!(!needs(Method::GET, Some("x-id=ListBuckets")));
        assert!(!needs(
            Method::GET,
            Some("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=00")
        ));
        // The IAM and STS query API.
        assert!(!needs(
            Method::GET,
            Some("Action=ListUsers&Version=2010-05-08")
        ));
        assert!(!needs(Method::POST, None));
        assert!(!needs(Method::OPTIONS, None));
        // What only a bucket takes.
        assert!(needs(Method::GET, Some("list-type=2")));
        assert!(needs(Method::GET, Some("encoding-type=url")));
        assert!(needs(Method::GET, Some("location")));
        assert!(needs(Method::GET, Some("x-id=ListObjectsV2")));
        assert!(needs(Method::HEAD, None));
        assert!(needs(Method::PUT, None));
        assert!(needs(Method::DELETE, None));
        assert!(needs(Method::POST, Some("delete")));
        let mut form = HeaderMap::new();
        form.insert(
            header::CONTENT_TYPE,
            "multipart/form-data; boundary=x".parse().unwrap(),
        );
        assert!(needs_a_bucket(&Method::POST, None, &form));
    }
}
