//! AWS `SigV4` request signing for the S3 service: the client half, for
//! requests ObjectIO itself sends (the CLI's, and the replicator's to a
//! target cluster). [`crate::sigv4`] verifies them. It
//! follows the SDKs (`sdk/go/sigv4.go`, `sdk/python/objectio/_sigv4.py`)
//! exactly and is pinned to the same test vectors, so the three cannot drift.
//!
//! The rule that matters: the path that is signed and the path that is sent
//! are the same string. Callers build paths with [`escape_segment`] /
//! [`escape_path`] and the HTTP layer sends them verbatim.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

const ALGORITHM: &str = "AWS4-HMAC-SHA256";
const SERVICE: &str = "s3";
const TERMINATOR: &str = "aws4_request";

/// SHA-256 of the empty string: the payload hash of a request with no body.
pub const EMPTY_PAYLOAD_HASH: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Percent-encode everything outside RFC 3986's unreserved set. A space is
/// `%20`, never `+`, which `SigV4` rejects.
pub fn escape_rfc3986(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Escape one path segment, `/` included — for a value such as a user ARN
/// that must stay a single segment.
pub fn escape_segment(s: &str) -> String {
    escape_rfc3986(s)
}

/// Escape a path segment by segment, keeping the `/` separators.
pub fn escape_path(path: &str) -> String {
    path.split('/')
        .map(escape_rfc3986)
        .collect::<Vec<_>>()
        .join("/")
}

/// The canonical query string: pairs sorted by key then value, both escaped.
pub fn canonical_query(query: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (escape_rfc3986(k), escape_rfc3986(v)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// What to sign: everything that goes on the wire and is covered.
pub struct Request<'a> {
    pub method: &'a str,
    /// `host` or `host:port`, exactly as the Host header will carry it.
    pub host: &'a str,
    /// The already-escaped path, as sent.
    pub path: &'a str,
    pub query: &'a [(String, String)],
    pub content_type: Option<&'a str>,
    pub body: &'a [u8],
}

/// Credentials to sign with.
pub struct Signer<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
}

impl Signer<'_> {
    /// The headers to add: `Authorization`, `X-Amz-Date` and
    /// `X-Amz-Content-Sha256`.
    ///
    /// Signs `host`, the two `x-amz-*` headers and `content-type` when there
    /// is one — never `content-length`, which a proxy may legitimately
    /// rewrite.
    pub fn sign(&self, req: &Request<'_>, now: DateTime<Utc>) -> Vec<(&'static str, String)> {
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date_stamp = now.format("%Y%m%d").to_string();
        let payload_hash = if req.body.is_empty() {
            EMPTY_PAYLOAD_HASH.to_string()
        } else {
            sha256_hex(req.body)
        };

        let mut headers: Vec<(&str, String)> = vec![
            ("host", req.host.trim().to_string()),
            ("x-amz-content-sha256", payload_hash.clone()),
            ("x-amz-date", amz_date.clone()),
        ];
        if let Some(ct) = req.content_type {
            headers.push(("content-type", ct.trim().to_string()));
        }
        headers.sort_by(|a, b| a.0.cmp(b.0));

        let canonical_headers: String = headers.iter().fold(String::new(), |mut acc, (k, v)| {
            use std::fmt::Write as _;
            let _ = writeln!(acc, "{k}:{v}");
            acc
        });
        let signed_headers = headers
            .iter()
            .map(|(k, _)| *k)
            .collect::<Vec<_>>()
            .join(";");
        let path = if req.path.is_empty() { "/" } else { req.path };

        let canonical_request = [
            req.method,
            path,
            &canonical_query(req.query),
            &canonical_headers,
            &signed_headers,
            &payload_hash,
        ]
        .join("\n");

        let scope = format!("{date_stamp}/{}/{SERVICE}/{TERMINATOR}", self.region);
        let string_to_sign = [
            ALGORITHM,
            &amz_date,
            &scope,
            &sha256_hex(canonical_request.as_bytes()),
        ]
        .join("\n");

        let mut key = hmac_sha256(format!("AWS4{}", self.secret_key).as_bytes(), &date_stamp);
        key = hmac_sha256(&key, self.region);
        key = hmac_sha256(&key, SERVICE);
        key = hmac_sha256(&key, TERMINATOR);
        let signature = hex::encode(hmac_sha256(&key, &string_to_sign));

        vec![
            (
                "authorization",
                format!(
                    "{ALGORITHM} Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
                    self.access_key
                ),
            ),
            ("x-amz-date", amz_date),
            ("x-amz-content-sha256", payload_hash),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    // Shared verbatim with sdk/go/sigv4_test.go and
    // sdk/python/tests/test_sigv4.py.
    const AK: &str = "AKIAEXAMPLE";
    const SK: &str = "secretkeyexample";
    const WANT_JSON_POST: &str = "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260914/us-east-1/s3/aws4_request, \
        SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, \
        Signature=dba80b89d2f2e7762c8e8bb324eb9a214195dd4f46f1c23ded0cba0e3f1de1ff";
    const WANT_AWKWARD_KEY_GET: &str = "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20260914/us-east-1/s3/aws4_request, \
        SignedHeaders=host;x-amz-content-sha256;x-amz-date, \
        Signature=551ff8cbf5e240b59d0db4470dbc862a781c9bb7295112ed76a64b961e863264";

    fn fixed() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 14, 12, 0, 0).unwrap()
    }

    fn signer() -> Signer<'static> {
        Signer {
            access_key: AK,
            secret_key: SK,
            region: "us-east-1",
        }
    }

    fn header<'a>(h: &'a [(&str, String)], name: &str) -> &'a str {
        h.iter()
            .find(|(k, _)| *k == name)
            .map(|(_, v)| v.as_str())
            .unwrap()
    }

    #[test]
    fn a_json_post_matches_the_sdk_vector() {
        let body = br#"{"name":"ws-1","tenant":"platform"}"#;
        let h = signer().sign(
            &Request {
                method: "POST",
                host: "s3.example.com",
                path: "/_admin/buckets",
                query: &[],
                content_type: Some("application/json"),
                body,
            },
            fixed(),
        );
        assert_eq!(header(&h, "authorization"), WANT_JSON_POST);
        assert_eq!(header(&h, "x-amz-date"), "20260914T120000Z");
    }

    #[test]
    fn a_path_with_a_space_and_a_hash_matches_the_sdk_vector() {
        let path = escape_path("/_admin/buckets/b/objects/q1 final#draft.txt");
        let h = signer().sign(
            &Request {
                method: "GET",
                host: "s3.example.com",
                path: &path,
                query: &[],
                content_type: None,
                body: b"",
            },
            fixed(),
        );
        assert_eq!(header(&h, "authorization"), WANT_AWKWARD_KEY_GET);
    }

    #[test]
    fn an_empty_body_uses_the_known_hash() {
        let h = signer().sign(
            &Request {
                method: "GET",
                host: "s3.example.com",
                path: "/_admin/users",
                query: &[],
                content_type: None,
                body: b"",
            },
            fixed(),
        );
        assert_eq!(header(&h, "x-amz-content-sha256"), EMPTY_PAYLOAD_HASH);
    }

    #[test]
    fn escape_path_keeps_separators() {
        for (input, want) in [
            ("/_admin/buckets", "/_admin/buckets"),
            ("/a/b c", "/a/b%20c"),
            ("/a/b#c", "/a/b%23c"),
            ("/a/b+c", "/a/b%2Bc"),
            ("/a/~tilde", "/a/~tilde"),
            (
                "/_admin/buckets/b/objects/x/y/z.json",
                "/_admin/buckets/b/objects/x/y/z.json",
            ),
        ] {
            assert_eq!(escape_path(input), want, "{input}");
        }
    }

    #[test]
    fn a_segment_escapes_its_slashes() {
        assert_eq!(
            escape_segment("arn:obio:iam::acme:user/u1"),
            "arn%3Aobio%3Aiam%3A%3Aacme%3Auser%2Fu1"
        );
    }

    #[test]
    fn rfc3986_uses_percent_20_not_plus() {
        assert_eq!(escape_rfc3986("a b"), "a%20b");
    }

    #[test]
    fn canonical_query_sorts_and_escapes() {
        let q = vec![
            ("b".to_string(), "2".to_string()),
            ("a".to_string(), "1".to_string()),
            ("c".to_string(), "x y".to_string()),
        ];
        assert_eq!(canonical_query(&q), "a=1&b=2&c=x%20y");
        // A bare S3 subresource is `key=`, which is how the gateway
        // canonicalises `?lifecycle` too.
        assert_eq!(
            canonical_query(&[("lifecycle".to_string(), String::new())]),
            "lifecycle="
        );
    }

    /// What the gateway's own verifier accepts — not just what the SDK
    /// vectors say — for the shapes the CLI sends: a query string, a
    /// subresource, an escaped segment, a JSON body.
    #[test]
    fn the_gateway_verifier_accepts_what_this_signs() {
        type Case<'a> = (
            &'a str,
            String,
            Vec<(String, String)>,
            Option<&'a str>,
            &'a [u8],
        );
        use std::sync::Arc;
        let store = crate::UserStore::new();
        let user = store.create_user("cli-test").unwrap();
        let key = store.create_access_key(&user.user_id).unwrap();
        let verifier = crate::SigV4Verifier::new(Arc::new(store), "us-east-1");
        let s = Signer {
            access_key: &key.access_key_id,
            secret_key: &key.secret_access_key,
            region: "us-east-1",
        };

        let cases: Vec<Case> = vec![
            (
                "GET",
                "/_admin/policies".into(),
                vec![("tenant".into(), "acme corp".into())],
                None,
                b"",
            ),
            (
                "PUT",
                "/bkt".into(),
                vec![("lifecycle".into(), String::new())],
                Some("application/xml"),
                b"<LifecycleConfiguration/>",
            ),
            (
                "DELETE",
                format!(
                    "/_admin/tenants/acme/admins/{}",
                    escape_segment("arn:obio:iam::acme:user/u1")
                ),
                vec![],
                None,
                b"",
            ),
            (
                "POST",
                "/_admin/users".into(),
                vec![],
                Some("application/json"),
                br#"{"display_name":"x"}"#,
            ),
        ];
        for (method, path, query, ct, body) in cases {
            let headers = s.sign(
                &Request {
                    method,
                    host: "127.0.0.1:9000",
                    path: &path,
                    query: &query,
                    content_type: ct,
                    body,
                },
                Utc::now(),
            );
            let qs = if query.is_empty() {
                String::new()
            } else {
                format!("?{}", canonical_query(&query))
            };
            let mut b = http::Request::builder()
                .method(method)
                .uri(format!("http://127.0.0.1:9000{path}{qs}"))
                .header("host", "127.0.0.1:9000");
            if let Some(ct) = ct {
                b = b.header("content-type", ct);
            }
            for (k, v) in &headers {
                b = b.header(*k, v);
            }
            let req = b.body(()).unwrap();
            verifier
                .verify(&req)
                .unwrap_or_else(|e| panic!("{method} {path}{qs} rejected: {e}"));
        }
    }
}
