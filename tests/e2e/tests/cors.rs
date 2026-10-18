//! CORS: a bucket's `CORSConfiguration` is managed at `?cors`, preflights
//! are answered from it without credentials, and actual requests from an
//! allowed origin get its headers — on errors too. Nothing else changes:
//! every request is still authenticated and authorized.

use objectio_e2e::{Cluster, Response};

const CONFIG: &[u8] = br#"<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <CORSRule>
    <ID>app</ID>
    <AllowedOrigin>https://*.example.com</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedMethod>POST</AllowedMethod>
    <AllowedHeader>Content-*</AllowedHeader>
    <AllowedHeader>x-amz-*</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader>
    <MaxAgeSeconds>600</MaxAgeSeconds>
  </CORSRule>
  <CORSRule>
    <AllowedOrigin>*</AllowedOrigin>
    <AllowedMethod>HEAD</AllowedMethod>
  </CORSRule>
</CORSConfiguration>"#;

const APP: &str = "https://app.example.com";

fn preflight(c: &Cluster, path: &str, headers: &[(&str, &str)]) -> Response {
    c.fetch_with_headers("OPTIONS", &format!("{}{path}", c.endpoint), headers)
}

fn code(r: &Response) -> String {
    let text = r.text();
    text.split("<Code>")
        .nth(1)
        .and_then(|t| t.split("</Code>").next())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn a_cors_configuration_is_put_read_and_deleted() {
    let c = Cluster::start();
    c.request("PUT", "/cfg", &[]).expect(200);

    let r = c.request("GET", "/cfg?cors", &[]);
    assert_eq!(r.status, 404, "{}", r.text());
    assert_eq!(code(&r), "NoSuchCORSConfiguration");

    c.request("PUT", "/cfg?cors", CONFIG).expect(200);
    let r = c.request("GET", "/cfg?cors", &[]);
    r.expect(200);
    let text = r.text();
    for want in [
        "<ID>app</ID>",
        "<AllowedOrigin>https://*.example.com</AllowedOrigin>",
        "<AllowedMethod>POST</AllowedMethod>",
        "<AllowedHeader>x-amz-*</AllowedHeader>",
        "<ExposeHeader>ETag</ExposeHeader>",
        "<MaxAgeSeconds>600</MaxAgeSeconds>",
        "<AllowedOrigin>*</AllowedOrigin>",
    ] {
        assert!(text.contains(want), "{want} missing from {text}");
    }
    // The bucket's listing is untouched by the sub-resource.
    assert!(!text.contains("ListBucketResult"));

    // Refused as S3 refuses them; the stored configuration stays.
    for (body, want) in [
        (
            &b"<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin>\
               <AllowedMethod>PATCH</AllowedMethod></CORSRule></CORSConfiguration>"[..],
            "InvalidRequest",
        ),
        (
            b"<CORSConfiguration><CORSRule><AllowedOrigin>https://*.*.x</AllowedOrigin>\
               <AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>",
            "InvalidRequest",
        ),
        (
            b"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod>\
               </CORSRule></CORSConfiguration>",
            "MalformedXML",
        ),
        (b"<CORSConfiguration></CORSConfiguration>", "MalformedXML"),
        (b"not xml at all", "MalformedXML"),
    ] {
        let r = c.request("PUT", "/cfg?cors", body);
        assert_eq!(r.status, 400, "{}", r.text());
        assert_eq!(code(&r), want, "{}", r.text());
    }
    assert!(
        c.request("GET", "/cfg?cors", &[])
            .text()
            .contains("<ID>app</ID>")
    );

    c.request("DELETE", "/cfg?cors", &[]).expect(204);
    c.request("GET", "/cfg?cors", &[]).expect(404);
    // Deleting what isn't there is fine, as in S3.
    c.request("DELETE", "/cfg?cors", &[]).expect(204);

    // No bucket, no configuration.
    let r = c.request("PUT", "/nope?cors", CONFIG);
    assert_eq!(r.status, 404, "{}", r.text());
    assert_eq!(code(&r), "NoSuchBucket");
    let r = c.request("GET", "/nope?cors", &[]);
    assert_eq!(code(&r), "NoSuchBucket", "{}", r.text());

    // The configuration is the owner's: an anonymous caller can't read or
    // change it.
    for method in ["GET", "PUT", "DELETE"] {
        let r = c.fetch(method, &format!("{}/cfg?cors", c.endpoint), CONFIG);
        assert_eq!(r.status, 403, "anonymous {method} ?cors: {}", r.text());
    }
}

#[test]
fn preflights_are_answered_from_the_configuration_alone() {
    let c = Cluster::start();
    c.request("PUT", "/web", &[]).expect(200);
    let ask = [
        ("Origin", APP),
        ("Access-Control-Request-Method", "PUT"),
        ("Access-Control-Request-Headers", "Content-Type, X-Amz-Date"),
    ];

    // No configuration: refused, as S3 refuses it.
    let r = preflight(&c, "/web/photo.jpg", &ask);
    assert_eq!(r.status, 403, "{}", r.text());
    assert_eq!(code(&r), "AccessForbidden");
    assert!(r.header("access-control-allow-origin").is_none());

    c.request("PUT", "/web?cors", CONFIG).expect(200);
    // Takes effect at once on this gateway: the PUT dropped the cached
    // absence.
    for path in ["/web/photo.jpg", "/web", "/web/"] {
        let r = preflight(&c, path, &ask);
        assert_eq!(r.status, 200, "{path}: {}", r.text());
        assert_eq!(
            r.header("access-control-allow-origin").as_deref(),
            Some(APP)
        );
        assert_eq!(
            r.header("access-control-allow-credentials").as_deref(),
            Some("true")
        );
        assert_eq!(
            r.header("access-control-allow-methods").as_deref(),
            Some("GET, PUT, POST")
        );
        assert_eq!(
            r.header("access-control-allow-headers").as_deref(),
            Some("content-type, x-amz-date")
        );
        assert_eq!(
            r.header("access-control-expose-headers").as_deref(),
            Some("ETag")
        );
        assert_eq!(r.header("access-control-max-age").as_deref(), Some("600"));
        assert!(r.header("vary").unwrap_or_default().contains("Origin"));
        // Nothing about the bucket itself.
        assert!(r.bytes.is_empty(), "{}", r.text());
    }

    // The catch-all rule: any origin, HEAD only, no headers — and `*`
    // back, without credentials.
    let r = preflight(
        &c,
        "/web/k",
        &[
            ("Origin", "https://elsewhere.org"),
            ("Access-Control-Request-Method", "HEAD"),
        ],
    );
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(
        r.header("access-control-allow-origin").as_deref(),
        Some("*")
    );
    assert!(r.header("access-control-allow-credentials").is_none());

    // What no rule allows.
    for (origin, method, headers) in [
        ("https://evil.org", "PUT", ""),
        ("https://app.example.com.evil.org", "GET", ""),
        ("http://app.example.com", "PUT", ""),
        (APP, "DELETE", ""),
        (APP, "PUT", "authorization"),
        ("https://elsewhere.org", "HEAD", "x-amz-date"),
    ] {
        let mut h = vec![
            ("Origin", origin),
            ("Access-Control-Request-Method", method),
        ];
        if !headers.is_empty() {
            h.push(("Access-Control-Request-Headers", headers));
        }
        let r = preflight(&c, "/web/k", &h);
        assert_eq!(r.status, 403, "{origin} {method} {headers}: {}", r.text());
        assert_eq!(code(&r), "AccessForbidden");
        assert!(r.header("access-control-allow-origin").is_none());
    }

    // Malformed preflights, and a bucket that isn't there.
    let r = preflight(&c, "/web/k", &[("Access-Control-Request-Method", "GET")]);
    assert_eq!(r.status, 400, "{}", r.text());
    let r = preflight(&c, "/web/k", &[("Origin", APP)]);
    assert_eq!(r.status, 400, "{}", r.text());
    let r = preflight(&c, "/missing/k", &ask);
    assert_eq!(r.status, 404, "{}", r.text());
    assert_eq!(code(&r), "NoSuchBucket");

    // Deleted: refused again at once.
    c.request("DELETE", "/web?cors", &[]).expect(204);
    assert_eq!(preflight(&c, "/web/k", &ask).status, 403);
}

#[test]
fn actual_requests_from_an_allowed_origin_get_the_headers_errors_included() {
    let c = Cluster::start();
    c.request("PUT", "/site", &[]).expect(200);
    c.request("PUT", "/site/index.html", b"<html></html>")
        .expect(200);
    c.request("PUT", "/plain", &[]).expect(200);
    c.request("PUT", "/plain/k", b"x").expect(200);
    c.request("PUT", "/site?cors", CONFIG).expect(200);

    // Signed and allowed.
    let r = c.request_with_headers("GET", "/site/index.html", &[], &[("Origin", APP)]);
    r.expect(200);
    assert_eq!(r.bytes, b"<html></html>");
    assert_eq!(
        r.header("access-control-allow-origin").as_deref(),
        Some(APP)
    );
    assert_eq!(
        r.header("access-control-expose-headers").as_deref(),
        Some("ETag")
    );
    assert!(r.header("access-control-allow-headers").is_none());

    // An error a browser must be able to read: anonymous, refused — with
    // the headers, and still refused.
    let r = c.fetch_with_headers(
        "GET",
        &format!("{}/site/index.html", c.endpoint),
        &[("Origin", APP)],
    );
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(r.text().contains("AccessDenied"), "{}", r.text());
    assert_eq!(
        r.header("access-control-allow-origin").as_deref(),
        Some(APP)
    );
    // A missing key, signed.
    let r = c.request_with_headers("GET", "/site/missing", &[], &[("Origin", APP)]);
    assert_eq!(r.status, 404, "{}", r.text());
    assert_eq!(
        r.header("access-control-allow-origin").as_deref(),
        Some(APP)
    );

    // No match, no headers: another origin, a method the rule doesn't
    // allow, a bucket without a configuration, no Origin at all.
    for r in [
        c.request_with_headers(
            "GET",
            "/site/index.html",
            &[],
            &[("Origin", "https://x.org")],
        ),
        c.request_with_headers("DELETE", "/site/nothing", &[], &[("Origin", APP)]),
        c.request_with_headers("GET", "/plain/k", &[], &[("Origin", APP)]),
        c.request("GET", "/site/index.html", &[]),
    ] {
        assert!(
            r.header("access-control-allow-origin").is_none(),
            "{:?}",
            r.headers
        );
        assert!(r.header("vary").is_none(), "{:?}", r.headers);
    }
}

#[test]
fn the_control_plane_is_left_alone() {
    let c = Cluster::start();
    c.request("PUT", "/any", &[]).expect(200);
    c.request("PUT", "/any?cors", CONFIG).expect(200);
    let ask = [("Origin", APP), ("Access-Control-Request-Method", "GET")];
    for path in [
        "/_admin/users",
        "/_console/api/session",
        "/iceberg/v1/config",
        "/delta-sharing/v1/shares",
        "/health",
    ] {
        let r = preflight(&c, path, &ask);
        assert!(
            r.header("access-control-allow-origin").is_none(),
            "{path}: {:?}",
            r.headers
        );
        assert_ne!(code(&r), "AccessForbidden", "{path}: {}", r.text());
        let r = c.request_with_headers("GET", path, &[], &[("Origin", APP)]);
        assert!(
            r.header("access-control-allow-origin").is_none(),
            "{path}: {:?}",
            r.headers
        );
    }
}
