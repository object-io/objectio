//! What an object is served with: the standard headers it was written
//! with, the `response-*` overrides a GET may ask for, and a plain refusal
//! for sub-resources that aren't implemented.

use objectio_e2e::Cluster;

#[test]
fn an_object_keeps_its_standard_headers() {
    let c = Cluster::start();
    c.request("PUT", "/hdrs", &[]).expect(200);
    c.request_with_headers(
        "PUT",
        "/hdrs/report.csv",
        b"a,b\n",
        &[
            ("Cache-Control", "max-age=60"),
            ("Content-Disposition", "attachment; filename=\"q3.csv\""),
            ("Content-Language", "en"),
            ("Expires", "Wed, 21 Oct 2037 07:28:00 GMT"),
            ("x-amz-meta-owner", "finance"),
        ],
    )
    .expect(200);
    for method in ["GET", "HEAD"] {
        let r = c.request(method, "/hdrs/report.csv", &[]);
        assert_eq!(r.header("cache-control").as_deref(), Some("max-age=60"));
        assert_eq!(
            r.header("content-disposition").as_deref(),
            Some("attachment; filename=\"q3.csv\"")
        );
        assert_eq!(r.header("content-language").as_deref(), Some("en"));
        assert_eq!(
            r.header("expires").as_deref(),
            Some("Wed, 21 Oct 2037 07:28:00 GMT")
        );
        assert_eq!(r.header("x-amz-meta-owner").as_deref(), Some("finance"));
        // Kept as headers, not leaked as metadata.
        assert!(
            r.headers.iter().all(|(k, _)| !k.contains("objectio")),
            "{:?}",
            r.headers
        );
    }
    // A copy keeps them.
    c.request_with_headers(
        "PUT",
        "/hdrs/copy.csv",
        &[],
        &[("x-amz-copy-source", "/hdrs/report.csv")],
    )
    .expect(200);
    assert_eq!(
        c.request("HEAD", "/hdrs/copy.csv", &[])
            .header("cache-control")
            .as_deref(),
        Some("max-age=60")
    );
}

#[test]
fn a_get_can_ask_for_its_own_response_headers_unless_anonymous() {
    let c = Cluster::start();
    c.request("PUT", "/ovr", &[]).expect(200);
    c.request("PUT", "/ovr/k", b"data").expect(200);
    let r = c.request(
        "GET",
        "/ovr/k?response-content-disposition=attachment; filename=x.bin&response-content-type=application/x-test",
        &[],
    );
    r.expect(200);
    assert_eq!(
        r.header("content-disposition").as_deref(),
        Some("attachment; filename=x.bin")
    );
    assert_eq!(
        r.header("content-type").as_deref(),
        Some("application/x-test")
    );
    assert_eq!(r.bytes, b"data");
    // Through a presigned link too: the usual way to force a download name.
    let url = c.presign("GET", "/ovr/k?response-content-disposition=attachment", 300);
    let p = c.fetch("GET", &url, &[]);
    assert_eq!(
        p.header("content-disposition").as_deref(),
        Some("attachment")
    );
    // Never for anonymous callers, as S3.
    let anon = c.fetch(
        "GET",
        &format!("{}/ovr/k?response-content-type=text/html", c.endpoint),
        &[],
    );
    assert!(anon.status == 400 || anon.status == 403, "{}", anon.status);
}

#[test]
fn unimplemented_sub_resources_are_refused_not_misread() {
    let c = Cluster::start();
    c.request("PUT", "/subr", &[]).expect(200);
    c.request("PUT", "/subr/k", b"x").expect(200);
    for (method, path) in [
        ("GET", "/subr?website"),
        ("PUT", "/subr?logging"),
        ("GET", "/subr?notification"),
        ("PUT", "/subr?replication"),
        ("POST", "/subr/k?restore"),
    ] {
        let r = c.request(method, path, &[]);
        assert_eq!(r.status, 501, "{method} {path}: {}", r.text());
        assert!(r.text().contains("NotImplemented"), "{}", r.text());
    }
    // The bucket was neither listed nor re-created; it's still there.
    c.request("GET", "/subr/k", &[]).expect(200);
}
