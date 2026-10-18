//! ACLs, bucket owner enforced (AWS's default since 2023): the bucket's
//! owner has `FULL_CONTROL` of everything in it, and access is granted by
//! policies alone. An ACL saying just that is accepted; no other is.

use objectio_e2e::Cluster;
use serde_json::json;

const PUBLIC_READ: &str = "<AccessControlPolicy><Owner><ID>x</ID></Owner><AccessControlList>\
    <Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
    <URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>\
    <Permission>READ</Permission></Grant></AccessControlList></AccessControlPolicy>";

/// A `PutObjectAcl` used to be taken as a `PutObject`: the ACL document became
/// the object's data.
#[test]
fn putting_an_object_acl_never_touches_the_object() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "acl"}))
        .expect_ok();
    c.request("PUT", "/acl/k", b"precious").expect(200);

    let r = c.request("PUT", "/acl/k?acl", PUBLIC_READ.as_bytes());
    assert_eq!(r.status, 400, "{}", r.text());
    assert!(r.text().contains("AccessControlListNotSupported"));
    let r = c.request_with_headers("PUT", "/acl/k?acl", &[], &[("x-amz-acl", "private")]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(c.request("GET", "/acl/k", &[]).bytes, b"precious");

    let acl = c.request("GET", "/acl/k?acl", &[]);
    assert_eq!(acl.status, 200);
    assert!(
        acl.text().contains("<Permission>FULL_CONTROL</Permission>"),
        "{}",
        acl.text()
    );
    assert!(
        !acl.text().contains("precious"),
        "GetObjectAcl returned the object"
    );
    let bucket_acl = c.request("GET", "/acl?acl", &[]).text();
    assert!(bucket_acl.contains("<AccessControlPolicy"), "{bucket_acl}");
}

/// No write can make data public through an ACL.
#[test]
fn public_acls_are_refused_on_writes() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "acl"}))
        .expect_ok();
    for (method, path) in [
        ("PUT", "/acl/k"),
        ("PUT", "/newbucket"),
        ("POST", "/acl/m?uploads"),
    ] {
        let r = c.request_with_headers(method, path, b"x", &[("x-amz-acl", "public-read")]);
        assert_eq!(r.status, 400, "{method} {path}: {}", r.text());
    }
    assert_eq!(
        c.request("GET", "/acl/k", &[]).status,
        404,
        "a refused PUT stored the object"
    );
    c.request_with_headers(
        "PUT",
        "/acl/k",
        b"x",
        &[("x-amz-acl", "bucket-owner-full-control")],
    )
    .expect(200);
}
