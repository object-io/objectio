//! Requests ceph's s3-tests found handled wrongly: a DELETE naming a
//! sub-resource the gateway doesn't handle, a request signed with `Date`
//! instead of `X-Amz-Date`, non-ASCII metadata, `aws-chunked` combined with
//! another content coding, `CreateBucket` of a taken name, bucket tagging.

use std::fmt::Write as _;

use base64::Engine as _;
use objectio_e2e::Cluster;
use serde_json::json;

fn bucket(c: &Cluster, name: &str) {
    c.json("POST", "/_admin/buckets", json!({ "name": name }))
        .expect_ok();
}

fn code(r: &objectio_e2e::Response) -> String {
    let xml = r.text();
    xml.split("<Code>")
        .nth(1)
        .and_then(|s| s.split("</Code>").next())
        .unwrap_or_default()
        .to_string()
}

/// A DELETE naming a sub-resource used to fall through to `DeleteBucket` or
/// `DeleteObject`: `DELETE /b?website` deleted the bucket.
#[test]
fn a_delete_of_an_unhandled_sub_resource_deletes_nothing() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "keep");
    for sub in [
        "website",
        "logging",
        "replication",
        "notification",
        "made-up",
    ] {
        let r = c.request("DELETE", &format!("/keep?{sub}"), &[]);
        assert_eq!(r.status, 405, "?{sub}: {}", r.text());
    }
    c.request("HEAD", "/keep", &[]).expect(200);

    c.request("PUT", "/keep/o", b"data").expect(200);
    for sub in ["acl", "retention", "legal-hold", "made-up"] {
        let r = c.request("DELETE", &format!("/keep/o?{sub}"), &[]);
        assert_eq!(r.status, 405, "?{sub}: {}", r.text());
    }
    assert_eq!(c.request("GET", "/keep/o", &[]).bytes, b"data");

    let r = c.request("DELETE", "/keep?ownershipControls", &[]);
    assert_eq!(r.status, 400, "{}", r.text());
    c.request("HEAD", "/keep", &[]).expect(200);

    // What is handled still is: the object, then the bucket.
    c.request("DELETE", "/keep/o", &[]).expect(204);
    let url = c.presign("DELETE", "/keep", 300);
    c.fetch("DELETE", &url, &[]).expect(204);
    c.request("HEAD", "/keep", &[]).expect(404);
}

/// Without `X-Amz-Date` a client signs the `Date` header; the gateway read
/// that RFC 1123 date as ISO 8601 and refused every such request.
#[test]
fn a_request_signed_with_the_date_header_is_accepted() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "dated");
    c.request_signed("PUT", "/dated/o", b"bar", &[], true)
        .expect(200);
    assert_eq!(c.request("GET", "/dated/o", &[]).bytes, b"bar");
}

/// A non-ASCII metadata value, sent as UTF-8 (Go, Rust SDKs) or as Latin-1
/// (Python's http.client), is signed and stored as the text it is, and read
/// back RFC 2047-encoded, as S3 returns it.
#[test]
fn non_ascii_metadata_is_kept() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "meta");
    let encoded = |s: &str| {
        format!(
            "=?UTF-8?B?{}?=",
            base64::engine::general_purpose::STANDARD.encode(s)
        )
    };
    for (key, sent) in [
        ("utf8", "Grüße, wörld".as_bytes()),
        ("latin1", b"Hello World\xe9".as_slice()),
    ] {
        c.request_signed(
            "PUT",
            &format!("/meta/{key}"),
            b"x",
            &[("x-amz-meta-greeting", sent)],
            false,
        )
        .expect(200);
        let want = if key == "utf8" {
            "Grüße, wörld"
        } else {
            "Hello Worldé"
        };
        let r = c.request("HEAD", &format!("/meta/{key}"), &[]);
        r.expect(200);
        assert_eq!(
            r.header("x-amz-meta-greeting"),
            Some(encoded(want)),
            "{key}"
        );
    }
}

fn chunked(data: &[u8]) -> Vec<u8> {
    let mut out = format!("{:x};chunk-signature=0\r\n", data.len()).into_bytes();
    out.extend_from_slice(data);
    out.extend_from_slice(b"\r\n0;chunk-signature=0\r\n\r\n");
    out
}

/// `aws-chunked` is the upload's framing; the coding before it belongs to
/// the object and is kept.
#[test]
fn the_content_coding_under_aws_chunked_is_kept() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "enc");
    c.request_with_headers(
        "PUT",
        "/enc/gz",
        &chunked(b"compressed"),
        &[("Content-Encoding", "gzip, aws-chunked")],
    )
    .expect(200);
    let r = c.request("GET", "/enc/gz", &[]);
    assert_eq!(r.bytes, b"compressed");
    assert_eq!(r.header("content-encoding").as_deref(), Some("gzip"));

    c.request_with_headers(
        "PUT",
        "/enc/plain",
        &chunked(b"plain"),
        &[("Content-Encoding", "aws-chunked")],
    )
    .expect(200);
    let r = c.request("GET", "/enc/plain", &[]);
    assert_eq!(r.bytes, b"plain");
    assert_eq!(r.header("content-encoding"), None);
}

/// An `aws-chunked` body cut short, or of the wrong length, is refused. It
/// used to be stored still framed, chunk headers and all, under the key.
#[test]
fn a_broken_aws_chunked_body_is_refused() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "cut");
    let whole = chunked(b"hello world");
    let cut = &whole[..whole.len() - 24];
    let r = c.request_with_headers("PUT", "/cut/a", cut, &[("Content-Encoding", "aws-chunked")]);
    assert_eq!(
        (r.status, code(&r).as_str()),
        (400, "IncompleteBody"),
        "{}",
        r.text()
    );
    c.request("HEAD", "/cut/a", &[]).expect(404);

    let r = c.request_with_headers(
        "PUT",
        "/cut/b",
        &whole,
        &[
            ("Content-Encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "99"),
        ],
    );
    assert_eq!(
        (r.status, code(&r).as_str()),
        (400, "IncompleteBody"),
        "{}",
        r.text()
    );
    c.request("HEAD", "/cut/b", &[]).expect(404);
}

/// Bucket names are one namespace: creating one another user holds is
/// "taken" (409), not "forbidden".
#[test]
fn creating_a_bucket_someone_else_holds_is_a_conflict() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "taken");
    let user = c
        .json("POST", "/_admin/users", json!({ "display_name": "other" }))
        .json();
    let id = user["user_id"].as_str().expect("user id").to_string();
    let key = c
        .json(
            "POST",
            &format!("/_admin/users/{id}/access-keys"),
            json!({}),
        )
        .json();
    let (ak, sk) = (
        key["access_key_id"].as_str().expect("key id").to_string(),
        key["secret_access_key"]
            .as_str()
            .expect("secret")
            .to_string(),
    );
    let r = c.request_as("PUT", "/taken", &[], &ak, &sk);
    assert_eq!(
        (r.status, code(&r).as_str()),
        (409, "BucketAlreadyExists"),
        "{}",
        r.text()
    );
    // A name nobody holds is still refused as forbidden when not granted.
    let r = c.request_as("PUT", "/free-name", &[], &ak, &sk);
    assert_ne!(r.status, 409, "{}", r.text());
}

#[test]
fn bucket_tags_are_set_read_and_removed() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "tagged");
    let r = c.request("GET", "/tagged?tagging", &[]);
    assert_eq!((r.status, code(&r).as_str()), (404, "NoSuchTagSet"));

    c.request(
        "PUT",
        "/tagged?tagging",
        b"<Tagging><TagSet><Tag><Key>team</Key><Value>ml</Value></Tag>\
          <Tag><Key>cost</Key><Value>a b</Value></Tag></TagSet></Tagging>",
    )
    .expect(204);
    let xml = c.request("GET", "/tagged?tagging", &[]).text();
    let cost = xml.find("<Key>cost</Key><Value>a b</Value>");
    let team = xml.find("<Key>team</Key><Value>ml</Value>");
    assert!(cost.is_some() && team.is_some() && cost < team, "{xml}");
    // The bucket itself was left as it was.
    c.request("HEAD", "/tagged", &[]).expect(200);

    let mut fifty_one = String::new();
    for i in 0..51 {
        write!(fifty_one, "<Tag><Key>k{i}</Key><Value>v</Value></Tag>").unwrap();
    }
    let r = c.request(
        "PUT",
        "/tagged?tagging",
        format!("<Tagging><TagSet>{fifty_one}</TagSet></Tagging>").as_bytes(),
    );
    assert_eq!((r.status, code(&r).as_str()), (400, "InvalidTag"));

    c.request("DELETE", "/tagged?tagging", &[]).expect(204);
    c.request("GET", "/tagged?tagging", &[]).expect(404);
    c.request("HEAD", "/tagged", &[]).expect(200);
}
