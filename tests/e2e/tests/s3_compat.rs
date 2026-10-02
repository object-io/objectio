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
        &[
            ("Content-Encoding", "gzip, aws-chunked"),
            ("x-amz-decoded-content-length", "10"),
        ],
    )
    .expect(200);
    let r = c.request("GET", "/enc/gz", &[]);
    assert_eq!(r.bytes, b"compressed");
    assert_eq!(r.header("content-encoding").as_deref(), Some("gzip"));

    c.request_with_headers(
        "PUT",
        "/enc/plain",
        &chunked(b"plain"),
        &[
            ("Content-Encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "5"),
        ],
    )
    .expect(200);
    let r = c.request("GET", "/enc/plain", &[]);
    assert_eq!(r.bytes, b"plain");
    assert_eq!(r.header("content-encoding"), None);
}

/// `aws-chunked` named over a plain body (no streaming hash, no decoded
/// length) is no framing: the body is stored as sent, under its other
/// codings. A strict decoder refused it as a broken chunked body. A
/// complete framed body with only the header is still decoded.
#[test]
fn aws_chunked_named_over_a_plain_body_is_not_decoded() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "plainenc");
    c.request_with_headers(
        "PUT",
        "/plainenc/o",
        b"gzipped bytes",
        &[("Content-Encoding", "gzip, aws-chunked")],
    )
    .expect(200);
    let r = c.request("GET", "/plainenc/o", &[]);
    assert_eq!(r.bytes, b"gzipped bytes");
    assert_eq!(r.header("content-encoding").as_deref(), Some("gzip"));

    c.request_with_headers(
        "PUT",
        "/plainenc/framed",
        &chunked(b"framed"),
        &[("Content-Encoding", "aws-chunked")],
    )
    .expect(200);
    assert_eq!(c.request("GET", "/plainenc/framed", &[]).bytes, b"framed");
}

/// An `aws-chunked` body cut short, or of the wrong length, is refused. It
/// used to be stored still framed, chunk headers and all, under the key.
#[test]
fn a_broken_aws_chunked_body_is_refused() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "cut");
    let whole = chunked(b"hello world");
    let cut = &whole[..whole.len() - 24];
    let r = c.request_with_headers(
        "PUT",
        "/cut/a",
        cut,
        &[
            ("Content-Encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", "11"),
        ],
    );
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

/// Object ownership other than `BucketOwnerEnforced` is refused at
/// `CreateBucket`, as `PutBucketOwnershipControls` refuses it: the bucket
/// used to be created and quietly behave as `BucketOwnerEnforced`.
#[test]
fn a_bucket_is_not_created_with_ownership_it_cannot_have() {
    let c = Cluster::start_with_ec(6, 4, 2);
    for ownership in ["BucketOwnerPreferred", "ObjectWriter"] {
        let r = c.request_with_headers(
            "PUT",
            "/owned",
            &[],
            &[("x-amz-object-ownership", ownership)],
        );
        assert_eq!(
            (r.status, code(&r).as_str()),
            (400, "InvalidRequest"),
            "{ownership}"
        );
        c.request("HEAD", "/owned", &[]).expect(404);
    }
    c.request_with_headers(
        "PUT",
        "/owned",
        &[],
        &[("x-amz-object-ownership", "BucketOwnerEnforced")],
    )
    .expect(200);
}

/// `x-amz-expiration` on PUT, HEAD and GET of an object a lifecycle rule
/// will expire: the rule's id and a UTC midnight. None for one no rule
/// covers.
#[test]
fn lifecycle_expiry_is_announced_on_the_object() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "exp");
    c.request(
        "PUT",
        "/exp?lifecycle",
        b"<LifecycleConfiguration>\
          <Rule><ID>rule1</ID><Filter><Prefix>days1/</Prefix></Filter><Status>Enabled</Status>\
          <Expiration><Days>1</Days></Expiration></Rule>\
          <Rule><ID>tagged</ID><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter>\
          <Status>Enabled</Status><Expiration><Days>3</Days></Expiration></Rule>\
          </LifecycleConfiguration>",
    )
    .expect(200);
    let announced = |r: &objectio_e2e::Response, rule: &str| {
        let h = r
            .header("x-amz-expiration")
            .unwrap_or_else(|| panic!("no x-amz-expiration: {:?}", r.headers));
        assert!(h.starts_with("expiry-date=\""), "{h}");
        assert!(h.contains(" 00:00:00 GMT\""), "not a midnight: {h}");
        assert!(h.ends_with(&format!("rule-id=\"{rule}\"")), "{h}");
    };
    let put = c.request("PUT", "/exp/days1/foo", b"bar");
    put.expect(200);
    announced(&put, "rule1");
    announced(&c.request("HEAD", "/exp/days1/foo", &[]), "rule1");
    announced(&c.request("GET", "/exp/days1/foo", &[]), "rule1");

    let other = c.request("PUT", "/exp/other", b"bar");
    other.expect(200);
    assert_eq!(other.header("x-amz-expiration"), None);
    // Tagged later: the tag rule now covers it.
    c.request(
        "PUT",
        "/exp/other?tagging",
        b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>",
    )
    .expect(200);
    announced(&c.request("HEAD", "/exp/other", &[]), "tagged");

    // No rules: nothing announced.
    c.request("DELETE", "/exp?lifecycle", &[]).expect(204);
    assert_eq!(
        c.request("HEAD", "/exp/days1/foo", &[])
            .header("x-amz-expiration"),
        None
    );
}

/// `ListObjectVersions` names each version's owner (the bucket owner's),
/// as S3 does.
#[test]
fn listed_versions_name_their_owner() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "ver");
    c.request(
        "PUT",
        "/ver?versioning",
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    )
    .expect(200);
    c.request("PUT", "/ver/k", b"one").expect(200);
    c.request("DELETE", "/ver/k", &[]).expect(204);
    let xml = c.request("GET", "/ver?versions", &[]).text();
    for (open, close) in [
        ("<Version>", "</Version>"),
        ("<DeleteMarker>", "</DeleteMarker>"),
    ] {
        let entry = xml
            .split(open)
            .nth(1)
            .and_then(|rest| rest.split(close).next())
            .unwrap_or_else(|| panic!("no {open}: {xml}"));
        assert!(entry.contains("<Owner><ID>"), "{open} has no owner: {xml}");
    }
}
