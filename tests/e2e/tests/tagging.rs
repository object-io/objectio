//! Object tagging (`?tagging`, `x-amz-tagging`), and what a multipart
//! upload carries onto its object.
//!
//! `GET ?tagging` used to answer with the object itself, 200 and all its
//! bytes: the AWS CLI asks for tags when it copies a multipart object, and
//! failed on the reply. Multipart uploads also dropped the object's
//! content type and `x-amz-meta-*`.

use std::fmt::Write as _;

use objectio_e2e::Cluster;
use serde_json::json;

fn bucket(c: &Cluster, name: &str) {
    c.json("POST", "/_admin/buckets", json!({"name": name}))
        .expect_ok();
}

/// `(key, value)` of every tag in a `GetObjectTagging` reply, in order.
fn tags(c: &Cluster, path: &str) -> Vec<(String, String)> {
    let r = c.request("GET", &format!("{path}?tagging"), &[]);
    r.expect(200);
    let xml = r.text();
    assert!(xml.contains("<Tagging"), "not a Tagging document: {xml}");
    xml.split("<Tag>")
        .skip(1)
        .map(|t| {
            let field = |name: &str| {
                let open = format!("<{name}>");
                let start = t.find(&open).map_or(0, |i| i + open.len());
                let end = t.find(&format!("</{name}>")).unwrap_or(start);
                t[start..end].to_string()
            };
            (field("Key"), field("Value"))
        })
        .collect()
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

const TAGGING_XML: &str = "<Tagging><TagSet>\
    <Tag><Key>team</Key><Value>ml</Value></Tag>\
    <Tag><Key>stage</Key><Value>raw data</Value></Tag>\
    </TagSet></Tagging>";

#[test]
fn tags_are_set_read_replaced_and_removed() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "t");
    let body = vec![3u8; 200_000];
    c.request_with_headers(
        "PUT",
        "/t/o",
        &body,
        &[("x-amz-tagging", "team=ml&note=a%20b")],
    )
    .expect(200);

    assert_eq!(tags(&c, "/t/o"), pairs(&[("note", "a b"), ("team", "ml")]));
    let head = c.request("HEAD", "/t/o", &[]);
    assert_eq!(head.header("x-amz-tagging-count").as_deref(), Some("2"));
    // The object itself is untouched by any of this.
    assert_eq!(c.request("GET", "/t/o", &[]).bytes, body);

    c.request("PUT", "/t/o?tagging", TAGGING_XML.as_bytes())
        .expect(200);
    assert_eq!(
        tags(&c, "/t/o"),
        pairs(&[("stage", "raw data"), ("team", "ml")])
    );

    c.request("DELETE", "/t/o?tagging", &[]).expect(204);
    assert!(tags(&c, "/t/o").is_empty());
    assert_eq!(
        c.request("HEAD", "/t/o", &[]).header("x-amz-tagging-count"),
        None
    );
    assert_eq!(c.request("GET", "/t/o", &[]).bytes, body);
}

#[test]
fn tags_breaking_s3s_rules_are_refused() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "r");
    let eleven = (0..11)
        .map(|i| format!("k{i}=v"))
        .collect::<Vec<_>>()
        .join("&");
    let r = c.request_with_headers("PUT", "/r/o", b"x", &[("x-amz-tagging", &eleven)]);
    r.expect(400);
    assert!(r.text().contains("InvalidTag"), "{}", r.text());
    // Refused before anything was stored.
    c.request("GET", "/r/o", &[]).expect(404);

    c.request("PUT", "/r/o", b"x").expect(200);
    for bad in [
        "<Tagging><TagSet><Tag><Key>aws:x</Key><Value>v</Value></Tag></TagSet></Tagging>",
        "<Tagging><TagSet><Tag><Key>a</Key><Value>1</Value></Tag>\
         <Tag><Key>a</Key><Value>2</Value></Tag></TagSet></Tagging>",
    ] {
        c.request("PUT", "/r/o?tagging", bad.as_bytes()).expect(400);
    }
    c.request("PUT", "/r/o?tagging", b"<not xml").expect(400);
    c.request("GET", "/r/missing?tagging", &[]).expect(404);
}

#[test]
fn a_copy_keeps_its_sources_tags_unless_told_to_replace_them() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "cp");
    c.request_with_headers(
        "PUT",
        "/cp/src",
        &vec![9u8; 50_000],
        &[("x-amz-tagging", "a=1")],
    )
    .expect(200);

    c.request_with_headers("PUT", "/cp/kept", &[], &[("x-amz-copy-source", "/cp/src")])
        .expect(200);
    assert_eq!(tags(&c, "/cp/kept"), pairs(&[("a", "1")]));

    c.request_with_headers(
        "PUT",
        "/cp/replaced",
        &[],
        &[
            ("x-amz-copy-source", "/cp/src"),
            ("x-amz-tagging-directive", "REPLACE"),
            ("x-amz-tagging", "b=2"),
        ],
    )
    .expect(200);
    assert_eq!(tags(&c, "/cp/replaced"), pairs(&[("b", "2")]));
    // Tagging a copy leaves its source alone.
    assert_eq!(tags(&c, "/cp/src"), pairs(&[("a", "1")]));
}

/// What the AWS CLI's `s3 cp` of a large object needs: the tags, the
/// content type and the metadata given at `CreateMultipartUpload` end up on
/// the object.
#[test]
fn a_multipart_object_keeps_what_its_upload_was_created_with() {
    const PART: usize = 5 * 1024 * 1024;
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "mp");
    let r = c.request_with_headers(
        "POST",
        "/mp/big?uploads",
        &[],
        &[
            ("x-amz-tagging", "kind=checkpoint"),
            ("content-type", "application/x-model"),
            ("x-amz-meta-epoch", "7"),
        ],
    );
    r.expect(200);
    let xml = r.text();
    let upload = xml
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .unwrap_or_else(|| panic!("no UploadId in {xml}"))
        .to_string();
    let mut parts = String::new();
    for n in 1..=2u8 {
        let body = vec![n; if n == 1 { PART } else { 1000 }];
        let r = c.request(
            "PUT",
            &format!("/mp/big?partNumber={n}&uploadId={upload}"),
            &body,
        );
        r.expect(200);
        let etag = r.header("etag").unwrap_or_default();
        let _ = write!(
            parts,
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        );
    }
    c.request(
        "POST",
        &format!("/mp/big?uploadId={upload}"),
        format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>").as_bytes(),
    )
    .expect(200);

    assert_eq!(tags(&c, "/mp/big"), pairs(&[("kind", "checkpoint")]));
    let head = c.request("HEAD", "/mp/big", &[]);
    assert_eq!(
        head.header("content-type").as_deref(),
        Some("application/x-model")
    );
    assert_eq!(head.header("x-amz-meta-epoch").as_deref(), Some("7"));
    assert_eq!(head.header("x-amz-tagging-count").as_deref(), Some("1"));
    // The reserved key that carried the tags is not user metadata.
    assert!(
        !head
            .headers
            .iter()
            .any(|(k, _)| k.contains("tagging") && k.starts_with("x-amz-meta")),
        "{:?}",
        head.headers
    );
}

#[test]
fn bucket_tagging_never_touches_the_bucket() {
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "bt");
    c.request("PUT", "/bt/o", b"x").expect(200);
    // No tags yet; an empty PUT is malformed; a DELETE removes no bucket.
    c.request("GET", "/bt?tagging", &[]).expect(404);
    c.request("PUT", "/bt?tagging", &[]).expect(400);
    c.request("DELETE", "/bt?tagging", &[]).expect(204);
    // And the bucket is still there, with its object.
    c.request("GET", "/bt/o", &[]).expect(200);
}

/// `UploadPartCopy`: parts taken from ranges of an existing object. It used
/// to store the request's empty body as the part.
#[test]
fn a_multipart_copy_assembles_the_sources_bytes() {
    const PART: u64 = 5 * 1024 * 1024;
    let c = Cluster::start_with_ec(6, 4, 2);
    bucket(&c, "pc");
    let source: Vec<u8> = (0..PART + 300_000)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    c.request("PUT", "/pc/src", &source).expect(200);

    let r = c.request("POST", "/pc/dst?uploads", &[]);
    r.expect(200);
    let xml = r.text();
    let upload = xml
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .unwrap()
        .to_string();
    let len = source.len() as u64;
    let mut parts = String::new();
    for (n, range) in [
        (1, format!("bytes=0-{}", PART - 1)),
        (2, format!("bytes={PART}-{}", len - 1)),
    ] {
        let r = c.request_with_headers(
            "PUT",
            &format!("/pc/dst?partNumber={n}&uploadId={upload}"),
            &[],
            &[
                ("x-amz-copy-source", "/pc/src"),
                ("x-amz-copy-source-range", &range),
            ],
        );
        r.expect(200);
        let body = r.text();
        assert!(body.contains("<CopyPartResult"), "{body}");
        let etag = body
            .split("<ETag>")
            .nth(1)
            .and_then(|s| s.split("</ETag>").next())
            .unwrap()
            .to_string();
        assert!(etag.len() > 2, "no ETag in {body}");
        let _ = write!(
            parts,
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        );
    }
    c.request(
        "POST",
        &format!("/pc/dst?uploadId={upload}"),
        format!("<CompleteMultipartUpload>{parts}</CompleteMultipartUpload>").as_bytes(),
    )
    .expect(200);
    assert_eq!(c.request("GET", "/pc/dst", &[]).bytes, source);
}
