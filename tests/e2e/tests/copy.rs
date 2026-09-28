//! What a copy is: a second object, independent of the first.
//!
//! `CopyObject` used to take a "fast path" that wrote the destination's
//! metadata as a clone of the source's -- the same stripes, the same shards --
//! and copied no data. Nothing counted references, so deleting the source
//! deleted the shards the copy still pointed at. A rename through an S3
//! FUSE mount is exactly that, copy then delete, and every renamed file
//! became unreadable. Observed on a deployment, in the gateway's log:
//!
//! ```text
//! 08:56:08  CopyObject fast-path: users/admin/test.ipynb -> users/admin/test1.ipynb (778 bytes, no data I/O)
//! 08:56:08  Deleted object: users/admin/test.ipynb
//! 09:05:01  ERROR Failed to read any replica for stripe 0 of users/admin/test1.ipynb
//! ```

use objectio_e2e::Cluster;
use serde_json::json;

fn copy(c: &Cluster, from: &str, to: &str, extra: &[(&str, &str)]) {
    let mut headers = vec![("x-amz-copy-source", from)];
    headers.extend_from_slice(extra);
    c.request_with_headers("PUT", to, &[], &headers).expect(200);
}

/// The rename a FUSE mount does: copy, then delete the original.
#[test]
fn a_copy_outlives_its_source() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "renames"}))
        .expect_ok();
    let payload = b"{\"cells\": [], \"nbformat\": 4}".to_vec();
    c.request("PUT", "/renames/before.ipynb", &payload)
        .expect(200);

    copy(&c, "/renames/before.ipynb", "/renames/after.ipynb", &[]);
    c.request("DELETE", "/renames/before.ipynb", &[])
        .expect(204);

    let got = c.request("GET", "/renames/after.ipynb", &[]);
    got.expect(200);
    assert_eq!(got.bytes, payload, "the copy lost its data with its source");
    c.request("GET", "/renames/before.ipynb", &[]).expect(404);
}

/// Several stripes, so a copy that shared any of them would show it.
#[test]
fn a_large_copy_outlives_its_source() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "big-renames"}))
        .expect_ok();
    let payload: Vec<u8> = (0..(9 * 1024 * 1024_u32))
        .map(|i| (i % 251) as u8)
        .collect();
    c.request("PUT", "/big-renames/a.bin", &payload).expect(200);

    copy(&c, "/big-renames/a.bin", "/big-renames/b.bin", &[]);
    c.request("DELETE", "/big-renames/a.bin", &[]).expect(204);

    let got = c.request("GET", "/big-renames/b.bin", &[]);
    got.expect(200);
    assert_eq!(got.bytes.len(), payload.len());
    assert!(
        got.bytes == payload,
        "the copy's data differs from what was written"
    );
}

/// And the other way round: deleting the copy leaves the source alone.
#[test]
fn a_source_outlives_its_copy() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "copies"}))
        .expect_ok();
    c.request("PUT", "/copies/original", b"kept").expect(200);
    copy(&c, "/copies/original", "/copies/duplicate", &[]);
    c.request("DELETE", "/copies/duplicate", &[]).expect(204);

    let got = c.request("GET", "/copies/original", &[]);
    got.expect(200);
    assert_eq!(got.bytes, b"kept");
}

/// S3's default metadata directive is COPY: the copy keeps the source's
/// content type and user metadata unless the request says REPLACE.
#[test]
fn a_copy_keeps_the_source_metadata_unless_told_to_replace_it() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "meta"}))
        .expect_ok();
    c.request_with_headers(
        "PUT",
        "/meta/src.json",
        b"{}",
        &[
            ("content-type", "application/json"),
            ("x-amz-meta-owner", "ana"),
        ],
    )
    .expect(200);

    copy(&c, "/meta/src.json", "/meta/kept.json", &[]);
    let kept = c.request("HEAD", "/meta/kept.json", &[]);
    kept.expect(200);
    assert_eq!(
        kept.header("content-type").as_deref(),
        Some("application/json")
    );
    assert_eq!(kept.header("x-amz-meta-owner").as_deref(), Some("ana"));

    copy(
        &c,
        "/meta/src.json",
        "/meta/replaced.json",
        &[
            ("x-amz-metadata-directive", "REPLACE"),
            ("content-type", "text/plain"),
            ("x-amz-meta-owner", "bo"),
        ],
    );
    let replaced = c.request("HEAD", "/meta/replaced.json", &[]);
    replaced.expect(200);
    assert_eq!(
        replaced.header("content-type").as_deref(),
        Some("text/plain")
    );
    assert_eq!(replaced.header("x-amz-meta-owner").as_deref(), Some("bo"));
}
