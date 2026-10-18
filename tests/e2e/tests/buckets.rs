//! Buckets hold what is in them: one with objects (or versions) can't be
//! deleted, and nothing is written into one that doesn't exist.

use objectio_e2e::Cluster;
use serde_json::json;

#[test]
fn a_bucket_with_objects_cannot_be_deleted() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "full"}))
        .expect_ok();
    c.request("PUT", "/full/k", b"data").expect(200);

    let r = c.request("DELETE", "/full", &[]);
    assert_eq!(
        r.status,
        409,
        "deleted a bucket with an object: {}",
        r.text()
    );
    assert!(r.text().contains("BucketNotEmpty"), "{}", r.text());
    assert_eq!(c.request("GET", "/full/k", &[]).bytes, b"data");

    c.request("DELETE", "/full/k", &[]).expect(204);
    assert_eq!(c.request("DELETE", "/full", &[]).status, 204);
}

/// A versioned bucket whose only contents are an old version behind a
/// delete marker is not empty either.
#[test]
fn a_bucket_with_only_versions_left_cannot_be_deleted() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "v"}))
        .expect_ok();
    c.request(
        "PUT",
        "/v?versioning",
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    )
    .expect(200);
    c.request("PUT", "/v/k", b"data").expect(200);
    c.request("DELETE", "/v/k", &[]).expect(204);

    let r = c.request("DELETE", "/v", &[]);
    assert_eq!(
        r.status,
        409,
        "deleted a bucket holding versions: {}",
        r.text()
    );
}

#[test]
fn nothing_is_written_into_a_bucket_that_does_not_exist() {
    let c = Cluster::start_with_ec(6, 4, 2);
    let r = c.request("PUT", "/nowhere/k", b"data");
    assert_eq!(r.status, 404, "{}", r.text());
    assert!(r.text().contains("NoSuchBucket"), "{}", r.text());
    assert_eq!(c.request("GET", "/nowhere/k", &[]).status, 404);
}

/// `/{bucket}/` is the bucket, for every verb: minio-go (warp, mc) creates
/// buckets with `PUT /b/`, s3fs probes with `HEAD /b/`.
#[test]
fn a_trailing_slash_names_the_bucket() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.request("PUT", "/slash/", &[]).expect(200);
    assert_eq!(c.request("HEAD", "/slash/", &[]).status, 200);
    c.request("PUT", "/slash/k", b"data").expect(200);
    let list = c.request("GET", "/slash/", &[]);
    assert_eq!(list.status, 200, "{}", list.text());
    assert!(list.text().contains("<Key>k</Key>"), "{}", list.text());

    let batch = b"<Delete><Object><Key>k</Key></Object></Delete>";
    let r = c.request("POST", "/slash/?delete", batch);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(c.request("GET", "/slash/k", &[]).status, 404);

    assert_eq!(c.request("DELETE", "/slash/", &[]).status, 204);
    assert_eq!(c.request("HEAD", "/slash", &[]).status, 404);
}
