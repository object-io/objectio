//! Writing a key that already exists, and what becomes of the object it
//! replaces.
//!
//! An overwrite replaced the key's `ObjectMeta` and never deleted the shards
//! the old one pointed at, so every overwrite leaked a whole object: a key
//! rewritten every minute filled a disk while the bucket held one object.
//! With versioning the old object is still a version and must stay.

use objectio_e2e::Cluster;
use serde_json::json;
use std::collections::HashSet;

const MIB: usize = 1024 * 1024;

/// 1 MiB whose bytes depend on `seed`, so a read of the wrong generation
/// is visible.
fn payload(seed: u8) -> Vec<u8> {
    (0..MIB)
        .map(|i| u8::try_from(i % 251).unwrap() ^ seed)
        .collect()
}

fn ec_cluster(bucket: &str) -> Cluster {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": bucket}))
        .expect_ok();
    c
}

/// Space one 1 MiB object takes, measured by writing one under `key`.
fn footprint_of_first_write(c: &Cluster, path: &str, baseline: u64) -> u64 {
    c.request("PUT", path, &payload(0)).expect(200);
    let one = c.total_used_bytes() - baseline;
    assert!(one >= MIB as u64, "a 1 MiB PUT used only {one} bytes");
    one
}

#[test]
fn overwriting_a_key_frees_the_object_it_replaced() {
    let c = ec_cluster("over");
    let baseline = c.total_used_bytes();
    let one = footprint_of_first_write(&c, "/over/k", baseline);

    for seed in 1..=8u8 {
        c.request("PUT", "/over/k", &payload(seed)).expect(200);
    }
    let used = c.await_total_used_bytes(baseline + one);
    assert_eq!(
        used - baseline,
        one,
        "after 9 writes of one key, {} objects' worth is allocated — overwrites leaked",
        (used - baseline) / one
    );

    let got = c.request("GET", "/over/k", &[]);
    got.expect(200);
    assert!(
        got.bytes == payload(8),
        "the last write is not what reads back"
    );

    c.request("DELETE", "/over/k", &[]).expect(204);
    assert_eq!(
        c.await_total_used_bytes(baseline),
        baseline,
        "deleting the overwritten key left blocks allocated"
    );
}

/// A copy onto itself — how S3 clients change an object's metadata —
/// writes the data again and must neither lose it nor keep both copies.
#[test]
fn copying_a_key_onto_itself_keeps_one_copy() {
    let c = ec_cluster("self-copy");
    let baseline = c.total_used_bytes();
    let one = footprint_of_first_write(&c, "/self-copy/k", baseline);

    c.request_with_headers(
        "PUT",
        "/self-copy/k",
        &[],
        &[
            ("x-amz-copy-source", "/self-copy/k"),
            ("x-amz-metadata-directive", "REPLACE"),
            ("content-type", "text/plain"),
        ],
    )
    .expect(200);

    let got = c.request("GET", "/self-copy/k", &[]);
    got.expect(200);
    assert!(got.bytes == payload(0), "copy-in-place lost the data");
    assert_eq!(
        c.await_total_used_bytes(baseline + one) - baseline,
        one,
        "copy-in-place kept the replaced copy's shards"
    );
}

/// With versioning on, the replaced object is an older version: it stays
/// allocated until that version is deleted, and deleting it frees it and
/// nothing else.
#[test]
fn versioned_overwrites_keep_every_version() {
    let c = ec_cluster("versioned");
    c.request(
        "PUT",
        "/versioned?versioning",
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    )
    .expect(200);
    let baseline = c.total_used_bytes();

    let mut ids = Vec::new();
    for seed in 0..4u8 {
        let r = c.request("PUT", "/versioned/k", &payload(seed));
        r.expect(200);
        ids.push(r.header("x-amz-version-id").expect("a version id"));
    }
    assert_eq!(
        ids.iter().collect::<HashSet<_>>().len(),
        4,
        "versioned PUTs did not get distinct versions"
    );
    let four = c.total_used_bytes() - baseline;
    assert_eq!(four % 4, 0);
    let one = four / 4;
    assert!(one >= MIB as u64, "a 1 MiB version used only {one} bytes");
    // Give a wrongful reclaim the time it would need to show.
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert_eq!(
        c.total_used_bytes() - baseline,
        4 * one,
        "an overwrite in a versioned bucket freed an older version's shards"
    );

    // Deleting the older versions frees exactly them. (Reading an old
    // version back is not asserted: the gateway ignores `?versionId=` on
    // GET.) Deleting a version used to free the *current* object's shards
    // whichever version it named.
    for id in &ids[..3] {
        c.request("DELETE", &format!("/versioned/k?versionId={id}"), &[])
            .expect(204);
    }
    assert_eq!(
        c.await_total_used_bytes(baseline + one) - baseline,
        one,
        "deleting three of four versions did not free exactly three"
    );
    let got = c.request("GET", "/versioned/k", &[]);
    got.expect(200);
    assert!(got.bytes == payload(3), "the latest version is not current");
}

/// `DeleteObjects` (what `aws s3 rm --recursive` sends) frees the shards
/// too, not only the metadata.
#[test]
fn batch_delete_frees_the_objects() {
    let c = ec_cluster("batch");
    let baseline = c.total_used_bytes();
    for i in 0..3 {
        c.request("PUT", &format!("/batch/o{i}"), &payload(i))
            .expect(200);
    }
    assert!(c.total_used_bytes() > baseline);

    let body = "<Delete><Object><Key>o0</Key></Object><Object><Key>o1</Key></Object>\
                <Object><Key>o2</Key></Object></Delete>";
    let r = c.request("POST", "/batch?delete", body.as_bytes());
    r.expect(200);
    assert!(r.text().matches("<Deleted>").count() == 3, "{}", r.text());
    for i in 0..3 {
        c.request("GET", &format!("/batch/o{i}"), &[]).expect(404);
    }
    assert_eq!(
        c.await_total_used_bytes(baseline),
        baseline,
        "DeleteObjects left the objects' blocks allocated"
    );
}
