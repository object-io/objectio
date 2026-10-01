//! An object's metadata is found where it was written, whatever joins the
//! cluster since: placement computed from today's topology is not where an
//! object written yesterday lives.

use objectio_e2e::Cluster;
use serde_json::json;

fn body(i: usize) -> Vec<u8> {
    (0..20_000)
        .map(|j| u8::try_from((i * 31 + j) % 251).unwrap())
        .collect()
}

fn unreadable(c: &Cluster, n: usize) -> Vec<String> {
    (0..n)
        .filter_map(|i| {
            let r = c.request("GET", &format!("/b/o{i}"), &[]);
            (r.status != 200 || r.bytes != body(i)).then(|| format!("o{i}: {}", r.status))
        })
        .collect()
}

/// A bucket with no pool is placed over the whole topology: twelve OSDs
/// joining must not lose track of objects written before.
#[test]
fn objects_stay_readable_after_osds_join() {
    const N: usize = 40;
    let mut c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "b"}))
        .expect_ok();
    for i in 0..N {
        c.request("PUT", &format!("/b/o{i}"), &body(i)).expect(200);
    }
    c.restart_with_osds(18);
    let missing = unreadable(&c, N);
    assert!(
        missing.is_empty(),
        "after 12 OSDs joined, {} of {N} objects are unreadable: {missing:?}",
        missing.len()
    );
}

/// Tagging, retention and legal hold update an object's metadata where GET
/// reads it. They used to ask for the placement of "bucket/bucket/key",
/// which on more OSDs than one stripe spans is some other set of OSDs: the
/// tag landed there, and GET, reading the object's own OSDs, didn't see it.
#[test]
fn tagging_finds_objects_on_a_cluster_wider_than_a_stripe() {
    const N: usize = 20;
    let c = Cluster::start_with_ec(12, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "b"}))
        .expect_ok();
    let tagging = b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>";
    let failed: Vec<String> = (0..N)
        .filter_map(|i| {
            c.request("PUT", &format!("/b/o{i}"), &body(i)).expect(200);
            let put = c.request("PUT", &format!("/b/o{i}?tagging"), tagging);
            let get = c.request("GET", &format!("/b/o{i}?tagging"), &[]);
            // The object itself, read the way GET reads it, carries the tag.
            let count = c
                .request("HEAD", &format!("/b/o{i}"), &[])
                .header("x-amz-tagging-count");
            (put.status != 200
                || get.status != 200
                || !get.text().contains("<Value>v</Value>")
                || count.as_deref() != Some("1"))
            .then(|| {
                format!(
                    "o{i}: put {} get {} tag count {count:?}",
                    put.status, get.status
                )
            })
        })
        .collect();
    assert!(
        failed.is_empty(),
        "{} of {N} objects: {failed:?}",
        failed.len()
    );
}
