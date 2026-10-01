//! `CopyObject` by reference: a copy shares the source's stripes instead of
//! copying their bytes, and meta's registry keeps a shared stripe until the
//! last object using it is gone. Both halves matter — the copy costs no
//! space, and deleting either side never takes the other's data.

use objectio_e2e::Cluster;
use serde_json::json;

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

fn copy(c: &Cluster, from: &str, to: &str, extra: &[(&str, &str)]) {
    let mut headers = vec![("x-amz-copy-source", from)];
    headers.extend_from_slice(extra);
    let r = c.request_with_headers("PUT", to, &[], &headers);
    assert_eq!(r.status, 200, "copy {from} -> {to}: {}", r.text());
}

fn setup() -> (Cluster, Vec<u8>, u64) {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "b"}))
        .expect_ok();
    let body = noise(3 << 20, 1);
    c.request("PUT", "/b/src", &body).expect(200);
    let one_object = c.await_total_used_bytes(c.total_used_bytes());
    assert!(one_object > 0);
    (c, body, one_object)
}

#[test]
fn a_copy_takes_no_space_and_reads_back() {
    let (c, body, one_object) = setup();
    copy(&c, "/b/src", "/b/copy", &[]);
    assert_eq!(c.request("GET", "/b/copy", &[]).bytes, body);
    assert_eq!(
        c.total_used_bytes(),
        one_object,
        "the copy stored its own bytes"
    );
}

/// The source going first must not take the copy's data with it — the
/// case that used to lose data (a rename through a FUSE mount).
#[test]
fn deleting_the_source_keeps_the_copy() {
    let (c, body, one_object) = setup();
    copy(&c, "/b/src", "/b/copy", &[]);
    c.request("DELETE", "/b/src", &[]).expect(204);
    assert_eq!(c.request("GET", "/b/copy", &[]).bytes, body);
    assert_eq!(
        c.await_total_used_bytes(one_object),
        one_object,
        "the copy's data was freed"
    );

    c.request("DELETE", "/b/copy", &[]).expect(204);
    assert_eq!(
        c.await_total_used_bytes(0),
        0,
        "the last copy did not free the data"
    );
}

#[test]
fn deleting_the_copy_keeps_the_source() {
    let (c, body, one_object) = setup();
    copy(&c, "/b/src", "/b/copy", &[]);
    c.request("DELETE", "/b/copy", &[]).expect(204);
    assert_eq!(c.request("GET", "/b/src", &[]).bytes, body);
    assert_eq!(c.await_total_used_bytes(one_object), one_object);

    c.request("DELETE", "/b/src", &[]).expect(204);
    assert_eq!(c.await_total_used_bytes(0), 0);
}

/// Overwriting the source gives it new stripes; the copy keeps the old.
#[test]
fn overwriting_the_source_keeps_the_copys_bytes() {
    let (c, body, one_object) = setup();
    copy(&c, "/b/src", "/b/copy", &[]);
    let newer = noise(3 << 20, 2);
    c.request("PUT", "/b/src", &newer).expect(200);
    assert_eq!(c.request("GET", "/b/copy", &[]).bytes, body);
    assert_eq!(c.request("GET", "/b/src", &[]).bytes, newer);
    assert_eq!(c.await_total_used_bytes(2 * one_object), 2 * one_object);
}

#[test]
fn copies_of_copies_free_the_data_with_the_last_one() {
    let (c, body, _) = setup();
    copy(&c, "/b/src", "/b/a", &[]);
    copy(&c, "/b/a", "/b/b", &[]);
    for key in ["/b/src", "/b/a"] {
        c.request("DELETE", key, &[]).expect(204);
    }
    assert_eq!(c.request("GET", "/b/b", &[]).bytes, body);
    c.request("DELETE", "/b/b", &[]).expect(204);
    assert_eq!(c.await_total_used_bytes(0), 0);
}

/// S3's way to change an object's metadata: copy it onto itself. The data
/// stays, the metadata changes, and nothing is left behind afterwards.
#[test]
fn a_copy_onto_itself_changes_metadata_and_leaks_nothing() {
    let (c, body, one_object) = setup();
    copy(
        &c,
        "/b/src",
        "/b/src",
        &[
            ("x-amz-metadata-directive", "REPLACE"),
            ("x-amz-meta-stage", "reviewed"),
        ],
    );
    let got = c.request("GET", "/b/src", &[]);
    assert_eq!(got.bytes, body);
    assert_eq!(got.header("x-amz-meta-stage").as_deref(), Some("reviewed"));
    assert_eq!(c.await_total_used_bytes(one_object), one_object);

    c.request("DELETE", "/b/src", &[]).expect(204);
    assert_eq!(
        c.await_total_used_bytes(0),
        0,
        "the replaced version left a reference behind"
    );
}
