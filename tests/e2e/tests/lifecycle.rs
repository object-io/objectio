//! Object and bucket lifecycle across the gateway → meta → OSD seam.
//!
//! Every test here is pinned to a defect that shipped. None of them could
//! have been caught by a unit test, because each one is about two components
//! disagreeing rather than one component being wrong.

use objectio_e2e::Cluster;
use serde_json::json;

/// Round-trip an object and get the same bytes back.
///
/// The floor: if this fails nothing else here means anything.
#[test]
fn put_then_get_returns_the_same_bytes() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "round-trip"}))
        .expect_ok();

    let payload: Vec<u8> = (0..64u32 * 1024)
        .map(|i| u8::try_from(i % 251).unwrap())
        .collect();
    c.request("PUT", "/round-trip/data.bin", &payload)
        .expect(200);

    let got = c.request("GET", "/round-trip/data.bin", &[]);
    got.expect(200);
    assert_eq!(got.bytes, payload, "bytes came back different");
}

/// Deleting an object returns its blocks to the pool.
///
/// This is the one that mattered most. The gateway never called
/// `DeleteShard`, the OSD would not have freed the block if it had, and
/// `used_capacity` was hardcoded to zero — so a cluster could report an empty
/// bucket and a full disk simultaneously, and did. Three separate defects,
/// none visible from inside any single component.
#[test]
fn deleting_an_object_reclaims_its_space() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "reclaim"}))
        .expect_ok();

    let baseline = c.used_bytes();
    let payload = vec![7u8; 4 * 1024 * 1024];

    for i in 0..8 {
        c.request("PUT", &format!("/reclaim/obj-{i}"), &payload)
            .expect(200);
    }
    let after_writes = c.used_bytes();
    assert!(
        after_writes > baseline,
        "writing 32 MB did not change reported usage ({baseline} -> {after_writes}); \
         used_capacity is not being computed"
    );

    for i in 0..8 {
        c.request("DELETE", &format!("/reclaim/obj-{i}"), &[])
            .expect(204);
    }
    let after_deletes = c.used_bytes();
    assert_eq!(
        after_deletes,
        baseline,
        "deleting every object left {} bytes allocated — blocks leaked",
        after_deletes - baseline
    );
}

/// Freed blocks are handed out again, not merely accounted for.
///
/// Reclamation that only moves a counter would pass the test above while the
/// disk still filled. This writes the same volume twice and asserts the
/// second pass did not grow the footprint.
#[test]
fn freed_blocks_are_reused_by_later_writes() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "reuse"}))
        .expect_ok();

    let payload = vec![3u8; 4 * 1024 * 1024];
    for i in 0..6 {
        c.request("PUT", &format!("/reuse/first-{i}"), &payload)
            .expect(200);
    }
    let peak = c.used_bytes();

    for i in 0..6 {
        c.request("DELETE", &format!("/reuse/first-{i}"), &[])
            .expect(204);
    }
    for i in 0..6 {
        c.request("PUT", &format!("/reuse/second-{i}"), &payload)
            .expect(200);
    }
    let after = c.used_bytes();

    assert!(
        after <= peak,
        "the second pass consumed fresh blocks ({peak} -> {after}) instead of \
         reusing the freed ones"
    );
}

/// A bucket that still holds objects cannot be dropped.
///
/// It could, and doing so orphaned every shard in it — the same leak as
/// above, by a route that never touched the object-delete path, so fixing
/// that path did not fix this.
#[test]
fn a_non_empty_bucket_cannot_be_deleted() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "occupied"}))
        .expect_ok();
    c.request("PUT", "/occupied/a.txt", b"x").expect(200);

    let refused = c.request("DELETE", "/_admin/buckets/occupied", &[]);
    assert_eq!(
        refused.status,
        409,
        "expected 409 BucketNotEmpty, got {}: {}",
        refused.status,
        refused.text()
    );

    c.request("DELETE", "/occupied/a.txt", &[]).expect(204);
    c.request("DELETE", "/_admin/buckets/occupied", &[])
        .expect(204);
}

/// A bucket created through the admin API is owned by its creator.
///
/// It used to record the literal string "admin", which matches no `user_id` —
/// so with "no policy means owner-only", every console-created bucket was
/// reachable by the root key alone, whatever its tenant admin did.
#[test]
fn an_admin_created_bucket_records_its_real_creator() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "owned"}))
        .expect_ok();

    let buckets = c.request("GET", "/_admin/buckets", &[]);
    buckets.expect(200);
    let v = buckets.json();
    let owner = v["buckets"]
        .as_array()
        .expect("buckets")
        .iter()
        .find(|b| b["name"] == "owned")
        .expect("the bucket we just made")["owner"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    assert!(
        !owner.is_empty() && owner != "admin",
        "owner was {owner:?} — a literal rather than the creator's user_id"
    );
}

/// An object key with characters that have to be percent-encoded survives a
/// round trip. Signing and routing must agree on the spelling, or the request
/// fails with `SignatureDoesNotMatch` — which reads like bad credentials.
#[test]
fn keys_needing_escaping_round_trip() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "escaping"}))
        .expect_ok();

    // Raw keys: the harness escapes once, for both the signature and the URL.
    for key in ["q1 final#draft.txt", "a+b.txt", "nested/deep/path.json"] {
        let path = format!("/escaping/{key}");
        c.request("PUT", &path, key.as_bytes()).expect(200);
        let got = c.request("GET", &path, &[]);
        got.expect(200);
        assert_eq!(got.text(), key, "round trip changed the body for {key:?}");
    }
}

/// A listing whose prefix is not ASCII must authenticate.
///
/// The gateway rebuilds the canonical query string by decoding each parameter
/// and re-encoding it, and the decode step turned each byte into a `char`.
/// Percent-encoding is a byte encoding: `%C3%A9` is two bytes that are one
/// character, so `caf%C3%A9` came back out as `caf%C3%83%C2%A9`. The gateway
/// signed a string the client never produced and answered
/// `SignatureDoesNotMatch` — which reads like bad credentials rather than a
/// prefix with an accent in it.
///
/// The harness escapes byte-wise, so it signs what a real SDK signs; only the
/// gateway's half of the canonicalisation is under test here.
#[test]
fn a_listing_with_a_non_ascii_prefix_authenticates() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "unicode"}))
        .expect_ok();

    for prefix in ["café/", "日本/", "📁/"] {
        let r = c.request("GET", &format!("/unicode?prefix={prefix}&max-keys=10"), &[]);
        assert_eq!(
            r.status,
            200,
            "listing with prefix {prefix:?} was refused: {}",
            r.text()
        );
    }
}

/// And an object whose key is not ASCII round-trips.
///
/// The path is signed and routed from the same escaping, so a mismatch here
/// surfaces the same way — as a credential error on a perfectly good key.
#[test]
fn a_non_ascii_object_key_round_trips() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "unicode-keys"}))
        .expect_ok();

    for key in ["café.txt", "日本語/ファイル.bin", "emoji-📁.txt"] {
        let path = format!("/unicode-keys/{key}");
        c.request("PUT", &path, key.as_bytes()).expect(200);
        let got = c.request("GET", &path, &[]);
        got.expect(200);
        assert_eq!(got.text(), key, "round trip changed the body for {key:?}");
    }
}

/// A zero-byte object can be read back.
///
/// It could be written and never read: an empty object has no stripes — there
/// are no bytes to erasure-code — and the GET path treated a missing stripe
/// list as corruption and answered 500 `InternalError`. `touch x && aws s3 cp
/// x s3://b/` succeeded and `aws s3 cp s3://b/x .` failed, which makes every
/// empty file a write-only object. Empty files are ordinary: .gitkeep, an
/// empty `__init__.py`, a zero-length marker.
#[test]
fn a_zero_byte_object_round_trips() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "empties"}))
        .expect_ok();

    c.request("PUT", "/empties/nothing.txt", b"").expect(200);

    let got = c.request("GET", "/empties/nothing.txt", &[]);
    got.expect(200);
    assert!(
        got.bytes.is_empty(),
        "a zero-byte object came back with {} bytes",
        got.bytes.len()
    );
    assert_eq!(
        got.header("content-length").as_deref(),
        Some("0"),
        "Content-Length must be 0, not absent"
    );

    // It lists, and it deletes.
    let listed = c.request("GET", "/empties?prefix=nothing", &[]);
    listed.expect(200);
    assert!(
        listed.text().contains("nothing.txt"),
        "a zero-byte object is missing from the listing: {}",
        listed.text()
    );
    c.request("DELETE", "/empties/nothing.txt", &[]).expect(204);
    assert_eq!(
        c.request("GET", "/empties/nothing.txt", &[]).status,
        404,
        "a deleted zero-byte object is still readable"
    );
}

/// And a Range over one is unsatisfiable rather than a server error.
#[test]
fn a_range_over_a_zero_byte_object_is_unsatisfiable() {
    let c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "empty-range"}))
        .expect_ok();
    c.request("PUT", "/empty-range/nothing.txt", b"")
        .expect(200);

    // `bytes=-5` is the one that used to underflow `total_size - 1` before it
    // was guarded; the 500 above hid it, since the handler never got this far.
    for range in ["bytes=-5", "bytes=0-0", "bytes=0-"] {
        let got =
            c.request_with_headers("GET", "/empty-range/nothing.txt", &[], &[("range", range)]);
        assert_eq!(
            got.status, 416,
            "Range {range} over a zero-byte object answered {} rather than 416",
            got.status
        );
    }
}
