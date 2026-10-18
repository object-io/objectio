//! Small objects stored inside their metadata record instead of in shards.
//!
//! An object of at most `--inline-max-size` bytes (4 KiB by default) makes
//! no shard writes: its bytes go whole into the `ObjectMeta` that every OSD
//! in its placement already holds. Everything a client can do with an object
//! has to work the same either way.

use objectio_e2e::Cluster;
use serde_json::json;

/// Shard writes the gateway has made so far.
fn shard_writes(c: &Cluster) -> u64 {
    c.request("GET", "/metrics", &[])
        .text()
        .lines()
        .filter(|l| {
            l.starts_with("objectio_gateway_shard_latency_seconds_count")
                && l.contains("direction=\"write\"")
        })
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

fn payload(len: usize) -> Vec<u8> {
    (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
}

fn ec_cluster(bucket: &str) -> Cluster {
    // Small shards in metadata (B21) off: these are inlining's own tests.
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--small-shard-max", "0"]);
    c.json("POST", "/_admin/buckets", json!({"name": bucket}))
        .expect_ok();
    c
}

#[test]
fn a_small_object_round_trips_without_shards() {
    let c = ec_cluster("inline");
    let body = payload(100);
    let before = shard_writes(&c);

    c.request("PUT", "/inline/small", &body).expect(200);
    assert_eq!(shard_writes(&c), before, "a 100-byte PUT wrote shards");

    let got = c.request("GET", "/inline/small", &[]);
    got.expect(200);
    assert_eq!(got.bytes, body);

    let ranged = c.request_with_headers("GET", "/inline/small", &[], &[("Range", "bytes=10-19")]);
    ranged.expect(206);
    assert_eq!(ranged.bytes, body[10..20]);
    assert_eq!(
        ranged.header("content-range").as_deref(),
        Some("bytes 10-19/100")
    );

    let head = c.request("HEAD", "/inline/small", &[]);
    head.expect(200);
    assert_eq!(head.header("content-length").as_deref(), Some("100"));

    let list = c.request("GET", "/inline?list-type=2", &[]).text();
    assert!(list.contains("<Key>small</Key>"), "{list}");
    assert!(list.contains("<Size>100</Size>"), "{list}");
}

/// Up to the limit is inline; one byte more is erasure-coded as before.
#[test]
fn the_limit_is_inclusive() {
    let c = ec_cluster("edge");

    let before = shard_writes(&c);
    c.request("PUT", "/edge/at", &payload(4096)).expect(200);
    assert_eq!(shard_writes(&c), before, "a 4096-byte object was sharded");

    c.request("PUT", "/edge/over", &payload(4097)).expect(200);
    assert!(
        shard_writes(&c) > before,
        "a 4097-byte object was not sharded"
    );

    for (key, len) in [("at", 4096), ("over", 4097)] {
        let got = c.request("GET", &format!("/edge/{key}"), &[]);
        got.expect(200);
        assert_eq!(got.bytes, payload(len), "{key}");
    }
}

/// Overwriting switches between the two forms both ways, and a delete
/// removes an inline object like any other.
#[test]
fn overwrites_and_deletes_switch_cleanly_between_inline_and_shards() {
    let c = ec_cluster("swap");
    for len in [10, 100_000, 20, 0, 30] {
        let body = payload(len);
        c.request("PUT", "/swap/k", &body).expect(200);
        let got = c.request("GET", "/swap/k", &[]);
        got.expect(200);
        assert_eq!(got.bytes, body, "after overwriting with {len} bytes");
    }
    c.request("DELETE", "/swap/k", &[]).expect(204);
    c.request("GET", "/swap/k", &[]).expect(404);
}

/// The bytes live in the OSDs' metadata log, which is what a restart replays.
#[test]
fn inline_objects_survive_a_restart() {
    let mut c = ec_cluster("kept");
    let body = payload(3000);
    c.request("PUT", "/kept/small", &body).expect(200);

    c.restart();

    let got = c.request("GET", "/kept/small", &[]);
    got.expect(200);
    assert_eq!(got.bytes, body);
}

/// `--inline-max-size 0` turns it off: every non-empty object is sharded.
#[test]
fn a_limit_of_zero_turns_inlining_off() {
    let c = Cluster::start_with_ec_and_args(
        6,
        4,
        2,
        &["--inline-max-size", "0", "--small-shard-max", "0"],
    );
    c.json("POST", "/_admin/buckets", json!({"name": "off"}))
        .expect_ok();
    let before = shard_writes(&c);
    c.request("PUT", "/off/small", &payload(100)).expect(200);
    assert!(shard_writes(&c) > before, "inlined with the limit at 0");
    assert_eq!(c.request("GET", "/off/small", &[]).bytes, payload(100));
}

/// An encrypted inline object is stored as ciphertext and decrypted on the
/// way out, whole or ranged. SSE-C, because it needs no key service.
#[test]
fn an_encrypted_inline_object_round_trips() {
    // The customer key is 32 bytes of 'A'; these are its base64 and the
    // base64 of its MD5.
    const SSE_C: [(&str, &str); 3] = [
        ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
        (
            "x-amz-server-side-encryption-customer-key",
            "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
        ),
        (
            "x-amz-server-side-encryption-customer-key-md5",
            "UhbdzFjo2t5SVgded/ZC2g==",
        ),
    ];
    let c = ec_cluster("sealed");
    let body = payload(1000);
    let before = shard_writes(&c);
    c.request_with_headers("PUT", "/sealed/s", &body, &SSE_C)
        .expect(200);
    assert_eq!(
        shard_writes(&c),
        before,
        "an encrypted 1000-byte PUT wrote shards"
    );

    let got = c.request_with_headers("GET", "/sealed/s", &[], &SSE_C);
    got.expect(200);
    assert_eq!(got.bytes, body);

    let range = [SSE_C.as_slice(), &[("Range", "bytes=500-599")]].concat();
    let ranged = c.request_with_headers("GET", "/sealed/s", &[], &range);
    ranged.expect(206);
    assert_eq!(ranged.bytes, body[500..600]);

    c.request("GET", "/sealed/s", &[]).expect(400);
}
