//! Small objects whose shards are kept with their metadata (B21): a GET
//! takes the shards from the metadata answers, with no shard reads.

use std::time::Duration;

use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use serde_json::json;

/// Shard reads the gateway has made so far.
fn shard_reads(c: &Cluster) -> u64 {
    c.request("GET", "/metrics", &[])
        .text()
        .lines()
        .filter(|l| {
            l.starts_with("objectio_gateway_shard_latency_seconds_count")
                && l.contains("direction=\"read\"")
        })
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from(i % 251).unwrap() ^ seed)
        .collect()
}

#[test]
fn a_small_get_reads_no_shards() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &[]);
    c.json("POST", "/_admin/buckets", json!({"name": "small"}))
        .expect_ok();
    let body = payload(64 * 1024, 1);
    c.request("PUT", "/small/k", &body).expect(200);

    let before = shard_reads(&c);
    let got = c.request("GET", "/small/k", &[]);
    got.expect(200);
    assert_eq!(got.bytes, body);
    let ranged = c.request_with_headers("GET", "/small/k", &[], &[("Range", "bytes=100-199")]);
    ranged.expect(206);
    assert_eq!(ranged.bytes, body[100..200]);
    assert_eq!(shard_reads(&c), before, "a small GET read shards");

    // Overwritten, the GET decodes the new object's shards, not the old.
    let newer = payload(40 * 1024, 2);
    c.request("PUT", "/small/k", &newer).expect(200);
    let got = c.request("GET", "/small/k", &[]);
    got.expect(200);
    assert_eq!(got.bytes, newer);
    assert_eq!(shard_reads(&c), before, "a small GET read shards");

    // A large object's shards are on disk: its GET reads them (and the
    // count above is a live one).
    let large = payload(1024 * 1024, 3);
    c.request("PUT", "/small/large", &large).expect(200);
    let got = c.request("GET", "/small/large", &[]);
    got.expect(200);
    assert_eq!(got.bytes, large);
    assert!(shard_reads(&c) > before, "a large GET read no shards");
}

/// Two OSDs down (m = 2): the GET still decodes, from the four that answer,
/// parity among them.
#[test]
fn a_small_get_with_two_osds_down_still_decodes() {
    let mut ha = HaCluster::start(1, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/degraded", &[]).status, 200);
    let objects: Vec<(String, Vec<u8>)> = (0..8u8)
        .map(|i| {
            (
                format!("/degraded/k{i}"),
                payload(20_000 + usize::from(i) * 4096, i),
            )
        })
        .collect();
    for (path, body) in &objects {
        c.request("PUT", path, body).expect(200);
    }
    ha.stop_osd(0);
    ha.stop_osd(3);
    let c = &ha.clients[0];
    for (path, body) in &objects {
        let got = c.request("GET", path, &[]);
        got.expect(200);
        assert_eq!(&got.bytes, body, "{path}");
    }
}
