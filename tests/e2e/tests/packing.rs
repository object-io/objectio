//! Small-object packing, phase 1: objects packed through the test hook
//! (`/_admin/test/pack`, mounted by `--test-hooks`) read back byte-identical;
//! each lets its own stripe go; the pack goes with its last object; and the
//! pack survives what a stripe survives: copies, overwrites, lost disks,
//! repair and drain (objectio-docs architecture/design/small-object-packing.md).

use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use serde_json::{Value, json};

/// Bytes that do not repeat, distinct per seed.
fn payload(len: usize, seed: u8) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ (u64::from(seed) << 7);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// Small objects of assorted sizes: above the inline cut-off (4 KiB), at or
/// under the pack cut-off (64 KiB), none block-aligned.
fn put_small(c: &Cluster, bucket: &str, count: u8) -> Vec<(String, Vec<u8>)> {
    c.json("POST", "/_admin/buckets", json!({ "name": bucket }))
        .expect_ok();
    (0..count)
        .map(|i| {
            let body = payload(5_000 + usize::from(i) * 4_999, i);
            let key = format!("o{i}");
            c.request("PUT", &format!("/{bucket}/{key}"), &body)
                .expect(200);
            (key, body)
        })
        .collect()
}

fn pack(c: &Cluster, bucket: &str, keys: &[&str]) -> Value {
    let r = c.json(
        "POST",
        "/_admin/test/pack",
        json!({ "bucket": bucket, "keys": keys }),
    );
    assert_eq!(r.status, 200, "pack: {}", r.text());
    r.json()
}

fn pack_all(c: &Cluster, bucket: &str, objects: &[(String, Vec<u8>)]) -> Value {
    let keys: Vec<&str> = objects.iter().map(|(k, _)| k.as_str()).collect();
    let report = pack(c, bucket, &keys);
    assert_eq!(
        report["packed"].as_array().map(Vec::len),
        Some(objects.len()),
        "{report}"
    );
    report
}

fn assert_readable(c: &Cluster, bucket: &str, objects: &[(String, Vec<u8>)], when: &str) {
    for (key, body) in objects {
        let r = c.request("GET", &format!("/{bucket}/{key}"), &[]);
        assert_eq!(r.status, 200, "{when}: {key}: {}", r.text());
        assert!(r.bytes == *body, "{when}: {key} reads back different bytes");
    }
}

/// Wait until the disks' used bytes satisfy `ok`, or fail after `within`.
fn await_used(c: &Cluster, what: &str, within: Duration, ok: impl Fn(u64) -> bool) -> u64 {
    let deadline = Instant::now() + within;
    loop {
        let used = c.total_used_bytes();
        if ok(used) {
            return used;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: used bytes stayed at {used}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn packed_objects_read_back_and_the_pack_goes_with_its_last_object() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    let empty = c.total_used_bytes();
    let objects = put_small(&c, "p", 12);
    let unpacked = await_used(&c, "written", Duration::from_secs(15), |u| u > empty);

    pack_all(&c, "p", &objects);
    assert_readable(&c, "p", &objects, "packed");

    // A range inside one object's slice, and its size and ETag unchanged.
    let (key, body) = &objects[5];
    let r = c.request_with_headers(
        "GET",
        &format!("/p/{key}"),
        &[],
        &[("Range", "bytes=100-1099")],
    );
    assert_eq!(r.status, 206, "{}", r.text());
    assert!(
        r.bytes == body[100..1100],
        "the range reads back different bytes"
    );
    let head = c.request("HEAD", &format!("/p/{key}"), &[]);
    assert_eq!(head.header("content-length"), Some(body.len().to_string()));

    // Each object let its own stripe go: twelve 4+2 stripes became one.
    let packed = await_used(&c, "after packing", Duration::from_secs(15), |u| {
        u < unpacked
    });
    assert!(packed < unpacked, "{packed} >= {unpacked}");

    // An overwrite leaves the rest of the pack readable.
    let fresh = payload(9_000, 200);
    c.request("PUT", "/p/o0", &fresh).expect(200);
    assert_eq!(c.request("GET", "/p/o0", &[]).bytes, fresh);
    assert_readable(&c, "p", &objects[1..], "after an overwrite");

    // Deleting every object frees the pack too.
    for (key, _) in &objects {
        c.request("DELETE", &format!("/p/{key}"), &[]).expect(204);
    }
    await_used(
        &c,
        "after deleting everything",
        Duration::from_secs(15),
        |u| u <= empty,
    );
}

/// A copy shares the pack like any stripe: it outlives its source and every
/// other object in the pack, and the pack goes only with it.
#[test]
fn a_copy_of_a_packed_object_keeps_the_pack() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    let empty = c.total_used_bytes();
    let objects = put_small(&c, "cp", 6);
    pack_all(&c, "cp", &objects);

    c.request_with_headers("PUT", "/cp/copy", &[], &[("x-amz-copy-source", "/cp/o3")])
        .expect(200);
    for (key, _) in &objects {
        c.request("DELETE", &format!("/cp/{key}"), &[]).expect(204);
    }
    std::thread::sleep(Duration::from_secs(1));
    let r = c.request("GET", "/cp/copy", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(
        r.bytes == objects[3].1,
        "the copy reads back different bytes"
    );

    c.request("DELETE", "/cp/copy", &[]).expect(204);
    await_used(
        &c,
        "after deleting the copy",
        Duration::from_secs(15),
        |u| u <= empty,
    );
}

/// What can't be packed is left as it was, and said why.
#[test]
fn what_cannot_be_packed_is_left_alone() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    let objects = put_small(&c, "s", 2);
    c.request("PUT", "/s/tiny", b"inline").expect(200);
    c.request("PUT", "/s/big", &payload(200_000, 7)).expect(200);
    let report = pack(&c, "s", &["tiny", "big", "missing", "o0"]);
    let skipped: Vec<&str> = report["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s[0].as_str())
        .collect();
    assert_eq!(skipped, ["tiny", "big", "missing"], "{report}");
    assert_readable(&c, "s", &objects, "after packing one");
    assert_eq!(c.request("GET", "/s/tiny", &[]).bytes, b"inline");
}

/// A lost pack shard is rebuilt once, from the pack's record, and the
/// packed objects then survive two more losses.
#[test]
fn a_pack_is_repaired_so_its_objects_survive_two_more_losses() {
    let mut c =
        Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks", "--repair-interval-secs", "1"]);
    let objects = put_small(&c, "r", 10);
    pack_all(&c, "r", &objects);

    c.restart_with_lost_disk(0);
    assert_readable(&c, "r", &objects, "one disk lost");
    // Every OSD holds one shard of the pack; the rebuild shows in the
    // repairer's count (the gateway refreshes meta's metrics every ~30 s).
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let rebuilt: u64 = c
            .request("GET", "/metrics", &[])
            .text()
            .lines()
            .filter(|l| {
                l.starts_with("objectio_meta_repair_shards_rebuilt_total")
                    && l.contains("reason=\"missing\"")
            })
            .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
            .sum();
        if rebuilt >= 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the pack's shard was never rebuilt"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    c.restart_with_lost_disks(&[1, 2]);
    assert_readable(&c, "r", &objects, "with two more disks lost");
}

fn node_ids(c: &Cluster) -> Vec<(String, String)> {
    let nodes = c.request("GET", "/_admin/nodes", &[]).json();
    nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            (
                n["address"].as_str().unwrap_or_default().to_string(),
                n["node_id"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn admin_state(c: &Cluster, id: &str) -> String {
    let nodes = c.request("GET", "/_admin/nodes", &[]).json();
    nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["node_id"].as_str() == Some(id))
        .and_then(|n| n["admin_state"].as_str())
        .unwrap_or("?")
        .to_string()
}

/// Drain moves a pack's shards off the OSD, recording them once in the
/// pack: the disk can then be pulled with two more lost.
#[test]
fn a_drain_moves_pack_shards() {
    let mut c =
        Cluster::start_with_ec_and_args(7, 4, 2, &["--test-hooks", "--drain-interval-secs", "1"]);
    let objects = put_small(&c, "d", 10);
    let report = pack_all(&c, "d", &objects);
    let holders: Vec<String> = report["shard_nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let ids = node_ids(&c);
    // OSD indexes holding a pack shard, by their registered address.
    let holding: Vec<(usize, String)> = (0..7)
        .filter_map(|i| {
            let addr = c.osd_address(i);
            let id = ids.iter().find(|(a, _)| *a == addr)?.1.clone();
            holders.contains(&id).then_some((i, id))
        })
        .collect();
    assert!(holding.len() >= 3, "{holding:?} of {holders:?}");
    let (drained_index, drained) = holding[0].clone();

    c.json(
        "PUT",
        &format!("/_admin/osds/{drained}/admin-state"),
        json!({ "state": "draining" }),
    )
    .expect_ok();
    let deadline = Instant::now() + Duration::from_secs(240);
    while admin_state(&c, &drained) != "out" {
        assert!(
            Instant::now() < deadline,
            "never finished draining: {}",
            admin_state(&c, &drained)
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    // Pull the drained disk, and lose two more of the pack's.
    c.restart_with_lost_disks(&[drained_index, holding[1].0, holding[2].0]);
    assert_readable(&c, "d", &objects, "drained, and two more lost");
}
