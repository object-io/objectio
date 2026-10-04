//! Restoring redundancy: Meta's repairer rebuilding shards an OSD lost or
//! that rotted on disk, found by asking the OSDs (and their scrubbers).
//!
//! Every object here is 4+2 on six OSDs, one shard per OSD, so any four
//! OSDs can serve it and losing a disk costs every object one shard.

use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use serde_json::json;

/// Sum of every sample of `name` whose labels contain all of `labels`.
fn metric(c: &Cluster, name: &str, labels: &[&str]) -> u64 {
    c.request("GET", "/metrics", &[])
        .text()
        .lines()
        .filter(|l| {
            l.split(['{', ' ']).next() == Some(name) && labels.iter().all(|want| l.contains(want))
        })
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// Wait until `name{labels}` reaches `want`, or fail after `within`. The
/// gateway refreshes meta's and the OSDs' metrics about every 30 s.
fn await_metric(c: &Cluster, name: &str, labels: &[&str], want: u64, within: Duration) {
    let deadline = Instant::now() + within;
    loop {
        let got = metric(c, name, labels);
        if got >= want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{name}{labels:?} stayed at {got}, wanted {want}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Bytes that do not repeat, so a run of them identifies one shard.
fn payload(len: usize, seed: u8) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ u64::from(seed);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

const OBJECTS: usize = 4;

fn put_objects(c: &Cluster, bucket: &str) -> Vec<Vec<u8>> {
    c.json("POST", "/_admin/buckets", json!({"name": bucket}))
        .expect_ok();
    (0..OBJECTS)
        .map(|i| {
            let body = payload(300_000, u8::try_from(i).unwrap());
            c.request("PUT", &format!("/{bucket}/o-{i}"), &body)
                .expect(200);
            body
        })
        .collect()
}

fn assert_readable(c: &Cluster, bucket: &str, bodies: &[Vec<u8>], when: &str) {
    for (i, body) in bodies.iter().enumerate() {
        let got = c.request("GET", &format!("/{bucket}/o-{i}"), &[]);
        assert_eq!(got.status, 200, "o-{i} unreadable {when}: {}", got.text());
        assert_eq!(&got.bytes, body, "o-{i} changed {when}");
    }
}

/// The point of repairing: after a disk is lost and rebuilt, the objects
/// survive two more losses. Without the rebuild, three lost shards out of
/// six would leave three — one short of k.
#[test]
fn a_lost_disk_is_rebuilt_so_objects_survive_two_more_losses() {
    let mut c = Cluster::start_with_ec_and_args(6, 4, 2, &["--repair-interval-secs", "1"]);
    let bodies = put_objects(&c, "lost");

    c.restart_with_lost_disk(0);
    await_metric(
        &c,
        "objectio_meta_repair_shards_rebuilt_total",
        &["reason=\"missing\""],
        OBJECTS as u64,
        Duration::from_secs(120),
    );
    assert_readable(&c, "lost", &bodies, "after the rebuild");

    c.restart_with_lost_disks(&[1, 2]);
    assert_readable(&c, "lost", &bodies, "with two more disks lost");
}

/// Flip one byte of `needle` in `path`, the way a bad sector would. Shards
/// sit at the front of a fresh disk's data region, which begins after the
/// 1 GiB metadata area.
fn rot(path: &std::path::Path, needle: &[u8]) -> bool {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let chunk = 8 << 20;
    let mut buf = vec![0u8; chunk + needle.len()];
    let mut base = 1u64 << 30;
    for _ in 0..64 {
        f.seek(SeekFrom::Start(base)).unwrap();
        let n = f.read(&mut buf).unwrap();
        if let Some(at) = buf[..n].windows(needle.len()).position(|w| w == needle) {
            let at = base + (at + needle.len() / 2) as u64;
            let mut b = [0u8];
            f.seek(SeekFrom::Start(at)).unwrap();
            f.read_exact(&mut b).unwrap();
            f.seek(SeekFrom::Start(at)).unwrap();
            f.write_all(&[b[0] ^ 0xff]).unwrap();
            f.sync_all().unwrap();
            return true;
        }
        if n < buf.len() {
            return false;
        }
        base += chunk as u64;
    }
    false
}

/// Rot nobody reads is found by the scrubber and rebuilt in place, and the
/// object reads back correctly throughout.
#[test]
fn a_rotted_shard_is_found_by_the_scrubber_and_rebuilt() {
    let c = Cluster::start_with_ec_and_args(
        6,
        4,
        2,
        &["--repair-interval-secs", "1", "--scrub-interval-secs", "1"],
    );
    c.json("POST", "/_admin/buckets", json!({"name": "rot"}))
        .expect_ok();
    let body = payload(400_000, 0x5a);
    c.request("PUT", "/rot/o", &body).expect(200);

    // The first data shard holds the first quarter of the body.
    let needle = &body[1000..1064];
    let rotted = (0..6).any(|i| rot(&c.osd_disk(i), needle));
    assert!(rotted, "shard bytes not found on any disk");

    await_metric(
        &c,
        "objectio_meta_repair_shards_rebuilt_total",
        &["reason=\"corrupt\""],
        1,
        Duration::from_secs(120),
    );
    let got = c.request("GET", "/rot/o", &[]);
    got.expect(200);
    assert_eq!(got.bytes, body);
}

/// OSD `index`'s node id, as `/_admin/nodes` lists it.
fn osd_id(c: &Cluster, index: usize) -> String {
    let addr = c.osd_address(index);
    c.request("GET", "/_admin/nodes", &[]).json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["address"].as_str() == Some(addr.as_str()))
        .and_then(|n| n["node_id"].as_str())
        .unwrap_or_else(|| panic!("no OSD at {addr}"))
        .to_string()
}

/// OSD `index`'s shard count, from `/_admin/nodes`.
fn shard_count(c: &Cluster, index: usize) -> u64 {
    let id = osd_id(c, index);
    c.request("GET", "/_admin/nodes", &[]).json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["node_id"].as_str() == Some(id.as_str()))
        .and_then(|n| n["shard_count"].as_u64())
        .unwrap_or(0)
}

/// Backfill (B20): objects written while an OSD is out have two shards on
/// one of the other five; once it is back in, the repairer moves one of
/// them to it, so every OSD holds one shard of each object again and the
/// objects survive any two losses.
#[test]
fn shards_doubled_up_while_an_osd_was_out_are_spread_when_it_is_back() {
    let mut c = Cluster::start_with_ec_and_args(6, 4, 2, &["--repair-interval-secs", "1"]);
    let out = osd_id(&c, 0);
    let set = |state: &str| {
        c.json(
            "PUT",
            &format!("/_admin/osds/{out}/admin-state"),
            json!({ "state": state }),
        )
        .expect_ok();
    };
    set("out");
    let bodies = put_objects(&c, "spread");
    let counts: Vec<u64> = (0..6).map(|i| shard_count(&c, i)).collect();
    let hot = counts
        .iter()
        .position(|n| *n > OBJECTS as u64)
        .unwrap_or_else(|| panic!("nothing doubled up with an OSD out: {counts:?}"));

    set("in");
    // Moved, and the old copies deleted after their grace.
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        let counts: Vec<u64> = (0..6).map(|i| shard_count(&c, i)).collect();
        if counts.iter().all(|n| *n == OBJECTS as u64) {
            break;
        }
        assert!(Instant::now() < deadline, "shards never spread: {counts:?}");
        std::thread::sleep(Duration::from_secs(1));
    }
    assert!(metric(&c, "objectio_meta_repair_shards_moved_total", &[]) >= OBJECTS as u64);
    assert_readable(&c, "spread", &bodies, "after the shards were spread");

    // The OSD that held two of each, and one more.
    c.restart_with_lost_disks(&[hot, (hot + 1) % 6]);
    assert_readable(&c, "spread", &bodies, "with two disks lost");
}
