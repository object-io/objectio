//! A full cluster (B3): client writes stop at each OSD's full ratio with
//! 507 `StorageFull`, which clients don't retry blindly; nothing that was
//! acknowledged is lost; the space past the ratio stays free for repair;
//! and deleting makes room again.

use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use serde_json::json;

const OBJECT: usize = 4 << 20;

/// Bytes that don't repeat, different for every seed.
fn payload(seed: u64) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ seed.wrapping_mul(0x2545_F491_4F6C_DD1D);
    (0..OBJECT)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// The highest share of its disk any OSD has used.
fn fullest(c: &Cluster) -> f64 {
    c.request("GET", "/_admin/nodes", &[]).json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            let used = n["used_capacity"].as_f64().unwrap_or(0.0);
            let total = n["total_capacity"].as_f64().unwrap_or(1.0);
            used / total
        })
        .fold(0.0, f64::max)
}

#[test]
fn a_full_cluster_refuses_writes_cleanly_and_deletes_make_room() {
    // 1 GiB disks (the smallest an OSD takes): it fills in a minute or two.
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--disk-size", "1073741824"]);
    c.json("POST", "/_admin/buckets", json!({"name": "full"}))
        .expect_ok();

    let mut acked: Vec<u64> = Vec::new();
    let mut refusals = 0;
    for i in 0..2000u64 {
        let r = c.request("PUT", &format!("/full/o{i}"), &payload(i));
        match r.status {
            200 => acked.push(i),
            507 => {
                assert!(r.text().contains("StorageFull"), "{}", r.text());
                refusals += 1;
                if refusals == 5 {
                    break;
                }
            }
            s => panic!("o{i}: {s} {}", r.text()),
        }
    }
    assert_eq!(refusals, 5, "the cluster never filled");
    assert!(acked.len() > 100, "full after only {} objects", acked.len());

    // The space past the full ratio (95%) stays free for repair: at most
    // one shard's worth over it.
    let used = fullest(&c);
    assert!(used < 0.97, "an OSD filled to {used:.3} of its disk");

    // Nothing acknowledged was lost: every fifth, and the last ones, written
    // as the disks filled.
    let tail = acked.len().saturating_sub(20);
    let sample = acked
        .iter()
        .enumerate()
        .filter(|(n, _)| n % 5 == 0 || *n >= tail)
        .map(|(_, i)| i);
    for i in sample {
        let r = c.request("GET", &format!("/full/o{i}"), &[]);
        assert_eq!(r.status, 200, "o{i}: {}", r.text());
        assert!(r.bytes == payload(*i), "o{i} reads back different bytes");
    }

    // Deleting half makes room again.
    for i in acked.iter().step_by(2) {
        c.request("DELETE", &format!("/full/o{i}"), &[]).expect(204);
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let r = c.request("PUT", "/full/after", &payload(9999));
        if r.status == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "deletes never made room: {}",
            r.status
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}
