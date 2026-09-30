//! The erasure-coded data path over Mooncake Transfer Engine.
//!
//! Needs an `objectio-aio` built with `--features rdma`, which needs a
//! Mooncake build, so these run only when `OBJECTIO_E2E_RDMA` names the
//! protocol aio is given (`tcp` in CI — no RDMA hardware). CI's `rdma` job
//! runs them in a Mooncake image; everywhere else they pass as no-ops.

use objectio_e2e::Cluster;
use serde_json::json;

fn protocol() -> Option<String> {
    std::env::var("OBJECTIO_E2E_RDMA")
        .ok()
        .filter(|p| !p.is_empty())
}

/// Sum of every sample of `name` whose labels contain all of `labels`.
fn metric(c: &Cluster, name: &str, labels: &[&str]) -> f64 {
    c.request("GET", "/metrics", &[])
        .text()
        .lines()
        .filter(|l| {
            l.split(['{', ' ']).next() == Some(name) && labels.iter().all(|want| l.contains(want))
        })
        .filter_map(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
        .sum()
}

fn payload(len: usize, seed: u32) -> Vec<u8> {
    (0..len)
        .map(|i| u8::try_from((u32::try_from(i).unwrap() ^ seed) % 251).unwrap())
        .collect()
}

/// Every shard of every object moves over Transfer Engine, and every object
/// comes back byte for byte — from one byte up to two stripes.
#[test]
fn objects_round_trip_with_every_shard_over_transfer_engine() {
    let Some(protocol) = protocol() else {
        eprintln!("skipped: set OBJECTIO_E2E_RDMA to run against an aio built with rdma");
        return;
    };
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--rdma", &protocol]);
    c.json("POST", "/_admin/buckets", json!({"name": "rdma"}))
        .expect_ok();

    for (n, len) in [1, 1000, 64 * 1024, 1024 * 1024 + 1, 4 << 20, 20 << 20]
        .into_iter()
        .enumerate()
    {
        let body = payload(len, u32::try_from(n).unwrap());
        let path = format!("/rdma/o-{len}");
        c.request("PUT", &path, &body).expect(200);
        let got = c.request("GET", &path, &[]);
        got.expect(200);
        assert_eq!(got.bytes, body, "{len}-byte object changed over rdma");
    }

    let shards = "objectio_gateway_shard_transfers_total";
    for direction in ["write", "read"] {
        let dir = format!("direction=\"{direction}\"");
        assert!(
            metric(&c, shards, &[&dir, "transport=\"rdma\""]) > 0.0,
            "no shard {direction} went over rdma"
        );
        assert!(
            metric(&c, shards, &[&dir, "transport=\"grpc\""]) < 1.0,
            "a shard {direction} went over grpc"
        );
    }
    assert!(
        metric(&c, "objectio_gateway_rdma_fallbacks_total", &[]) < 1.0,
        "a shard fell back to grpc on a healthy cluster"
    );
}

/// With Transfer Engine on, a stripe that lost a shard still reads: the
/// failed rdma read of the missing shard falls back, and the stripe is
/// rebuilt from the others.
#[test]
fn a_degraded_read_over_transfer_engine_still_returns_the_object() {
    let Some(protocol) = protocol() else {
        eprintln!("skipped: set OBJECTIO_E2E_RDMA to run against an aio built with rdma");
        return;
    };
    let mut c = Cluster::start_with_ec_and_args(6, 4, 2, &["--rdma", &protocol]);
    c.json("POST", "/_admin/buckets", json!({"name": "rdma-degraded"}))
        .expect_ok();

    let objects: Vec<(String, Vec<u8>)> = (0..8u32)
        .map(|n| {
            (
                format!("/rdma-degraded/o-{n}"),
                payload(1024 * 1024 + 4099 * n as usize, n),
            )
        })
        .collect();
    for (path, body) in &objects {
        c.request("PUT", path, body).expect(200);
    }

    c.restart_with_lost_disk(4);

    for (path, body) in &objects {
        let got = c.request("GET", path, &[]);
        got.expect(200);
        assert_eq!(&got.bytes, body, "{path} changed after losing a shard");
    }
    assert!(
        metric(
            &c,
            "objectio_gateway_shard_transfers_total",
            &["direction=\"read\"", "transport=\"rdma\""]
        ) > 0.0,
        "reads stopped using rdma altogether"
    );
}
