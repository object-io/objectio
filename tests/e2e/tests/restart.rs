//! What a cluster serves immediately after it comes back up.
//!
//! Meta's OSD list is persisted, so a restart replays it — and the topology
//! was rebuilt from that list with every node marked live, because status was
//! derived from `admin_state` alone. `admin_state` is operator intent; it says
//! nothing about whether a node is there. A registration for an OSD that had
//! been gone for days therefore came back Active and placement handed it out,
//! and object reads answered 500 `InternalError` until the liveness prober
//! had missed three probes at the steady-state interval — thirty seconds,
//! every restart. Observed on the live deployment, in the logs:
//!
//! ```text
//! 10:57:14  Loaded 2 OSD nodes from store
//! 10:57:40  ERROR Failed to get object metadata from OSDs: transport error
//! 10:57:44  WARN  OSD 92486c11 ... missed 3 probes — taking it out of placement
//! ```

use objectio_e2e::Cluster;
use serde_json::json;

/// The floor: a restart must not cost the data.
#[test]
fn objects_survive_a_restart() {
    let mut c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "restarts"}))
        .expect_ok();
    let payload = vec![7u8; 1024 * 1024];
    c.request("PUT", "/restarts/kept.bin", &payload).expect(200);

    c.restart();

    let got = c.request("GET", "/restarts/kept.bin", &[]);
    got.expect(200);
    assert_eq!(got.bytes, payload, "the object changed across a restart");
}

/// And they must be readable *immediately*, not after a liveness sweep.
///
/// `wait_healthy` returns as soon as the gateway answers, which is when a load
/// balancer would start sending it traffic. Every read here happens inside the
/// window where a resurrected dead node used to be in placement.
#[test]
fn reads_work_the_moment_the_gateway_answers() {
    let mut c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "no-window"}))
        .expect_ok();
    for i in 0..5 {
        c.request(
            "PUT",
            &format!("/no-window/obj-{i}"),
            format!("body-{i}").as_bytes(),
        )
        .expect(200);
    }

    c.restart();

    // No sleep, no retry: the first request after the gateway says it is up.
    for i in 0..5 {
        let got = c.request("GET", &format!("/no-window/obj-{i}"), &[]);
        assert_eq!(
            got.status,
            200,
            "read {i} failed right after restart with {}: {}",
            got.status,
            got.text()
        );
        assert_eq!(got.text(), format!("body-{i}"));
    }
}

/// Writes too — placement has to have somewhere to put them straight away.
///
/// The other half of the trade: marking stored nodes `Down` until probed would
/// be no good if it left the cluster with nothing to write to. The prober
/// sweeps immediately on startup and restores a node on its first success, so
/// the live OSD is back in placement before the gateway is answering.
#[test]
fn writes_work_the_moment_the_gateway_answers() {
    let mut c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "write-after"}))
        .expect_ok();
    c.request("PUT", "/write-after/before.bin", b"before")
        .expect(200);

    c.restart();

    c.request("PUT", "/write-after/after.bin", b"after")
        .expect(200);
    let got = c.request("GET", "/write-after/after.bin", &[]);
    got.expect(200);
    assert_eq!(got.text(), "after");
}

/// Restarting repeatedly must not accumulate anything that degrades the
/// cluster — each restart re-registers the OSD rather than adding a second
/// entry for it.
#[test]
fn repeated_restarts_stay_healthy() {
    let mut c = Cluster::start();
    c.json("POST", "/_admin/buckets", json!({"name": "churn"}))
        .expect_ok();
    c.request("PUT", "/churn/x.bin", b"payload").expect(200);

    for round in 0..3 {
        c.restart();
        let got = c.request("GET", "/churn/x.bin", &[]);
        assert_eq!(
            got.status,
            200,
            "read failed after restart {round}: {}",
            got.text()
        );
        let nodes = c.request("GET", "/_admin/nodes", &[]);
        nodes.expect(200);
        let v = nodes.json();
        let n = v["nodes"].as_array().map_or(0, Vec::len);
        assert_eq!(
            n, 1,
            "restart {round} left {n} OSD registrations, expected 1"
        );
    }
}

// A faithful reproduction of the live failure — a registration for an OSD that
// is gone while another still holds the data — is not expressible here. The
// only way to retire an OSD through this harness is to restart with fewer, and
// that takes its shards with it: the reads then fail because the data really is
// unreachable, which is a durability question and not this one. What the live
// cluster had was a *ghost* registration left by an identity reset, holding
// nothing. `topology_status` in objectio-meta is where that decision lives and
// where it is pinned; these tests cover the other half — that requiring a
// probe before a node counts as Active does not cost a healthy cluster
// anything on the way back up.
