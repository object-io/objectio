//! A gateway whose clock is far from meta's refuses writes: its stamps
//! would order them wrongly against the other gateways'
//! (core/object-metadata-quorum.md, "Stamps").

use std::time::Duration;

use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use serde_json::json;

#[test]
fn a_gateway_with_a_wrong_clock_refuses_writes() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-clock-offset-ms=3000"]);
    c.json("POST", "/_admin/buckets", json!({"name": "skew"}))
        .expect_ok();

    // The first comparison with meta's clock comes within a second.
    let mut put = c.request("PUT", "/skew/k", b"data");
    for _ in 0..50 {
        if put.status == 503 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
        put = c.request("PUT", "/skew/k", b"data");
    }
    assert_eq!(put.status, 503, "a write stamped 3 s ahead: {}", put.text());
    assert!(put.text().contains("clock"), "{}", put.text());
    assert_eq!(c.request("DELETE", "/skew/k", &[]).status, 503);

    let metrics = c.request("GET", "/metrics", &[]).text();
    assert!(
        metrics.contains("objectio_gateway_clock_skewed 1"),
        "{}",
        metrics
            .lines()
            .filter(|l| l.contains("clock"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Gateways' clocks differ by less than the limit, yet a write that
/// follows another through a gateway whose clock is behind takes effect:
/// it is stamped above what the copies hold. It was acknowledged and lost
/// (the B2 soak found it), for overwrites, deletes and a PUT after a
/// delete alike.
#[test]
fn a_later_write_through_a_slower_clock_still_wins() {
    let mut ha = HaCluster::start(1, 6, 1); // gateway 0: the system's clock
    let _ = ha.await_leader(Duration::from_secs(30));
    ha.add_gateway_with_args(None, &["--test-clock-offset-ms=300"]); // gateway 1: ahead
    let (slow, fast) = (&ha.clients[0], &ha.clients[1]);
    assert_eq!(slow.request("PUT", "/order", &[]).status, 200);

    for round in 0..20u8 {
        let key = format!("/order/k{round}");
        let first = vec![round; 3_000 + usize::from(round)];
        let then = vec![round ^ 0xff; 2_000 + usize::from(round)];
        assert_eq!(fast.request("PUT", &key, &first).status, 200);
        assert_eq!(slow.request("PUT", &key, &then).status, 200);
        for c in [slow, fast] {
            let got = c.request("GET", &key, &[]);
            assert!(got.bytes == then, "round {round}: the later overwrite lost");
        }

        assert_eq!(fast.request("PUT", &key, &first).status, 200);
        assert_eq!(slow.request("DELETE", &key, &[]).status, 204);
        assert_eq!(
            fast.request("GET", &key, &[]).status,
            404,
            "round {round}: the delete lost"
        );

        assert_eq!(fast.request("DELETE", &key, &[]).status, 204);
        assert_eq!(slow.request("PUT", &key, &then).status, 200);
        assert!(
            fast.request("GET", &key, &[]).bytes == then,
            "round {round}: the PUT after a delete lost"
        );
    }
}
