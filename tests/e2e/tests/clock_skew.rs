//! A gateway whose clock is far from meta's refuses writes: its stamps
//! would order them wrongly against the other gateways'
//! (core/object-metadata-quorum.md, "Stamps").

use objectio_e2e::Cluster;
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
