//! How fast repair rebuilds a replaced disk (B24): measured, not a pass or
//! fail of correctness (the `repair` tests are). Ignored by default:
//!
//! ```text
//! cargo test -p objectio-e2e --test repair_throughput -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use objectio_e2e::ha::HaCluster;

fn rebuilt(ha: &HaCluster) -> u64 {
    let m = ha.clients[0].request("GET", "/metrics", &[]).text();
    m.lines()
        .filter(|l| l.starts_with("objectio_meta_repair_shards_rebuilt_total"))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

#[test]
#[ignore = "a measurement; run on demand"]
fn a_replaced_disk_is_rebuilt_at_this_rate() {
    let objects: usize = std::env::var("OBJECTS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);
    let mut ha = HaCluster::start_with_meta_args(1, 6, 1, &["--repair-interval-secs", "5"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/thru", &[]).status, 200);
    let body = vec![7u8; 16 * 1024];
    for i in 0..objects {
        assert_eq!(c.request("PUT", &format!("/thru/k{i}"), &body).status, 200);
    }
    // Every object has a shard on each of the six OSDs: replace one's disk.
    ha.stop_osd(5);
    std::fs::remove_file(ha.osd_disk(5)).unwrap();
    let before = rebuilt(&ha);
    let started = Instant::now();
    ha.start_osd(5, None);
    let target = before + objects as u64;
    while rebuilt(&ha) < target {
        assert!(
            started.elapsed() < Duration::from_secs(1800),
            "rebuilt {} of {objects} in 30 minutes",
            rebuilt(&ha) - before
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    let secs = started.elapsed().as_secs_f64();
    eprintln!(
        "rebuilt {objects} shards in {secs:.1} s: {:.0} shards/s",
        f64::from(u32::try_from(objects).unwrap_or(u32::MAX)) / secs
    );
}
