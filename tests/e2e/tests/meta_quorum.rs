//! Object metadata at quorum (objectio-docs core/object-metadata-quorum.md):
//! the copies of an object's `ObjectMeta`, one per OSD of its placement.

use std::time::Duration;

use objectio_e2e::ha::HaCluster;

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| i.to_le_bytes()[0].wrapping_mul(31) ^ seed)
        .collect()
}

/// A copy that missed a write never wins a read: with one OSD down, an
/// overwrite reaches the other copies; when the OSD is back with the old
/// copy, every read gives the newer object.
#[test]
fn a_copy_that_missed_a_write_never_wins_a_read() {
    let mut ha = HaCluster::start(1, 6, 2);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    let r = c.request("PUT", "/quorum", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    let old = payload(40_000, 1);
    assert_eq!(c.request("PUT", "/quorum/k", &old).status, 200);

    // Every OSD holds a copy (6 OSDs, 4+2). Stale each in turn, so one of
    // them is the copy a read would ask first.
    for osd in 0..6u8 {
        await_writable(&ha.clients[0]);
        ha.stop_osd(usize::from(osd));
        let new = payload(50_000, 2 + osd);
        let put = ha.clients[0].request("PUT", "/quorum/k", &new);
        // With a copy down the PUT fails, after its shards and the other
        // copies' ObjectMeta are written.
        assert!(
            put.status == 200 || put.text().contains("store object metadata"),
            "OSD {osd} down: the overwrite did not reach the metadata: {}",
            put.text()
        );
        ha.start_osd(usize::from(osd), None);

        for (g, c) in ha.clients.iter().enumerate() {
            let r = c.request("GET", "/quorum/k", &[]);
            assert_eq!(r.status, 200, "OSD {osd} stale, gateway {g}: {}", r.text());
            assert!(
                r.bytes == new,
                "OSD {osd} stale, gateway {g}: the copy that missed the overwrite won"
            );
        }
    }
}

/// Wait until a PUT succeeds: every OSD up and reachable again.
fn await_writable(c: &objectio_e2e::Cluster) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while c.request("PUT", "/quorum/probe", b"probe").status != 200 {
        assert!(std::time::Instant::now() < deadline, "writes never resumed");
        std::thread::sleep(Duration::from_millis(500));
    }
}
