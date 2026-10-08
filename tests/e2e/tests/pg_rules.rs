//! Placement rules (B31 phase 1b, objectio-docs `core/pg-recovery.md`): a
//! pool's copies spread over a number of racks with a limit per rack, and
//! an LRC pool's local groups each kept in a rack of their own; placement
//! groups made, and members stood in for, only within the rule.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use serde_json::{Value, json};

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

/// Every OSD's node id (hex), by index.
fn node_ids(ha: &HaCluster, count: usize) -> Vec<String> {
    let nodes = ha.clients[0].request("GET", "/_admin/nodes", &[]).json();
    (0..count)
        .map(|i| {
            let endpoint = ha.osd_endpoint(i);
            nodes["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .find(|n| n["address"].as_str() == Some(endpoint.as_str()))
                .and_then(|n| n["node_id"].as_str())
                .unwrap_or_else(|| panic!("OSD {i} at {endpoint} not registered: {nodes}"))
                .to_string()
        })
        .collect()
}

/// Every OSD's rack, by node id (hex).
fn racks_by_id(ha: &HaCluster, racks: &[&str]) -> HashMap<String, String> {
    node_ids(ha, racks.len())
        .into_iter()
        .zip(racks.iter().map(ToString::to_string))
        .collect()
}

/// A pool's placement groups, each as its acting set (hex ids).
fn acting_sets(c: &Cluster, pool: &str) -> Vec<Vec<String>> {
    let pgs: Value = c
        .request(
            "GET",
            &format!("/_admin/pools/{pool}/placement-groups"),
            &[],
        )
        .json();
    pgs["pgs"]
        .as_array()
        .unwrap_or_else(|| panic!("no placement groups: {pgs}"))
        .iter()
        .map(|pg| {
            pg["acting"]
                .as_array()
                .unwrap()
                .iter()
                .map(|m| m.as_str().unwrap().to_string())
                .collect()
        })
        .collect()
}

/// Copies per rack in `acting`.
fn per_rack(acting: &[String], rack: &HashMap<String, String>) -> HashMap<String, usize> {
    let mut out: HashMap<String, usize> = HashMap::new();
    for id in acting {
        *out.entry(rack[id].clone()).or_insert(0) += 1;
    }
    out
}

fn make_pool(c: &Cluster, body: Value) {
    let r = c.json("POST", "/_admin/pools", body);
    assert!(r.status < 300, "pool: {}", r.text());
}

fn bucket_in(c: &Cluster, bucket: &str, pool: &str) {
    c.request_with_headers(
        "PUT",
        &format!("/{bucket}"),
        &[],
        &[("x-objectio-pool", pool)],
    )
    .expect(200);
}

fn set_out(c: &Cluster, id: &str) {
    c.json(
        "PUT",
        &format!("/_admin/osds/{id}/admin-state"),
        json!({ "state": "out" }),
    )
    .expect_ok();
}

/// 4+2 over three racks, two copies in each: every placement group's
/// members are two per rack, each on its own host. With a whole rack down
/// (both its OSDs) every object still reads: 4 shards are left, k = 4.
/// Writes need k + 1 = 5 copies, so they are refused while the rack is
/// down (as Ceph's EC `min_size` holds them) and go through once it is
/// back.
#[test]
fn a_pool_two_per_rack_reads_through_a_whole_rack_lost() {
    let racks = ["A", "A", "B", "B", "C", "C"];
    let mut ha = HaCluster::start_with_osd_racks(1, &racks, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    make_pool(
        c,
        json!({"name": "r3", "ec_type": 0, "ec_k": 4, "ec_m": 2,
            "failure_domain": "rack", "per_domain": 2, "pg_count": 8, "enabled": true}),
    );
    let rack = racks_by_id(&ha, &racks);
    let sets = acting_sets(c, "r3");
    assert_eq!(sets.len(), 8, "{sets:?}");
    for acting in &sets {
        let counts = per_rack(acting, &rack);
        assert_eq!(counts.len(), 3, "{acting:?}");
        assert!(counts.values().all(|n| *n == 2), "{counts:?}");
    }

    bucket_in(c, "spread", "r3");
    let bodies: Vec<Vec<u8>> = (0..12u8).map(|i| payload(300_000, i)).collect();
    for (i, b) in bodies.iter().enumerate() {
        assert_eq!(c.request("PUT", &format!("/spread/k{i}"), b).status, 200);
    }

    ha.stop_osd(0);
    ha.stop_osd(1);
    let c = &ha.clients[0];
    for (i, b) in bodies.iter().enumerate() {
        let got = c.request("GET", &format!("/spread/k{i}"), &[]);
        assert_eq!(got.status, 200, "k{i} with rack A down: {}", got.text());
        assert_eq!(&got.bytes, b, "k{i}");
    }
    let refused = c.request("PUT", "/spread/new", &payload(300_000, 99));
    assert_eq!(
        refused.status,
        503,
        "a write with only 4 of 6 copies reachable: {}",
        refused.text()
    );

    ha.start_osd(0, None);
    ha.start_osd(1, None);
    let c = &ha.clients[0];
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let r = c.request("PUT", "/spread/new", &payload(300_000, 99));
        if r.status == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "writes never came back with rack A: {}",
            r.text()
        );
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// A pool can't have a rule the racks can't hold: four racks asked of
/// three is refused when the pool is made, and nothing is made.
#[test]
fn a_rule_the_racks_cannot_hold_is_refused() {
    let racks = ["A", "A", "B", "B", "C", "C"];
    let ha = HaCluster::start_with_osd_racks(1, &racks, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    let r = c.json(
        "POST",
        "/_admin/pools",
        json!({"name": "r4", "ec_type": 0, "ec_k": 4, "ec_m": 2, "failure_domain": "rack",
            "spread_domains": 4, "per_domain": 2, "pg_count": 8, "enabled": true}),
    );
    assert!((400..500).contains(&r.status), "{}: {}", r.status, r.text());
    // Three per rack puts 4+2 in two racks, three hosts in each; these
    // racks have two hosts.
    let r = c.json(
        "POST",
        "/_admin/pools",
        json!({"name": "r2", "ec_type": 0, "ec_k": 4, "ec_m": 2, "failure_domain": "rack",
            "per_domain": 3, "pg_count": 8, "enabled": true}),
    );
    assert!((400..500).contains(&r.status), "{}: {}", r.status, r.text());
    let pools = c.request("GET", "/_admin/pools", &[]).text();
    assert!(
        !pools.contains("\"r4\"") && !pools.contains("\"r2\""),
        "{pools}"
    );
}

/// A stand-in keeps the rule. Racks: A holds three OSDs, B and C two; 4+2
/// with two per rack uses both of B's in every placement group. B's OSD
/// set out can't be stood in for (A's spare would make three in A): its
/// PGs are left undersized. A's set out is stood in for by A's spare.
#[test]
fn a_stand_in_never_breaks_the_rule() {
    let racks = ["A", "A", "A", "B", "B", "C", "C"];
    let ha = HaCluster::start_with_osd_racks(1, &racks, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    make_pool(
        c,
        json!({"name": "r3", "ec_type": 0, "ec_k": 4, "ec_m": 2,
            "failure_domain": "rack", "per_domain": 2, "pg_count": 16, "enabled": true}),
    );
    let rack = racks_by_id(&ha, &racks);
    let ids = node_ids(&ha, racks.len());
    let id_of = |i: usize| ids[i].clone();
    let assert_rule = |when: &str, sets: &[Vec<String>]| {
        for acting in sets {
            let counts = per_rack(acting, &rack);
            assert!(
                counts.values().all(|n| *n <= 2),
                "{when}: {counts:?} in {acting:?}"
            );
        }
    };
    assert_rule("made", &acting_sets(c, "r3"));

    let b = id_of(3);
    set_out(c, &b);
    // Long enough for the leader to have tried (it looks every 2 s).
    std::thread::sleep(Duration::from_secs(8));
    let sets = acting_sets(c, "r3");
    assert_rule("B's OSD out", &sets);
    assert!(
        sets.iter().all(|acting| acting.contains(&b)),
        "B's OSD was stood in for outside the rule: {sets:?}"
    );

    let a = id_of(0);
    let held: usize = sets.iter().filter(|s| s.contains(&a)).count();
    assert!(held > 0, "OSD 0 in no placement group: {sets:?}");
    set_out(c, &a);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let sets = acting_sets(c, "r3");
        assert_rule("A's OSD out", &sets);
        if sets.iter().all(|s| !s.contains(&a)) {
            for acting in &sets {
                assert_eq!(per_rack(acting, &rack).get("A"), Some(&2), "{acting:?}");
            }
            break;
        }
        assert!(
            Instant::now() < deadline,
            "A's OSD never stood in for: {sets:?}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// LRC 4+2+1 with each local group in a rack of its own: positions 0, 1
/// (data) and 4 (their local parity) in one rack, 2, 3 and 5 in another,
/// the global parity (6) in a third. Objects write and read; with a
/// group's member set out, its stand-in comes from the group's own rack,
/// and every object still reads.
#[test]
fn an_lrc_pool_keeps_each_local_group_in_a_rack() {
    let racks = ["A", "A", "A", "A", "B", "B", "B", "B", "C", "C"];
    // LRC isn't released (no repair yet, B10): made for its placement only.
    let ha = HaCluster::start_with_racks(1, &racks, 1, &["--allow-unrepaired-schemes"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    make_pool(
        c,
        json!({"name": "lrc", "ec_type": 1, "ec_k": 4, "ec_m": 3, "ec_local_parity": 2,
            "ec_global_parity": 1, "failure_domain": "rack", "lrc_groups_per_domain": true,
            "pg_count": 8, "enabled": true}),
    );
    let rack = racks_by_id(&ha, &racks);
    let groups_hold = |sets: &[Vec<String>]| {
        for acting in sets {
            let r: Vec<&String> = acting.iter().map(|id| &rack[id]).collect();
            assert_eq!(r.len(), 7, "{acting:?}");
            assert!(r[0] == r[1] && r[1] == r[4], "group 0 split: {r:?}");
            assert!(r[2] == r[3] && r[3] == r[5], "group 1 split: {r:?}");
            assert_ne!(r[0], r[2], "both groups in one rack: {r:?}");
            assert!(
                r[6] != r[0] && r[6] != r[2],
                "global parity with a group: {r:?}"
            );
        }
    };
    let sets = acting_sets(c, "lrc");
    assert_eq!(sets.len(), 8, "{sets:?}");
    groups_hold(&sets);

    bucket_in(c, "local", "lrc");
    let bodies: Vec<Vec<u8>> = (0..8u8).map(|i| payload(300_000, 40 + i)).collect();
    for (i, b) in bodies.iter().enumerate() {
        let r = c.request("PUT", &format!("/local/k{i}"), b);
        assert_eq!(r.status, 200, "k{i}: {}", r.text());
    }

    // A data member of group 0 in the first placement group, set out.
    let out = sets[0][1].clone();
    set_out(c, &out);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let sets = acting_sets(c, "lrc");
        groups_hold(&sets);
        if sets.iter().all(|s| !s.contains(&out)) {
            break;
        }
        assert!(Instant::now() < deadline, "never stood in for: {sets:?}");
        std::thread::sleep(Duration::from_millis(500));
    }
    for (i, b) in bodies.iter().enumerate() {
        let got = c.request("GET", &format!("/local/k{i}"), &[]);
        assert_eq!(got.status, 200, "k{i}: {}", got.text());
        assert_eq!(&got.bytes, b, "k{i}");
    }
}
