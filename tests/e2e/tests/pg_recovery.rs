//! Recovery by placement group (B31 phase 3a, objectio-docs
//! `core/pg-recovery.md`): peering's findings acted on. The exit test, for
//! MDS erasure coding:
//!
//! - a lost drive takes its PGs through backfill to clean, and every object
//!   then survives two more OSDs down;
//! - a leader change in the middle of a backfill resumes from its cursor;
//! - a member to fill that is too full holds the PG in `WaitTooFull` until
//!   it has room;
//! - copies an overwrite left stale are brought up to date;
//! - a write short of shards is recovered in seconds;
//! - draining an OSD empties it through its PGs, and it is then finalised.
//!
//! Repair's walk is off (an hour) in all of them: what is rebuilt, recovery
//! rebuilt.

use std::collections::HashMap;
use std::time::{Duration, Instant};

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

/// A cluster of `osds` OSDs and `metas` meta nodes, the walk off, peering
/// and recovery looking often.
fn cluster(metas: usize, osds: usize) -> HaCluster {
    let ha = HaCluster::start_with_meta_args(metas, osds, 1, &["--repair-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    config(&ha, "pg/peer_every_seconds", json!(2));
    config(&ha, "pg/peer_per_look", json!(1000));
    ha
}

fn config(ha: &HaCluster, key: &str, value: Value) {
    let r = ha.clients[0].json("PUT", &format!("/_admin/config/{key}"), value);
    assert!(r.status < 300, "{key}: {}", r.text());
}

/// A pool of one placement group (so one PG holds every object), and a
/// bucket in it.
fn one_pg_bucket(ha: &HaCluster, bucket: &str) {
    let c = &ha.clients[0];
    let r = c.json(
        "POST",
        "/_admin/pools",
        json!({"name": "one", "ec_type": 0, "ec_k": 4, "ec_m": 2, "pg_count": 1,
            "failure_domain": "osd", "enabled": true}),
    );
    assert!(r.status < 300, "pool: {}", r.text());
    c.request_with_headers(
        "PUT",
        &format!("/{bucket}"),
        &[],
        &[("x-objectio-pool", "one")],
    )
    .expect(200);
}

/// A pool's placement groups, by id.
fn pgs(ha: &HaCluster, pool: &str) -> HashMap<u32, Value> {
    let v = ha.clients[0]
        .request(
            "GET",
            &format!("/_admin/pools/{pool}/placement-groups"),
            &[],
        )
        .json();
    v["pgs"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|pg| (u32::try_from(pg["pg_id"].as_u64().unwrap()).unwrap(), pg))
        .collect()
}

/// Every OSD's node id (hex), by index.
fn node_ids(ha: &HaCluster, osds: usize) -> Vec<String> {
    let nodes = ha.clients[0].request("GET", "/_admin/nodes", &[]).json();
    (0..osds)
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

/// Wait until every PG of `pool` is clean, with nothing being filled.
fn await_clean(ha: &HaCluster, pool: &str, secs: u64) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let all = pgs(ha, pool);
        let unclean: Vec<&Value> = all
            .values()
            .filter(|pg| {
                pg["state"]["state"] != "Clean"
                    || pg["filling"].as_array().is_some_and(|f| !f.is_empty())
                    || pg["state"]["epoch"] != pg["epoch"]
            })
            .collect();
        if unclean.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{} PGs of {pool} not clean after {secs} s, e.g. {}",
            unclean.len(),
            unclean[0]
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Every key reads back as written.
fn all_read(ha: &HaCluster, bucket: &str, bodies: &[(String, Vec<u8>)]) {
    let c = &ha.clients[0];
    for (k, b) in bodies {
        let got = c.request("GET", &format!("/{bucket}/{k}"), &[]);
        assert_eq!(got.status, 200, "{k}: {}", got.text());
        assert_eq!(&got.bytes, b, "{k}");
    }
}

/// Write `n` objects, every third one small (its shards in its metadata).
fn write(ha: &HaCluster, bucket: &str, prefix: &str, count: u8) -> Vec<(String, Vec<u8>)> {
    let client = &ha.clients[0];
    (0..count)
        .map(|i| {
            let key = format!("{prefix}{i}");
            let len = if i % 3 == 0 { 20_000 } else { 300_000 };
            let body = payload(len, i);
            let r = client.request("PUT", &format!("/{bucket}/{key}"), &body);
            assert_eq!(r.status, 200, "{key}: {}", r.text());
            (key, body)
        })
        .collect()
}

/// The OSD indexes holding the most of `pool`'s positions, other than
/// `except`, `n` of them.
fn busiest(ha: &HaCluster, pool: &str, ids: &[String], except: &[usize], n: usize) -> Vec<usize> {
    let mut held: HashMap<usize, usize> = HashMap::new();
    for pg in pgs(ha, pool).values() {
        for m in pg["acting"].as_array().unwrap() {
            if let Some(i) = ids.iter().position(|id| Some(id.as_str()) == m.as_str()) {
                *held.entry(i).or_default() += 1;
            }
        }
    }
    let mut order: Vec<(usize, usize)> = held
        .into_iter()
        .filter(|(i, _)| !except.contains(i))
        .collect();
    order.sort_by_key(|(i, h)| (std::cmp::Reverse(*h), *i));
    order.into_iter().take(n).map(|(i, _)| i).collect()
}

/// A drive lost for good: its PGs stand in for it and backfill the
/// stand-in (shards and metadata copies, small objects included); every PG
/// is clean, the lost OSD's entry goes, recovery wrote the shards, and
/// every object reads with two more OSDs down.
#[test]
fn a_lost_drive_is_backfilled_through_its_pgs_and_survives_two_more_losses() {
    let mut ha = cluster(1, 7);
    let c = &ha.clients[0];
    c.request("PUT", "/lost", &[]).expect(200);
    let bodies = write(&ha, "lost", "k", 24);
    let ids = node_ids(&ha, 7);
    let lost = busiest(&ha, "default", &ids, &[], 1)[0];
    let old = ids[lost].clone();

    ha.stop_osd(lost);
    ha.lose_osd_drive(lost);
    ha.start_osd(lost, None);

    // Its PGs are filled from the others, then clean, and it is gone.
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut seen_filling = false;
    loop {
        let all = pgs(&ha, "default");
        seen_filling |= all.values().any(|pg| {
            pg["filling"].as_array().is_some_and(|f| !f.is_empty())
                || pg["state"]["state"] == "Backfilling"
        });
        let gone = !ha.clients[0]
            .request("GET", "/_admin/nodes", &[])
            .text()
            .contains(&old);
        if gone {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the lost OSD was never let go (seen filling: {seen_filling})"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(seen_filling, "no PG was ever filling");
    await_clean(&ha, "default", 120);
    assert!(
        ha.meta_metric("objectio_meta_pg_recovered_shards_total")
            .unwrap_or(0.0)
            > 0.0,
        "recovery wrote no shards"
    );

    // Two more down: everything still reads.
    let ids = node_ids(&ha, 7);
    for i in busiest(&ha, "default", &ids, &[], 2) {
        ha.stop_osd(i);
    }
    all_read(&ha, "lost", &bodies);
}

/// The leader killed in the middle of a backfill: the next one resumes it
/// from the cursor in the PG's state (the objects recovered so far are
/// counted on, not started again), and the PG ends clean with every
/// object readable two OSDs down.
#[test]
fn a_leader_change_mid_backfill_resumes_from_its_cursor() {
    let mut ha = cluster(3, 7);
    one_pg_bucket(&ha, "resume");
    // Slow, so the leader dies in the middle: one PG, one object at a time.
    config(&ha, "pg/rebuilds_per_osd", json!(1));
    let bodies = write(&ha, "resume", "k", 200);
    let ids = node_ids(&ha, 7);
    let pg = pgs(&ha, "one")[&0].clone();
    let member = pg["acting"][0].as_str().unwrap().to_string();
    let lost = ids.iter().position(|id| *id == member).unwrap();

    ha.stop_osd(lost);
    ha.lose_osd_drive(lost);
    ha.start_osd(lost, None);

    // Backfilling, some of it done.
    let deadline = Instant::now() + Duration::from_secs(180);
    let before = loop {
        let st = pgs(&ha, "one")[&0]["state"].clone();
        let done = st["recovery"]["recovered"].as_u64().unwrap_or(0);
        if st["state"] == "Backfilling" && done >= 70 {
            break done;
        }
        assert!(
            Instant::now() < deadline,
            "never well into a backfill: {st}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let leader = ha.await_leader(Duration::from_secs(10));
    ha.kill_meta(leader);
    let _ = ha.await_leader(Duration::from_secs(30));

    // The next leader goes on from where the last one got to.
    let deadline = Instant::now() + Duration::from_secs(240);
    let mut least_after = u64::MAX;
    let mut cursor_seen = false;
    loop {
        let all = pgs(&ha, "one");
        let st = &all[&0]["state"];
        if st["state"] == "Clean" && all[&0]["filling"].as_array().is_some_and(Vec::is_empty) {
            break;
        }
        if st["state"] == "Backfilling" {
            let done = st["recovery"]["recovered"].as_u64().unwrap_or(0);
            least_after = least_after.min(done);
            cursor_seen |= st["recovery"]["cursor"]
                .as_str()
                .is_some_and(|c| !c.is_empty());
        }
        assert!(
            Instant::now() < deadline,
            "not clean after the failover: {st}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        least_after != u64::MAX,
        "the backfill was never seen going on after the failover"
    );
    assert!(
        least_after >= before,
        "the count went back from {before} to {least_after}: the backfill started again"
    );
    assert!(cursor_seen, "the backfill went on without a cursor");
    ha.restart_meta(leader, None);
    let ids = node_ids(&ha, 7);
    for i in busiest(&ha, "one", &ids, &[], 2) {
        ha.stop_osd(i);
    }
    all_read(&ha, "resume", &bodies);
}

/// A member to fill past the backfill ratio: the PG waits in
/// `WaitTooFull`, and backfills once there is room (the ratio raised).
#[test]
fn a_full_member_holds_the_backfill_until_it_has_room() {
    let mut ha = cluster(1, 7);
    one_pg_bucket(&ha, "full");
    let bodies = write(&ha, "full", "k", 12);
    config(&ha, "pg/backfill_full_ratio", json!(0.0));
    config(&ha, "pg/too_full_retry_seconds", json!(2));
    let ids = node_ids(&ha, 7);
    let member = pgs(&ha, "one")[&0]["acting"][1]
        .as_str()
        .unwrap()
        .to_string();
    let lost = ids.iter().position(|id| *id == member).unwrap();
    ha.stop_osd(lost);
    ha.lose_osd_drive(lost);
    ha.start_osd(lost, None);

    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let st = pgs(&ha, "one")[&0]["state"].clone();
        if st["state"] == "WaitTooFull" {
            assert!(
                st["last_error"].as_str().unwrap_or("").contains("full"),
                "{st}"
            );
            break;
        }
        assert!(Instant::now() < deadline, "never waited for room: {st}");
        std::thread::sleep(Duration::from_millis(200));
    }
    // Still waiting a while later: nothing was filled.
    std::thread::sleep(Duration::from_secs(5));
    let pg = pgs(&ha, "one")[&0].clone();
    assert_eq!(pg["state"]["state"], "WaitTooFull", "{pg}");
    assert!(
        pg["filling"].as_array().is_some_and(|f| !f.is_empty()),
        "{pg}"
    );

    config(&ha, "pg/backfill_full_ratio", json!(0.95));
    await_clean(&ha, "one", 120);
    let ids = node_ids(&ha, 7);
    for i in busiest(&ha, "one", &ids, &[], 2) {
        ha.stop_osd(i);
    }
    all_read(&ha, "full", &bodies);
}

/// Overwrites while an OSD is down leave it the objects they replaced:
/// once it is back, recovery brings its copies up to date, and every
/// member holds the newest of every key.
#[test]
fn stale_copies_an_overwrite_left_are_brought_up_to_date() {
    let mut ha = cluster(1, 6);
    let c = &ha.clients[0];
    c.request("PUT", "/stale", &[]).expect(200);
    let mut bodies = write(&ha, "stale", "k", 12);
    ha.stop_osd(2);
    let c = &ha.clients[0];
    for (i, (k, b)) in bodies.iter_mut().enumerate().take(8) {
        *b = payload(300_000, 100 + u8::try_from(i).unwrap());
        let r = c.request("PUT", &format!("/stale/{k}"), b);
        assert_eq!(r.status, 200, "{k}: {}", r.text());
    }
    ha.start_osd(2, None);
    await_clean(&ha, "default", 120);
    assert!(
        ha.meta_metric("objectio_meta_pg_recovered_copies_total")
            .unwrap_or(0.0)
            > 0.0,
        "recovery wrote no copies"
    );
    // The OSD that was down is one of two to lose: it serves the newest.
    let ids = node_ids(&ha, 6);
    let other = busiest(&ha, "default", &ids, &[2], 1)[0];
    ha.stop_osd(other);
    let one_more = busiest(&ha, "default", &ids, &[2, other], 1)[0];
    ha.stop_osd(one_more);
    all_read(&ha, "stale", &bodies);
}

/// Writes short of a shard (an OSD down while they were made): once it is
/// back, recovery makes them whole within seconds, and they survive two
/// other OSDs down.
#[test]
fn a_write_short_of_shards_is_recovered_in_seconds() {
    let mut ha = cluster(1, 6);
    let c = &ha.clients[0];
    c.request("PUT", "/short", &[]).expect(200);
    ha.stop_osd(4);
    let bodies = write(&ha, "short", "k", 12);
    ha.start_osd(4, None);
    let started = Instant::now();
    await_clean(&ha, "default", 60);
    let took = started.elapsed();
    assert!(took < Duration::from_secs(45), "took {took:?}");
    let ids = node_ids(&ha, 6);
    for i in busiest(&ha, "default", &ids, &[4], 2) {
        ha.stop_osd(i);
    }
    all_read(&ha, "short", &bodies);
}

/// Draining an OSD: its PGs stand in for it and backfill the stand-ins,
/// then it is finalised (out); it can then be pulled with two more lost,
/// and everything reads.
#[test]
fn draining_an_osd_empties_it_through_its_pgs() {
    let mut ha = cluster(1, 7);
    let c = &ha.clients[0];
    c.request("PUT", "/drain", &[]).expect(200);
    let bodies = write(&ha, "drain", "k", 24);
    let ids = node_ids(&ha, 7);
    let drained = busiest(&ha, "default", &ids, &[], 1)[0];
    c.json(
        "PUT",
        &format!("/_admin/osds/{}/admin-state", ids[drained]),
        json!({"state": "draining"}),
    )
    .expect_ok();
    let state = |ha: &HaCluster| -> String {
        let nodes = ha.clients[0].request("GET", "/_admin/nodes", &[]).json();
        nodes["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["node_id"].as_str() == Some(ids[drained].as_str()))
            .and_then(|n| n["admin_state"].as_str())
            .unwrap_or("?")
            .to_string()
    };
    let deadline = Instant::now() + Duration::from_secs(240);
    while state(&ha) != "out" {
        assert!(
            Instant::now() < deadline,
            "never finished draining: {}",
            state(&ha)
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    // No PG holds it any more.
    for pg in pgs(&ha, "default").values() {
        let s = pg.to_string();
        assert!(!s.contains(&ids[drained]), "still held: {s}");
    }
    ha.stop_osd(drained);
    for i in busiest(&ha, "default", &ids, &[drained], 2) {
        ha.stop_osd(i);
    }
    all_read(&ha, "drain", &bodies);
}

/// How fast a backfill goes (not a test of anything): one PG of 400
/// objects of 256 KiB, a member's drive lost, the time until the PG is
/// clean. `cargo test -p objectio-e2e --test pg_recovery -- --ignored
/// --nocapture backfill_throughput`.
#[test]
#[ignore = "a measurement"]
fn backfill_throughput() {
    let mut ha = cluster(1, 7);
    one_pg_bucket(&ha, "speed");
    let client = &ha.clients[0];
    let body = payload(256 * 1024, 1);
    for i in 0..400 {
        client
            .request("PUT", &format!("/speed/k{i}"), &body)
            .expect(200);
    }
    let ids = node_ids(&ha, 7);
    let member = pgs(&ha, "one")[&0]["acting"][2]
        .as_str()
        .unwrap()
        .to_string();
    let lost = ids.iter().position(|id| *id == member).unwrap();
    ha.stop_osd(lost);
    ha.lose_osd_drive(lost);
    ha.start_osd(lost, None);
    // From the stand-in committed (the PG filling) to clean.
    let deadline = Instant::now() + Duration::from_secs(60);
    while pgs(&ha, "one")[&0]["filling"]
        .as_array()
        .is_none_or(Vec::is_empty)
    {
        assert!(Instant::now() < deadline, "never filling");
        std::thread::sleep(Duration::from_millis(20));
    }
    let started = Instant::now();
    await_clean(&ha, "one", 600);
    let took = started.elapsed();
    println!(
        "backfill: 400 objects of 256 KiB in {took:?}: {:.1} objects/s",
        400.0 / took.as_secs_f64()
    );
}

/// Degraded records (B29) of keys a full listing shows with a copy to
/// spare are spent, even while their PG can't get back to Clean. Recovery
/// forgot a record only once it made its key whole, and the repairer only
/// once peering found the PG Clean: in a PG kept out of Clean, the records
/// of keys that needed neither stayed for good, held their PG at risk, and
/// passes elsewhere gave way to it (soak run 23: 2,184 records, the oldest
/// 105 minutes old, and a PG starved for 70 minutes).
///
/// One PG, an OSD down: `u` is written a shard short, and three keys are
/// written short and deleted. Two of `u`'s shards are then stored wrong,
/// so once the OSD is back `u` can't be rebuilt (unfound), and the PG
/// stays Degraded with every member answering. Within a minute of the
/// pass that finds `u` unfound, the records are spent.
#[test]
fn a_full_listing_spends_degraded_records_while_the_pg_stays_unclean() {
    let mut ha = cluster(1, 6);
    one_pg_bucket(&ha, "spent");
    // Six OSDs, 4+2: the PG is on all of them. Down: its last position's.
    let ids = node_ids(&ha, 6);
    let last = pgs(&ha, "one")[&0]["acting"][5]
        .as_str()
        .unwrap()
        .to_string();
    let down = ids.iter().position(|id| *id == last).unwrap();
    ha.clients[0]
        .request("PUT", "/spent/whole", &payload(300_000, 1))
        .expect(200);
    ha.stop_osd(down);

    let c = &ha.clients[0];
    c.request("PUT", "/spent/u", &payload(300_000, 2))
        .expect(200);
    for i in 0..3 {
        let key = format!("/spent/gone{i}");
        c.request("PUT", &key, &payload(300_000, 3 + i)).expect(200);
        c.request("DELETE", &key, &[]).expect(204);
    }
    // Two of `u`'s five shards wrong: three good, a read needs four.
    for position in [0, 1] {
        c.json(
            "POST",
            "/_admin/test/rewrite-shard",
            json!({"bucket": "spent", "key": "u", "position": position}),
        )
        .expect_ok();
    }
    let records = |ha: &HaCluster| ha.meta_metric("objectio_meta_degraded_objects");
    let deadline = Instant::now() + Duration::from_secs(60);
    while records(&ha) != Some(4.0) {
        assert!(
            Instant::now() < deadline,
            "the short writes were never recorded: {:?}",
            records(&ha)
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    ha.start_osd(down, None);
    // A pass with every member answering tries `u`, and finds it unfound.
    let unfound = |ha: &HaCluster| {
        pgs(ha, "one")[&0]["state"]["recovery"]["unfound_keys"]
            .to_string()
            .contains("spent/u")
    };
    let deadline = Instant::now() + Duration::from_secs(120);
    while !unfound(&ha) {
        assert!(
            Instant::now() < deadline,
            "recovery never found u unfound: {}",
            pgs(&ha, "one")[&0]
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    // That pass listed every member first: the deleted keys' records are
    // spent, and `u`'s (a copy to spare as listed; at most it is kept, if
    // a pass saw it below k first). Counted by the repairer every 5 s; on
    // the old code they stay as long as the PG stays out of Clean.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let pg = pgs(&ha, "one")[&0].clone();
        assert_ne!(pg["state"]["state"], "Clean", "{pg}");
        let left = records(&ha).unwrap_or(f64::MAX);
        if left <= 1.0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{left} degraded records outlived full listings of their PG: {pg}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}
