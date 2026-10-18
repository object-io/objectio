//! B25: a meta node killed under load is back in seconds, however large its
//! database (objectio-docs `core/meta-log.md`).
//!
//! redb used to rebuild its allocator state after any unclean stop by
//! walking the whole file: minutes for a few GB, growing with the object
//! count. Every durable commit now saves that state, so a crash costs a
//! read of the Raft log since the last purge and a re-apply of what the
//! last checkpoint didn't cover, not a walk.
//!
//! The database is grown before the kill by writing rows into a table of
//! its own while the node is stopped (`OBJECTIO_E2E_META_DB_GB`, default
//! 1): filling it through S3 would take hours. Nothing reads the table; it
//! is there for its size, which is what the walk was proportional to.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use serde_json::json;

/// Started again, the node listens within this...
const ANSWERS_WITHIN: Duration = Duration::from_secs(15);
/// ...and is back in step with the leader within this (the exit test's
/// 30 s, from the start of the process).
const IN_STEP_WITHIN: Duration = Duration::from_secs(30);

fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// The database size asked for, in bytes.
fn wanted_bytes() -> u64 {
    let gb: f64 = std::env::var("OBJECTIO_E2E_META_DB_GB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1.0);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let bytes = (gb * 1e9) as u64;
    bytes
}

/// `bytes` in GB, for messages.
#[allow(clippy::cast_precision_loss)]
fn gb(bytes: u64) -> f64 {
    bytes as f64 / 1e9
}

/// Grow the stopped node's `meta.redb` to `bytes` with rows in a table
/// nothing reads, keyed like listing entries and inserted out of order (a
/// B-tree with as many pages as real listings would make). Each commit
/// saves the allocator state, as meta's own durable commits do.
fn grow(db_path: &Path, bytes: u64) {
    const BALLAST: redb::TableDefinition<&str, &[u8]> = redb::TableDefinition::new("e2e_ballast");
    let started = Instant::now();
    let db = redb::Database::create(db_path).expect("open meta.redb");
    let value = payload(3_000, 11);
    let mut n = 0u64;
    while std::fs::metadata(db_path).expect("meta.redb").len() < bytes {
        let mut txn = db.begin_write().expect("begin");
        txn.set_quick_repair(true);
        {
            let mut t = txn.open_table(BALLAST).expect("table");
            for _ in 0..20_000 {
                let h = n.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(29);
                let key = format!("bkt{}\0data/{:04x}/object-{h:016x}", h % 7, h >> 48);
                t.insert(key.as_str(), value.as_slice()).expect("insert");
                n += 1;
            }
        }
        txn.commit().expect("commit");
    }
    eprintln!(
        "meta.redb grown to {:.2} GB ({n} rows) in {:.0?}",
        gb(std::fs::metadata(db_path).expect("meta.redb").len()),
        started.elapsed()
    );
}

/// Acknowledged writes, by key.
type Acked = Mutex<BTreeMap<String, Vec<u8>>>;

/// Small objects written through `c` until `stop`, each acknowledged one
/// recorded. A failure is retried as a new key, as a client would.
fn writer(c: &Cluster, bucket: &str, acked: &Acked, stop: &AtomicBool, seed: u64) {
    let mut n = 0u64;
    while !stop.load(Ordering::Relaxed) {
        let key = format!("w{seed}-{n}");
        let body = payload(
            1_000 + usize::try_from(n % 5).unwrap() * 2_000,
            (seed << 32) | n,
        );
        if c.request("PUT", &format!("/{bucket}/{key}"), &body).status == 200 {
            acked.lock().unwrap().insert(key, body);
        }
        n += 1;
    }
}

/// Wait until node `i` follows the leader and has applied `index`;
/// returns when, or panics after `within` of `since`.
fn await_in_step(ha: &HaCluster, i: usize, index: u64, since: Instant, within: Duration) {
    loop {
        let s = ha.status(i);
        if let Some(s) = &s
            && s.state == "Follower"
            && s.last_applied >= index
        {
            // Killed under load, it opened its database without the walk.
            assert!(!s.open_repair, "a full repair ran on reopen: {s:?}");
            return;
        }
        assert!(
            since.elapsed() < within,
            "node {i} not back in step {within:?} after it started: {s:?}, the leader at {index}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A follower whose database is large, killed (SIGKILL: what a power cut
/// leaves of redb's state) while two gateways write: started again, it
/// listens in seconds and is back in step with the leader within the exit
/// test's 30 s, without walking its file; every acknowledged write reads
/// back.
#[test]
fn a_meta_node_killed_under_load_is_back_in_seconds_whatever_its_size() {
    let ha = HaCluster::start(3, 6, 2);
    ha.clients[0]
        .json("POST", "/_admin/buckets", json!({ "name": "rp" }))
        .expect_ok();
    let leader = ha.await_leader(Duration::from_secs(20));
    let node = (0..3).find(|&i| i != leader).unwrap();

    // Its database grown while it is stopped.
    ha.kill_meta(node);
    let db = ha.meta_dir(node).join("meta.redb");
    grow(&db, wanted_bytes());
    ha.start_meta(node);
    let index = ha.status(leader).expect("leader status").last_applied;
    await_in_step(&ha, node, index, Instant::now(), Duration::from_secs(120));

    // Killed under load, and started again at once (a power cut and a boot).
    let acked = Acked::default();
    let stop = AtomicBool::new(false);
    let (mut answered, mut in_step) = (Duration::ZERO, Duration::ZERO);
    std::thread::scope(|s| {
        for (g, c) in ha.clients.iter().enumerate() {
            let (stop, acked) = (&stop, &acked);
            s.spawn(move || writer(c, "rp", acked, stop, g as u64));
        }
        std::thread::sleep(Duration::from_secs(5));
        ha.kill_meta(node);
        std::thread::sleep(Duration::from_secs(2));
        let started = Instant::now();
        ha.start_meta(node);
        answered = started.elapsed();
        let index = ha.status(leader).map_or(0, |s| s.last_applied);
        await_in_step(&ha, node, index, started, IN_STEP_WITHIN);
        in_step = started.elapsed();
        std::thread::sleep(Duration::from_secs(3));
        stop.store(true, Ordering::Relaxed);
    });
    let size = std::fs::metadata(&db).expect("meta.redb").len();
    eprintln!(
        "{:.2} GB meta.redb: listening {answered:.1?} after start, in step after {in_step:.1?}",
        gb(size)
    );
    assert!(size >= wanted_bytes(), "meta.redb is {size} bytes");
    assert!(
        answered < ANSWERS_WITHIN,
        "listening only {answered:?} after start"
    );

    // Nothing acknowledged was lost, read through the node that crashed
    // too (a follower forwards to the leader, so through both gateways).
    let acked = acked.lock().unwrap();
    assert!(acked.len() > 50, "only {} writes acknowledged", acked.len());
    for (key, body) in acked.iter() {
        let r = ha.clients[1].request("GET", &format!("/rp/{key}"), &[]);
        assert_eq!(r.status, 200, "acknowledged {key} unreadable: {}", r.text());
        assert!(r.bytes == *body, "{key} reads back different bytes");
    }
}
