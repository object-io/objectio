//! A meta node whose filesystem fills up. It used to exit: a write the
//! filesystem refused stopped its Raft for good (openraft treats any
//! storage error so), the node exited to be restarted, and could not start
//! again while the disk was full; with the leader's or a majority's disk
//! full, the cluster was down.
//!
//! Now meta keeps a reserve free (`--min-free-mib`): below it the leader
//! refuses new writes, which an S3 client sees as 507 `StorageFull`, while
//! reads go on; a follower takes entries down to half of it and then falls
//! behind; once there is room, writes resume and followers catch up, with
//! no restart and nothing acknowledged lost. A test can't fill a real
//! filesystem without root: each node reads its free space from a file in
//! its data directory (`--test-free-bytes-file`).

use std::time::{Duration, Instant};

use objectio_e2e::ha::HaCluster;

/// Each meta node's free space, read from this file in its data directory.
const FREE_FILE: &str = "free-bytes";

/// Under the default reserve (1 GiB) and under half of it.
const FULL: u64 = 100 << 20;

fn cluster() -> HaCluster {
    let ha = HaCluster::start_with_meta_args(3, 6, 1, &["--test-free-bytes-file", FREE_FILE]);
    ha.await_default_pool();
    ha
}

/// Meta node `i`'s filesystem with `free` bytes free; `None`: its own.
fn set_free(ha: &HaCluster, i: usize, free: Option<u64>) {
    let file = ha.meta_dir(i).join(FREE_FILE);
    match free {
        Some(free) => std::fs::write(file, free.to_string()).expect("free-space file"),
        None => {
            let _ = std::fs::remove_file(file);
        }
    }
}

/// Every meta node still runs, healthy: none exited for want of room.
fn assert_every_meta_up(ha: &HaCluster, when: &str) {
    for i in 0..ha.meta_count() {
        assert!(!ha.meta_exited(i), "{when}: meta {i} exited");
        assert_eq!(ha.meta_health(i), Some(200), "{when}: meta {i}'s health");
        let s = ha.status(i).expect("meta answers");
        assert_eq!(s.fatal, None, "{when}: meta {i}'s Raft stopped");
    }
}

/// Create bucket `name`, answered `status`, within `secs` (meta's answers
/// may be 503 meanwhile, while a write it can't commit times out).
fn create_bucket_until(ha: &HaCluster, name: &str, status: u16, secs: u64) {
    let c = &ha.clients[0];
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let r = c.request("PUT", &format!("/{name}"), &[]);
        if r.status == status {
            if status == 507 {
                assert!(r.text().contains("StorageFull"), "{}", r.text());
            }
            return;
        }
        assert!(
            Instant::now() < deadline,
            "create bucket {name}: {} {} (wanted {status})",
            r.status,
            r.text()
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Every running meta node has applied what the leader has, within 30 s.
fn await_in_step(ha: &HaCluster, when: &str) {
    let leader = ha.await_leader(Duration::from_secs(20));
    let applied = ha.status(leader).expect("leader answers").last_applied;
    for i in 0..ha.meta_count() {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let s = ha.status(i).expect("meta answers");
            if s.last_applied >= applied {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{when}: meta {i} applied {} of {applied}",
                s.last_applied
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[test]
fn a_leader_without_room_refuses_writes_serves_reads_and_takes_writes_again() {
    let ha = cluster();
    let c = &ha.clients[0];
    create_bucket_until(&ha, "kept", 200, 30);
    let body = b"written before the disk filled".to_vec();
    assert_eq!(c.request("PUT", "/kept/before", &body).status, 200);

    let leader = ha.await_leader(Duration::from_secs(20));
    set_free(&ha, leader, Some(FULL));

    // A write meta must make is refused, 507 (no retry helps), at once.
    create_bucket_until(&ha, "refused", 507, 10);
    let s = ha.status(leader).expect("leader answers");
    assert!(
        s.disk_full
            .as_deref()
            .is_some_and(|w| w.contains("reserve")),
        "{:?}",
        s.disk_full
    );
    assert!(
        ha.meta_metric("objectio_meta_writes_refused_no_room_total")
            .is_some_and(|n| n >= 1.0),
        "refusals counted"
    );
    // Reads go on: an object, a listing, the bucket.
    let r = c.request("GET", "/kept/before", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.bytes, body);
    let r = c.request("GET", "/kept?list-type=2", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(r.text().contains("<Key>before</Key>"), "{}", r.text());
    assert_eq!(c.request("HEAD", "/kept", &[]).status, 200);
    assert_eq!(c.request("GET", "/refused", &[]).status, 404);
    // An object's PUT stores its metadata on its OSDs, not on meta: it is
    // acknowledged and reads back; its listing entry waits for room.
    let during = c.request("PUT", "/kept/during", b"while full");
    assert_eq!(during.status, 200, "{}", during.text());
    assert_eq!(c.request("GET", "/kept/during", &[]).bytes, b"while full");
    assert_every_meta_up(&ha, "with the leader's disk full");

    // Room again: writes are taken, by the same processes.
    set_free(&ha, leader, None);
    create_bucket_until(&ha, "after", 200, 10);
    assert_eq!(c.request("PUT", "/after/k", b"after").status, 200);
    assert_eq!(c.request("GET", "/after/k", &[]).bytes, b"after");
    assert_eq!(c.request("GET", "/kept/before", &[]).bytes, body);
    // The object written while meta was full is listed once it has room.
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let listing = c.request("GET", "/kept?list-type=2", &[]).text();
        if listing.contains("<Key>during</Key>") {
            break;
        }
        assert!(Instant::now() < deadline, "never listed: {listing}");
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_every_meta_up(&ha, "after room came back");
    await_in_step(&ha, "after room came back");
}

#[test]
fn a_follower_without_room_falls_behind_and_a_majority_without_room_refuses_writes() {
    let ha = cluster();
    let c = &ha.clients[0];
    create_bucket_until(&ha, "first", 200, 30);
    let leader = ha.await_leader(Duration::from_secs(20));
    let followers: Vec<usize> = (0..ha.meta_count()).filter(|i| *i != leader).collect();

    // One follower full: the leader and the other make a majority, and
    // writes go on; the full one takes no entries and falls behind.
    set_free(&ha, followers[0], Some(FULL));
    for i in 0..5 {
        create_bucket_until(&ha, &format!("one-full-{i}"), 200, 10);
    }
    let behind = ha.status(followers[0]).expect("answers").last_applied;
    let ahead = ha.status(leader).expect("answers").last_applied;
    assert!(
        behind < ahead,
        "the full follower applied {behind} of {ahead}"
    );
    assert_every_meta_up(&ha, "with a follower's disk full");

    // Both followers full: no majority can take entries, and the leader
    // refuses writes (a write it took before it knew may time out, 503).
    set_free(&ha, followers[1], Some(FULL));
    create_bucket_until(&ha, "no-majority", 507, 30);
    assert_eq!(c.request("HEAD", "/first", &[]).status, 200, "reads go on");
    assert_every_meta_up(&ha, "with a majority's disks full");

    // Room again: writes resume, the followers catch up, and every bucket
    // acknowledged is there.
    set_free(&ha, followers[0], None);
    set_free(&ha, followers[1], None);
    create_bucket_until(&ha, "after", 200, 30);
    await_in_step(&ha, "after room came back");
    assert_every_meta_up(&ha, "after room came back");
    for name in ["first", "after"]
        .into_iter()
        .map(String::from)
        .chain((0..5).map(|i| format!("one-full-{i}")))
    {
        assert_eq!(
            c.request("HEAD", &format!("/{name}"), &[]).status,
            200,
            "{name}"
        );
    }
}
