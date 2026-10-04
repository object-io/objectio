//! Meta high availability: a cluster with three meta nodes in one Raft
//! group, OSDs and two gateways, all separate processes. Losing a meta node
//! — the leader, a follower, one that's frozen as if cut off, or two at
//! once — must never lose an acknowledged write, and service must come back
//! as soon as a majority is up.
//!
//! These found that it didn't: a gateway or OSD talked to one meta node and
//! was down with it; a follower refused writes; and OSD registrations, KMS
//! keys, multipart uploads and the admin user lived only on the meta node
//! that took them, so a new leader had no OSDs and the cluster stopped.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use serde_json::json;

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

fn bucket(c: &Cluster, name: &str) {
    c.json("POST", "/_admin/buckets", json!({ "name": name }))
        .expect_ok();
}

/// Acknowledged writes, by key, and when each was acknowledged.
type Acked = Mutex<BTreeMap<String, (Vec<u8>, Instant)>>;

/// Write small objects to `bucket` through `c` until `stop`, recording each
/// one acknowledged. Failures (an election under way) are retried as new
/// keys, as a client would.
fn writer(c: &Cluster, bucket: &str, acked: &Acked, stop: &AtomicBool, seed: u64) {
    let mut n = 0u64;
    while !stop.load(Ordering::Relaxed) {
        let key = format!("w{seed}-{n}");
        let size = 2_000 + usize::try_from(n % 7).unwrap() * 3_000;
        let body = payload(size, seed * 1_000_000 + n);
        if c.request("PUT", &format!("/{bucket}/{key}"), &body).status == 200 {
            acked.lock().unwrap().insert(key, (body, Instant::now()));
        }
        n += 1;
    }
}

fn assert_all_readable(c: &Cluster, bucket: &str, acked: &Acked, when: &str) {
    let acked = acked.lock().unwrap();
    assert!(!acked.is_empty(), "{when}: nothing was written");
    for (key, (body, _)) in acked.iter() {
        // Retried while it says "retry", as a client would: right after a
        // node is lost, meta may still be electing a leader.
        let mut r = c.request("GET", &format!("/{bucket}/{key}"), &[]);
        let until = Instant::now() + Duration::from_secs(30);
        while r.status == 503 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(200));
            r = c.request("GET", &format!("/{bucket}/{key}"), &[]);
        }
        assert_eq!(
            r.status,
            200,
            "{when}: acknowledged {key} unreadable: {}",
            r.text()
        );
        assert!(r.bytes == *body, "{when}: {key} reads back different bytes");
    }
}

/// Write through every gateway for `secs`, calling `during` (on this
/// thread) once the writers are going. Returns when they've stopped.
fn while_writing(ha: &HaCluster, bucket: &str, acked: &Acked, secs: u64, during: impl FnOnce()) {
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        for (i, c) in ha.clients.iter().enumerate() {
            let stop = &stop;
            s.spawn(move || writer(c, bucket, acked, stop, i as u64 * 1_000 + secs));
        }
        std::thread::sleep(Duration::from_secs(2));
        during();
        std::thread::sleep(Duration::from_secs(secs));
        stop.store(true, Ordering::Relaxed);
    });
}

/// How long after `since` writes were acknowledged again.
fn resumed_after(acked: &Acked, since: Instant) -> Duration {
    acked
        .lock()
        .unwrap()
        .values()
        .filter(|(_, at)| *at > since)
        .map(|(_, at)| at.duration_since(since))
        .min()
        .expect("no write was acknowledged after the loss")
}

/// The leader killed while two gateways write: a new leader is elected,
/// writes resume within seconds, and every write acknowledged before,
/// during or after reads back from either gateway.
#[test]
fn losing_the_leader_loses_no_acknowledged_write() {
    let ha = HaCluster::start(3, 6, 2);
    bucket(&ha.clients[0], "ha");
    let acked = Acked::default();
    let leader = ha.await_leader(Duration::from_secs(20));
    let mut killed_at = Instant::now();
    while_writing(&ha, "ha", &acked, 10, || {
        killed_at = Instant::now();
        ha.kill_meta(leader);
    });
    let new_leader = ha.await_leader(Duration::from_secs(20));
    assert_ne!(new_leader, leader, "the killed node still leads");
    let resumed = resumed_after(&acked, killed_at);
    assert!(
        resumed < Duration::from_secs(10),
        "writes took {resumed:?} to resume after the leader was lost"
    );
    assert_all_readable(&ha.clients[0], "ha", &acked, "via gateway 0");
    assert_all_readable(&ha.clients[1], "ha", &acked, "via gateway 1");
}

/// A follower lost, then back: service goes on throughout, the returned
/// node catches up, and then serves when the leader is lost in turn.
#[test]
fn a_follower_lost_and_back_catches_up() {
    let ha = HaCluster::start(3, 6, 2);
    bucket(&ha.clients[0], "fo");
    let acked = Acked::default();
    let leader = ha.await_leader(Duration::from_secs(20));
    let follower = (0..3).find(|&i| i != leader).unwrap();
    while_writing(&ha, "fo", &acked, 6, || ha.kill_meta(follower));
    ha.start_meta(follower);
    // It catches up with the leader's log.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (f, l) = (ha.status(follower), ha.status(leader));
        if let (Some(f), Some(l)) = (&f, &l)
            && f.last_applied >= l.last_applied
            && f.state == "Follower"
        {
            break;
        }
        assert!(Instant::now() < deadline, "never caught up: {f:?} vs {l:?}");
        std::thread::sleep(Duration::from_millis(300));
    }
    // Now the leader goes: the returned node is part of the new majority.
    while_writing(&ha, "fo", &acked, 6, || ha.kill_meta(leader));
    assert_all_readable(&ha.clients[1], "fo", &acked, "after both losses");
}

/// B18: the log is compacted into snapshots, so a follower down for
/// longer than the kept log can't be caught up from it: it is sent a
/// snapshot, under traffic, and then serves as part of the majority.
#[test]
fn a_follower_behind_the_compacted_log_catches_up_from_a_snapshot() {
    let ha = HaCluster::start_with_meta_args(
        3,
        6,
        2,
        &["--raft-snapshot-every", "50", "--raft-keep-logs", "10"],
    );
    bucket(&ha.clients[0], "sn");
    let acked = Acked::default();
    let leader = ha.await_leader(Duration::from_secs(20));
    let follower = (0..3).find(|&i| i != leader).unwrap();
    let mut stopped_at = 0;
    while_writing(&ha, "sn", &acked, 8, || {
        stopped_at = ha.status(follower).map_or(0, |s| s.last_applied);
        ha.kill_meta(follower);
    });
    let l = ha.status(leader).expect("leader status");
    assert!(
        l.purged > stopped_at,
        "the leader's log was not compacted past the follower: {l:?}, follower at {stopped_at}"
    );

    ha.start_meta(follower);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (f, l) = (ha.status(follower), ha.status(leader));
        if let (Some(f), Some(l)) = (&f, &l)
            && f.last_applied >= l.last_applied
            && f.snapshot > stopped_at
            && f.state == "Follower"
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "never caught up from a snapshot: {f:?} vs {l:?}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // Now the leader goes: the node caught up from the snapshot is part of
    // the new majority, and holds everything.
    while_writing(&ha, "sn", &acked, 6, || ha.kill_meta(leader));
    assert_all_readable(&ha.clients[1], "sn", &acked, "after both losses");
}

/// The leader frozen (as if cut off by a partition): the others elect a
/// new one and go on; when it thaws it steps down rather than leading a
/// second cluster, and nothing written meanwhile is lost.
#[test]
fn a_frozen_leader_steps_down_when_it_returns() {
    let ha = HaCluster::start(3, 6, 2);
    bucket(&ha.clients[0], "fz");
    let acked = Acked::default();
    let leader = ha.await_leader(Duration::from_secs(20));
    let mut frozen_at = Instant::now();
    while_writing(&ha, "fz", &acked, 10, || {
        frozen_at = Instant::now();
        ha.freeze_meta(leader);
    });
    let new_leader = ha.await_leader_among_others(Duration::from_secs(20), &[leader]);
    assert_ne!(new_leader, leader);
    assert!(resumed_after(&acked, frozen_at) < Duration::from_secs(10));
    ha.thaw_meta(leader);
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let s = ha.status(leader);
        if s.as_ref().is_some_and(|s| s.state == "Follower") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the thawed node never stepped down: {s:?}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    while_writing(&ha, "fz", &acked, 3, || {});
    assert_all_readable(&ha.clients[0], "fz", &acked, "after the thaw");
}

/// Two of three meta nodes gone: no majority, so writes are refused —
/// promptly, not hanging, and never acknowledged. One back: service
/// resumes, and nothing acknowledged before was lost.
#[test]
fn without_a_majority_writes_are_refused_then_resume() {
    let ha = HaCluster::start(3, 6, 1);
    let c = &ha.clients[0];
    bucket(c, "q");
    c.request("PUT", "/q/before", b"before").expect(200);
    let leader = ha.await_leader(Duration::from_secs(20));
    let follower = (0..3).find(|&i| i != leader).unwrap();
    ha.kill_meta(follower);
    ha.kill_meta(leader);
    let started = Instant::now();
    let r = c.request("PUT", "/q/during", b"during");
    assert!(
        r.status >= 500,
        "a write was accepted without a majority: {}",
        r.status
    );
    assert!(
        started.elapsed() < Duration::from_secs(60),
        "a refused write took {:?}",
        started.elapsed()
    );
    ha.start_meta(follower);
    let deadline = Instant::now() + Duration::from_secs(30);
    while c.request("PUT", "/q/after", b"after").status != 200 {
        assert!(Instant::now() < deadline, "service never resumed");
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_eq!(c.request("GET", "/q/before", &[]).bytes, b"before");
    assert_eq!(c.request("GET", "/q/after", &[]).bytes, b"after");
}

/// What used to live only on the meta node that took it survives losing
/// it: a KMS key (and objects encrypted under it), a multipart upload in
/// progress, and the admin's credentials.
#[test]
fn keys_uploads_and_credentials_survive_a_failover() {
    let ha = HaCluster::start(3, 6, 1);
    let c = &ha.clients[0];
    bucket(c, "kv");
    c.json("POST", "/_admin/kms/keys", json!({ "key_id": "ha-key" }))
        .expect_ok();
    let secret = payload(30_000, 7);
    c.request_with_headers(
        "PUT",
        "/kv/sealed",
        &secret,
        &[
            ("x-amz-server-side-encryption", "aws:kms"),
            ("x-amz-server-side-encryption-aws-kms-key-id", "ha-key"),
        ],
    )
    .expect(200);
    let r = c.request("POST", "/kv/big?uploads", &[]);
    r.expect(200);
    let upload = r
        .text()
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .unwrap()
        .to_string();
    let part1 = payload(5 << 20, 1);
    let e1 = c
        .request(
            "PUT",
            &format!("/kv/big?partNumber=1&uploadId={upload}"),
            &part1,
        )
        .header("etag")
        .unwrap();

    let leader = ha.await_leader(Duration::from_secs(20));
    ha.kill_meta(leader);
    let _ = ha.await_leader(Duration::from_secs(20));

    // The credentials still sign (the admin is the cluster's, not the dead
    // node's), the key still decrypts, and the upload goes on.
    let r = c.request("GET", "/kv/sealed", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(
        r.bytes == secret,
        "the KMS-encrypted object reads back different bytes"
    );
    let part2 = payload(1 << 20, 2);
    let e2 = c
        .request(
            "PUT",
            &format!("/kv/big?partNumber=2&uploadId={upload}"),
            &part2,
        )
        .header("etag")
        .unwrap();
    c.request(
        "POST",
        &format!("/kv/big?uploadId={upload}"),
        format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{e1}</ETag></Part>\
             <Part><PartNumber>2</PartNumber><ETag>{e2}</ETag></Part></CompleteMultipartUpload>"
        )
        .as_bytes(),
    )
    .expect(200);
    let mut whole = part1;
    whole.extend_from_slice(&part2);
    assert!(c.request("GET", "/kv/big", &[]).bytes == whole);
}

/// A meta node replaced by a new, empty one: it joins, catches up, and
/// counts toward the majority — the cluster survives losing another.
#[test]
fn a_replaced_meta_node_takes_its_place() {
    let mut ha = HaCluster::start(3, 6, 1);
    bucket(&ha.clients[0], "rp");
    let acked = Acked::default();
    while_writing(&ha, "rp", &acked, 3, || {});
    let leader = ha.await_leader(Duration::from_secs(20));
    let follower = (0..3).find(|&i| i != leader).unwrap();
    let new = ha.replace_meta(follower);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let s = ha.status(new);
        if s.as_ref()
            .is_some_and(|s| s.state == "Follower" && s.voters.len() == 3)
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the new node never joined: {s:?}"
        );
        std::thread::sleep(Duration::from_millis(300));
    }
    // The original leader goes: the new node and the remaining original
    // one are the majority.
    while_writing(&ha, "rp", &acked, 6, || ha.kill_meta(leader));
    assert_all_readable(&ha.clients[0], "rp", &acked, "with the replacement");
}
