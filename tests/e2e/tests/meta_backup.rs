//! Meta backup, restore and forced membership (objectio-docs `core/meta.md`,
//! "Backup, restore and losing a majority"): three meta nodes, OSDs and a
//! gateway as separate processes.
//!
//! Every meta node's data lost: restored from an `obioctl meta export`, the
//! cluster serves what the backup held and lists what was written after it.
//! Two of three lost for good: the survivor, forced to one voter, serves
//! everything, and the group grows back to three.
//!
//! Needs `cargo build --bin objectio-meta --bin objectio-osd --bin
//! objectio-gateway --bin obioctl` first.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
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

/// Sizes across the paths: inline, a small shard, one stripe, several.
const SIZES: [usize; 5] = [300, 20_000, 300_000, 1 << 20, 5 << 20];

/// A cluster of three metas, six OSDs and a gateway whose heal pass is
/// off, so a listing comes back only from peering; a listing peering
/// judges every key at once. Set before any backup, so a restore keeps it.
fn cluster() -> HaCluster {
    cluster_with(&[])
}

/// As [`cluster`], the gateway also given `gateway_args`.
fn cluster_with(gateway_args: &[&str]) -> HaCluster {
    let mut ha = HaCluster::start(3, 6, 1);
    let mut args = vec!["--heal-interval-secs", "3600"];
    args.extend_from_slice(gateway_args);
    ha.restart_gateway_with_args(0, &args);
    let _ = ha.await_leader(Duration::from_secs(30));
    for (key, v) in [
        ("pg/peer_every_seconds", 2),
        ("pg/peer_per_look", 1000),
        ("pg/listing_grace_seconds", 0),
    ] {
        let r = ha.clients[0].json("PUT", &format!("/_admin/config/{key}"), json!(v));
        assert!(r.status < 300, "{key}: {}", r.text());
    }
    ha
}

fn bucket(c: &Cluster, name: &str) {
    c.json("POST", "/_admin/buckets", json!({ "name": name }))
        .expect_ok();
}

/// A PUT, retried on 503 as S3 clients do (a meta node or an election
/// away), for a while.
#[track_caller]
fn put(c: &Cluster, path: &str, body: &[u8]) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let r = c.request("PUT", path, body);
        if r.status == 200 {
            return;
        }
        assert!(
            r.status == 503 && Instant::now() < deadline,
            "PUT {path}: {} {}",
            r.status,
            r.text()
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// The keys `ListObjectsV2` lists in `bucket`.
fn listed(c: &Cluster, bucket: &str) -> Option<BTreeSet<String>> {
    let r = c.request("GET", &format!("/{bucket}?list-type=2&max-keys=1000"), &[]);
    if r.status != 200 {
        return None;
    }
    let text = r.text();
    Some(
        text.split("<Key>")
            .skip(1)
            .filter_map(|s| s.split("</Key>").next())
            .map(ToString::to_string)
            .collect(),
    )
}

/// Wait up to `secs` for `f`, saying what didn't happen.
#[track_caller]
fn eventually(secs: u64, what: &str, mut f: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(Instant::now() < deadline, "{what}: not within {secs} s");
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// Every object in `objects` reads back byte for byte, through `c`, once
/// the cluster serves.
#[track_caller]
fn assert_all_read(c: &Cluster, bucket: &str, objects: &BTreeMap<String, Vec<u8>>, when: &str) {
    for (key, body) in objects {
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let r = c.request("GET", &format!("/{bucket}/{key}"), &[]);
            if r.status == 200 {
                assert!(
                    r.bytes == *body,
                    "{when}: {bucket}/{key} read back different bytes"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{when}: GET {bucket}/{key}: {} {}",
                r.status,
                r.text()
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }
}

/// Every meta node agrees on one leader and `voters`.
fn await_group(ha: &HaCluster, voters: &[u64]) -> usize {
    let mut leader = 0;
    eventually(60, &format!("a group of voters {voters:?}"), || {
        leader = ha.await_leader(Duration::from_secs(60));
        (0..3).all(|i| ha.status(i).is_some_and(|s| s.voters == voters))
    });
    leader
}

fn export(ha: &HaCluster, file: &Path) {
    let out = ha.obioctl(
        0,
        &["meta", "export", "--file", &file.display().to_string()],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "obioctl meta export: {stderr}");
    assert!(stderr.contains("meta backup:"), "{stderr}");
    assert!(file.exists(), "{}", file.display());
    assert!(!file.with_extension("backup.part").exists());
}

#[test]
fn a_cluster_restored_from_a_backup_serves_what_it_held_and_lists_what_came_after() {
    let ha = cluster();
    let c = &ha.clients[0];
    bucket(c, "kept");
    let mut objects: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (i, size) in SIZES.iter().enumerate() {
        let key = format!("before-{i}");
        let body = payload(*size, i as u64);
        put(c, &format!("/kept/{key}"), &body);
        objects.insert(key, body);
    }
    let alice = c
        .json("POST", "/_admin/users", json!({"display_name": "alice"}))
        .json();
    let alice_id = alice["user_id"].as_str().unwrap().to_string();
    let key = c
        .json(
            "POST",
            &format!("/_admin/users/{alice_id}/access-keys"),
            json!({}),
        )
        .json();
    let (ak, sk) = (
        key["access_key_id"].as_str().unwrap().to_string(),
        key["secret_access_key"].as_str().unwrap().to_string(),
    );
    c.request_as("GET", "/", &[], &ak, &sk).expect(200);

    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("meta.backup");
    export(&ha, &backup);

    // After the backup: objects written, one overwritten, one deleted; a
    // bucket and a user made; alice's key deleted.
    for (i, size) in SIZES.iter().enumerate() {
        let key = format!("after-{i}");
        let body = payload(*size, 100 + i as u64);
        put(c, &format!("/kept/{key}"), &body);
        objects.insert(key, body);
    }
    let rewritten = payload(40_000, 999);
    put(c, "/kept/before-0", &rewritten);
    objects.insert("before-0".into(), rewritten);
    c.request("DELETE", "/kept/before-1", &[]).expect(204);
    objects.remove("before-1");
    bucket(c, "made-after");
    put(c, "/made-after/x", b"x");
    c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "bob-made-after"}),
    )
    .expect_ok();
    c.request("DELETE", &format!("/_admin/access-keys/{ak}"), &[])
        .expect_ok();
    assert_eq!(c.request_as("GET", "/", &[], &ak, &sk).status, 403);

    // Every meta node's data lost.
    for i in 0..3 {
        ha.lose_meta(i);
    }
    let printed = ha.restore_meta(0, &backup);
    assert!(printed.contains("only voter"), "{printed}");
    ha.start_meta(0);
    assert_eq!(ha.await_leader(Duration::from_secs(60)), 0);
    assert_eq!(ha.status(0).unwrap().voters, vec![1]);
    // Grown back to three, as the group was formed.
    ha.start_meta(1);
    ha.start_meta(2);
    ha.join_metas(0, &[1, 2]);
    await_group(&ha, &[1, 2, 3]);

    // Everything the OSDs hold reads, written after the backup or not.
    assert_all_read(c, "kept", &objects, "after the restore");
    assert_eq!(c.request("GET", "/kept/before-1", &[]).status, 404);

    // Peering lists every placement group: the listing takes in what was
    // written after the backup, and drops what was deleted.
    let want: BTreeSet<String> = objects.keys().cloned().collect();
    let mut seen = None;
    eventually(180, "the listing after the restore", || {
        seen = listed(c, "kept");
        seen.as_ref() == Some(&want)
    });
    eventually(120, "every placement group relisted", || {
        ha.meta_metric("objectio_meta_pgs_to_relist") == Some(0.0)
    });
    assert_eq!(ha.meta_metric("objectio_meta_restored"), Some(1.0));

    // Placement groups in a new epoch era: above anything the OSDs knew.
    let pgs = c
        .request("GET", "/_admin/pools/default/placement-groups", &[])
        .json();
    let pgs = pgs["pgs"].as_array().unwrap();
    assert!(!pgs.is_empty());
    for pg in pgs {
        assert!(pg["epoch"].as_u64().unwrap() > 1 << 32, "{pg}");
    }

    // What was made after the backup is gone, what was deleted is back.
    assert_eq!(c.request("HEAD", "/made-after", &[]).status, 404);
    let users = c.request("GET", "/_admin/users", &[]).text();
    assert!(!users.contains("bob-made-after"), "{users}");
    assert!(users.contains("alice"), "{users}");
    c.request_as("GET", "/", &[], &ak, &sk).expect(200);

    // And it takes new writes.
    let body = payload(70_000, 4242);
    put(c, "/kept/after-the-restore", &body);
    assert_eq!(c.request("GET", "/kept/after-the-restore", &[]).bytes, body);
}

#[test]
fn two_metas_lost_for_good_the_survivor_serves_alone_and_grows_back() {
    let ha = cluster();
    let c = &ha.clients[0];
    bucket(c, "kept");
    let mut objects: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (i, size) in SIZES.iter().enumerate() {
        let key = format!("w-{i}");
        let body = payload(*size, i as u64);
        put(c, &format!("/kept/{key}"), &body);
        objects.insert(key, body);
    }

    // The leader and one follower lost for good; the other follower alone
    // has no majority.
    let leader = ha.await_leader(Duration::from_secs(30));
    let survivor = (leader + 1) % 3;
    let lost: Vec<usize> = (0..3).filter(|i| *i != survivor).collect();
    for &i in &lost {
        ha.lose_meta(i);
    }
    eventually(30, "the survivor without a leader", || {
        ha.status(survivor).is_some_and(|s| s.state != "Leader")
    });

    ha.kill_meta(survivor);
    let printed = ha.force_single_voter(survivor);
    assert!(printed.contains("only voter"), "{printed}");
    assert!(printed.contains("are gone"), "{printed}");
    ha.start_meta(survivor);
    assert_eq!(ha.await_leader(Duration::from_secs(60)), survivor);
    assert_all_read(c, "kept", &objects, "on the survivor alone");
    let want: BTreeSet<String> = objects.keys().cloned().collect();
    eventually(120, "the listing on the survivor", || {
        listed(c, "kept").as_ref() == Some(&want)
    });
    let body = payload(50_000, 7);
    put(c, "/kept/on-the-survivor", &body);
    objects.insert("on-the-survivor".into(), body);

    // Two empty nodes join.
    for &i in &lost {
        ha.start_meta(i);
    }
    ha.join_metas(survivor, &lost);
    let ids: Vec<u64> = {
        let mut v: Vec<u64> = (0..3).map(|i| ha.meta_id(i)).collect();
        v.sort_unstable();
        v
    };
    await_group(&ha, &ids);

    // They hold it all: with the survivor gone, the two serve.
    ha.kill_meta(survivor);
    let new_leader = ha.await_leader(Duration::from_secs(60));
    assert!(lost.contains(&new_leader));
    assert_all_read(c, "kept", &objects, "on the nodes that joined");
    let body = payload(9_000, 8);
    put(c, "/kept/on-the-new-nodes", &body);
    assert_eq!(c.request("GET", "/kept/on-the-new-nodes", &[]).bytes, body);
}

/// Copies by reference made after the backup share stripes the restored
/// registry doesn't know of: of a whole object, and of a slice of a pack
/// made before it. Deleting the source, or every object of the pack, must
/// free nothing a copy still reads. An object packed after the backup can't
/// be read (its pack's record went with the rest of meta's later history),
/// and says so.
#[test]
fn deleting_after_a_restore_never_frees_bytes_another_object_still_reads() {
    // Small objects take disk blocks of their own, to be packed (as the
    // packing tests run).
    let ha = cluster_with(&["--small-shard-max", "0"]);
    let c = &ha.clients[0];
    bucket(c, "b");
    let source = payload(300_000, 1);
    put(c, "/b/source", &source);
    let small: Vec<(String, Vec<u8>)> = (0..4u8)
        .map(|i| {
            (
                format!("small-{i}"),
                payload(5_000 + usize::from(i) * 4_999, 10 + u64::from(i)),
            )
        })
        .collect();
    for (key, body) in &small {
        put(c, &format!("/b/{key}"), body);
    }
    let pack = |keys: &[&str]| {
        let r = c.json(
            "POST",
            "/_admin/test/pack",
            json!({ "bucket": "b", "keys": keys }),
        );
        assert_eq!(r.status, 200, "pack: {}", r.text());
        assert_eq!(
            r.json()["packed"].as_array().map(Vec::len),
            Some(keys.len()),
            "{}",
            r.text()
        );
    };
    let keys: Vec<&str> = small.iter().map(|(k, _)| k.as_str()).collect();
    pack(&keys);

    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("meta.backup");
    export(&ha, &backup);

    // After the backup: copies by reference of `source` and of a packed
    // object, and two more small objects packed.
    for (from, to) in [("/b/source", "/b/copy"), ("/b/small-1", "/b/small-copy")] {
        let r = c.request_with_headers("PUT", to, &[], &[("x-amz-copy-source", from)]);
        assert_eq!(r.status, 200, "copy {from}: {}", r.text());
    }
    let late: Vec<(String, Vec<u8>)> = (0..2u8)
        .map(|i| {
            (
                format!("late-{i}"),
                payload(6_000 + usize::from(i) * 3_000, 50 + u64::from(i)),
            )
        })
        .collect();
    for (key, body) in &late {
        put(c, &format!("/b/{key}"), body);
    }
    pack(&["late-0", "late-1"]);

    for i in 0..3 {
        ha.lose_meta(i);
    }
    let _ = ha.restore_meta(0, &backup);
    ha.start_meta(0);
    let _ = ha.await_leader(Duration::from_secs(60));
    ha.start_meta(1);
    ha.start_meta(2);
    ha.join_metas(0, &[1, 2]);
    await_group(&ha, &[1, 2, 3]);

    let mut copies: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    copies.insert("copy".into(), source);
    copies.insert("small-copy".into(), small[1].1.clone());
    let mut all = copies.clone();
    all.extend(small.iter().cloned());
    assert_all_read(c, "b", &all, "after the restore");
    // Packed after the backup: the pack's record is gone, so the read fails
    // and says why; never other bytes.
    for (key, _) in &late {
        let r = c.request("GET", &format!("/b/{key}"), &[]);
        assert_eq!(r.status, 500, "{key}: {}", r.text());
        assert!(r.text().contains("has no record"), "{key}: {}", r.text());
    }

    // The source deleted, and every object packed before the backup.
    eventually(60, "deleting the source", || {
        c.request("DELETE", "/b/source", &[]).status == 204
    });
    for (key, _) in &small {
        c.request("DELETE", &format!("/b/{key}"), &[]).expect(204);
    }
    eventually(30, "the frees held", || {
        ha.meta_metric("objectio_meta_restore_frees_held_total")
            .is_some_and(|n| n >= 2.0)
    });
    // Whatever a reclaim was going to do, it has done (it runs behind the
    // delete's answer).
    std::thread::sleep(Duration::from_secs(3));
    assert_all_read(c, "b", &copies, "after the deletes");
}

/// After the backup an OSD is set out, so its placement groups move to new
/// epochs, which the OSDs learn. The restored epochs are older: without the
/// restore's new era every write to those PGs was refused, for good.
#[test]
fn writes_go_on_to_placement_groups_whose_epoch_moved_after_the_backup() {
    let mut ha = HaCluster::start(3, 7, 1);
    ha.restart_gateway_with_args(0, &["--heal-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    bucket(c, "e");
    let epochs = || -> BTreeMap<u64, u64> {
        let pgs = c
            .request("GET", "/_admin/pools/default/placement-groups", &[])
            .json();
        pgs["pgs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pg| (pg["pg_id"].as_u64().unwrap(), pg["epoch"].as_u64().unwrap()))
            .collect()
    };
    let before = epochs();
    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("meta.backup");
    export(&ha, &backup);

    let nodes = c.request("GET", "/_admin/nodes", &[]).json();
    let out = nodes["nodes"].as_array().unwrap()[0]["node_id"]
        .as_str()
        .unwrap()
        .to_string();
    c.json(
        "PUT",
        &format!("/_admin/osds/{out}/admin-state"),
        json!({ "state": "out" }),
    )
    .expect_ok();
    eventually(60, "a placement group at a new epoch", || {
        let now = epochs();
        now.iter()
            .any(|(pg, e)| before.get(pg).is_some_and(|b| e > b))
    });

    for i in 0..3 {
        ha.lose_meta(i);
    }
    let _ = ha.restore_meta(0, &backup);
    ha.start_meta(0);
    let _ = ha.await_leader(Duration::from_secs(60));
    ha.start_meta(1);
    ha.start_meta(2);
    ha.join_metas(0, &[1, 2]);
    await_group(&ha, &[1, 2, 3]);

    // Enough keys to land in every placement group the OSD was in.
    let objects: BTreeMap<String, Vec<u8>> = (0..64u64)
        .map(|i| {
            (
                format!("k-{i}"),
                payload(3_000 + usize::try_from(i).unwrap() * 97, i),
            )
        })
        .collect();
    for (key, body) in &objects {
        put(c, &format!("/e/{key}"), body);
    }
    assert_all_read(c, "e", &objects, "after the restore");
}

/// The shards an OSD holds, as it counts them.
fn osd_shards(rt: &tokio::runtime::Runtime, address: &str) -> u64 {
    use objectio_proto::storage::GetStatusRequest;
    use objectio_proto::storage::storage_service_client::StorageServiceClient;
    rt.block_on(async {
        let channel = objectio_e2e::tls::channel(address)
            .await
            .expect("connect OSD");
        StorageServiceClient::new(channel)
            .get_status(GetStatusRequest::default())
            .await
            .expect("status")
            .into_inner()
            .shard_count
    })
}

/// An OSD of the cluster, as `/_admin/nodes` lists it: its id and admin
/// state.
fn osd_state(c: &Cluster, address: &str) -> (String, String) {
    let nodes = c.request("GET", "/_admin/nodes", &[]).json();
    let node = nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["address"].as_str() == Some(address))
        .unwrap_or_else(|| panic!("no OSD at {address}: {nodes}"))
        .clone();
    (
        node["node_id"].as_str().unwrap().to_string(),
        node["admin_state"].as_str().unwrap_or("?").to_string(),
    )
}

/// An OSD draining when the backup was taken, and put back in right after
/// (its drain cancelled), keeps its data and serves. The restored meta
/// holds it draining: finishing that drain would move everything off it
/// and wipe it. It is left alone until the operator sets its state.
#[test]
fn an_osd_draining_in_the_backup_is_left_alone_until_its_state_is_set() {
    // The drain observer's default pace: a sweep every 30 s.
    let mut ha = HaCluster::start(3, 7, 1);
    ha.restart_gateway_with_args(0, &["--heal-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    let rt = tokio::runtime::Runtime::new().unwrap();
    let c = &ha.clients[0];
    bucket(c, "d");
    let objects: BTreeMap<String, Vec<u8>> = (0..12u64)
        .map(|i| (format!("o-{i}"), payload(200_000, i)))
        .collect();
    for (key, body) in &objects {
        put(c, &format!("/d/{key}"), body);
    }
    let address = ha.osd_endpoint(0);
    let (osd, _) = osd_state(c, &address);
    let held = osd_shards(&rt, &address);
    assert!(held > 0, "the OSD holds nothing");
    let set = |state: &str| {
        c.json(
            "PUT",
            &format!("/_admin/osds/{osd}/admin-state"),
            json!({ "state": state }),
        )
        .expect_ok();
    };
    // Draining in the backup; in service again at once after it.
    set("draining");
    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("meta.backup");
    export(&ha, &backup);
    set("in");
    assert_eq!(osd_state(c, &address).1, "in");

    for i in 0..3 {
        ha.lose_meta(i);
    }
    let printed = ha.restore_meta(0, &backup);
    assert!(
        printed.contains(&osd),
        "the restore names the OSD: {printed}"
    );
    ha.start_meta(0);
    let _ = ha.await_leader(Duration::from_secs(60));
    ha.start_meta(1);
    ha.start_meta(2);
    ha.join_metas(0, &[1, 2]);
    await_group(&ha, &[1, 2, 3]);

    // Draining, as the backup has it, and left alone through two sweeps
    // and more: still holding what it held, never wiped.
    assert_eq!(osd_state(c, &address).1, "draining");
    eventually(30, "the OSD counted as unconfirmed", || {
        ha.meta_metric("objectio_meta_restore_osds_unconfirmed") == Some(1.0)
    });
    std::thread::sleep(Duration::from_secs(75));
    assert_eq!(osd_state(c, &address).1, "draining");
    assert!(
        osd_shards(&rt, &address) >= held,
        "the OSD lost shards before anyone said what it is"
    );
    assert_all_read(c, "d", &objects, "after the restore");

    // The operator says: in service.
    set("in");
    eventually(30, "the OSD confirmed", || {
        ha.meta_metric("objectio_meta_restore_osds_unconfirmed") == Some(0.0)
    });
    assert_eq!(osd_state(c, &address).1, "in");
    assert_all_read(c, "d", &objects, "with the OSD back in");
}
