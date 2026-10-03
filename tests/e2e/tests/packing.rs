//! Small-object packing, phase 1: objects packed through the test hook
//! (`/_admin/test/pack`, mounted by `--test-hooks`) read back byte-identical;
//! each lets its own stripe go; the pack goes with its last object; and the
//! pack survives what a stripe survives: copies, overwrites, lost disks,
//! repair and drain (objectio-docs architecture/design/small-object-packing.md).

use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use serde_json::{Value, json};

/// Bytes that do not repeat, distinct per seed.
fn payload(len: usize, seed: u8) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ (u64::from(seed) << 7);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// Small objects of assorted sizes: above the inline cut-off (4 KiB), at or
/// under the pack cut-off (64 KiB), none block-aligned.
fn put_small(c: &Cluster, bucket: &str, count: u8) -> Vec<(String, Vec<u8>)> {
    c.json("POST", "/_admin/buckets", json!({ "name": bucket }))
        .expect_ok();
    (0..count)
        .map(|i| {
            let body = payload(5_000 + usize::from(i) * 4_999, i);
            let key = format!("o{i}");
            c.request("PUT", &format!("/{bucket}/{key}"), &body)
                .expect(200);
            (key, body)
        })
        .collect()
}

fn pack(c: &Cluster, bucket: &str, keys: &[&str]) -> Value {
    let r = c.json(
        "POST",
        "/_admin/test/pack",
        json!({ "bucket": bucket, "keys": keys }),
    );
    assert_eq!(r.status, 200, "pack: {}", r.text());
    r.json()
}

fn pack_all(c: &Cluster, bucket: &str, objects: &[(String, Vec<u8>)]) -> Value {
    let keys: Vec<&str> = objects.iter().map(|(k, _)| k.as_str()).collect();
    let report = pack(c, bucket, &keys);
    assert_eq!(
        report["packed"].as_array().map(Vec::len),
        Some(objects.len()),
        "{report}"
    );
    report
}

fn assert_readable(c: &Cluster, bucket: &str, objects: &[(String, Vec<u8>)], when: &str) {
    for (key, body) in objects {
        let r = c.request("GET", &format!("/{bucket}/{key}"), &[]);
        assert_eq!(r.status, 200, "{when}: {key}: {}", r.text());
        assert!(r.bytes == *body, "{when}: {key} reads back different bytes");
    }
}

/// Wait until the disks' used bytes satisfy `ok`, or fail after `within`.
fn await_used(c: &Cluster, what: &str, within: Duration, ok: impl Fn(u64) -> bool) -> u64 {
    let deadline = Instant::now() + within;
    loop {
        let used = c.total_used_bytes();
        if ok(used) {
            return used;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: used bytes stayed at {used}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn packed_objects_read_back_and_the_pack_goes_with_its_last_object() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    let empty = c.total_used_bytes();
    let objects = put_small(&c, "p", 12);
    let unpacked = await_used(&c, "written", Duration::from_secs(15), |u| u > empty);

    pack_all(&c, "p", &objects);
    assert_readable(&c, "p", &objects, "packed");

    // A range inside one object's slice, and its size and ETag unchanged.
    let (key, body) = &objects[5];
    let r = c.request_with_headers(
        "GET",
        &format!("/p/{key}"),
        &[],
        &[("Range", "bytes=100-1099")],
    );
    assert_eq!(r.status, 206, "{}", r.text());
    assert!(
        r.bytes == body[100..1100],
        "the range reads back different bytes"
    );
    let head = c.request("HEAD", &format!("/p/{key}"), &[]);
    assert_eq!(head.header("content-length"), Some(body.len().to_string()));

    // Each object let its own stripe go: twelve 4+2 stripes became one.
    let packed = await_used(&c, "after packing", Duration::from_secs(15), |u| {
        u < unpacked
    });
    assert!(packed < unpacked, "{packed} >= {unpacked}");

    // An overwrite leaves the rest of the pack readable.
    let fresh = payload(9_000, 200);
    c.request("PUT", "/p/o0", &fresh).expect(200);
    assert_eq!(c.request("GET", "/p/o0", &[]).bytes, fresh);
    assert_readable(&c, "p", &objects[1..], "after an overwrite");

    // Deleting every object frees the pack too.
    for (key, _) in &objects {
        c.request("DELETE", &format!("/p/{key}"), &[]).expect(204);
    }
    await_used(
        &c,
        "after deleting everything",
        Duration::from_secs(15),
        |u| u <= empty,
    );
}

/// A copy shares the pack like any stripe: it outlives its source and every
/// other object in the pack, and the pack goes only with it.
#[test]
fn a_copy_of_a_packed_object_keeps_the_pack() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    let empty = c.total_used_bytes();
    let objects = put_small(&c, "cp", 6);
    pack_all(&c, "cp", &objects);

    c.request_with_headers("PUT", "/cp/copy", &[], &[("x-amz-copy-source", "/cp/o3")])
        .expect(200);
    for (key, _) in &objects {
        c.request("DELETE", &format!("/cp/{key}"), &[]).expect(204);
    }
    std::thread::sleep(Duration::from_secs(1));
    let r = c.request("GET", "/cp/copy", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert!(
        r.bytes == objects[3].1,
        "the copy reads back different bytes"
    );

    c.request("DELETE", "/cp/copy", &[]).expect(204);
    await_used(
        &c,
        "after deleting the copy",
        Duration::from_secs(15),
        |u| u <= empty,
    );
}

/// What can't be packed is left as it was, and said why.
#[test]
fn what_cannot_be_packed_is_left_alone() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    let objects = put_small(&c, "s", 2);
    c.request("PUT", "/s/tiny", b"inline").expect(200);
    c.request("PUT", "/s/big", &payload(200_000, 7)).expect(200);
    let report = pack(&c, "s", &["tiny", "big", "missing", "o0"]);
    let skipped: Vec<&str> = report["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|s| s[0].as_str())
        .collect();
    assert_eq!(skipped, ["tiny", "big", "missing"], "{report}");
    assert_readable(&c, "s", &objects, "after packing one");
    assert_eq!(c.request("GET", "/s/tiny", &[]).bytes, b"inline");
}

/// A lost pack shard is rebuilt once, from the pack's record, and the
/// packed objects then survive two more losses.
#[test]
fn a_pack_is_repaired_so_its_objects_survive_two_more_losses() {
    let mut c =
        Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks", "--repair-interval-secs", "1"]);
    let objects = put_small(&c, "r", 10);
    pack_all(&c, "r", &objects);

    c.restart_with_lost_disk(0);
    assert_readable(&c, "r", &objects, "one disk lost");
    // Every OSD holds one shard of the pack; the rebuild shows in the
    // repairer's count (the gateway refreshes meta's metrics every ~30 s).
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let rebuilt: u64 = c
            .request("GET", "/metrics", &[])
            .text()
            .lines()
            .filter(|l| {
                l.starts_with("objectio_meta_repair_shards_rebuilt_total")
                    && l.contains("reason=\"missing\"")
            })
            .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
            .sum();
        if rebuilt >= 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the pack's shard was never rebuilt"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    c.restart_with_lost_disks(&[1, 2]);
    assert_readable(&c, "r", &objects, "with two more disks lost");
}

fn node_ids(c: &Cluster) -> Vec<(String, String)> {
    let nodes = c.request("GET", "/_admin/nodes", &[]).json();
    nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| {
            (
                n["address"].as_str().unwrap_or_default().to_string(),
                n["node_id"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn admin_state(c: &Cluster, id: &str) -> String {
    let nodes = c.request("GET", "/_admin/nodes", &[]).json();
    nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["node_id"].as_str() == Some(id))
        .and_then(|n| n["admin_state"].as_str())
        .unwrap_or("?")
        .to_string()
}

/// Drain moves a pack's shards off the OSD, recording them once in the
/// pack: the disk can then be pulled with two more lost.
#[test]
fn a_drain_moves_pack_shards() {
    let mut c =
        Cluster::start_with_ec_and_args(7, 4, 2, &["--test-hooks", "--drain-interval-secs", "1"]);
    let objects = put_small(&c, "d", 10);
    let report = pack_all(&c, "d", &objects);
    let holders: Vec<String> = report["shard_nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let ids = node_ids(&c);
    // OSD indexes holding a pack shard, by their registered address.
    let holding: Vec<(usize, String)> = (0..7)
        .filter_map(|i| {
            let addr = c.osd_address(i);
            let id = ids.iter().find(|(a, _)| *a == addr)?.1.clone();
            holders.contains(&id).then_some((i, id))
        })
        .collect();
    assert!(holding.len() >= 3, "{holding:?} of {holders:?}");
    let (drained_index, drained) = holding[0].clone();

    c.json(
        "PUT",
        &format!("/_admin/osds/{drained}/admin-state"),
        json!({ "state": "draining" }),
    )
    .expect_ok();
    let deadline = Instant::now() + Duration::from_secs(240);
    while admin_state(&c, &drained) != "out" {
        assert!(
            Instant::now() < deadline,
            "never finished draining: {}",
            admin_state(&c, &drained)
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    // Pull the drained disk, and lose two more of the pack's.
    c.restart_with_lost_disks(&[drained_index, holding[1].0, holding[2].0]);
    assert_readable(&c, "d", &objects, "drained, and two more lost");
}

// ── Phase 2: crash injection, reconciliation, the worker ─────────────────

fn reconcile(c: &Cluster) -> Value {
    let r = c.json(
        "POST",
        "/_admin/test/pack-reconcile",
        json!({ "min_age_secs": 0 }),
    );
    assert_eq!(r.status, 200, "reconcile: {}", r.text());
    r.json()
}

fn pack_stopping(c: &Cluster, bucket: &str, objects: &[(String, Vec<u8>)], stop: &str) -> Value {
    let keys: Vec<&str> = objects.iter().map(|(k, _)| k.as_str()).collect();
    let r = c.json(
        "POST",
        "/_admin/test/pack",
        json!({ "bucket": bucket, "keys": keys, "stop_after": stop }),
    );
    assert_eq!(r.status, 200, "pack: {}", r.text());
    r.json()
}

fn count(report: &Value, field: &str) -> u64 {
    report[field]
        .as_u64()
        .unwrap_or_else(|| panic!("no {field}: {report}"))
}

fn delete_all(c: &Cluster, bucket: &str, objects: &[(String, Vec<u8>)]) {
    for (key, _) in objects {
        c.request("DELETE", &format!("/{bucket}/{key}"), &[])
            .expect(204);
    }
}

/// The packer stopped (as by a crash) after each of its steps. Every object
/// reads back throughout; reconciliation then settles the pack; a second
/// pass finds nothing to do; and deleting every object gives back all the
/// space, so nothing leaked and nothing still pointed at was freed.
#[test]
fn a_packer_that_dies_at_any_step_is_reconciled() {
    for (stop, aborted, released, finished) in [
        ("intend", 1, 0, 0),
        ("write", 1, 0, 0),
        ("seal", 0, 8, 0),
        ("switch-one", 0, 7, 1),
    ] {
        let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
        let empty = c.total_used_bytes();
        let objects = put_small(&c, "crash", 8);
        let unpacked = await_used(&c, "written", Duration::from_secs(15), |u| u > empty);

        pack_stopping(&c, "crash", &objects, stop);
        assert_readable(&c, "crash", &objects, &format!("stopped after {stop}"));

        let report = reconcile(&c);
        assert_eq!(
            (
                count(&report, "aborted"),
                count(&report, "released"),
                count(&report, "finished"),
                count(&report, "unknown"),
            ),
            (aborted, released, finished, 0),
            "{stop}: {report}"
        );
        assert_readable(&c, "crash", &objects, &format!("reconciled after {stop}"));
        let again = reconcile(&c);
        assert_eq!(
            count(&again, "aborted") + count(&again, "released") + count(&again, "finished"),
            0,
            "{stop}: a second pass had work: {again}"
        );
        if aborted + released == 8 || aborted == 1 {
            // Nothing stayed packed: the space is what it was unpacked.
            await_used(
                &c,
                &format!("{stop}: back to unpacked"),
                Duration::from_secs(15),
                |u| u <= unpacked,
            );
        }

        delete_all(&c, "crash", &objects);
        await_used(
            &c,
            &format!("{stop}: all deleted"),
            Duration::from_secs(15),
            |u| u <= empty,
        );
    }
}

/// Objects overwritten and deleted between the pack's seal and their
/// switch: the client's writes win, the pack lets go of them, and the
/// other objects' slices stay readable.
#[test]
fn objects_changed_while_being_packed_keep_what_the_client_wrote() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    let empty = c.total_used_bytes();
    let objects = put_small(&c, "race", 6);
    pack_stopping(&c, "race", &objects, "seal");

    let fresh = payload(7_000, 99);
    c.request("PUT", "/race/o0", &fresh).expect(200);
    c.request("DELETE", "/race/o1", &[]).expect(204);
    // The rest switched by the next attempt; o0 and o1 are no longer
    // the objects that were read.
    let report = reconcile(&c);
    assert_eq!(count(&report, "released"), 6, "{report}");
    assert_eq!(c.request("GET", "/race/o0", &[]).bytes, fresh);
    c.request("GET", "/race/o1", &[]).expect(404);
    assert_readable(&c, "race", &objects[2..], "after the race");

    // Packed for real now, the survivors read and delete cleanly.
    let rest: Vec<&str> = objects[2..].iter().map(|(k, _)| k.as_str()).collect();
    let report = pack(&c, "race", &rest);
    assert_eq!(
        report["packed"].as_array().map(Vec::len),
        Some(4),
        "{report}"
    );
    assert_readable(&c, "race", &objects[2..], "packed after the race");
    c.request("DELETE", "/race/o0", &[]).expect(204);
    delete_all(&c, "race", &objects[2..]);
    await_used(&c, "all deleted", Duration::from_secs(15), |u| u <= empty);
}

/// A locked object packs and stays locked: its retention and legal hold
/// travel with it, and its version still can't be deleted.
#[test]
fn a_locked_object_packs_and_stays_locked() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    c.request_with_headers(
        "PUT",
        "/worm",
        &[],
        &[("x-amz-bucket-object-lock-enabled", "true")],
    )
    .expect(200);
    let mut versions = Vec::new();
    let mut objects = Vec::new();
    for i in 0..3u8 {
        let body = payload(6_000 + usize::from(i) * 1_000, i);
        let r = c.request_with_headers(
            "PUT",
            &format!("/worm/o{i}"),
            &body,
            &[
                ("x-amz-object-lock-mode", "COMPLIANCE"),
                (
                    "x-amz-object-lock-retain-until-date",
                    "2099-01-01T00:00:00Z",
                ),
                ("x-amz-object-lock-legal-hold", "ON"),
            ],
        );
        r.expect(200);
        versions.push(r.header("x-amz-version-id").expect("a version"));
        objects.push((format!("o{i}"), body));
    }
    pack_all(&c, "worm", &objects);
    assert_readable(&c, "worm", &objects, "packed");
    for (i, v) in versions.iter().enumerate() {
        let head = c.request("HEAD", &format!("/worm/o{i}"), &[]);
        assert_eq!(
            head.header("x-amz-object-lock-mode").as_deref(),
            Some("COMPLIANCE")
        );
        assert_eq!(
            head.header("x-amz-object-lock-legal-hold").as_deref(),
            Some("ON")
        );
        let del = c.request("DELETE", &format!("/worm/o{i}?versionId={v}"), &[]);
        assert_eq!(
            del.status,
            403,
            "a locked, packed version was deleted: {}",
            del.text()
        );
    }
}

fn metric(c: &Cluster, name: &str) -> u64 {
    c.request("GET", "/metrics", &[])
        .text()
        .lines()
        .filter(|l| l.split(['{', ' ']).next() == Some(name))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// The background packer, on: small objects old enough end up in packs
/// and read back; tiny (inline) and large objects are left alone. (One
/// small object left over on its own is not packed: it would save
/// nothing.)
#[test]
fn the_packer_packs_small_objects_in_the_background() {
    let c = Cluster::start_with_ec_and_args(
        6,
        4,
        2,
        // Old enough a moment after the writes finish, so they're packed
        // together, not as they arrive; old stripes released a second
        // after the switch.
        &[
            "--pack-interval-secs",
            "1",
            "--pack-min-age-secs",
            "3",
            "--pack-grace-secs",
            "1",
        ],
    );
    c.json("POST", "/_admin/buckets", json!({ "name": "bg" }))
        .expect_ok();
    // Twenty objects, all within the packing cut-off (64 KiB).
    let objects: Vec<(String, Vec<u8>)> = (0..20u8)
        .map(|i| {
            let body = payload(5_000 + usize::from(i) * 2_500, i);
            let key = format!("o{i}");
            c.request("PUT", &format!("/bg/{key}"), &body).expect(200);
            (key, body)
        })
        .collect();
    c.request("PUT", "/bg/tiny", b"inline").expect(200);
    let large = payload(300_000, 77);
    c.request("PUT", "/bg/large", &large).expect(200);
    let written = c.total_used_bytes();

    let deadline = Instant::now() + Duration::from_secs(60);
    while metric(&c, "objectio_pack_objects_total") < 20 {
        assert!(
            Instant::now() < deadline,
            "the packer never packed the objects"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    assert_readable(&c, "bg", &objects, "packed in the background");
    assert_eq!(c.request("GET", "/bg/tiny", &[]).bytes, b"inline");
    assert!(c.request("GET", "/bg/large", &[]).bytes == large);
    await_used(&c, "after packing", Duration::from_secs(15), |u| {
        u < written
    });
    // Settled: nothing left for reconciliation.
    assert_eq!(metric(&c, "objectio_pack_reconciled_total"), 0);
    // Packed once: later passes leave packed objects alone.
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(metric(&c, "objectio_pack_objects_total"), 20);
}

// ── Phase 3: compaction ──────────────────────────────────────────────────

fn compact(c: &Cluster, stop: Option<&str>) -> Value {
    let r = c.json(
        "POST",
        "/_admin/test/pack-compact",
        json!({ "min_age_secs": 0, "stop_after": stop }),
    );
    assert_eq!(r.status, 200, "compact: {}", r.text());
    r.json()
}

/// A pack most of whose objects are gone has its survivors moved into a
/// new pack, and its space comes back; the survivors read throughout.
#[test]
fn a_mostly_deleted_pack_is_compacted() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    let empty = c.total_used_bytes();
    let objects = put_small(&c, "cmp", 10);
    pack_all(&c, "cmp", &objects);
    // Keep the three smallest: well under half the pack.
    delete_all(&c, "cmp", &objects[3..]);
    let kept = &objects[..3];
    std::thread::sleep(Duration::from_secs(1));
    let before = c.total_used_bytes();

    let report = compact(&c, None);
    assert_eq!(
        (count(&report, "compacted"), count(&report, "moved")),
        (1, 3),
        "{report}"
    );
    assert_readable(&c, "cmp", kept, "compacted");
    await_used(&c, "after compaction", Duration::from_secs(15), |u| {
        u < before
    });
    // Settled: nothing for reconciliation, and nothing more to compact.
    let again = reconcile(&c);
    assert_eq!(
        count(&again, "released") + count(&again, "finished"),
        0,
        "{again}"
    );
    assert_eq!(count(&compact(&c, None), "compacted"), 0);

    delete_all(&c, "cmp", kept);
    await_used(&c, "all deleted", Duration::from_secs(15), |u| u <= empty);
}

/// A pack still more than half live is left as it is, and so is one a
/// copy shares: moving the source wouldn't free it.
#[test]
fn live_and_shared_packs_are_not_compacted() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    let objects = put_small(&c, "keep", 10);
    pack_all(&c, "keep", &objects);
    delete_all(&c, "keep", &objects[..1]);
    assert_eq!(count(&compact(&c, None), "compacted"), 0, "mostly live");

    let shared = put_small(&c, "shared", 10);
    pack_all(&c, "shared", &shared);
    c.request_with_headers(
        "PUT",
        "/shared/copy",
        &[],
        &[("x-amz-copy-source", "/shared/o1")],
    )
    .expect(200);
    delete_all(&c, "shared", &shared[2..]);
    assert_eq!(
        count(&compact(&c, None), "compacted"),
        0,
        "shared by a copy"
    );
    assert_readable(&c, "shared", &shared[..2], "not compacted");
    assert!(c.request("GET", "/shared/copy", &[]).bytes == shared[1].1);
}

/// A compaction that dies after switching one object is reconciled like
/// any pack, and a later pass finishes the job; nothing is lost or leaked.
#[test]
fn a_compaction_that_dies_midway_is_reconciled() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    let empty = c.total_used_bytes();
    let objects = put_small(&c, "half", 10);
    pack_all(&c, "half", &objects);
    delete_all(&c, "half", &objects[4..]);
    let kept = &objects[..4];

    compact(&c, Some("switch-one"));
    assert_readable(&c, "half", kept, "compaction stopped");
    let report = reconcile(&c);
    assert_eq!(
        (
            count(&report, "finished"),
            count(&report, "released"),
            count(&report, "unknown")
        ),
        (1, 3, 0),
        "{report}"
    );
    assert_readable(&c, "half", kept, "reconciled");
    // The three not moved are still in the old pack, still under half
    // live; and the crashed pass's new pack holds one live object of four:
    // a pass now compacts both.
    let report = compact(&c, None);
    assert_eq!(
        (count(&report, "compacted"), count(&report, "moved")),
        (2, 4),
        "{report}"
    );
    assert_readable(&c, "half", kept, "compacted after the crash");

    delete_all(&c, "half", kept);
    await_used(&c, "all deleted", Duration::from_secs(15), |u| u <= empty);
}

type Model = std::collections::BTreeMap<String, Vec<u8>>;

/// Every object in `model` reads back as written.
fn verify(c: &Cluster, model: &Model, when: &str) {
    for (key, body) in model {
        let r = c.request("GET", &format!("/soak/{key}"), &[]);
        assert_eq!(r.status, 200, "{when}: {key}: {}", r.text());
        assert!(r.bytes == *body, "{when}: {key} reads back different bytes");
    }
}

/// Random writes, overwrites, deletes and reads over 30 keys for `secs`,
/// each read checked against what was last written. Returns what's left
/// and how many operations ran.
fn soak_ops(c: &Cluster, secs: u64) -> (Model, u32) {
    let mut model = Model::new();
    let mut x = 0x2545_F491_4F6C_DD1D_u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let started = Instant::now();
    let mut ops = 0u32;
    while started.elapsed() < Duration::from_secs(secs) {
        let key = format!("k{:02}", next() % 30);
        match next() % 10 {
            0..=4 => {
                let size = 4_200 + usize::try_from(next() % 56_000).unwrap();
                let body = payload(size, u8::try_from(next() % 251).unwrap());
                c.request("PUT", &format!("/soak/{key}"), &body).expect(200);
                model.insert(key, body);
            }
            5 | 6 => {
                c.request("DELETE", &format!("/soak/{key}"), &[])
                    .expect(204);
                model.remove(&key);
            }
            _ => {
                let r = c.request("GET", &format!("/soak/{key}"), &[]);
                match model.get(&key) {
                    Some(body) => {
                        assert_eq!(r.status, 200, "{key}: {}", r.text());
                        assert!(r.bytes == *body, "{key} reads back different bytes");
                    }
                    None => assert_eq!(r.status, 404, "{key} came back"),
                }
            }
        }
        ops += 1;
        if ops.is_multiple_of(200) {
            verify(c, &model, "during the soak");
        }
    }
    (model, ops)
}

/// Wait until the packer has stopped packing and compacting; returns the
/// objects it packed.
fn await_packer_quiet(c: &Cluster) -> u64 {
    let activity = || {
        (
            metric(c, "objectio_pack_objects_total"),
            metric(c, "objectio_pack_compactions_total"),
        )
    };
    let mut last = activity();
    loop {
        std::thread::sleep(Duration::from_secs(5));
        let now = activity();
        if now == last {
            return last.0;
        }
        last = now;
    }
}

/// Reconciliation as in production: it settles only packs older than any
/// packer could still be working on (here: past the grace and a pass).
fn reconcile_settled(c: &Cluster) -> Value {
    std::thread::sleep(Duration::from_secs(12));
    let r = c.json(
        "POST",
        "/_admin/test/pack-reconcile",
        json!({ "min_age_secs": 10 }),
    );
    assert_eq!(r.status, 200, "reconcile: {}", r.text());
    r.json()
}

/// Soak: writes, overwrites, deletes and reads of small objects for a
/// while, with the packer and compaction running underneath. Every read
/// returns what was last written; at the end nothing is left for
/// reconciliation; and deleting everything gives back every byte: nothing
/// was freed that anything pointed at, and nothing leaked.
#[test]
fn a_soak_with_packing_and_compaction_loses_nothing() {
    let c = Cluster::start_with_ec_and_args(
        6,
        4,
        2,
        &[
            "--test-hooks",
            "--pack-interval-secs",
            "1",
            "--pack-min-age-secs",
            "0",
            "--pack-grace-secs",
            "2",
        ],
    );
    c.json("POST", "/_admin/buckets", json!({ "name": "soak" }))
        .expect_ok();
    let empty = c.total_used_bytes();

    let (model, ops) = soak_ops(&c, 45);
    verify(&c, &model, "at the end of the soak");
    let packed = await_packer_quiet(&c);
    assert!(packed > 0, "the packer packed nothing in {ops} operations");
    verify(&c, &model, "the packer quiet");
    let report = reconcile_settled(&c);
    assert_eq!(count(&report, "unknown"), 0, "{report}");
    assert_eq!(count(&report, "aborted"), 0, "{report}");
    verify(&c, &model, "reconciled");

    for key in model.keys() {
        c.request("DELETE", &format!("/soak/{key}"), &[])
            .expect(204);
    }
    // Deletes racing the packer's switches leave work for reconciliation;
    // once it has run, every byte is back.
    reconcile_settled(&c);
    let deadline = Instant::now() + Duration::from_secs(30);
    while c.total_used_bytes() > empty {
        assert!(
            Instant::now() < deadline,
            "all deleted: used bytes stayed at {} (empty: {empty}); packs left: {}",
            c.total_used_bytes(),
            c.request("GET", "/_admin/test/packs", &[]).text()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    eprintln!(
        "soak: {ops} operations, {packed} objects packed, {} packs compacted",
        metric(&c, "objectio_pack_compactions_total")
    );
}
