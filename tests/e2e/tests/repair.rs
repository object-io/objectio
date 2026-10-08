//! Restoring redundancy: Meta's repairer rebuilding shards an OSD lost or
//! that rotted on disk, found by asking the OSDs (and their scrubbers).
//!
//! Every object here is 4+2 on six OSDs, one shard per OSD, so any four
//! OSDs can serve it and losing a disk costs every object one shard.

use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use serde_json::json;

/// Sum of every sample of `name` whose labels contain all of `labels`.
fn metric(c: &Cluster, name: &str, labels: &[&str]) -> u64 {
    c.request("GET", "/metrics", &[])
        .text()
        .lines()
        .filter(|l| {
            l.split(['{', ' ']).next() == Some(name) && labels.iter().all(|want| l.contains(want))
        })
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// Wait until `name{labels}` reaches `want`, or fail after `within`. The
/// gateway refreshes meta's and the OSDs' metrics about every 30 s.
fn await_metric(c: &Cluster, name: &str, labels: &[&str], want: u64, within: Duration) {
    let deadline = Instant::now() + within;
    loop {
        let got = metric(c, name, labels);
        if got >= want {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{name}{labels:?} stayed at {got}, wanted {want}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Bytes that do not repeat, so a run of them identifies one shard.
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

const OBJECTS: usize = 4;

fn put_objects(c: &Cluster, bucket: &str) -> Vec<Vec<u8>> {
    c.json("POST", "/_admin/buckets", json!({"name": bucket}))
        .expect_ok();
    (0..OBJECTS)
        .map(|i| {
            let body = payload(300_000, u8::try_from(i).unwrap());
            c.request("PUT", &format!("/{bucket}/o-{i}"), &body)
                .expect(200);
            body
        })
        .collect()
}

fn assert_readable(c: &Cluster, bucket: &str, bodies: &[Vec<u8>], when: &str) {
    for (i, body) in bodies.iter().enumerate() {
        let got = c.request("GET", &format!("/{bucket}/o-{i}"), &[]);
        assert_eq!(got.status, 200, "o-{i} unreadable {when}: {}", got.text());
        assert_eq!(&got.bytes, body, "o-{i} changed {when}");
    }
}

/// The point of repairing: after a disk is lost and rebuilt, the objects
/// survive two more losses. Without the rebuild, three lost shards out of
/// six would leave three — one short of k.
#[test]
fn a_lost_disk_is_rebuilt_so_objects_survive_two_more_losses() {
    let mut c = Cluster::start_with_ec_and_args(6, 4, 2, &["--repair-interval-secs", "1"]);
    let bodies = put_objects(&c, "lost");

    c.restart_with_lost_disk(0);
    // Rebuilt by its placement groups' recovery (B31 phase 3a), which the
    // OSD's report of shards dropped at start sets off.
    await_metric(
        &c,
        "objectio_meta_pg_recovered_shards_total",
        &[],
        OBJECTS as u64,
        Duration::from_secs(120),
    );
    assert_readable(&c, "lost", &bodies, "after the rebuild");

    c.restart_with_lost_disks(&[1, 2]);
    assert_readable(&c, "lost", &bodies, "with two more disks lost");
}

/// Whether the OSD at `address` holds a metadata copy of `bucket/key`.
fn osd_has_meta(address: &str, bucket: &str, key: &str) -> bool {
    use objectio_proto::storage::GetObjectMetaRequest;
    use objectio_proto::storage::storage_service_client::StorageServiceClient;
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mut client = StorageServiceClient::new(
            objectio_e2e::tls::channel(address)
                .await
                .expect("connect OSD"),
        );
        client
            .get_object_meta(GetObjectMetaRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: String::new(),
                with_small_shard: false,
            })
            .await
            .expect("GetObjectMeta")
            .into_inner()
            .found
    })
}

/// Every object keeps a metadata copy on each of its k + m OSDs: reads take
/// the newest of a read quorum, which only holds while every copy is kept.
/// A drive lost whole (its shards and the metadata on it) is replaced by a
/// blank one; repair must give it back a copy of every object it should
/// hold, erasure-coded and inline alike, not only the shards.
#[test]
fn a_replaced_drive_gets_back_every_metadata_copy() {
    let mut c = Cluster::start_with_ec_and_args(6, 4, 2, &["--repair-interval-secs", "1"]);
    let bodies = put_objects(&c, "copies");
    let inline: Vec<Vec<u8>> = (0..OBJECTS)
        .map(|i| {
            let body = payload(1000, 100 + u8::try_from(i).unwrap());
            c.request("PUT", &format!("/copies/small-{i}"), &body)
                .expect(200);
            body
        })
        .collect();
    // Small objects whose shards are kept in the OSDs' metadata records
    // (B21): the lost drive takes its records with it.
    let mid: Vec<Vec<u8>> = (0..OBJECTS)
        .map(|i| {
            let body = payload(20_000, 180 + u8::try_from(i).unwrap());
            c.request("PUT", &format!("/copies/mid-{i}"), &body)
                .expect(200);
            body
        })
        .collect();

    // The drive is gone for good: its OSD is set out, as the runbook says,
    // and the blank drive comes back as a new OSD.
    let dead = osd_id(&c, 0);
    c.restart_with_lost_drive(0);
    c.json(
        "PUT",
        &format!("/_admin/osds/{dead}/admin-state"),
        json!({ "state": "out" }),
    )
    .expect_ok();

    // The blank drive's OSD gets back a shard of every stripe and a
    // metadata copy of every object, inline ones too.
    let address = c.osd_address(0);
    let keys: Vec<String> = (0..OBJECTS)
        .map(|i| format!("o-{i}"))
        .chain((0..OBJECTS).map(|i| format!("small-{i}")))
        .chain((0..OBJECTS).map(|i| format!("mid-{i}")))
        .collect();
    let deadline = Instant::now() + Duration::from_secs(300);
    for key in &keys {
        while !osd_has_meta(&address, "copies", key) {
            assert!(
                Instant::now() < deadline,
                "the replaced drive never got {key}'s metadata copy back"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    while shard_count(&c, 0) < 2 * OBJECTS as u64 {
        assert!(
            Instant::now() < deadline,
            "the replaced drive holds {} shards, wanted {OBJECTS}",
            shard_count(&c, 0)
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    // Two more drives lost whole: every object still reads, from four
    // shards and the metadata copies left.
    c.restart_with_lost_drive(1);
    c.restart_with_lost_drive(2);
    assert_readable(&c, "copies", &bodies, "with two more drives lost");
    for (i, body) in inline.iter().enumerate() {
        let got = c.request("GET", &format!("/copies/small-{i}"), &[]);
        assert_eq!(got.status, 200, "small-{i} unreadable: {}", got.text());
        assert_eq!(&got.bytes, body, "small-{i}");
    }
    for (i, body) in mid.iter().enumerate() {
        let got = c.request("GET", &format!("/copies/mid-{i}"), &[]);
        assert_eq!(got.status, 200, "mid-{i} unreadable: {}", got.text());
        assert_eq!(&got.bytes, body, "mid-{i}");
    }
}

/// Flip one byte of `needle` in `path`, the way a bad sector would. Shards
/// sit at the front of a fresh disk's data region, which begins after the
/// 1 GiB metadata area.
fn rot(path: &std::path::Path, needle: &[u8]) -> bool {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let chunk = 8 << 20;
    let mut buf = vec![0u8; chunk + needle.len()];
    let mut base = 1u64 << 30;
    for _ in 0..64 {
        f.seek(SeekFrom::Start(base)).unwrap();
        let n = f.read(&mut buf).unwrap();
        if let Some(at) = buf[..n].windows(needle.len()).position(|w| w == needle) {
            let at = base + (at + needle.len() / 2) as u64;
            let mut b = [0u8];
            f.seek(SeekFrom::Start(at)).unwrap();
            f.read_exact(&mut b).unwrap();
            f.seek(SeekFrom::Start(at)).unwrap();
            f.write_all(&[b[0] ^ 0xff]).unwrap();
            f.sync_all().unwrap();
            return true;
        }
        if n < buf.len() {
            return false;
        }
        base += chunk as u64;
    }
    false
}

/// Rot nobody reads is found by its placement group's scrub (B31 phase 4),
/// which reads every member's shards back and checks them, and rebuilt by
/// the PG's recovery; the object reads back correctly throughout. The
/// OSDs' own scrubber is off: the PG scrub finds it by itself.
#[test]
fn a_rotted_shard_is_found_by_the_scrubber_and_rebuilt() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--scrub-interval-secs", "0"]);
    c.json("POST", "/_admin/buckets", json!({"name": "rot"}))
        .expect_ok();
    let body = payload(400_000, 0x5a);
    c.request("PUT", "/rot/o", &body).expect(200);

    // The first data shard holds the first quarter of the body.
    let needle = &body[1000..1064];
    let rotted = (0..6).any(|i| rot(&c.osd_disk(i), needle));
    assert!(rotted, "shard bytes not found on any disk");

    // The PG holding it (the only one with an object) scrubbed now.
    let deadline = Instant::now() + Duration::from_secs(60);
    let pg = loop {
        let pgs = c
            .request("GET", "/_admin/pools/default/placement-groups", &[])
            .json();
        if let Some(id) = pgs["pgs"].as_array().and_then(|a| {
            a.iter()
                .find(|p| p["state"]["objects"].as_u64().unwrap_or(0) > 0)
                .and_then(|p| p["pg_id"].as_u64())
        }) {
            break id;
        }
        assert!(Instant::now() < deadline, "no PG holds the object: {pgs}");
        std::thread::sleep(Duration::from_millis(500));
    };
    let r = c.request(
        "POST",
        &format!("/_admin/pools/default/placement-groups/{pg}/scrub"),
        &[],
    );
    assert_eq!(r.status, 202, "{}", r.text());
    await_metric(
        &c,
        "objectio_meta_scrub_shards_bad_total",
        &["reason=\"corrupt\""],
        1,
        Duration::from_secs(120),
    );
    await_metric(
        &c,
        "objectio_meta_pg_recovered_shards_total",
        &[],
        1,
        Duration::from_secs(120),
    );
    let got = c.request("GET", "/rot/o", &[]);
    got.expect(200);
    assert_eq!(got.bytes, body);
}

/// OSD `index`'s node id, as `/_admin/nodes` lists it.
fn osd_id(c: &Cluster, index: usize) -> String {
    let addr = c.osd_address(index);
    c.request("GET", "/_admin/nodes", &[]).json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["address"].as_str() == Some(addr.as_str()))
        .and_then(|n| n["node_id"].as_str())
        .unwrap_or_else(|| panic!("no OSD at {addr}"))
        .to_string()
}

/// OSD `index`'s shard count, from `/_admin/nodes`.
fn shard_count(c: &Cluster, index: usize) -> u64 {
    let id = osd_id(c, index);
    c.request("GET", "/_admin/nodes", &[]).json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["node_id"].as_str() == Some(id.as_str()))
        .and_then(|n| n["shard_count"].as_u64())
        .unwrap_or(0)
}

/// An OSD set out with no other to stand in for it (six OSDs, 4+2): its
/// placement groups are undersized, and objects written meanwhile go to the
/// other five, one shard each, short one and recorded so (B31): nothing is
/// put on the OSD that is out, and nothing doubles up on another (it did,
/// before placement groups: two shards of every such object on one OSD,
/// spread again by repair later). Once the OSD is back in, repair puts the
/// missing shard there, and the objects survive any two losses.
#[test]
fn objects_written_while_an_osd_is_out_get_their_missing_shard_when_it_is_back() {
    let mut c = Cluster::start_with_ec_and_args(6, 4, 2, &["--repair-interval-secs", "1"]);
    let out = osd_id(&c, 0);
    let set = |state: &str| {
        c.json(
            "PUT",
            &format!("/_admin/osds/{out}/admin-state"),
            json!({ "state": state }),
        )
        .expect_ok();
    };
    set("out");
    let bodies = put_objects(&c, "undersized");
    let counts: Vec<u64> = (0..6).map(|i| shard_count(&c, i)).collect();
    assert_eq!(
        counts[0], 0,
        "a shard went to the OSD that is out: {counts:?}"
    );
    assert!(
        counts.iter().all(|n| *n <= OBJECTS as u64),
        "shards doubled up: {counts:?}"
    );

    set("in");
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        let counts: Vec<u64> = (0..6).map(|i| shard_count(&c, i)).collect();
        if counts.iter().all(|n| *n == OBJECTS as u64) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the missing shards never came: {counts:?}"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    assert_readable(&c, "undersized", &bodies, "once the OSD was back");

    // The OSD that was out, and one more.
    c.restart_with_lost_disks(&[0, 1]);
    assert_readable(&c, "undersized", &bodies, "with two disks lost");
}

/// B26, as a drive is replaced in production: the OSD's drive dies with
/// its metadata on it, a blank one goes in the same slot, and the OSD
/// comes back new, at the same address. Nobody sets anything: the old OSD
/// is recorded lost, everything it held is rebuilt from the other copies
/// (shards and metadata copies, inline objects too), its entry goes, and
/// the objects then survive two more OSDs down.
#[test]
fn a_drive_replaced_in_place_is_rebuilt_without_an_operator() {
    use objectio_e2e::ha::HaCluster;
    let mut ha = HaCluster::start(1, 6, 1);
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/swap", &[]).status, 200);
    let big: Vec<Vec<u8>> = (0..OBJECTS)
        .map(|i| payload(300_000, 50 + u8::try_from(i).unwrap()))
        .collect();
    let small: Vec<Vec<u8>> = (0..OBJECTS)
        .map(|i| payload(1000, 150 + u8::try_from(i).unwrap()))
        .collect();
    for (i, b) in big.iter().enumerate() {
        assert_eq!(c.request("PUT", &format!("/swap/o-{i}"), b).status, 200);
    }
    for (i, b) in small.iter().enumerate() {
        assert_eq!(c.request("PUT", &format!("/swap/small-{i}"), b).status, 200);
    }
    let ids = |c: &Cluster| -> Vec<(String, String, String)> {
        c.request("GET", "/_admin/nodes", &[]).json()["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| {
                (
                    n["node_id"].as_str().unwrap_or_default().to_string(),
                    n["address"].as_str().unwrap_or_default().to_string(),
                    n["admin_state"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    };
    let endpoint = ha.osd_endpoint(5);
    let old = ids(&ha.clients[0])
        .into_iter()
        .find(|(_, a, _)| *a == endpoint)
        .map(|(id, ..)| id)
        .expect("OSD 5 registered");

    ha.stop_osd(5);
    ha.lose_osd_drive(5);
    ha.start_osd(5, None);

    let c = &ha.clients[0];
    let deadline = Instant::now() + Duration::from_secs(600);
    loop {
        let now = ids(c);
        let new_in = now
            .iter()
            .any(|(id, a, s)| *a == endpoint && *id != old && s == "in");
        let old_gone = !now.iter().any(|(id, ..)| *id == old);
        if new_in && old_gone {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the lost OSD was not evacuated and removed: {now:?}"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    let keys: Vec<String> = (0..OBJECTS)
        .map(|i| format!("o-{i}"))
        .chain((0..OBJECTS).map(|i| format!("small-{i}")))
        .collect();
    for key in &keys {
        assert!(
            osd_has_meta(&endpoint, "swap", key),
            "the new OSD has no metadata copy of {key}"
        );
    }

    ha.stop_osd(0);
    ha.stop_osd(1);
    let c = &ha.clients[0];
    for (i, b) in big.iter().enumerate() {
        let got = c.request("GET", &format!("/swap/o-{i}"), &[]);
        assert_eq!(got.status, 200, "o-{i}: {}", got.text());
        assert_eq!(&got.bytes, b, "o-{i}");
    }
    for (i, b) in small.iter().enumerate() {
        let got = c.request("GET", &format!("/swap/small-{i}"), &[]);
        assert_eq!(got.status, 200, "small-{i}: {}", got.text());
        assert_eq!(&got.bytes, b, "small-{i}");
    }
}

/// B26, as the soak found it: an OSD down during an overwrite and a delete
/// keeps stale metadata copies naming the old objects' shards, which the
/// newer writes freed. When another OSD is then lost for good, those
/// shards can't be rebuilt, and needn't be: the evacuation brings the
/// stale copies up to date instead of retrying them forever, and finishes.
#[test]
fn stale_copies_do_not_hold_up_a_lost_osds_evacuation() {
    use objectio_e2e::ha::HaCluster;
    let mut ha = HaCluster::start(1, 6, 1);
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/stale", &[]).status, 200);
    for i in 0..OBJECTS {
        let body = payload(300_000, 10 + u8::try_from(i).unwrap());
        assert_eq!(
            c.request("PUT", &format!("/stale/o-{i}"), &body).status,
            200
        );
        assert_eq!(
            c.request("PUT", &format!("/stale/d-{i}"), &body).status,
            200
        );
        assert_eq!(
            c.request("PUT", &format!("/stale/od-{i}"), &body).status,
            200
        );
    }
    // OSD 2 misses an overwrite of every o-, the delete of every d-, and
    // an overwrite then a delete of every od-: the overwrite frees the
    // first object's shards everywhere else, and the delete removes the
    // key's home (as the soak found: no home to read the key from).
    ha.stop_osd(2);
    let c = &ha.clients[0];
    let newer: Vec<Vec<u8>> = (0..OBJECTS)
        .map(|i| payload(300_000, 90 + u8::try_from(i).unwrap()))
        .collect();
    for (i, body) in newer.iter().enumerate() {
        assert_eq!(c.request("PUT", &format!("/stale/o-{i}"), body).status, 200);
        assert_eq!(
            c.request("DELETE", &format!("/stale/d-{i}"), &[]).status,
            204
        );
        assert_eq!(
            c.request("PUT", &format!("/stale/od-{i}"), body).status,
            200
        );
        assert_eq!(
            c.request("DELETE", &format!("/stale/od-{i}"), &[]).status,
            204
        );
    }
    ha.start_osd(2, None);

    let c = &ha.clients[0];
    let endpoint = ha.osd_endpoint(5);
    let ids = |c: &Cluster| -> Vec<(String, String)> {
        c.request("GET", "/_admin/nodes", &[]).json()["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| {
                (
                    n["node_id"].as_str().unwrap_or_default().to_string(),
                    n["address"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    };
    let old = ids(c)
        .into_iter()
        .find(|(_, a)| *a == endpoint)
        .map(|(id, _)| id)
        .expect("OSD 5 registered");
    ha.stop_osd(5);
    ha.lose_osd_drive(5);
    ha.start_osd(5, None);

    let c = &ha.clients[0];
    let deadline = Instant::now() + Duration::from_secs(600);
    while ids(c).iter().any(|(id, _)| *id == old) {
        assert!(
            Instant::now() < deadline,
            "the lost OSD was never evacuated: {:?}",
            ids(c)
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    for (i, body) in newer.iter().enumerate() {
        let got = c.request("GET", &format!("/stale/o-{i}"), &[]);
        assert_eq!(got.status, 200, "o-{i}: {}", got.text());
        assert_eq!(&got.bytes, body, "o-{i}");
        assert_eq!(
            c.request("GET", &format!("/stale/d-{i}"), &[]).status,
            404,
            "d-{i}"
        );
        assert_eq!(
            c.request("GET", &format!("/stale/od-{i}"), &[]).status,
            404,
            "od-{i}"
        );
    }
}

/// B29: a PUT acknowledged with only k + 1 shards (an OSD down while it
/// was written) is recorded as degraded when it is written, and repaired
/// from that record once the OSD is back, without waiting for a walk of
/// every object (the walk is all but off here). It then survives two more
/// OSDs down. Soak run 9 lost an object written this way: five shards for
/// an hour, then two more lost.
#[test]
fn a_write_short_of_shards_is_repaired_from_its_record() {
    use objectio_e2e::ha::HaCluster;
    let mut ha = HaCluster::start_with_meta_args(1, 6, 1, &["--repair-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/partial", &[]).status, 200);
    ha.stop_osd(2);
    let c = &ha.clients[0];
    let bodies: Vec<Vec<u8>> = (0..OBJECTS)
        .map(|i| payload(300_000, 30 + u8::try_from(i).unwrap()))
        .collect();
    for (i, b) in bodies.iter().enumerate() {
        assert_eq!(c.request("PUT", &format!("/partial/k{i}"), b).status, 200);
    }
    ha.start_osd(2, None);
    // A few rounds of the degraded worker (every 5 s).
    std::thread::sleep(Duration::from_secs(25));
    ha.stop_osd(4);
    ha.stop_osd(5);
    let c = &ha.clients[0];
    for (i, b) in bodies.iter().enumerate() {
        let got = c.request("GET", &format!("/partial/k{i}"), &[]);
        assert_eq!(got.status, 200, "k{i}: {}", got.text());
        assert_eq!(&got.bytes, b, "k{i}");
    }
}

/// Soak run 16: objects written while an OSD was down, that OSD their
/// owner (the first of their placement), and no gateway healing their
/// metadata copies. Repair read the object from the owner's copy alone,
/// found none, called it gone, and the degraded records waited forever.
/// They are repaired from a quorum of copies, the owner's copy written
/// back, and every object survives two more OSDs down.
#[test]
fn a_write_whose_owner_missed_it_is_repaired_without_a_heal() {
    use objectio_e2e::ha::HaCluster;
    let mut ha = HaCluster::start_with_meta_args(1, 6, 1, &["--repair-interval-secs", "3600"]);
    ha.restart_gateway_with_args(0, &["--heal-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    assert_eq!(ha.clients[0].request("PUT", "/owner", &[]).status, 200);
    ha.stop_osd(0);
    let c = &ha.clients[0];
    let bodies: Vec<Vec<u8>> = (0..24u8).map(|i| payload(300_000, 90 + i)).collect();
    for (i, b) in bodies.iter().enumerate() {
        assert_eq!(c.request("PUT", &format!("/owner/k{i}"), b).status, 200);
    }
    ha.start_osd(0, None);
    // Until every one of them is repaired: no degraded record left, and
    // (keys in placement groups mark their PG rather than keep a record)
    // every PG Clean.
    let deadline = Instant::now() + Duration::from_secs(120);
    let repaired = |ha: &HaCluster| {
        ha.meta_metric("objectio_meta_degraded_objects") == Some(0.0)
            && ha.meta_metric("objectio_meta_pgs_not_clean") == Some(0.0)
    };
    while !repaired(&ha) {
        assert!(
            Instant::now() < deadline,
            "still degraded after 120 s: {:?} records, {:?} PGs not Clean",
            ha.meta_metric("objectio_meta_degraded_objects"),
            ha.meta_metric("objectio_meta_pgs_not_clean")
        );
        std::thread::sleep(Duration::from_secs(2));
    }
    ha.stop_osd(4);
    ha.stop_osd(5);
    let c = &ha.clients[0];
    for (i, b) in bodies.iter().enumerate() {
        let got = c.request("GET", &format!("/owner/k{i}"), &[]);
        assert_eq!(got.status, 200, "k{i}: {}", got.text());
        assert_eq!(&got.bytes, b, "k{i}");
    }
}

/// B29: an evacuation that meets an object with fewer than k shards left
/// records it as lost and finishes, rather than wait on it forever; but
/// never while a holder of the rest is only down (it may have its shard).
#[test]
fn an_evacuation_records_a_lost_object_and_finishes() {
    use objectio_e2e::ha::HaCluster;
    let mut ha = HaCluster::start_with_meta_args(
        1,
        6,
        1,
        &[
            "--repair-interval-secs",
            "3600",
            "--drain-interval-secs",
            "1",
        ],
    );
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/gone", &[]).status, 200);
    assert_eq!(
        c.request("PUT", "/gone/k", &payload(300_000, 7)).status,
        200
    );
    let ids = |c: &Cluster| -> Vec<(String, String)> {
        c.request("GET", "/_admin/nodes", &[]).json()["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| {
                (
                    n["node_id"].as_str().unwrap_or_default().to_string(),
                    n["address"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    };
    let endpoint = ha.osd_endpoint(5);
    let old = ids(c)
        .into_iter()
        .find(|(_, a)| *a == endpoint)
        .map(|(id, _)| id)
        .expect("OSD 5 registered");

    // Two OSDs down with their disks gone, and a third lost for good.
    ha.stop_osd(0);
    ha.stop_osd(1);
    std::fs::remove_file(ha.osd_disk(0)).unwrap();
    std::fs::remove_file(ha.osd_disk(1)).unwrap();
    ha.stop_osd(5);
    ha.lose_osd_drive(5);
    ha.start_osd(5, None);

    // Only down, OSDs 0 and 1 may still have their shards: no verdict.
    std::thread::sleep(Duration::from_secs(15));
    let c = &ha.clients[0];
    assert!(
        ids(c).iter().any(|(id, _)| *id == old),
        "the lost OSD was removed while two holders were only down"
    );

    // Back, on blank disks: three shards left of the four a read needs.
    ha.start_osd(0, None);
    ha.start_osd(1, None);
    let c = &ha.clients[0];
    let deadline = Instant::now() + Duration::from_secs(120);
    while ids(c).iter().any(|(id, _)| *id == old) {
        assert!(
            Instant::now() < deadline,
            "the evacuation never finished: {:?}",
            ids(c)
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    // The object is gone, and says so; and it is counted.
    assert_eq!(c.request("GET", "/gone/k", &[]).status, 500);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let m = c.request("GET", "/metrics", &[]).text();
        let lost = m
            .lines()
            .find(|l| l.starts_with("objectio_meta_lost_objects"))
            .and_then(|l| l.rsplit(' ').next()?.parse::<f64>().ok())
            .unwrap_or(0.0);
        if lost >= 1.0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the lost object was never counted"
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// B29, heal on read: a shard lost with nothing recording it (a disk
/// wiped) is found by a GET, which decodes around it and reports the
/// object; repair rebuilds it within seconds, with the walk all but off.
/// The object then survives two more OSDs down.
#[test]
fn a_read_that_finds_a_shard_missing_has_it_rebuilt() {
    use objectio_e2e::ha::HaCluster;
    let mut ha = HaCluster::start_with_meta_args(1, 6, 1, &["--repair-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/heal", &[]).status, 200);
    let body = payload(300_000, 9);
    assert_eq!(c.request("PUT", "/heal/k", &body).status, 200);

    // The disk holding position 0 is wiped (a read takes the data
    // positions first, so it meets this one): its shard is gone, and
    // nothing says so.
    let holder = holder_of_position(&ha, "heal", "k", 0);
    ha.stop_osd(holder);
    std::fs::remove_file(ha.osd_disk(holder)).unwrap();
    ha.start_osd(holder, None);

    // A read decodes around it, and reports it.
    let c = &ha.clients[0];
    let got = c.request("GET", "/heal/k", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.bytes, body);
    // Until its placement group's recovery has rebuilt it.
    let deadline = Instant::now() + Duration::from_secs(120);
    while ha
        .meta_metric("objectio_meta_pg_recovered_shards_total")
        .is_none_or(|n| n < 0.5)
    {
        assert!(Instant::now() < deadline, "never rebuilt");
        std::thread::sleep(Duration::from_millis(500));
    }

    // Two other OSDs down: it reads only if position 0 is back.
    for i in (0..6).filter(|&i| i != holder).take(2) {
        ha.stop_osd(i);
    }
    let c = &ha.clients[0];
    let got = c.request("GET", "/heal/k", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.bytes, body);
}

/// Which of `ha`'s OSDs holds position `pos` of `bucket/key`'s first
/// stripe, from the object's metadata.
fn holder_of_position(
    ha: &objectio_e2e::ha::HaCluster,
    bucket: &str,
    key: &str,
    pos: u32,
) -> usize {
    use objectio_proto::storage::GetObjectMetaRequest;
    use objectio_proto::storage::storage_service_client::StorageServiceClient;
    let object = tokio::runtime::Runtime::new().unwrap().block_on(async {
        let mut client = StorageServiceClient::new(
            objectio_e2e::tls::channel(&ha.osd_endpoint(0))
                .await
                .expect("connect OSD"),
        );
        client
            .get_object_meta(GetObjectMetaRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: String::new(),
                with_small_shard: false,
            })
            .await
            .expect("GetObjectMeta")
            .into_inner()
            .object
            .expect("a copy on OSD 0")
    });
    let node = &object.stripes[0]
        .shards
        .iter()
        .find(|l| l.position == pos)
        .expect("position placed")
        .node_id;
    let nodes = ha.clients[0].request("GET", "/_admin/nodes", &[]).json();
    let address = nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["node_id"].as_str() == Some(hex::encode(node).as_str()))
        .and_then(|n| n["address"].as_str())
        .expect("holder registered")
        .to_string();
    (0..6)
        .find(|&i| ha.osd_endpoint(i) == address)
        .expect("holder is one of the cluster's OSDs")
}

/// A small PUT (shards with their metadata, B21) refused with two OSDs
/// down, after four copies took it: k copies, enough for a read, none to
/// spare. Soak run 10 found such an object left as it was, and lost it to
/// the next drive lost. It is kept, readable, and brought back to all six
/// shards at once, so it then survives two other OSDs down.
#[test]
fn a_small_write_refused_on_k_copies_is_repaired() {
    use objectio_e2e::ha::HaCluster;
    let mut ha = HaCluster::start_with_meta_args(1, 6, 1, &["--repair-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    assert_eq!(ha.clients[0].request("PUT", "/short", &[]).status, 200);
    ha.stop_osd(4);
    ha.stop_osd(5);
    let body = payload(58_620, 61);
    let put = ha.clients[0].request("PUT", "/short/k", &body);
    assert_ne!(put.status, 200, "acknowledged on four copies of six");
    let got = ha.clients[0].request("GET", "/short/k", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.bytes, body);

    ha.start_osd(4, None);
    ha.start_osd(5, None);
    // Rounds of the degraded worker (every 5 s) and the heal queue (10 s).
    std::thread::sleep(Duration::from_secs(30));
    ha.stop_osd(0);
    ha.stop_osd(1);
    let got = ha.clients[0].request("GET", "/short/k", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.bytes, body);
}

/// A small PUT refused with three OSDs down, after only three copies took
/// it: fewer than a read needs. It is withdrawn from them: a new key reads
/// as never written, an overwritten one as the object it was, never as an
/// error, once the OSDs are back.
#[test]
fn a_small_write_refused_below_k_copies_is_withdrawn() {
    use objectio_e2e::ha::HaCluster;
    let mut ha = HaCluster::start_with_meta_args(1, 6, 1, &["--repair-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/short", &[]).status, 200);
    let old = payload(40_000, 71);
    assert_eq!(c.request("PUT", "/short/old", &old).status, 200);

    ha.stop_osd(3);
    ha.stop_osd(4);
    ha.stop_osd(5);
    let c = &ha.clients[0];
    let put = c.request("PUT", "/short/new", &payload(58_620, 72));
    assert_ne!(put.status, 200, "acknowledged on three copies of six");
    let put = c.request("PUT", "/short/old", &payload(50_000, 73));
    assert_ne!(put.status, 200, "acknowledged on three copies of six");

    ha.start_osd(3, None);
    ha.start_osd(4, None);
    ha.start_osd(5, None);
    // Past the gateway's fail-fast window, and a heal round.
    std::thread::sleep(Duration::from_secs(15));
    let c = &ha.clients[0];
    let got = c.request("GET", "/short/new", &[]);
    assert_eq!(got.status, 404, "{}", got.text());
    let got = c.request("GET", "/short/old", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.bytes, old, "the refused overwrite won");
    let list = c.request("GET", "/short?list-type=2", &[]).text();
    assert!(!list.contains("<Key>new</Key>"), "{list}");
}

/// A lost OSD in a pool with placement groups: a PG keeps its members
/// until the balancer moves it, and a lost one never makes it, so the PG
/// still named the lost OSD (set out, its address taken by the drive that
/// replaced it, then forgotten). Placement handed it out with no address:
/// a gateway that had it cached wrote to the replacement under its name,
/// one started since wrote five shards of six, every new object in the
/// pool a shard short, and repair had nowhere to put the sixth. Placement
/// now stands another OSD in for it, during the evacuation and after.
#[test]
fn a_pg_pool_places_around_a_lost_osd() {
    use objectio_e2e::ha::HaCluster;
    let mut ha = HaCluster::start_with_osd_hosts(1, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    let r = c.json(
        "POST",
        "/_admin/pools",
        json!({"name": "pgp", "ec_type": 0, "ec_k": 4, "ec_m": 2,
            "pg_count": 8, "failure_domain": "host", "enabled": true}),
    );
    assert!(r.status < 300, "pool: {}", r.text());
    let pgs = c
        .request("GET", "/_admin/pools/pgp/placement-groups", &[])
        .json();
    // Pre-allocated: the pool places through its PGs.
    assert!(
        pgs["pgs"].as_array().is_some_and(|p| !p.is_empty()),
        "{pgs}"
    );
    c.request_with_headers("PUT", "/pgpool", &[], &[("x-objectio-pool", "pgp")])
        .expect(200);

    let ids = |c: &Cluster| -> Vec<(String, String)> {
        c.request("GET", "/_admin/nodes", &[]).json()["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| {
                (
                    n["node_id"].as_str().unwrap_or_default().to_string(),
                    n["address"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    };
    let endpoint = ha.osd_endpoint(5);
    let old = ids(c)
        .into_iter()
        .find(|(_, a)| *a == endpoint)
        .map(|(id, _)| id)
        .expect("OSD 5 registered");
    ha.stop_osd(5);
    ha.lose_osd_drive(5);
    ha.start_osd(5, None);
    // A gateway with nothing cached of the lost OSD.
    ha.restart_gateway(0, None);
    let mut bodies: Vec<(String, Vec<u8>)> = Vec::new();
    let put = |c: &Cluster, bodies: &mut Vec<(String, Vec<u8>)>, name: String, seed: u8| {
        let body = payload(300_000, seed);
        let r = c.request("PUT", &format!("/pgpool/{name}"), &body);
        assert_eq!(r.status, 200, "{name}: {}", r.text());
        bodies.push((name, body));
    };
    // While the lost OSD is out and being evacuated...
    let c = &ha.clients[0];
    for i in 0..10u8 {
        put(c, &mut bodies, format!("during-{i}"), i);
    }
    let deadline = Instant::now() + Duration::from_secs(600);
    while ids(&ha.clients[0]).iter().any(|(id, _)| *id == old) {
        assert!(
            Instant::now() < deadline,
            "the lost OSD was never evacuated"
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    // ...and once it is forgotten.
    ha.restart_gateway(0, None);
    let c = &ha.clients[0];
    for i in 0..10u8 {
        put(c, &mut bodies, format!("after-{i}"), 100 + i);
    }
    // Every one on six OSDs: it survives two more down.
    ha.stop_osd(0);
    ha.stop_osd(1);
    let c = &ha.clients[0];
    for (name, body) in &bodies {
        let got = c.request("GET", &format!("/pgpool/{name}"), &[]);
        assert_eq!(got.status, 200, "{name}: {}", got.text());
        assert_eq!(&got.bytes, body, "{name}");
    }
}

/// A disk replaced under the same OSD (the documented replacement, and the
/// soak's disk-pull fault): the OSD forgets the shards the old disk held
/// and tells Meta, whose repair walk starts at once. It used to wait until
/// next due, an hour by default, with every object it held a shard short
/// all that time (and after it, until the walk reached it).
#[test]
fn a_replaced_disk_is_rebuilt_without_waiting_for_the_walk() {
    use objectio_e2e::ha::HaCluster;
    // The walk's default interval: an hour.
    let mut ha = HaCluster::start_with_meta_args(1, 6, 1, &["--repair-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    assert_eq!(c.request("PUT", "/replaced", &[]).status, 200);
    let bodies: Vec<Vec<u8>> = (0..20u8).map(|i| payload(300_000, 60 + i)).collect();
    for (i, b) in bodies.iter().enumerate() {
        assert_eq!(c.request("PUT", &format!("/replaced/k{i}"), b).status, 200);
    }
    let endpoint = ha.osd_endpoint(2);
    let shards_on_2 = |c: &Cluster| -> u64 {
        c.request("GET", "/_admin/nodes", &[]).json()["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["address"].as_str() == Some(endpoint.as_str()))
            .and_then(|n| n["shard_count"].as_u64())
            .unwrap_or(0)
    };

    // The disk pulled and a blank one put in; the OSD's identity and
    // metadata (its state directory) stay.
    ha.stop_osd(2);
    std::fs::remove_file(ha.osd_disk(2)).unwrap();
    ha.start_osd(2, None);

    // Rebuilt in place: one shard of each object on it again.
    let c = &ha.clients[0];
    let deadline = Instant::now() + Duration::from_secs(120);
    while shards_on_2(c) < bodies.len() as u64 {
        assert!(
            Instant::now() < deadline,
            "OSD 2 holds {} shards of {} two minutes after its disk was replaced",
            shards_on_2(c),
            bodies.len()
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    // Two other OSDs down: every object still has four.
    ha.stop_osd(4);
    ha.stop_osd(5);
    let c = &ha.clients[0];
    for (i, b) in bodies.iter().enumerate() {
        let got = c.request("GET", &format!("/replaced/k{i}"), &[]);
        assert_eq!(got.status, 200, "k{i}: {}", got.text());
        assert_eq!(&got.bytes, b, "k{i}");
    }
}
