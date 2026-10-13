//! Recovery of every protection scheme (B31 phase 3b, objectio-docs
//! `core/pg-recovery.md`, B10): a replicated pool's lost copies are copied
//! back from an intact one; an LRC pool's lost shard is rebuilt from its
//! local group, inside the group's rack, and from the whole stripe only
//! when the group can't. A multipart upload's parts are placed in its
//! object's placement group, so completing it copies nothing. A
//! versioned key's older versions are recovered as its current object is.
//!
//! Repair's walk is off (an hour) in all of them: what is rebuilt, recovery
//! rebuilt.

use std::collections::HashMap;
use std::fmt::Write as _;
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

fn config(ha: &HaCluster, key: &str, value: Value) {
    let r = ha.clients[0].json("PUT", &format!("/_admin/config/{key}"), value);
    assert!(r.status < 300, "{key}: {}", r.text());
}

/// Peering and recovery looking often.
fn eager(ha: &HaCluster) {
    let _ = ha.await_leader(Duration::from_secs(30));
    config(ha, "pg/peer_every_seconds", json!(2));
    config(ha, "pg/peer_per_look", json!(1000));
}

fn pool_and_bucket(ha: &HaCluster, pool: Value, bucket: &str) {
    let c = &ha.clients[0];
    let name = pool["name"].as_str().unwrap().to_string();
    let r = c.json("POST", "/_admin/pools", pool);
    assert!(r.status < 300, "pool: {}", r.text());
    c.request_with_headers(
        "PUT",
        &format!("/{bucket}"),
        &[],
        &[("x-objectio-pool", &name)],
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

/// Lose OSD `i`'s drive for good (it comes back empty, as a new OSD), and
/// wait until the lost one is let go: its PGs filled from the others.
fn lose_drives(ha: &mut HaCluster, lost: &[usize], ids: &[String]) {
    for &i in lost {
        ha.stop_osd(i);
        ha.lose_osd_drive(i);
    }
    for &i in lost {
        ha.start_osd(i, None);
    }
    let deadline = Instant::now() + Duration::from_secs(240);
    loop {
        let nodes = ha.clients[0].request("GET", "/_admin/nodes", &[]).text();
        if lost.iter().all(|&i| !nodes.contains(&ids[i])) {
            return;
        }
        assert!(Instant::now() < deadline, "a lost OSD was never let go");
        std::thread::sleep(Duration::from_millis(300));
    }
}

fn write(ha: &HaCluster, bucket: &str, count: u8) -> Vec<(String, Vec<u8>)> {
    (0..count)
        .map(|i| {
            let key = format!("k{i}");
            let len = if i % 3 == 0 { 20_000 } else { 300_000 };
            let body = payload(len, i);
            let r = ha.clients[0].request("PUT", &format!("/{bucket}/{key}"), &body);
            assert_eq!(r.status, 200, "{key}: {}", r.text());
            (key, body)
        })
        .collect()
}

fn all_read(ha: &HaCluster, bucket: &str, bodies: &[(String, Vec<u8>)]) {
    for (k, b) in bodies {
        let got = ha.clients[0].request("GET", &format!("/{bucket}/{k}"), &[]);
        assert_eq!(got.status, 200, "{k}: {}", got.text());
        assert_eq!(&got.bytes, b, "{k}");
    }
}

fn metric(ha: &HaCluster, name: &str) -> f64 {
    ha.meta_metric(name).unwrap_or(0.0)
}

/// A 3-way replicated pool of one placement group: one member's drive
/// lost for good, every object's copy copied back from an intact one onto
/// the OSD standing in (its metadata and its stripe), the PG clean; then
/// an original member down, and every object read from the two copies left.
/// (Two down leaves one copy, short of the metadata read quorum of two:
/// refused, as Ceph's `min_size` 2 refuses.)
#[test]
fn a_replicated_pools_lost_copies_are_copied_back() {
    let mut ha = HaCluster::start_with_meta_args(1, 7, 1, &["--repair-interval-secs", "3600"]);
    eager(&ha);
    pool_and_bucket(
        &ha,
        json!({"name": "rep3", "ec_type": 2, "replication_count": 3, "pg_count": 1,
            "failure_domain": "osd", "enabled": true}),
        "copies",
    );
    let bodies = write(&ha, "copies", 24);
    let ids = node_ids(&ha, 7);
    let acting = |ha: &HaCluster| -> Vec<String> {
        pgs(ha, "rep3")[&0]["acting"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m.as_str().unwrap().to_string())
            .collect()
    };
    let before = acting(&ha);
    let lost = ids.iter().position(|id| *id == before[0]).unwrap();

    lose_drives(&mut ha, &[lost], &ids);
    await_clean(&ha, "rep3", 180);
    assert!(
        metric(&ha, "objectio_meta_pg_replica_copies_total") >= count(&bodies),
        "recovery copied {} replicas for {} objects",
        metric(&ha, "objectio_meta_pg_replica_copies_total"),
        bodies.len()
    );

    // The OSD standing in holds every object's metadata.
    let ids = node_ids(&ha, 7);
    let after = acting(&ha);
    let stand_in = after
        .iter()
        .find(|m| !before.contains(m))
        .expect("an OSD stood in for the lost one");
    let at = ids.iter().position(|id| id == stand_in).unwrap();
    for (k, _) in &bodies {
        assert!(
            osd_has_meta(&ha.osd_endpoint(at), "copies", k),
            "{k}: not on the stand-in"
        );
    }

    // An original member down: two copies, the stand-in's one of them.
    let other = ids.iter().position(|id| *id == before[1]).unwrap();
    ha.stop_osd(other);
    all_read(&ha, "copies", &bodies);
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

/// LRC 4+2+1, one placement group, each local group in a rack of its own
/// (positions 0, 1 and their local parity 4 in one rack; 2, 3 and 5 in
/// another; the global parity 6 in a third). `which`: the positions whose
/// OSDs are lost.
fn lrc(which: &[usize]) -> (HaCluster, Vec<(String, Vec<u8>)>) {
    let racks = ["A", "A", "A", "A", "B", "B", "B", "B", "C", "C"];
    let mut ha = HaCluster::start_with_racks(1, &racks, 1, &["--repair-interval-secs", "3600"]);
    eager(&ha);
    pool_and_bucket(
        &ha,
        json!({"name": "lrc", "ec_type": 1, "ec_k": 4, "ec_m": 3, "ec_local_parity": 2,
            "ec_global_parity": 1, "failure_domain": "rack", "lrc_groups_per_domain": true,
            "pg_count": 1, "enabled": true}),
        "lrc",
    );
    let bodies: Vec<(String, Vec<u8>)> = (0..12u8)
        .map(|i| {
            let key = format!("k{i}");
            let body = payload(300_000, 60 + i);
            let r = ha.clients[0].request("PUT", &format!("/lrc/{key}"), &body);
            assert_eq!(r.status, 200, "{key}: {}", r.text());
            (key, body)
        })
        .collect();
    let ids = node_ids(&ha, racks.len());
    let acting: Vec<String> = pgs(&ha, "lrc")[&0]["acting"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap().to_string())
        .collect();
    let lost: Vec<usize> = which
        .iter()
        .map(|&p| ids.iter().position(|id| *id == acting[p]).unwrap())
        .collect();
    lose_drives(&mut ha, &lost, &ids);
    await_clean(&ha, "lrc", 180);
    (ha, bodies)
}

/// One data shard's OSD lost: every object's shard is rebuilt from the
/// other data shard of its group and the group's local parity, reads that
/// stay inside the group's rack; nothing is rebuilt from the whole stripe.
#[test]
fn an_lrc_shard_is_rebuilt_from_its_local_group() {
    let (ha, bodies) = lrc(&[1]);
    let local = metric(&ha, "objectio_meta_pg_lrc_rebuilds_total{kind=\"local\"}");
    let global = metric(&ha, "objectio_meta_pg_lrc_rebuilds_total{kind=\"global\"}");
    let local_reads = metric(
        &ha,
        "objectio_meta_pg_lrc_shards_read_total{kind=\"local\"}",
    );
    assert!(
        local >= count(&bodies),
        "{local} local rebuilds for {} objects",
        bodies.len()
    );
    assert!(global < 0.5, "{global} rebuilds went to the whole stripe");
    // Each read its group's two other members: the data shard beside it
    // and the local parity, both in its rack.
    assert!(
        2.0f64.mul_add(-local, local_reads).abs() < 0.5,
        "{local_reads} reads for {local} rebuilds: reads outside the group"
    );
    all_read(&ha, "lrc", &bodies);
}

/// A data shard and its group's local parity lost together: the group
/// can't rebuild either, so both come from the whole stripe (the data
/// decoded with the global parity, the local parity encoded again), and
/// every object reads.
#[test]
fn an_lrc_group_short_of_two_is_rebuilt_from_the_whole_stripe() {
    let (ha, bodies) = lrc(&[0, 4]);
    let global = metric(&ha, "objectio_meta_pg_lrc_rebuilds_total{kind=\"global\"}");
    assert!(
        global >= 2.0 * count(&bodies),
        "{global} whole-stripe rebuilds for {} objects, two shards each",
        bodies.len()
    );
    all_read(&ha, "lrc", &bodies);
}

/// A multipart upload's parts land in the object's placement group, on
/// the acting member at each position: the completed object is already
/// where recovery wants it, so recovery writes no shard for it (parts
/// placed by a key of their own landed in other PGs, and recovery copied
/// every one into the object's).
#[test]
fn a_multipart_objects_parts_are_already_in_its_placement_group() {
    let ha = HaCluster::start_with_meta_args(1, 7, 1, &["--repair-interval-secs", "3600"]);
    eager(&ha);
    let c = &ha.clients[0];
    c.request("PUT", "/mpu", &[]).expect(200);
    // Settled before: nothing for recovery to do.
    await_clean(&ha, "default", 60);
    let shards_before = metric(&ha, "objectio_meta_pg_recovered_shards_total");

    let r = c.request("POST", "/mpu/big?uploads", &[]);
    assert!(r.status < 300, "initiate: {}", r.text());
    let text = r.text();
    let upload = text
        .split("<UploadId>")
        .nth(1)
        .and_then(|t| t.split("</UploadId>").next())
        .expect("an upload id")
        .to_string();
    let parts: Vec<Vec<u8>> = (0..3u8)
        .map(|i| payload(if i < 2 { 5 * 1024 * 1024 } else { 700_000 }, 80 + i))
        .collect();
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, body) in parts.iter().enumerate() {
        let n = i + 1;
        let r = c.request(
            "PUT",
            &format!("/mpu/big?partNumber={n}&uploadId={upload}"),
            body,
        );
        assert_eq!(r.status, 200, "part {n}: {}", r.text());
        let etag = r.header("etag").unwrap_or_else(|| format!("\"part{n}\""));
        let _ = write!(
            xml,
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        );
    }
    xml.push_str("</CompleteMultipartUpload>");
    let r = c.request(
        "POST",
        &format!("/mpu/big?uploadId={upload}"),
        xml.as_bytes(),
    );
    assert_eq!(r.status, 200, "complete: {}", r.text());

    // Peered (every PG looked at, more than once) and clean.
    std::thread::sleep(Duration::from_secs(8));
    await_clean(&ha, "default", 60);
    let shards_after = metric(&ha, "objectio_meta_pg_recovered_shards_total");
    assert!(
        (shards_after - shards_before).abs() < 0.5,
        "recovery wrote {} shards for the completed object",
        shards_after - shards_before
    );
    let got = c.request("GET", "/mpu/big", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.bytes, parts.concat());
}

/// How many objects, as the metrics count them.
fn count(bodies: &[(String, Vec<u8>)]) -> f64 {
    f64::from(u32::try_from(bodies.len()).unwrap())
}

/// A versioned bucket in a pool of one placement group: three versions of
/// each key, then a member's drive lost for good. Every version, not only
/// the current, is rebuilt on the OSD standing in, so with two of the
/// original members down every version still reads back by its id.
/// (Recovering the current objects alone, the older versions are left with
/// three of the four shards a read needs.)
#[test]
fn every_version_is_recovered_not_only_the_current() {
    let mut ha = HaCluster::start_with_meta_args(1, 7, 1, &["--repair-interval-secs", "3600"]);
    eager(&ha);
    pool_and_bucket(
        &ha,
        json!({"name": "one", "ec_type": 0, "ec_k": 4, "ec_m": 2, "pg_count": 1,
            "failure_domain": "osd", "enabled": true}),
        "vers",
    );
    let c = &ha.clients[0];
    c.request(
        "PUT",
        "/vers?versioning",
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    )
    .expect(200);
    let mut versions: Vec<(String, String, Vec<u8>)> = Vec::new();
    for k in 0..4u8 {
        for n in 0..3u8 {
            let key = format!("k{k}");
            let body = payload(if n == 1 { 20_000 } else { 300_000 }, k * 10 + n);
            let r = c.request("PUT", &format!("/vers/{key}"), &body);
            assert_eq!(r.status, 200, "{key}: {}", r.text());
            let id = r.header("x-amz-version-id").expect("a version id");
            versions.push((key, id, body));
        }
    }
    let ids = node_ids(&ha, 7);
    let acting: Vec<String> = pgs(&ha, "one")[&0]["acting"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m.as_str().unwrap().to_string())
        .collect();
    let lost = ids.iter().position(|id| *id == acting[0]).unwrap();

    lose_drives(&mut ha, &[lost], &ids);
    await_clean(&ha, "one", 180);

    // Two original members down: four shards left of every version, the
    // stand-in's among them.
    let ids = node_ids(&ha, 7);
    for m in &acting[1..3] {
        let i = ids.iter().position(|id| id == m).unwrap();
        ha.stop_osd(i);
    }
    for (key, id, body) in &versions {
        let got = ha.clients[0].request("GET", &format!("/vers/{key}?versionId={id}"), &[]);
        assert_eq!(got.status, 200, "{key} version {id}: {}", got.text());
        assert_eq!(&got.bytes, body, "{key} version {id}");
    }
}
