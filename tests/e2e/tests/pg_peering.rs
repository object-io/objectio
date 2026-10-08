//! Peering (B31 phase 2, objectio-docs `core/pg-recovery.md`): each
//! placement group's members compared, and its state and what each member
//! lacks recorded. The exit test: in each scenario the computed states and
//! counts match what the objects actually lack, checked against every
//! OSD's copies directly.
//!
//! Repair and the gateways' heal are off in the first two, so nothing
//! changes what the OSDs hold while peering looks at it.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use objectio_e2e::ha::HaCluster;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::metadata::{GetPlacementRequest, ObjectMeta};
use objectio_proto::storage::GetObjectMetaRequest;
use objectio_proto::storage::storage_service_client::StorageServiceClient;
use serde_json::{Value, json};

const OSDS: usize = 6;

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

fn host_port(endpoint: &str) -> String {
    endpoint.trim_start_matches("http://").to_string()
}

/// `bucket/key`'s placement group and its acting set (hex node ids).
fn pg_of(
    rt: &tokio::runtime::Runtime,
    ha: &HaCluster,
    bucket: &str,
    key: &str,
) -> (u32, Vec<String>) {
    let meta = ha.meta_endpoints();
    objectio_e2e::tls::client();
    rt.block_on(async {
        let p = MetadataServiceClient::new(
            objectio_proto::transport::meta_channel(&meta)
                .await
                .unwrap(),
        )
        .get_placement(GetPlacementRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            size: 0,
            storage_class: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
        (
            p.pg_id,
            p.nodes.iter().map(|n| hex::encode(&n.node_id)).collect(),
        )
    })
}

/// The `ObjectMeta` copy OSD `i` holds of `bucket/key`, if any.
fn copy_on(
    rt: &tokio::runtime::Runtime,
    ha: &HaCluster,
    i: usize,
    bucket: &str,
    key: &str,
) -> Option<ObjectMeta> {
    let address = host_port(&ha.osd_endpoint(i));
    rt.block_on(async {
        let r = StorageServiceClient::new(objectio_e2e::tls::channel(&address).await.ok()?)
            .get_object_meta(GetObjectMetaRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: String::new(),
                with_small_shard: false,
            })
            .await
            .ok()?
            .into_inner();
        let found = r.found;
        r.object.filter(|_| found)
    })
}

/// Every OSD's node id (hex), by index.
fn node_ids(ha: &HaCluster) -> Vec<String> {
    let nodes = ha.clients[0].request("GET", "/_admin/nodes", &[]).json();
    (0..OSDS)
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

/// Peering often, every PG in one look.
fn peer_often(ha: &HaCluster) {
    let c = &ha.clients[0];
    for (key, v) in [("pg/peer_every_seconds", 2), ("pg/peer_per_look", 1000)] {
        let r = c.json("PUT", &format!("/_admin/config/{key}"), json!(v));
        assert!(r.status < 300, "{key}: {}", r.text());
    }
}

/// The default pool's placement groups, with their states, by id.
fn pgs(ha: &HaCluster) -> HashMap<u32, Value> {
    let v = ha.clients[0]
        .request("GET", "/_admin/pools/default/placement-groups", &[])
        .json();
    v["pgs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pg| {
            (
                u32::try_from(pg["pg_id"].as_u64().unwrap()).unwrap(),
                pg.clone(),
            )
        })
        .collect()
}

/// Unix seconds now.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Wait until every PG (those in `ids` among them) has a state computed at
/// `since` or later, for its current epoch; then every PG.
fn peered_since(ha: &HaCluster, ids: &[u32], since: u64) -> HashMap<u32, Value> {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let all = pgs(ha);
        let stale: Vec<u32> = all
            .iter()
            .filter(|(_, pg)| {
                !(pg["state"]["computed_at"]
                    .as_u64()
                    .is_some_and(|t| t >= since)
                    && pg["state"]["epoch"] == pg["epoch"])
            })
            .map(|(id, _)| *id)
            .collect();
        if stale.is_empty() && ids.iter().all(|id| all.contains_key(id)) {
            return all;
        }
        assert!(
            Instant::now() < deadline,
            "{} PGs not peered since {since}, e.g. {:?}",
            stale.len(),
            stale
                .iter()
                .take(3)
                .map(|id| (&all[id]["epoch"], &all[id]["state"]))
                .collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// What the keys actually lack, by PG: (objects degraded, copies missing,
/// copies stale, shards short), from every acting member's copy.
fn truth(
    rt: &tokio::runtime::Runtime,
    ha: &HaCluster,
    ids: &[String],
    bucket: &str,
    keys: &[String],
) -> BTreeMap<u32, (u64, u64, u64, u64)> {
    let mut out: BTreeMap<u32, (u64, u64, u64, u64)> = BTreeMap::new();
    for key in keys {
        let (pg, acting) = pg_of(rt, ha, bucket, key);
        let copies: Vec<Option<ObjectMeta>> = acting
            .iter()
            .map(|id| {
                let i = ids
                    .iter()
                    .position(|x| x == id)
                    .expect("acting member is an OSD");
                copy_on(rt, ha, i, bucket, key)
            })
            .collect();
        let newest = copies
            .iter()
            .flatten()
            .max_by(|a, b| a.write_order().cmp(&b.write_order()))
            .unwrap_or_else(|| panic!("{key}: no copy"))
            .clone();
        let missing = copies.iter().filter(|c| c.is_none()).count() as u64;
        let stale = copies
            .iter()
            .flatten()
            .filter(|c| c.write_order() < newest.write_order())
            .count() as u64;
        let short: u64 = newest
            .stripes
            .iter()
            .map(|s| u64::from(s.ec_k + s.ec_m) - s.shards.len() as u64)
            .sum();
        let e = out.entry(pg).or_default();
        e.0 += u64::from(missing + stale + short > 0);
        e.1 += missing;
        e.2 += stale;
        e.3 += short;
    }
    out
}

/// Every PG `truth` names has the state and counts it says; the other PGs
/// the keys don't touch are clean.
fn assert_matches(all: &HashMap<u32, Value>, truth: &BTreeMap<u32, (u64, u64, u64, u64)>) {
    for (pg, (degraded, missing, stale, short)) in truth {
        let st = &all[pg]["state"];
        let want = if *degraded > 0 { "Degraded" } else { "Clean" };
        assert_eq!(st["state"], want, "pg {pg}: {st}");
        assert_eq!(
            st["objects_degraded"].as_u64(),
            Some(*degraded),
            "pg {pg}: {st}"
        );
        assert_eq!(
            st["copies_missing"].as_u64(),
            Some(*missing),
            "pg {pg}: {st}"
        );
        assert_eq!(st["copies_stale"].as_u64(), Some(*stale), "pg {pg}: {st}");
        assert_eq!(st["shards_missing"].as_u64(), Some(*short), "pg {pg}: {st}");
        assert_eq!(st["objects_unfound"].as_u64(), Some(0), "pg {pg}: {st}");
    }
    for (id, pg) in all {
        if !truth.contains_key(id) {
            assert_eq!(pg["state"]["state"], "Clean", "pg {id}: {}", pg["state"]);
        }
    }
}

fn cluster() -> HaCluster {
    let mut ha = HaCluster::start(1, OSDS, 1);
    // Nothing heals metadata copies behind peering's back.
    ha.restart_gateway_with_args(0, &["--heal-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    peer_often(&ha);
    ha
}

/// An OSD down for a while, with writes meanwhile: while it is down its PGs
/// are degraded with a member down; once it is back each PG counts the
/// copies it missed, and the positions those writes left without a shard,
/// exactly as its copies show them.
#[test]
fn peering_counts_what_an_osd_missed_while_down() {
    let mut ha = cluster();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let c = &ha.clients[0];
    c.request("PUT", "/peer", &[]).expect(200);
    let before: Vec<String> = (0..8).map(|i| format!("before-{i}")).collect();
    for (i, k) in before.iter().enumerate() {
        c.request(
            "PUT",
            &format!("/peer/{k}"),
            &payload(300_000, u8::try_from(i).unwrap()),
        )
        .expect(200);
    }
    let ids = node_ids(&ha);
    let pg_ids: Vec<u32> = before
        .iter()
        .map(|k| pg_of(&rt, &ha, "peer", k).0)
        .collect();
    let all = peered_since(&ha, &pg_ids, now());
    assert_matches(&all, &truth(&rt, &ha, &ids, "peer", &before));

    ha.stop_osd(5);
    let c = &ha.clients[0];
    let during: Vec<String> = (0..12).map(|i| format!("during-{i}")).collect();
    for (i, k) in during.iter().enumerate() {
        let r = c.request(
            "PUT",
            &format!("/peer/{k}"),
            &payload(300_000, 50 + u8::try_from(i).unwrap()),
        );
        assert_eq!(r.status, 200, "{k}: {}", r.text());
    }
    let during_pgs: Vec<u32> = during
        .iter()
        .map(|k| pg_of(&rt, &ha, "peer", k).0)
        .collect();
    let down = peered_since(&ha, &during_pgs, now() + 1);
    for pg in &during_pgs {
        let st = &down[pg]["state"];
        assert_eq!(st["state"], "Degraded", "pg {pg} with a member down: {st}");
        assert_eq!(st["members_down"].as_u64(), Some(1), "pg {pg}: {st}");
    }

    ha.start_osd(5, None);
    let mut keys = before;
    keys.extend(during.iter().cloned());
    let mut touched: Vec<u32> = pg_ids;
    touched.extend(during_pgs.iter().copied());
    let all = peered_since(&ha, &touched, now() + 1);
    let truth = truth(&rt, &ha, &ids, "peer", &keys);
    assert!(
        truth.values().map(|t| t.1).sum::<u64>() >= during.len() as u64,
        "the OSD that was down should lack every write made meanwhile: {truth:?}"
    );
    assert_matches(&all, &truth);
}

/// Overwrites while an OSD is down leave it holding the objects they
/// replaced: once it is back each PG counts those stale copies, exactly as
/// the copies show them.
#[test]
fn peering_counts_the_stale_copies_overwrites_left() {
    let mut ha = cluster();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let c = &ha.clients[0];
    c.request("PUT", "/stale", &[]).expect(200);
    let keys: Vec<String> = (0..10).map(|i| format!("k{i}")).collect();
    for (i, k) in keys.iter().enumerate() {
        c.request(
            "PUT",
            &format!("/stale/{k}"),
            &payload(300_000, u8::try_from(i).unwrap()),
        )
        .expect(200);
    }
    let ids = node_ids(&ha);
    ha.stop_osd(2);
    let c = &ha.clients[0];
    for (i, k) in keys.iter().enumerate().take(6) {
        let r = c.request(
            "PUT",
            &format!("/stale/{k}"),
            &payload(300_000, 100 + u8::try_from(i).unwrap()),
        );
        assert_eq!(r.status, 200, "{k}: {}", r.text());
    }
    ha.start_osd(2, None);
    let pg_ids: Vec<u32> = keys.iter().map(|k| pg_of(&rt, &ha, "stale", k).0).collect();
    let all = peered_since(&ha, &pg_ids, now() + 1);
    let truth = truth(&rt, &ha, &ids, "stale", &keys);
    assert_eq!(
        truth.values().map(|t| t.2).sum::<u64>(),
        6,
        "OSD 2 should hold the six objects overwritten while it was down: {truth:?}"
    );
    assert_matches(&all, &truth);
    // The member that holds them is named.
    let stale_on: u64 = all
        .values()
        .flat_map(|pg| {
            pg["state"]["members"]
                .as_array()
                .cloned()
                .unwrap_or_default()
        })
        .filter(|m| m["node_id"].as_str() == Some(ids[2].as_str()))
        .map(|m| m["copies_stale"].as_u64().unwrap_or(0))
        .sum();
    assert_eq!(stale_on, 6);
}

/// A drive lost for good: its PGs get a stand-in, which holds none of
/// their shards, so they are degraded with shards missing; once the
/// evacuation has moved them, every PG is clean and every object reads.
#[test]
fn a_lost_drives_pgs_are_degraded_until_evacuated_then_clean() {
    let mut ha =
        HaCluster::start_with_meta_args(1, OSDS + 1, 1, &["--repair-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    peer_often(&ha);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let c = &ha.clients[0];
    c.request("PUT", "/lost", &[]).expect(200);
    let keys: Vec<String> = (0..16).map(|i| format!("k{i}")).collect();
    let bodies: Vec<Vec<u8>> = (0..16).map(|i| payload(300_000, i)).collect();
    for (k, b) in keys.iter().zip(&bodies) {
        c.request("PUT", &format!("/lost/{k}"), b).expect(200);
    }
    let nodes = c.request("GET", "/_admin/nodes", &[]).json();
    let endpoint = ha.osd_endpoint(5);
    let old = nodes["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["address"].as_str() == Some(endpoint.as_str()))
        .and_then(|n| n["node_id"].as_str())
        .unwrap()
        .to_string();
    let held: Vec<u32> = keys
        .iter()
        .filter_map(|k| {
            let (pg, acting) = pg_of(&rt, &ha, "lost", k);
            acting.contains(&old).then_some(pg)
        })
        .collect();
    assert!(!held.is_empty(), "no key on the OSD to lose");

    ha.stop_osd(5);
    ha.lose_osd_drive(5);
    ha.start_osd(5, None);
    let c = &ha.clients[0];

    // Degraded at some point, with something missing, before it is clean.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut seen_degraded = false;
    loop {
        let all = pgs(&ha);
        let states: Vec<&Value> = held.iter().map(|id| &all[id]["state"]).collect();
        if states.iter().any(|st| {
            st["state"] != "Clean"
                && (st["shards_missing"].as_u64().unwrap_or(0) > 0
                    || st["copies_missing"].as_u64().unwrap_or(0) > 0
                    || st["members_down"].as_u64().unwrap_or(0) > 0)
        }) {
            seen_degraded = true;
        }
        let gone = !c.request("GET", "/_admin/nodes", &[]).text().contains(&old);
        if seen_degraded && gone {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "seen degraded: {seen_degraded}; lost OSD gone: {gone}; states: {states:?}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }

    // Evacuated: clean, once peered after it.
    let since = now() + 1;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let all = peered_since(&ha, &held, since);
        if held.iter().all(|id| all[id]["state"]["state"] == "Clean") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "not clean after the evacuation: {:?}",
            held.iter().map(|id| &all[id]["state"]).collect::<Vec<_>>()
        );
        std::thread::sleep(Duration::from_secs(1));
    }
    for (k, b) in keys.iter().zip(&bodies) {
        let got = c.request("GET", &format!("/lost/{k}"), &[]);
        assert_eq!(got.status, 200, "{k}: {}", got.text());
        assert_eq!(&got.bytes, b, "{k}");
    }
}
