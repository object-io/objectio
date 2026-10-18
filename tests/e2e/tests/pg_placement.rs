//! Placement through placement groups whose acting set and epoch are
//! committed before any write uses them, and OSDs that refuse a request
//! placed under an older epoch (B31 phase 1, objectio-docs
//! `core/pg-recovery.md`).
//!
//! Soak run 14 found what this prevents: an overwrite during a disk pull
//! was placed per request around the OSD that was out, on five OSDs no
//! record named; the key's recorded home and the sixth OSD kept the older
//! object, and the evacuation, building its moves from the home, looped
//! for hours.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::metadata::{GetPlacementRequest, GetPlacementResponse, ObjectMeta};
use objectio_proto::storage::GetObjectMetaRequest;
use objectio_proto::storage::storage_service_client::StorageServiceClient;
use serde_json::json;

const OSDS: usize = 7;

/// Keys written in a test.
const KEYS: u8 = 16;

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

/// Meta's placement for `bucket/key`.
fn placement(
    rt: &tokio::runtime::Runtime,
    ha: &HaCluster,
    bucket: &str,
    key: &str,
) -> GetPlacementResponse {
    let meta = ha.meta_endpoints();
    objectio_e2e::tls::client();
    rt.block_on(async {
        // With this build's format level: meta refuses a client without.
        let channel = objectio_proto::transport::meta_channel(&meta)
            .await
            .unwrap();
        MetadataServiceClient::new(channel)
            .get_placement(GetPlacementRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                size: 0,
                storage_class: String::new(),
            })
            .await
            .unwrap()
            .into_inner()
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

/// Set OSD `id` out.
fn set_out(c: &Cluster, id: &str) {
    c.json(
        "PUT",
        &format!("/_admin/osds/{id}/admin-state"),
        json!({ "state": "out" }),
    )
    .expect_ok();
}

/// Wait until no placement group of the default pool has `id` acting.
fn await_stood_in(c: &Cluster, id: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let pgs = c
            .request("GET", "/_admin/pools/default/placement-groups", &[])
            .json();
        let holding = pgs["pgs"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|pg| {
                pg["acting"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|m| m.as_str() == Some(id))
            })
            .count();
        if holding == 0 {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{holding} placement groups still have {id} acting"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// `bucket/key`'s current object is on its placement group's acting set and
/// nowhere else, its shards on members of it: the copies are where the
/// record says they are. Returns the acting set.
fn assert_on_acting_set(
    rt: &tokio::runtime::Runtime,
    ha: &HaCluster,
    ids: &[String],
    bucket: &str,
    key: &str,
    body: &[u8],
) -> BTreeSet<String> {
    let got = ha.clients[0].request("GET", &format!("/{bucket}/{key}"), &[]);
    assert_eq!(got.status, 200, "{key}: {}", got.text());
    assert_eq!(got.bytes, body, "{key}");

    let p = placement(rt, ha, bucket, key);
    assert!(p.pg_epoch > 0, "{key}: placed without a placement group");
    let acting: BTreeSet<String> = p.nodes.iter().map(|n| hex::encode(&n.node_id)).collect();
    let copies: Vec<(String, ObjectMeta)> = (0..OSDS)
        .filter_map(|i| copy_on(rt, ha, i, bucket, key).map(|o| (ids[i].clone(), o)))
        .collect();
    let newest = copies
        .iter()
        .map(|(_, o)| o)
        .max_by(|a, b| a.write_order().cmp(&b.write_order()))
        .unwrap_or_else(|| panic!("{key}: no copy anywhere"))
        .clone();
    let holders: BTreeSet<String> = copies
        .iter()
        .filter(|(_, o)| o.object_id == newest.object_id)
        .map(|(id, _)| id.clone())
        .collect();
    assert_eq!(
        holders, acting,
        "{key}: the current object's copies are not its placement group's acting set (epoch {})",
        p.pg_epoch
    );
    for stripe in &newest.stripes {
        for shard in &stripe.shards {
            let at = hex::encode(&shard.node_id);
            assert!(
                acting.contains(&at),
                "{key}: shard {} on {at}, outside the acting set {acting:?}",
                shard.position
            );
        }
    }
    acting
}

/// An overwrite while an OSD is out goes to the acting set committed for
/// it (the leader's stand-in), and only there: no copy of the new object
/// on the OSD that is out, every acting member with one, its shards on
/// members. Before, placement stood in per request and recorded nothing.
#[test]
fn an_overwrite_while_an_osd_is_out_lands_on_the_committed_acting_set() {
    let ha = HaCluster::start(1, OSDS, 1);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let c = &ha.clients[0];
    c.request("PUT", "/pgs", &[]).expect(200);
    for i in 0..KEYS {
        let r = c.request("PUT", &format!("/pgs/k{i}"), &payload(300_000, i));
        assert_eq!(r.status, 200, "k{i}: {}", r.text());
    }
    let ids = node_ids(&ha);

    let out = ids[0].clone();
    set_out(c, &out);
    await_stood_in(c, &out);

    for i in 0..KEYS {
        let body = payload(300_000, 100 + i);
        let r = c.request("PUT", &format!("/pgs/k{i}"), &body);
        assert_eq!(r.status, 200, "k{i} overwrite: {}", r.text());
        let acting = assert_on_acting_set(&rt, &ha, &ids, "pgs", &format!("k{i}"), &body);
        assert!(
            !acting.contains(&out),
            "k{i}: the OSD that is out is still acting"
        );
    }
}

/// A PUT placed under an epoch that changes before it writes is refused by
/// the OSDs, which know the new epoch, and placed again: the client gets a
/// 200, and the object is on the new acting set.
#[test]
fn a_write_placed_under_an_old_epoch_is_refused_and_placed_again() {
    let ha = HaCluster::start(1, OSDS, 1);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let c = &ha.clients[0];
    c.request("PUT", "/pgs", &[]).expect(200);
    c.request("PUT", "/pgs/k", &payload(300_000, 1)).expect(200);
    let ids = node_ids(&ha);

    let before = placement(&rt, &ha, "pgs", "k");
    let member = hex::encode(&before.nodes[0].node_id);
    let body = payload(300_000, 2);
    let held = c.json(
        "POST",
        "/_admin/test/hold-placed",
        json!({ "bucket": "pgs", "key": "k", "millis": 8000 }),
    );
    assert!(held.status < 300, "hold: {}", held.text());

    let put = std::thread::scope(|s| {
        let writer = s.spawn(|| c.request("PUT", "/pgs/k", &body));
        // Placed, then held: the acting set changes under it.
        std::thread::sleep(Duration::from_secs(1));
        set_out(c, &member);
        let deadline = Instant::now() + Duration::from_secs(6);
        while placement(&rt, &ha, "pgs", "k").pg_epoch <= before.pg_epoch {
            assert!(
                Instant::now() < deadline,
                "no stand-in committed for {member}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        writer.join().unwrap()
    });
    assert_eq!(put.status, 200, "{}", put.text());

    let acting = assert_on_acting_set(&rt, &ha, &ids, "pgs", "k", &body);
    assert!(!acting.contains(&member));
    let placed_again: u64 = c
        .request("GET", "/metrics", &[])
        .text()
        .lines()
        .filter(|l| l.starts_with("objectio_gateway_stale_placement_total"))
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum();
    assert!(placed_again >= 1, "the PUT was not placed again");
}
