//! Metadata copies and meta's listing index brought to agree by placement
//! group peering and recovery alone (B31 phase 4): what the gateways' heal
//! queue did for keys in placement groups. A heal request for such a key
//! marks its PG instead of queuing it, and the gateway's heal pass is off
//! here (`--heal-interval-secs 3600`), so nothing else could do it.
//!
//! Each case leaves one copy behind (its OSD down while the key changes)
//! or one listing entry wrong, and waits for it to come right.

use std::time::{Duration, Instant};

use objectio_e2e::ha::HaCluster;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::metadata::{
    CreateObjectRequest, DeleteObjectRequest, HealEnqueueRequest, HealListRequest, ObjectMeta,
};
use objectio_proto::storage::GetObjectMetaRequest;
use objectio_proto::storage::storage_service_client::StorageServiceClient;
use serde_json::json;

const WITHIN: Duration = Duration::from_secs(120);

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

/// A cluster of one meta, six OSDs and a gateway whose heal pass is off,
/// peering often, and the bucket `conv`.
fn cluster() -> HaCluster {
    let mut ha = HaCluster::start(1, 6, 1);
    ha.restart_gateway_with_args(0, &["--heal-interval-secs", "3600"]);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    for (key, v) in [
        ("pg/peer_every_seconds", 2),
        ("pg/peer_per_look", 1000),
        ("pg/listing_grace_seconds", 0),
    ] {
        let r = c.json("PUT", &format!("/_admin/config/{key}"), json!(v));
        assert!(r.status < 300, "{key}: {}", r.text());
    }
    assert_eq!(c.request("PUT", "/conv", &[]).status, 200);
    ha
}

/// The `ObjectMeta` copy OSD `i` holds of `conv/key`, if any.
fn copy_on(
    rt: &tokio::runtime::Runtime,
    ha: &HaCluster,
    i: usize,
    key: &str,
) -> Option<ObjectMeta> {
    let address = ha.osd_endpoint(i).trim_start_matches("http://").to_string();
    rt.block_on(async {
        let r = StorageServiceClient::new(objectio_e2e::tls::channel(&address).await.ok()?)
            .get_object_meta(GetObjectMetaRequest {
                bucket: "conv".to_string(),
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

fn meta(
    rt: &tokio::runtime::Runtime,
    ha: &HaCluster,
) -> MetadataServiceClient<tonic::transport::Channel> {
    objectio_e2e::tls::client();
    let endpoints = ha.meta_endpoints();
    rt.block_on(async {
        MetadataServiceClient::new(
            objectio_proto::transport::meta_channel(&endpoints)
                .await
                .unwrap(),
        )
    })
}

/// Wait until `ok` holds, or fail saying `what`.
fn until(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + WITHIN;
    while !ok() {
        assert!(Instant::now() < deadline, "{what}: not within {WITHIN:?}");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Nothing went into the heal queue: every heal request was a PG's mark.
fn queue_empty(rt: &tokio::runtime::Runtime, ha: &HaCluster) {
    let entries = rt
        .block_on(meta(rt, ha).heal_list(HealListRequest { limit: 100 }))
        .unwrap()
        .into_inner()
        .entries;
    assert!(entries.is_empty(), "heal queue: {entries:?}");
}

/// A copy that missed an overwrite (its OSD down) is given the new object.
#[test]
fn a_copy_that_missed_an_overwrite_is_brought_up_to_date_by_its_pg() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut ha = cluster();
    let c = &ha.clients[0];
    c.request("PUT", "/conv/k", &payload(300_000, 1))
        .expect(200);
    ha.stop_osd(1);
    let c = &ha.clients[0];
    let newer = payload(300_000, 2);
    let put = c.request("PUT", "/conv/k", &newer);
    put.expect(200);
    let etag = put.header("etag").unwrap().trim_matches('"').to_string();
    assert_ne!(
        copy_on(&rt, &ha, 0, "k").map(|o| o.etag),
        None,
        "the other copies hold it"
    );
    ha.start_osd(1, None);
    until("OSD 1's copy is the overwrite", || {
        copy_on(&rt, &ha, 1, "k").is_some_and(|o| o.etag.trim_matches('"') == etag)
    });
    queue_empty(&rt, &ha);
    // And the object reads with two other OSDs down.
    ha.stop_osd(4);
    ha.stop_osd(5);
    let got = ha.clients[0].request("GET", "/conv/k", &[]);
    assert_eq!(got.status, 200, "{}", got.text());
    assert_eq!(got.bytes, newer);
}

/// A copy that missed a delete (its OSD down) lets the object go.
#[test]
fn a_copy_that_missed_a_delete_lets_it_go_by_its_pg() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut ha = cluster();
    let c = &ha.clients[0];
    c.request("PUT", "/conv/d", &payload(300_000, 3))
        .expect(200);
    ha.stop_osd(1);
    assert_eq!(ha.clients[0].request("DELETE", "/conv/d", &[]).status, 204);
    ha.start_osd(1, None);
    assert!(copy_on(&rt, &ha, 1, "d").is_some(), "OSD 1 still holds it");
    until("OSD 1 lets the deleted object go", || {
        copy_on(&rt, &ha, 1, "d").is_none()
    });
    queue_empty(&rt, &ha);
    assert_eq!(ha.clients[0].request("GET", "/conv/d", &[]).status, 404);
}

/// A copy that missed a change to the object's metadata (its tags, its OSD
/// down) is given it.
#[test]
fn a_copy_that_missed_a_metadata_update_is_given_it_by_its_pg() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut ha = cluster();
    let c = &ha.clients[0];
    c.request("PUT", "/conv/t", &payload(300_000, 4))
        .expect(200);
    ha.stop_osd(1);
    let tagging =
        "<Tagging><TagSet><Tag><Key>team</Key><Value>blue</Value></Tag></TagSet></Tagging>";
    let r = ha.clients[0].request("PUT", "/conv/t?tagging", tagging.as_bytes());
    assert_eq!(r.status, 200, "{}", r.text());
    ha.start_osd(1, None);
    assert!(
        copy_on(&rt, &ha, 1, "t").is_some_and(|o| o.tags.is_empty()),
        "OSD 1 holds the object without the tag"
    );
    until("OSD 1's copy has the tag", || {
        copy_on(&rt, &ha, 1, "t")
            .is_some_and(|o| o.tags.get("team").map(String::as_str) == Some("blue"))
    });
    queue_empty(&rt, &ha);
}

/// Meta's listing index follows what the copies hold: an entry lost while
/// the object is there is put back, and one left for a key deleted is
/// removed, once the key's PG is marked (as a heal request does).
#[test]
fn the_listing_follows_what_the_copies_hold() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let ha = cluster();
    let c = &ha.clients[0];
    c.request("PUT", "/conv/listed", &payload(100_000, 5))
        .expect(200);
    c.request("PUT", "/conv/gone", &payload(100_000, 6))
        .expect(200);
    assert_eq!(c.request("DELETE", "/conv/gone", &[]).status, 204);
    let listed = |key: &str| {
        c.request("GET", "/conv?list-type=2", &[])
            .text()
            .contains(&format!("<Key>{key}</Key>"))
    };
    let mut m = meta(&rt, &ha);
    // `listed` loses its entry; `gone` gets one, of an object nobody holds.
    rt.block_on(m.delete_object(DeleteObjectRequest {
        bucket: "conv".to_string(),
        key: "listed".to_string(),
        version_id: String::new(),
    }))
    .unwrap();
    rt.block_on(m.create_object(CreateObjectRequest {
        bucket: "conv".to_string(),
        key: "gone".to_string(),
        size: 1,
        object_id: vec![7; 16],
        ..Default::default()
    }))
    .unwrap();
    assert!(!listed("listed") && listed("gone"), "the listing is wrong");
    for key in ["listed", "gone"] {
        rt.block_on(m.heal_enqueue(HealEnqueueRequest {
            bucket: "conv".to_string(),
            key: key.to_string(),
            version_id: String::new(),
        }))
        .unwrap();
    }
    drop(m);
    until("listed again", || listed("listed"));
    until("unlisted", || !listed("gone"));
    queue_empty(&rt, &ha);
}

/// Three of six OSDs gone (4+2): every PG is Down. It says why, and nothing
/// retries it in a loop: recovery leaves a Down PG alone, a scrub skips
/// members known down, and their counters stay flat while it lasts.
#[test]
fn a_pg_down_says_why_and_nothing_loops() {
    let mut ha = cluster();
    let c = &ha.clients[0];
    for i in 0..8u8 {
        c.request("PUT", &format!("/conv/o{i}"), &payload(100_000, 10 + i))
            .expect(200);
    }
    // Scrubs due at once, so they run while the PGs are down.
    let r = c.json("PUT", "/_admin/config/scrub/every_seconds", json!(1));
    assert!(r.status < 300, "{}", r.text());
    ha.stop_osd(3);
    ha.stop_osd(4);
    ha.stop_osd(5);
    let down = "objectio_meta_pgs{state=\"Down\"}";
    until("PGs Down", || ha.meta_metric(down).unwrap_or(0.0) > 0.0);

    let pgs = ha.clients[0]
        .request("GET", "/_admin/pools/default/placement-groups", &[])
        .json();
    let why = pgs["pgs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["state"]["state"] == "Down")
        .and_then(|p| p["state"]["last_error"].as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        why.contains("3 of 6 members answered") && why.contains("a read needs 4"),
        "{why}"
    );

    let counters = |ha: &HaCluster| {
        (
            ha.meta_metric("objectio_meta_pg_recovery_retries_total")
                .unwrap_or(0.0),
            ha.meta_metric("objectio_meta_scrub_errors_total")
                .unwrap_or(0.0),
        )
    };
    // Settled (the liveness checks have the OSDs down, backoffs grown):
    // from then on, a few retries at most, not one a second.
    std::thread::sleep(Duration::from_secs(60));
    let before = counters(&ha);
    std::thread::sleep(Duration::from_secs(30));
    let after = counters(&ha);
    assert!(
        after.0 - before.0 <= 3.0 && after.1 - before.1 <= 3.0,
        "retries {before:?} -> {after:?} in 30 s"
    );
    // Still Down, saying why: nothing pretended otherwise meanwhile.
    assert!(ha.meta_metric(down).unwrap_or(0.0) > 0.0);
}
