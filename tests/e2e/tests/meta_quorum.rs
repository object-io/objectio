//! Object metadata at quorum (objectio-docs core/object-metadata-quorum.md):
//! the copies of an object's `ObjectMeta`, one per OSD of its placement.

use std::time::Duration;

use objectio_e2e::ha::HaCluster;

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| i.to_le_bytes()[0].wrapping_mul(31) ^ seed)
        .collect()
}

/// A copy that missed a write never wins a read: with one OSD down, an
/// overwrite reaches the other copies; when the OSD is back with the old
/// copy, every read gives the newer object.
#[test]
fn a_copy_that_missed_a_write_never_wins_a_read() {
    let mut ha = HaCluster::start(1, 6, 2);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    let r = c.request("PUT", "/quorum", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    let old = payload(40_000, 1);
    assert_eq!(c.request("PUT", "/quorum/k", &old).status, 200);

    // Every OSD holds a copy (6 OSDs, 4+2). Stale each in turn, so one of
    // them is the copy a read would ask first.
    for osd in 0..6u8 {
        await_writable(&ha.clients[0]);
        ha.stop_osd(usize::from(osd));
        let new = payload(50_000, 2 + osd);
        let put = ha.clients[0].request("PUT", "/quorum/k", &new);
        // With a copy down the PUT fails, after its shards and the other
        // copies' ObjectMeta are written.
        assert!(
            put.status == 200 || put.text().contains("store object metadata"),
            "OSD {osd} down: the overwrite did not reach the metadata: {}",
            put.text()
        );
        ha.start_osd(usize::from(osd), None);
        // Past the gateways' fail-fast window for the OSD that was down, so
        // the next round has only its own OSD down.
        std::thread::sleep(Duration::from_secs(6));

        for (g, c) in ha.clients.iter().enumerate() {
            let r = c.request("GET", "/quorum/k", &[]);
            assert_eq!(r.status, 200, "OSD {osd} stale, gateway {g}: {}", r.text());
            assert!(
                r.bytes == new,
                "OSD {osd} stale, gateway {g}: the copy that missed the overwrite won"
            );
        }
    }
}

/// Wait until a PUT succeeds: every OSD up and reachable again.
fn await_writable(c: &objectio_e2e::Cluster) {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while c.request("PUT", "/quorum/probe", b"probe").status != 200 {
        assert!(std::time::Instant::now() < deadline, "writes never resumed");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// With one OSD down, PUT and overwrite still succeed (the metadata write
/// quorum, 5 of 6); when it is back, every read gives the newest.
#[test]
fn writes_go_on_with_an_osd_down() {
    let mut ha = HaCluster::start(1, 6, 2);
    let _ = ha.await_leader(Duration::from_secs(30));
    assert_eq!(ha.clients[0].request("PUT", "/quorum", &[]).status, 200);
    await_writable(&ha.clients[0]);

    ha.stop_osd(3);
    let mut latest = Vec::new();
    for i in 0..10u8 {
        let body = payload(20_000 + usize::from(i) * 3_000, i);
        let r = ha.clients[usize::from(i) % 2].request("PUT", "/quorum/w", &body);
        assert_eq!(r.status, 200, "write {i} with an OSD down: {}", r.text());
        let r = ha.clients[0].request("PUT", &format!("/quorum/n{i}"), &body);
        assert_eq!(
            r.status,
            200,
            "new object {i} with an OSD down: {}",
            r.text()
        );
        latest = body;
    }
    for c in &ha.clients {
        assert!(c.request("GET", "/quorum/w", &[]).bytes == latest);
    }

    ha.start_osd(3, None);
    std::thread::sleep(Duration::from_secs(3));
    for (g, c) in ha.clients.iter().enumerate() {
        let r = c.request("GET", "/quorum/w", &[]);
        assert!(
            r.bytes == latest,
            "gateway {g}: not the newest after the OSD returned"
        );
        for i in 0..10u8 {
            let r = c.request("GET", &format!("/quorum/n{i}"), &[]);
            assert_eq!(r.status, 200, "gateway {g}, n{i}: {}", r.text());
        }
    }
}

/// A delete with one OSD down succeeds, and when that OSD returns still
/// holding the object, the object stays deleted: its copy is outvoted by
/// the others' tombstones, on GET and in the listing.
#[test]
fn a_deleted_object_does_not_come_back_with_a_stale_copy() {
    let mut ha = HaCluster::start(1, 6, 2);
    let _ = ha.await_leader(Duration::from_secs(30));
    assert_eq!(ha.clients[0].request("PUT", "/quorum", &[]).status, 200);
    await_writable(&ha.clients[0]);
    for i in 0..6u8 {
        let r = ha.clients[0].request("PUT", &format!("/quorum/d{i}"), &payload(9_000, i));
        assert_eq!(r.status, 200, "{}", r.text());
    }

    // Each object deleted with a different OSD down, so one of them is the
    // copy a read would ask first.
    for i in 0..6u8 {
        ha.stop_osd(usize::from(i));
        let r = ha.clients[usize::from(i) % 2].request("DELETE", &format!("/quorum/d{i}"), &[]);
        assert_eq!(r.status, 204, "delete d{i} with OSD {i} down: {}", r.text());
        ha.start_osd(usize::from(i), None);
        std::thread::sleep(Duration::from_secs(6));
    }
    for (g, c) in ha.clients.iter().enumerate() {
        for i in 0..6u8 {
            let r = c.request("GET", &format!("/quorum/d{i}"), &[]);
            assert_eq!(r.status, 404, "gateway {g}: d{i} came back: {}", r.text());
        }
        let list = c.request("GET", "/quorum?list-type=2&prefix=d", &[]).text();
        assert!(
            !list.contains("<Key>d"),
            "gateway {g}: listed after delete: {list}"
        );
    }
}

/// Healing (core/object-metadata-quorum.md): an overwrite and a delete made
/// with one OSD down leave its copy naming what they replaced; once the OSD
/// is back its copy is brought up to date, and with everything deleted the
/// space is all back (what they replaced was freed on the other OSDs at
/// once, and on this one by the retries or by recovery).
#[test]
fn healing_brings_a_returning_copy_up_to_date_and_frees_space() {
    let mut ha = HaCluster::start(1, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    assert_eq!(ha.clients[0].request("PUT", "/quorum", &[]).status, 200);
    await_writable(&ha.clients[0]);
    assert_eq!(
        ha.clients[0].request("DELETE", "/quorum/probe", &[]).status,
        204
    );
    let empty = ha.clients[0].await_total_used_bytes(0);
    for k in ["a", "d"] {
        let r = ha.clients[0].request("PUT", &format!("/quorum/{k}"), &payload(300_000, 1));
        assert_eq!(r.status, 200, "{}", r.text());
    }

    ha.stop_osd(2);
    let c = &ha.clients[0];
    assert_eq!(
        c.request("PUT", "/quorum/a", &payload(300_000, 2)).status,
        200
    );
    assert_eq!(c.request("DELETE", "/quorum/d", &[]).status, 204);
    ha.start_osd(2, None);
    let c = &ha.clients[0];

    // Both keys healed: every copy agrees again, brought up to date by
    // the keys' placement group (B31 phase 4).
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while !(agree(&ha, "a") && agree(&ha, "d")) {
        assert!(
            std::time::Instant::now() < deadline,
            "never healed: a {:?}, d {:?}",
            copies(&ha, "a"),
            copies(&ha, "d")
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(c.request("GET", "/quorum/a", &[]).bytes == payload(300_000, 2));
    assert_eq!(c.request("GET", "/quorum/d", &[]).status, 404);

    assert_eq!(c.request("DELETE", "/quorum/a", &[]).status, 204);
    let used = c.await_total_used_bytes(empty);
    assert_eq!(
        used, empty,
        "space left behind after healing and deleting everything"
    );
}

/// An overwrite and a delete made with one OSD down free what they
/// replaced at once, rather than when that OSD is brought up to date: it
/// may come back on a new drive, which never held it, so nothing would.
/// Soak run 26 leaked 2.6 GB so, everything deleted or overwritten while
/// a lost drive's replacement was being filled.
#[test]
fn what_an_overwrite_and_a_delete_replace_with_a_drive_lost_is_freed() {
    let mut ha = HaCluster::start(1, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    assert_eq!(ha.clients[0].request("PUT", "/quorum", &[]).status, 200);
    await_writable(&ha.clients[0]);
    assert_eq!(
        ha.clients[0].request("DELETE", "/quorum/probe", &[]).status,
        204
    );
    let empty = ha.clients[0].await_total_used_bytes(0);
    for k in ["a", "d"] {
        let r = ha.clients[0].request("PUT", &format!("/quorum/{k}"), &payload(300_000, 1));
        assert_eq!(r.status, 200, "{}", r.text());
    }
    let ids = node_ids(&ha);

    ha.stop_osd(2);
    let c = &ha.clients[0];
    assert_eq!(
        c.request("PUT", "/quorum/a", &payload(300_000, 2)).status,
        200
    );
    assert_eq!(c.request("DELETE", "/quorum/d", &[]).status, 204);
    ha.lose_osd_drive(2);
    ha.start_osd(2, None);
    let c = &ha.clients[0];

    // The new drive filled and the lost one's entry gone (its last used
    // bytes would count otherwise).
    let deadline = std::time::Instant::now() + Duration::from_secs(180);
    loop {
        let now = node_ids(&ha);
        if agree(&ha, "a") && agree(&ha, "d") && ids.iter().filter(|i| now.contains(i)).count() == 5
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "never recovered: a {:?}, d {:?}, nodes {now:?}",
            copies(&ha, "a"),
            copies(&ha, "d")
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    assert!(c.request("GET", "/quorum/a", &[]).bytes == payload(300_000, 2));

    assert_eq!(c.request("DELETE", "/quorum/a", &[]).status, 204);
    let used = c.await_total_used_bytes(empty);
    assert_eq!(
        used, empty,
        "space left behind by what was replaced while the drive was lost"
    );
}

/// The OSDs' node ids, as `/_admin/nodes` lists them.
fn node_ids(ha: &HaCluster) -> Vec<String> {
    ha.clients[0].request("GET", "/_admin/nodes", &[]).json()["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|n| n["node_id"].as_str().map(str::to_string))
        .collect()
}

/// Each OSD's copy of `quorum/key`: its object id, or None.
fn copies(ha: &HaCluster, key: &str) -> Vec<Option<Vec<u8>>> {
    use objectio_proto::storage::GetObjectMetaRequest;
    use objectio_proto::storage::storage_service_client::StorageServiceClient;
    let rt = tokio::runtime::Runtime::new().unwrap();
    (0..6)
        .map(|i| {
            let address = ha.osd_endpoint(i).trim_start_matches("http://").to_string();
            rt.block_on(async {
                let r = StorageServiceClient::new(objectio_e2e::tls::channel(&address).await.ok()?)
                    .get_object_meta(GetObjectMetaRequest {
                        bucket: "quorum".to_string(),
                        key: key.to_string(),
                        version_id: String::new(),
                        with_small_shard: false,
                    })
                    .await
                    .ok()?
                    .into_inner();
                let found = r.found;
                r.object.filter(|_| found).map(|o| o.object_id)
            })
        })
        .collect()
}

/// Whether every OSD's copy of `quorum/key` is the same: one object, or
/// none (deleted).
fn agree(ha: &HaCluster, key: &str) -> bool {
    let all = copies(ha, key);
    all.windows(2).all(|w| w[0] == w[1])
}

/// A delete refused (503) after it reached some copies, short of the
/// quorum, may still take effect, as S3 allows: those copies hold the
/// newest stamp. It is healed like any write left on some copies: every
/// copy then agrees, so the object can't come back when the copies that
/// took the delete are down, and its space is freed. No heal was queued:
/// the copies disagreed for good and the shards were never freed.
#[test]
fn a_refused_delete_that_reached_some_copies_is_healed() {
    let mut ha = HaCluster::start(1, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    assert_eq!(ha.clients[0].request("PUT", "/quorum", &[]).status, 200);
    await_writable(&ha.clients[0]);
    assert_eq!(
        ha.clients[0].request("DELETE", "/quorum/probe", &[]).status,
        204
    );
    let empty = ha.clients[0].await_total_used_bytes(0);
    let r = ha.clients[0].request("PUT", "/quorum/d", &payload(300_000, 1));
    assert_eq!(r.status, 200, "{}", r.text());

    // Three of six copies down: the delete (after its read, which needs
    // three) reaches three, short of four.
    for i in 3..6 {
        ha.stop_osd(i);
    }
    let r = ha.clients[0].request("DELETE", "/quorum/d", &[]);
    assert_eq!(r.status, 503, "{}", r.text());
    for i in 3..6 {
        ha.start_osd(i, None);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    while !agree(&ha, "d") {
        assert!(
            std::time::Instant::now() < deadline,
            "the refused delete was never healed: {:?}",
            copies(&ha, "d")
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    // The copies that took the delete down: the rest agree with them now.
    for i in 0..3 {
        ha.stop_osd(i);
    }
    let c = &ha.clients[0];
    let r = c.request("GET", "/quorum/d", &[]);
    assert_eq!(r.status, 404, "the deleted object came back: {}", r.status);
    for i in 0..3 {
        ha.start_osd(i, None);
    }
    let c = &ha.clients[0];
    assert_eq!(
        c.await_total_used_bytes(empty),
        empty,
        "its space was never freed"
    );
}

/// Soak run 27's leak, as it ran: a drive lost under load. (What leaked
/// was overwritten while the blank replacement was filled: its copy, which
/// held nothing, disagreed with the others on what the overwrite replaced.) Writes,
/// overwrites and deletes go on while the OSD is down and while its blank
/// replacement is filled; once it is, everything is deleted, and every
/// byte must come back. Each group of keys has its own size, so what is
/// left says which group left it.
#[test]
fn everything_written_around_a_lost_drive_is_freed_when_deleted() {
    let mut ha = HaCluster::start(1, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    assert_eq!(ha.clients[0].request("PUT", "/quorum", &[]).status, 200);
    await_writable(&ha.clients[0]);
    assert_eq!(
        ha.clients[0].request("DELETE", "/quorum/probe", &[]).status,
        204
    );
    let empty = ha.clients[0].await_total_used_bytes(0);
    // Group g's keys are g-<i>, 200 KB + 8 KB × g.
    let size = |g: usize| 200_000 + 8_192 * g;
    let put = |ha: &HaCluster, g: usize, i: usize, seed: u8| {
        let r = ha.clients[0].request("PUT", &format!("/quorum/{g}-{i}"), &payload(size(g), seed));
        assert_eq!(r.status, 200, "PUT {g}-{i}: {}", r.text());
    };
    let delete = |ha: &HaCluster, g: usize, i: usize| {
        let r = ha.clients[0].request("DELETE", &format!("/quorum/{g}-{i}"), &[]);
        assert_eq!(r.status, 204, "DELETE {g}-{i}: {}", r.text());
    };
    // 1: overwritten while down; 2: deleted while down; 3: overwritten
    // while filled; 4: deleted while filled; 5: left alone. 6: written
    // while down; 7: written while filled.
    for g in 1..=5 {
        for i in 0..8 {
            put(&ha, g, i, 1);
        }
    }
    let ids = node_ids(&ha);

    ha.stop_osd(2);
    await_writable(&ha.clients[0]);
    for i in 0..8 {
        put(&ha, 1, i, 2);
        delete(&ha, 2, i);
        put(&ha, 6, i, 1);
    }
    ha.lose_osd_drive(2);
    ha.start_osd(2, None);
    for i in 0..8 {
        put(&ha, 3, i, 2);
        delete(&ha, 4, i);
        put(&ha, 7, i, 1);
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(240);
    loop {
        let now = node_ids(&ha);
        if ids.iter().filter(|i| now.contains(i)).count() == 5 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the lost OSD never evacuated: nodes {now:?}"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    std::thread::sleep(Duration::from_secs(10));

    for g in [1, 3, 5, 6, 7] {
        for i in 0..8 {
            delete(&ha, g, i);
        }
    }
    // What copies disagreed on is checked again after the gateway's
    // restamp settle (2 min).
    let deadline = std::time::Instant::now() + Duration::from_secs(200);
    let used = loop {
        let used = ha.clients[0].await_total_used_bytes(empty);
        if used == empty || std::time::Instant::now() > deadline {
            break used;
        }
    };
    let left = shards(&ha);
    let held: Vec<_> = (0..8).map(|i| copies(&ha, &format!("3-{i}"))).collect();
    assert_eq!(
        used, empty,
        "space left behind; shards by OSD (object, position, size): {left:?}; \
         group 3's copies: {held:?}"
    );
}

/// Every OSD's shards: (object id prefix, position, size).
fn shards(ha: &HaCluster) -> Vec<Vec<(String, u32, u32)>> {
    use objectio_proto::storage::ListShardsRequest;
    use objectio_proto::storage::storage_service_client::StorageServiceClient;
    let rt = tokio::runtime::Runtime::new().unwrap();
    (0..6)
        .map(|i| {
            let address = ha.osd_endpoint(i).trim_start_matches("http://").to_string();
            rt.block_on(async {
                let Ok(channel) = objectio_e2e::tls::channel(&address).await else {
                    return Vec::new();
                };
                let Ok(r) = StorageServiceClient::new(channel)
                    .list_shards(ListShardsRequest {
                        object_id: Vec::new(),
                        limit: 100_000,
                        continuation_token: Vec::new(),
                    })
                    .await
                else {
                    return Vec::new();
                };
                r.into_inner()
                    .shards
                    .into_iter()
                    .filter_map(|s| {
                        let id = s.shard_id?;
                        Some((
                            hex::encode(&id.object_id[..8.min(id.object_id.len())]),
                            id.position,
                            s.size,
                        ))
                    })
                    .collect()
            })
        })
        .collect()
}
