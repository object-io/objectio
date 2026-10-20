//! A request that needs more writes than one meta command carries, or one
//! that could never apply, fails alone or is split: meta goes on. Such a
//! command used to reach the Raft log and fail as every node applied it,
//! which stopped Raft on all of them at once; each restart stopped again at
//! the same entry.

use std::time::{Duration, Instant};

use objectio_e2e::ha::HaCluster;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::metadata::{
    IcebergCommitTableChange, IcebergCommitTransactionRequest, ShareStripesRequest,
};
use serde_json::json;

/// More than one meta command carries ([`objectio_common::META_MAX_OPS`]).
const TOO_MANY: usize = objectio_common::META_MAX_OPS + 44;

/// Every meta node still runs, says it is healthy, and applies what the
/// leader commits.
fn assert_every_meta_up(ha: &HaCluster, when: &str) {
    let leader = ha.await_leader(Duration::from_secs(20));
    let applied = ha.status(leader).expect("leader answers").last_applied;
    for i in 0..ha.meta_count() {
        assert!(!ha.meta_exited(i), "{when}: meta {i} exited");
        assert_eq!(ha.meta_health(i), Some(200), "{when}: meta {i}'s health");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let s = ha.status(i).expect("meta answers");
            assert_eq!(s.fatal, None, "{when}: meta {i}'s Raft stopped");
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
fn requests_too_big_for_one_command_leave_every_meta_up() {
    let ha = HaCluster::start(3, 6, 1);
    ha.await_default_pool();
    let c = &ha.clients[0];

    // A user with more access keys than one command carries, deleted:
    // the keys go in several commands, the user last.
    let user = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "many-keys"}),
    );
    user.expect_ok();
    let user_id = user.json()["user_id"].as_str().unwrap().to_string();
    let mut keys = Vec::new();
    for _ in 0..TOO_MANY {
        let k = c.json(
            "POST",
            &format!("/_admin/users/{user_id}/access-keys"),
            json!({}),
        );
        k.expect_ok();
        let k = k.json();
        keys.push((
            k["access_key_id"].as_str().unwrap().to_string(),
            k["secret_access_key"].as_str().unwrap().to_string(),
        ));
    }
    let r = c.request("DELETE", &format!("/_admin/users/{user_id}"), &[]);
    assert!(r.status < 300, "delete user: {} {}", r.status, r.text());
    assert_every_meta_up(&ha, "after deleting a user of many keys");
    let users = c.request("GET", "/_admin/users", &[]).text();
    assert!(!users.contains(&user_id), "the user is still listed");
    for (ak, sk) in [&keys[0], &keys[TOO_MANY - 1]] {
        let r = c.request_as("GET", "/", &[], ak, sk);
        assert_eq!(r.status, 403, "a deleted user's key {ak} still signs");
        assert!(r.text().contains("inactive"), "{}", r.text());
    }

    // An Iceberg transaction of more tables than one command carries: the
    // gateway refuses it.
    let changes: Vec<_> = (0..TOO_MANY)
        .map(|i| {
            json!({
                "identifier": {"namespace": ["ns"], "name": format!("t{i}")},
                "requirements": [],
                "updates": [],
            })
        })
        .collect();
    let r = c.json(
        "POST",
        "/iceberg/v1/transactions/commit",
        json!({"table-changes": changes}),
    );
    assert_eq!(r.status, 400, "{}", r.text());

    // Straight to meta, as a client of another release could send them:
    // refused before they are proposed.
    let rt = tokio::runtime::Runtime::new().unwrap();
    objectio_e2e::tls::client();
    rt.block_on(async {
        let mut meta = MetadataServiceClient::new(
            objectio_proto::transport::meta_channel(&ha.meta_endpoints())
                .await
                .unwrap(),
        );
        let ids = (0..TOO_MANY)
            .map(|i| {
                let mut id = vec![0xAB; 16];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                id
            })
            .collect();
        let e = meta
            .share_stripes(ShareStripesRequest {
                stripe_ids: ids,
                owner: vec![1; 16],
                sharer: vec![2; 16],
            })
            .await
            .expect_err("sharing that many stripes in one call");
        assert_eq!(e.code(), tonic::Code::FailedPrecondition, "{e}");

        let table_changes = (0..TOO_MANY)
            .map(|i| IcebergCommitTableChange {
                namespace_levels: vec!["ns".into()],
                table_name: format!("t{i}"),
                current_metadata_location: "s3://w/old".into(),
                new_metadata_location: "s3://w/new".into(),
                new_metadata_json: b"{}".to_vec(),
            })
            .collect();
        let e = meta
            .iceberg_commit_transaction(IcebergCommitTransactionRequest {
                warehouse: String::new(),
                table_changes,
            })
            .await
            .expect_err("a transaction of that many tables");
        drop(meta);
        assert_eq!(e.code(), tonic::Code::InvalidArgument, "{e}");
    });
    assert_every_meta_up(&ha, "after the refused requests");

    // And writes go on.
    c.json("POST", "/_admin/buckets", json!({"name": "after"}))
        .expect_ok();
    c.request("PUT", "/after/k", b"still here").expect(200);
    assert_eq!(c.request("GET", "/after/k", &[]).bytes, b"still here");
}
