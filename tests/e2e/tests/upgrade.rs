//! Rolling upgrades, phase 1 (objectio-docs core/upgrade-path.md): every
//! node reports its release and format level, a new cluster starts at this
//! release's level, and meta refuses a client older than the cluster.

use std::time::{Duration, Instant};

use objectio_common::version::{FORMAT_LEVEL, RELEASE};
use objectio_e2e::ha::HaCluster;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::metadata::{DeleteConfigRequest, GetUpgradeStatusRequest, SetConfigRequest};
use serde_json::Value;

/// `GET /_admin/upgrade`, once it lists `metas` metas, `osds` OSDs and
/// `gateways` gateways.
fn status_with_everyone(ha: &HaCluster, metas: usize, osds: usize, gateways: usize) -> Value {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let r = ha.clients[0].request("GET", "/_admin/upgrade", &[]);
        if r.status == 200 {
            let v = r.json();
            let count = |kind: &str| {
                v["nodes"]
                    .as_array()
                    .map_or(0, |n| n.iter().filter(|n| n["kind"] == kind).count())
            };
            if count("meta") == metas && count("osd") == osds && count("gateway") == gateways {
                return v;
            }
        }
        assert!(
            Instant::now() < deadline,
            "not every node reported: {}",
            r.text()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// A meta client sending `user_agent`, as an older release would.
fn meta_client_as(
    rt: &tokio::runtime::Runtime,
    endpoint: &str,
    user_agent: &str,
) -> MetadataServiceClient<tonic::transport::Channel> {
    rt.block_on(async {
        objectio_e2e::tls::client();
        let channel = objectio_proto::transport::endpoint(endpoint)
            .unwrap()
            .user_agent(user_agent)
            .unwrap()
            .connect()
            .await
            .unwrap();
        MetadataServiceClient::new(channel)
    })
}

#[test]
fn a_new_cluster_starts_at_this_releases_level_and_every_node_reports() {
    let ha = HaCluster::start(3, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    let v = status_with_everyone(&ha, 3, 6, 1);

    assert_eq!(v["active_level"], FORMAT_LEVEL, "{v}");
    assert_eq!(v["blockers"], serde_json::json!([]), "{v}");
    assert_eq!(v["can_finalize"], false, "nothing to finalize: {v}");
    for n in v["nodes"].as_array().unwrap() {
        assert_eq!(n["release"], RELEASE, "{n}");
        assert_eq!(n["format_level"], FORMAT_LEVEL, "{n}");
    }

    // Finalizing with nothing to do changes nothing.
    let r = ha.clients[0].request("POST", "/_admin/upgrade/finalize", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["active_level"], FORMAT_LEVEL);
}

/// After finalize, a node from an older release would misread what the
/// others write: meta refuses its calls, at whichever node it reaches.
#[test]
fn a_client_older_than_the_cluster_is_refused() {
    let ha = HaCluster::start(3, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    status_with_everyone(&ha, 3, 6, 1); // the cluster has its level
    let rt = tokio::runtime::Runtime::new().unwrap();

    for endpoint in ha.meta_endpoints().split(',') {
        // A release from before levels sends tonic's user-agent alone.
        let mut old = meta_client_as(&rt, endpoint, "objectio-old");
        let err = rt
            .block_on(old.get_upgrade_status(GetUpgradeStatusRequest {}))
            .unwrap_err();
        drop(old);
        assert_eq!(
            err.code(),
            tonic::Code::FailedPrecondition,
            "{endpoint}: {err}"
        );

        let mut current = meta_client_as(&rt, endpoint, &objectio_common::version::user_agent());
        rt.block_on(current.get_upgrade_status(GetUpgradeStatusRequest {}))
            .unwrap_or_else(|e| panic!("{endpoint} refused a current client: {e}"));
        drop(current);
    }
}

/// Only finalize raises the active level: the generic config API can't set
/// it, or delete it.
#[test]
fn the_active_level_is_not_ordinary_config() {
    let ha = HaCluster::start(3, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    status_with_everyone(&ha, 3, 6, 1);
    let rt = tokio::runtime::Runtime::new().unwrap();
    let endpoint = ha.meta_endpoints().split(',').next().unwrap().to_string();
    let mut meta = meta_client_as(&rt, &endpoint, &objectio_common::version::user_agent());

    let err = rt
        .block_on(meta.set_config(SetConfigRequest {
            key: objectio_common::version::ACTIVE_LEVEL_KEY.to_string(),
            value: b"99".to_vec(),
            updated_by: "test".into(),
        }))
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err}");
    let err = rt
        .block_on(meta.delete_config(DeleteConfigRequest {
            key: objectio_common::version::ACTIVE_LEVEL_KEY.to_string(),
        }))
        .unwrap_err();
    drop(meta);
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err}");
    let v = ha.clients[0].request("GET", "/_admin/upgrade", &[]).json();
    assert_eq!(v["active_level"], FORMAT_LEVEL, "{v}");
}
