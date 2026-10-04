//! Block volumes and snapshots: gRPC to the block gateway's `BlockService`
//! (`--block-endpoint`), not the management API.

use crate::cli::{SnapshotCmd, VolumeCmd};
use crate::commands::{format_size, parse_size};
use crate::output::{Out, key_values};
use anyhow::{Context, Result};
use objectio_proto::block::{
    AttachVolumeRequest, Attachment, CloneVolumeRequest, CreateSnapshotRequest,
    CreateVolumeRequest, DeleteSnapshotRequest, DeleteVolumeRequest, DetachVolumeRequest,
    GetSnapshotRequest, GetVolumeRequest, ListAttachmentsRequest, ListSnapshotsRequest,
    ListVolumesRequest, ResizeVolumeRequest, Snapshot, TargetType, Volume,
    block_service_client::BlockServiceClient,
};
use serde_json::{Value, json};

pub const fn volume_state(state: i32) -> &'static str {
    match state {
        1 => "Creating",
        2 => "Available",
        3 => "Attached",
        4 => "Error",
        5 => "Deleting",
        _ => "Unknown",
    }
}

pub const fn snapshot_state(state: i32) -> &'static str {
    match state {
        1 => "Creating",
        2 => "Available",
        3 => "Deleting",
        4 => "Error",
        _ => "Unknown",
    }
}

fn volume_json(v: &Volume) -> Value {
    json!({
        "volume_id": v.volume_id,
        "name": v.name,
        "size_bytes": v.size_bytes,
        "used_bytes": v.used_bytes,
        "size": format_size(v.size_bytes),
        "used": format_size(v.used_bytes),
        "pool": v.pool,
        "state": volume_state(v.state),
        "chunk_size_bytes": v.chunk_size_bytes,
        "parent_snapshot_id": v.parent_snapshot_id,
        "created_at": v.created_at,
        "updated_at": v.updated_at,
        "qos": v.qos.as_ref().map(|q| json!({
            "max_iops": q.max_iops,
            "min_iops": q.min_iops,
            "max_bandwidth_bps": q.max_bandwidth_bps,
            "burst_iops": q.burst_iops,
            "burst_seconds": q.burst_seconds,
        })),
    })
}

fn snapshot_json(s: &Snapshot) -> Value {
    json!({
        "snapshot_id": s.snapshot_id,
        "volume_id": s.volume_id,
        "name": s.name,
        "size_bytes": s.size_bytes,
        "unique_bytes": s.unique_bytes,
        "size": format_size(s.size_bytes),
        "unique": format_size(s.unique_bytes),
        "state": snapshot_state(s.state),
        "created_at": s.created_at,
    })
}

const VOLUME_COLUMNS: &[(&str, &str)] = &[
    ("VOLUME ID", "volume_id"),
    ("NAME", "name"),
    ("SIZE", "size"),
    ("USED", "used"),
    ("POOL", "pool"),
    ("STATE", "state"),
];

const SNAPSHOT_COLUMNS: &[(&str, &str)] = &[
    ("SNAPSHOT ID", "snapshot_id"),
    ("NAME", "name"),
    ("SIZE", "size"),
    ("UNIQUE", "unique"),
    ("STATE", "state"),
];

async fn connect(endpoint: &str) -> Result<BlockServiceClient<tonic::transport::Channel>> {
    BlockServiceClient::connect(endpoint.to_string())
        .await
        .with_context(|| format!("connecting to the block gateway at {endpoint}"))
}

#[allow(clippy::needless_pass_by_value)] // shaped for map_err
fn rpc(e: tonic::Status) -> anyhow::Error {
    anyhow::anyhow!("{:?}: {}", e.code(), e.message())
}

#[allow(clippy::significant_drop_tightening)] // the client is used in every arm
pub async fn volume(cmd: VolumeCmd, endpoint: &str, out: &mut Out<'_>) -> Result<()> {
    let mut client = connect(endpoint).await?;
    match cmd {
        VolumeCmd::List { pool } => {
            let resp = client
                .list_volumes(ListVolumesRequest {
                    pool,
                    max_results: 1000,
                    marker: String::new(),
                })
                .await
                .map_err(rpc)?
                .into_inner();
            let rows: Vec<Value> = resp.volumes.iter().map(volume_json).collect();
            out.list(
                &json!({ "volumes": rows }),
                &rows,
                VOLUME_COLUMNS,
                "No volumes.",
            )?;
        }
        VolumeCmd::Create { name, size, pool } => {
            let size_bytes = parse_size(&size)?;
            let vol = client
                .create_volume(CreateVolumeRequest {
                    name,
                    size_bytes,
                    pool,
                    chunk_size_bytes: 0,
                    metadata: std::collections::HashMap::default(),
                    qos: None,
                })
                .await
                .map_err(rpc)?
                .into_inner()
                .volume
                .context("the block gateway returned no volume")?;
            out.emit(&volume_json(&vol), |v| {
                format!("Volume created\n{}", key_values(v))
            })?;
        }
        VolumeCmd::Show { volume_id } => {
            let vol = client
                .get_volume(GetVolumeRequest { volume_id })
                .await
                .map_err(rpc)?
                .into_inner()
                .volume
                .context("the block gateway returned no volume")?;
            out.emit(&volume_json(&vol), key_values)?;
        }
        VolumeCmd::Resize { volume_id, size } => {
            let new_size_bytes = parse_size(&size)?;
            let vol = client
                .resize_volume(ResizeVolumeRequest {
                    volume_id,
                    new_size_bytes,
                })
                .await
                .map_err(rpc)?
                .into_inner()
                .volume
                .context("the block gateway returned no volume")?;
            out.emit(&volume_json(&vol), |v| {
                format!("Volume {} is now {}\n", v["volume_id"], v["size"])
            })?;
        }
        VolumeCmd::Delete { volume_id, force } => {
            client
                .delete_volume(DeleteVolumeRequest {
                    volume_id: volume_id.clone(),
                    force,
                })
                .await
                .map_err(rpc)?;
            out.done(&format!("Deleted volume {volume_id}"))?;
        }
        VolumeCmd::Attach {
            volume_id,
            read_only,
        } => {
            let att = client
                .attach_volume(AttachVolumeRequest {
                    volume_id,
                    target_type: TargetType::Nbd.into(),
                    initiator: String::new(),
                    read_only,
                })
                .await
                .map_err(rpc)?
                .into_inner()
                .attachment
                .context("the block gateway returned no attachment")?;
            out.emit(&attachment_json(&att), key_values)?;
        }
        VolumeCmd::Detach { volume_id, force } => {
            client
                .detach_volume(DetachVolumeRequest {
                    volume_id: volume_id.clone(),
                    force,
                })
                .await
                .map_err(rpc)?;
            out.done(&format!("Detached volume {volume_id}"))?;
        }
        VolumeCmd::Attachments { volume_id } => {
            let resp = client
                .list_attachments(ListAttachmentsRequest { volume_id })
                .await
                .map_err(rpc)?
                .into_inner();
            let rows: Vec<Value> = resp.attachments.iter().map(attachment_json).collect();
            out.list(
                &json!({ "attachments": rows }),
                &rows,
                &[
                    ("VOLUME", "volume_id"),
                    ("TARGET", "target"),
                    ("READ-ONLY", "read_only"),
                ],
                "No attachments",
            )?;
        }
    }
    Ok(())
}

fn attachment_json(a: &Attachment) -> Value {
    json!({
        "volume_id": a.volume_id,
        "target": a.target_address,
        "read_only": a.read_only,
        "attached_at": a.attached_at,
    })
}

#[allow(clippy::significant_drop_tightening)] // the client is used in every arm
pub async fn snapshot(cmd: SnapshotCmd, endpoint: &str, out: &mut Out<'_>) -> Result<()> {
    let mut client = connect(endpoint).await?;
    match cmd {
        SnapshotCmd::List { volume_id } => {
            let resp = client
                .list_snapshots(ListSnapshotsRequest {
                    volume_id,
                    max_results: 1000,
                    marker: String::new(),
                })
                .await
                .map_err(rpc)?
                .into_inner();
            let rows: Vec<Value> = resp.snapshots.iter().map(snapshot_json).collect();
            out.list(
                &json!({ "snapshots": rows }),
                &rows,
                SNAPSHOT_COLUMNS,
                "No snapshots.",
            )?;
        }
        SnapshotCmd::Create { volume_id, name } => {
            let snap = client
                .create_snapshot(CreateSnapshotRequest {
                    volume_id,
                    name,
                    metadata: std::collections::HashMap::default(),
                })
                .await
                .map_err(rpc)?
                .into_inner()
                .snapshot
                .context("the block gateway returned no snapshot")?;
            out.emit(&snapshot_json(&snap), |v| {
                format!("Snapshot created\n{}", key_values(v))
            })?;
        }
        SnapshotCmd::Show { snapshot_id } => {
            let snap = client
                .get_snapshot(GetSnapshotRequest { snapshot_id })
                .await
                .map_err(rpc)?
                .into_inner()
                .snapshot
                .context("the block gateway returned no snapshot")?;
            out.emit(&snapshot_json(&snap), key_values)?;
        }
        SnapshotCmd::Delete { snapshot_id } => {
            client
                .delete_snapshot(DeleteSnapshotRequest {
                    snapshot_id: snapshot_id.clone(),
                })
                .await
                .map_err(rpc)?;
            out.done(&format!("Deleted snapshot {snapshot_id}"))?;
        }
        SnapshotCmd::Clone { snapshot_id, name } => {
            let vol = client
                .clone_volume(CloneVolumeRequest {
                    snapshot_id,
                    name,
                    metadata: std::collections::HashMap::default(),
                })
                .await
                .map_err(rpc)?
                .into_inner()
                .volume
                .context("the block gateway returned no volume")?;
            out.emit(&volume_json(&vol), |v| {
                format!("Volume cloned\n{}", key_values(v))
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_state_codes_do_not_panic() {
        for state in [-1, 0, 99, i32::MAX, i32::MIN] {
            assert_eq!(volume_state(state), "Unknown");
            assert_eq!(snapshot_state(state), "Unknown");
        }
        assert_eq!(volume_state(3), "Attached");
        assert_eq!(snapshot_state(2), "Available");
    }

    #[test]
    fn a_volume_renders_with_human_sizes() {
        let v = volume_json(&Volume {
            volume_id: "v1".into(),
            name: "data".into(),
            size_bytes: 20 << 30,
            state: 2,
            ..Volume::default()
        });
        let t = crate::output::table(&[v], VOLUME_COLUMNS);
        assert!(t.contains("20 GiB"), "{t}");
        assert!(t.contains("Available"), "{t}");
    }
}
