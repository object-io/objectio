//! gRPC BlockService implementation
//!
//! Volumes, snapshots and clones are meta's (see `meta_blocks`); the
//! volume manager here mirrors meta's volume records for the I/O path.

use std::sync::Arc;

use objectio_block::volume::VolumeState;
use objectio_block::{VolumeManager, WriteCache};
use objectio_proto::block::block_service_server::BlockService;
use objectio_proto::block::{
    AttachVolumeRequest, AttachVolumeResponse, Attachment, CloneVolumeRequest, CloneVolumeResponse,
    CreateSnapshotRequest, CreateSnapshotResponse, CreateVolumeRequest, CreateVolumeResponse,
    DeleteSnapshotRequest, DeleteSnapshotResponse, DeleteVolumeRequest, DeleteVolumeResponse,
    DetachVolumeRequest, DetachVolumeResponse, FlushRequest, FlushResponse,
    GetClusterMetricsRequest, GetClusterMetricsResponse, GetIoTraceRequest, GetIoTraceResponse,
    GetOsdMetricsRequest, GetOsdMetricsResponse, GetSnapshotRequest, GetSnapshotResponse,
    GetVolumeRequest, GetVolumeResponse, GetVolumeStatsRequest, GetVolumeStatsResponse,
    ListAttachmentsRequest, ListAttachmentsResponse, ListOsdMetricsRequest, ListOsdMetricsResponse,
    ListSnapshotsRequest, ListSnapshotsResponse, ListVolumesRequest, ListVolumesResponse,
    ReadRequest, ReadResponse, ResizeVolumeRequest, ResizeVolumeResponse, TargetType, TrimRequest,
    TrimResponse, UpdateVolumeQosRequest, UpdateVolumeQosResponse, Volume as ProtoVolume,
    VolumeState as ProtoVolumeState, VolumeStats, WriteRequest, WriteResponse,
};
use objectio_proto::metadata::{
    BlockCloneVolumeRequest, BlockCreateSnapshotRequest, BlockCreateVolumeRequest,
    BlockDeleteSnapshotRequest, BlockDeleteVolumeRequest, BlockGetSnapshotRequest,
    BlockGetVolumeRequest, BlockListSnapshotsRequest, BlockListVolumesRequest,
    BlockUpdateVolumeRequest, StripeMeta,
};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::ec_io::free_stripes;
use crate::flush::{flush_volume_all, flush_volume_all_locked};
use crate::meta_blocks::MetaBlocks;
use crate::metrics::{Io, Protocol};
use crate::nbd::NbdServer;
use crate::osd_pool::OsdPool;

// ── Shared state ──────────────────────────────────────────────────────────────

pub struct BlockGatewayState {
    pub meta: Arc<MetaBlocks>,
    pub osd_pool: Arc<OsdPool>,
    pub cache: Arc<WriteCache>,
    pub volume_manager: Arc<VolumeManager>,
    pub nbd_server: Arc<NbdServer>,
    /// Loads the stored bytes of chunks with pending writes; serves reads.
    pub resolver: Arc<crate::resolve::Resolver>,
    pub advertise_host: String,
    pub nbd_port: u16,
    pub ec_k: u32,
    pub ec_m: u32,
    /// Held while chunks are flushed (see `flush`), and while a snapshot is
    /// taken or a volume deleted, so neither races a flush.
    pub flush_lock: tokio::sync::Mutex<()>,
}

impl BlockGatewayState {
    /// Make the local copy of a volume match meta's record of it.
    pub fn mirror(&self, v: &ProtoVolume) {
        let _ = self.volume_manager.delete_volume(&v.volume_id, true);
        if let Err(e) = self.volume_manager.restore_volume(from_proto(v)) {
            warn!("volume {}: cannot mirror meta's record: {e}", v.volume_id);
        }
        self.cache.init_volume_sized(&v.volume_id, chunk_size_of(v));
    }

    /// Delete the shards of stripes meta says nothing uses any more.
    async fn free(&self, what: &str, reason: &str, stripes: &[StripeMeta]) {
        let failed = free_stripes(&self.meta, &self.osd_pool, stripes).await;
        crate::metrics::stripes_freed(reason, stripes.len(), failed);
        if failed > 0 {
            warn!("{what}: {failed} shard deletes failed; that space leaks");
        }
        if !stripes.is_empty() {
            info!("{what}: freed {} chunks", stripes.len());
        }
    }

    /// Record a volume's new state in meta, then here.
    async fn set_state(&self, volume_id: &str, state: ProtoVolumeState) -> Result<(), Status> {
        let v = self
            .meta
            .client()
            .await
            .block_update_volume(BlockUpdateVolumeRequest {
                volume_id: volume_id.to_string(),
                size_bytes: 0,
                state: state.into(),
            })
            .await?
            .into_inner()
            .volume
            .ok_or_else(|| Status::internal("meta returned no volume"))?;
        self.mirror(&v);
        Ok(())
    }
}

// ── Service ───────────────────────────────────────────────────────────────────

pub struct BlockGatewayService {
    state: Arc<BlockGatewayState>,
}

impl BlockGatewayService {
    /// Refuse I/O past the end of the volume: it would create chunks the
    /// volume does not own.
    fn check_bounds(&self, volume_id: &str, offset: u64, len: u64) -> Result<(), Status> {
        let vol = self
            .state
            .volume_manager
            .get_volume(volume_id)
            .map_err(|e| Status::not_found(e.to_string()))?;
        if offset
            .checked_add(len)
            .is_none_or(|end| end > vol.size_bytes)
        {
            return Err(Status::out_of_range(format!(
                "{len} bytes at {offset} run past the end of the {}-byte volume",
                vol.size_bytes
            )));
        }
        Ok(())
    }

    pub fn new(state: Arc<BlockGatewayState>) -> Self {
        Self { state }
    }
}

// ── Conversions ───────────────────────────────────────────────────────────────

/// Meta's record of a volume, as the volume manager holds it.
pub fn from_proto(v: &ProtoVolume) -> objectio_block::volume::Volume {
    objectio_block::volume::Volume {
        volume_id: v.volume_id.clone(),
        name: v.name.clone(),
        size_bytes: v.size_bytes,
        used_bytes: v.used_bytes,
        pool: v.pool.clone(),
        state: VolumeState::from(v.state),
        created_at: v.created_at,
        updated_at: v.updated_at,
        parent_snapshot_id: Some(v.parent_snapshot_id.clone()).filter(|s| !s.is_empty()),
        chunk_size: u64::from(v.chunk_size_bytes),
        metadata: v.metadata.clone(),
    }
}

/// Bytes the OSD allocates a shard in. A shard smaller than this is padded
/// to it, so a chunk smaller than k of them wastes capacity.
const OSD_BLOCK: u64 = 64 * 1024;
/// Largest chunk size: the erasure-coding stripe objects use.
const MAX_CHUNK: u64 = 4 * 1024 * 1024;
/// Smallest chunk size offered.
const MIN_CHUNK: u64 = 256 * 1024;

/// The chunk size a new volume gets: `requested` (0: the 4 MiB default),
/// if it is a power of two from 256 KiB to 4 MiB, and at least `ec_k`
/// OSD blocks so its shards fill whole blocks. Smaller chunks rewrite less
/// per small random write (a 4 KiB write rewrites its whole chunk's
/// stripe), at the cost of more chunk records per volume.
fn valid_chunk_size(requested: u32, ec_k: u32) -> Result<u64, String> {
    let size = if requested == 0 {
        MAX_CHUNK
    } else {
        u64::from(requested)
    };
    let min = MIN_CHUNK.max(u64::from(ec_k) * OSD_BLOCK);
    if !size.is_power_of_two() || size < min || size > MAX_CHUNK {
        return Err(format!(
            "chunk size must be a power of two from {min} to {MAX_CHUNK} bytes \
             (at least {ec_k} OSD blocks of {OSD_BLOCK}, or its shards are padded); got {size}"
        ));
    }
    Ok(size)
}

/// A volume's chunk size as meta records it (0 on volumes from before it
/// was recorded: the 4 MiB default).
pub fn chunk_size_of(v: &ProtoVolume) -> u64 {
    if v.chunk_size_bytes == 0 {
        MAX_CHUNK
    } else {
        u64::from(v.chunk_size_bytes)
    }
}

fn block_err_to_status(e: objectio_block::error::BlockError) -> Status {
    use objectio_block::error::BlockError;
    match e {
        BlockError::VolumeNotFound(id) => Status::not_found(format!("volume not found: {id}")),
        BlockError::SnapshotNotFound(id) => Status::not_found(format!("snapshot not found: {id}")),
        BlockError::VolumeExists(name) => {
            Status::already_exists(format!("volume already exists: {name}"))
        }
        BlockError::VolumeAttached(id) => {
            Status::failed_precondition(format!("volume attached: {id}"))
        }
        BlockError::VolumeHasSnapshots(id) => {
            Status::failed_precondition(format!("volume has snapshots: {id}"))
        }
        other => Status::internal(other.to_string()),
    }
}

fn some<T>(v: Option<T>) -> Result<T, Status> {
    v.ok_or_else(|| Status::internal("meta returned an empty response"))
}

// ── BlockService impl ─────────────────────────────────────────────────────────

#[tonic::async_trait]
impl BlockService for BlockGatewayService {
    // ── Volume CRUD ───────────────────────────────────────────────────────────

    async fn create_volume(
        &self,
        request: Request<CreateVolumeRequest>,
    ) -> Result<Response<CreateVolumeResponse>, Status> {
        let req = request.into_inner();
        let chunk_size = valid_chunk_size(req.chunk_size_bytes, self.state.ec_k)
            .map_err(Status::invalid_argument)?;
        let vol = some(
            self.state
                .meta
                .client()
                .await
                .block_create_volume(BlockCreateVolumeRequest {
                    name: req.name,
                    size_bytes: req.size_bytes,
                    pool: req.pool,
                    chunk_size_bytes: chunk_size as u32,
                    metadata: req.metadata,
                })
                .await?
                .into_inner()
                .volume,
        )?;
        self.state.mirror(&vol);
        info!("Created volume {} ({}B)", vol.volume_id, vol.size_bytes);
        Ok(Response::new(CreateVolumeResponse { volume: Some(vol) }))
    }

    async fn delete_volume(
        &self,
        request: Request<DeleteVolumeRequest>,
    ) -> Result<Response<DeleteVolumeResponse>, Status> {
        let req = request.into_inner();
        if let Ok(v) = self.state.volume_manager.get_volume(&req.volume_id)
            && v.state == VolumeState::Attached
        {
            if !req.force {
                return Err(block_err_to_status(
                    objectio_block::error::BlockError::VolumeAttached(req.volume_id),
                ));
            }
            self.state.nbd_server.unregister(&req.volume_id);
            self.state
                .set_state(&req.volume_id, ProtoVolumeState::Available)
                .await?;
        }

        // No flush in flight for it while meta drops its chunks.
        let freeable = {
            let _flushing = self.state.flush_lock.lock().await;
            let freeable = self
                .state
                .meta
                .client()
                .await
                .block_delete_volume(BlockDeleteVolumeRequest {
                    volume_id: req.volume_id.clone(),
                })
                .await?
                .into_inner()
                .freeable;
            let _ = self
                .state
                .volume_manager
                .delete_volume(&req.volume_id, true);
            self.state.cache.remove_volume(&req.volume_id);
            freeable
        };
        // Only the stripes nothing else uses: a snapshot of this volume,
        // or a clone of one, keeps the chunks it shares.
        self.state
            .free(&format!("volume {}", req.volume_id), "volume", &freeable)
            .await;
        info!("Deleted volume {}", req.volume_id);
        Ok(Response::new(DeleteVolumeResponse { success: true }))
    }

    async fn get_volume(
        &self,
        request: Request<GetVolumeRequest>,
    ) -> Result<Response<GetVolumeResponse>, Status> {
        let req = request.into_inner();
        let vol = self
            .state
            .meta
            .client()
            .await
            .block_get_volume(BlockGetVolumeRequest {
                volume_id: req.volume_id,
                name: String::new(),
            })
            .await?
            .into_inner()
            .volume;
        Ok(Response::new(GetVolumeResponse { volume: vol }))
    }

    async fn list_volumes(
        &self,
        _request: Request<ListVolumesRequest>,
    ) -> Result<Response<ListVolumesResponse>, Status> {
        let volumes = self
            .state
            .meta
            .client()
            .await
            .block_list_volumes(BlockListVolumesRequest {})
            .await?
            .into_inner()
            .volumes;
        Ok(Response::new(ListVolumesResponse {
            volumes,
            next_marker: String::new(),
            is_truncated: false,
        }))
    }

    async fn resize_volume(
        &self,
        request: Request<ResizeVolumeRequest>,
    ) -> Result<Response<ResizeVolumeResponse>, Status> {
        let req = request.into_inner();
        let current = self
            .state
            .volume_manager
            .get_volume(&req.volume_id)
            .map_err(block_err_to_status)?;
        if !current.can_modify() {
            return Err(Status::failed_precondition(format!(
                "volume {} is attached",
                req.volume_id
            )));
        }
        let vol = some(
            self.state
                .meta
                .client()
                .await
                .block_update_volume(BlockUpdateVolumeRequest {
                    volume_id: req.volume_id,
                    size_bytes: req.new_size_bytes,
                    state: 0,
                })
                .await?
                .into_inner()
                .volume,
        )?;
        self.state.mirror(&vol);
        Ok(Response::new(ResizeVolumeResponse { volume: Some(vol) }))
    }

    async fn update_volume_qos(
        &self,
        request: Request<UpdateVolumeQosRequest>,
    ) -> Result<Response<UpdateVolumeQosResponse>, Status> {
        let req = request.into_inner();
        let vol = self
            .state
            .meta
            .client()
            .await
            .block_get_volume(BlockGetVolumeRequest {
                volume_id: req.volume_id,
                name: String::new(),
            })
            .await?
            .into_inner()
            .volume;
        Ok(Response::new(UpdateVolumeQosResponse { volume: vol }))
    }

    async fn get_volume_stats(
        &self,
        request: Request<GetVolumeStatsRequest>,
    ) -> Result<Response<GetVolumeStatsResponse>, Status> {
        let req = request.into_inner();

        // Validate volume exists
        self.state
            .volume_manager
            .get_volume(&req.volume_id)
            .map_err(block_err_to_status)?;

        Ok(Response::new(GetVolumeStatsResponse {
            stats: Some(VolumeStats {
                volume_id: req.volume_id,
                ..Default::default()
            }),
        }))
    }

    // ── Snapshot CRUD ─────────────────────────────────────────────────────────

    async fn create_snapshot(
        &self,
        request: Request<CreateSnapshotRequest>,
    ) -> Result<Response<CreateSnapshotResponse>, Status> {
        let req = request.into_inner();
        self.state
            .volume_manager
            .get_volume(&req.volume_id)
            .map_err(block_err_to_status)?;

        // Everything written before the snapshot is in it: flush it all,
        // and hold flushes off until meta has recorded the chunk map, so
        // the snapshot is one point in time rather than a mix of two.
        let _flushing = self.state.flush_lock.lock().await;
        let dirty = flush_volume_all_locked(&req.volume_id, &self.state).await;
        if dirty > 0 {
            return Err(Status::unavailable(format!(
                "{dirty} chunks of {} could not be stored; snapshot not taken",
                req.volume_id
            )));
        }
        let snap = some(
            self.state
                .meta
                .client()
                .await
                .block_create_snapshot(BlockCreateSnapshotRequest {
                    volume_id: req.volume_id.clone(),
                    name: req.name,
                })
                .await?
                .into_inner()
                .snapshot,
        )?;
        info!(
            "Created snapshot {} for volume {}",
            snap.snapshot_id, snap.volume_id
        );
        Ok(Response::new(CreateSnapshotResponse {
            snapshot: Some(snap),
        }))
    }

    async fn delete_snapshot(
        &self,
        request: Request<DeleteSnapshotRequest>,
    ) -> Result<Response<DeleteSnapshotResponse>, Status> {
        let req = request.into_inner();
        let freeable = self
            .state
            .meta
            .client()
            .await
            .block_delete_snapshot(BlockDeleteSnapshotRequest {
                snapshot_id: req.snapshot_id.clone(),
            })
            .await?
            .into_inner()
            .freeable;
        self.state
            .free(
                &format!("snapshot {}", req.snapshot_id),
                "snapshot",
                &freeable,
            )
            .await;
        Ok(Response::new(DeleteSnapshotResponse { success: true }))
    }

    async fn get_snapshot(
        &self,
        request: Request<GetSnapshotRequest>,
    ) -> Result<Response<GetSnapshotResponse>, Status> {
        let req = request.into_inner();
        let snapshot = self
            .state
            .meta
            .client()
            .await
            .block_get_snapshot(BlockGetSnapshotRequest {
                snapshot_id: req.snapshot_id,
            })
            .await?
            .into_inner()
            .snapshot;
        Ok(Response::new(GetSnapshotResponse { snapshot }))
    }

    async fn list_snapshots(
        &self,
        request: Request<ListSnapshotsRequest>,
    ) -> Result<Response<ListSnapshotsResponse>, Status> {
        let req = request.into_inner();
        let snapshots = self
            .state
            .meta
            .client()
            .await
            .block_list_snapshots(BlockListSnapshotsRequest {
                volume_id: req.volume_id,
            })
            .await?
            .into_inner()
            .snapshots;
        Ok(Response::new(ListSnapshotsResponse {
            snapshots,
            next_marker: String::new(),
            is_truncated: false,
        }))
    }

    async fn clone_volume(
        &self,
        request: Request<CloneVolumeRequest>,
    ) -> Result<Response<CloneVolumeResponse>, Status> {
        let req = request.into_inner();
        let vol = some(
            self.state
                .meta
                .client()
                .await
                .block_clone_volume(BlockCloneVolumeRequest {
                    snapshot_id: req.snapshot_id.clone(),
                    name: req.name,
                })
                .await?
                .into_inner()
                .volume,
        )?;
        self.state.mirror(&vol);
        info!(
            "Cloned volume {} from snapshot {}",
            vol.volume_id, req.snapshot_id
        );
        Ok(Response::new(CloneVolumeResponse { volume: Some(vol) }))
    }

    // ── Attachment ────────────────────────────────────────────────────────────

    async fn attach_volume(
        &self,
        request: Request<AttachVolumeRequest>,
    ) -> Result<Response<AttachVolumeResponse>, Status> {
        let req = request.into_inner();
        let vol = self
            .state
            .volume_manager
            .get_volume(&req.volume_id)
            .map_err(block_err_to_status)?;

        if !vol.can_attach() {
            return Err(Status::failed_precondition(format!(
                "volume {} is not in Available state",
                req.volume_id
            )));
        }

        let target_type = TargetType::try_from(req.target_type).unwrap_or(TargetType::Nbd);
        if target_type != TargetType::Nbd {
            return Err(Status::unimplemented("only NBD target type is supported"));
        }
        let read_only = req.read_only;

        self.state
            .set_state(&req.volume_id, ProtoVolumeState::Attached)
            .await?;
        self.state
            .nbd_server
            .register(&req.volume_id, vol.size_bytes, read_only);
        let target_address = format!(
            "nbd://{}:{}/{}",
            self.state.advertise_host, self.state.nbd_port, req.volume_id
        );

        info!("Attached volume {} → {}", req.volume_id, target_address);

        Ok(Response::new(AttachVolumeResponse {
            attachment: Some(Attachment {
                volume_id: req.volume_id,
                target_type: target_type.into(),
                target_address,
                initiator: req.initiator,
                attached_at: chrono::Utc::now().timestamp_millis() as u64,
                read_only,
            }),
        }))
    }

    async fn detach_volume(
        &self,
        request: Request<DetachVolumeRequest>,
    ) -> Result<Response<DetachVolumeResponse>, Status> {
        let req = request.into_inner();

        // Store what is dirty. Anything that fails stays journaled and is
        // flushed later; detaching does not lose it.
        let dirty = flush_volume_all(&req.volume_id, &self.state).await;
        if dirty > 0 {
            warn!(
                "Detaching {} with {dirty} chunks still to store",
                req.volume_id
            );
        }

        self.state.nbd_server.unregister(&req.volume_id);
        self.state
            .set_state(&req.volume_id, ProtoVolumeState::Available)
            .await?;

        info!("Detached volume {}", req.volume_id);

        Ok(Response::new(DetachVolumeResponse { success: true }))
    }

    async fn list_attachments(
        &self,
        request: Request<ListAttachmentsRequest>,
    ) -> Result<Response<ListAttachmentsResponse>, Status> {
        let req = request.into_inner();

        let attachments = self.state.nbd_server.list_attachments(&req.volume_id);

        Ok(Response::new(ListAttachmentsResponse { attachments }))
    }

    // ── Direct I/O ────────────────────────────────────────────────────────────

    async fn read(&self, request: Request<ReadRequest>) -> Result<Response<ReadResponse>, Status> {
        let io = Io::start(Protocol::Grpc, "read");
        let req = request.into_inner();
        self.check_bounds(
            &req.volume_id,
            req.offset_bytes,
            u64::from(req.length_bytes),
        )?;

        let result = self
            .state
            .resolver
            .read(
                &req.volume_id,
                req.offset_bytes,
                u64::from(req.length_bytes),
            )
            .await
            .map_err(|e| Status::unavailable(e.to_string()))?;

        io.done(result.len() as u64);
        Ok(Response::new(ReadResponse { data: result }))
    }

    async fn write(
        &self,
        request: Request<WriteRequest>,
    ) -> Result<Response<WriteResponse>, Status> {
        let io = Io::start(Protocol::Grpc, "write");
        let req = request.into_inner();
        let len = req.data.len() as u32;

        self.check_bounds(&req.volume_id, req.offset_bytes, req.data.len() as u64)?;
        self.state
            .cache
            .write(&req.volume_id, req.offset_bytes, &req.data)
            .map_err(|e| Status::internal(e.to_string()))?;
        self.state
            .resolver
            .kick(&req.volume_id, req.offset_bytes, req.data.len() as u64);

        io.done(u64::from(len));
        Ok(Response::new(WriteResponse { bytes_written: len }))
    }

    async fn flush(
        &self,
        request: Request<FlushRequest>,
    ) -> Result<Response<FlushResponse>, Status> {
        let io = Io::start(Protocol::Grpc, "flush");
        let req = request.into_inner();
        // Writes are durable once acknowledged (journaled); a chunk that
        // could not be stored now is retried, and the caller told.
        let dirty = flush_volume_all(&req.volume_id, &self.state).await;
        if dirty > 0 {
            return Err(Status::unavailable(format!(
                "{dirty} chunks could not be stored yet; they stay journaled and are retried"
            )));
        }
        io.done(0);
        Ok(Response::new(FlushResponse { success: true }))
    }

    async fn trim(&self, request: Request<TrimRequest>) -> Result<Response<TrimResponse>, Status> {
        let io = Io::start(Protocol::Grpc, "trim");
        let req = request.into_inner();

        // Zero-fill the trimmed range in cache
        self.check_bounds(&req.volume_id, req.offset_bytes, req.length_bytes)?;
        let zeros = vec![0u8; req.length_bytes as usize];
        // A failed trim is an error to the caller. (It used to be logged
        // and reported as success.)
        self.state
            .cache
            .write(&req.volume_id, req.offset_bytes, &zeros)
            .map_err(|e| Status::internal(format!("trim: {e}")))?;
        self.state
            .resolver
            .kick(&req.volume_id, req.offset_bytes, req.length_bytes);

        io.done(req.length_bytes);
        Ok(Response::new(TrimResponse { success: true }))
    }

    // ── Metrics (stubs) ───────────────────────────────────────────────────────

    async fn get_osd_metrics(
        &self,
        _request: Request<GetOsdMetricsRequest>,
    ) -> Result<Response<GetOsdMetricsResponse>, Status> {
        Ok(Response::new(GetOsdMetricsResponse { metrics: None }))
    }

    async fn list_osd_metrics(
        &self,
        _request: Request<ListOsdMetricsRequest>,
    ) -> Result<Response<ListOsdMetricsResponse>, Status> {
        Ok(Response::new(ListOsdMetricsResponse { osds: vec![] }))
    }

    async fn get_cluster_metrics(
        &self,
        _request: Request<GetClusterMetricsRequest>,
    ) -> Result<Response<GetClusterMetricsResponse>, Status> {
        Ok(Response::new(GetClusterMetricsResponse { metrics: None }))
    }

    async fn get_io_trace(
        &self,
        _request: Request<GetIoTraceRequest>,
    ) -> Result<Response<GetIoTraceResponse>, Status> {
        Ok(Response::new(GetIoTraceResponse { traces: vec![] }))
    }
}

#[cfg(test)]
mod tests {
    use super::valid_chunk_size;

    #[test]
    fn a_chunk_size_is_a_power_of_two_that_fills_whole_osd_blocks() {
        assert_eq!(valid_chunk_size(0, 4), Ok(4 << 20), "default");
        assert_eq!(valid_chunk_size(256 << 10, 4), Ok(256 << 10));
        assert_eq!(valid_chunk_size(1 << 20, 4), Ok(1 << 20));
        // 4+2 needs 4 × 64 KiB; 8+3 needs 8 × 64 KiB.
        assert!(valid_chunk_size(256 << 10, 8).is_err());
        assert_eq!(valid_chunk_size(512 << 10, 8), Ok(512 << 10));
        for bad in [64 << 10, 128 << 10, 300 << 10, 8 << 20] {
            assert!(valid_chunk_size(bad, 4).is_err(), "{bad} accepted");
        }
    }
}
