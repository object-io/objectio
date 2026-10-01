//! OSD gRPC service implementation

use futures::stream::Stream;
use objectio_proto::metadata::ObjectMeta;
use objectio_proto::storage::{
    AffectedObject,
    AffectedShardRef,
    BlockLocation,
    CheckShardsRequest,
    CheckShardsResponse,
    Checksum,
    CopyObjectMetaRequest,
    CopyObjectMetaResponse,
    DeleteObjectMetaRequest,
    DeleteObjectMetaResponse,
    DeleteShardRequest,
    DeleteShardResponse,
    DiskStatus,
    FindObjectsReferencingNodeRequest,
    FindObjectsReferencingNodeResponse,
    GetObjectMetaRequest,
    GetObjectMetaResponse,
    GetShardMetaRequest,
    GetShardMetaResponse,
    GetStatusRequest,
    GetStatusResponse,
    HealthCheckRequest,
    HealthCheckResponse,
    ListObjectVersionsMetaRequest,
    ListObjectVersionsMetaResponse,
    ListObjectsMetaChunk,
    ListObjectsMetaRequest,
    ListObjectsMetaResponse,
    ListShardsRequest,
    ListShardsResponse,
    // Object metadata RPCs
    PutObjectMetaRequest,
    PutObjectMetaResponse,
    RdmaBuffer,
    ReadShardRequest,
    ReadShardResponse,
    ShardState,
    WriteShardRequest,
    WriteShardResponse,
    health_check_response::Status as HealthStatus,
    storage_service_server::StorageService,
};
use objectio_storage::DiskManager;
use objectio_storage::metadata::{MetadataKey, MetadataStore, MetadataStoreConfig};
use parking_lot::RwLock;
use prost::Message;
use std::collections::HashMap;
use std::fmt::Write;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::usage::{EntryKind, UsageTracker};

/// gRPC method metrics
#[derive(Debug, Default)]
pub struct GrpcMethodMetrics {
    pub requests_total: AtomicU64,
    pub requests_success: AtomicU64,
    pub requests_error: AtomicU64,
    pub latency_sum_us: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
}

impl GrpcMethodMetrics {
    pub fn record(&self, success: bool, latency_us: u64, bytes_in: u64, bytes_out: u64) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
        if success {
            self.requests_success.fetch_add(1, Ordering::Relaxed);
        } else {
            self.requests_error.fetch_add(1, Ordering::Relaxed);
        }
        self.latency_sum_us.fetch_add(latency_us, Ordering::Relaxed);
        self.bytes_received.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes_out, Ordering::Relaxed);
    }
}

/// gRPC metrics collector for OSD
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct GrpcMetrics {
    pub write_shard: GrpcMethodMetrics,
    pub read_shard: GrpcMethodMetrics,
    pub delete_shard: GrpcMethodMetrics,
    pub get_shard_meta: GrpcMethodMetrics,
    pub list_shards: GrpcMethodMetrics,
    pub put_object_meta: GrpcMethodMetrics,
    pub get_object_meta: GrpcMethodMetrics,
    pub delete_object_meta: GrpcMethodMetrics,
    pub list_objects_meta: GrpcMethodMetrics,
    pub copy_object_meta: GrpcMethodMetrics,
    pub stream_list_objects_meta: GrpcMethodMetrics,
    pub health_check: GrpcMethodMetrics,
    pub get_status: GrpcMethodMetrics,
}

impl GrpcMetrics {
    /// Export metrics in Prometheus format
    pub fn export_prometheus(&self, osd_id: &str) -> String {
        let mut output = String::with_capacity(4 * 1024);

        // Requests total by method and status
        writeln!(
            output,
            "# HELP objectio_osd_grpc_requests_total Total gRPC requests by method and status"
        )
        .unwrap();
        writeln!(output, "# TYPE objectio_osd_grpc_requests_total counter").unwrap();

        let methods = [
            ("WriteShard", &self.write_shard),
            ("ReadShard", &self.read_shard),
            ("DeleteShard", &self.delete_shard),
            ("GetShardMeta", &self.get_shard_meta),
            ("ListShards", &self.list_shards),
            ("PutObjectMeta", &self.put_object_meta),
            ("GetObjectMeta", &self.get_object_meta),
            ("DeleteObjectMeta", &self.delete_object_meta),
            ("ListObjectsMeta", &self.list_objects_meta),
            ("HealthCheck", &self.health_check),
            ("GetStatus", &self.get_status),
        ];

        for (method, metrics) in methods.iter() {
            let success = metrics.requests_success.load(Ordering::Relaxed);
            let error = metrics.requests_error.load(Ordering::Relaxed);
            writeln!(
                output,
                "objectio_osd_grpc_requests_total{{osd_id=\"{}\",method=\"{}\",status=\"success\"}} {}",
                osd_id, method, success
            ).unwrap();
            writeln!(
                output,
                "objectio_osd_grpc_requests_total{{osd_id=\"{}\",method=\"{}\",status=\"error\"}} {}",
                osd_id, method, error
            ).unwrap();
        }

        // Latency sum (for calculating average)
        writeln!(
            output,
            "# HELP objectio_osd_grpc_latency_seconds_sum Sum of gRPC request latencies"
        )
        .unwrap();
        writeln!(
            output,
            "# TYPE objectio_osd_grpc_latency_seconds_sum counter"
        )
        .unwrap();
        for (method, metrics) in methods.iter() {
            let sum_us = metrics.latency_sum_us.load(Ordering::Relaxed);
            writeln!(
                output,
                "objectio_osd_grpc_latency_seconds_sum{{osd_id=\"{}\",method=\"{}\"}} {}",
                osd_id,
                method,
                sum_us as f64 / 1_000_000.0
            )
            .unwrap();
        }

        // Bytes sent/received
        writeln!(
            output,
            "# HELP objectio_osd_grpc_bytes_received_total Total bytes received via gRPC"
        )
        .unwrap();
        writeln!(
            output,
            "# TYPE objectio_osd_grpc_bytes_received_total counter"
        )
        .unwrap();
        for (method, metrics) in methods.iter() {
            let bytes = metrics.bytes_received.load(Ordering::Relaxed);
            if bytes > 0 {
                writeln!(
                    output,
                    "objectio_osd_grpc_bytes_received_total{{osd_id=\"{}\",method=\"{}\"}} {}",
                    osd_id, method, bytes
                )
                .unwrap();
            }
        }

        writeln!(
            output,
            "# HELP objectio_osd_grpc_bytes_sent_total Total bytes sent via gRPC"
        )
        .unwrap();
        writeln!(output, "# TYPE objectio_osd_grpc_bytes_sent_total counter").unwrap();
        for (method, metrics) in methods.iter() {
            let bytes = metrics.bytes_sent.load(Ordering::Relaxed);
            if bytes > 0 {
                writeln!(
                    output,
                    "objectio_osd_grpc_bytes_sent_total{{osd_id=\"{}\",method=\"{}\"}} {}",
                    osd_id, method, bytes
                )
                .unwrap();
            }
        }

        output
    }
}

/// Disk status information for metrics
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct DiskStatusInfo {
    pub path: String,
    pub capacity: u64,
    pub used: u64,
    pub shard_count: u64,
    pub status: String,
    pub read_errors: u64,
    pub write_errors: u64,
    pub checksum_errors: u64,
    pub reads: u64,
    pub writes: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
}

/// OSD status information for metrics
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct OsdStatus {
    pub disks: Vec<DiskStatusInfo>,
    pub total_capacity: u64,
    pub total_used: u64,
    pub total_shards: u64,
    pub uptime_secs: u64,
}

/// Shard location stored in memory. Mirrored to the persistent
/// MetadataStore on every write so pod restarts can rebuild the
/// in-memory index from the WAL — without this, the OSD forgets
/// which shards it holds the moment its process restarts, and
/// meta thinks every OSD is empty.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ShardLocation {
    disk_idx: usize,
    block_num: u64,
    size: u32,
    crc32c: u32,
    created_at: u64,
}

/// Prefix under which the OSD persists its shard-location index in
/// MetadataStore. Keys are `{PREFIX}{shard_key_string}`. The prefix
/// keeps us from colliding with the ShardMeta entries the object
/// layer writes under its own 's'-prefixed keys.
const SHARD_LOC_PREFIX: &[u8] = b"osd_loc:";

/// OSD service state
pub struct OsdService {
    node_id: [u8; 16],
    disks: Vec<DiskManager>,
    disk_ids: Vec<[u8; 16]>,
    /// Shard index: object_id:stripe_id:position -> location (in-memory cache)
    shard_index: RwLock<HashMap<String, ShardLocation>>,
    /// Persistent metadata store (WAL + B-tree + ARC cache)
    meta_store: Arc<MetadataStore>,
    start_time: Instant,
    /// Round-robin disk selection for writes
    next_disk: RwLock<usize>,
    /// gRPC metrics collector
    grpc_metrics: Arc<GrpcMetrics>,
    /// Per-bucket usage of the objects this OSD is primary for
    usage: UsageTracker,
    /// Renders this OSD's Prometheus exposition for `GetMetrics`. Set once
    /// the metrics state exists, which is after the service is built.
    metrics_renderer: std::sync::OnceLock<MetricsRenderer>,
    /// Shards that cannot be read back intact — failing their checksum or
    /// unreadable — found by the scrubber or a read. Kept until the shard is rewritten; reported through
    /// `CheckShards` so Meta's repairer rebuilds them. In memory only: after
    /// a restart the next scrub pass finds them again.
    corrupt: RwLock<std::collections::HashSet<String>>,
    scrub: ScrubStats,
    /// Transfer Engine and staging pool, once enabled at startup. Without it
    /// every shard arrives and leaves as gRPC bytes.
    #[cfg(feature = "rdma")]
    rdma: std::sync::OnceLock<crate::rdma::RdmaStaging>,
}

type MetricsRenderer = Box<dyn Fn() -> String + Send + Sync>;

/// What the scrubber has done since the OSD started.
#[derive(Default)]
struct ScrubStats {
    passes: AtomicU64,
    shards: AtomicU64,
    bytes: AtomicU64,
    corrupt: AtomicU64,
}

/// Resolve the OSD's stable node_id + cluster_uuid from (in priority order):
///
/// 1. **Any opened disk's superblock** that already carries an identity.
///    If two disks disagree on `osd_node_id` or `cluster_uuid`, reject
///    the whole mount — the operator mixed disks from different OSDs
///    or different clusters, which would silently corrupt metadata.
/// 2. **`data_dir/node_id`** — the state-PVC fallback from the L1
///    commit. Used when disks haven't yet been claimed (pre-upgrade
///    or brand-new disks).
/// 3. **Fresh random UUID** — only on the very first boot of a new
///    OSD. Caller writes it back to (1) and (2) so subsequent boots
///    are idempotent.
///
/// Returns `(node_id, cluster_uuid, from_disk)`. `from_disk = false`
/// tells the caller to persist the identity to every disk (the
/// Ceph/Rook-style activation flow).
fn resolve_node_identity(
    disks: &[objectio_storage::DiskManager],
    id_path: &std::path::Path,
) -> Result<([u8; 16], Uuid, bool), String> {
    // Check every disk first — even one claimed disk wins over the
    // state-PVC fallback, and mixed identities must be rejected.
    let mut claimed: Option<([u8; 16], Uuid)> = None;
    for disk in disks {
        if disk.has_identity() {
            let id = disk.osd_node_id();
            let cuid = disk.cluster_uuid();
            match claimed {
                None => claimed = Some((id, cuid)),
                Some((prev_id, prev_cuid)) => {
                    if prev_id != id || prev_cuid != cuid {
                        return Err(format!(
                            "disks disagree on identity — first saw \
                             node_id={} cluster_uuid={}, now disk '{}' has \
                             node_id={} cluster_uuid={}. Refusing to mount; \
                             resolve by removing the mis-claimed disk.",
                            hex::encode(prev_id),
                            prev_cuid,
                            disk.path(),
                            hex::encode(id),
                            cuid,
                        ));
                    }
                }
            }
        }
    }
    if let Some((id, cuid)) = claimed {
        info!(
            "Loaded OSD identity from disk superblock: node_id={} cluster_uuid={}",
            hex::encode(id),
            cuid
        );
        return Ok((id, cuid, true));
    }

    // No disk has an identity yet — fall back to the state-PVC file.
    if let Ok(bytes) = std::fs::read(id_path)
        && bytes.len() == 16
    {
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes);
        info!(
            "Loaded OSD node_id from state-PVC file {}: {}",
            id_path.display(),
            hex::encode(id)
        );
        // cluster_uuid stays nil here — Meta will set it on first
        // registration once the cluster-UUID RPC lands (task #145).
        return Ok((id, Uuid::nil(), false));
    }

    // True first boot.
    if let Some(parent) = id_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        return Err(format!(
            "Failed to create OSD data directory {}: {e}",
            parent.display()
        ));
    }
    let id = *Uuid::new_v4().as_bytes();
    if let Err(e) = std::fs::write(id_path, id) {
        warn!(
            "Generated OSD node_id but failed to persist to {}: {e} — \
             restarts will re-generate and orphan data",
            id_path.display()
        );
    } else {
        info!(
            "Generated new OSD node_id at {}: {}",
            id_path.display(),
            hex::encode(id)
        );
    }
    Ok((id, Uuid::nil(), false))
}

impl OsdService {
    /// Create a new OSD service with the given disks
    ///
    /// The block_size parameter configures the storage block size for new disks.
    /// Existing disks will use their existing block size from the superblock.
    /// A larger block size allows larger erasure-coded shards without chunking.
    pub fn new(
        disk_paths: Vec<String>,
        block_size: u32,
        data_dir: PathBuf,
    ) -> Result<Self, String> {
        // Node identity: Ceph/Rook pattern — the disk is the source of
        // truth. Three-level cascade:
        //   1. Existing disk's superblock with a non-nil osd_node_id.
        //      All claimed disks must agree; mixed identities = refuse.
        //   2. data_dir/node_id file on the state PVC (fallback for
        //      pre-identity disks or dev setups).
        //   3. Fresh UUID on genuine first boot; persisted to (1) by
        //      writing every disk's superblock, and to (2) as a
        //      fallback.
        let mut disks = Vec::new();
        let mut disk_ids = Vec::new();
        // Disks formatted just now, by index: whatever the shard index says
        // was on them is gone.
        let mut formatted_now = Vec::new();

        for path in &disk_paths {
            info!("Initializing disk: {}", path);

            // Try to open existing disk or initialize new one
            let disk = match DiskManager::open(path) {
                Ok(d) => {
                    info!(
                        "Opened existing disk: {} (block_size={})",
                        path,
                        d.block_size()
                    );
                    formatted_now.push(false);
                    d
                }
                Err(_) => {
                    // Get device/file size - for block devices we need to check
                    let size = if std::path::Path::new(path).exists() {
                        // Use raw_io to get size
                        let rf = objectio_storage::RawFile::open(path, true)
                            .map_err(|e| format!("Failed to check {}: {}", path, e))?;
                        rf.size()
                    } else {
                        // Default to 10GB for new files
                        10 * 1024 * 1024 * 1024
                    };

                    info!(
                        "Initializing new disk: {} with size {} bytes, block_size {} bytes",
                        path, size, block_size
                    );
                    formatted_now.push(true);
                    DiskManager::init(path, size, Some(block_size))
                        .map_err(|e| format!("Failed to init disk {}: {}", path, e))?
                }
            };

            disk_ids.push(*disk.id().as_bytes());
            disks.push(disk);
        }

        if disks.is_empty() {
            return Err("No disks configured".into());
        }

        // Identity resolution: prefer any disk's superblock, then
        // state-PVC fallback, then generate fresh.
        let id_path = data_dir.join("node_id");
        let (node_id, cluster_uuid, from_disk) = resolve_node_identity(&disks, &id_path)?;

        // If the identity came from the state PVC (or was freshly
        // generated), write it to every disk's superblock so the next
        // restart has the real Ceph/Rook pattern (disk = truth). Disks
        // that already matched are no-ops.
        if !from_disk {
            for (i, disk) in disks.iter().enumerate() {
                if let Err(e) = disk.set_identity(cluster_uuid, node_id) {
                    warn!(
                        "Failed to write identity to disk {}: {e} — next \
                         restart will fall back to state-PVC file",
                        disk_paths[i]
                    );
                } else {
                    info!(
                        "Persisted OSD identity to disk {} (cluster_uuid={}, node_id={})",
                        disk_paths[i],
                        cluster_uuid,
                        hex::encode(node_id)
                    );
                }
            }
        }

        // Initialize metadata store for persistent object metadata
        let meta_config = MetadataStoreConfig::with_data_dir(&data_dir);
        let meta_store = MetadataStore::open_or_create(meta_config)
            .map_err(|e| format!("Failed to open metadata store: {}", e))?;

        info!(
            "OSD initialized with {} disks, metadata at {:?}",
            disks.len(),
            data_dir
        );

        let num_disks = disks.len();
        // Rebuild the in-memory shard index from persisted entries
        // (replayed from the WAL as part of `MetadataStore::open_or_create`
        // above). Before this step the OSD used to report 0 shards on
        // every restart even though disk.raw was full.
        let mut persisted = Self::load_persisted_shard_index(&meta_store);
        // A disk that had to be formatted — replaced, or wiped — holds none
        // of the shards the index remembers on it. Forget them, so they are
        // reported missing and rebuilt rather than reported present and
        // failing every read.
        let before = persisted.len();
        persisted.retain(|key, loc| {
            let lost = formatted_now.get(loc.disk_idx).copied().unwrap_or(false);
            if lost {
                let _ = Self::forget_shard_location(&meta_store, key);
            }
            !lost
        });
        if persisted.len() < before {
            warn!(
                "{} shards were on a disk formatted at startup; they are lost \
                 and will be rebuilt by Meta's repairer",
                before - persisted.len()
            );
        }
        info!(
            "Rebuilt shard index from persistent store: {} entries",
            persisted.len()
        );
        // Reconcile each disk's allocation bitmap against the shard index.
        //
        // The index is the source of truth for what is actually on the
        // platter. A disk formatted before the allocator was wired up has an
        // all-zero bitmap under a full data region, so without this the OSD
        // would hand out block 0 on restart and overwrite live shards. It is
        // also what makes the fix work on an existing disk rather than only
        // on a freshly formatted one.
        let mut reclaimed_check: Vec<u64> = vec![0; num_disks];
        for loc in persisted.values() {
            if loc.disk_idx >= disks.len() {
                warn!(
                    "Shard index references disk {} but only {} are attached; skipping",
                    loc.disk_idx,
                    disks.len()
                );
                continue;
            }
            let blocks = disks[loc.disk_idx].blocks_for_len(loc.size as usize);
            if let Err(e) = disks[loc.disk_idx].mark_extent_used(loc.block_num, blocks) {
                warn!(
                    "Could not mark block {} on disk {} as used: {e}",
                    loc.block_num, loc.disk_idx
                );
            } else {
                reclaimed_check[loc.disk_idx] += 1;
            }
        }
        for (idx, disk) in disks.iter().enumerate() {
            if let Err(e) = disk.persist_allocator() {
                warn!("Could not persist allocation bitmap for disk {idx}: {e}");
            }
            info!(
                "Disk {idx}: {} of {} bytes used across {} indexed shards",
                disk.used_space(),
                disk.capacity(),
                reclaimed_check[idx]
            );
        }
        let usage = UsageTracker::new(node_id);
        let started = Instant::now();
        usage.rebuild(
            meta_store
                .scan_prefix(&MetadataKey::all_object_meta_prefix())
                .into_iter()
                .chain(meta_store.scan_prefix(&MetadataKey::from_bytes(vec![b'v']))),
        );
        info!(
            "Rebuilt usage for {} buckets in {:?}",
            usage.snapshot().len(),
            started.elapsed()
        );

        Ok(Self {
            node_id,
            disks,
            disk_ids,
            shard_index: RwLock::new(persisted),
            meta_store: Arc::new(meta_store),
            start_time: Instant::now(),
            next_disk: RwLock::new(0),
            grpc_metrics: Arc::new(GrpcMetrics::default()),
            usage,
            metrics_renderer: std::sync::OnceLock::new(),
            corrupt: RwLock::new(std::collections::HashSet::new()),
            scrub: ScrubStats::default(),
            #[cfg(feature = "rdma")]
            rdma: std::sync::OnceLock::new(),
        })
    }

    /// Install the function `GetMetrics` serves. Later calls are ignored.
    pub fn set_metrics_renderer(&self, f: MetricsRenderer) {
        let _ = self.metrics_renderer.set(f);
    }

    /// The Transfer Engine segment to register with meta; empty unless
    /// rdma is enabled.
    #[must_use]
    pub fn te_segment(&self) -> String {
        #[cfg(feature = "rdma")]
        if let Some(staging) = self.rdma.get() {
            return staging.segment().to_string();
        }
        String::new()
    }

    /// Accept shard transfers over Transfer Engine from now on.
    #[cfg(feature = "rdma")]
    pub fn enable_rdma(&self, staging: crate::rdma::RdmaStaging) {
        let _ = self.rdma.set(staging);
    }

    /// Read a PUT shard from the gateway's buffer into a staging slot.
    #[cfg_attr(not(feature = "rdma"), allow(clippy::unused_async))]
    async fn pull_shard(
        &self,
        src: &RdmaBuffer,
        checksum: Option<&Checksum>,
    ) -> Result<(objectio_transport_te::Slot, usize), Status> {
        #[cfg(feature = "rdma")]
        {
            let staging = self
                .rdma
                .get()
                .ok_or_else(|| Status::failed_precondition("rdma is not enabled on this OSD"))?;
            let crc32c = checksum.map(|c| c.crc32c).ok_or_else(|| {
                Status::invalid_argument("a shard sent over rdma needs a checksum")
            })?;
            staging.pull(src, crc32c).await
        }
        #[cfg(not(feature = "rdma"))]
        {
            let _ = (src, checksum);
            Err(Status::unimplemented("this OSD was built without rdma"))
        }
    }

    /// Write a GET shard into the gateway's buffer.
    #[cfg_attr(not(feature = "rdma"), allow(clippy::unused_async))]
    async fn push_shard(&self, data: &[u8], dest: &RdmaBuffer) -> Result<(), Status> {
        #[cfg(feature = "rdma")]
        {
            let staging = self
                .rdma
                .get()
                .ok_or_else(|| Status::failed_precondition("rdma is not enabled on this OSD"))?;
            staging.push(data, dest).await
        }
        #[cfg(not(feature = "rdma"))]
        {
            let _ = (data, dest);
            Err(Status::unimplemented("this OSD was built without rdma"))
        }
    }

    /// Metadata WAL fsync latency and batching, as Prometheus families.
    pub fn render_wal_metrics(&self, out: &mut String, osd_label: &str) {
        let st = self.meta_store.wal_sync_stats();
        st.seconds.render(
            out,
            "objectio_osd_wal_fsync_seconds",
            "Time for one metadata WAL fdatasync",
            osd_label,
        );
        for (name, help, v) in [
            (
                "objectio_osd_wal_syncs_total",
                "Metadata WAL fdatasyncs",
                st.syncs.load(Ordering::Relaxed),
            ),
            (
                "objectio_osd_wal_records_synced_total",
                "Metadata WAL records made durable; divide by syncs for records per fsync",
                st.records.load(Ordering::Relaxed),
            ),
        ] {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name}{{{osd_label}}} {v}");
        }
    }

    /// Per-bucket usage of the objects this OSD is primary for.
    pub fn bucket_usage(&self) -> Vec<objectio_proto::storage::BucketUsage> {
        self.usage.snapshot()
    }

    /// Return a shard's blocks to the pool. The index entry must already be
    /// gone, so a crash in between leaks a block rather than handing a live
    /// shard's block to the next write.
    fn free_location(&self, loc: &ShardLocation) {
        if loc.disk_idx >= self.disks.len() {
            return;
        }
        let disk = &self.disks[loc.disk_idx];
        // `size` is the shard's payload length, so the extent's length is
        // derivable — which is why nothing had to be added to the index.
        let blocks = disk.blocks_for_len(loc.size as usize);
        match disk.free_extent(loc.block_num, blocks) {
            Ok(()) => {
                if let Err(e) = disk.persist_allocator() {
                    warn!(
                        "Freed block {} on disk {} but could not persist the bitmap: {e}",
                        loc.block_num, loc.disk_idx
                    );
                }
            }
            Err(e) => warn!(
                "Could not free block {} on disk {}: {e}",
                loc.block_num, loc.disk_idx
            ),
        }
    }

    /// Record that the shard under `key`, at `block_num`, failed its
    /// checksum — unless it has been rewritten or deleted since it was read.
    fn mark_corrupt(&self, key: &str, block_num: u64) {
        let still_there = self
            .shard_index
            .read()
            .get(key)
            .is_some_and(|l| l.block_num == block_num);
        if still_there && self.corrupt.write().insert(key.to_string()) {
            self.scrub.corrupt.fetch_add(1, Ordering::Relaxed);
            warn!("shard {key} (block {block_num}) is corrupt; Meta's repairer will rebuild it");
        }
    }

    /// One scrub pass: read every shard on this OSD and check its blocks'
    /// checksums, at no more than `bytes_per_sec`, so a shard that rots on
    /// disk is found even if nobody reads it. Corrupt shards are recorded
    /// for the repairer.
    pub async fn scrub_pass(&self, bytes_per_sec: u64) {
        let shards: Vec<(String, ShardLocation)> = self
            .shard_index
            .read()
            .iter()
            .map(|(k, l)| (k.clone(), l.clone()))
            .collect();
        let started = Instant::now();
        let mut bytes = 0u64;
        for (key, loc) in shards {
            if loc.disk_idx >= self.disks.len() {
                continue;
            }
            // Any failure counts, not only a checksum: a block whose header
            // no longer parses, or that the disk cannot return, cannot be
            // served either. `mark_corrupt` ignores a shard rewritten or
            // deleted since the snapshot.
            if let Err(e) = self.disks[loc.disk_idx]
                .read_block_async(loc.block_num)
                .await
            {
                debug!("scrub: {key} is unreadable: {e}");
                self.mark_corrupt(&key, loc.block_num);
            }
            bytes += u64::from(loc.size);
            self.scrub.shards.fetch_add(1, Ordering::Relaxed);
            self.scrub
                .bytes
                .fetch_add(u64::from(loc.size), Ordering::Relaxed);
            // Pace to the rate: wait until this many bytes are due.
            if bytes_per_sec > 0 {
                let due = std::time::Duration::from_secs_f64(bytes as f64 / bytes_per_sec as f64);
                if let Some(wait) = due.checked_sub(started.elapsed()) {
                    tokio::time::sleep(wait).await;
                }
            }
        }
        self.scrub.passes.fetch_add(1, Ordering::Relaxed);
        info!(
            "scrub pass done: {} bytes in {:.1}s, {} shard(s) corrupt",
            bytes,
            started.elapsed().as_secs_f64(),
            self.corrupt.read().len()
        );
    }

    /// Scrub progress as Prometheus families.
    pub fn render_scrub_metrics(&self, out: &mut String, osd_label: &str) {
        let corrupt_now = self.corrupt.read().len() as u64;
        for (name, kind, help, v) in [
            (
                "objectio_osd_scrub_passes_total",
                "counter",
                "Completed scrub passes",
                self.scrub.passes.load(Ordering::Relaxed),
            ),
            (
                "objectio_osd_scrub_shards_total",
                "counter",
                "Shards read and checked by the scrubber",
                self.scrub.shards.load(Ordering::Relaxed),
            ),
            (
                "objectio_osd_scrub_bytes_total",
                "counter",
                "Bytes read and checked by the scrubber",
                self.scrub.bytes.load(Ordering::Relaxed),
            ),
            (
                "objectio_osd_corrupt_shards_found_total",
                "counter",
                "Shards found failing their checksum, by the scrubber or a read",
                self.scrub.corrupt.load(Ordering::Relaxed),
            ),
            (
                "objectio_osd_corrupt_shards",
                "gauge",
                "Corrupt shards on this OSD not yet rebuilt",
                corrupt_now,
            ),
        ] {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} {kind}");
            let _ = writeln!(out, "{name}{{{osd_label}}} {v}");
        }
    }

    /// Decoded ObjectMeta currently stored under `key`, if any.
    fn stored_meta(&self, key: &MetadataKey) -> Option<ObjectMeta> {
        self.meta_store
            .get(key)
            .and_then(|v| ObjectMeta::decode(&v[..]).ok())
    }

    /// Get gRPC metrics
    pub fn grpc_metrics(&self) -> &Arc<GrpcMetrics> {
        &self.grpc_metrics
    }

    /// Create OSD service with default metadata directory
    #[allow(dead_code)]
    pub fn new_default(disk_paths: Vec<String>, block_size: u32) -> Result<Self, String> {
        let data_dir = PathBuf::from("./osd-metadata");
        Self::new(disk_paths, block_size, data_dir)
    }

    /// Get node ID as bytes
    pub fn node_id(&self) -> &[u8; 16] {
        &self.node_id
    }

    /// Stamp the cluster UUID into each disk's superblock. Called by
    /// the registration path once Meta returns a cluster_uuid. Idempotent
    /// — disks that already have the matching cluster_uuid are no-ops,
    /// disks with a different cluster_uuid refuse the write and surface
    /// the error (cross-cluster guard).
    pub fn stamp_cluster_uuid(&self, cluster_uuid: Uuid) -> std::result::Result<(), String> {
        if cluster_uuid.is_nil() {
            return Ok(());
        }
        for disk in &self.disks {
            if disk.cluster_uuid() == cluster_uuid && disk.osd_node_id() == self.node_id {
                continue; // already stamped, nothing to do
            }
            disk.set_identity(cluster_uuid, self.node_id)
                .map_err(|e| format!("disk {}: {e}", disk.path()))?;
            info!(
                "Stamped cluster_uuid {} on disk {}",
                cluster_uuid,
                disk.path()
            );
        }
        Ok(())
    }

    /// Get disk IDs
    pub fn disk_ids(&self) -> &[[u8; 16]] {
        &self.disk_ids
    }

    /// Raw capacity of each managed disk, index-aligned with `disk_ids()`.
    /// Used at registration time so meta can sum raw capacity across OSDs.
    pub fn disk_capacities(&self) -> Vec<u64> {
        self.disks.iter().map(|d| d.capacity()).collect()
    }

    /// Get disk count
    #[allow(dead_code)]
    pub fn disk_count(&self) -> usize {
        self.disks.len()
    }

    /// Get OSD status for metrics
    pub fn status(&self) -> OsdStatus {
        let mut disks = Vec::new();
        let mut total_capacity = 0u64;
        let mut total_used = 0u64;
        let mut total_shards = 0u64;

        for (i, disk) in self.disks.iter().enumerate() {
            let stats = disk.stats();
            let capacity = disk.capacity();
            let free = disk.free_space();
            let used = capacity.saturating_sub(free);
            let shard_count = self
                .shard_index
                .read()
                .values()
                .filter(|loc| loc.disk_idx == i)
                .count() as u64;

            total_capacity += capacity;
            total_used += used;
            total_shards += shard_count;

            let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
            let read_errors = load(&stats.read_errors);
            let write_errors = load(&stats.write_errors);
            let checksum_errors = load(&stats.checksum_errors);
            // A disk that has returned bad data or failed an IO since start
            // is not healthy, even though it is still serving requests.
            let status = if read_errors + write_errors + checksum_errors > 0 {
                "degraded"
            } else {
                "healthy"
            };
            disks.push(DiskStatusInfo {
                path: disk.path().to_string(),
                capacity,
                used,
                shard_count,
                status: status.to_string(),
                read_errors,
                write_errors,
                checksum_errors,
                reads: load(&stats.reads),
                writes: load(&stats.writes),
                bytes_read: load(&stats.bytes_read),
                bytes_written: load(&stats.bytes_written),
            });
        }

        OsdStatus {
            disks,
            total_capacity,
            total_used,
            total_shards,
            uptime_secs: self.start_time.elapsed().as_secs(),
        }
    }

    /// Select disk for write (round-robin)
    fn select_disk_for_write(&self) -> usize {
        let mut next = self.next_disk.write();
        let disk_idx = *next;
        *next = (*next + 1) % self.disks.len();
        disk_idx
    }

    /// Generate shard key for index
    fn shard_key(object_id: &[u8], stripe_id: u64, position: u32) -> String {
        format!("{}:{}:{}", hex::encode(object_id), stripe_id, position)
    }

    /// Build the MetadataStore key we persist a ShardLocation under.
    fn shard_loc_meta_key(shard_key: &str) -> objectio_storage::MetadataKey {
        let mut bytes = Vec::with_capacity(SHARD_LOC_PREFIX.len() + shard_key.len());
        bytes.extend_from_slice(SHARD_LOC_PREFIX);
        bytes.extend_from_slice(shard_key.as_bytes());
        objectio_storage::MetadataKey::from_bytes(bytes)
    }

    /// Persist a ShardLocation so a restart can rebuild the in-memory
    /// index. Called on every successful WriteShard.
    fn persist_shard_location(
        meta_store: &MetadataStore,
        shard_key: &str,
        loc: &ShardLocation,
    ) -> std::result::Result<(), String> {
        let key = Self::shard_loc_meta_key(shard_key);
        let value = bincode::serialize(loc).map_err(|e| e.to_string())?;
        meta_store
            .put(key, value)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Remove a persisted ShardLocation (delete_shard path).
    fn forget_shard_location(
        meta_store: &MetadataStore,
        shard_key: &str,
    ) -> std::result::Result<(), String> {
        let key = Self::shard_loc_meta_key(shard_key);
        meta_store
            .delete(&key)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Scan the MetadataStore for every persisted ShardLocation and
    /// rebuild the in-memory index. Called once during OSD startup —
    /// before this, `shard_index` started empty after every restart
    /// and the OSD reported 0 shards to meta even when disk.raw was
    /// full of real data.
    fn load_persisted_shard_index(meta_store: &MetadataStore) -> HashMap<String, ShardLocation> {
        let prefix_key = objectio_storage::MetadataKey::from_bytes(SHARD_LOC_PREFIX.to_vec());
        let mut out = HashMap::new();
        for (key, value) in meta_store.scan_prefix(&prefix_key) {
            let raw = key.as_bytes();
            let Some(stripped) = raw.strip_prefix(SHARD_LOC_PREFIX) else {
                continue;
            };
            let Ok(shard_key) = std::str::from_utf8(stripped) else {
                continue;
            };
            match bincode::deserialize::<ShardLocation>(&value) {
                Ok(loc) => {
                    out.insert(shard_key.to_string(), loc);
                }
                Err(e) => warn!("skipping corrupt ShardLocation entry {shard_key}: {e}"),
            }
        }
        out
    }

    /// Allocate a block for writing.
    ///
    /// Was `next_block.fetch_add(1)` — a counter that never checked itself
    /// against the size of the device and never reused anything. A full disk
    /// therefore surfaced as `block 2718 exceeds total blocks 2303`, a 500
    /// from the gateway, rather than as "out of space".
    #[allow(clippy::result_large_err)]
    fn allocate_extent(&self, disk_idx: usize, blocks: u64) -> Result<u64, Status> {
        self.disks[disk_idx].allocate_extent(blocks).map_err(|e| {
            // ResourceExhausted, not Internal: the caller can act on a full
            // disk — pick another OSD, alert, expand — and cannot act on an
            // internal error.
            Status::resource_exhausted(format!("disk {disk_idx} is full: {e}"))
        })
    }

    /// Get current timestamp
    fn current_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// An ObjectMeta as listings return it: without an inline object's bytes.
/// Listing callers want keys, sizes and ETags, and a page of 1000 inline
/// objects would otherwise carry megabytes of data nobody asked for.
fn for_listing(mut object: ObjectMeta) -> ObjectMeta {
    object.inline_data = Vec::new();
    object
}

#[tonic::async_trait]
impl StorageService for OsdService {
    async fn check_shards(
        &self,
        request: Request<CheckShardsRequest>,
    ) -> Result<Response<CheckShardsResponse>, Status> {
        let req = request.into_inner();
        let index = self.shard_index.read();
        let corrupt = self.corrupt.read();
        let states = req
            .shards
            .iter()
            .map(|id| {
                let key = Self::shard_key(&id.object_id, id.stripe_id, id.position);
                let state = if corrupt.contains(&key) {
                    ShardState::Corrupt
                } else if index.contains_key(&key) {
                    ShardState::Ok
                } else {
                    ShardState::Missing
                };
                state as i32
            })
            .collect();
        Ok(Response::new(CheckShardsResponse { states }))
    }

    async fn get_metrics(
        &self,
        _request: Request<objectio_proto::metadata::GetMetricsRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetMetricsResponse>, Status> {
        let render = || self.metrics_renderer.get().map(|f| f()).unwrap_or_default();
        // SMART polling may shell out to smartctl; don't stall a runtime
        // worker on it where the runtime allows moving off.
        let text = if tokio::runtime::Handle::current().runtime_flavor()
            == tokio::runtime::RuntimeFlavor::MultiThread
        {
            tokio::task::block_in_place(render)
        } else {
            render()
        };
        Ok(Response::new(
            objectio_proto::metadata::GetMetricsResponse {
                text,
                process_instance: objectio_common::process_metrics::instance_id().to_string(),
            },
        ))
    }

    async fn write_shard(
        &self,
        request: Request<WriteShardRequest>,
    ) -> Result<Response<WriteShardResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let shard_id = req.shard_id.ok_or_else(|| {
            self.grpc_metrics
                .write_shard
                .record(false, start.elapsed().as_micros() as u64, 0, 0);
            Status::invalid_argument("missing shard_id")
        })?;

        // The shard is either in the request, or in the gateway's memory to
        // be read over Transfer Engine into a staging slot held until it is
        // on disk.
        let staged = match req.rdma.as_ref() {
            Some(src) => Some(
                self.pull_shard(src, req.checksum.as_ref())
                    .await
                    .inspect_err(|_| {
                        self.grpc_metrics.write_shard.record(
                            false,
                            start.elapsed().as_micros() as u64,
                            0,
                            0,
                        );
                    })?,
            ),
            None => None,
        };
        let data: &[u8] = match &staged {
            Some((slot, len)) => &slot.as_slice()[..*len],
            None => &req.data,
        };
        let bytes_in = data.len() as u64;

        // Over rdma the staging slot has already checked this. Bytes in the
        // message are checked here, before a block is allocated, so a shard
        // damaged on the way is refused rather than stored and later served
        // as good under a checksum computed from the damage. A writer that
        // sends no checksum is still accepted.
        let crc32c = crc32c::crc32c(data);
        if staged.is_none()
            && let Some(expected) = req.checksum.as_ref().map(|c| c.crc32c)
            && expected != crc32c
        {
            self.grpc_metrics
                .write_shard
                .record(false, start.elapsed().as_micros() as u64, 0, 0);
            return Err(Status::data_loss(format!(
                "shard has crc32c {crc32c:08x}, expected {expected:08x}"
            )));
        }

        debug!(
            "WriteShard: object={}, stripe={}, pos={}, size={}",
            hex::encode(&shard_id.object_id),
            shard_id.stripe_id,
            shard_id.position,
            data.len()
        );

        // Select disk and allocate an extent sized to this shard.
        //
        // One shard used to take exactly one block, and the block was sized
        // for the largest shard any EC scheme could produce — 4 MB — so a
        // 4 KB object and a 4 MB object both cost 24 MB across a 4+2 stripe.
        // Measured at 6144x and 6x amplification; the real capacity limit was
        // an object count, not a byte count, and nothing reported it.
        let disk_idx = self.select_disk_for_write();
        let blocks = self.disks[disk_idx].blocks_for_len(data.len());
        let block_num = self.allocate_extent(disk_idx, blocks)?;

        let disk = &self.disks[disk_idx];

        // Prepare object_id as fixed array
        let mut object_id = [0u8; 16];
        let copy_len = shard_id.object_id.len().min(16);
        object_id[..copy_len].copy_from_slice(&shard_id.object_id[..copy_len]);

        // Write block through the async IoBackend — the tokio
        // reactor stays free during the syscall / io_uring wait. On
        // Linux + --features io-uring this is +25% throughput on
        // 4 MiB stripes vs the old sync path (see storage-io-levels.md).
        disk.write_block_async(block_num, object_id, shard_id.stripe_id, data)
            .await
            .map_err(|e| Status::internal(format!("write failed: {}", e)))?;

        disk.sync()
            .map_err(|e| Status::internal(format!("sync failed: {}", e)))?;

        // Store location in index
        let key = Self::shard_key(&shard_id.object_id, shard_id.stripe_id, shard_id.position);
        let timestamp = Self::current_timestamp();

        let loc = ShardLocation {
            disk_idx,
            block_num,
            size: data.len() as u32,
            crc32c,
            created_at: timestamp,
        };
        // Persist to the WAL-backed MetadataStore before inserting into
        // the in-memory index — if the put fails the in-memory state
        // stays accurate to what's actually recoverable. A failure
        // here is non-fatal (the shard bytes are on disk); log loud
        // so we notice the drift.
        if let Err(e) = Self::persist_shard_location(&self.meta_store, &key, &loc) {
            warn!(
                "Failed to persist shard_location for {key}: {e} — \
                 in-memory only, will be lost on restart"
            );
        }
        let replaced = self.shard_index.write().insert(key.clone(), loc);
        // Rewriting a shard that is already here — the repairer replacing a
        // corrupt copy — gets new blocks; the old ones go back to the pool
        // now that the index no longer points at them.
        if let Some(old) = replaced {
            self.free_location(&old);
        }
        self.corrupt.write().remove(&key);

        info!(
            "Wrote shard: disk={}, block={}, size={}, crc32c={:08x}",
            disk_idx,
            block_num,
            data.len(),
            crc32c
        );

        let resp = WriteShardResponse {
            location: Some(BlockLocation {
                node_id: self.node_id.to_vec(),
                disk_id: self.disk_ids[disk_idx].to_vec(),
                offset: block_num * disk.block_size() as u64,
                size: data.len() as u32,
            }),
            timestamp,
        };
        let bytes_out = resp.encoded_len() as u64;
        self.grpc_metrics.write_shard.record(
            true,
            start.elapsed().as_micros() as u64,
            bytes_in,
            bytes_out,
        );

        Ok(Response::new(resp))
    }

    async fn read_shard(
        &self,
        request: Request<ReadShardRequest>,
    ) -> Result<Response<ReadShardResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let bytes_in = req.encoded_len() as u64;
        let shard_id = req.shard_id.ok_or_else(|| {
            self.grpc_metrics.read_shard.record(
                false,
                start.elapsed().as_micros() as u64,
                bytes_in,
                0,
            );
            Status::invalid_argument("missing shard_id")
        })?;

        let key = Self::shard_key(&shard_id.object_id, shard_id.stripe_id, shard_id.position);

        let location = self.shard_index.read().get(&key).cloned().ok_or_else(|| {
            self.grpc_metrics.read_shard.record(
                false,
                start.elapsed().as_micros() as u64,
                bytes_in,
                0,
            );
            Status::not_found("shard not found")
        })?;

        let disk = &self.disks[location.disk_idx];

        // Async read — same semantics, reactor stays free during I/O.
        let (_header, data) = disk
            .read_block_async(location.block_num)
            .await
            .map_err(|e| {
                self.grpc_metrics.read_shard.record(
                    false,
                    start.elapsed().as_micros() as u64,
                    bytes_in,
                    0,
                );
                // Unreadable is as good as gone: report it for rebuilding.
                self.mark_corrupt(&key, location.block_num);
                Status::data_loss(format!("shard is unreadable: {e}"))
            })?;

        debug!(
            "ReadShard: object={}, stripe={}, pos={}, size={}",
            hex::encode(&shard_id.object_id),
            shard_id.stripe_id,
            shard_id.position,
            data.len()
        );

        let timestamp = Self::current_timestamp();

        // Either the shard goes back in the response, or it is written into
        // the gateway's buffer over Transfer Engine and the response only
        // says how much landed there.
        let (data, rdma_len) = match req.rdma_dest.as_ref() {
            Some(dest) => {
                self.push_shard(&data, dest).await.inspect_err(|_| {
                    self.grpc_metrics.read_shard.record(
                        false,
                        start.elapsed().as_micros() as u64,
                        bytes_in,
                        0,
                    );
                })?;
                (Vec::new(), data.len() as u64)
            }
            None => (data, 0),
        };
        let bytes_out = data.len() as u64 + rdma_len;
        let resp = ReadShardResponse {
            data: data.into(),
            checksum: Some(Checksum {
                crc32c: location.crc32c,
                xxhash64: 0,
                sha256: vec![],
            }),
            timestamp,
            rdma_len,
        };
        self.grpc_metrics.read_shard.record(
            true,
            start.elapsed().as_micros() as u64,
            bytes_in,
            bytes_out,
        );

        Ok(Response::new(resp))
    }

    async fn delete_shard(
        &self,
        request: Request<DeleteShardRequest>,
    ) -> Result<Response<DeleteShardResponse>, Status> {
        let req = request.into_inner();
        let shard_id = req
            .shard_id
            .ok_or_else(|| Status::invalid_argument("missing shard_id"))?;

        let key = Self::shard_key(&shard_id.object_id, shard_id.stripe_id, shard_id.position);

        let removed = self.shard_index.write().remove(&key);
        // Mirror the removal in the persistent index so a future
        // restart doesn't resurrect the deleted shard.
        if removed.is_some()
            && let Err(e) = Self::forget_shard_location(&self.meta_store, &key)
        {
            warn!("Failed to persist shard delete for {key}: {e}");
        }

        // Return the block to the pool. This used to be a comment saying a
        // real implementation would do it, which meant storage was write-once
        // until the disk filled and then every write failed — with the
        // capacity readings still reporting the disk as empty, because those
        // came from a superblock field written at format time.
        //
        // Order matters: the index entry goes first, so a crash between the
        // two leaks a block rather than handing a live shard's block to the
        // next write.
        if let Some(loc) = removed.as_ref() {
            self.free_location(loc);
        }
        self.corrupt.write().remove(&key);

        Ok(Response::new(DeleteShardResponse {
            success: removed.is_some(),
        }))
    }

    async fn get_shard_meta(
        &self,
        request: Request<GetShardMetaRequest>,
    ) -> Result<Response<GetShardMetaResponse>, Status> {
        let req = request.into_inner();
        let shard_id = req
            .shard_id
            .ok_or_else(|| Status::invalid_argument("missing shard_id"))?;

        let key = Self::shard_key(&shard_id.object_id, shard_id.stripe_id, shard_id.position);

        let location = self
            .shard_index
            .read()
            .get(&key)
            .cloned()
            .ok_or_else(|| Status::not_found("shard not found"))?;

        let disk = &self.disks[location.disk_idx];

        Ok(Response::new(GetShardMetaResponse {
            shard_id: Some(shard_id),
            location: Some(BlockLocation {
                node_id: self.node_id.to_vec(),
                disk_id: self.disk_ids[location.disk_idx].to_vec(),
                offset: location.block_num * disk.block_size() as u64,
                size: location.size,
            }),
            size: location.size,
            checksum: Some(Checksum {
                crc32c: location.crc32c,
                xxhash64: 0,
                sha256: vec![],
            }),
            created_at: location.created_at,
        }))
    }

    async fn list_shards(
        &self,
        request: Request<ListShardsRequest>,
    ) -> Result<Response<ListShardsResponse>, Status> {
        let req = request.into_inner();
        let limit = if req.limit == 0 {
            100
        } else {
            req.limit as usize
        };

        let index = self.shard_index.read();
        let mut shards: Vec<GetShardMetaResponse> = Vec::new();

        for (key, location) in index.iter().take(limit) {
            // Parse key back to shard_id
            let parts: Vec<&str> = key.split(':').collect();
            if parts.len() != 3 {
                continue;
            }

            let object_id = hex::decode(parts[0]).unwrap_or_default();
            let stripe_id: u64 = parts[1].parse().unwrap_or_default();
            let position: u32 = parts[2].parse().unwrap_or_default();

            // Filter by object_id if specified
            if !req.object_id.is_empty() && object_id != req.object_id {
                continue;
            }

            let disk = &self.disks[location.disk_idx];

            shards.push(GetShardMetaResponse {
                shard_id: Some(objectio_proto::storage::ShardId {
                    object_id,
                    stripe_id,
                    position,
                }),
                location: Some(BlockLocation {
                    node_id: self.node_id.to_vec(),
                    disk_id: self.disk_ids[location.disk_idx].to_vec(),
                    offset: location.block_num * disk.block_size() as u64,
                    size: location.size,
                }),
                size: location.size,
                checksum: Some(Checksum {
                    crc32c: location.crc32c,
                    xxhash64: 0,
                    sha256: vec![],
                }),
                created_at: location.created_at,
            });
        }

        Ok(Response::new(ListShardsResponse {
            shards,
            next_token: vec![],
        }))
    }

    async fn health_check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        // Check if all disks are accessible
        let all_healthy = self.disks.iter().all(|d| d.verify_block(0).is_ok());

        let (status, message) = if all_healthy {
            (HealthStatus::Healthy, "All disks healthy".to_string())
        } else {
            (HealthStatus::Degraded, "Some disks have issues".to_string())
        };

        Ok(Response::new(HealthCheckResponse {
            status: status.into(),
            message,
        }))
    }

    async fn get_status(
        &self,
        request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
        let up_nodes = request.into_inner().up_nodes;
        let safety = if up_nodes.is_empty() {
            None
        } else {
            let up: std::collections::HashSet<Vec<u8>> = up_nodes.into_iter().collect();
            // A scan of every ObjectMeta this OSD holds; keep it off the
            // async worker where the runtime allows.
            let scan = || {
                self.usage.safety(
                    self.meta_store
                        .scan_prefix(&MetadataKey::all_object_meta_prefix())
                        .into_iter()
                        .chain(
                            self.meta_store
                                .scan_prefix(&MetadataKey::from_bytes(vec![b'v'])),
                        ),
                    &up,
                )
            };
            Some(
                if tokio::runtime::Handle::current().runtime_flavor()
                    == tokio::runtime::RuntimeFlavor::MultiThread
                {
                    tokio::task::block_in_place(scan)
                } else {
                    scan()
                },
            )
        };
        let mut total_capacity = 0u64;
        let mut used_capacity = 0u64;
        let mut disk_statuses = Vec::new();

        for (idx, disk) in self.disks.iter().enumerate() {
            let cap = disk.capacity();
            let free = disk.free_space();
            let used = cap - free;

            total_capacity += cap;
            used_capacity += used;

            let shard_count = self
                .shard_index
                .read()
                .values()
                .filter(|loc| loc.disk_idx == idx)
                .count() as u64;

            disk_statuses.push(DiskStatus {
                disk_id: self.disk_ids[idx].to_vec(),
                path: disk.path().to_string(),
                total_capacity: cap,
                used_capacity: used,
                status: "healthy".to_string(),
                shard_count,
            });
        }

        let shard_count = self.shard_index.read().len() as u64;
        let uptime = self.start_time.elapsed().as_secs();

        // Gather host/environment info
        let kubernetes_node = std::env::var("NODE_NAME").unwrap_or_default();
        let pod_name = std::env::var("POD_NAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_default();
        let hostname = gethostname::gethostname().to_string_lossy().to_string();
        let os_info = sys_info::os_type()
            .map(|t| {
                let rel = sys_info::os_release().unwrap_or_default();
                format!("{t} {rel}")
            })
            .unwrap_or_default();
        let cpu_cores = sys_info::cpu_num().unwrap_or(0) as u64;
        let memory_bytes = sys_info::mem_info()
            .map(|m| m.total * 1024) // mem_info returns KB
            .unwrap_or(0);

        Ok(Response::new(GetStatusResponse {
            node_id: self.node_id.to_vec(),
            node_name: if pod_name.is_empty() {
                format!("osd-{}", hex::encode(&self.node_id[..4]))
            } else {
                pod_name.clone()
            },
            disks: disk_statuses,
            total_capacity,
            used_capacity,
            shard_count,
            uptime_seconds: uptime,
            kubernetes_node,
            pod_name,
            os_info,
            hostname,
            cpu_cores,
            memory_bytes,
            version: env!("CARGO_PKG_VERSION").to_string(),
            bucket_usage: self.usage.snapshot(),
            safety,
        }))
    }

    // ============================================================
    // Object Metadata Operations (stored on primary OSD)
    // ============================================================

    async fn put_object_meta(
        &self,
        request: Request<PutObjectMetaRequest>,
    ) -> Result<Response<PutObjectMetaResponse>, Status> {
        let req = request.into_inner();

        let object = req
            .object
            .ok_or_else(|| Status::invalid_argument("missing object"))?;

        // Serialize ObjectMeta to bytes using protobuf
        let value = object.encode_to_vec();

        let _guard = self.usage.lock_key(&req.bucket, &req.key);

        // Always store as current version at m:{bucket}\0{key}
        let key = MetadataKey::object_meta(&req.bucket, &req.key);
        let old = self.stored_meta(&key);
        if !req.expected_object_id.is_empty()
            && old.as_ref().map(|o| o.object_id.as_slice())
                != Some(req.expected_object_id.as_slice())
        {
            return Err(Status::failed_precondition(format!(
                "{}/{} is no longer the object it was",
                req.bucket, req.key
            )));
        }
        self.meta_store
            .put(key, value.clone())
            .map_err(|e| Status::internal(format!("failed to store object metadata: {}", e)))?;
        self.usage
            .apply(&req.bucket, EntryKind::Current, old.as_ref(), Some(&object));

        // If versioning is enabled and version_id is set, also store version entry
        if req.versioning_enabled && !object.version_id.is_empty() {
            let version_key =
                MetadataKey::object_version(&req.bucket, &req.key, &object.version_id);
            let old = self.stored_meta(&version_key);
            self.meta_store
                .put(version_key, value)
                .map_err(|e| Status::internal(format!("failed to store version entry: {}", e)))?;
            self.usage
                .apply(&req.bucket, EntryKind::Version, old.as_ref(), Some(&object));
        }

        let timestamp = Self::current_timestamp();

        info!(
            "Stored object metadata: {}/{} ({} bytes, version={})",
            req.bucket, req.key, object.size, object.version_id
        );

        Ok(Response::new(PutObjectMetaResponse {
            success: true,
            timestamp,
        }))
    }

    async fn get_object_meta(
        &self,
        request: Request<GetObjectMetaRequest>,
    ) -> Result<Response<GetObjectMetaResponse>, Status> {
        let req = request.into_inner();

        // If version_id specified, look up specific version; otherwise get current
        let key = if req.version_id.is_empty() {
            MetadataKey::object_meta(&req.bucket, &req.key)
        } else {
            MetadataKey::object_version(&req.bucket, &req.key, &req.version_id)
        };

        // Lookup in metadata store
        match self.meta_store.get(&key) {
            Some(value) => {
                // Deserialize ObjectMeta from protobuf
                let object = ObjectMeta::decode(&value[..]).map_err(|e| {
                    Status::internal(format!("failed to decode object metadata: {}", e))
                })?;

                debug!("Found object metadata: {}/{}", req.bucket, req.key);

                Ok(Response::new(GetObjectMetaResponse {
                    object: Some(object),
                    found: true,
                }))
            }
            None => {
                debug!("Object metadata not found: {}/{}", req.bucket, req.key);

                Ok(Response::new(GetObjectMetaResponse {
                    object: None,
                    found: false,
                }))
            }
        }
    }

    async fn delete_object_meta(
        &self,
        request: Request<DeleteObjectMetaRequest>,
    ) -> Result<Response<DeleteObjectMetaResponse>, Status> {
        let req = request.into_inner();

        let _guard = self.usage.lock_key(&req.bucket, &req.key);

        if req.version_id.is_empty() {
            // Delete current version entry
            let key = MetadataKey::object_meta(&req.bucket, &req.key);
            let old = self.stored_meta(&key);
            self.meta_store.delete(&key).map_err(|e| {
                Status::internal(format!("failed to delete object metadata: {}", e))
            })?;
            self.usage
                .apply(&req.bucket, EntryKind::Current, old.as_ref(), None);
            info!("Deleted object metadata: {}/{}", req.bucket, req.key);
        } else {
            // Delete specific version entry
            let version_key = MetadataKey::object_version(&req.bucket, &req.key, &req.version_id);
            let old = self.stored_meta(&version_key);
            self.meta_store
                .delete(&version_key)
                .map_err(|e| Status::internal(format!("failed to delete version entry: {}", e)))?;
            self.usage
                .apply(&req.bucket, EntryKind::Version, old.as_ref(), None);
            info!(
                "Deleted version: {}/{} (version={})",
                req.bucket, req.key, req.version_id
            );
        }

        Ok(Response::new(DeleteObjectMetaResponse { success: true }))
    }

    async fn list_objects_meta(
        &self,
        request: Request<ListObjectsMetaRequest>,
    ) -> Result<Response<ListObjectsMetaResponse>, Status> {
        let req = request.into_inner();
        let max_keys = if req.max_keys == 0 {
            1000
        } else {
            req.max_keys as usize
        };

        // Empty bucket means "scan every primary-held ObjectMeta on
        // this OSD". Used by the cluster rebalancer to enumerate
        // candidates without driving per-bucket fan-out. Regular
        // bucket-scoped callers keep their existing semantics.
        let prefix = if req.bucket.is_empty() {
            MetadataKey::all_object_meta_prefix()
        } else {
            MetadataKey::object_meta_prefix(&req.bucket)
        };

        // Scan all objects in bucket (or cluster-wide when bucket="")
        let entries = self.meta_store.scan_prefix(&prefix);

        let mut objects = Vec::new();
        let mut count = 0;
        let mut last_key = String::new();

        // Cluster-wide pagination: object keys can repeat across
        // buckets (bucketA/file.txt vs bucketB/file.txt), so the
        // single `key` string isn't a total order. When bucket is
        // empty we cursor on `{bucket}\0{key}` instead — that matches
        // the underlying meta_store key order.
        let cluster_wide = req.bucket.is_empty();
        for (meta_key, value) in entries {
            if let Some((bucket_of, key)) = meta_key.parse_object_meta() {
                let cursor = if cluster_wide {
                    format!("{bucket_of}\0{key}")
                } else {
                    key.clone()
                };

                // Skip if before start_after
                if !req.start_after.is_empty() && cursor <= req.start_after {
                    continue;
                }

                // Apply prefix filter (only meaningful within a bucket)
                if !req.prefix.is_empty() && !key.starts_with(&req.prefix) {
                    continue;
                }

                // Skip if before continuation token
                if !req.continuation_token.is_empty() && cursor <= req.continuation_token {
                    continue;
                }

                // Check limit
                if count >= max_keys {
                    break;
                }

                // Decode object metadata
                if let Ok(object) = ObjectMeta::decode(&value[..]) {
                    last_key = cursor;
                    objects.push(for_listing(object));
                    count += 1;
                }
            }
        }

        let is_truncated = count >= max_keys;
        let next_token = if is_truncated {
            last_key
        } else {
            String::new()
        };

        Ok(Response::new(ListObjectsMetaResponse {
            objects,
            next_continuation_token: next_token,
            is_truncated,
            key_count: count as u32,
        }))
    }

    async fn find_objects_referencing_node(
        &self,
        request: Request<FindObjectsReferencingNodeRequest>,
    ) -> Result<Response<FindObjectsReferencingNodeResponse>, Status> {
        let req = request.into_inner();

        // 16-byte UUID validation. Unknown lengths are almost always a
        // client bug; fail fast rather than "no matches" which would be
        // misleading under a real drain.
        if req.draining_node_id.len() != 16 {
            return Err(Status::invalid_argument(
                "draining_node_id must be 16 bytes",
            ));
        }
        let needle = req.draining_node_id.as_slice();
        let limit = if req.limit == 0 {
            usize::MAX
        } else {
            req.limit as usize
        };

        // Scan every object_meta on this OSD (across all buckets) and
        // collect the ones whose any stripe has a ShardLocation on the
        // draining node. O(total objects on this OSD) — only runs when
        // an operator-triggered drain is actively sweeping, so the
        // linear scan is acceptable.
        let prefix = MetadataKey::all_object_meta_prefix();
        let entries = self.meta_store.scan_prefix(&prefix);
        let mut out: Vec<AffectedObject> = Vec::new();
        let mut truncated = false;

        for (meta_key, value) in entries {
            if out.len() >= limit {
                truncated = true;
                break;
            }
            // `m:` prefix also matches any future `m*`-rooted key we
            // might add. parse_object_meta is the canonical check —
            // skip anything that isn't a plain object_meta record.
            let Some((bucket, key)) = meta_key.parse_object_meta() else {
                continue;
            };
            let Ok(object) = objectio_proto::metadata::ObjectMeta::decode(&value[..]) else {
                continue;
            };

            let mut shards: Vec<AffectedShardRef> = Vec::new();
            for stripe in &object.stripes {
                for shard in &stripe.shards {
                    if shard.node_id == needle {
                        shards.push(AffectedShardRef {
                            stripe_id: stripe.stripe_id,
                            position: shard.position,
                        });
                    }
                }
            }

            if !shards.is_empty() {
                out.push(AffectedObject {
                    bucket,
                    key,
                    object_id: object.object_id.clone(),
                    shards,
                });
            }
        }

        debug!(
            "find_objects_referencing_node({}): {} objects affected (truncated={})",
            hex::encode(&req.draining_node_id),
            out.len(),
            truncated
        );

        Ok(Response::new(FindObjectsReferencingNodeResponse {
            objects: out,
            truncated,
        }))
    }

    async fn copy_object_meta(
        &self,
        request: Request<CopyObjectMetaRequest>,
    ) -> Result<Response<CopyObjectMetaResponse>, Status> {
        let req = request.into_inner();

        // Read source ObjectMeta from local store
        let src_key = MetadataKey::object_meta(&req.source_bucket, &req.source_key);
        let value = self
            .meta_store
            .get(&src_key)
            .ok_or_else(|| Status::not_found("source object not found on this OSD"))?;

        let mut object = ObjectMeta::decode(&value[..]).map_err(|e| {
            Status::internal(format!("failed to decode source object metadata: {e}"))
        })?;

        // Update metadata fields for the destination key
        let now = Self::current_timestamp();
        object.bucket = req.dest_bucket.clone();
        object.key = req.dest_key.clone();
        object.created_at = now;
        object.modified_at = now;
        // Generate a new ETag based on object_id + timestamp so dest has its own identity
        object.etag = format!("{:x}", Uuid::new_v4().as_u128());

        // Write dest ObjectMeta
        let _guard = self.usage.lock_key(&req.dest_bucket, &req.dest_key);
        let dst_key = MetadataKey::object_meta(&req.dest_bucket, &req.dest_key);
        let old = self.stored_meta(&dst_key);
        let dest_bytes = object.encode_to_vec();
        self.meta_store
            .put(dst_key, dest_bytes)
            .map_err(|e| Status::internal(format!("failed to store dest object metadata: {e}")))?;
        self.usage.apply(
            &req.dest_bucket,
            EntryKind::Current,
            old.as_ref(),
            Some(&object),
        );

        info!(
            "Copied object metadata: {}/{} -> {}/{}",
            req.source_bucket, req.source_key, req.dest_bucket, req.dest_key
        );

        Ok(Response::new(CopyObjectMetaResponse {
            object: Some(object),
        }))
    }

    type StreamListObjectsMetaStream =
        Pin<Box<dyn Stream<Item = Result<ListObjectsMetaChunk, Status>> + Send + 'static>>;

    async fn stream_list_objects_meta(
        &self,
        request: Request<ListObjectsMetaRequest>,
    ) -> Result<Response<Self::StreamListObjectsMetaStream>, Status> {
        const CHUNK_SIZE: usize = 500;

        let req = request.into_inner();
        let prefix = MetadataKey::object_meta_prefix(&req.bucket);
        let entries = self.meta_store.scan_prefix(&prefix);

        let mut chunks: Vec<ListObjectsMetaChunk> = Vec::new();
        let mut batch: Vec<ObjectMeta> = Vec::with_capacity(CHUNK_SIZE);

        for (meta_key, value) in entries {
            if let Some((_bucket, key)) = meta_key.parse_object_meta() {
                // Apply start_after / continuation_token cursor
                if !req.start_after.is_empty() && key <= req.start_after {
                    continue;
                }
                if !req.continuation_token.is_empty() && key <= req.continuation_token {
                    continue;
                }
                // Apply prefix filter
                if !req.prefix.is_empty() && !key.starts_with(&req.prefix) {
                    continue;
                }

                if let Ok(object) = ObjectMeta::decode(&value[..]) {
                    batch.push(for_listing(object));

                    if batch.len() >= CHUNK_SIZE {
                        let cursor = key.clone();
                        chunks.push(ListObjectsMetaChunk {
                            objects: std::mem::take(&mut batch),
                            next_start_after: cursor,
                            is_last: false,
                        });
                    }
                }
            }
        }

        // Emit the final (possibly partial) batch
        chunks.push(ListObjectsMetaChunk {
            objects: batch,
            next_start_after: String::new(),
            is_last: true,
        });

        let stream = futures::stream::iter(chunks.into_iter().map(Ok));
        Ok(Response::new(Box::pin(stream)))
    }

    async fn list_object_versions_meta(
        &self,
        request: Request<ListObjectVersionsMetaRequest>,
    ) -> Result<Response<ListObjectVersionsMetaResponse>, Status> {
        let req = request.into_inner();
        let max_keys = if req.max_keys == 0 {
            1000
        } else {
            req.max_keys as usize
        };

        // Scan version entries (v:{bucket}\0...)
        let prefix = MetadataKey::object_version_bucket_prefix(&req.bucket);
        let entries = self.meta_store.scan_prefix(&prefix);

        let mut versions = Vec::new();
        let mut count = 0;
        let mut last_key = String::new();
        let mut last_version_id = String::new();

        for (meta_key, value) in entries {
            if let Some((_bucket, key, version_id)) = meta_key.parse_object_version() {
                // Apply prefix filter
                if !req.prefix.is_empty() && !key.starts_with(&req.prefix) {
                    continue;
                }

                // Apply key_marker: skip entries at or before key_marker
                if !req.key_marker.is_empty() {
                    if key < req.key_marker {
                        continue;
                    }
                    if key == req.key_marker
                        && !req.version_id_marker.is_empty()
                        && version_id <= req.version_id_marker
                    {
                        continue;
                    }
                }

                if count >= max_keys {
                    break;
                }

                if let Ok(object) = ObjectMeta::decode(&value[..]) {
                    last_key = key;
                    last_version_id = version_id;
                    versions.push(for_listing(object));
                    count += 1;
                }
            }
        }

        let is_truncated = count >= max_keys;

        Ok(Response::new(ListObjectVersionsMetaResponse {
            versions,
            next_key_marker: if is_truncated {
                last_key
            } else {
                String::new()
            },
            next_version_id_marker: if is_truncated {
                last_version_id
            } else {
                String::new()
            },
            is_truncated,
        }))
    }
}

#[cfg(test)]
mod shard_index_tests {
    use super::{OsdService, SHARD_LOC_PREFIX, ShardLocation};
    use objectio_storage::metadata::{MetadataKey, MetadataStore, MetadataStoreConfig};

    fn store() -> (tempfile::TempDir, MetadataStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = MetadataStore::open_or_create(MetadataStoreConfig::with_data_dir(dir.path()))
            .expect("open metadata store");
        (dir, store)
    }

    fn loc(disk_idx: usize, block_num: u64) -> ShardLocation {
        ShardLocation {
            disk_idx,
            block_num,
            size: 64 * 1024,
            crc32c: 0xDEAD_BEEF,
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn a_shard_key_is_unique_per_object_stripe_and_position() {
        let a = [1u8; 16];
        let b = [2u8; 16];
        let keys = [
            OsdService::shard_key(&a, 0, 0),
            OsdService::shard_key(&a, 0, 1),
            OsdService::shard_key(&a, 1, 0),
            OsdService::shard_key(&b, 0, 0),
        ];
        let mut unique: Vec<&String> = keys.iter().collect();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), keys.len(), "two shards share one index key");
    }

    /// The object id is hex, so it is fixed-width and the `:` separators
    /// cannot be confused with its contents. Without that, an id ending in a
    /// digit and a stripe id could spell the same key as a different pair.
    #[test]
    fn a_shard_key_is_stable_and_readable() {
        assert_eq!(
            OsdService::shard_key(&[0xABu8; 4], 7, 3),
            "abababab:7:3".to_string()
        );
    }

    #[test]
    fn the_metadata_key_carries_the_prefix_and_gives_the_shard_key_back() {
        let sk = OsdService::shard_key(&[9u8; 16], 2, 5);
        let mk = OsdService::shard_loc_meta_key(&sk);
        let raw = mk.as_bytes();
        assert!(raw.starts_with(SHARD_LOC_PREFIX));
        assert_eq!(
            std::str::from_utf8(raw.strip_prefix(SHARD_LOC_PREFIX).unwrap()).unwrap(),
            sk
        );
    }

    /// The restart path, end to end.
    ///
    /// Before the index was persisted at all, `shard_index` started empty on
    /// every boot: the OSD reported zero shards to meta with a disk full of
    /// real data, and the allocator handed out block 0 over the top of it.
    /// This is the round trip that stops that.
    #[test]
    fn locations_written_before_a_restart_are_found_after_one() {
        let (_dir, s) = store();
        let written = [
            (OsdService::shard_key(&[1u8; 16], 0, 0), loc(0, 100)),
            (OsdService::shard_key(&[1u8; 16], 0, 1), loc(0, 101)),
            (OsdService::shard_key(&[2u8; 16], 3, 4), loc(1, 7)),
        ];
        for (key, l) in &written {
            OsdService::persist_shard_location(&s, key, l).expect("persist");
        }

        let rebuilt = OsdService::load_persisted_shard_index(&s);
        assert_eq!(rebuilt.len(), written.len());
        for (key, l) in &written {
            let got = rebuilt.get(key).unwrap_or_else(|| panic!("{key} missing"));
            assert_eq!(got.disk_idx, l.disk_idx);
            assert_eq!(got.block_num, l.block_num);
            assert_eq!(got.size, l.size);
            assert_eq!(got.crc32c, l.crc32c);
        }
    }

    /// A deleted shard must not come back on the next boot.
    ///
    /// It would re-mark its block used, so the block is never handed out
    /// again — the space is leaked in a way that survives restarts.
    #[test]
    fn a_forgotten_location_stays_forgotten() {
        let (_dir, s) = store();
        let keep = OsdService::shard_key(&[1u8; 16], 0, 0);
        let drop = OsdService::shard_key(&[1u8; 16], 0, 1);
        OsdService::persist_shard_location(&s, &keep, &loc(0, 1)).unwrap();
        OsdService::persist_shard_location(&s, &drop, &loc(0, 2)).unwrap();

        OsdService::forget_shard_location(&s, &drop).expect("forget");

        let rebuilt = OsdService::load_persisted_shard_index(&s);
        assert!(rebuilt.contains_key(&keep));
        assert!(
            !rebuilt.contains_key(&drop),
            "a deleted shard reappeared on reload and would re-mark its block used"
        );
    }

    /// The prefix is a filter, not a suggestion.
    ///
    /// The object layer writes ShardMeta under its own keys in the same store.
    /// If those were swept into the shard index, the OSD would mark blocks
    /// used that it does not own — or fail to deserialize and lose the whole
    /// scan.
    #[test]
    fn keys_belonging_to_another_family_are_not_read_as_shard_locations() {
        let (_dir, s) = store();
        let mine = OsdService::shard_key(&[1u8; 16], 0, 0);
        OsdService::persist_shard_location(&s, &mine, &loc(0, 1)).unwrap();

        for foreign in [&b"s:some-shard-meta"[..], b"osd_other:thing", b"zzz"] {
            s.put(MetadataKey::from_bytes(foreign.to_vec()), vec![1, 2, 3])
                .expect("put foreign key");
        }

        let rebuilt = OsdService::load_persisted_shard_index(&s);
        assert_eq!(
            rebuilt.len(),
            1,
            "the scan picked up keys outside its own prefix: {:?}",
            rebuilt.keys().collect::<Vec<_>>()
        );
        assert!(rebuilt.contains_key(&mine));
    }

    /// One corrupt entry does not take the rest of the index with it.
    ///
    /// A boot that gives up on the whole scan reports zero shards, which is
    /// the state that made the allocator overwrite live data.
    #[test]
    fn a_corrupt_entry_is_skipped_rather_than_abandoning_the_scan() {
        let (_dir, s) = store();
        for i in 0..3u8 {
            let k = OsdService::shard_key(&[i; 16], 0, 0);
            OsdService::persist_shard_location(&s, &k, &loc(0, u64::from(i))).unwrap();
        }
        s.put(
            OsdService::shard_loc_meta_key("deadbeef:0:0"),
            b"not bincode".to_vec(),
        )
        .expect("put corrupt entry");

        let rebuilt = OsdService::load_persisted_shard_index(&s);
        assert_eq!(rebuilt.len(), 3, "a corrupt entry cost the whole index");
    }

    #[test]
    fn an_empty_store_rebuilds_to_an_empty_index() {
        let (_dir, s) = store();
        assert!(OsdService::load_persisted_shard_index(&s).is_empty());
    }
}

#[cfg(test)]
mod grpc_write_tests {
    //! Shards sent as bytes in the WriteShard message.

    use super::*;
    use objectio_proto::storage::ShardId;
    use objectio_proto::storage::storage_service_server::StorageService;

    fn osd() -> (tempfile::TempDir, OsdService) {
        let dir = tempfile::tempdir().unwrap();
        let osd = OsdService::new(
            vec![dir.path().join("disk.raw").display().to_string()],
            64 * 1024,
            dir.path().join("state"),
        )
        .unwrap();
        (dir, osd)
    }

    fn shard_id() -> ShardId {
        ShardId {
            object_id: vec![9; 16],
            stripe_id: 0,
            position: 1,
        }
    }

    fn write_request(data: &[u8], crc: Option<u32>) -> WriteShardRequest {
        WriteShardRequest {
            shard_id: Some(shard_id()),
            data: data.to_vec().into(),
            ec_k: 4,
            ec_m: 2,
            checksum: crc.map(|crc32c| Checksum {
                crc32c,
                ..Default::default()
            }),
            rdma: None,
        }
    }

    async fn read_back(osd: &OsdService) -> Result<ReadShardResponse, Status> {
        osd.read_shard(Request::new(ReadShardRequest {
            shard_id: Some(shard_id()),
            ..Default::default()
        }))
        .await
        .map(Response::into_inner)
    }

    fn free_space(osd: &OsdService) -> u64 {
        osd.disks.iter().map(DiskManager::free_space).sum()
    }

    /// The gRPC twin of the rdma test of the same name: bytes damaged on the
    /// way must not be stored under a checksum computed from the damage.
    #[tokio::test]
    async fn a_shard_that_does_not_match_its_checksum_is_refused_and_not_stored() {
        let (_dir, osd) = osd();
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();
        let free_before = free_space(&osd);
        let wrong = crc32c::crc32c(&data) ^ 1;

        let err = osd
            .write_shard(Request::new(write_request(&data, Some(wrong))))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::DataLoss, "{err}");

        let err = read_back(&osd).await.unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::NotFound,
            "a refused shard was indexed"
        );
        assert_eq!(
            free_space(&osd),
            free_before,
            "a refused shard kept its blocks"
        );
    }

    #[tokio::test]
    async fn a_shard_that_matches_its_checksum_is_stored() {
        let (_dir, osd) = osd();
        let data = vec![0x5a; 70_000];
        osd.write_shard(Request::new(write_request(
            &data,
            Some(crc32c::crc32c(&data)),
        )))
        .await
        .unwrap();

        let resp = read_back(&osd).await.unwrap();
        assert_eq!(&resp.data[..], &data[..]);
        assert_eq!(resp.checksum.unwrap().crc32c, crc32c::crc32c(&data));
    }

    /// Older writers send no checksum; they keep working, and the OSD
    /// records the checksum of what it got.
    #[tokio::test]
    async fn a_shard_without_a_checksum_is_still_stored() {
        let (_dir, osd) = osd();
        let data = b"no checksum from this writer".to_vec();
        osd.write_shard(Request::new(write_request(&data, None)))
            .await
            .unwrap();

        let resp = read_back(&osd).await.unwrap();
        assert_eq!(&resp.data[..], &data[..]);
        assert_eq!(resp.checksum.unwrap().crc32c, crc32c::crc32c(&data));
    }
}

#[cfg(test)]
mod integrity_tests {
    //! Finding damaged shards (scrub, reads), reporting them, and replacing
    //! them; and the compare-and-set on ObjectMeta.

    use super::*;
    use objectio_proto::storage::ShardId;
    use objectio_proto::storage::storage_service_server::StorageService;

    fn osd() -> (tempfile::TempDir, OsdService) {
        let dir = tempfile::tempdir().unwrap();
        let osd = OsdService::new(
            vec![dir.path().join("disk.raw").display().to_string()],
            64 * 1024,
            dir.path().join("state"),
        )
        .unwrap();
        (dir, osd)
    }

    fn id(position: u32) -> ShardId {
        ShardId {
            object_id: vec![7; 16],
            stripe_id: 0,
            position,
        }
    }

    async fn write(osd: &OsdService, position: u32, data: &[u8]) {
        osd.write_shard(Request::new(WriteShardRequest {
            shard_id: Some(id(position)),
            data: data.to_vec().into(),
            ec_k: 4,
            ec_m: 2,
            checksum: Some(Checksum {
                crc32c: crc32c::crc32c(data),
                ..Default::default()
            }),
            ..Default::default()
        }))
        .await
        .unwrap();
    }

    async fn states(osd: &OsdService, positions: &[u32]) -> Vec<ShardState> {
        osd.check_shards(Request::new(CheckShardsRequest {
            shards: positions.iter().map(|p| id(*p)).collect(),
        }))
        .await
        .unwrap()
        .into_inner()
        .states
        .into_iter()
        .map(|s| ShardState::try_from(s).unwrap())
        .collect()
    }

    /// Flip one byte of `needle` where shard `position` lies in the disk
    /// file, the way a bad sector would.
    fn rot(dir: &tempfile::TempDir, osd: &OsdService, position: u32, needle: &[u8]) {
        use std::io::{Read, Seek, SeekFrom, Write};
        let loc = osd.shard_index.read()[&OsdService::shard_key(&[7; 16], 0, position)].clone();
        let block = u64::from(osd.disks[0].block_size());
        let start = osd.disks[0].block_offset(loc.block_num);
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join("disk.raw"))
            .unwrap();
        let mut bytes = vec![0; usize::try_from(block).unwrap() * 4];
        f.seek(SeekFrom::Start(start)).unwrap();
        f.read_exact(&mut bytes).unwrap();
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("shard bytes not found on disk");
        let at = start + (at + needle.len() / 2) as u64;
        let mut byte = [0u8];
        f.seek(SeekFrom::Start(at)).unwrap();
        f.read_exact(&mut byte).unwrap();
        f.seek(SeekFrom::Start(at)).unwrap();
        f.write_all(&[byte[0] ^ 0xff]).unwrap();
    }

    fn payload(seed: u8) -> Vec<u8> {
        (0..50_000u32).map(|i| (i % 241) as u8 ^ seed).collect()
    }

    #[tokio::test]
    async fn shards_are_reported_ok_or_missing() {
        let (_dir, osd) = osd();
        write(&osd, 0, &payload(1)).await;
        assert_eq!(
            states(&osd, &[0, 1]).await,
            vec![ShardState::Ok, ShardState::Missing]
        );
    }

    /// Rot that nobody reads is found by the scrubber; the shard is then
    /// refused to readers and reported for repair, and rewriting it clears
    /// that and gives its old blocks back.
    #[tokio::test]
    async fn the_scrubber_finds_rot_and_a_rewrite_repairs_it() {
        let (dir, osd) = osd();
        let data = payload(2);
        write(&osd, 0, &data).await;
        write(&osd, 1, &payload(3)).await;
        rot(&dir, &osd, 0, &data[1000..1064]);

        osd.scrub_pass(0).await;
        assert_eq!(
            states(&osd, &[0, 1]).await,
            vec![ShardState::Corrupt, ShardState::Ok]
        );
        let err = osd
            .read_shard(Request::new(ReadShardRequest {
                shard_id: Some(id(0)),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::DataLoss, "{err}");

        let free_before = osd.disks[0].free_space();
        write(&osd, 0, &data).await;
        assert_eq!(states(&osd, &[0]).await, vec![ShardState::Ok]);
        assert_eq!(
            osd.disks[0].free_space(),
            free_before,
            "the corrupt copy's blocks were not given back"
        );
        let got = osd
            .read_shard(Request::new(ReadShardRequest {
                shard_id: Some(id(0)),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(&got.data[..], &data[..]);
    }

    /// A read that hits rot reports it too, without waiting for a scrub.
    #[tokio::test]
    async fn a_read_that_hits_rot_reports_it() {
        let (dir, osd) = osd();
        let data = payload(4);
        write(&osd, 2, &data).await;
        rot(&dir, &osd, 2, &data[2000..2064]);
        let _ = osd
            .read_shard(Request::new(ReadShardRequest {
                shard_id: Some(id(2)),
                ..Default::default()
            }))
            .await;
        assert_eq!(states(&osd, &[2]).await, vec![ShardState::Corrupt]);
    }

    fn meta(object_id: u8) -> ObjectMeta {
        ObjectMeta {
            bucket: "b".into(),
            key: "k".into(),
            object_id: vec![object_id; 16],
            ..Default::default()
        }
    }

    async fn put(
        osd: &OsdService,
        object: ObjectMeta,
        expected: &[u8],
    ) -> Result<(), tonic::Status> {
        osd.put_object_meta(Request::new(PutObjectMetaRequest {
            bucket: "b".into(),
            key: "k".into(),
            object: Some(object),
            versioning_enabled: false,
            expected_object_id: expected.to_vec(),
        }))
        .await
        .map(drop)
    }

    /// The repairer's update must not undo a PUT that replaced the object
    /// after the repairer read it.
    #[tokio::test]
    async fn object_meta_is_only_replaced_if_it_is_still_the_expected_object() {
        let (_dir, osd) = osd();
        put(&osd, meta(1), &[]).await.unwrap();
        put(&osd, meta(2), &[]).await.unwrap(); // a PUT replaces it

        let err = put(&osd, meta(1), &[1; 16]).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        let stored = osd
            .stored_meta(&MetadataKey::object_meta("b", "k"))
            .unwrap();
        assert_eq!(
            stored.object_id,
            vec![2; 16],
            "the newer object was rolled back"
        );

        put(&osd, meta(2), &[2; 16]).await.unwrap();
    }
}

#[cfg(all(test, feature = "rdma"))]
mod rdma_tests {
    //! Shards in and out of a real `OsdService` over Transfer Engine. TCP
    //! mode by default; `OBJECTIO_TE_TEST_PROTOCOL=rdma` with
    //! `OBJECTIO_TE_TEST_HOST=<address on the RDMA interface>` runs them over
    //! verbs.

    use super::*;
    use crate::rdma::RdmaStaging;
    use objectio_proto::storage::ShardId;
    use objectio_proto::storage::storage_service_server::StorageService;
    use objectio_transport_te::{Engine, EngineConfig, Protocol, Registration, SlotPool};

    const MIB: usize = 1024 * 1024;

    fn protocol_and_host() -> (Protocol, String) {
        let protocol = match std::env::var("OBJECTIO_TE_TEST_PROTOCOL").as_deref() {
            Ok("rdma") => Protocol::Rdma,
            _ => Protocol::Tcp,
        };
        let host = std::env::var("OBJECTIO_TE_TEST_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        (protocol, host)
    }

    /// An OSD with rdma enabled, and a "gateway": an engine with a
    /// remote-accessible pool that shards move out of and into.
    struct Rig {
        _dir: tempfile::TempDir,
        osd: OsdService,
        gateway: Arc<Engine>,
        pool: SlotPool,
        _registration: Registration,
    }

    fn rig() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let osd = OsdService::new(
            vec![dir.path().join("disk.raw").display().to_string()],
            64 * 1024,
            dir.path().join("state"),
        )
        .unwrap();
        let (protocol, host) = protocol_and_host();
        osd.enable_rdma(RdmaStaging::start(protocol, &host, 4).unwrap());
        let gateway = Engine::start(&EngineConfig { protocol, host }).unwrap();
        let pool = SlotPool::new(4 * MIB, 2).unwrap();
        let registration = gateway.register(&pool, true).unwrap();
        Rig {
            _dir: dir,
            osd,
            gateway,
            pool,
            _registration: registration,
        }
    }

    fn shard(len: usize) -> Vec<u8> {
        (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect()
    }

    fn shard_id() -> ShardId {
        ShardId {
            object_id: vec![7; 16],
            stripe_id: 0,
            position: 2,
        }
    }

    fn write_request(
        rig: &Rig,
        src: &objectio_transport_te::Slot,
        data: &[u8],
        crc: Option<u32>,
    ) -> WriteShardRequest {
        WriteShardRequest {
            shard_id: Some(shard_id()),
            ec_k: 4,
            ec_m: 2,
            checksum: crc.map(|crc32c| Checksum {
                crc32c,
                ..Default::default()
            }),
            rdma: Some(RdmaBuffer {
                segment: rig.gateway.segment().to_string(),
                addr: src.addr(),
                len: data.len() as u64,
            }),
            ..Default::default()
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_shard_goes_in_and_comes_back_out_over_transfer_engine() {
        let rig = rig();
        assert!(!rig.osd.te_segment().is_empty());

        // An odd length, so nothing lines up with a block by accident.
        let data = shard(MIB + 123);
        let mut src = rig.pool.acquire().unwrap();
        src.as_mut_slice()[..data.len()].copy_from_slice(&data);
        let req = write_request(&rig, &src, &data, Some(crc32c::crc32c(&data)));
        rig.osd.write_shard(Request::new(req)).await.unwrap();

        // Stored intact: read it back as gRPC bytes.
        let resp = rig
            .osd
            .read_shard(Request::new(ReadShardRequest {
                shard_id: Some(shard_id()),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(&resp.data[..], &data[..]);

        // And read it back into the gateway over Transfer Engine.
        let dest = rig.pool.acquire().unwrap();
        let resp = rig
            .osd
            .read_shard(Request::new(ReadShardRequest {
                shard_id: Some(shard_id()),
                rdma_dest: Some(RdmaBuffer {
                    segment: rig.gateway.segment().to_string(),
                    addr: dest.addr(),
                    len: dest.capacity() as u64,
                }),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(resp.data.is_empty());
        assert_eq!(resp.rdma_len, data.len() as u64);
        assert_eq!(&dest.as_slice()[..data.len()], &data[..]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_shard_that_does_not_match_its_checksum_is_refused_and_not_stored() {
        let rig = rig();
        let data = shard(64 * 1024);
        let mut src = rig.pool.acquire().unwrap();
        src.as_mut_slice()[..data.len()].copy_from_slice(&data);
        let wrong = crc32c::crc32c(&data) ^ 1;
        let err = rig
            .osd
            .write_shard(Request::new(write_request(&rig, &src, &data, Some(wrong))))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::DataLoss, "{err}");

        let err = rig
            .osd
            .read_shard(Request::new(ReadShardRequest {
                shard_id: Some(shard_id()),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::NotFound,
            "a refused shard was indexed"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_rdma_write_without_a_checksum_is_refused() {
        let rig = rig();
        let data = shard(4096);
        let src = rig.pool.acquire().unwrap();
        let err = rig
            .osd
            .write_shard(Request::new(write_request(&rig, &src, &data, None)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
    }
}
