//! OSD gRPC service implementation

use futures::stream::Stream;
use objectio_proto::metadata::ObjectMeta;
use objectio_proto::storage::{
    AffectedObject,
    AffectedShardRef,
    BlockLocation,
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
    ReadShardRequest,
    ReadShardResponse,
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
        let persisted = Self::load_persisted_shard_index(&meta_store);
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
            if let Err(e) = disks[loc.disk_idx].mark_block_used(loc.block_num) {
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
        Ok(Self {
            node_id,
            disks,
            disk_ids,
            shard_index: RwLock::new(persisted),
            meta_store: Arc::new(meta_store),
            start_time: Instant::now(),
            next_disk: RwLock::new(0),
            grpc_metrics: Arc::new(GrpcMetrics::default()),
        })
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
    /// Used at registration time so meta can sum capacity across OSDs and
    /// enforce the license's `max_raw_capacity_bytes` cap.
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

            disks.push(DiskStatusInfo {
                path: disk.path().to_string(),
                capacity,
                used,
                shard_count,
                status: "healthy".to_string(), // TODO: Check actual health
                read_errors: stats.read_errors.load(std::sync::atomic::Ordering::Relaxed),
                write_errors: stats
                    .write_errors
                    .load(std::sync::atomic::Ordering::Relaxed),
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
    fn allocate_block(&self, disk_idx: usize) -> Result<u64, Status> {
        self.disks[disk_idx].allocate_block().map_err(|e| {
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

#[tonic::async_trait]
impl StorageService for OsdService {
    async fn write_shard(
        &self,
        request: Request<WriteShardRequest>,
    ) -> Result<Response<WriteShardResponse>, Status> {
        let start = Instant::now();
        let req = request.into_inner();
        let bytes_in = req.data.len() as u64;
        let shard_id = req.shard_id.ok_or_else(|| {
            self.grpc_metrics
                .write_shard
                .record(false, start.elapsed().as_micros() as u64, 0, 0);
            Status::invalid_argument("missing shard_id")
        })?;

        debug!(
            "WriteShard: object={}, stripe={}, pos={}, size={}",
            hex::encode(&shard_id.object_id),
            shard_id.stripe_id,
            shard_id.position,
            req.data.len()
        );

        // Select disk and allocate block
        let disk_idx = self.select_disk_for_write();
        let block_num = self.allocate_block(disk_idx)?;

        let disk = &self.disks[disk_idx];

        // Prepare object_id as fixed array
        let mut object_id = [0u8; 16];
        let copy_len = shard_id.object_id.len().min(16);
        object_id[..copy_len].copy_from_slice(&shard_id.object_id[..copy_len]);

        // Write block through the async IoBackend — the tokio
        // reactor stays free during the syscall / io_uring wait. On
        // Linux + --features io-uring this is +25% throughput on
        // 4 MiB stripes vs the old sync path (see storage-io-levels.md).
        disk.write_block_async(block_num, object_id, shard_id.stripe_id, &req.data)
            .await
            .map_err(|e| Status::internal(format!("write failed: {}", e)))?;

        disk.sync()
            .map_err(|e| Status::internal(format!("sync failed: {}", e)))?;

        // Calculate checksum
        let crc32c = crc32c::crc32c(&req.data);

        // Store location in index
        let key = Self::shard_key(&shard_id.object_id, shard_id.stripe_id, shard_id.position);
        let timestamp = Self::current_timestamp();

        let loc = ShardLocation {
            disk_idx,
            block_num,
            size: req.data.len() as u32,
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
        self.shard_index.write().insert(key.clone(), loc);

        info!(
            "Wrote shard: disk={}, block={}, size={}, crc32c={:08x}",
            disk_idx,
            block_num,
            req.data.len(),
            crc32c
        );

        let resp = WriteShardResponse {
            location: Some(BlockLocation {
                node_id: self.node_id.to_vec(),
                disk_id: self.disk_ids[disk_idx].to_vec(),
                offset: block_num * disk.block_size() as u64,
                size: req.data.len() as u32,
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
                Status::internal(format!("read failed: {}", e))
            })?;

        debug!(
            "ReadShard: object={}, stripe={}, pos={}, size={}",
            hex::encode(&shard_id.object_id),
            shard_id.stripe_id,
            shard_id.position,
            data.len()
        );

        let timestamp = Self::current_timestamp();

        let resp = ReadShardResponse {
            data,
            checksum: Some(Checksum {
                crc32c: location.crc32c,
                xxhash64: 0,
                sha256: vec![],
            }),
            timestamp,
        };
        let bytes_out = resp.data.len() as u64;
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
        if let Some(loc) = removed.as_ref()
            && loc.disk_idx < self.disks.len()
        {
            let disk = &self.disks[loc.disk_idx];
            match disk.free_block(loc.block_num) {
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
        _request: Request<GetStatusRequest>,
    ) -> Result<Response<GetStatusResponse>, Status> {
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

        // Always store as current version at m:{bucket}\0{key}
        let key = MetadataKey::object_meta(&req.bucket, &req.key);
        self.meta_store
            .put(key, value.clone())
            .map_err(|e| Status::internal(format!("failed to store object metadata: {}", e)))?;

        // If versioning is enabled and version_id is set, also store version entry
        if req.versioning_enabled && !object.version_id.is_empty() {
            let version_key =
                MetadataKey::object_version(&req.bucket, &req.key, &object.version_id);
            self.meta_store
                .put(version_key, value)
                .map_err(|e| Status::internal(format!("failed to store version entry: {}", e)))?;
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

        if req.version_id.is_empty() {
            // Delete current version entry
            let key = MetadataKey::object_meta(&req.bucket, &req.key);
            self.meta_store.delete(&key).map_err(|e| {
                Status::internal(format!("failed to delete object metadata: {}", e))
            })?;
            info!("Deleted object metadata: {}/{}", req.bucket, req.key);
        } else {
            // Delete specific version entry
            let version_key = MetadataKey::object_version(&req.bucket, &req.key, &req.version_id);
            self.meta_store
                .delete(&version_key)
                .map_err(|e| Status::internal(format!("failed to delete version entry: {}", e)))?;
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
                    objects.push(object);
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
        let dst_key = MetadataKey::object_meta(&req.dest_bucket, &req.dest_key);
        let dest_bytes = object.encode_to_vec();
        self.meta_store
            .put(dst_key, dest_bytes)
            .map_err(|e| Status::internal(format!("failed to store dest object metadata: {e}")))?;

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
                    batch.push(object);

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
                    versions.push(object);
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
