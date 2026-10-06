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
    NoteChunksRequest,
    NoteChunksResponse,
    // Object metadata RPCs
    PutObjectMetaRequest,
    PutObjectMetaResponse,
    RdmaBuffer,
    ReadShardRequest,
    ReadShardResponse,
    ResetChunkNotesRequest,
    ResetChunkNotesResponse,
    ShardState,
    WriteShardRequest,
    WriteShardResponse,
    health_check_response::Status as HealthStatus,
    storage_service_server::StorageService,
};
use objectio_storage::DiskManager;
use objectio_storage::metadata::{MetaIndex, MetadataKey, MetadataStoreConfig};
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
use tracing::{debug, error, info, warn};
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
    pub stream_list_objects_meta: GrpcMethodMetrics,
    pub health_check: GrpcMethodMetrics,
    pub get_status: GrpcMethodMetrics,
}

impl GrpcMetrics {
    /// Shard bytes moved, in Prometheus format. Request counts and latency
    /// for every method come from the transport layer (`RPC_METRICS`).
    pub fn export_prometheus(&self, osd_id: &str) -> String {
        let mut output = String::with_capacity(1024);
        let methods = [
            ("WriteShard", &self.write_shard),
            ("ReadShard", &self.read_shard),
        ];
        for (name, help, load) in [
            (
                "objectio_osd_grpc_bytes_received_total",
                "Bytes of shard requests received, by method",
                (|m: &GrpcMethodMetrics| m.bytes_received.load(Ordering::Relaxed))
                    as fn(&GrpcMethodMetrics) -> u64,
            ),
            (
                "objectio_osd_grpc_bytes_sent_total",
                "Bytes of shard responses sent, by method",
                |m: &GrpcMethodMetrics| m.bytes_sent.load(Ordering::Relaxed),
            ),
        ] {
            writeln!(output, "# HELP {name} {help}").unwrap();
            writeln!(output, "# TYPE {name} counter").unwrap();
            for (method, metrics) in &methods {
                writeln!(
                    output,
                    "{name}{{osd_id=\"{osd_id}\",method=\"{method}\"}} {}",
                    load(metrics)
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

/// Run `f`, which blocks (a WAL sync, a shell-out), moving off the runtime
/// worker where the runtime allows, so other tasks keep running meanwhile.
fn blocking<T>(f: impl FnOnce() -> T) -> T {
    if tokio::runtime::Handle::current().runtime_flavor()
        == tokio::runtime::RuntimeFlavor::MultiThread
    {
        tokio::task::block_in_place(f)
    } else {
        f()
    }
}

#[cfg(test)]
thread_local! {
    /// Tests: make recording (or forgetting) a shard's location fail, as an
    /// unwritable or full metadata log would. Per thread, so a test's
    /// failures stay in that test.
    static LOCATION_RECORDS_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn location_records_fail() -> bool {
    LOCATION_RECORDS_FAIL.with(std::cell::Cell::get)
}

/// Shard location stored in memory. Mirrored to the persistent
/// MetadataStore on every write so pod restarts can rebuild the
/// in-memory index from the WAL — without this, the OSD forgets
/// which shards it holds the moment its process restarts, and
/// meta thinks every OSD is empty.
#[derive(Clone, Debug)]
struct ShardLocation {
    disk_idx: usize,
    block_num: u64,
    size: u32,
    crc32c: u32,
    created_at: u64,
    /// A small shard's bytes, kept in its record rather than in a disk block
    /// (B21: written, with its object's metadata, in one log flush);
    /// `disk_idx` is then [`SMALL_DISK`].
    small: Option<Vec<u8>>,
}

/// The `disk_idx` of a shard kept in its record (B21).
const SMALL_DISK: usize = u32::MAX as usize;

use objectio_common::version::SMALL_SHARD_MAX;

/// How a [`ShardLocation`] is stored in the metadata log: protobuf.
#[derive(Clone, PartialEq, ::prost::Message)]
struct ShardLocationRecord {
    #[prost(uint32, tag = "1")]
    disk_idx: u32,
    #[prost(uint64, tag = "2")]
    block_num: u64,
    #[prost(uint32, tag = "3")]
    size: u32,
    #[prost(uint32, tag = "4")]
    crc32c: u32,
    #[prost(uint64, tag = "5")]
    created_at: u64,
    /// A small shard's bytes (B21), with `disk_idx` `u32::MAX`.
    #[prost(bytes = "vec", tag = "6")]
    small: Vec<u8>,
}

impl ShardLocation {
    fn to_bytes(&self) -> Vec<u8> {
        prost::Message::encode_to_vec(&ShardLocationRecord {
            disk_idx: u32::try_from(self.disk_idx).unwrap_or(u32::MAX),
            block_num: self.block_num,
            size: self.size,
            crc32c: self.crc32c,
            created_at: self.created_at,
            small: self.small.clone().unwrap_or_default(),
        })
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, prost::DecodeError> {
        let r = <ShardLocationRecord as prost::Message>::decode(bytes)?;
        let small = (r.disk_idx == u32::MAX).then_some(r.small);
        Ok(Self {
            disk_idx: if small.is_some() {
                SMALL_DISK
            } else {
                r.disk_idx as usize
            },
            block_num: r.block_num,
            size: r.size,
            crc32c: r.crc32c,
            created_at: r.created_at,
            small,
        })
    }
}

/// Prefix under which the OSD persists its shard-location index in
/// MetadataStore. Keys are `{PREFIX}{shard_key_string}`. The prefix
/// keeps us from colliding with the ShardMeta entries the object
/// layer writes under its own 's'-prefixed keys.
const SHARD_LOC_PREFIX: &[u8] = b"osd_loc:";

/// Where each shard on this OSD is: its persisted `SHARD_LOC` entry, read
/// from the metadata store when asked. Only counts are kept in memory; the
/// in-memory map of every shard this held made an OSD's memory grow with
/// its shard count (B22).
struct ShardIndex {
    store: Arc<dyn MetaIndex>,
    /// Shards per disk.
    per_disk: Vec<AtomicU64>,
    /// Shards kept in their records (B21).
    small: AtomicU64,
    /// A key's read-modify-write (replace, remove) runs under its stripe.
    stripes: Vec<parking_lot::Mutex<()>>,
}

impl ShardIndex {
    const STRIPES: usize = 256;

    fn new(store: Arc<dyn MetaIndex>, num_disks: usize) -> Self {
        Self {
            store,
            per_disk: (0..num_disks).map(|_| AtomicU64::new(0)).collect(),
            small: AtomicU64::new(0),
            stripes: (0..Self::STRIPES)
                .map(|_| parking_lot::Mutex::new(()))
                .collect(),
        }
    }

    fn lock(&self, key: &str) -> parking_lot::MutexGuard<'_, ()> {
        use std::hash::{Hash, Hasher};
        let mut h = std::hash::DefaultHasher::new();
        key.hash(&mut h);
        let i = (h.finish() % Self::STRIPES as u64) as usize;
        self.stripes[i].lock()
    }

    fn get(&self, key: &str) -> Option<ShardLocation> {
        let v = self.store.get(&OsdService::shard_loc_meta_key(key))?;
        ShardLocation::from_bytes(&v)
            .inspect_err(|e| warn!("corrupt ShardLocation entry {key}: {e}"))
            .ok()
    }

    fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    fn counter(&self, l: &ShardLocation) -> Option<&AtomicU64> {
        if l.small.is_some() {
            Some(&self.small)
        } else {
            self.per_disk.get(l.disk_idx)
        }
    }

    fn counted(&self, gone: Option<&ShardLocation>, new: Option<&ShardLocation>) {
        if let Some(c) = gone.and_then(|l| self.counter(l)) {
            c.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(c) = new.and_then(|l| self.counter(l)) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record `loc` for `key` durably; what it replaced, if anything.
    fn record(&self, key: &str, loc: &ShardLocation) -> Result<Option<ShardLocation>, String> {
        let _key = self.lock(key);
        let old = self.get(key);
        OsdService::persist_shard_location(&*self.store, key, loc)?;
        self.counted(old.as_ref(), Some(loc));
        Ok(old)
    }

    /// Record `loc` for `key` and the `extra` entries in one log batch (one
    /// flush, all or nothing: B21's small shard with its object's
    /// metadata); what the location replaced, if anything.
    fn record_with(
        &self,
        key: &str,
        loc: &ShardLocation,
        mut extra: Vec<(MetadataKey, Vec<u8>)>,
    ) -> Result<Option<ShardLocation>, String> {
        let _key = self.lock(key);
        let old = self.get(key);
        extra.push((OsdService::shard_loc_meta_key(key), loc.to_bytes()));
        self.store
            .batch_put(extra)
            .map_err(|e| format!("record shard {key} with its metadata: {e}"))?;
        self.counted(old.as_ref(), Some(loc));
        Ok(old)
    }

    /// Forget `key` durably; where the shard was, if it was here. Its
    /// blocks may be freed only after this returns.
    fn forget(&self, key: &str) -> Result<Option<ShardLocation>, String> {
        let _key = self.lock(key);
        let Some(old) = self.get(key) else {
            return Ok(None);
        };
        OsdService::forget_shard_location(&*self.store, key)?;
        self.counted(Some(&old), None);
        Ok(Some(old))
    }

    /// Up to `n` shards in key order, after `after`: a page, so walking
    /// every shard (scrub, purge) holds one page at a time.
    fn page(&self, after: Option<&str>, n: usize) -> Vec<(String, ShardLocation)> {
        let prefix = MetadataKey::from_bytes(SHARD_LOC_PREFIX.to_vec());
        let after = after.map(OsdService::shard_loc_meta_key);
        let mut out = Vec::with_capacity(n.min(4096));
        self.store
            .for_each_prefix(&prefix, after.as_ref(), &mut |k: &[u8], v: &[u8]| {
                if let (Some(key), Ok(loc)) = (
                    k.strip_prefix(SHARD_LOC_PREFIX)
                        .and_then(|k| std::str::from_utf8(k).ok()),
                    ShardLocation::from_bytes(v),
                ) {
                    out.push((key.to_string(), loc));
                }
                out.len() < n
            });
        out
    }

    fn count(&self) -> u64 {
        self.per_disk
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum::<u64>()
            + self.small.load(Ordering::Relaxed)
    }

    fn count_on(&self, disk_idx: usize) -> u64 {
        self.per_disk
            .get(disk_idx)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }
}

/// Dedup dry-run: chunk fingerprints this OSD has been told about, each
/// with how many times. See objectio-docs `architecture/design/core/dedup.md`.
const DEDUP_NOTE_PREFIX: &[u8] = b"dedup_note:";

fn dedup_note_key(fingerprint: &[u8]) -> MetadataKey {
    MetadataKey::from_bytes([DEDUP_NOTE_PREFIX, fingerprint].concat())
}

/// OSD service state
/// The default share of a disk client writes may fill: the rest is kept for
/// repair, drain and backfill (as Ceph's `full_ratio`).
pub const DEFAULT_FULL_RATIO: f64 = 0.95;

/// The share of the metadata store's filesystem that must stay free: below
/// it, a small shard (B21) goes to a disk block instead, so the index keeps
/// room for metadata, which has nowhere else to go.
const META_SPACE_FREE_FLOOR: f64 = 0.10;

/// Whether the metadata store's filesystem is below
/// [`META_SPACE_FREE_FLOOR`], looked up at most every few seconds.
struct MetaSpace {
    dir: PathBuf,
    /// When it was last looked up (ms since the service started), and the
    /// answer.
    checked_ms: AtomicU64,
    low: std::sync::atomic::AtomicBool,
    started: Instant,
}

impl MetaSpace {
    const EVERY_MS: u64 = 5_000;

    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            checked_ms: AtomicU64::new(u64::MAX),
            low: std::sync::atomic::AtomicBool::new(false),
            started: Instant::now(),
        }
    }

    fn low(&self) -> bool {
        let now = self.started.elapsed().as_millis() as u64;
        let at = self.checked_ms.load(Ordering::Relaxed);
        if at == u64::MAX || now.saturating_sub(at) >= Self::EVERY_MS {
            self.checked_ms.store(now, Ordering::Relaxed);
            let low = match nix::sys::statvfs::statvfs(&self.dir) {
                Ok(st) if st.blocks() > 0 => {
                    (st.blocks_available() as f64) / (st.blocks() as f64) < META_SPACE_FREE_FLOOR
                }
                // Unknown: keep the shard out of the index, to be safe.
                _ => true,
            };
            #[cfg(test)]
            let low = low || META_SPACE_LOW.with(std::cell::Cell::get);
            self.low.store(low, Ordering::Relaxed);
        }
        self.low.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
thread_local! {
    /// Tests: report the metadata store's filesystem as nearly full.
    static META_SPACE_LOW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// How long a count of objects at risk serves `GetStatus` before it is
/// counted again: each count is a scan of every ObjectMeta the OSD holds.
const SAFETY_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// A count of objects at risk: when, and for which nodes up.
type SafetyCount = (Instant, Vec<Vec<u8>>, objectio_proto::storage::ObjectSafety);

/// The last count of objects at risk, for which set of nodes up, and when;
/// and the one scan that may be running.
#[derive(Default)]
struct SafetyCache {
    last: parking_lot::Mutex<Option<SafetyCount>>,
    scanning: parking_lot::Mutex<()>,
    /// Counts taken since start.
    scans: AtomicU64,
}

pub struct OsdService {
    node_id: [u8; 16],
    /// The share of a disk client writes may fill (B3); the rest is kept
    /// for writes that restore redundancy.
    full_ratio: f64,
    disks: Vec<DiskManager>,
    disk_ids: Vec<[u8; 16]>,
    /// Shard index: object_id:stripe_id:position -> location (in-memory cache)
    shard_index: ShardIndex,
    /// Persistent metadata store (WAL + B-tree + ARC cache)
    meta_store: Arc<dyn MetaIndex>,
    start_time: Instant,
    /// Round-robin disk selection for writes
    next_disk: RwLock<usize>,
    /// gRPC metrics collector
    grpc_metrics: Arc<GrpcMetrics>,
    /// Per-bucket usage of the objects this OSD is primary for
    usage: UsageTracker,
    /// The last count of objects at risk, for `GetStatus` (B28: it was a
    /// scan of every ObjectMeta on every poll, from every gateway).
    safety: SafetyCache,
    /// Renders this OSD's Prometheus exposition for `GetMetrics`. Set once
    /// the metrics state exists, which is after the service is built.
    metrics_renderer: std::sync::OnceLock<MetricsRenderer>,
    /// Shards that cannot be read back intact — failing their checksum or
    /// unreadable — found by the scrubber or a read. Kept until the shard is rewritten; reported through
    /// `CheckShards` so Meta's repairer rebuilds them. In memory only: after
    /// a restart the next scrub pass finds them again.
    corrupt: RwLock<std::collections::HashSet<String>>,
    /// Whether the metadata store's filesystem has room for small shards.
    meta_space: MetaSpace,
    scrub: ScrubStats,
    /// Transfer Engine and staging pool, once enabled at startup. Without it
    /// every shard arrives and leaves as gRPC bytes.
    #[cfg(feature = "rdma")]
    rdma: std::sync::OnceLock<crate::rdma::RdmaStaging>,
}

type MetricsRenderer = Box<dyn Fn() -> String + Send + Sync>;

/// Time of each shard's disk operation on this OSD: `write` (the block),
/// `sync` (making it durable before the write is acknowledged), `read`.
static DISK_SECONDS: std::sync::LazyLock<objectio_common::histogram::HistogramVec> =
    std::sync::LazyLock::new(|| {
        objectio_common::histogram::HistogramVec::new(objectio_common::histogram::LATENCY_BUCKETS)
    });

/// Disk operation latency, as a Prometheus family.
pub fn render_disk_metrics(out: &mut String, osd_label: &str) {
    DISK_SECONDS.render(
        out,
        "objectio_osd_disk_seconds",
        "Time of one shard disk operation: write, sync (before the write is acknowledged), read",
        osd_label,
    );
}

/// What the scrubber has done since the OSD started.
#[derive(Default)]
struct ScrubStats {
    passes: AtomicU64,
    shards: AtomicU64,
    bytes: AtomicU64,
    corrupt: AtomicU64,
    last_pass_ms: AtomicU64,
    last_pass_end: AtomicU64,
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
        Self::new_with_cache(
            disk_paths,
            block_size,
            data_dir,
            MetadataStoreConfig::default().cache_bytes,
        )
    }

    /// [`Self::new`], the metadata index's page cache at most `cache_bytes`.
    pub fn new_with_cache(
        disk_paths: Vec<String>,
        block_size: u32,
        data_dir: PathBuf,
        cache_bytes: usize,
    ) -> Result<Self, String> {
        Self::new_with_store(disk_paths, block_size, data_dir, |c| {
            c.cache_bytes = cache_bytes;
        })
    }

    /// [`Self::new`], the metadata store's settings changed by `tune` (the
    /// crash test makes its checkpoints and log truncations frequent).
    pub fn new_with_store(
        disk_paths: Vec<String>,
        block_size: u32,
        data_dir: PathBuf,
        tune: impl FnOnce(&mut MetadataStoreConfig),
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
                Err(open_error) => {
                    // Formatted only when blank: a disk that fails to open
                    // for any other reason (an I/O error, a superblock torn
                    // in both copies) holds shards, and formatting it was
                    // the OSD destroying them. It stays as it is and the
                    // OSD doesn't start, saying why.
                    if std::path::Path::new(path).exists() {
                        match objectio_storage::is_blank(path) {
                            Ok(true) => {}
                            Ok(false) => {
                                return Err(format!(
                                    "disk {path} has data but cannot be opened ({open_error}); \
                                     not formatting it. Check the device, or wipe it to \
                                     replace it."
                                ));
                            }
                            Err(e) => {
                                return Err(format!(
                                    "disk {path} cannot be opened ({open_error}) or read ({e}); \
                                     not formatting it"
                                ));
                            }
                        }
                    }
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
        let mut meta_config = MetadataStoreConfig::with_data_dir(&data_dir);
        tune(&mut meta_config);
        let meta_space = MetaSpace::new(meta_config.data_dir.clone());
        let meta_store = objectio_storage::metadata::open(meta_config)
            .map_err(|e| format!("Failed to open metadata store: {}", e))?;

        info!(
            "OSD initialized with {} disks, metadata at {:?}",
            disks.len(),
            data_dir
        );

        let num_disks = disks.len();
        // Rebuild the in-memory shard index from persisted entries
        // (replayed from its log when the metadata index was opened
        // above). Before this step the OSD used to report 0 shards on
        // every restart even though disk.raw was full.
        let shard_index = ShardIndex::new(Arc::clone(&meta_store), num_disks);
        // One pass over the persisted shard locations (replayed from the
        // log when the metadata index was opened above), streamed:
        //
        // - A disk that had to be formatted (replaced, or wiped) holds none
        //   of the shards the index remembers on it. They are forgotten, so
        //   they are reported missing and rebuilt rather than reported
        //   present and failing every read.
        // - Each disk's allocation bitmap is reconciled against the index,
        //   the source of truth for what is on the platter: a disk formatted
        //   before the allocator was wired up has an all-zero bitmap under a
        //   full data region, and would hand out block 0 over live shards.
        let mut lost = Vec::new();
        let mut reclaimed_check: Vec<u64> = vec![0; num_disks];
        let prefix = MetadataKey::from_bytes(SHARD_LOC_PREFIX.to_vec());
        meta_store.for_each_prefix(&prefix, None, &mut |k: &[u8], v: &[u8]| {
            let loc = match ShardLocation::from_bytes(v) {
                Ok(loc) => loc,
                Err(e) => {
                    warn!("skipping corrupt ShardLocation entry: {e}");
                    return true;
                }
            };
            if loc.small.is_some() {
                // In its record, on no disk: nothing to reconcile.
                shard_index.counted(None, Some(&loc));
                return true;
            }
            if formatted_now.get(loc.disk_idx).copied().unwrap_or(false) {
                lost.push(MetadataKey::from_bytes(k.to_vec()));
                return true;
            }
            if loc.disk_idx >= disks.len() {
                warn!(
                    "Shard index references disk {} but only {} are attached; skipping",
                    loc.disk_idx,
                    disks.len()
                );
                return true;
            }
            shard_index.counted(None, Some(&loc));
            let blocks = disks[loc.disk_idx].blocks_for_len(loc.size as usize);
            if let Err(e) = disks[loc.disk_idx].mark_extent_used(loc.block_num, blocks) {
                warn!(
                    "Could not mark block {} on disk {} as used: {e}",
                    loc.block_num, loc.disk_idx
                );
            } else {
                reclaimed_check[loc.disk_idx] += 1;
            }
            true
        });
        // In batches, one log record (and fsync) each: one per shard took
        // over five minutes for a disk of 24,000 shards.
        for chunk in lost.chunks(1000) {
            if let Err(e) = meta_store.batch_delete(chunk) {
                // Harmless if they stay: the disk was formatted, so the
                // entries' CRCs never match and the shards read as corrupt.
                warn!("forgetting {} shards on a formatted disk: {e}", chunk.len());
            }
        }
        if !lost.is_empty() {
            warn!(
                "{} shards were on a disk formatted at startup; they are lost \
                 and will be rebuilt by Meta's repairer",
                lost.len()
            );
        }
        info!("Shard index: {} shards", shard_index.count());
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
                .iter_prefix(&MetadataKey::all_object_meta_prefix())
                .chain(meta_store.iter_prefix(&MetadataKey::from_bytes(vec![b'v']))),
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
            shard_index,
            full_ratio: DEFAULT_FULL_RATIO,
            meta_store,
            start_time: Instant::now(),
            next_disk: RwLock::new(0),
            grpc_metrics: Arc::new(GrpcMetrics::default()),
            usage,
            safety: SafetyCache::default(),
            metrics_renderer: std::sync::OnceLock::new(),
            corrupt: RwLock::new(std::collections::HashSet::new()),
            meta_space,
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

    /// The metadata index's own metrics (its engine's), as Prometheus
    /// families.
    pub fn render_wal_metrics(&self, out: &mut String, osd_label: &str) {
        self.meta_store.render_metrics(out, osd_label);
    }

    /// Objects at risk with `up` (sorted) the nodes up: the last count if it
    /// is for the same nodes and under [`SAFETY_EVERY`] old, else a new
    /// one. Only one count runs at a time; a caller that would start a
    /// second gets the last count, whatever it was for. Every gateway polls
    /// every OSD, every few seconds with quotas set: each poll was a scan
    /// of every ObjectMeta here.
    fn object_safety(&self, up: Vec<Vec<u8>>) -> objectio_proto::storage::ObjectSafety {
        let cached = || {
            self.safety
                .last
                .lock()
                .as_ref()
                .map(|(at, nodes, s)| (*at, nodes.clone(), *s))
        };
        if let Some((at, nodes, s)) = cached()
            && nodes == up
            && at.elapsed() < SAFETY_EVERY
        {
            return s;
        }
        let Some(_one) = self.safety.scanning.try_lock() else {
            return cached().map(|(_, _, s)| s).unwrap_or_default();
        };
        // Counted while this waited for the lock: done.
        if let Some((at, nodes, s)) = cached()
            && nodes == up
            && at.elapsed() < SAFETY_EVERY
        {
            return s;
        }
        let set: std::collections::HashSet<Vec<u8>> = up.iter().cloned().collect();
        // A scan of every ObjectMeta this OSD holds: off the async worker
        // where the runtime allows.
        let scan = || {
            self.usage.safety(
                self.meta_store
                    .iter_prefix(&MetadataKey::all_object_meta_prefix())
                    .chain(
                        self.meta_store
                            .iter_prefix(&MetadataKey::from_bytes(vec![b'v'])),
                    ),
                &set,
            )
        };
        let s = blocking(scan);
        self.safety.scans.fetch_add(1, Ordering::Relaxed);
        *self.safety.last.lock() = Some((Instant::now(), up, s));
        s
    }

    /// Per-bucket usage of the objects this OSD is primary for.
    pub fn bucket_usage(&self) -> Vec<objectio_proto::storage::BucketUsage> {
        self.usage.snapshot()
    }

    /// Store a small shard sent with its object's metadata (B21): its
    /// record and `writes` in one log batch.
    #[allow(clippy::result_large_err)] // tonic::Status, as the handlers return
    fn store_with_small_shard(
        &self,
        shard: objectio_proto::storage::SmallShard,
        writes: Vec<(MetadataKey, Vec<u8>)>,
    ) -> Result<(), Status> {
        // No level check here: a gateway sends a shard with the metadata
        // only once the cluster is finalized at SMALL_SHARDS_LEVEL, which
        // every node then reads (levels only rise). This OSD may not have
        // heard yet; it doesn't need to.
        let id = shard
            .shard_id
            .ok_or_else(|| Status::invalid_argument("small shard without an id"))?;
        if shard.data.len() > SMALL_SHARD_MAX {
            return Err(Status::invalid_argument(
                "shard too large to keep in metadata",
            ));
        }
        let crc32c = crc32c::crc32c(&shard.data);
        if crc32c != shard.crc32c {
            return Err(Status::data_loss(format!(
                "shard has crc32c {crc32c:08x}, expected {:08x}",
                shard.crc32c
            )));
        }
        let key = Self::shard_key(&id.object_id, id.stripe_id, id.position);
        let loc = if self.meta_space.low() {
            // No room to spare in the index: a disk block, as WriteShard.
            self.spill_small_shard(&id, &shard.data, crc32c)?
        } else {
            ShardLocation {
                disk_idx: SMALL_DISK,
                block_num: 0,
                size: shard.data.len() as u32,
                crc32c,
                created_at: Self::current_timestamp(),
                small: Some(shard.data.to_vec()),
            }
        };
        let replaced = self
            .shard_index
            .record_with(&key, &loc, writes)
            .map_err(|e| Status::internal(format!("failed to store object metadata: {e}")))?;
        if let Some(old) = replaced {
            self.free_location(&old);
        }
        self.corrupt.write().remove(&key);
        Ok(())
    }

    /// Write a small shard to a disk block, synced, as `WriteShard` does:
    /// for when the metadata store's filesystem is nearly full. Its location
    /// is the caller's to record; a failure before that frees the extent.
    #[allow(clippy::result_large_err)] // tonic::Status, as the handlers return
    fn spill_small_shard(
        &self,
        id: &objectio_proto::storage::ShardId,
        data: &[u8],
        crc32c: u32,
    ) -> Result<ShardLocation, Status> {
        let disk_idx = self.select_disk_for_write();
        let disk = &self.disks[disk_idx];
        let blocks = disk.blocks_for_len(data.len());
        self.check_room(disk_idx, blocks)?;
        let block_num = self.allocate_extent(disk_idx, blocks)?;
        let mut object_id = [0u8; 16];
        let n = id.object_id.len().min(16);
        object_id[..n].copy_from_slice(&id.object_id[..n]);
        let started = Instant::now();
        if let Err(e) = disk.write_block(block_num, object_id, id.stripe_id, data) {
            let _ = disk.free_extent(block_num, blocks);
            return Err(Status::internal(format!("write failed: {e}")));
        }
        DISK_SECONDS.observe_duration("op=\"write\"", started.elapsed());
        let started = Instant::now();
        if let Err(e) = disk.sync() {
            let _ = disk.free_extent(block_num, blocks);
            return Err(Status::internal(format!("sync failed: {e}")));
        }
        DISK_SECONDS.observe_duration("op=\"sync\"", started.elapsed());
        Ok(ShardLocation {
            disk_idx,
            block_num,
            size: data.len() as u32,
            crc32c,
            created_at: Self::current_timestamp(),
            small: None,
        })
    }

    /// This OSD's shard of `object`, if it is kept in its record (B21) and
    /// passes its checksum: sent with the object's metadata, so a small GET
    /// needs no shard read. A shard that fails is marked for rebuilding and
    /// not sent; the reader then reads the others.
    fn small_shard_of(&self, object: &ObjectMeta) -> Option<objectio_proto::storage::SmallShard> {
        let stripe = object.stripes.first().filter(|s| s.shards_in_metadata)?;
        let mine = stripe
            .shards
            .iter()
            .find(|s| s.node_id.as_slice() == self.node_id.as_slice())?;
        let key = Self::shard_key(&stripe.object_id, stripe.stripe_id, mine.position);
        let loc = self.shard_index.get(&key)?;
        let data = loc.small?;
        if crc32c::crc32c(&data) != loc.crc32c {
            self.mark_corrupt(&key, loc.block_num);
            return None;
        }
        Some(objectio_proto::storage::SmallShard {
            shard_id: Some(objectio_proto::storage::ShardId {
                object_id: stripe.object_id.clone(),
                stripe_id: stripe.stripe_id,
                position: mine.position,
            }),
            crc32c: loc.crc32c,
            data,
        })
    }

    /// Where a shard is, as the RPCs report it: its disk and offset, or, for
    /// one kept in its record (B21), no disk.
    fn block_location(&self, loc: &ShardLocation) -> BlockLocation {
        let (disk_id, offset) = match self.disks.get(loc.disk_idx) {
            Some(disk) if loc.small.is_none() => (
                self.disk_ids[loc.disk_idx].to_vec(),
                loc.block_num * disk.block_size() as u64,
            ),
            _ => (vec![0u8; 16], 0),
        };
        BlockLocation {
            node_id: self.node_id.to_vec(),
            disk_id,
            offset,
            size: loc.size,
        }
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
        let started = Instant::now();
        let mut bytes = 0u64;
        // A page of shards at a time, in key order.
        let mut after: Option<String> = None;
        loop {
            let page = self.shard_index.page(after.as_deref(), 1024);
            let Some((last, _)) = page.last() else { break };
            after = Some(last.clone());
            for (key, loc) in page {
                if let Some(data) = &loc.small {
                    if crc32c::crc32c(data) != loc.crc32c {
                        self.mark_corrupt(&key, loc.block_num);
                    }
                    bytes += u64::from(loc.size);
                    self.scrub.shards.fetch_add(1, Ordering::Relaxed);
                    self.scrub
                        .bytes
                        .fetch_add(u64::from(loc.size), Ordering::Relaxed);
                    continue;
                }
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
                    let due =
                        std::time::Duration::from_secs_f64(bytes as f64 / bytes_per_sec as f64);
                    if let Some(wait) = due.checked_sub(started.elapsed()) {
                        tokio::time::sleep(wait).await;
                    }
                }
            }
        }
        self.scrub.passes.fetch_add(1, Ordering::Relaxed);
        self.scrub.last_pass_ms.store(
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.scrub.last_pass_end.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            Ordering::Relaxed,
        );
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
        for (name, help, v) in [
            (
                "objectio_osd_scrub_last_pass_seconds",
                "How long the last completed scrub pass took",
                self.scrub.last_pass_ms.load(Ordering::Relaxed) as f64 / 1000.0,
            ),
            (
                "objectio_osd_scrub_last_pass_timestamp_seconds",
                "When the last scrub pass completed (Unix time; 0: none yet)",
                self.scrub.last_pass_end.load(Ordering::Relaxed) as f64,
            ),
        ] {
            let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge");
            let _ = writeln!(out, "{name}{{{osd_label}}} {v}");
        }
    }

    /// Decoded ObjectMeta currently stored under `key`, if any.
    fn stored_meta(&self, key: &MetadataKey) -> Option<ObjectMeta> {
        self.meta_store
            .get(key)
            .and_then(|v| ObjectMeta::decode(&v[..]).ok())
    }

    /// `PutObjectMeta` with `replication_update`: merge the replication
    /// statuses into the entries holding `object` (its version entry, and
    /// the current entry when it is that version), under the key lock the
    /// caller holds, leaving every other field as stored.
    #[allow(clippy::result_large_err)]
    fn merge_replication(
        &self,
        bucket: &str,
        object_key: &str,
        set: &std::collections::HashMap<String, String>,
        object: &ObjectMeta,
        current_key: MetadataKey,
        current: Option<&ObjectMeta>,
    ) -> Result<Response<PutObjectMetaResponse>, Status> {
        let holds =
            |o: &ObjectMeta| o.object_id == object.object_id && o.version_id == object.version_id;
        let mut entries: Vec<(MetadataKey, ObjectMeta, EntryKind)> = Vec::new();
        if let Some(c) = current.filter(|c| holds(c)) {
            entries.push((current_key, c.clone(), EntryKind::Current));
        }
        if !object.version_id.is_empty() {
            let version_key = MetadataKey::object_version(bucket, object_key, &object.version_id);
            if let Some(v) = self.stored_meta(&version_key).filter(|v| holds(v)) {
                entries.push((version_key, v, EntryKind::Version));
            }
        }
        if entries.is_empty() {
            return Err(Status::failed_precondition(format!(
                "{bucket}/{object_key} version {:?} is not stored here",
                object.version_id
            )));
        }
        for (key, mut stored, kind) in entries {
            let before = stored.clone();
            for (target, status) in set {
                stored.replication.insert(target.clone(), status.clone());
            }
            self.meta_store
                .put(key, stored.encode_to_vec())
                .map_err(|e| {
                    Status::internal(format!("failed to store replication status: {e}"))
                })?;
            self.usage.apply(bucket, kind, Some(&before), Some(&stored));
        }
        Ok(Response::new(PutObjectMetaResponse {
            success: true,
            timestamp: Self::current_timestamp(),
            replaced: None,
            replaced_version_kept: false,
            superseded: false,
            held_stamp: 0,
        }))
    }

    /// Whether a `PutObjectMeta` that expects `expected` (empty: anything)
    /// may replace `current`. No current entry passes, unless
    /// `require_existing`.
    /// The stamp of the last delete of `bucket/key` (`version_id` empty: the
    /// current object) on this copy; 0 if none.
    fn tombstone(&self, bucket: &str, key: &str, version_id: &str) -> u64 {
        self.meta_store
            .get(&MetadataKey::tombstone(bucket, key, version_id))
            .and_then(|v| <[u8; 8]>::try_from(v.as_slice()).ok())
            .map_or(0, u64::from_be_bytes)
    }

    /// Record a delete's stamp (only ever raised).
    #[allow(clippy::result_large_err)] // tonic::Status, as every handler returns
    fn put_tombstone(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        stamp: u64,
    ) -> Result<(), Status> {
        if self.tombstone(bucket, key, version_id) >= stamp {
            return Ok(());
        }
        self.meta_store
            .put(
                MetadataKey::tombstone(bucket, key, version_id),
                stamp.to_be_bytes().to_vec(),
            )
            .map(drop)
            .map_err(|e| Status::internal(format!("failed to record the delete: {e}")))
    }

    /// Whether this copy saw a delete of the key (or version) newer than
    /// `incoming`: a late write must not bring the object back.
    fn deleted_since(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        incoming: &ObjectMeta,
    ) -> bool {
        incoming.stamp != 0 && self.tombstone(bucket, key, version_id) >= incoming.stamp
    }

    /// The answer to a write this copy already holds a newer one than:
    /// `stored` (or a tombstone) at `held_stamp`.
    fn superseded(held_stamp: u64) -> Response<PutObjectMetaResponse> {
        Response::new(PutObjectMetaResponse {
            success: true,
            timestamp: Self::current_timestamp(),
            replaced: None,
            replaced_version_kept: false,
            superseded: true,
            held_stamp,
        })
    }

    fn precondition_holds(
        current: Option<&ObjectMeta>,
        expected: &[u8],
        require_existing: bool,
    ) -> bool {
        if expected.is_empty() {
            return true;
        }
        current.map_or(!require_existing, |c| c.object_id == expected)
    }

    /// Whether `object` is also stored as a version of `bucket/key`, which
    /// keeps its shards referenced after it stops being current.
    fn version_entry_holds(
        store: &dyn MetaIndex,
        bucket: &str,
        key: &str,
        object: &ObjectMeta,
    ) -> bool {
        store
            .get(&MetadataKey::object_version(
                bucket,
                key,
                version_entry_id(&object.version_id),
            ))
            .and_then(|v| ObjectMeta::decode(&v[..]).ok())
            .is_some_and(|v| v.object_id == object.object_id)
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
            let shard_count = self.shard_index.count_on(i);

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
        meta_store: &dyn MetaIndex,
        shard_key: &str,
        loc: &ShardLocation,
    ) -> std::result::Result<(), String> {
        #[cfg(test)]
        if location_records_fail() {
            return Err("injected: the metadata log is unwritable".into());
        }
        let key = Self::shard_loc_meta_key(shard_key);
        let value = loc.to_bytes();
        meta_store
            .put(key, value)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Remove a persisted ShardLocation (delete_shard path).
    fn forget_shard_location(
        meta_store: &dyn MetaIndex,
        shard_key: &str,
    ) -> std::result::Result<(), String> {
        #[cfg(test)]
        if location_records_fail() {
            return Err("injected: the metadata log is unwritable".into());
        }
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
    #[cfg(test)]
    fn load_persisted_shard_index(meta_store: &dyn MetaIndex) -> HashMap<String, ShardLocation> {
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
            match ShardLocation::from_bytes(&value) {
                Ok(loc) => {
                    out.insert(shard_key.to_string(), loc);
                }
                Err(e) => warn!("skipping corrupt ShardLocation entry {shard_key}: {e}"),
            }
        }
        out
    }

    /// The share of each disk client writes may fill (B3).
    #[must_use]
    pub fn with_full_ratio(mut self, ratio: f64) -> Self {
        self.full_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Whether a client write of `blocks` fits on disk `disk_idx` without
    /// going into the space kept for writes that restore redundancy. A full
    /// disk refused client writes only when it had no block left, so repair
    /// had nowhere to rebuild a lost shard on a full cluster.
    #[allow(clippy::result_large_err)]
    fn check_room(&self, disk_idx: usize, blocks: u64) -> Result<(), Status> {
        let disk = &self.disks[disk_idx];
        let need = blocks * u64::from(disk.block_size());
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let reserve = (disk.capacity() as f64 * (1.0 - self.full_ratio)) as u64;
        if disk.free_space() < need + reserve {
            return Err(Status::resource_exhausted(format!(
                "disk {disk_idx} is full: {} of {} bytes used, the rest kept for repair",
                disk.used_space(),
                disk.capacity()
            )));
        }
        Ok(())
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
        let index = &self.shard_index;
        let corrupt = self.corrupt.read();
        let states = req
            .shards
            .iter()
            .map(|id| {
                let key = Self::shard_key(&id.object_id, id.stripe_id, id.position);
                let state = if corrupt.contains(&key) {
                    ShardState::Corrupt
                } else if index.contains(&key) {
                    ShardState::Ok
                } else {
                    ShardState::Missing
                };
                state as i32
            })
            .collect();
        Ok(Response::new(CheckShardsResponse { states }))
    }

    async fn note_chunks(
        &self,
        request: Request<NoteChunksRequest>,
    ) -> Result<Response<NoteChunksResponse>, Status> {
        let req = request.into_inner();
        let mut seen = Vec::with_capacity(req.fingerprints.len());
        let mut writes = Vec::with_capacity(req.fingerprints.len());
        // A fingerprint repeated within one call counts from its first
        // occurrence, as it would across calls.
        let mut counts: HashMap<&[u8], u64> = HashMap::new();
        for fp in &req.fingerprints {
            let count = counts.entry(fp.as_slice()).or_insert_with(|| {
                self.meta_store
                    .get(&dedup_note_key(fp))
                    .and_then(|v| v.try_into().ok().map(u64::from_le_bytes))
                    .unwrap_or(0)
            });
            seen.push(*count > 0);
            *count += 1;
        }
        for (fp, count) in counts {
            writes.push((dedup_note_key(fp), count.to_le_bytes().to_vec()));
        }
        // One WAL record for the whole call.
        self.meta_store
            .batch_put(writes)
            .map_err(|e| Status::internal(format!("recording chunk notes: {e}")))?;
        Ok(Response::new(NoteChunksResponse { seen }))
    }

    async fn purge(
        &self,
        request: Request<objectio_proto::storage::PurgeRequest>,
    ) -> Result<Response<objectio_proto::storage::PurgeResponse>, Status> {
        let req = request.into_inner();
        if req.node_id.as_slice() != self.node_id.as_slice() {
            return Err(Status::invalid_argument("purge names another OSD; refused"));
        }
        // Shards: the index entry, its persisted copy, then the block — the
        // same order as DeleteShard, so a crash leaks a block rather than
        // handing a live shard's block out.
        let mut shards = 0u64;
        loop {
            // Forgotten as it goes, so each page starts at the next.
            let page = self.shard_index.page(None, 1024);
            if page.is_empty() {
                break;
            }
            for (key, _) in page {
                // As in DeleteShard: blocks are freed only once the removal
                // is durable. Otherwise stop; the purge is retried.
                match self.shard_index.forget(&key) {
                    Ok(Some(loc)) => {
                        self.free_location(&loc);
                        shards += 1;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        return Err(Status::unavailable(format!(
                            "purge: the removal of shard {key} could not be recorded ({e}); retry"
                        )));
                    }
                }
                self.corrupt.write().remove(&key);
            }
        }
        // Object and version metadata: stale once drained, and harmful if
        // the OSD came back with it (deleted objects would reappear).
        let mut entries = 0u64;
        for prefix in [
            MetadataKey::all_object_meta_prefix(),
            MetadataKey::from_bytes(vec![b'v']),
        ] {
            for (key, _) in self.meta_store.iter_prefix(&prefix) {
                match self.meta_store.delete(&key) {
                    Ok(_) => entries += 1,
                    Err(e) => {
                        return Err(Status::internal(format!("purge: {e}")));
                    }
                }
            }
        }
        self.usage.rebuild(std::iter::empty());
        info!("Purged: {shards} shards, {entries} metadata entries");
        Ok(Response::new(objectio_proto::storage::PurgeResponse {
            shards,
            entries,
        }))
    }

    async fn reset_chunk_notes(
        &self,
        _request: Request<ResetChunkNotesRequest>,
    ) -> Result<Response<ResetChunkNotesResponse>, Status> {
        let prefix = MetadataKey::from_bytes(DEDUP_NOTE_PREFIX.to_vec());
        // A batch at a time, each deleted before the next is read.
        let mut forgotten = 0u64;
        loop {
            let batch: Vec<MetadataKey> = self
                .meta_store
                .iter_prefix(&prefix)
                .take(4096)
                .map(|(k, _)| k)
                .collect();
            if batch.is_empty() {
                break;
            }
            self.meta_store
                .batch_delete(&batch)
                .map_err(|e| Status::internal(format!("forgetting chunk notes: {e}")))?;
            forgotten += batch.len() as u64;
        }
        info!("dedup dry-run: forgot {forgotten} chunk notes");
        Ok(Response::new(ResetChunkNotesResponse { forgotten }))
    }

    async fn get_metrics(
        &self,
        _request: Request<objectio_proto::metadata::GetMetricsRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetMetricsResponse>, Status> {
        let render = || self.metrics_renderer.get().map(|f| f()).unwrap_or_default();
        // SMART polling may shell out to smartctl; don't stall a runtime
        // worker on it where the runtime allows moving off.
        let text = blocking(render);
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
        // as good under a checksum computed from the damage. Every writer
        // sends one.
        let crc32c = crc32c::crc32c(data);
        if staged.is_none() {
            let refuse = |status: Status| {
                self.grpc_metrics.write_shard.record(
                    false,
                    start.elapsed().as_micros() as u64,
                    0,
                    0,
                );
                status
            };
            let Some(expected) = req.checksum.as_ref().map(|c| c.crc32c) else {
                return Err(refuse(Status::invalid_argument(
                    "shard sent without a checksum",
                )));
            };
            if expected != crc32c {
                return Err(refuse(Status::data_loss(format!(
                    "shard has crc32c {crc32c:08x}, expected {expected:08x}"
                ))));
            }
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
        if !req.use_reserve {
            self.check_room(disk_idx, blocks)?;
        }
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
        // Nothing records this extent until the location below, so if the
        // write or the sync fails the extent goes straight back.
        let fail = |status: Status| {
            self.grpc_metrics.write_shard.record(
                false,
                start.elapsed().as_micros() as u64,
                bytes_in,
                0,
            );
            status
        };
        let started = Instant::now();
        if let Err(e) = disk
            .write_block_async(block_num, object_id, shard_id.stripe_id, data)
            .await
        {
            let _ = disk.free_extent(block_num, blocks);
            return Err(fail(Status::internal(format!("write failed: {e}"))));
        }
        DISK_SECONDS.observe_duration("op=\"write\"", started.elapsed());

        let started = Instant::now();
        if let Err(e) = disk.sync() {
            let _ = disk.free_extent(block_num, blocks);
            return Err(fail(Status::internal(format!("sync failed: {e}"))));
        }
        DISK_SECONDS.observe_duration("op=\"sync\"", started.elapsed());

        // Store location in index
        let key = Self::shard_key(&shard_id.object_id, shard_id.stripe_id, shard_id.position);
        let timestamp = Self::current_timestamp();

        let loc = ShardLocation {
            disk_idx,
            block_num,
            size: data.len() as u32,
            crc32c,
            created_at: timestamp,
            small: None,
        };
        // Durable before acknowledged: the shard's bytes are synced, and
        // its location must be too, or a restart forgets the shard and the
        // write we acknowledged is gone. So a failure here fails the write.
        //
        // The extent is not freed: the failed record may still have reached
        // the log, and a restart that replays it must find these bytes in
        // its blocks, not another shard's. It is reclaimed at restart if the
        // record didn't survive (the bitmap is rebuilt from the index).
        let replaced = match self.shard_index.record(&key, &loc) {
            Ok(replaced) => replaced,
            Err(e) => {
                error!("Shard {key} written but its location not recorded: {e}; write refused");
                return Err(fail(Status::unavailable(format!(
                    "the shard's location could not be recorded durably ({e}); not stored, retry"
                ))));
            }
        };
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

        let location = self.shard_index.get(&key).ok_or_else(|| {
            self.grpc_metrics.read_shard.record(
                false,
                start.elapsed().as_micros() as u64,
                bytes_in,
                0,
            );
            Status::not_found("shard not found")
        })?;

        let data = if let Some(small) = location.small.clone() {
            // Kept in its record (B21): checked against the checksum
            // recorded with it, as a block's own checks would.
            if crc32c::crc32c(&small) != location.crc32c {
                self.mark_corrupt(&key, location.block_num);
                return Err(Status::data_loss("shard failed its checksum"));
            }
            small
        } else {
            let disk = &self.disks[location.disk_idx];

            // Async read — same semantics, reactor stays free during I/O.
            let read_started = Instant::now();
            let read = disk.read_block_async(location.block_num).await;
            DISK_SECONDS.observe_duration("op=\"read\"", read_started.elapsed());
            let (_header, data) = read.map_err(|e| {
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
            data
        };

        debug!(
            "ReadShard: object={}, stripe={}, pos={}, size={}",
            hex::encode(&shard_id.object_id),
            shard_id.stripe_id,
            shard_id.position,
            data.len()
        );

        let timestamp = Self::current_timestamp();

        // The checksum the shard's object records (B23). The block's own
        // checks passed above against this OSD's checksum; that one was
        // taken of whatever bytes this OSD was sent, so a shard stored wrong
        // (rebuilt from a bad source) passes them. It doesn't pass this.
        if let Some(expected) = req.expected_crc32c {
            let actual = crc32c::crc32c(&data);
            if actual != expected {
                self.mark_corrupt(&key, location.block_num);
                return Err(Status::data_loss(format!(
                    "shard is not the one its object records \
                     (crc32c {actual:08x}, expected {expected:08x})"
                )));
            }
        }

        // A ranged read (a packed object's slice): the whole shard is
        // checked against its stored checksum first, as the gateway checks
        // a whole shard, and only the range goes back, with a checksum of
        // its own. A shard that fails the check is reported for rebuilding.
        let (data, crc32c) = if req.length > 0 {
            if crc32c::crc32c(&data) != location.crc32c {
                self.mark_corrupt(&key, location.block_num);
                return Err(Status::data_loss("shard failed its checksum"));
            }
            let start = usize::try_from(req.offset)
                .unwrap_or(usize::MAX)
                .min(data.len());
            let end = start.saturating_add(req.length as usize).min(data.len());
            let slice = data[start..end].to_vec();
            let crc = crc32c::crc32c(&slice);
            (slice, crc)
        } else {
            (data, location.crc32c)
        };

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
                crc32c,
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

        // The removal is durable before the blocks are freed. If it fails,
        // the persisted entry still points at these blocks: freeing them
        // would let another shard's bytes sit where a restart expects this
        // one. So the shard stays, and the delete is refused for the caller
        // to retry.
        let removed = match self.shard_index.forget(&key) {
            Ok(removed) => removed,
            Err(e) => {
                error!("Shard {key}: its removal could not be recorded: {e}; delete refused");
                return Err(Status::unavailable(format!(
                    "the shard's removal could not be recorded durably ({e}); retry"
                )));
            }
        };

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
            .get(&key)
            .ok_or_else(|| Status::not_found("shard not found"))?;

        Ok(Response::new(GetShardMetaResponse {
            shard_id: Some(shard_id),
            location: Some(self.block_location(&location)),
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

        let mut shards: Vec<GetShardMetaResponse> = Vec::new();

        for (key, location) in self.shard_index.page(None, limit) {
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

            shards.push(GetShardMetaResponse {
                shard_id: Some(objectio_proto::storage::ShardId {
                    object_id,
                    stripe_id,
                    position,
                }),
                location: Some(self.block_location(&location)),
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
        let mut up_nodes = request.into_inner().up_nodes;
        let safety = if up_nodes.is_empty() {
            None
        } else {
            up_nodes.sort();
            up_nodes.dedup();
            Some(self.object_safety(up_nodes))
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

            let shard_count = self.shard_index.count_on(idx);

            disk_statuses.push(DiskStatus {
                disk_id: self.disk_ids[idx].to_vec(),
                path: disk.path().to_string(),
                total_capacity: cap,
                used_capacity: used,
                status: "healthy".to_string(),
                shard_count,
            });
        }

        let shard_count = self.shard_index.count();
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

    #[allow(clippy::result_large_err)] // tonic::Status, as every handler returns
    async fn put_object_meta(
        &self,
        request: Request<PutObjectMetaRequest>,
    ) -> Result<Response<PutObjectMetaResponse>, Status> {
        // The store write syncs the WAL: off the runtime worker, so a
        // sync stalls nothing else and concurrent writes share it.
        blocking(|| {
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

            if req.replication_update {
                return self.merge_replication(
                    &req.bucket,
                    &req.key,
                    &req.replication_set,
                    &object,
                    key,
                    old.as_ref(),
                );
            }

            // Only the version entry: a change to a version that may not be
            // current (`version_only`), or a replica older than the current
            // version (`keep_newer_current`).
            let older_replica = req.keep_newer_current
                && old
                    .as_ref()
                    .is_some_and(|c| version_age(c) > version_age(&object));
            if (req.version_only || older_replica) && !object.version_id.is_empty() {
                let version_key =
                    MetadataKey::object_version(&req.bucket, &req.key, &object.version_id);
                let prev = self.stored_meta(&version_key);
                if supersedes(prev.as_ref(), &object)
                    || self.deleted_since(&req.bucket, &req.key, &object.version_id, &object)
                {
                    let held = prev.as_ref().map_or(0, |p| p.stamp).max(self.tombstone(
                        &req.bucket,
                        &req.key,
                        &object.version_id,
                    ));
                    return Ok(Self::superseded(held));
                }
                if req.version_only
                    && !Self::precondition_holds(
                        prev.as_ref(),
                        &req.expected_object_id,
                        req.require_existing,
                    )
                {
                    return Err(Status::failed_precondition(format!(
                        "{}/{} version {} is no longer the object this write was built from",
                        req.bucket, req.key, object.version_id
                    )));
                }
                match req.shard {
                    // An older replica's small shard (B21): kept with its
                    // version entry, as a current one's is.
                    Some(shard) => {
                        self.store_with_small_shard(shard, vec![(version_key, value)])?
                    }
                    None => {
                        self.meta_store.put(version_key, value).map_err(|e| {
                            Status::internal(format!("failed to store version entry: {e}"))
                        })?;
                    }
                }
                self.usage.apply(
                    &req.bucket,
                    EntryKind::Version,
                    prev.as_ref(),
                    Some(&object),
                );
                return Ok(Response::new(PutObjectMetaResponse {
                    success: true,
                    timestamp: Self::current_timestamp(),
                    replaced: None,
                    replaced_version_kept: false,
                    superseded: false,
                    held_stamp: 0,
                }));
            }

            // A replica from another cluster is ordered by its version's age
            // (`keep_newer_current`, above), not by when this cluster
            // stamped it: replicas arrive in any order.
            if !req.keep_newer_current
                && (supersedes(old.as_ref(), &object)
                    || self.deleted_since(&req.bucket, &req.key, "", &object))
            {
                let held = old.as_ref().map_or(0, |o| o.stamp).max(self.tombstone(
                    &req.bucket,
                    &req.key,
                    "",
                ));
                return Ok(Self::superseded(held));
            }
            if !Self::precondition_holds(
                old.as_ref(),
                &req.expected_object_id,
                req.require_existing,
            ) {
                return Err(Status::failed_precondition(format!(
                    "{}/{} is no longer the object this write was built from",
                    req.bucket, req.key
                )));
            }
            // Everything this write stores goes in one log batch: one flush,
            // all or nothing (B21). Usage follows once it is durable.
            let mut writes: Vec<(MetadataKey, Vec<u8>)> = vec![(key, value.clone())];
            let mut usage: Vec<(EntryKind, Option<ObjectMeta>, ObjectMeta)> =
                vec![(EntryKind::Current, old.clone(), object.clone())];

            // The object this write replaces was stored while versioning was
            // off (the "null" version). With versioning on now, S3 keeps it as
            // a noncurrent version rather than letting it go: give it a version
            // entry. It used to be dropped, and its shards freed.
            if req.versioning_enabled
                && !object.version_id.is_empty()
                && let Some(null) = old.as_ref().filter(|o| o.version_id.is_empty())
            {
                let null_key = MetadataKey::object_version(&req.bucket, &req.key, NULL_VERSION);
                let replaced = self.stored_meta(&null_key);
                writes.push((null_key, null.encode_to_vec()));
                usage.push((EntryKind::Version, replaced, null.clone()));
            }

            // A versioned object's own version entry is the same object: an
            // update in place (tags, retention, legal hold) changes both, or a
            // read by version id sees it without them, and a delete by version
            // id checks a lock that isn't there.
            let updates_its_version = !req.versioning_enabled
                && !object.version_id.is_empty()
                && Self::version_entry_holds(&*self.meta_store, &req.bucket, &req.key, &object);
            // If versioning is enabled and version_id is set, also store version entry
            if (req.versioning_enabled || updates_its_version) && !object.version_id.is_empty() {
                let version_key =
                    MetadataKey::object_version(&req.bucket, &req.key, &object.version_id);
                let old = self.stored_meta(&version_key);
                writes.push((version_key, value));
                usage.push((EntryKind::Version, old, object.clone()));
            }

            match req.shard {
                // This OSD's small shard of the object, with it (B21).
                Some(shard) => self.store_with_small_shard(shard, writes)?,
                None => self.meta_store.batch_put(writes).map(|_| ()).map_err(|e| {
                    Status::internal(format!("failed to store object metadata: {e}"))
                })?,
            }
            for (kind, before, after) in &usage {
                self.usage
                    .apply(&req.bucket, *kind, before.as_ref(), Some(after));
            }

            let timestamp = Self::current_timestamp();

            info!(
                "Stored object metadata: {}/{} ({} bytes, version={})",
                req.bucket, req.key, object.size, object.version_id
            );

            // Hand back what this write displaced, read under the same key lock
            // as the write, so the caller can free its shards. Whether a version
            // entry still holds it is checked after this write's own version
            // entry has gone in.
            let replaced_version_kept = old.as_ref().is_some_and(|o| {
                Self::version_entry_holds(&*self.meta_store, &req.bucket, &req.key, o)
            });

            Ok(Response::new(PutObjectMetaResponse {
                success: true,
                timestamp,
                replaced: old,
                replaced_version_kept,
                superseded: false,
                held_stamp: 0,
            }))
        })
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

                let small_shard = if req.with_small_shard {
                    self.small_shard_of(&object)
                } else {
                    None
                };
                Ok(Response::new(GetObjectMetaResponse {
                    object: Some(object),
                    found: true,
                    tombstone_stamp: self.tombstone(&req.bucket, &req.key, &req.version_id),
                    small_shard,
                }))
            }
            None => {
                debug!("Object metadata not found: {}/{}", req.bucket, req.key);

                Ok(Response::new(GetObjectMetaResponse {
                    object: None,
                    found: false,
                    tombstone_stamp: self.tombstone(&req.bucket, &req.key, &req.version_id),
                    small_shard: None,
                }))
            }
        }
    }

    #[allow(clippy::result_large_err)] // tonic::Status, as every handler returns
    async fn delete_object_meta(
        &self,
        request: Request<DeleteObjectMetaRequest>,
    ) -> Result<Response<DeleteObjectMetaResponse>, Status> {
        // The store write syncs the WAL: off the runtime worker, so a
        // sync stalls nothing else and concurrent writes share it.
        blocking(|| {
            let req = request.into_inner();

            let _guard = self.usage.lock_key(&req.bucket, &req.key);

            // A copy that holds a newer write than this delete keeps it
            // (last writer wins); the delete changes nothing here.
            let target = if req.version_id.is_empty() {
                MetadataKey::object_meta(&req.bucket, &req.key)
            } else {
                MetadataKey::object_version(&req.bucket, &req.key, &req.version_id)
            };
            if req.stamp != 0
                && let Some(held) = self
                    .stored_meta(&target)
                    .map(|o| o.stamp)
                    .filter(|&s| s > req.stamp)
            {
                return Ok(Response::new(DeleteObjectMetaResponse {
                    success: true,
                    current: None,
                    removed: None,
                    superseded: true,
                    held_stamp: held,
                }));
            }
            // The tombstone goes first: a copy that crashed after it but
            // before the removal still answers "deleted" (newer stamp).
            if req.stamp != 0 {
                self.put_tombstone(&req.bucket, &req.key, &req.version_id, req.stamp)?;
            }

            let removed;
            if req.version_id.is_empty() {
                // Delete current version entry
                let key = MetadataKey::object_meta(&req.bucket, &req.key);
                let old = self.stored_meta(&key);
                removed = old.clone();
                self.meta_store.delete(&key).map_err(|e| {
                    Status::internal(format!("failed to delete object metadata: {}", e))
                })?;
                self.usage
                    .apply(&req.bucket, EntryKind::Current, old.as_ref(), None);
                info!("Deleted object metadata: {}/{}", req.bucket, req.key);
            } else {
                // Delete specific version entry
                let version_key =
                    MetadataKey::object_version(&req.bucket, &req.key, &req.version_id);
                let old = self.stored_meta(&version_key);
                removed = old.clone();
                self.meta_store.delete(&version_key).map_err(|e| {
                    Status::internal(format!("failed to delete version entry: {}", e))
                })?;
                self.usage
                    .apply(&req.bucket, EntryKind::Version, old.as_ref(), None);
                info!(
                    "Deleted version: {}/{} (version={})",
                    req.bucket, req.key, req.version_id
                );

                // Was it the current version? Then the newest remaining one
                // becomes current, still under the key's lock.
                let current_key = MetadataKey::object_meta(&req.bucket, &req.key);
                let current = self.stored_meta(&current_key);
                if current
                    .as_ref()
                    .is_some_and(|c| version_entry_id(&c.version_id) == req.version_id)
                {
                    let newest = self
                        .meta_store
                        .scan_prefix(&MetadataKey::object_version_prefix(&req.bucket, &req.key))
                        .into_iter()
                        .filter_map(|(_, v)| ObjectMeta::decode(&v[..]).ok())
                        .max_by(|a, b| version_age(a).cmp(&version_age(b)));
                    match &newest {
                        Some(n) => self.meta_store.put(current_key, n.encode_to_vec()),
                        None => self.meta_store.delete(&current_key),
                    }
                    .map_err(|e| {
                        Status::internal(format!("failed to replace the current version: {e}"))
                    })?;
                    self.usage.apply(
                        &req.bucket,
                        EntryKind::Current,
                        current.as_ref(),
                        newest.as_ref(),
                    );
                }
            }

            let current = if req.version_id.is_empty() {
                None
            } else {
                self.stored_meta(&MetadataKey::object_meta(&req.bucket, &req.key))
                    .map(for_listing)
            };
            Ok(Response::new(DeleteObjectMetaResponse {
                success: true,
                current,
                removed,
                superseded: false,
                held_stamp: 0,
            }))
        })
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
            // Within a bucket, only the keys under the listing's prefix.
            MetadataKey::from_bytes(
                [
                    MetadataKey::object_meta_prefix(&req.bucket).0,
                    req.prefix.as_bytes().to_vec(),
                ]
                .concat(),
            )
        };
        // Start past the cursor rather than read the bucket up to it: a
        // page costs its own size, not the bucket's.
        let cursor = std::cmp::max(&req.start_after, &req.continuation_token);
        let after = (!cursor.is_empty())
            .then(|| {
                if req.bucket.is_empty() {
                    MetadataKey::from_bytes([b"m".as_slice(), cursor.as_bytes()].concat())
                } else {
                    MetadataKey::object_meta(&req.bucket, cursor)
                }
            })
            .filter(|a| a.0 > prefix.0);
        let entries =
            objectio_storage::metadata::iter_prefix(&*self.meta_store, prefix.clone(), after);

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

                // Decode object metadata. A bucket's listing leaves out keys
                // whose current version is a delete marker: they don't exist.
                if let Ok(object) = ObjectMeta::decode(&value[..]) {
                    if !cluster_wide && object.is_delete_marker {
                        continue;
                    }
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
        let entries = self.meta_store.iter_prefix(&prefix);
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
                            shard_object_id: if stripe.object_id.is_empty() {
                                object.object_id.clone()
                            } else {
                                stripe.object_id.clone()
                            },
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

    type StreamListObjectsMetaStream =
        Pin<Box<dyn Stream<Item = Result<ListObjectsMetaChunk, Status>> + Send + 'static>>;

    async fn stream_list_objects_meta(
        &self,
        request: Request<ListObjectsMetaRequest>,
    ) -> Result<Response<Self::StreamListObjectsMetaStream>, Status> {
        const CHUNK_SIZE: usize = 500;

        let req = request.into_inner();
        // The keys under the listing's prefix, past the cursor, read as the
        // stream is consumed: a chunk in memory at a time, not the bucket.
        let prefix = MetadataKey::from_bytes(
            [
                MetadataKey::object_meta_prefix(&req.bucket).0,
                req.prefix.as_bytes().to_vec(),
            ]
            .concat(),
        );
        let cursor = std::cmp::max(&req.start_after, &req.continuation_token);
        let after = (!cursor.is_empty())
            .then(|| MetadataKey::object_meta(&req.bucket, cursor))
            .filter(|a| a.0 > prefix.0);
        let entries =
            objectio_storage::metadata::iter_prefix(Arc::clone(&self.meta_store), prefix, after);

        let stream = futures::stream::unfold(Some(entries), |state| async move {
            let mut entries = state?;
            let mut batch: Vec<ObjectMeta> = Vec::with_capacity(CHUNK_SIZE);
            let mut last = String::new();
            for (meta_key, value) in entries.by_ref() {
                let Some((_bucket, key)) = meta_key.parse_object_meta() else {
                    continue;
                };
                if let Ok(object) = ObjectMeta::decode(&value[..]) {
                    batch.push(for_listing(object));
                    last = key;
                    if batch.len() >= CHUNK_SIZE {
                        break;
                    }
                }
            }
            let is_last = batch.len() < CHUNK_SIZE;
            let chunk = ListObjectsMetaChunk {
                objects: batch,
                next_start_after: if is_last { String::new() } else { last },
                is_last,
            };
            Some((Ok(chunk), (!is_last).then_some(entries)))
        });
        Ok(Response::new(Box::pin(stream)))
    }

    /// Every version of the bucket's keys under `prefix`, in key order,
    /// whole keys at a time: keys after `key_marker` (and `key_marker`
    /// itself when `version_id_marker` is set, its versions left to the
    /// caller to skip), stopping at the first key boundary at or past
    /// `max_keys` versions. Includes the null version: the current object
    /// when it was stored while versioning was off.
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
        let wanted = |key: &str| {
            key.starts_with(&req.prefix)
                && (req.key_marker.is_empty()
                    || key > req.key_marker.as_str()
                    || (key == req.key_marker && !req.version_id_marker.is_empty()))
        };

        // Two sources in key order, version entries and current objects,
        // each read from past `key_marker` and only as far as `max_keys` + 1
        // keys: every key listed has a version, so that is enough to fill
        // the page and to know whether more follow. Whichever stops first
        // bounds the page; past it, the other may have keys not yet read.
        let limit_keys = max_keys + 1;
        let under = |base: MetadataKey| {
            MetadataKey::from_bytes([base.0, req.prefix.as_bytes().to_vec()].concat())
        };
        let past_marker = |base: MetadataKey, prefix: &MetadataKey| {
            (!req.key_marker.is_empty())
                .then(|| {
                    MetadataKey::from_bytes([base.0, req.key_marker.as_bytes().to_vec()].concat())
                })
                .filter(|a| a.0 > prefix.0)
        };
        let mut by_key: std::collections::BTreeMap<String, Vec<ObjectMeta>> =
            std::collections::BTreeMap::new();
        let mut bound: Option<String> = None;

        let v_prefix = under(MetadataKey::object_version_bucket_prefix(&req.bucket));
        let v_after = past_marker(
            MetadataKey::object_version_bucket_prefix(&req.bucket),
            &v_prefix,
        );
        let mut v_keys = 0usize;
        let mut v_last = String::new();
        for (meta_key, value) in
            objectio_storage::metadata::iter_prefix(&*self.meta_store, v_prefix.clone(), v_after)
        {
            let Some((_, key, _)) = meta_key.parse_object_version() else {
                continue;
            };
            if !wanted(&key) {
                continue;
            }
            if key != v_last {
                if v_keys == limit_keys {
                    bound = Some(v_last.clone());
                    break;
                }
                v_keys += 1;
                v_last.clone_from(&key);
            }
            if let Ok(object) = ObjectMeta::decode(&value[..]) {
                by_key.entry(key).or_default().push(for_listing(object));
            }
        }

        let m_prefix = under(MetadataKey::object_meta_prefix(&req.bucket));
        let m_after = past_marker(MetadataKey::object_meta_prefix(&req.bucket), &m_prefix);
        // The marker key's own current object is at the seek point, not
        // past it: read it on its own when its versions are wanted.
        let marker_current = (!req.key_marker.is_empty() && !req.version_id_marker.is_empty())
            .then(|| {
                let k = MetadataKey::object_meta(&req.bucket, &req.key_marker);
                self.meta_store.get(&k).map(|v| (k, v))
            })
            .flatten();
        let mut m_keys = 0usize;
        for (meta_key, value) in
            marker_current
                .into_iter()
                .chain(objectio_storage::metadata::iter_prefix(
                    &*self.meta_store,
                    m_prefix.clone(),
                    m_after,
                ))
        {
            let Some((_, key)) = meta_key.parse_object_meta() else {
                continue;
            };
            if !wanted(&key) {
                continue;
            }
            if m_keys == limit_keys {
                if bound.as_ref().is_none_or(|b| &key < b) {
                    bound = by_key
                        .range(..key.clone())
                        .next_back()
                        .map(|(k, _)| k.clone());
                }
                break;
            }
            m_keys += 1;
            if let Ok(object) = ObjectMeta::decode(&value[..])
                && object.version_id.is_empty()
            {
                // The current null version supersedes a null version
                // entry kept from before.
                let versions = by_key.entry(key).or_default();
                versions.retain(|v| !v.version_id.is_empty());
                versions.push(for_listing(object));
            }
        }
        // Past the bound, one source may be missing keys: leave them to the
        // next page.
        if let Some(bound) = bound {
            by_key.retain(|k, _| *k <= bound);
        }

        let mut versions = Vec::new();
        let mut last_key = String::new();
        let mut is_truncated = false;
        for (key, mut of_key) in by_key {
            if versions.len() >= max_keys {
                is_truncated = true;
                break;
            }
            versions.append(&mut of_key);
            last_key = key;
        }

        Ok(Response::new(ListObjectVersionsMetaResponse {
            versions,
            next_key_marker: if is_truncated {
                last_key
            } else {
                String::new()
            },
            next_version_id_marker: String::new(),
            is_truncated,
        }))
    }
}

/// The version entry of the object stored while versioning was off.
const NULL_VERSION: &str = "null";

/// Where a version sorts among its key's: when it was made, in ms. A
/// UUIDv7 version id carries it; the null version has no id, so its object
/// id (a UUIDv7 too) does; older ids fall back to the modification time,
/// in seconds. The gateway orders versions the same way.
/// Whether `stored` is a newer write than `incoming`, so this copy keeps it
/// (objectio-docs core/object-metadata-quorum.md): the newer object wins
/// (higher stamp, then higher object id, so every copy picks the same), and
/// between copies of one object the later update. An update keeps its
/// object's stamp, so it never outranks a newer object written meanwhile.
/// The same write again is not newer than itself. An unstamped write (0, a
/// previous-release writer during a rolling upgrade) is applied as before.
fn supersedes(stored: Option<&ObjectMeta>, incoming: &ObjectMeta) -> bool {
    incoming.stamp != 0 && stored.is_some_and(|s| s.write_order() > incoming.write_order())
}

fn version_age(object: &ObjectMeta) -> (u64, &str) {
    let ms_of = |u: uuid::Uuid| {
        (u.get_version_num() == 7)
            .then(|| u.get_timestamp())
            .flatten()
            .map(|t| {
                let (secs, nanos) = t.to_unix();
                secs * 1000 + u64::from(nanos / 1_000_000)
            })
    };
    let ms = uuid::Uuid::parse_str(&object.version_id)
        .ok()
        .and_then(ms_of)
        .or_else(|| {
            uuid::Uuid::from_slice(&object.object_id)
                .ok()
                .and_then(ms_of)
                .filter(|_| object.version_id.is_empty())
        })
        .unwrap_or_else(|| object.modified_at.saturating_mul(1000));
    (ms, object.version_id.as_str())
}

/// The version entry an object's `version_id` is kept under.
fn version_entry_id(version_id: &str) -> &str {
    if version_id.is_empty() {
        NULL_VERSION
    } else {
        version_id
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
            small: None,
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
            b"not a record".to_vec(),
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

    /// A disk the OSD can't open is not formatted unless it is blank: with
    /// both superblock copies damaged it holds shards still, and the OSD
    /// formatting it on start destroyed them. It refuses to start instead.
    #[tokio::test]
    async fn a_disk_that_wont_open_is_not_formatted() {
        use std::os::unix::fs::FileExt;
        let (dir, osd) = osd();
        osd.write_shard(Request::new(write_request(
            &[7; 5000],
            Some(crc32c::crc32c(&[7; 5000])),
        )))
        .await
        .unwrap();
        drop(osd);
        let path = dir.path().join("disk.raw");
        let damage = [0xAB; 4096];
        {
            let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
            f.write_all_at(&damage, 0).unwrap();
            f.write_all_at(&damage, objectio_storage::layout::BACKUP_SUPERBLOCK_OFFSET)
                .unwrap();
            f.sync_all().unwrap();
        }
        let reopened = OsdService::new(
            vec![path.display().to_string()],
            64 * 1024,
            dir.path().join("state"),
        );
        let Err(why) = reopened else {
            panic!("an unopenable disk with data was taken (formatted)");
        };
        assert!(why.contains("not formatting"), "{why}");
        let mut head = [0u8; 4096];
        std::fs::File::open(&path)
            .unwrap()
            .read_exact_at(&mut head, 0)
            .unwrap();
        assert_eq!(head, damage, "the disk was written to");
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
            use_reserve: false,
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

    fn reopen(dir: &tempfile::TempDir) -> OsdService {
        OsdService::new(
            vec![dir.path().join("disk.raw").display().to_string()],
            64 * 1024,
            dir.path().join("state"),
        )
        .unwrap()
    }

    /// An acknowledgement means the shard survives a restart, so a shard
    /// whose location can't be recorded durably is refused, not
    /// acknowledged and then forgotten at the next restart.
    #[tokio::test]
    async fn a_write_whose_location_cannot_be_recorded_is_refused() {
        let (dir, osd) = osd();
        let data = vec![0x33; 50_000];
        let free_before = free_space(&osd);

        LOCATION_RECORDS_FAIL.with(|f| f.set(true));
        let err = osd
            .write_shard(Request::new(write_request(
                &data,
                Some(crc32c::crc32c(&data)),
            )))
            .await
            .unwrap_err();
        LOCATION_RECORDS_FAIL.with(|f| f.set(false));
        assert_eq!(err.code(), tonic::Code::Unavailable, "{err}");
        assert_eq!(
            read_back(&osd).await.unwrap_err().code(),
            tonic::Code::NotFound,
            "a refused shard was served"
        );

        // A retry stores it, and it survives a restart; the extent the
        // refused attempt held is reclaimed there.
        osd.write_shard(Request::new(write_request(
            &data,
            Some(crc32c::crc32c(&data)),
        )))
        .await
        .unwrap();
        drop(osd);
        let osd = reopen(&dir);
        assert_eq!(&read_back(&osd).await.unwrap().data[..], &data[..]);
        let one_shard = osd.disks[0].blocks_for_len(data.len()) * 64 * 1024;
        assert_eq!(
            free_space(&osd),
            free_before - one_shard,
            "the refused attempt's extent was not reclaimed"
        );
    }

    /// A delete frees blocks only once the removal is durable: otherwise a
    /// restart would find the old entry pointing at blocks another shard
    /// may have been given.
    #[tokio::test]
    async fn a_delete_whose_removal_cannot_be_recorded_keeps_the_shard() {
        let (dir, osd) = osd();
        let data = vec![0x44; 50_000];
        osd.write_shard(Request::new(write_request(
            &data,
            Some(crc32c::crc32c(&data)),
        )))
        .await
        .unwrap();
        let free_with_shard = free_space(&osd);
        let delete = || {
            osd.delete_shard(Request::new(DeleteShardRequest {
                shard_id: Some(shard_id()),
            }))
        };

        LOCATION_RECORDS_FAIL.with(|f| f.set(true));
        let err = delete().await.unwrap_err();
        LOCATION_RECORDS_FAIL.with(|f| f.set(false));
        assert_eq!(err.code(), tonic::Code::Unavailable, "{err}");
        assert_eq!(&read_back(&osd).await.unwrap().data[..], &data[..]);
        assert_eq!(free_space(&osd), free_with_shard, "blocks freed anyway");

        // The retry deletes it, for good.
        assert!(delete().await.unwrap().into_inner().success);
        drop(osd);
        let osd = reopen(&dir);
        assert_eq!(
            read_back(&osd).await.unwrap_err().code(),
            tonic::Code::NotFound,
            "the deleted shard came back after a restart"
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

    /// Every writer sends a checksum; a shard without one is refused.
    #[tokio::test]
    async fn a_shard_without_a_checksum_is_refused() {
        let (_dir, osd) = osd();
        let data = vec![0x11; 4096];
        let err = osd
            .write_shard(Request::new(write_request(&data, None)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "{err}");
        assert_eq!(
            read_back(&osd).await.unwrap_err().code(),
            tonic::Code::NotFound
        );
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
        let loc = osd
            .shard_index
            .get(&OsdService::shard_key(&[7; 16], 0, position))
            .unwrap();
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

    /// Store `data` as this OSD's small shard of object `b/k` (position 0),
    /// sent with its metadata as a gateway does (B21).
    async fn put_small(osd: &OsdService, data: &[u8]) {
        use objectio_proto::storage::{PutObjectMetaRequest, SmallShard};
        osd.put_object_meta(Request::new(PutObjectMetaRequest {
            bucket: "b".into(),
            key: "k".into(),
            object: Some(objectio_proto::metadata::ObjectMeta {
                bucket: "b".into(),
                key: "k".into(),
                object_id: vec![7; 16],
                stamp: 1,
                ..Default::default()
            }),
            shard: Some(SmallShard {
                shard_id: Some(id(0)),
                data: data.to_vec(),
                crc32c: crc32c::crc32c(data),
            }),
            ..Default::default()
        }))
        .await
        .unwrap();
    }

    /// B21: a small shard sent with its metadata is kept in its record: no
    /// disk block, read back, checked, counted, kept across a restart,
    /// found rotten by the scrubber when its bytes no longer match their
    /// checksum, rewritten (to a block, as repair does) and deleted like any
    /// shard.
    #[tokio::test]
    async fn a_small_shard_lives_in_its_record() {
        let (dir, osd) = osd();
        let free_before = osd.disks[0].free_space();
        let small: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        put_small(&osd, &small).await;
        assert_eq!(
            osd.disks[0].free_space(),
            free_before,
            "it took a disk block"
        );
        let key = OsdService::shard_key(&id(0).object_id, 0, 0);
        assert!(osd.shard_index.get(&key).unwrap().small.is_some());
        async fn read(osd: &OsdService, crc: u32) -> Result<Response<ReadShardResponse>, Status> {
            osd.read_shard(Request::new(ReadShardRequest {
                shard_id: Some(id(0)),
                expected_crc32c: Some(crc),
                ..Default::default()
            }))
            .await
        }
        let crc = crc32c::crc32c(&small);
        assert_eq!(
            &read(&osd, crc).await.unwrap().into_inner().data[..],
            &small[..]
        );
        assert_eq!(states(&osd, &[0]).await, vec![ShardState::Ok]);
        assert_eq!(osd.shard_index.count(), 1);
        drop(osd);

        let osd = reopen_at(&dir);
        assert_eq!(osd.shard_index.count(), 1, "not counted after a restart");
        assert_eq!(
            &read(&osd, crc).await.unwrap().into_inner().data[..],
            &small[..]
        );

        // Its bytes rot in the record: the scrubber finds it, reads refuse
        // it, and a rewrite clears it.
        let mut bad = osd.shard_index.get(&key).unwrap();
        bad.small.as_mut().unwrap()[5] ^= 0xff;
        OsdService::persist_shard_location(&*osd.meta_store, &key, &bad).unwrap();
        osd.scrub_pass(0).await;
        assert_eq!(states(&osd, &[0]).await, vec![ShardState::Corrupt]);
        assert_eq!(
            read(&osd, crc).await.unwrap_err().code(),
            tonic::Code::DataLoss
        );
        write(&osd, 0, &small).await;
        assert_eq!(states(&osd, &[0]).await, vec![ShardState::Ok]);
        assert_eq!(
            &read(&osd, crc).await.unwrap().into_inner().data[..],
            &small[..]
        );

        osd.delete_shard(Request::new(DeleteShardRequest {
            shard_id: Some(id(0)),
        }))
        .await
        .unwrap();
        assert_eq!(states(&osd, &[0]).await, vec![ShardState::Missing]);
        assert_eq!(osd.shard_index.count(), 0);
    }

    /// B21: an object's metadata and this OSD's small shard of it, in one
    /// call and one log batch; a damaged shard stores neither. Taken even
    /// before this OSD has heard the cluster is at the level: the gateway's
    /// word for it is the cluster's.
    #[tokio::test]
    async fn a_small_shard_comes_with_its_metadata() {
        use objectio_proto::storage::{GetObjectMetaRequest, PutObjectMetaRequest, SmallShard};
        let (_dir, osd) = osd();
        let data: Vec<u8> = (0..12_000u32).map(|i| (i % 253) as u8).collect();
        let object = objectio_proto::metadata::ObjectMeta {
            bucket: "b".into(),
            key: "k".into(),
            object_id: vec![7; 16],
            size: 48_000,
            stamp: 10,
            stripes: vec![objectio_proto::metadata::StripeMeta {
                object_id: vec![7; 16],
                shards_in_metadata: true,
                shards: vec![objectio_proto::metadata::ShardLocation {
                    position: 3,
                    node_id: osd.node_id.to_vec(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        let put = |crc: u32| PutObjectMetaRequest {
            bucket: "b".into(),
            key: "k".into(),
            object: Some(object.clone()),
            shard: Some(SmallShard {
                shard_id: Some(id(3)),
                data: data.clone(),
                crc32c: crc,
            }),
            ..Default::default()
        };
        let found = |osd: &OsdService| {
            osd.shard_index
                .get(&OsdService::shard_key(&id(3).object_id, 0, 3))
                .is_some()
        };
        let has_meta = |osd: &OsdService| {
            osd.stored_meta(&MetadataKey::object_meta("b", "k"))
                .is_some()
        };

        let damaged = osd
            .put_object_meta(Request::new(put(crc32c::crc32c(&data) ^ 1)))
            .await
            .unwrap_err();
        assert_eq!(damaged.code(), tonic::Code::DataLoss);
        assert!(!found(&osd) && !has_meta(&osd), "half a write was stored");

        osd.put_object_meta(Request::new(put(crc32c::crc32c(&data))))
            .await
            .unwrap();
        assert!(found(&osd) && has_meta(&osd));
        let got = osd
            .read_shard(Request::new(ReadShardRequest {
                shard_id: Some(id(3)),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(&got.data[..], &data[..]);
        let meta = |with_small_shard| {
            osd.get_object_meta(Request::new(GetObjectMetaRequest {
                bucket: "b".into(),
                key: "k".into(),
                version_id: String::new(),
                with_small_shard,
            }))
        };
        let plain = meta(false).await.unwrap().into_inner();
        assert!(plain.found && plain.small_shard.is_none());
        // Asked for, the shard comes with the metadata: a GET in one round.
        let both = meta(true).await.unwrap().into_inner();
        assert!(both.found);
        let shard = both.small_shard.expect("the shard, with its metadata");
        assert_eq!(shard.shard_id, Some(id(3)));
        assert_eq!(shard.data, data);
        assert_eq!(shard.crc32c, crc32c::crc32c(&data));

        // A damaged one is not sent, and is marked for rebuilding.
        let key = OsdService::shard_key(&id(3).object_id, 0, 3);
        let mut bad = osd.shard_index.get(&key).unwrap();
        bad.small.as_mut().unwrap()[5] ^= 0xff;
        OsdService::persist_shard_location(&*osd.meta_store, &key, &bad).unwrap();
        let both = meta(true).await.unwrap().into_inner();
        assert!(both.found && both.small_shard.is_none());
        assert!(osd.corrupt.read().contains(&key));
    }

    /// B21: with the metadata store's filesystem nearly full, a small shard
    /// sent with its metadata goes to a disk block; it reads the same, and
    /// isn't sent with the metadata (the reader reads it).
    #[tokio::test]
    async fn a_small_shard_goes_to_a_block_when_the_index_is_short_of_room() {
        use objectio_proto::storage::{GetObjectMetaRequest, PutObjectMetaRequest, SmallShard};
        META_SPACE_LOW.with(|c| c.set(true));
        let (_dir, osd) = osd();
        let data: Vec<u8> = (0..11_000u32).map(|i| (i % 239) as u8).collect();
        let object = objectio_proto::metadata::ObjectMeta {
            bucket: "b".into(),
            key: "k".into(),
            object_id: vec![7; 16],
            stamp: 10,
            stripes: vec![objectio_proto::metadata::StripeMeta {
                object_id: vec![7; 16],
                shards_in_metadata: true,
                shards: vec![objectio_proto::metadata::ShardLocation {
                    position: 1,
                    node_id: osd.node_id.to_vec(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        osd.put_object_meta(Request::new(PutObjectMetaRequest {
            bucket: "b".into(),
            key: "k".into(),
            object: Some(object),
            shard: Some(SmallShard {
                shard_id: Some(id(1)),
                data: data.clone(),
                crc32c: crc32c::crc32c(&data),
            }),
            ..Default::default()
        }))
        .await
        .unwrap();
        META_SPACE_LOW.with(|c| c.set(false));

        let loc = osd
            .shard_index
            .get(&OsdService::shard_key(&id(1).object_id, 0, 1))
            .unwrap();
        assert!(
            loc.small.is_none() && loc.disk_idx != SMALL_DISK,
            "kept in the index"
        );
        let got = osd
            .read_shard(Request::new(ReadShardRequest {
                shard_id: Some(id(1)),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(&got.data[..], &data[..]);
        let meta = osd
            .get_object_meta(Request::new(GetObjectMetaRequest {
                bucket: "b".into(),
                key: "k".into(),
                version_id: String::new(),
                with_small_shard: true,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(meta.found && meta.small_shard.is_none());
    }

    /// B21: a replica older than the current version (replicas arrive in
    /// any order) is kept as a version only, and its small shard with it.
    #[tokio::test]
    async fn an_older_replica_keeps_its_small_shard() {
        use objectio_proto::storage::{PutObjectMetaRequest, SmallShard};
        let (_dir, osd) = osd();
        let data: Vec<u8> = (0..9_000u32).map(|i| (i % 241) as u8).collect();
        let replica =
            |version_id: String, object_id: u8, shard: Option<SmallShard>| PutObjectMetaRequest {
                bucket: "b".into(),
                key: "k".into(),
                object: Some(objectio_proto::metadata::ObjectMeta {
                    bucket: "b".into(),
                    key: "k".into(),
                    version_id,
                    object_id: vec![object_id; 16],
                    stamp: 10,
                    ..Default::default()
                }),
                versioning_enabled: true,
                keep_newer_current: true,
                shard,
                ..Default::default()
            };
        let older = uuid::Uuid::now_v7().to_string();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let newer = uuid::Uuid::now_v7().to_string();
        osd.put_object_meta(Request::new(replica(newer, 8, None)))
            .await
            .unwrap();
        osd.put_object_meta(Request::new(replica(
            older.clone(),
            7,
            Some(SmallShard {
                shard_id: Some(id(2)),
                data: data.clone(),
                crc32c: crc32c::crc32c(&data),
            }),
        )))
        .await
        .unwrap();
        assert!(
            osd.stored_meta(&MetadataKey::object_version("b", "k", &older))
                .is_some()
        );
        let got = osd
            .read_shard(Request::new(ReadShardRequest {
                shard_id: Some(id(2)),
                ..Default::default()
            }))
            .await
            .expect("the older replica's shard")
            .into_inner();
        assert_eq!(&got.data[..], &data[..]);
    }

    /// B28: `GetStatus` counts objects at risk at most once a minute for
    /// the same nodes up, not once per poll; a change in which nodes are up
    /// is counted at once.
    #[tokio::test]
    async fn objects_at_risk_are_counted_once_a_minute_not_per_poll() {
        let (_dir, osd) = osd();
        let up = |ids: &[u8]| ids.iter().map(|i| vec![*i; 16]).collect::<Vec<_>>();
        let ask = |nodes: Vec<Vec<u8>>| {
            osd.get_status(Request::new(GetStatusRequest { up_nodes: nodes }))
        };
        for _ in 0..5 {
            ask(up(&[1, 2, 3])).await.unwrap();
        }
        assert_eq!(osd.safety.scans.load(Ordering::Relaxed), 1);
        // The same nodes, given in another order: still the same count.
        ask(up(&[3, 1, 2])).await.unwrap();
        assert_eq!(osd.safety.scans.load(Ordering::Relaxed), 1);
        // A node went down: counted again.
        ask(up(&[1, 2])).await.unwrap();
        assert_eq!(osd.safety.scans.load(Ordering::Relaxed), 2);
        // No nodes given: no count asked for.
        ask(Vec::new()).await.unwrap();
        assert_eq!(osd.safety.scans.load(Ordering::Relaxed), 2);
    }

    fn reopen_at(dir: &tempfile::TempDir) -> OsdService {
        OsdService::new(
            vec![dir.path().join("disk.raw").display().to_string()],
            64 * 1024,
            dir.path().join("state"),
        )
        .unwrap()
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
        put_as(osd, object, expected, false).await
    }

    async fn put_as(
        osd: &OsdService,
        object: ObjectMeta,
        expected: &[u8],
        require_existing: bool,
    ) -> Result<(), tonic::Status> {
        osd.put_object_meta(Request::new(PutObjectMetaRequest {
            bucket: "b".into(),
            key: "k".into(),
            object: Some(object),
            versioning_enabled: false,
            expected_object_id: expected.to_vec(),
            require_existing,
            ..Default::default()
        }))
        .await
        .map(drop)
    }

    fn stamped(object_id: u8, stamp: u64) -> ObjectMeta {
        ObjectMeta {
            stamp,
            ..meta(object_id)
        }
    }

    fn stored(osd: &OsdService) -> Option<ObjectMeta> {
        osd.stored_meta(&MetadataKey::object_meta("b", "k"))
    }

    /// A copy keeps the newest write: an older stamp arriving late is
    /// superseded, not applied (core/object-metadata-quorum.md).
    #[tokio::test]
    async fn a_copy_keeps_the_write_with_the_higher_stamp() {
        let (_dir, osd) = osd();
        put(&osd, stamped(2, 200), &[]).await.unwrap();
        put(&osd, stamped(1, 100), &[]).await.unwrap();
        assert_eq!(
            stored(&osd).unwrap().object_id,
            vec![2; 16],
            "an older write won"
        );

        put(&osd, stamped(3, 300), &[]).await.unwrap();
        assert_eq!(stored(&osd).unwrap().object_id, vec![3; 16]);
    }

    /// An update of an object (tagging, packing, ...) racing a PUT of the
    /// key, in either order on a copy: the PUT wins on both. The update was
    /// stamped above the object it read, so where it arrived first it
    /// superseded the PUT — acknowledged on the other copies — and the old
    /// object, the newest by stamp, came back everywhere once healed. It
    /// keeps the object's stamp now and is ordered among its updates.
    #[tokio::test]
    async fn an_update_never_outranks_a_newer_object() {
        let fresh = osd;
        let updated = ObjectMeta {
            update_stamp: 300,
            ..stamped(1, 100)
        };
        let put_after = stamped(2, 200);

        // The update first, then the PUT.
        let (_dir, osd) = fresh();
        put(&osd, stamped(1, 100), &[]).await.unwrap();
        put(&osd, updated.clone(), &[1; 16]).await.unwrap();
        put(&osd, put_after.clone(), &[]).await.unwrap();
        assert_eq!(stored(&osd).unwrap().object_id, vec![2; 16]);

        // The PUT first: the update, of an object no longer there, is
        // refused or superseded — not applied.
        let (_dir, osd) = fresh();
        put(&osd, stamped(1, 100), &[]).await.unwrap();
        put(&osd, put_after, &[]).await.unwrap();
        let _ = put(&osd, updated, &[1; 16]).await;
        assert_eq!(stored(&osd).unwrap().object_id, vec![2; 16]);

        // Updates of one object keep their order.
        let (_dir, osd) = fresh();
        put(&osd, stamped(1, 100), &[]).await.unwrap();
        let later = ObjectMeta {
            update_stamp: 400,
            tags: [("v".to_string(), "2".to_string())].into(),
            ..stamped(1, 100)
        };
        let earlier = ObjectMeta {
            update_stamp: 300,
            ..stamped(1, 100)
        };
        put(&osd, later, &[1; 16]).await.unwrap();
        put(&osd, earlier, &[1; 16]).await.unwrap();
        assert_eq!(stored(&osd).unwrap().update_stamp, 400);
    }

    /// Equal stamps: the higher object id wins on every copy; the same write
    /// again is applied (idempotent); an unstamped write is applied as before.
    #[tokio::test]
    async fn ties_and_replays_and_unstamped_writes() {
        let (_dir, osd) = osd();
        put(&osd, stamped(5, 100), &[]).await.unwrap();
        put(&osd, stamped(4, 100), &[]).await.unwrap();
        assert_eq!(stored(&osd).unwrap().object_id, vec![5; 16]);
        put(&osd, stamped(6, 100), &[]).await.unwrap();
        assert_eq!(stored(&osd).unwrap().object_id, vec![6; 16]);

        let again = osd
            .put_object_meta(Request::new(PutObjectMetaRequest {
                bucket: "b".into(),
                key: "k".into(),
                object: Some(stamped(6, 100)),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(!again.superseded, "the same write again is not superseded");

        put(&osd, meta(7), &[]).await.unwrap();
        assert_eq!(stored(&osd).unwrap().object_id, vec![7; 16]);
    }

    async fn delete_stamped(osd: &OsdService, stamp: u64) -> DeleteObjectMetaResponse {
        osd.delete_object_meta(Request::new(DeleteObjectMetaRequest {
            bucket: "b".into(),
            key: "k".into(),
            stamp,
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
    }

    async fn read(osd: &OsdService) -> GetObjectMetaResponse {
        osd.get_object_meta(Request::new(GetObjectMetaRequest {
            bucket: "b".into(),
            key: "k".into(),
            version_id: String::new(),
            with_small_shard: false,
        }))
        .await
        .unwrap()
        .into_inner()
    }

    /// A stamped delete leaves a tombstone: a read reports its stamp, and a
    /// write older than it is superseded, not applied.
    #[tokio::test]
    async fn a_delete_leaves_a_tombstone_that_refuses_older_writes() {
        let (_dir, osd) = osd();
        put(&osd, stamped(1, 100), &[]).await.unwrap();
        let d = delete_stamped(&osd, 200).await;
        assert!(!d.superseded && d.removed.is_some());
        let r = read(&osd).await;
        assert!(!r.found);
        assert_eq!(r.tombstone_stamp, 200);

        // A write that predates the delete arrives late: refused.
        put(&osd, stamped(2, 150), &[]).await.unwrap();
        assert!(stored(&osd).is_none(), "a deleted object came back");
        // A newer one is a new object.
        put(&osd, stamped(3, 300), &[]).await.unwrap();
        assert_eq!(stored(&osd).unwrap().object_id, vec![3; 16]);
    }

    /// A copy that missed the PUT still records the delete.
    #[tokio::test]
    async fn a_delete_of_nothing_still_leaves_a_tombstone() {
        let (_dir, osd) = osd();
        delete_stamped(&osd, 500).await;
        assert_eq!(read(&osd).await.tombstone_stamp, 500);
        put(&osd, stamped(1, 400), &[]).await.unwrap();
        assert!(stored(&osd).is_none());
    }

    /// Replicas from another cluster arrive in any order and are stamped
    /// when this cluster commits them: the newer version must become
    /// current even if it was stamped first.
    #[tokio::test]
    async fn a_replica_is_ordered_by_its_version_not_its_stamp() {
        let (_dir, osd) = osd();
        let version = |id: u8, vid: &str, stamp: u64| ObjectMeta {
            version_id: vid.into(),
            stamp,
            ..meta(id)
        };
        let replica = |o: ObjectMeta| PutObjectMetaRequest {
            bucket: "b".into(),
            key: "k".into(),
            object: Some(o),
            versioning_enabled: true,
            keep_newer_current: true,
            ..Default::default()
        };
        // v1 (older version) committed second, so with the higher stamp.
        let v1 = uuid::Uuid::now_v7().to_string();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let v2 = uuid::Uuid::now_v7().to_string();
        osd.put_object_meta(Request::new(replica(version(1, &v1, 200))))
            .await
            .unwrap();
        osd.put_object_meta(Request::new(replica(version(2, &v2, 100))))
            .await
            .unwrap();
        assert_eq!(
            stored(&osd).unwrap().version_id,
            v2,
            "the newer version is current"
        );
        assert!(
            osd.stored_meta(&MetadataKey::object_version("b", "k", &v2))
                .is_some()
        );
    }

    /// A delete older than what the copy holds changes nothing.
    #[tokio::test]
    async fn an_older_delete_is_superseded() {
        let (_dir, osd) = osd();
        put(&osd, stamped(1, 300), &[]).await.unwrap();
        let d = delete_stamped(&osd, 200).await;
        assert!(d.superseded && d.removed.is_none());
        assert_eq!(stored(&osd).unwrap().object_id, vec![1; 16]);
    }

    /// A superseded write says so, and displaces nothing.
    #[tokio::test]
    async fn a_superseded_write_says_so() {
        let (_dir, osd) = osd();
        put(&osd, stamped(2, 200), &[]).await.unwrap();
        let r = osd
            .put_object_meta(Request::new(PutObjectMetaRequest {
                bucket: "b".into(),
                key: "k".into(),
                object: Some(stamped(1, 100)),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(r.superseded);
        assert!(r.replaced.is_none());
    }

    /// The repairer must not bring back an object deleted after it read it;
    /// shard migration, writing to an OSD with no copy yet, must get through.
    #[tokio::test]
    async fn an_absent_object_refuses_a_write_only_when_one_is_required() {
        let (_dir, osd) = osd();
        let err = put_as(&osd, meta(1), &[1; 16], true).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        assert!(
            osd.stored_meta(&MetadataKey::object_meta("b", "k"))
                .is_none(),
            "a deleted object came back"
        );
        put_as(&osd, meta(1), &[1; 16], false).await.unwrap();
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

#[cfg(test)]
mod dedup_note_tests {
    //! The dedup dry-run's per-OSD fingerprint set.

    use super::*;
    use objectio_proto::storage::storage_service_server::StorageService;

    fn osd_at(dir: &std::path::Path) -> OsdService {
        OsdService::new(
            vec![dir.join("disk.raw").display().to_string()],
            64 * 1024,
            dir.join("state"),
        )
        .unwrap()
    }

    async fn note(osd: &OsdService, fps: &[&[u8]]) -> Vec<bool> {
        osd.note_chunks(Request::new(NoteChunksRequest {
            fingerprints: fps.iter().map(|f| f.to_vec()).collect(),
        }))
        .await
        .unwrap()
        .into_inner()
        .seen
    }

    #[tokio::test]
    async fn a_fingerprint_is_new_once_then_seen() {
        let dir = tempfile::tempdir().unwrap();
        let osd = osd_at(dir.path());
        assert_eq!(note(&osd, &[b"a", b"b"]).await, vec![false, false]);
        assert_eq!(note(&osd, &[b"b", b"c"]).await, vec![true, false]);
    }

    /// Two copies of a chunk in one object count the second as a duplicate.
    #[tokio::test]
    async fn a_repeat_within_one_call_is_seen() {
        let dir = tempfile::tempdir().unwrap();
        let osd = osd_at(dir.path());
        assert_eq!(
            note(&osd, &[b"x", b"x", b"x"]).await,
            vec![false, true, true]
        );
    }

    /// The set outlives a restart, and a reset outlives one too.
    #[tokio::test]
    async fn notes_and_resets_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        {
            let osd = osd_at(dir.path());
            note(&osd, &[b"kept"]).await;
        }
        {
            let osd = osd_at(dir.path());
            assert_eq!(note(&osd, &[b"kept"]).await, vec![true]);
            let forgotten = osd
                .reset_chunk_notes(Request::new(ResetChunkNotesRequest {}))
                .await
                .unwrap()
                .into_inner()
                .forgotten;
            assert_eq!(forgotten, 1);
        }
        let osd = osd_at(dir.path());
        assert_eq!(
            note(&osd, &[b"kept"]).await,
            vec![false],
            "the reset was lost"
        );
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

#[cfg(test)]
mod object_meta_tests {
    //! What `PutObjectMeta` tells the gateway about the object it replaced,
    //! which is what the gateway frees.

    use super::*;
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

    fn object(id: u8, version_id: &str) -> ObjectMeta {
        ObjectMeta {
            bucket: "b".into(),
            key: "k".into(),
            object_id: vec![id; 16],
            version_id: version_id.into(),
            size: 1,
            ..Default::default()
        }
    }

    async fn put(
        osd: &OsdService,
        object: ObjectMeta,
        versioning: bool,
        expected: &[u8],
    ) -> Result<PutObjectMetaResponse, Status> {
        osd.put_object_meta(Request::new(PutObjectMetaRequest {
            bucket: "b".into(),
            key: "k".into(),
            object: Some(object),
            versioning_enabled: versioning,
            expected_object_id: expected.to_vec(),
            require_existing: false,
            ..Default::default()
        }))
        .await
        .map(Response::into_inner)
    }

    #[tokio::test]
    async fn an_overwrite_hands_back_the_object_it_replaced() {
        let (_dir, osd) = osd();
        let first = put(&osd, object(1, ""), false, &[]).await.unwrap();
        assert!(first.replaced.is_none(), "a new key replaced something");

        let second = put(&osd, object(2, ""), false, &[]).await.unwrap();
        assert_eq!(second.replaced.unwrap().object_id, vec![1; 16]);
        assert!(!second.replaced_version_kept);
    }

    /// With versioning the replaced object is still a version: its shards
    /// are referenced, and the response says so.
    #[tokio::test]
    async fn a_replaced_object_kept_as_a_version_is_flagged() {
        let (_dir, osd) = osd();
        put(&osd, object(1, "v1"), true, &[]).await.unwrap();
        let second = put(&osd, object(2, "v2"), true, &[]).await.unwrap();
        assert_eq!(second.replaced.unwrap().object_id, vec![1; 16]);
        assert!(second.replaced_version_kept);

        // Suspended versioning: the new write keeps no version, but the
        // one it replaces still has its own.
        let third = put(&osd, object(3, ""), false, &[]).await.unwrap();
        assert!(third.replaced_version_kept);
        let fourth = put(&osd, object(4, ""), false, &[]).await.unwrap();
        assert!(!fourth.replaced_version_kept, "a null version is not kept");
    }

    /// A read-modify-write built from an object a newer PUT has replaced
    /// must not put it back: that PUT has freed its shards.
    #[tokio::test]
    async fn a_write_expecting_a_replaced_object_is_refused() {
        let (_dir, osd) = osd();
        put(&osd, object(1, ""), false, &[]).await.unwrap();
        put(&osd, object(2, ""), false, &[]).await.unwrap();

        let err = put(&osd, object(1, ""), false, &[1; 16]).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);
        let current = osd
            .get_object_meta(Request::new(GetObjectMetaRequest {
                bucket: "b".into(),
                key: "k".into(),
                version_id: String::new(),
                with_small_shard: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(current.object.unwrap().object_id, vec![2; 16]);

        // Expecting the current object, or writing to a key with none, is
        // allowed.
        put(&osd, object(2, ""), false, &[2; 16]).await.unwrap();
        osd.delete_object_meta(Request::new(DeleteObjectMetaRequest {
            bucket: "b".into(),
            key: "k".into(),
            version_id: String::new(),
            stamp: 0,
        }))
        .await
        .unwrap();
        put(&osd, object(5, ""), false, &[9; 16]).await.unwrap();
    }
}
