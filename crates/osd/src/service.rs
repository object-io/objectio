//! OSD gRPC service implementation

use crate::shard_store::{BlockStore, Disks, ShardInfo, ShardStore};
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
    GetPgInfoRequest,
    GetPgInfoResponse,
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
    ListPgRequest,
    ListPgResponse,
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
    SetPgEpochsRequest,
    SetPgEpochsResponse,
    WriteShardRequest,
    WriteShardResponse,
    health_check_response::Status as HealthStatus,
    storage_service_server::StorageService,
};
use objectio_storage::metadata::{MetaIndex, MetadataKey, MetadataOp, MetadataStoreConfig};
use prost::Message;
use std::collections::HashMap;
use std::fmt::Write;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tonic::{Request, Response, Status};
use tracing::{debug, info};
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

/// Dedup dry-run: chunk fingerprints this OSD has been told about, each
/// with how many times. See objectio-docs `architecture/design/core/dedup.md`.
const DEDUP_NOTE_PREFIX: &[u8] = b"dedup_note:";

fn dedup_note_key(fingerprint: &[u8]) -> MetadataKey {
    MetadataKey::from_bytes([DEDUP_NOTE_PREFIX, fingerprint].concat())
}

pub use crate::shard_store::DEFAULT_FULL_RATIO;

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

/// OSD service state
pub struct OsdService {
    node_id: [u8; 16],
    /// Shard bytes and their locations (B27: behind [`ShardStore`]).
    shards: Arc<dyn ShardStore>,
    /// Persistent metadata store (WAL + B-tree + ARC cache)
    meta_store: Arc<dyn MetaIndex>,
    start_time: Instant,
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
    scrub: ScrubStats,
    /// Transfer Engine and staging pool, once enabled at startup. Without it
    /// every shard arrives and leaves as gRPC bytes.
    #[cfg(feature = "rdma")]
    rdma: std::sync::OnceLock<crate::rdma::RdmaStaging>,
    /// Placement groups' epochs (B31): a request placed under an older one
    /// than known is refused.
    pg_epochs: crate::pg_epochs::PgEpochs,
    /// The same store as `meta_store`, indexed by placement group (B31
    /// phase 2): what peering asks of this OSD.
    pg_index: Arc<crate::pg_index::PgIndexed>,
}

type MetricsRenderer = Box<dyn Fn() -> String + Send + Sync>;

/// What the scrubber has done since the OSD started.
#[derive(Default)]
struct ScrubStats {
    passes: AtomicU64,
    shards: AtomicU64,
    bytes: AtomicU64,
    last_pass_ms: AtomicU64,
    last_pass_end: AtomicU64,
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
        let disks = Disks::open(&disk_paths, block_size)?;
        let node_id = disks.identity(&data_dir.join("node_id"))?;

        // Initialize metadata store for persistent object metadata
        let mut meta_config = MetadataStoreConfig::with_data_dir(&data_dir);
        tune(&mut meta_config);
        let meta_dir = meta_config.data_dir.clone();
        let meta_store = objectio_storage::metadata::open(meta_config)
            .map_err(|e| format!("Failed to open metadata store: {}", e))?;
        // Every write goes through the placement-group index (B31 phase 2),
        // the shard store's included.
        let pg_index = Arc::new(
            crate::pg_index::PgIndexed::open(meta_store, node_id)
                .map_err(|e| format!("Failed to index metadata by placement group: {e}"))?,
        );
        let meta_store: Arc<dyn MetaIndex> = Arc::clone(&pg_index) as Arc<dyn MetaIndex>;

        info!(
            "OSD initialized with {} disks, metadata at {:?}",
            disks.len(),
            data_dir
        );

        let shards: Arc<dyn ShardStore> =
            Arc::new(BlockStore::new(disks, Arc::clone(&meta_store), meta_dir));
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
            shards,
            meta_store,
            start_time: Instant::now(),
            grpc_metrics: Arc::new(GrpcMetrics::default()),
            usage,
            safety: SafetyCache::default(),
            metrics_renderer: std::sync::OnceLock::new(),
            scrub: ScrubStats::default(),
            pg_epochs: crate::pg_epochs::PgEpochs::default(),
            pg_index,
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
    /// Shards forgotten when this OSD opened its store, their disk having
    /// come back blank (replaced): reported to Meta at registration.
    /// The placement-group epochs this OSD holds requests to (B31).
    pub fn pg_epochs(&self) -> &crate::pg_epochs::PgEpochs {
        &self.pg_epochs
    }

    pub fn shards_dropped_at_open(&self) -> u64 {
        self.shards.dropped_at_open()
    }

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
        self.shards.small_shard(&objectio_proto::storage::ShardId {
            object_id: stripe.object_id.clone(),
            stripe_id: stripe.stripe_id,
            position: mine.position,
        })
    }

    /// Where a shard is, as the RPCs report it: this node, its disk and
    /// offset (no disk for one kept in its record, B21).
    fn block_location(&self, info: &ShardInfo) -> BlockLocation {
        BlockLocation {
            node_id: self.node_id.to_vec(),
            disk_id: info.disk_id.to_vec(),
            offset: info.offset,
            size: info.size,
        }
    }

    /// One scrub pass: read every shard on this OSD and check its blocks'
    /// checksums, at no more than `bytes_per_sec`, so a shard that rots on
    /// disk is found even if nobody reads it. Corrupt shards are recorded
    /// for the repairer.
    pub async fn scrub_pass(&self, bytes_per_sec: u64) {
        let started = Instant::now();
        let bytes = AtomicU64::new(0);
        self.shards
            .scrub(bytes_per_sec, &|size| {
                bytes.fetch_add(size, Ordering::Relaxed);
                self.scrub.shards.fetch_add(1, Ordering::Relaxed);
                self.scrub.bytes.fetch_add(size, Ordering::Relaxed);
            })
            .await;
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
            bytes.into_inner(),
            started.elapsed().as_secs_f64(),
            self.shards.corrupt_now()
        );
    }

    /// Scrub progress as Prometheus families.
    pub fn render_scrub_metrics(&self, out: &mut String, osd_label: &str) {
        let corrupt_now = self.shards.corrupt_now();
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
                self.shards.corrupt_found(),
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

    /// Of the shard positions `bucket/key`'s current object (if it is still
    /// `object_id`) names on this OSD, how many it holds intact.
    fn held_here(&self, bucket: &str, key: &str, object_id: &[u8]) -> u32 {
        let Some(o) = self
            .stored_meta(&MetadataKey::object_meta(bucket, key))
            .filter(|o| o.object_id == object_id)
        else {
            return 0;
        };
        let mut held = 0u32;
        for stripe in crate::pg_index::own_stripes(&o) {
            let mut mine: Vec<u32> = stripe
                .shards
                .iter()
                .filter(|l| l.node_id.as_slice() == self.node_id.as_slice())
                .map(|l| l.position)
                .collect();
            mine.sort_unstable();
            mine.dedup();
            let shard_object = if stripe.object_id.is_empty() {
                o.object_id.clone()
            } else {
                stripe.object_id.clone()
            };
            for position in mine {
                let id = objectio_proto::storage::ShardId {
                    object_id: shard_object.clone(),
                    stripe_id: stripe.stripe_id,
                    position,
                };
                if self.shards.state(&id) == objectio_proto::storage::ShardState::Ok {
                    held += 1;
                }
            }
        }
        held
    }

    /// Decoded ObjectMeta currently stored under `key`, if any.
    fn stored_meta(&self, key: &MetadataKey) -> Option<ObjectMeta> {
        self.meta_store
            .get(key)
            .and_then(|v| ObjectMeta::decode(&v[..]).ok())
    }

    /// `DeleteObjectMeta` with `withdraw_object_id`: take back one write of
    /// `bucket/object_key`, under the key lock the caller holds. Every entry
    /// holding `object_id` goes, in one store write, and nothing else: no
    /// tombstone, so whatever the other copies hold of the key stands. If
    /// the current entry went, the newest version left becomes current.
    #[allow(clippy::result_large_err)]
    fn withdraw(
        &self,
        bucket: &str,
        object_key: &str,
        object_id: &[u8],
    ) -> Result<Response<DeleteObjectMetaResponse>, Status> {
        let current_key = MetadataKey::object_meta(bucket, object_key);
        let current = self.stored_meta(&current_key);
        let mut ops = Vec::new();
        let mut usage = Vec::new();
        let mut removed = None;
        let mut versions = Vec::new();
        for (key, value) in self
            .meta_store
            .scan_prefix(&MetadataKey::object_version_prefix(bucket, object_key))
        {
            let Ok(version) = ObjectMeta::decode(&value[..]) else {
                continue;
            };
            if version.object_id == object_id {
                ops.push(MetadataOp::Delete { key });
                usage.push((EntryKind::Version, Some(version.clone()), None));
                removed = Some(version);
            } else {
                versions.push(version);
            }
        }
        let mut now_current = current.clone();
        if let Some(c) = current.as_ref().filter(|c| c.object_id == object_id) {
            let newest = versions
                .into_iter()
                .max_by(|a, b| version_age(a).cmp(&version_age(b)));
            ops.push(match &newest {
                Some(n) => MetadataOp::Put {
                    key: current_key,
                    value: n.encode_to_vec(),
                },
                None => MetadataOp::Delete { key: current_key },
            });
            usage.push((EntryKind::Current, Some(c.clone()), newest.clone()));
            removed = Some(c.clone());
            now_current = newest;
        }
        if !ops.is_empty() {
            self.meta_store
                .write(ops)
                .map_err(|e| Status::internal(format!("failed to withdraw the write: {e}")))?;
            for (kind, before, after) in &usage {
                self.usage
                    .apply(bucket, *kind, before.as_ref(), after.as_ref());
            }
            info!(
                "Withdrew {bucket}/{object_key} object {}",
                hex::encode(object_id)
            );
        }
        Ok(Response::new(DeleteObjectMetaResponse {
            success: true,
            current: now_current.map(for_listing),
            removed,
            superseded: false,
            held_stamp: 0,
        }))
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
            .map_or(0, |v| crate::pg_index::tombstone_stamp(&v))
    }

    /// Record a delete's stamp (only ever raised), with the placement group
    /// of its key when known (`pg`, else the one it recorded before), so a
    /// key left with only its tombstone stays indexed under its PG.
    #[allow(clippy::result_large_err)] // tonic::Status, as every handler returns
    fn put_tombstone(
        &self,
        bucket: &str,
        key: &str,
        version_id: &str,
        stamp: u64,
        pg: Option<crate::pg_index::PgId>,
    ) -> Result<(), Status> {
        let at = MetadataKey::tombstone(bucket, key, version_id);
        let old = self.meta_store.get(&at);
        if old.as_deref().map_or(0, crate::pg_index::tombstone_stamp) >= stamp {
            return Ok(());
        }
        let pg = pg.or_else(|| old.as_deref().and_then(crate::pg_index::tombstone_pg));
        self.meta_store
            .put(
                at,
                crate::pg_index::tombstone_value(
                    stamp,
                    pg.as_ref().map(|(pool, id)| (pool.as_str(), *id)),
                ),
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
        self.shards.claim(cluster_uuid, self.node_id)
    }

    /// Get disk IDs
    pub fn disk_ids(&self) -> Vec<[u8; 16]> {
        self.shards.disks().iter().map(|d| d.id).collect()
    }

    /// Raw capacity of each managed disk, index-aligned with `disk_ids()`.
    /// Used at registration time so meta can sum raw capacity across OSDs.
    pub fn disk_capacities(&self) -> Vec<u64> {
        self.shards.disks().iter().map(|d| d.capacity).collect()
    }

    /// Get disk count
    #[allow(dead_code)]
    pub fn disk_count(&self) -> usize {
        self.shards.disks().len()
    }

    /// Get OSD status for metrics
    pub fn status(&self) -> OsdStatus {
        let mut disks = Vec::new();
        let mut total_capacity = 0u64;
        let mut total_used = 0u64;
        let mut total_shards = 0u64;

        for disk in self.shards.disks() {
            let capacity = disk.capacity;
            let used = capacity.saturating_sub(disk.free);
            let shard_count = disk.shard_count;

            total_capacity += capacity;
            total_used += used;
            total_shards += shard_count;

            let read_errors = disk.read_errors;
            let write_errors = disk.write_errors;
            let checksum_errors = disk.checksum_errors;
            // A disk that has returned bad data or failed an IO since start
            // is not healthy, even though it is still serving requests.
            let status = if read_errors + write_errors + checksum_errors > 0 {
                "degraded"
            } else {
                "healthy"
            };
            disks.push(DiskStatusInfo {
                path: disk.path,
                capacity,
                used,
                shard_count,
                status: status.to_string(),
                read_errors,
                write_errors,
                checksum_errors,
                reads: disk.reads,
                writes: disk.writes,
                bytes_read: disk.bytes_read,
                bytes_written: disk.bytes_written,
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

    /// The share of each disk client writes may fill (B3).
    #[must_use]
    pub fn with_full_ratio(self, ratio: f64) -> Self {
        self.shards.set_full_ratio(ratio.clamp(0.0, 1.0));
        self
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
    async fn set_pg_epochs(
        &self,
        request: Request<SetPgEpochsRequest>,
    ) -> Result<Response<SetPgEpochsResponse>, Status> {
        for e in request.into_inner().epochs {
            self.pg_epochs.learn(&e.pool, e.pg_id, e.epoch);
        }
        Ok(Response::new(SetPgEpochsResponse {}))
    }

    async fn get_pg_info(
        &self,
        request: Request<GetPgInfoRequest>,
    ) -> Result<Response<GetPgInfoResponse>, Status> {
        let r = request.into_inner();
        let summary = self.pg_index.summary(&(r.pool, r.pg_id));
        Ok(Response::new(GetPgInfoResponse {
            summary: Some(summary.to_proto()),
        }))
    }

    async fn list_pg(
        &self,
        request: Request<ListPgRequest>,
    ) -> Result<Response<ListPgResponse>, Status> {
        let r = request.into_inner();
        let limit = if r.limit == 0 {
            1000
        } else {
            r.limit.min(10_000)
        } as usize;
        // Reads the store and asks the shard store of each entry: off the
        // runtime worker.
        Ok(blocking(|| {
            let (mut entries, next) =
                self.pg_index
                    .list(&(r.pool.clone(), r.pg_id), &r.after, limit);
            for e in entries
                .iter_mut()
                .filter(|e| !e.tombstone && e.named_here > 0)
            {
                e.held_here = self.held_here(&e.bucket, &e.key, &e.object_id);
            }
            Response::new(ListPgResponse { entries, next })
        }))
    }

    async fn check_shards(
        &self,
        request: Request<CheckShardsRequest>,
    ) -> Result<Response<CheckShardsResponse>, Status> {
        let req = request.into_inner();
        let states = req
            .shards
            .iter()
            .map(|id| self.shards.state(id) as i32)
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
        // Shards first, each freed only once its removal is durable.
        let shards = self.shards.purge()?;
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
        self.pg_epochs.check(req.pg.as_ref()).await?;
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
        // message are checked by the store, before a block is allocated, so a
        // shard damaged on the way is refused rather than stored and later
        // served as good under a checksum computed from the damage. Every
        // writer sends one.
        let Some(expected) = req.checksum.as_ref().map(|c| c.crc32c) else {
            self.grpc_metrics
                .write_shard
                .record(false, start.elapsed().as_micros() as u64, 0, 0);
            return Err(Status::invalid_argument("shard sent without a checksum"));
        };

        debug!(
            "WriteShard: object={}, stripe={}, pos={}, size={}",
            hex::encode(&shard_id.object_id),
            shard_id.stripe_id,
            shard_id.position,
            data.len()
        );

        let info = self
            .shards
            .write(&shard_id, data, expected, req.use_reserve)
            .await
            .inspect_err(|status| {
                // As counted before the store was split out: a damaged shard
                // brings no bytes in; a full disk isn't counted.
                let bytes_in = match status.code() {
                    tonic::Code::ResourceExhausted => return,
                    tonic::Code::DataLoss => 0,
                    _ => bytes_in,
                };
                self.grpc_metrics.write_shard.record(
                    false,
                    start.elapsed().as_micros() as u64,
                    bytes_in,
                    0,
                );
            })?;

        let resp = WriteShardResponse {
            location: Some(self.block_location(&info)),
            timestamp: info.created_at,
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

        // Checked by the store against the checksum it recorded; one that
        // fails is reported for rebuilding.
        let (data, location) = self.shards.read(&shard_id).await.inspect_err(|_| {
            self.grpc_metrics.read_shard.record(
                false,
                start.elapsed().as_micros() as u64,
                bytes_in,
                0,
            );
        })?;

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
                self.shards.mark_corrupt(&shard_id, &location);
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
                self.shards.mark_corrupt(&shard_id, &location);
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

        // Refused (unavailable) if the removal can't be made durable: the
        // shard stays, for the caller to retry.
        let success = self.shards.delete(&shard_id)?;
        Ok(Response::new(DeleteShardResponse { success }))
    }

    async fn get_shard_meta(
        &self,
        request: Request<GetShardMetaRequest>,
    ) -> Result<Response<GetShardMetaResponse>, Status> {
        let req = request.into_inner();
        let shard_id = req
            .shard_id
            .ok_or_else(|| Status::invalid_argument("missing shard_id"))?;

        let location = self
            .shards
            .info(&shard_id)
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

        for (shard_id, location) in self.shards.page(None, limit) {
            // Filter by object_id if specified
            if !req.object_id.is_empty() && shard_id.object_id != req.object_id {
                continue;
            }

            shards.push(GetShardMetaResponse {
                shard_id: Some(shard_id),
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
        let all_healthy = self.shards.healthy();

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

        for disk in self.shards.disks() {
            let cap = disk.capacity;
            let used = cap - disk.free;

            total_capacity += cap;
            used_capacity += used;

            disk_statuses.push(DiskStatus {
                disk_id: disk.id.to_vec(),
                path: disk.path,
                total_capacity: cap,
                used_capacity: used,
                status: "healthy".to_string(),
                shard_count: disk.shard_count,
            });
        }

        let shard_count = self.shards.count();
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
        self.pg_epochs.check(request.get_ref().pg.as_ref()).await?;
        // The store write syncs the WAL: off the runtime worker, so a
        // sync stalls nothing else and concurrent writes share it.
        blocking(|| {
            let req = request.into_inner();

            let mut object = req
                .object
                .ok_or_else(|| Status::invalid_argument("missing object"))?;
            // The placement group the write was placed under, for an object
            // that doesn't record one yet: kept with it, and indexed by it.
            if object.pg_pool.is_empty()
                && let Some(pg) = req.pg.as_ref().filter(|p| !p.pool.is_empty())
            {
                object.pg_pool.clone_from(&pg.pool);
                object.pg_id = pg.pg_id;
            }

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
                    Some(shard) => self
                        .shards
                        .write_with_metadata(shard, vec![(version_key, value)])?,
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
                Some(shard) => self.shards.write_with_metadata(shard, writes)?,
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
        self.pg_epochs.check(request.get_ref().pg.as_ref()).await?;
        // The store write syncs the WAL: off the runtime worker, so a
        // sync stalls nothing else and concurrent writes share it.
        blocking(|| {
            let req = request.into_inner();

            let _guard = self.usage.lock_key(&req.bucket, &req.key);

            if !req.withdraw_object_id.is_empty() {
                return self.withdraw(&req.bucket, &req.key, &req.withdraw_object_id);
            }

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
                // The key's placement group: as the request was placed, else
                // as its current object records it.
                let pg = req
                    .pg
                    .as_ref()
                    .filter(|p| !p.pool.is_empty())
                    .map(|p| (p.pool.clone(), p.pg_id))
                    .or_else(|| {
                        self.stored_meta(&MetadataKey::object_meta(&req.bucket, &req.key))
                            .filter(|o| !o.pg_pool.is_empty())
                            .map(|o| (o.pg_pool, o.pg_id))
                    });
                self.put_tombstone(&req.bucket, &req.key, &req.version_id, req.stamp, pg)?;
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
mod grpc_write_tests {
    //! Shards sent as bytes in the WriteShard message.

    use super::*;
    use crate::shard_store::LOCATION_RECORDS_FAIL;
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
            pg: None,
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
        osd.shards.disks().iter().map(|d| d.free).sum()
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
        let one_shard =
            objectio_storage::DiskManager::blocks_for(data.len(), 64 * 1024) * 64 * 1024;
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
    use crate::shard_store::META_SPACE_LOW;
    use objectio_proto::storage::ShardId;
    use objectio_proto::storage::ShardState;
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
        crate::shard_store::rot_block(
            &dir.path().join("disk.raw"),
            64 * 1024,
            &*osd.shards,
            &id(position),
            needle,
        );
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
        let free_before = osd.shards.disks()[0].free;
        let small: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        put_small(&osd, &small).await;
        assert_eq!(
            osd.shards.disks()[0].free,
            free_before,
            "it took a disk block"
        );
        assert_eq!(osd.shards.info(&id(0)).unwrap().disk_id, [0; 16]);
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
        assert_eq!(osd.shards.count(), 1);
        drop(osd);

        let osd = reopen_at(&dir);
        assert_eq!(osd.shards.count(), 1, "not counted after a restart");
        assert_eq!(
            &read(&osd, crc).await.unwrap().into_inner().data[..],
            &small[..]
        );

        // Its bytes rot in the record: the scrubber finds it, reads refuse
        // it, and a rewrite clears it.
        crate::shard_store::rot_small(&*osd.meta_store, &id(0), |b| b[5] ^= 0xff);
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
        assert_eq!(osd.shards.count(), 0);
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
        let found = |osd: &OsdService| osd.shards.info(&id(3)).is_some();
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
        crate::shard_store::rot_small(&*osd.meta_store, &id(3), |b| b[5] ^= 0xff);
        let both = meta(true).await.unwrap().into_inner();
        assert!(both.found && both.small_shard.is_none());
        assert_eq!(osd.shards.state(&id(3)), ShardState::Corrupt);
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

        let info = osd.shards.info(&id(1)).unwrap();
        assert_ne!(info.disk_id, [0; 16], "kept in the index");
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

    /// A disk path under /dev that doesn't exist is a missing drive, not a
    /// file to create (it was made in memory, and the OSD ran on it).
    #[test]
    fn a_missing_device_is_refused_not_created() {
        let dir = tempfile::tempdir().unwrap();
        let path = "/dev/objectio-test-no-such-device";
        let Err(e) = OsdService::new(vec![path.to_string()], 64 * 1024, dir.path().join("state"))
        else {
            panic!("an OSD started on a device that isn't there");
        };
        assert!(e.contains("no such device"), "{e}");
        assert!(!std::path::Path::new(path).exists());
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

        let free_before = osd.shards.disks()[0].free;
        write(&osd, 0, &data).await;
        assert_eq!(states(&osd, &[0]).await, vec![ShardState::Ok]);
        assert_eq!(
            osd.shards.disks()[0].free,
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

    async fn withdraw(osd: &OsdService, id: u8) -> DeleteObjectMetaResponse {
        osd.delete_object_meta(Request::new(DeleteObjectMetaRequest {
            bucket: "b".into(),
            key: "k".into(),
            withdraw_object_id: vec![id; 16],
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner()
    }

    /// A refused write withdrawn from a copy: its entries go and nothing
    /// else, with no tombstone; the version it hid is current again; another
    /// object's id changes nothing.
    #[tokio::test]
    async fn a_withdrawn_write_leaves_what_it_hid() {
        let (_dir, osd) = osd();
        let current = |osd: &OsdService| osd.stored_meta(&MetadataKey::object_meta("b", "k"));
        put(&osd, object(1, ""), false, &[]).await.unwrap();
        assert!(withdraw(&osd, 9).await.removed.is_none());
        assert_eq!(current(&osd).unwrap().object_id, vec![1; 16]);
        assert_eq!(
            withdraw(&osd, 1).await.removed.unwrap().object_id,
            vec![1; 16]
        );
        assert!(current(&osd).is_none());
        assert_eq!(osd.tombstone("b", "k", ""), 0, "it left a tombstone");

        let v1 = ObjectMeta {
            modified_at: 1,
            ..object(2, "v1")
        };
        let v2 = ObjectMeta {
            modified_at: 2,
            ..object(3, "v2")
        };
        put(&osd, v1, true, &[]).await.unwrap();
        put(&osd, v2, true, &[]).await.unwrap();
        let after = withdraw(&osd, 3).await;
        assert_eq!(after.current.unwrap().object_id, vec![2; 16]);
        assert_eq!(current(&osd).unwrap().object_id, vec![2; 16]);
        let version = |v: &str| osd.stored_meta(&MetadataKey::object_version("b", "k", v));
        assert!(version("v2").is_none(), "the withdrawn version stayed");
        assert!(version("v1").is_some(), "the version it hid went too");
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
            ..Default::default()
        }))
        .await
        .unwrap();
        put(&osd, object(5, ""), false, &[9; 16]).await.unwrap();
    }
}
