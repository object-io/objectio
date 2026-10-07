//! Where the OSD keeps shard bytes and their locations, as an interface
//! (B27, objectio-docs `core/osd-engines.md`): what the OSD's handlers need
//! of the engine, so one engine can replace another. [`BlockStore`] (raw
//! disks of checksummed blocks, locations recorded in the metadata index)
//! is the implementation today.
//!
//! The contract, which every implementation keeps and the conformance tests
//! check:
//!
//! - **Durable when acknowledged.** A write that returns `Ok` is on stable
//!   storage, bytes and location: a restart finds it.
//! - **Checksums.** A shard is checked against its CRC32C when written (a
//!   mismatch is refused, nothing stored), when read and when scrubbed; one
//!   that fails is reported corrupt until it is rewritten.
//! - **Atomic with metadata.** A small shard and its object's metadata go
//!   in one all-or-nothing write (B21).
//! - **Space comes back.** A delete, or a rewrite of the same shard, frees
//!   the old copy's space, never before the change is durable.
//! - **Room for repair.** Client writes stop at the full ratio; the rest is
//!   kept for writes that restore redundancy (`use_reserve`).
//! - **Bounded memory.** Shards are listed a page at a time; nothing grows
//!   with the number of shards.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use objectio_common::version::SMALL_SHARD_MAX;
use objectio_proto::storage::{ShardId, ShardState, SmallShard};
use objectio_storage::DiskManager;
use objectio_storage::metadata::{MetaIndex, MetadataKey};
use parking_lot::RwLock;
use tonic::Status;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// What the OSD knows of a stored shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardInfo {
    pub size: u32,
    pub crc32c: u32,
    /// When it was written (Unix seconds).
    pub created_at: u64,
    /// The device it is on, all zeros when on none (a small shard kept in
    /// its record, B21).
    pub disk_id: [u8; 16],
    /// Where on the device, in bytes.
    pub offset: u64,
}

/// One device's space, shards and I/O counts, for `GetStatus` and the
/// metrics.
#[derive(Clone, Debug)]
pub struct DiskReport {
    pub id: [u8; 16],
    pub path: String,
    pub capacity: u64,
    pub free: u64,
    pub shard_count: u64,
    pub reads: u64,
    pub writes: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_errors: u64,
    pub write_errors: u64,
    pub checksum_errors: u64,
}

/// The engine that keeps this OSD's shards. See the module documentation
/// for what an implementation guarantees. Errors are the `Status` the RPC
/// returns.
#[allow(clippy::result_large_err)] // tonic::Status, as the handlers return
#[async_trait::async_trait]
pub trait ShardStore: Send + Sync {
    /// Store `data` as shard `id`, durably, if it matches `crc32c`
    /// (`data_loss` if not, nothing stored). It replaces, and frees, an
    /// earlier copy, and clears its corrupt mark. Without `use_reserve`
    /// it is refused (`resource_exhausted`) past the full ratio.
    async fn write(
        &self,
        id: &ShardId,
        data: &[u8],
        crc32c: u32,
        use_reserve: bool,
    ) -> Result<ShardInfo, Status>;

    /// Store a small shard and the metadata `writes` in one atomic, durable
    /// write (B21): both or neither.
    fn write_with_metadata(
        &self,
        shard: SmallShard,
        writes: Vec<(MetadataKey, Vec<u8>)>,
    ) -> Result<(), Status>;

    /// Shard `id`'s bytes, checked against its checksum: `not_found` if it
    /// isn't here; `data_loss`, and marked corrupt, if it can't be read
    /// back intact.
    async fn read(&self, id: &ShardId) -> Result<(Vec<u8>, ShardInfo), Status>;

    /// Shard `id` if it is small and kept with its metadata (B21) and
    /// passes its checksum; one that fails is marked corrupt.
    fn small_shard(&self, id: &ShardId) -> Option<SmallShard>;

    /// Report that the copy `copy` of shard `id` failed a check the caller
    /// made (the checksum its object records), unless the shard has been
    /// rewritten or deleted since.
    fn mark_corrupt(&self, id: &ShardId, copy: &ShardInfo);

    /// Delete shard `id`, durably, then free its space; whether it was
    /// here. `unavailable` if the removal can't be made durable: the shard
    /// stays.
    fn delete(&self, id: &ShardId) -> Result<bool, Status>;

    /// Delete every shard (the OSD was drained); how many.
    fn purge(&self) -> Result<u64, Status>;

    /// Whether shard `id` is here and intact, as far as known.
    fn state(&self, id: &ShardId) -> ShardState;

    /// What is known of shard `id`, if it is here.
    fn info(&self, id: &ShardId) -> Option<ShardInfo>;

    /// Up to `n` shards in key order (object id, stripe, position, as
    /// [`shard_key`] spells them), after `after`.
    fn page(&self, after: Option<&ShardId>, n: usize) -> Vec<(ShardId, ShardInfo)>;

    /// How many shards are here.
    fn count(&self) -> u64;

    /// Read back every shard and check it, at no more than `bytes_per_sec`
    /// (0: unpaced), calling `checked` with each shard's size. Those that
    /// fail are marked corrupt.
    async fn scrub(&self, bytes_per_sec: u64, checked: &(dyn Fn(u64) + Send + Sync));

    /// Shards marked corrupt and not yet rewritten.
    fn corrupt_now(&self) -> u64;

    /// Shards found corrupt since start, by a read or a scrub.
    fn corrupt_found(&self) -> u64;

    /// Each device's space, shards and I/O counts.
    fn disks(&self) -> Vec<DiskReport>;

    /// Whether every device answers.
    fn healthy(&self) -> bool;

    /// The share of each device client writes may fill (B3).
    fn set_full_ratio(&self, ratio: f64);

    /// Mark the devices as this OSD's (`node_id`) in cluster `cluster_uuid`;
    /// refused for a device that belongs to another cluster.
    fn claim(&self, cluster_uuid: Uuid, node_id: [u8; 16]) -> Result<(), String>;
}

/// A shard's key in the index: hex object id, stripe, position.
pub fn shard_key(object_id: &[u8], stripe_id: u64, position: u32) -> String {
    format!("{}:{}:{}", hex::encode(object_id), stripe_id, position)
}

fn key_of(id: &ShardId) -> String {
    shard_key(&id.object_id, id.stripe_id, id.position)
}

/// The shard a key names; `None` for one [`shard_key`] wouldn't have
/// written, so a cursor made from it gives back the same key.
fn id_of(key: &str) -> Option<ShardId> {
    let mut parts = key.split(':');
    let (Some(object), Some(stripe), Some(position), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let id = ShardId {
        object_id: hex::decode(object).ok()?,
        stripe_id: stripe.parse().ok()?,
        position: position.parse().ok()?,
    };
    (key_of(&id) == key).then_some(id)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
thread_local! {
    /// Tests: make recording (or forgetting) a shard's location fail, as an
    /// unwritable or full metadata log would. Per thread, so a test's
    /// failures stay in that test.
    pub(crate) static LOCATION_RECORDS_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
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
pub(crate) struct ShardLocation {
    pub(crate) disk_idx: usize,
    pub(crate) block_num: u64,
    pub(crate) size: u32,
    pub(crate) crc32c: u32,
    pub(crate) created_at: u64,
    /// A small shard's bytes, kept in its record rather than in a disk block
    /// (B21: written, with its object's metadata, in one log flush);
    /// `disk_idx` is then [`SMALL_DISK`].
    pub(crate) small: Option<Vec<u8>>,
}

/// The `disk_idx` of a shard kept in its record (B21).
const SMALL_DISK: usize = u32::MAX as usize;

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
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        prost::Message::encode_to_vec(&ShardLocationRecord {
            disk_idx: u32::try_from(self.disk_idx).unwrap_or(u32::MAX),
            block_num: self.block_num,
            size: self.size,
            crc32c: self.crc32c,
            created_at: self.created_at,
            small: self.small.clone().unwrap_or_default(),
        })
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, prost::DecodeError> {
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

/// Build the MetadataStore key we persist a ShardLocation under.
pub(crate) fn shard_loc_meta_key(shard_key: &str) -> MetadataKey {
    let mut bytes = Vec::with_capacity(SHARD_LOC_PREFIX.len() + shard_key.len());
    bytes.extend_from_slice(SHARD_LOC_PREFIX);
    bytes.extend_from_slice(shard_key.as_bytes());
    MetadataKey::from_bytes(bytes)
}

/// Persist a ShardLocation so a restart can rebuild the in-memory
/// index. Called on every successful WriteShard.
pub(crate) fn persist_shard_location(
    meta_store: &dyn MetaIndex,
    shard_key: &str,
    loc: &ShardLocation,
) -> std::result::Result<(), String> {
    #[cfg(test)]
    if location_records_fail() {
        return Err("injected: the metadata log is unwritable".into());
    }
    let key = shard_loc_meta_key(shard_key);
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
    let key = shard_loc_meta_key(shard_key);
    meta_store
        .delete(&key)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

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
        let v = self.store.get(&shard_loc_meta_key(key))?;
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
        persist_shard_location(&*self.store, key, loc)?;
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
        #[cfg(test)]
        if location_records_fail() {
            return Err("injected: the metadata log is unwritable".into());
        }
        extra.push((shard_loc_meta_key(key), loc.to_bytes()));
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
        forget_shard_location(&*self.store, key)?;
        self.counted(Some(&old), None);
        Ok(Some(old))
    }

    /// Up to `n` shards in key order, after `after`: a page, so walking
    /// every shard (scrub, purge) holds one page at a time.
    fn page(&self, after: Option<&str>, n: usize) -> Vec<(String, ShardLocation)> {
        let prefix = MetadataKey::from_bytes(SHARD_LOC_PREFIX.to_vec());
        let after = after.map(shard_loc_meta_key);
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
    pub(crate) static META_SPACE_LOW: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

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

/// The raw disks a [`BlockStore`] is opened on, before its index is.
pub struct Disks {
    disks: Vec<DiskManager>,
    disk_ids: Vec<[u8; 16]>,
    /// Disks formatted just now, by index: whatever the shard index says
    /// was on them is gone.
    formatted_now: Vec<bool>,
}

impl Disks {
    /// Open each disk at `paths`, formatting one only when it is blank (or a
    /// file not there yet), with blocks of `block_size`. Existing disks
    /// keep the block size in their superblock.
    pub fn open(paths: &[String], block_size: u32) -> Result<Self, String> {
        let mut disks = Vec::new();
        let mut disk_ids = Vec::new();
        let mut formatted_now = Vec::new();

        for path in paths {
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
                    // A device that isn't there is a wrong path or a missing
                    // drive, not a file to create: under /dev that file was
                    // made in memory (devtmpfs), and the OSD ran on it.
                    if !std::path::Path::new(path).exists() && path.starts_with("/dev/") {
                        return Err(format!(
                            "disk {path} does not exist: no such device (a file is created \
                             for a disk only outside /dev)"
                        ));
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
        Ok(Self {
            disks,
            disk_ids,
            formatted_now,
        })
    }

    /// How many disks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.disks.len()
    }

    /// Whether there are none (never, once opened).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.disks.is_empty()
    }

    /// This OSD's node id, from the disks' superblocks, else `id_path`,
    /// else new; written to every disk that doesn't carry it yet.
    pub fn identity(&self, id_path: &Path) -> Result<[u8; 16], String> {
        // Identity resolution: prefer any disk's superblock, then
        // state-PVC fallback, then generate fresh.
        let (node_id, cluster_uuid, from_disk) = resolve_node_identity(&self.disks, id_path)?;

        // If the identity came from the state PVC (or was freshly
        // generated), write it to every disk's superblock so the next
        // restart has the real Ceph/Rook pattern (disk = truth). Disks
        // that already matched are no-ops.
        if !from_disk {
            for disk in &self.disks {
                if let Err(e) = disk.set_identity(cluster_uuid, node_id) {
                    warn!(
                        "Failed to write identity to disk {}: {e} — next \
                         restart will fall back to state-PVC file",
                        disk.path()
                    );
                } else {
                    info!(
                        "Persisted OSD identity to disk {} (cluster_uuid={}, node_id={})",
                        disk.path(),
                        cluster_uuid,
                        hex::encode(node_id)
                    );
                }
            }
        }
        Ok(node_id)
    }
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
    disks: &[DiskManager],
    id_path: &Path,
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

/// [`ShardStore`] on raw disks: each shard an extent of checksummed blocks,
/// its location recorded in the OSD's metadata index (`osd_loc:` keys); a
/// small shard (B21) kept in its record instead.
pub struct BlockStore {
    disks: Vec<DiskManager>,
    disk_ids: Vec<[u8; 16]>,
    /// Shard index: object_id:stripe_id:position -> location.
    index: ShardIndex,
    /// The share of a disk client writes may fill (B3), as `f64` bits; the
    /// rest is kept for writes that restore redundancy.
    full_ratio: AtomicU64,
    /// Round-robin disk selection for writes
    next_disk: RwLock<usize>,
    /// Shards that cannot be read back intact — failing their checksum or
    /// unreadable — found by the scrubber or a read. Kept until the shard is rewritten; reported through
    /// `CheckShards` so Meta's repairer rebuilds them. In memory only: after
    /// a restart the next scrub pass finds them again.
    corrupt: RwLock<HashSet<String>>,
    /// Shards found corrupt since start.
    corrupt_found: AtomicU64,
    /// Whether the metadata store's filesystem has room for small shards.
    meta_space: MetaSpace,
}

impl BlockStore {
    /// The store over `disks`, its locations in `meta` (kept in `meta_dir`,
    /// whose free space decides where small shards go). The index, as
    /// replayed when `meta` was opened, is reconciled with the disks.
    pub fn new(disks: Disks, meta: Arc<dyn MetaIndex>, meta_dir: PathBuf) -> Self {
        let Disks {
            disks,
            disk_ids,
            formatted_now,
        } = disks;
        let num_disks = disks.len();
        // Rebuild the in-memory shard index from persisted entries
        // (replayed from its log when the metadata index was opened
        // above). Before this step the OSD used to report 0 shards on
        // every restart even though disk.raw was full.
        let index = ShardIndex::new(Arc::clone(&meta), num_disks);
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
        meta.for_each_prefix(&prefix, None, &mut |k: &[u8], v: &[u8]| {
            let loc = match ShardLocation::from_bytes(v) {
                Ok(loc) => loc,
                Err(e) => {
                    warn!("skipping corrupt ShardLocation entry: {e}");
                    return true;
                }
            };
            if loc.small.is_some() {
                // In its record, on no disk: nothing to reconcile.
                index.counted(None, Some(&loc));
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
            index.counted(None, Some(&loc));
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
            if let Err(e) = meta.batch_delete(chunk) {
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
        info!("Shard index: {} shards", index.count());
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
        Self {
            disks,
            disk_ids,
            index,
            full_ratio: AtomicU64::new(DEFAULT_FULL_RATIO.to_bits()),
            next_disk: RwLock::new(0),
            corrupt: RwLock::new(HashSet::new()),
            corrupt_found: AtomicU64::new(0),
            meta_space: MetaSpace::new(meta_dir),
        }
    }

    /// Select disk for write (round-robin)
    fn select_disk_for_write(&self) -> usize {
        let mut next = self.next_disk.write();
        let disk_idx = *next;
        *next = (*next + 1) % self.disks.len();
        disk_idx
    }

    /// Whether a client write of `blocks` fits on disk `disk_idx` without
    /// going into the space kept for writes that restore redundancy. A full
    /// disk refused client writes only when it had no block left, so repair
    /// had nowhere to rebuild a lost shard on a full cluster.
    #[allow(clippy::result_large_err)]
    fn check_room(&self, disk_idx: usize, blocks: u64) -> Result<(), Status> {
        let disk = &self.disks[disk_idx];
        let need = blocks * u64::from(disk.block_size());
        let full_ratio = f64::from_bits(self.full_ratio.load(Ordering::Relaxed));
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let reserve = (disk.capacity() as f64 * (1.0 - full_ratio)) as u64;
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

    /// Where a shard is, as the RPCs report it: its disk and offset, or, for
    /// one kept in its record (B21), no disk.
    fn info_of(&self, loc: &ShardLocation) -> ShardInfo {
        let (disk_id, offset) = match self.disks.get(loc.disk_idx) {
            Some(disk) if loc.small.is_none() => (
                self.disk_ids[loc.disk_idx],
                loc.block_num * u64::from(disk.block_size()),
            ),
            _ => ([0u8; 16], 0),
        };
        ShardInfo {
            size: loc.size,
            crc32c: loc.crc32c,
            created_at: loc.created_at,
            disk_id,
            offset,
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
    fn mark_corrupt_at(&self, key: &str, block_num: u64) {
        let still_there = self
            .index
            .get(key)
            .is_some_and(|l| l.block_num == block_num);
        if still_there && self.corrupt.write().insert(key.to_string()) {
            self.corrupt_found.fetch_add(1, Ordering::Relaxed);
            warn!("shard {key} (block {block_num}) is corrupt; Meta's repairer will rebuild it");
        }
    }

    /// Write a small shard to a disk block, synced, as `WriteShard` does:
    /// for when the metadata store's filesystem is nearly full. Its location
    /// is the caller's to record; a failure before that frees the extent.
    #[allow(clippy::result_large_err)] // tonic::Status, as the handlers return
    fn spill_small_shard(
        &self,
        id: &ShardId,
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
            created_at: now_secs(),
            small: None,
        })
    }
}

#[async_trait::async_trait]
impl ShardStore for BlockStore {
    async fn write(
        &self,
        id: &ShardId,
        data: &[u8],
        expected: u32,
        use_reserve: bool,
    ) -> Result<ShardInfo, Status> {
        // Checked before a block is allocated, so a shard damaged on the way
        // is refused rather than stored and later served as good under a
        // checksum computed from the damage.
        let crc32c = crc32c::crc32c(data);
        if expected != crc32c {
            return Err(Status::data_loss(format!(
                "shard has crc32c {crc32c:08x}, expected {expected:08x}"
            )));
        }

        // Select disk and allocate an extent sized to this shard.
        //
        // One shard used to take exactly one block, and the block was sized
        // for the largest shard any EC scheme could produce — 4 MB — so a
        // 4 KB object and a 4 MB object both cost 24 MB across a 4+2 stripe.
        // Measured at 6144x and 6x amplification; the real capacity limit was
        // an object count, not a byte count, and nothing reported it.
        let disk_idx = self.select_disk_for_write();
        let blocks = self.disks[disk_idx].blocks_for_len(data.len());
        if !use_reserve {
            self.check_room(disk_idx, blocks)?;
        }
        let block_num = self.allocate_extent(disk_idx, blocks)?;

        let disk = &self.disks[disk_idx];

        // Prepare object_id as fixed array
        let mut object_id = [0u8; 16];
        let copy_len = id.object_id.len().min(16);
        object_id[..copy_len].copy_from_slice(&id.object_id[..copy_len]);

        // Write block through the async IoBackend — the tokio
        // reactor stays free during the syscall / io_uring wait. On
        // Linux + --features io-uring this is +25% throughput on
        // 4 MiB stripes vs the old sync path (see storage-io-levels.md).
        // Nothing records this extent until the location below, so if the
        // write or the sync fails the extent goes straight back.
        let started = Instant::now();
        if let Err(e) = disk
            .write_block_async(block_num, object_id, id.stripe_id, data)
            .await
        {
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

        // Store location in index
        let key = key_of(id);
        let loc = ShardLocation {
            disk_idx,
            block_num,
            size: data.len() as u32,
            crc32c,
            created_at: now_secs(),
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
        let replaced = match self.index.record(&key, &loc) {
            Ok(replaced) => replaced,
            Err(e) => {
                error!("Shard {key} written but its location not recorded: {e}; write refused");
                return Err(Status::unavailable(format!(
                    "the shard's location could not be recorded durably ({e}); not stored, retry"
                )));
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
        Ok(self.info_of(&loc))
    }

    fn write_with_metadata(
        &self,
        shard: SmallShard,
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
        let key = key_of(&id);
        let loc = if self.meta_space.low() {
            // No room to spare in the index: a disk block, as WriteShard.
            self.spill_small_shard(&id, &shard.data, crc32c)?
        } else {
            ShardLocation {
                disk_idx: SMALL_DISK,
                block_num: 0,
                size: shard.data.len() as u32,
                crc32c,
                created_at: now_secs(),
                small: Some(shard.data.clone()),
            }
        };
        let replaced = self
            .index
            .record_with(&key, &loc, writes)
            .map_err(|e| Status::internal(format!("failed to store object metadata: {e}")))?;
        if let Some(old) = replaced {
            self.free_location(&old);
        }
        self.corrupt.write().remove(&key);
        Ok(())
    }

    async fn read(&self, id: &ShardId) -> Result<(Vec<u8>, ShardInfo), Status> {
        let key = key_of(id);
        let location = self
            .index
            .get(&key)
            .ok_or_else(|| Status::not_found("shard not found"))?;

        let data = if let Some(small) = location.small.clone() {
            // Kept in its record (B21): checked against the checksum
            // recorded with it, as a block's own checks would.
            if crc32c::crc32c(&small) != location.crc32c {
                self.mark_corrupt_at(&key, location.block_num);
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
                // Unreadable is as good as gone: report it for rebuilding.
                self.mark_corrupt_at(&key, location.block_num);
                Status::data_loss(format!("shard is unreadable: {e}"))
            })?;
            data
        };
        Ok((data, self.info_of(&location)))
    }

    fn small_shard(&self, id: &ShardId) -> Option<SmallShard> {
        let key = key_of(id);
        let loc = self.index.get(&key)?;
        let data = loc.small?;
        if crc32c::crc32c(&data) != loc.crc32c {
            self.mark_corrupt_at(&key, loc.block_num);
            return None;
        }
        Some(SmallShard {
            shard_id: Some(id.clone()),
            crc32c: loc.crc32c,
            data,
        })
    }

    fn mark_corrupt(&self, id: &ShardId, copy: &ShardInfo) {
        let key = key_of(id);
        let Some(loc) = self.index.get(&key) else {
            return;
        };
        let now = self.info_of(&loc);
        if now.disk_id == copy.disk_id && now.offset == copy.offset {
            self.mark_corrupt_at(&key, loc.block_num);
        }
    }

    fn delete(&self, id: &ShardId) -> Result<bool, Status> {
        let key = key_of(id);

        // The removal is durable before the blocks are freed. If it fails,
        // the persisted entry still points at these blocks: freeing them
        // would let another shard's bytes sit where a restart expects this
        // one. So the shard stays, and the delete is refused for the caller
        // to retry.
        let removed = match self.index.forget(&key) {
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
        Ok(removed.is_some())
    }

    fn purge(&self) -> Result<u64, Status> {
        // The index entry, its persisted copy, then the block — the same
        // order as DeleteShard, so a crash leaks a block rather than
        // handing a live shard's block out.
        let mut shards = 0u64;
        loop {
            // Forgotten as it goes, so each page starts at the next.
            let page = self.index.page(None, 1024);
            if page.is_empty() {
                break;
            }
            for (key, _) in page {
                // As in DeleteShard: blocks are freed only once the removal
                // is durable. Otherwise stop; the purge is retried.
                match self.index.forget(&key) {
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
        Ok(shards)
    }

    fn state(&self, id: &ShardId) -> ShardState {
        let key = key_of(id);
        if self.corrupt.read().contains(&key) {
            ShardState::Corrupt
        } else if self.index.contains(&key) {
            ShardState::Ok
        } else {
            ShardState::Missing
        }
    }

    fn info(&self, id: &ShardId) -> Option<ShardInfo> {
        self.index.get(&key_of(id)).map(|l| self.info_of(&l))
    }

    fn page(&self, after: Option<&ShardId>, n: usize) -> Vec<(ShardId, ShardInfo)> {
        let after = after.map(key_of);
        self.index
            .page(after.as_deref(), n)
            .into_iter()
            .filter_map(|(key, loc)| Some((id_of(&key)?, self.info_of(&loc))))
            .collect()
    }

    fn count(&self) -> u64 {
        self.index.count()
    }

    async fn scrub(&self, bytes_per_sec: u64, checked: &(dyn Fn(u64) + Send + Sync)) {
        let started = Instant::now();
        let mut bytes = 0u64;
        // A page of shards at a time, in key order.
        let mut after: Option<String> = None;
        loop {
            let page = self.index.page(after.as_deref(), 1024);
            let Some((last, _)) = page.last() else { break };
            after = Some(last.clone());
            for (key, loc) in page {
                if let Some(data) = &loc.small {
                    if crc32c::crc32c(data) != loc.crc32c {
                        self.mark_corrupt_at(&key, loc.block_num);
                    }
                    bytes += u64::from(loc.size);
                    checked(u64::from(loc.size));
                    continue;
                }
                if loc.disk_idx >= self.disks.len() {
                    continue;
                }
                // Any failure counts, not only a checksum: a block whose header
                // no longer parses, or that the disk cannot return, cannot be
                // served either. `mark_corrupt_at` ignores a shard rewritten or
                // deleted since the snapshot.
                if let Err(e) = self.disks[loc.disk_idx]
                    .read_block_async(loc.block_num)
                    .await
                {
                    debug!("scrub: {key} is unreadable: {e}");
                    self.mark_corrupt_at(&key, loc.block_num);
                }
                bytes += u64::from(loc.size);
                checked(u64::from(loc.size));
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
    }

    fn corrupt_now(&self) -> u64 {
        self.corrupt.read().len() as u64
    }

    fn corrupt_found(&self) -> u64 {
        self.corrupt_found.load(Ordering::Relaxed)
    }

    fn disks(&self) -> Vec<DiskReport> {
        self.disks
            .iter()
            .enumerate()
            .map(|(i, disk)| {
                let stats = disk.stats();
                let load = |c: &AtomicU64| c.load(Ordering::Relaxed);
                DiskReport {
                    id: self.disk_ids[i],
                    path: disk.path().to_string(),
                    capacity: disk.capacity(),
                    free: disk.free_space(),
                    shard_count: self.index.count_on(i),
                    reads: load(&stats.reads),
                    writes: load(&stats.writes),
                    bytes_read: load(&stats.bytes_read),
                    bytes_written: load(&stats.bytes_written),
                    read_errors: load(&stats.read_errors),
                    write_errors: load(&stats.write_errors),
                    checksum_errors: load(&stats.checksum_errors),
                }
            })
            .collect()
    }

    fn healthy(&self) -> bool {
        // Check if all disks are accessible
        self.disks.iter().all(|d| d.verify_block(0).is_ok())
    }

    fn set_full_ratio(&self, ratio: f64) {
        self.full_ratio
            .store(ratio.clamp(0.0, 1.0).to_bits(), Ordering::Relaxed);
    }

    fn claim(&self, cluster_uuid: Uuid, node_id: [u8; 16]) -> Result<(), String> {
        for disk in &self.disks {
            if disk.cluster_uuid() == cluster_uuid && disk.osd_node_id() == node_id {
                continue; // already stamped, nothing to do
            }
            disk.set_identity(cluster_uuid, node_id)
                .map_err(|e| format!("disk {}: {e}", disk.path()))?;
            info!(
                "Stamped cluster_uuid {} on disk {}",
                cluster_uuid,
                disk.path()
            );
        }
        Ok(())
    }
}

/// Tests: flip one byte of `needle` where shard `id` lies in `disk_file`
/// (a [`BlockStore`]'s only disk, of blocks of `block_size`), the way a bad
/// sector would.
#[cfg(test)]
pub(crate) fn rot_block(
    disk_file: &Path,
    block_size: u32,
    store: &dyn ShardStore,
    id: &ShardId,
    needle: &[u8],
) {
    use std::io::{Read, Seek, SeekFrom, Write};
    let info = store.info(id).expect("the shard to rot");
    assert_ne!(info.disk_id, [0; 16], "not in a block");
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(disk_file)
        .unwrap();
    let len = f.metadata().unwrap().len();
    // Where blocks start on a disk of this size, as it was formatted.
    let data_offset = objectio_storage::layout::Superblock::new(len, block_size)
        .unwrap()
        .data_offset;
    let start = data_offset + info.offset;
    let mut bytes = vec![0; block_size as usize * 4];
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

/// Tests: replace the bytes of small shard `key`'s record with `rot` of
/// them, the way rot in the index would.
#[cfg(test)]
pub(crate) fn rot_small(meta: &dyn MetaIndex, id: &ShardId, rot: impl FnOnce(&mut Vec<u8>)) {
    let key = key_of(id);
    let mut loc = ShardLocation::from_bytes(&meta.get(&shard_loc_meta_key(&key)).unwrap()).unwrap();
    rot(loc.small.as_mut().expect("a small shard"));
    persist_shard_location(meta, &key, &loc).unwrap();
}

/// The contract as tests, for any implementation: each takes an [`Engine`]
/// that opens the implementation's store in a directory (and opens it again
/// there, to check what survives).
#[cfg(test)]
pub(crate) mod conformance {
    use super::{ShardInfo, ShardStore};
    use objectio_proto::storage::{ShardId, ShardState, SmallShard};
    use objectio_storage::metadata::{MetaIndex, MetadataKey};
    use std::path::Path;
    use std::sync::Arc;

    /// A store, and the metadata index it records into.
    pub type Opened = (Arc<dyn ShardStore>, Arc<dyn MetaIndex>);

    /// An implementation, as the suite drives it.
    pub struct Engine {
        /// Open the store kept in a directory, with the metadata index it
        /// records into.
        pub open: fn(&Path) -> Opened,
        /// Damage the stored bytes of a shard held as a block (`needle` is
        /// some of them), as a bad sector would.
        pub rot: fn(&Path, &dyn ShardStore, &ShardId, &[u8]),
        /// Make writes of the metadata index fail (or not), as an
        /// unwritable log would.
        pub fail_records: fn(bool),
    }

    fn id(object: u8, position: u32) -> ShardId {
        ShardId {
            object_id: vec![object; 16],
            stripe_id: 0,
            position,
        }
    }

    fn data(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 241) as u8 ^ seed).collect()
    }

    fn free(store: &dyn ShardStore) -> u64 {
        store.disks().iter().map(|d| d.free).sum()
    }

    async fn put(store: &dyn ShardStore, id: &ShardId, data: &[u8]) -> ShardInfo {
        store
            .write(id, data, crc32c::crc32c(data), false)
            .await
            .unwrap()
    }

    fn small(id: &ShardId, data: &[u8]) -> SmallShard {
        SmallShard {
            shard_id: Some(id.clone()),
            crc32c: crc32c::crc32c(data),
            data: data.to_vec(),
        }
    }

    /// Every check, against one implementation.
    pub async fn run(engine: &Engine) {
        reads_its_writes(engine).await;
        a_damaged_write_is_refused(engine).await;
        writes_survive_a_reopen(engine).await;
        a_delete_frees_and_forgets(engine).await;
        an_overwrite_frees_the_old_copy(engine).await;
        rot_is_found_and_a_rewrite_clears_it(engine).await;
        a_shard_with_metadata_is_all_or_nothing(engine).await;
        shards_page_in_key_order(engine).await;
        client_writes_stop_at_the_full_ratio(engine).await;
    }

    async fn reads_its_writes(engine: &Engine) {
        let dir = tempfile::tempdir().unwrap();
        let (store, _meta) = (engine.open)(dir.path());
        assert_eq!(store.count(), 0);
        assert_eq!(store.state(&id(1, 0)), ShardState::Missing);
        assert_eq!(
            store.read(&id(1, 0)).await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        let bytes = data(1, 70_000);
        let info = put(&*store, &id(1, 0), &bytes).await;
        assert_eq!(info.size, 70_000);
        assert_eq!(info.crc32c, crc32c::crc32c(&bytes));
        assert_eq!(store.info(&id(1, 0)), Some(info.clone()));
        let (got, read_info) = store.read(&id(1, 0)).await.unwrap();
        assert_eq!(got, bytes);
        assert_eq!(read_info, info);
        assert_eq!(store.state(&id(1, 0)), ShardState::Ok);
        assert_eq!(store.count(), 1);
        assert_eq!(store.disks().iter().map(|d| d.shard_count).sum::<u64>(), 1);
        assert!(store.healthy());
    }

    async fn a_damaged_write_is_refused(engine: &Engine) {
        let dir = tempfile::tempdir().unwrap();
        let (store, _meta) = (engine.open)(dir.path());
        let before = free(&*store);
        let bytes = data(2, 100_000);
        let err = store
            .write(&id(2, 0), &bytes, crc32c::crc32c(&bytes) ^ 1, false)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::DataLoss, "{err}");
        assert_eq!(store.state(&id(2, 0)), ShardState::Missing);
        assert_eq!(free(&*store), before, "a refused shard kept its space");
    }

    async fn writes_survive_a_reopen(engine: &Engine) {
        let dir = tempfile::tempdir().unwrap();
        let big = data(3, 200_000);
        let little = data(4, 5_000);
        let (used, info) = {
            let (store, _meta) = (engine.open)(dir.path());
            let before = free(&*store);
            let info = put(&*store, &id(3, 0), &big).await;
            store
                .write_with_metadata(small(&id(3, 1), &little), Vec::new())
                .unwrap();
            put(&*store, &id(3, 2), &data(5, 1000)).await;
            assert!(store.delete(&id(3, 2)).unwrap());
            (before - free(&*store), info)
        };
        let (store, _meta) = (engine.open)(dir.path());
        assert_eq!(store.count(), 2);
        assert_eq!(store.info(&id(3, 0)), Some(info));
        assert_eq!(store.read(&id(3, 0)).await.unwrap().0, big);
        assert_eq!(store.read(&id(3, 1)).await.unwrap().0, little);
        assert_eq!(store.state(&id(3, 2)), ShardState::Missing);
        let capacity: u64 = store.disks().iter().map(|d| d.capacity).sum();
        assert_eq!(capacity - free(&*store), used, "space not as it was");
    }

    async fn a_delete_frees_and_forgets(engine: &Engine) {
        let dir = tempfile::tempdir().unwrap();
        let (store, _meta) = (engine.open)(dir.path());
        let before = free(&*store);
        put(&*store, &id(6, 0), &data(6, 150_000)).await;
        assert!(free(&*store) < before);
        assert!(store.delete(&id(6, 0)).unwrap());
        assert_eq!(free(&*store), before, "its space did not come back");
        assert_eq!(store.state(&id(6, 0)), ShardState::Missing);
        assert_eq!(store.info(&id(6, 0)), None);
        assert_eq!(store.count(), 0);
        assert!(!store.delete(&id(6, 0)).unwrap(), "deleted twice");

        // A delete that can't be made durable keeps the shard.
        put(&*store, &id(6, 1), &data(7, 10_000)).await;
        let with = free(&*store);
        (engine.fail_records)(true);
        let err = store.delete(&id(6, 1));
        (engine.fail_records)(false);
        assert_eq!(err.unwrap_err().code(), tonic::Code::Unavailable);
        assert_eq!(store.state(&id(6, 1)), ShardState::Ok);
        assert_eq!(free(&*store), with, "freed anyway");
    }

    async fn an_overwrite_frees_the_old_copy(engine: &Engine) {
        let dir = tempfile::tempdir().unwrap();
        let (store, _meta) = (engine.open)(dir.path());
        let bytes = data(8, 120_000);
        put(&*store, &id(8, 0), &bytes).await;
        let once = free(&*store);
        put(&*store, &id(8, 0), &bytes).await;
        assert_eq!(free(&*store), once, "the old copy kept its space");
        assert_eq!(store.count(), 1);
        // Moved into its record (B21), the block is freed too.
        let before = free(&*store);
        store
            .write_with_metadata(small(&id(8, 0), &bytes[..4000]), Vec::new())
            .unwrap();
        assert!(free(&*store) > before, "the block copy kept its space");
        assert_eq!(store.read(&id(8, 0)).await.unwrap().0, &bytes[..4000]);
        assert_eq!(store.count(), 1);
    }

    async fn rot_is_found_and_a_rewrite_clears_it(engine: &Engine) {
        let dir = tempfile::tempdir().unwrap();
        let (store, _meta) = (engine.open)(dir.path());
        let bytes = data(9, 50_000);
        put(&*store, &id(9, 0), &bytes).await;
        put(&*store, &id(9, 1), &data(10, 50_000)).await;
        (engine.rot)(dir.path(), &*store, &id(9, 0), &bytes[1000..1064]);

        let err = store.read(&id(9, 0)).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::DataLoss, "{err}");
        assert_eq!(store.state(&id(9, 0)), ShardState::Corrupt);
        assert_eq!(store.state(&id(9, 1)), ShardState::Ok);
        assert_eq!(store.corrupt_now(), 1);
        assert_eq!(store.corrupt_found(), 1);

        put(&*store, &id(9, 0), &bytes).await;
        assert_eq!(store.state(&id(9, 0)), ShardState::Ok);
        assert_eq!(store.corrupt_now(), 0);
        assert_eq!(store.read(&id(9, 0)).await.unwrap().0, bytes);

        // The scrubber finds rot nobody reads.
        let other = data(11, 50_000);
        put(&*store, &id(9, 2), &other).await;
        (engine.rot)(dir.path(), &*store, &id(9, 2), &other[2000..2064]);
        let seen = std::sync::atomic::AtomicU64::new(0);
        store
            .scrub(0, &|n| {
                seen.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
            })
            .await;
        assert_eq!(seen.into_inner(), 150_000);
        assert_eq!(store.state(&id(9, 2)), ShardState::Corrupt);
        assert_eq!(store.state(&id(9, 0)), ShardState::Ok);

        // A copy the caller finds wrong is marked; a stale report is not.
        let stale = store.info(&id(9, 1)).unwrap();
        put(&*store, &id(9, 1), &data(10, 50_000)).await;
        store.mark_corrupt(&id(9, 1), &stale);
        assert_eq!(store.state(&id(9, 1)), ShardState::Ok);
        store.mark_corrupt(&id(9, 1), &store.info(&id(9, 1)).unwrap());
        assert_eq!(store.state(&id(9, 1)), ShardState::Corrupt);
        assert!(store.delete(&id(9, 1)).unwrap());
        assert_eq!(store.state(&id(9, 1)), ShardState::Missing);
    }

    async fn a_shard_with_metadata_is_all_or_nothing(engine: &Engine) {
        let dir = tempfile::tempdir().unwrap();
        let (store, meta) = (engine.open)(dir.path());
        let bytes = data(12, 9_000);
        let entry = || vec![(MetadataKey::object_meta("b", "k"), b"meta".to_vec())];

        // A damaged shard stores neither.
        let mut damaged = small(&id(12, 0), &bytes);
        damaged.crc32c ^= 1;
        let err = store.write_with_metadata(damaged, entry()).unwrap_err();
        assert_eq!(err.code(), tonic::Code::DataLoss);
        // Nor does a write that can't be made durable.
        (engine.fail_records)(true);
        let err = store.write_with_metadata(small(&id(12, 0), &bytes), entry());
        (engine.fail_records)(false);
        assert!(err.is_err());
        assert_eq!(store.state(&id(12, 0)), ShardState::Missing);
        assert_eq!(meta.get(&MetadataKey::object_meta("b", "k")), None);
        assert_eq!(store.count(), 0);

        store
            .write_with_metadata(small(&id(12, 0), &bytes), entry())
            .unwrap();
        assert_eq!(
            meta.get(&MetadataKey::object_meta("b", "k")).as_deref(),
            Some(&b"meta"[..])
        );
        assert_eq!(store.read(&id(12, 0)).await.unwrap().0, bytes);
        let got = store
            .small_shard(&id(12, 0))
            .expect("kept with its metadata");
        assert_eq!(got, small(&id(12, 0), &bytes));
        assert!(store.small_shard(&id(12, 1)).is_none());
        let too_big = data(13, objectio_common::version::SMALL_SHARD_MAX + 1);
        let err = store
            .write_with_metadata(small(&id(12, 2), &too_big), entry())
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    async fn shards_page_in_key_order(engine: &Engine) {
        let dir = tempfile::tempdir().unwrap();
        let (store, _meta) = (engine.open)(dir.path());
        let mut ids = Vec::new();
        for object in 0..6u8 {
            for position in 0..5u32 {
                let i = id(object.wrapping_mul(37), position);
                if position == 0 {
                    put(&*store, &i, &data(object, 3000)).await;
                } else {
                    store
                        .write_with_metadata(small(&i, &data(object, 100)), Vec::new())
                        .unwrap();
                }
                ids.push(i);
            }
        }
        assert_eq!(store.count(), 30);
        let mut seen = Vec::new();
        let mut after: Option<ShardId> = None;
        loop {
            let page = store.page(after.as_ref(), 7);
            assert!(page.len() <= 7);
            let Some((last, _)) = page.last() else { break };
            after = Some(last.clone());
            seen.extend(page.into_iter().map(|(i, _)| i));
        }
        let key = |i: &ShardId| super::shard_key(&i.object_id, i.stripe_id, i.position);
        ids.sort_by_key(key);
        assert_eq!(seen, ids, "not every shard, once, in key order");

        // Purged, none is left and their space is back.
        assert_eq!(store.purge().unwrap(), 30);
        assert_eq!(store.count(), 0);
        assert!(store.page(None, 10).is_empty());
    }

    async fn client_writes_stop_at_the_full_ratio(engine: &Engine) {
        let dir = tempfile::tempdir().unwrap();
        let (store, _meta) = (engine.open)(dir.path());
        let bytes = data(14, 10_000);
        store.set_full_ratio(0.0);
        let before = free(&*store);
        let err = store
            .write(&id(14, 0), &bytes, crc32c::crc32c(&bytes), false)
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::ResourceExhausted, "{err}");
        assert_eq!(free(&*store), before);
        // Writes that restore redundancy may use the rest.
        store
            .write(&id(14, 0), &bytes, crc32c::crc32c(&bytes), true)
            .await
            .unwrap();
        assert_eq!(store.state(&id(14, 0)), ShardState::Ok);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use objectio_storage::metadata::{MetadataStore, MetadataStoreConfig};
    use std::collections::HashMap;

    const BLOCK: u32 = 64 * 1024;

    fn open(dir: &Path) -> conformance::Opened {
        let disks = Disks::open(&[dir.join("disk.raw").display().to_string()], BLOCK).unwrap();
        let meta_dir = dir.join("state");
        let meta = objectio_storage::metadata::open(MetadataStoreConfig::with_data_dir(&meta_dir))
            .unwrap();
        let store = BlockStore::new(disks, Arc::clone(&meta), meta_dir);
        (Arc::new(store), meta)
    }

    #[tokio::test]
    async fn block_store_keeps_the_contract() {
        conformance::run(&conformance::Engine {
            open,
            rot: |dir, store, id, needle| {
                rot_block(&dir.join("disk.raw"), BLOCK, store, id, needle);
            },
            fail_records: |on| LOCATION_RECORDS_FAIL.with(|f| f.set(on)),
        })
        .await;
    }

    /// A shard key gives back the shard it was made from, and nothing else
    /// reads as one.
    #[test]
    fn a_key_spells_its_shard_and_only_it() {
        let id = ShardId {
            object_id: vec![0xAB; 16],
            stripe_id: 7,
            position: 3,
        };
        assert_eq!(id_of(&key_of(&id)), Some(id));
        for not in [
            "", "ab:1", "ab:1:2:3", "zz:1:2", "AB:1:2", "ab:01:2", "ab:x:2",
        ] {
            assert_eq!(id_of(not), None, "{not}");
        }
    }

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

    /// Scan the MetadataStore for every persisted ShardLocation, as the
    /// startup pass does: before it, the index started empty after every
    /// restart and the OSD reported 0 shards to meta even when disk.raw
    /// was full of real data.
    fn load_persisted_shard_index(meta_store: &dyn MetaIndex) -> HashMap<String, ShardLocation> {
        let prefix_key = MetadataKey::from_bytes(SHARD_LOC_PREFIX.to_vec());
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

    #[test]
    fn a_shard_key_is_unique_per_object_stripe_and_position() {
        let a = [1u8; 16];
        let b = [2u8; 16];
        let keys = [
            shard_key(&a, 0, 0),
            shard_key(&a, 0, 1),
            shard_key(&a, 1, 0),
            shard_key(&b, 0, 0),
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
        assert_eq!(shard_key(&[0xABu8; 4], 7, 3), "abababab:7:3".to_string());
    }

    #[test]
    fn the_metadata_key_carries_the_prefix_and_gives_the_shard_key_back() {
        let sk = shard_key(&[9u8; 16], 2, 5);
        let mk = shard_loc_meta_key(&sk);
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
            (shard_key(&[1u8; 16], 0, 0), loc(0, 100)),
            (shard_key(&[1u8; 16], 0, 1), loc(0, 101)),
            (shard_key(&[2u8; 16], 3, 4), loc(1, 7)),
        ];
        for (key, l) in &written {
            persist_shard_location(&s, key, l).expect("persist");
        }

        let rebuilt = load_persisted_shard_index(&s);
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
        let keep = shard_key(&[1u8; 16], 0, 0);
        let drop = shard_key(&[1u8; 16], 0, 1);
        persist_shard_location(&s, &keep, &loc(0, 1)).unwrap();
        persist_shard_location(&s, &drop, &loc(0, 2)).unwrap();

        forget_shard_location(&s, &drop).expect("forget");

        let rebuilt = load_persisted_shard_index(&s);
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
        let mine = shard_key(&[1u8; 16], 0, 0);
        persist_shard_location(&s, &mine, &loc(0, 1)).unwrap();

        for foreign in [&b"s:some-shard-meta"[..], b"osd_other:thing", b"zzz"] {
            s.put(MetadataKey::from_bytes(foreign.to_vec()), vec![1, 2, 3])
                .expect("put foreign key");
        }

        let rebuilt = load_persisted_shard_index(&s);
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
            let k = shard_key(&[i; 16], 0, 0);
            persist_shard_location(&s, &k, &loc(0, u64::from(i))).unwrap();
        }
        s.put(shard_loc_meta_key("deadbeef:0:0"), b"not a record".to_vec())
            .expect("put corrupt entry");

        let rebuilt = load_persisted_shard_index(&s);
        assert_eq!(rebuilt.len(), 3, "a corrupt entry cost the whole index");
    }

    #[test]
    fn an_empty_store_rebuilds_to_an_empty_index() {
        let (_dir, s) = store();
        assert!(load_persisted_shard_index(&s).is_empty());
    }
}
