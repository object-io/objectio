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
//!   that fails is reported corrupt until it is rewritten. Bytes stored as
//!   another shard, intact or not, are never served as this one.
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
use objectio_storage::metadata::{MetaIndex, MetadataKey, MetadataOp};
use objectio_storage::{BlockHeader, DiskManager};
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

    /// Shards this store forgot when it opened, because the device that
    /// held them came back blank (replaced, or wiped): Meta is told, so
    /// repair rebuilds them now rather than when its walk gets there.
    fn dropped_at_open(&self) -> u64;

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
    /// unwritable metadata log would. Per thread, so a test's failures stay
    /// in that test.
    pub(crate) static LOCATION_RECORDS_FAIL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Tests: the same, as a metadata log on a filesystem with no room
    /// left would.
    pub(crate) static LOCATION_RECORDS_FULL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// Tests: make a shard's disk write fail as on a filesystem with no
    /// room left.
    pub(crate) static DISK_WRITES_FULL: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// An injected "no room" (ENOSPC), as the storage engine reports one.
#[cfg(test)]
fn injected_no_room(what: &str) -> objectio_common::Error {
    objectio_common::Error::io(
        format_args!("injected: {what}"),
        &std::io::Error::from(std::io::ErrorKind::StorageFull),
    )
}

#[cfg(test)]
fn location_records_fail() -> objectio_common::Result<()> {
    if LOCATION_RECORDS_FAIL.with(std::cell::Cell::get) {
        return Err(objectio_common::Error::storage(
            "injected: the metadata log is unwritable",
        ));
    }
    if LOCATION_RECORDS_FULL.with(std::cell::Cell::get) {
        return Err(injected_no_room("the metadata log"));
    }
    Ok(())
}

/// A write to this OSD's disks or metadata store that failed, `what`, as
/// the RPC answers it: ResourceExhausted when the filesystem had no room
/// for it (ENOSPC, EDQUOT), as a disk refused at its full ratio is, so the
/// gateway answers 507 rather than taking this OSD for unreachable;
/// otherwise `otherwise`.
pub(crate) fn write_failed(
    what: &str,
    e: &objectio_common::Error,
    otherwise: tonic::Code,
) -> Status {
    if e.is_out_of_space() {
        Status::resource_exhausted(format!("{what}: no room: {e}"))
    } else {
        Status::new(otherwise, format!("{what}: {e}"))
    }
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
    /// A small shard's bytes, kept in the metadata index rather than in a
    /// disk block (B21: written, with its object's metadata, in one log
    /// flush); `disk_idx` is then [`SMALL_DISK`]. They are under their own
    /// key ([`small_data_key`]), not in the location record: empty here
    /// when only the record was read ([`ShardIndex::get`]), filled by
    /// [`ShardIndex::get_whole`].
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
}

impl ShardLocation {
    /// The location record: without a small shard's bytes, which are
    /// stored apart ([`location_ops`]).
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        prost::Message::encode_to_vec(&ShardLocationRecord {
            disk_idx: u32::try_from(self.disk_idx).unwrap_or(u32::MAX),
            block_num: self.block_num,
            size: self.size,
            crc32c: self.crc32c,
            created_at: self.created_at,
        })
    }

    /// The location a record holds; a small shard's bytes empty.
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, prost::DecodeError> {
        let r = <ShardLocationRecord as prost::Message>::decode(bytes)?;
        let small = (r.disk_idx == u32::MAX).then(Vec::new);
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

/// A key just past every location record ([`SHARD_LOC_PREFIX`] ends in
/// `:`, this in `;`), kept so the records' range ends in an ordinary leaf of
/// the index file. A shard key starts with its object's id, a UUIDv7, so a
/// new record sorts after every other and goes in the leaf that ends the
/// range. Without this key that leaf held the first small shard's bytes
/// ([`SMALL_DATA_PREFIX`], a value of a page or more), and redb gives a key
/// inserted beside a leaf of one large value a leaf of its own: each record,
/// some 70 bytes, took a 4 KiB page, and the startup pass over the records
/// read one page per shard (an OSD of 135,000 shards took five minutes to
/// start on a soak VM, B2 soak run 36).
const LOC_END_KEY: &[u8] = b"osd_loc;";

/// Which disk is at each index a location names (`ShardLocation.disk_idx`):
/// a [`DiskSetRecord`], written when the OSD first opens its disks and
/// whenever the set changes. A disk is known by the id in its superblock,
/// not by its path or its place in a list: paths sort differently when a
/// disk is missing or renamed, and a location read against the wrong disk
/// hands that disk's live blocks to new writes.
const DISK_SET_KEY: &[u8] = b"osd_disks";

/// The disks of this OSD, by index.
#[derive(Clone, PartialEq, ::prost::Message)]
struct DiskSetRecord {
    #[prost(message, repeated, tag = "1")]
    disks: Vec<DiskSlotRecord>,
}

/// The disk at one index.
#[derive(Clone, PartialEq, ::prost::Message)]
struct DiskSlotRecord {
    /// The disk's id, as its superblock carries it.
    #[prost(bytes = "vec", tag = "1")]
    id: Vec<u8>,
    /// Where it was last opened: for the operator, when it is missing.
    #[prost(string, tag = "2")]
    path: String,
}

/// The disks recorded in `meta`, or none (the OSD's first start). A record
/// that can't be read or decoded is an error, never "none": taken for a
/// first start, the disks would be recorded again in whatever order they
/// were named.
fn read_disk_set(meta: &dyn MetaIndex) -> Result<Option<DiskSetRecord>, String> {
    meta.try_get(&MetadataKey::from_bytes(DISK_SET_KEY.to_vec()))
        .map_err(|e| format!("the record of this OSD's disks can't be read: {e}"))?
        .map(|v| {
            <DiskSetRecord as prost::Message>::decode(v.as_slice())
                .map_err(|e| format!("the record of this OSD's disks is unreadable: {e}"))
        })
        .transpose()
}

/// A disk as [`Disks::open`] found it, for [`arrange_disks`].
struct OpenedDisk {
    id: [u8; 16],
    path: String,
    /// Formatted just now: blank, so a replacement or a new disk.
    formatted_now: bool,
}

/// Which opened disk is at each index, from [`arrange_disks`].
#[derive(Debug)]
struct Arrangement {
    /// For each index, the opened disk at it.
    order: Vec<usize>,
    /// The indexes whose disk was formatted just now: whatever the shard
    /// index says was on them is gone.
    replaced: Vec<bool>,
    /// The record to write, when it isn't the one there.
    record: Option<DiskSetRecord>,
}

/// Put each of the `opened` disks at its index in the set `recorded` (none
/// on a first open). A recorded disk is found by its id, wherever it is now
/// and in whatever order the disks were named. A disk formatted just now
/// (blank) takes the index of one missing, as a replacement, its shards
/// forgotten to be rebuilt; or a new index at the end. Refused: a disk
/// missing with no blank one in its place, a disk that is not blank and not
/// one of the set, and one disk named twice.
fn arrange_disks(
    recorded: Option<&DiskSetRecord>,
    opened: &[OpenedDisk],
) -> Result<Arrangement, String> {
    let record_of = |order: &[usize]| DiskSetRecord {
        disks: order
            .iter()
            .map(|&i| DiskSlotRecord {
                id: opened[i].id.to_vec(),
                path: opened[i].path.clone(),
            })
            .collect(),
    };
    for (i, d) in opened.iter().enumerate() {
        if let Some(other) = opened[..i].iter().find(|o| o.id == d.id) {
            return Err(format!(
                "{} and {} are the same disk (id {}): name each disk once",
                other.path,
                d.path,
                hex::encode(d.id)
            ));
        }
    }
    let Some(recorded) = recorded else {
        let order: Vec<usize> = (0..opened.len()).collect();
        return Ok(Arrangement {
            replaced: opened.iter().map(|d| d.formatted_now).collect(),
            record: Some(record_of(&order)),
            order,
        });
    };
    let mut slots: Vec<Option<usize>> = vec![None; recorded.disks.len()];
    let mut blanks = Vec::new();
    for (i, d) in opened.iter().enumerate() {
        if d.formatted_now {
            blanks.push(i);
            continue;
        }
        let Some(slot) = recorded.disks.iter().position(|r| r.id == d.id) else {
            return Err(format!(
                "disk {} (id {}) is not one of this OSD's {} disks: it belongs to another \
                 OSD, or was replaced. Remove it from this OSD's disks, or wipe it to add it \
                 as a new disk",
                d.path,
                hex::encode(d.id),
                recorded.disks.len()
            ));
        };
        slots[slot] = Some(i);
    }
    let mut replaced = vec![false; slots.len()];
    let mut blanks = blanks.into_iter();
    for (slot, at) in slots.iter_mut().enumerate() {
        if at.is_none()
            && let Some(blank) = blanks.next()
        {
            warn!(
                "disk {slot} (id {}, last at {}) is replaced by blank disk {}: the shards \
                 it held are forgotten, and rebuilt by Meta's repairer",
                hex::encode(&recorded.disks[slot].id),
                recorded.disks[slot].path,
                opened[blank].path
            );
            *at = Some(blank);
            replaced[slot] = true;
        }
    }
    for blank in blanks {
        info!("disk {} added at index {}", opened[blank].path, slots.len());
        slots.push(Some(blank));
        replaced.push(true);
    }
    let missing: Vec<String> = slots
        .iter()
        .enumerate()
        .filter(|(_, at)| at.is_none())
        .map(|(slot, _)| {
            format!(
                "disk {slot} (id {}, last at {})",
                hex::encode(&recorded.disks[slot].id),
                recorded.disks[slot].path
            )
        })
        .collect();
    if !missing.is_empty() {
        let (is, it, blank) = if missing.len() == 1 {
            ("is", "it", "a blank disk")
        } else {
            ("are", "them", "blank disks")
        };
        return Err(format!(
            "this OSD's {} {is} missing; not starting, as its shards would be looked for on \
             other disks. Attach {it} again (at any path), or replace {it} with {blank} as \
             the operations guide's \"Replacing a disk\" says",
            missing.join(", ")
        ));
    }
    let order: Vec<usize> = slots.into_iter().flatten().collect();
    let record = record_of(&order);
    Ok(Arrangement {
        record: (record != *recorded).then_some(record),
        order,
        replaced,
    })
}

/// Prefix of a small shard's bytes (B21), apart from its location record:
/// in the record, the startup pass over every location read every small
/// shard's bytes too, and an OSD holding 115,000 of them took five minutes
/// to start (B2 soak run 24).
const SMALL_DATA_PREFIX: &[u8] = b"osd_small:";

/// The key small shard `shard_key`'s bytes are kept under.
fn small_data_key(shard_key: &str) -> MetadataKey {
    let mut bytes = Vec::with_capacity(SMALL_DATA_PREFIX.len() + shard_key.len());
    bytes.extend_from_slice(SMALL_DATA_PREFIX);
    bytes.extend_from_slice(shard_key.as_bytes());
    MetadataKey::from_bytes(bytes)
}

/// The writes that record `loc` for `shard_key`, replacing `old`: its
/// location, and a small shard's bytes (or the removal of `old`'s).
fn location_ops(
    shard_key: &str,
    loc: &ShardLocation,
    old: Option<&ShardLocation>,
) -> Vec<MetadataOp> {
    let mut ops = vec![MetadataOp::Put {
        key: shard_loc_meta_key(shard_key),
        value: loc.to_bytes(),
    }];
    if let Some(data) = &loc.small {
        ops.push(MetadataOp::Put {
            key: small_data_key(shard_key),
            value: data.clone(),
        });
    } else if old.is_some_and(|o| o.small.is_some()) {
        ops.push(MetadataOp::Delete {
            key: small_data_key(shard_key),
        });
    }
    ops
}

/// Persist a ShardLocation, replacing `old`, so a restart can rebuild
/// the in-memory index. Called on every successful WriteShard.
pub(crate) fn persist_shard_location(
    meta_store: &dyn MetaIndex,
    shard_key: &str,
    loc: &ShardLocation,
    old: Option<&ShardLocation>,
) -> objectio_common::Result<()> {
    #[cfg(test)]
    location_records_fail()?;
    meta_store.write(location_ops(shard_key, loc, old))
}

/// Remove a persisted ShardLocation, `old` (delete_shard path), with a
/// small shard's bytes.
fn forget_shard_location(
    meta_store: &dyn MetaIndex,
    shard_key: &str,
    old: &ShardLocation,
) -> objectio_common::Result<()> {
    #[cfg(test)]
    location_records_fail()?;
    let mut ops = vec![MetadataOp::Delete {
        key: shard_loc_meta_key(shard_key),
    }];
    if old.small.is_some() {
        ops.push(MetadataOp::Delete {
            key: small_data_key(shard_key),
        });
    }
    meta_store.write(ops)
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

    /// `key`'s location, as its record holds it: a small shard's bytes
    /// empty.
    fn get(&self, key: &str) -> Option<ShardLocation> {
        let v = self.store.get(&shard_loc_meta_key(key))?;
        ShardLocation::from_bytes(&v)
            .inspect_err(|e| warn!("corrupt ShardLocation entry {key}: {e}"))
            .ok()
    }

    /// `key`'s location with a small shard's bytes.
    fn get_whole(&self, key: &str) -> Option<ShardLocation> {
        let mut loc = self.get(key)?;
        self.fill(key, &mut loc);
        Some(loc)
    }

    /// Read a small shard's bytes into `loc`, its record. Missing ones stay
    /// empty: they fail the shard's checksum, so it reads as corrupt.
    fn fill(&self, key: &str, loc: &mut ShardLocation) {
        if let Some(data) = loc.small.as_mut() {
            *data = self.store.get(&small_data_key(key)).unwrap_or_default();
        }
    }

    fn contains(&self, key: &str) -> bool {
        self.store.get(&shard_loc_meta_key(key)).is_some()
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
    fn record(
        &self,
        key: &str,
        loc: &ShardLocation,
    ) -> objectio_common::Result<Option<ShardLocation>> {
        let _key = self.lock(key);
        let old = self.get(key);
        persist_shard_location(&*self.store, key, loc, old.as_ref())?;
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
        extra: Vec<(MetadataKey, Vec<u8>)>,
    ) -> objectio_common::Result<Option<ShardLocation>> {
        let _key = self.lock(key);
        let old = self.get(key);
        #[cfg(test)]
        location_records_fail()?;
        let mut ops: Vec<MetadataOp> = extra
            .into_iter()
            .map(|(key, value)| MetadataOp::Put { key, value })
            .collect();
        ops.extend(location_ops(key, loc, old.as_ref()));
        self.store.write(ops)?;
        self.counted(old.as_ref(), Some(loc));
        Ok(old)
    }

    /// Forget `key` durably; where the shard was, if it was here. Its
    /// blocks may be freed only after this returns.
    fn forget(&self, key: &str) -> objectio_common::Result<Option<ShardLocation>> {
        let _key = self.lock(key);
        let Some(old) = self.get(key) else {
            return Ok(None);
        };
        forget_shard_location(&*self.store, key, &old)?;
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
    /// Disks formatted just now, by index: whatever the shard index says
    /// was on them is gone.
    formatted_now: Vec<bool>,
}

impl Disks {
    /// Open each disk at `paths` for the store whose locations are in
    /// `meta`, formatting one only when it is blank, with blocks of
    /// `block_size`. Existing disks keep the block size in their
    /// superblock. A file not there yet is created only on the OSD's first
    /// start (no disks recorded in `meta`): after that it is a disk gone,
    /// and a file made in its place would be taken for its replacement.
    pub fn open(paths: &[String], block_size: u32, meta: &dyn MetaIndex) -> Result<Self, String> {
        let create_missing = read_disk_set(meta)?.is_none();
        let mut disks = Vec::new();
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
                    // Nor is one an OSD that has run had: its disk is gone (a
                    // mount that failed, a volume detached). Formatted, it
                    // would replace the lost disk, and the shards there be
                    // forgotten while the disk may yet come back.
                    if !std::path::Path::new(path).exists() && !create_missing {
                        return Err(format!(
                            "disk {path} does not exist, and this OSD has run on its disks \
                             (a file is created for a disk only on an OSD's first start). \
                             Attach the disk again; to replace it, put a blank disk or file \
                             there (for a file: truncate -s <size> {path})"
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

            disks.push(disk);
        }

        if disks.is_empty() {
            return Err("No disks configured".into());
        }
        Ok(Self {
            disks,
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

/// The object id a shard's block header carries: the first 16 bytes of
/// its object's id, zero-padded.
fn header_object_id(id: &ShardId) -> [u8; 16] {
    let mut object_id = [0u8; 16];
    let n = id.object_id.len().min(16);
    object_id[..n].copy_from_slice(&id.object_id[..n]);
    object_id
}

/// Whether the block read at `loc` is shard `id`: its header names the
/// shard's object and stripe, and its payload has the length and checksum
/// the location records. The block's own checks pass for any intact block,
/// so a location that points at another shard's (a disk at the wrong
/// index, a block handed out twice) would serve that shard's bytes as this
/// one's.
fn check_block(
    id: &ShardId,
    loc: &ShardLocation,
    header: &BlockHeader,
    data: &[u8],
) -> Result<(), String> {
    if header.object_id != header_object_id(id) || header.object_offset != id.stripe_id {
        return Err(format!(
            "block {} on disk {} holds object {} stripe {}, not this shard",
            loc.block_num,
            loc.disk_idx,
            hex::encode(header.object_id),
            header.object_offset
        ));
    }
    if data.len() != loc.size as usize {
        return Err(format!(
            "block {} on disk {} holds {} bytes, the shard {}",
            loc.block_num,
            loc.disk_idx,
            data.len(),
            loc.size
        ));
    }
    let crc32c = crc32c::crc32c(data);
    if crc32c != loc.crc32c {
        return Err(format!(
            "block {} on disk {} has crc32c {crc32c:08x}, the shard {:08x}",
            loc.block_num, loc.disk_idx, loc.crc32c
        ));
    }
    Ok(())
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
    /// Shards forgotten at open: their disk came back formatted.
    dropped_at_open: u64,
    /// Whether the metadata store's filesystem has room for small shards.
    meta_space: MetaSpace,
}

impl BlockStore {
    /// The store over `disks`, its locations in `meta` (kept in `meta_dir`,
    /// whose free space decides where small shards go). The index, as
    /// replayed when `meta` was opened, is reconciled with the disks: each
    /// is put at the index the OSD recorded for it ([`arrange_disks`]), and
    /// the store isn't opened when one is missing or isn't this OSD's.
    pub fn new(disks: Disks, meta: Arc<dyn MetaIndex>, meta_dir: PathBuf) -> Result<Self, String> {
        let Disks {
            disks,
            formatted_now,
        } = disks;
        let set_key = MetadataKey::from_bytes(DISK_SET_KEY.to_vec());
        let recorded = read_disk_set(meta.as_ref())?;
        let opened: Vec<OpenedDisk> = disks
            .iter()
            .zip(&formatted_now)
            .map(|(d, &formatted_now)| OpenedDisk {
                id: *d.id().as_bytes(),
                path: d.path().to_string(),
                formatted_now,
            })
            .collect();
        let Arrangement {
            order,
            replaced: formatted_now,
            record,
        } = arrange_disks(recorded.as_ref(), &opened)?;
        let mut unplaced: Vec<Option<DiskManager>> = disks.into_iter().map(Some).collect();
        let disks: Vec<DiskManager> = order
            .iter()
            .map(|&i| unplaced[i].take().ok_or("a disk placed twice"))
            .collect::<Result<_, _>>()?;
        let disk_ids: Vec<[u8; 16]> = disks.iter().map(|d| *d.id().as_bytes()).collect();
        for (idx, disk) in disks.iter().enumerate() {
            info!(
                "Disk {idx}: {} (id {})",
                disk.path(),
                hex::encode(disk_ids[idx])
            );
        }
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
        // - Each disk's blocks that the index points at are marked used: a
        //   disk opens with every block free (the index is the only record
        //   of what is on it), and would hand out block 0 over live shards.
        let mut lost = Vec::new();
        let mut beyond: Option<(String, usize)> = None;
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
                // A disk of this OSD that isn't in its set: the index and the
                // disks disagree, and any block handed out could be a live
                // shard's.
                beyond = Some((String::from_utf8_lossy(k).into_owned(), loc.disk_idx));
                return false;
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
        if let Some((key, disk_idx)) = beyond {
            return Err(format!(
                "the shard index places {key} on disk {disk_idx}, and this OSD has {} disks: \
                 a disk is missing. Not starting",
                disks.len()
            ));
        }
        // The set before the forgetting: a restart in between finds the
        // records left on the new disk's index, and every read of them fails
        // its checks (the block isn't the shard), so they are rebuilt. The
        // other way round, it would find the new disk in no slot and refuse.
        if let Some(record) = record {
            meta.put(set_key, prost::Message::encode_to_vec(&record))
                .map_err(|e| format!("recording this OSD's disks: {e}"))?;
        }
        // In batches, one log record (and fsync) each: one per shard took
        // over five minutes for a disk of 24,000 shards.
        for chunk in lost.chunks(1000) {
            if let Err(e) = meta.batch_delete(chunk) {
                // Harmless if they stay: the disk was formatted, so a read of
                // one finds another block or none, fails its checks, and the
                // shard is rebuilt.
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
        let end = MetadataKey::from_bytes(LOC_END_KEY.to_vec());
        if meta.get(&end).is_none()
            && let Err(e) = meta.put(end, Vec::new())
        {
            // Only the index file's layout suffers: records written meanwhile
            // take a page each.
            warn!("recording the end of the shard locations: {e}");
        }
        info!("Shard index: {} shards", index.count());
        for (idx, disk) in disks.iter().enumerate() {
            info!(
                "Disk {idx}: {} of {} bytes used across {} indexed shards",
                disk.used_space(),
                disk.capacity(),
                reclaimed_check[idx]
            );
        }
        Ok(Self {
            disks,
            disk_ids,
            index,
            full_ratio: AtomicU64::new(DEFAULT_FULL_RATIO.to_bits()),
            next_disk: RwLock::new(0),
            corrupt: RwLock::new(HashSet::new()),
            corrupt_found: AtomicU64::new(0),
            dropped_at_open: lost.len() as u64,
            meta_space: MetaSpace::new(meta_dir),
        })
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
    /// gone: freed first, a block could go to the next write while the
    /// index still points at it.
    fn free_location(&self, loc: &ShardLocation) {
        if loc.disk_idx >= self.disks.len() {
            return;
        }
        let disk = &self.disks[loc.disk_idx];
        // `size` is the shard's payload length, so the extent's length is
        // derivable — which is why nothing had to be added to the index.
        let blocks = disk.blocks_for_len(loc.size as usize);
        if let Err(e) = disk.free_extent(loc.block_num, blocks) {
            warn!(
                "Could not free block {} on disk {}: {e}",
                loc.block_num, loc.disk_idx
            );
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
        let object_id = header_object_id(id);
        let started = Instant::now();
        if let Err(e) = disk.write_block(block_num, object_id, id.stripe_id, data) {
            let _ = disk.free_extent(block_num, blocks);
            return Err(write_failed("write failed", &e, tonic::Code::Internal));
        }
        DISK_SECONDS.observe_duration("op=\"write\"", started.elapsed());
        let started = Instant::now();
        if let Err(e) = disk.sync() {
            let _ = disk.free_extent(block_num, blocks);
            return Err(write_failed("sync failed", &e, tonic::Code::Internal));
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

        let object_id = header_object_id(id);

        // Write block through the async IoBackend — the tokio
        // reactor stays free during the syscall / io_uring wait. On
        // Linux + --features io-uring this is +25% throughput on
        // 4 MiB stripes vs the old sync path (see storage-io-levels.md).
        // Nothing records this extent until the location below, so if the
        // write or the sync fails the extent goes straight back.
        let started = Instant::now();
        #[cfg(test)]
        let written = if DISK_WRITES_FULL.with(std::cell::Cell::get) {
            Err(injected_no_room("the disk's filesystem"))
        } else {
            disk.write_block_async(block_num, object_id, id.stripe_id, data)
                .await
        };
        #[cfg(not(test))]
        let written = disk
            .write_block_async(block_num, object_id, id.stripe_id, data)
            .await;
        if let Err(e) = written {
            let _ = disk.free_extent(block_num, blocks);
            return Err(write_failed("write failed", &e, tonic::Code::Internal));
        }
        DISK_SECONDS.observe_duration("op=\"write\"", started.elapsed());

        // A failed sync is a failed write, whatever the error: the shard
        // is refused, its extent freed, and nothing records it.
        let started = Instant::now();
        if let Err(e) = disk.sync() {
            let _ = disk.free_extent(block_num, blocks);
            return Err(write_failed("sync failed", &e, tonic::Code::Internal));
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
            Err(e) if e.is_out_of_space() => {
                warn!("Shard {key} written but no room to record its location: {e}; write refused");
                return Err(Status::resource_exhausted(format!(
                    "the shard's location could not be recorded: no room ({e}); not stored"
                )));
            }
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

        debug!(
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
        let replaced = self.index.record_with(&key, &loc, writes).map_err(|e| {
            write_failed(
                &format!("failed to store object metadata with shard {key}"),
                &e,
                tonic::Code::Internal,
            )
        })?;
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
            .get_whole(&key)
            .ok_or_else(|| Status::not_found("shard not found"))?;

        let data = if let Some(small) = location.small.clone() {
            // Kept in the index (B21): checked against the checksum
            // recorded with it, as a block's own checks would.
            if crc32c::crc32c(&small) != location.crc32c {
                self.mark_corrupt_at(&key, location.block_num);
                return Err(Status::data_loss("shard failed its checksum"));
            }
            small
        } else {
            let Some(disk) = self.disks.get(location.disk_idx) else {
                self.mark_corrupt_at(&key, location.block_num);
                return Err(Status::data_loss(format!(
                    "shard is on disk {}, and this OSD has {}",
                    location.disk_idx,
                    self.disks.len()
                )));
            };

            // Async read — same semantics, reactor stays free during I/O.
            let read_started = Instant::now();
            let read = disk.read_block_async(location.block_num).await;
            DISK_SECONDS.observe_duration("op=\"read\"", read_started.elapsed());
            let (header, data) = read.map_err(|e| {
                // Unreadable is as good as gone: report it for rebuilding.
                self.mark_corrupt_at(&key, location.block_num);
                Status::data_loss(format!("shard is unreadable: {e}"))
            })?;
            // Another shard's block is no copy of this one: an error, so the
            // gateway reads around it and the shard is rebuilt.
            if let Err(e) = check_block(id, &location, &header, &data) {
                warn!("shard {key}: {e}");
                self.mark_corrupt_at(&key, location.block_num);
                return Err(Status::data_loss(format!("shard failed its checks: {e}")));
            }
            data
        };
        Ok((data, self.info_of(&location)))
    }

    fn small_shard(&self, id: &ShardId) -> Option<SmallShard> {
        let key = key_of(id);
        let loc = self.index.get_whole(&key)?;
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
                return Err(write_failed(
                    "the shard's removal could not be recorded durably; retry",
                    &e,
                    tonic::Code::Unavailable,
                ));
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
            for (key, mut loc) in page {
                self.index.fill(&key, &mut loc);
                if let Some(data) = &loc.small {
                    if crc32c::crc32c(data) != loc.crc32c {
                        self.mark_corrupt_at(&key, loc.block_num);
                    }
                    bytes += u64::from(loc.size);
                    checked(u64::from(loc.size));
                    continue;
                }
                // Any failure counts, not only a checksum: a block whose header
                // no longer parses, that the disk cannot return, or that is
                // another shard's cannot be served either. `mark_corrupt_at`
                // ignores a shard rewritten or deleted since the snapshot.
                let Some(disk) = self.disks.get(loc.disk_idx) else {
                    error!(
                        "scrub: {key} is on disk {}, and this OSD has {}",
                        loc.disk_idx,
                        self.disks.len()
                    );
                    self.mark_corrupt_at(&key, loc.block_num);
                    continue;
                };
                let checked_block = match disk.read_block_async(loc.block_num).await {
                    Ok((header, data)) => id_of(&key)
                        .ok_or_else(|| "not a shard key".to_string())
                        .and_then(|id| check_block(&id, &loc, &header, &data)),
                    Err(e) => Err(format!("unreadable: {e}")),
                };
                if let Err(e) = checked_block {
                    warn!("scrub: {key}: {e}");
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

    fn dropped_at_open(&self) -> u64 {
        self.dropped_at_open
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

/// Tests: replace the bytes of small shard `key` in the index with `rot` of
/// them, the way rot in the index would.
#[cfg(test)]
pub(crate) fn rot_small(meta: &dyn MetaIndex, id: &ShardId, rot: impl FnOnce(&mut Vec<u8>)) {
    let key = key_of(id);
    let mut data = meta.get(&small_data_key(&key)).expect("a small shard");
    rot(&mut data);
    meta.put(small_data_key(&key), data).unwrap();
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
        /// Make writes of the metadata index fail (or not) as on a
        /// filesystem with no room left (ENOSPC).
        pub fill_records: fn(bool),
        /// Make writes of shards to disk fail (or not) as on a filesystem
        /// with no room left.
        pub fill_disks: fn(bool),
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
        a_full_filesystem_refuses_writes_as_full(engine).await;
    }

    /// A filesystem with no room left under the disks or the metadata
    /// index: a write is refused as full (ResourceExhausted, what the
    /// gateway answers 507 for), not as failed; nothing of it is kept;
    /// what was stored reads as before; and writes work again once there
    /// is room.
    async fn a_full_filesystem_refuses_writes_as_full(engine: &Engine) {
        let dir = tempfile::tempdir().unwrap();
        let (store, meta) = (engine.open)(dir.path());
        let kept = data(15, 30_000);
        put(&*store, &id(15, 0), &kept).await;
        let before = free(&*store);
        let bytes = data(16, 40_000);
        let entry = || vec![(MetadataKey::object_meta("b", "full"), b"meta".to_vec())];

        for fill in [engine.fill_disks, engine.fill_records] {
            fill(true);
            let err = store
                .write(&id(15, 1), &bytes, crc32c::crc32c(&bytes), false)
                .await
                .unwrap_err();
            fill(false);
            assert_eq!(err.code(), tonic::Code::ResourceExhausted, "{err}");
            assert_eq!(store.state(&id(15, 1)), ShardState::Missing);
            assert_eq!(store.read(&id(15, 0)).await.unwrap().0, kept);
        }
        // The disk's extent goes back when the block write failed; one
        // whose record failed is held until a restart (the record may
        // have reached the log).
        assert!(free(&*store) <= before);

        (engine.fill_records)(true);
        let err = store
            .write_with_metadata(small(&id(15, 2), &bytes[..3000]), entry())
            .unwrap_err();
        (engine.fill_records)(false);
        assert_eq!(err.code(), tonic::Code::ResourceExhausted, "{err}");
        assert_eq!(meta.get(&MetadataKey::object_meta("b", "full")), None);
        assert_eq!(store.state(&id(15, 2)), ShardState::Missing);

        put(&*store, &id(15, 1), &bytes).await;
        assert_eq!(store.read(&id(15, 1)).await.unwrap().0, bytes);
        store
            .write_with_metadata(small(&id(15, 2), &bytes[..3000]), entry())
            .unwrap();
        assert_eq!(store.read(&id(15, 2)).await.unwrap().0, &bytes[..3000]);
        assert_eq!(store.read(&id(15, 0)).await.unwrap().0, kept);
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
        // A write after it takes free blocks, not the ones held.
        put(&*store, &id(3, 3), &data(6, 200_000)).await;
        assert_eq!(store.read(&id(3, 0)).await.unwrap().0, big);
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
        let meta_dir = dir.join("state");
        let meta = objectio_storage::metadata::open(MetadataStoreConfig::with_data_dir(&meta_dir))
            .unwrap();
        let disks = Disks::open(
            &[dir.join("disk.raw").display().to_string()],
            BLOCK,
            meta.as_ref(),
        )
        .unwrap();
        let store = BlockStore::new(disks, Arc::clone(&meta), meta_dir).unwrap();
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
            fill_records: |on| LOCATION_RECORDS_FULL.with(|f| f.set(on)),
            fill_disks: |on| DISK_WRITES_FULL.with(|f| f.set(on)),
        })
        .await;
    }

    /// A small shard's bytes are kept apart from its location record, so
    /// the startup pass over every record reads none of them, and they go
    /// with the record: replaced by a disk block's shard, or deleted.
    #[tokio::test]
    async fn a_small_shard_s_bytes_are_kept_apart_from_its_record_and_go_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let shard = |object: u8| ShardId {
            object_id: vec![object; 16],
            stripe_id: 0,
            position: 0,
        };
        let small = |id: &ShardId, data: &[u8]| SmallShard {
            shard_id: Some(id.clone()),
            crc32c: crc32c::crc32c(data),
            data: data.to_vec(),
        };
        let bytes = vec![7u8; 5_000];
        {
            let (store, meta) = open(dir.path());
            for o in [1, 2, 3] {
                store
                    .write_with_metadata(small(&shard(o), &bytes), Vec::new())
                    .unwrap();
            }
            let key = key_of(&shard(1));
            let record = meta.get(&shard_loc_meta_key(&key)).unwrap();
            assert!(record.len() < 64, "the record holds the bytes");
            assert_eq!(meta.get(&small_data_key(&key)), Some(bytes.clone()));

            // Replaced by a shard in a disk block: the bytes go.
            let big = vec![9u8; 100_000];
            store
                .write(&shard(1), &big, crc32c::crc32c(&big), false)
                .await
                .unwrap();
            assert_eq!(meta.get(&small_data_key(&key)), None);
            assert_eq!(store.read(&shard(1)).await.unwrap().0, big);

            // Deleted: record and bytes go.
            let key = key_of(&shard(2));
            assert!(store.delete(&shard(2)).unwrap());
            assert_eq!(meta.get(&shard_loc_meta_key(&key)), None);
            assert_eq!(meta.get(&small_data_key(&key)), None);
        }
        // Found again after a restart, bytes and all.
        let (store, _meta) = open(dir.path());
        assert_eq!(store.count(), 2);
        assert_eq!(store.read(&shard(3)).await.unwrap().0, bytes);
        assert_eq!(store.small_shard(&shard(3)).unwrap().data, bytes);
    }

    /// Location records written in key order, as they are (a shard key
    /// starts with its object's id, a UUIDv7), pack many to a page of the
    /// index file beside the small shards' bytes, which take a page each
    /// ([`LOC_END_KEY`]).
    #[test]
    fn location_records_written_in_order_pack_many_to_a_page() {
        const ENTRIES: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("entries");
        let dir = tempfile::tempdir().unwrap();
        let meta_dir = dir.path().join("state");
        let n: u32 = 1_000;
        {
            let mut config = MetadataStoreConfig::with_data_dir(&meta_dir);
            config.background_compaction = false;
            let meta = Arc::new(MetadataStore::open_or_create(config).unwrap());
            let disks = Disks::open(
                &[dir.path().join("disk.raw").display().to_string()],
                BLOCK,
                meta.as_ref(),
            )
            .unwrap();
            let store = BlockStore::new(disks, Arc::clone(&meta) as _, meta_dir.clone()).unwrap();
            let data = vec![7u8; 5_000];
            for i in 0..n {
                let mut object_id = vec![0u8; 16];
                object_id[..4].copy_from_slice(&i.to_be_bytes());
                let shard_id = ShardId {
                    object_id,
                    stripe_id: 0,
                    position: 0,
                };
                let small = SmallShard {
                    shard_id: Some(shard_id),
                    crc32c: crc32c::crc32c(&data),
                    data: data.clone(),
                };
                store.write_with_metadata(small, Vec::new()).unwrap();
                // Into the file a few at a time, as checkpoints take them:
                // each time after the bytes of the shards before.
                if i % 50 == 49 {
                    meta.checkpoint().unwrap();
                }
            }
        }
        let db = redb::Database::open(meta_dir.join("index.redb")).unwrap();
        let tx = db.begin_read().unwrap();
        let leaves = redb::ReadableTableMetadata::stats(&tx.open_table(ENTRIES).unwrap())
            .unwrap()
            .leaf_pages();
        assert!(
            leaves < u64::from(n) * 11 / 10,
            "{leaves} leaf pages for {n} small shards and their records"
        );
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
            persist_shard_location(&s, key, l, None).expect("persist");
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
        persist_shard_location(&s, &keep, &loc(0, 1), None).unwrap();
        persist_shard_location(&s, &drop, &loc(0, 2), None).unwrap();

        forget_shard_location(&s, &drop, &loc(0, 2)).expect("forget");

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
        persist_shard_location(&s, &mine, &loc(0, 1), None).unwrap();

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
            persist_shard_location(&s, &k, &loc(0, u64::from(i)), None).unwrap();
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

    /// A store on the disk files `names` in `dir` (each made, 1 GiB, if not
    /// there), its metadata in `dir/state`.
    fn open_disks(dir: &Path, names: &[&str]) -> Result<(BlockStore, Arc<dyn MetaIndex>), String> {
        let meta =
            objectio_storage::metadata::open(MetadataStoreConfig::with_data_dir(dir.join("state")))
                .unwrap();
        open_disks_on(dir, names, meta)
    }

    /// [`open_disks`], its metadata in `meta`.
    fn open_disks_on(
        dir: &Path,
        names: &[&str],
        meta: Arc<dyn MetaIndex>,
    ) -> Result<(BlockStore, Arc<dyn MetaIndex>), String> {
        let paths: Vec<String> = names
            .iter()
            .map(|n| {
                let path = dir.join(n);
                if !path.exists() {
                    drop(DiskManager::init(&path, 1 << 30, Some(BLOCK)).unwrap());
                }
                path.display().to_string()
            })
            .collect();
        let disks = Disks::open(&paths, BLOCK, meta.as_ref())?;
        let store = BlockStore::new(disks, Arc::clone(&meta), dir.join("state"))?;
        Ok((store, meta))
    }

    fn shard(object: u8) -> ShardId {
        ShardId {
            object_id: vec![object; 16],
            stripe_id: u64::from(object) * 3,
            position: 0,
        }
    }

    fn bytes_of(object: u8) -> Vec<u8> {
        (0..10_000u32).map(|i| (i % 251) as u8 ^ object).collect()
    }

    /// Write shards `objects` (round-robin over the disks), then close.
    async fn write_shards(dir: &Path, names: &[&str], objects: std::ops::Range<u8>) {
        let (store, _meta) = open_disks(dir, names).unwrap();
        for o in objects {
            let data = bytes_of(o);
            store
                .write(&shard(o), &data, crc32c::crc32c(&data), false)
                .await
                .unwrap();
        }
    }

    async fn assert_reads(store: &BlockStore, objects: std::ops::Range<u8>) {
        for o in objects {
            let (data, _) = store
                .read(&shard(o))
                .await
                .unwrap_or_else(|e| panic!("shard {o}: {e}"));
            assert!(data == bytes_of(o), "shard {o} read back another's bytes");
        }
    }

    /// An OSD started with one of its disks missing refuses, naming it,
    /// rather than renumbering the rest; with it back, all is as before.
    #[tokio::test]
    async fn a_missing_disk_refuses_the_store_and_says_which() {
        let dir = tempfile::tempdir().unwrap();
        write_shards(dir.path(), &["a", "b", "c"], 0..9).await;
        let err = open_disks(dir.path(), &["a", "c"])
            .err()
            .expect("opened with a disk missing");
        assert!(err.contains("disk 1"), "{err}");
        assert!(
            err.contains(&dir.path().join("b").display().to_string()),
            "{err}"
        );
        let (store, _meta) = open_disks(dir.path(), &["a", "b", "c"]).unwrap();
        assert_reads(&store, 0..9).await;
    }

    /// Disks named in another order (paths renamed, a glob sorting another
    /// way) are found by their ids: every shard reads back as written, and
    /// new writes take no live shard's blocks.
    #[tokio::test]
    async fn disks_in_another_order_are_found_by_their_ids() {
        let dir = tempfile::tempdir().unwrap();
        write_shards(dir.path(), &["a", "b", "c"], 0..9).await;
        {
            let (store, _meta) = open_disks(dir.path(), &["c", "a", "b"]).unwrap();
            assert_reads(&store, 0..9).await;
            for o in 9..30 {
                let data = bytes_of(o);
                store
                    .write(&shard(o), &data, crc32c::crc32c(&data), false)
                    .await
                    .unwrap();
            }
            assert_reads(&store, 0..30).await;
        }
        let (store, _meta) = open_disks(dir.path(), &["b", "c", "a"]).unwrap();
        assert_reads(&store, 0..30).await;
    }

    /// A disk that isn't blank and isn't one of the OSD's is refused; a
    /// blank one is added at a new index.
    #[tokio::test]
    async fn a_disk_not_of_the_set_is_refused_and_a_blank_one_added() {
        let dir = tempfile::tempdir().unwrap();
        write_shards(dir.path(), &["a", "b"], 0..4).await;
        // Formatted elsewhere: it may hold another OSD's shards.
        drop(DiskManager::init(dir.path().join("other"), 1 << 30, Some(BLOCK)).unwrap());
        let err = open_disks(dir.path(), &["a", "b", "other"])
            .err()
            .expect("opened with a disk of no one's");
        assert!(err.contains("not one of this OSD's"), "{err}");
        // A blank file: formatted, at index 2.
        let blank = dir.path().join("new");
        std::fs::File::create(&blank)
            .unwrap()
            .set_len(1 << 30)
            .unwrap();
        {
            let (store, _meta) = open_disks(dir.path(), &["new", "a", "b"]).unwrap();
            assert_reads(&store, 0..4).await;
            assert_eq!(store.disks()[2].path, blank.display().to_string());
        }
        let (store, _meta) = open_disks(dir.path(), &["a", "b", "new"]).unwrap();
        assert_reads(&store, 0..4).await;
    }

    /// A blank disk in place of a missing one replaces it, as the
    /// operations guide's disk replacement says: the shards that were on it
    /// are forgotten (rebuilt by repair), the rest read as before.
    #[tokio::test]
    async fn a_blank_disk_replaces_a_missing_one() {
        let dir = tempfile::tempdir().unwrap();
        write_shards(dir.path(), &["a", "b", "c"], 0..9).await;
        let blank = dir.path().join("b2");
        std::fs::File::create(&blank)
            .unwrap()
            .set_len(1 << 30)
            .unwrap();
        let (store, _meta) = open_disks(dir.path(), &["a", "b2", "c"]).unwrap();
        assert_eq!(store.dropped_at_open(), 3);
        for o in 0..9 {
            // Round-robin from disk 0: every third shard was on disk 1.
            if o % 3 == 1 {
                assert_eq!(store.state(&shard(o)), ShardState::Missing, "shard {o}");
            } else {
                assert!(store.read(&shard(o)).await.unwrap().0 == bytes_of(o));
            }
        }
    }

    /// A disk whose primary superblock is torn is opened by its backup and
    /// keeps its place.
    #[tokio::test]
    async fn a_disk_with_a_torn_primary_superblock_keeps_its_place() {
        use std::io::{Seek, SeekFrom, Write};
        let dir = tempfile::tempdir().unwrap();
        write_shards(dir.path(), &["a", "b", "c"], 0..9).await;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.path().join("b"))
            .unwrap();
        f.seek(SeekFrom::Start(100)).unwrap();
        f.write_all(&[0xAA; 64]).unwrap();
        drop(f);
        let (store, _meta) = open_disks(dir.path(), &["a", "b", "c"]).unwrap();
        assert_eq!(store.dropped_at_open(), 0);
        assert_reads(&store, 0..9).await;
    }

    /// A location that points at another shard's block, intact, is no copy
    /// of its shard: the read is an error and the shard is reported corrupt,
    /// and so does scrub find it; as it does a location on a disk the OSD
    /// doesn't have.
    #[tokio::test]
    async fn a_location_pointing_at_another_shard_s_block_fails_read_and_scrub() {
        let dir = tempfile::tempdir().unwrap();
        write_shards(dir.path(), &["a", "b"], 0..4).await;
        let (store, meta) = open_disks(dir.path(), &["a", "b"]).unwrap();
        let record = |o: u8| {
            ShardLocation::from_bytes(&meta.get(&shard_loc_meta_key(&key_of(&shard(o)))).unwrap())
                .unwrap()
        };
        // Shard 0's record made shard 2's (same disk), size and checksum
        // too: only the block header tells them apart.
        let other = record(2);
        persist_shard_location(meta.as_ref(), &key_of(&shard(0)), &other, None).unwrap();
        let err = store
            .read(&shard(0))
            .await
            .expect_err("read another's block");
        assert_eq!(err.code(), tonic::Code::DataLoss, "{err}");
        assert_eq!(store.state(&shard(0)), ShardState::Corrupt);
        // Shard 1's checksum not the one its block holds.
        let mut wrong_crc = record(1);
        wrong_crc.crc32c ^= 1;
        persist_shard_location(meta.as_ref(), &key_of(&shard(1)), &wrong_crc, None).unwrap();
        // Shard 3's disk one the OSD hasn't got.
        let mut no_disk = record(3);
        no_disk.disk_idx = 7;
        persist_shard_location(meta.as_ref(), &key_of(&shard(3)), &no_disk, None).unwrap();
        let err = store.read(&shard(3)).await.expect_err("read from no disk");
        assert_eq!(err.code(), tonic::Code::DataLoss, "{err}");
        store.corrupt.write().clear();

        store.scrub(0, &|_| {}).await;
        for o in [0, 1, 3] {
            assert_eq!(store.state(&shard(o)), ShardState::Corrupt, "shard {o}");
        }
        assert_eq!(store.state(&shard(2)), ShardState::Ok);
    }

    /// The disks a store is opened on are placed by what was recorded:
    /// each by its id, a blank one in a missing one's place or at the end.
    #[test]
    fn disks_are_arranged_by_their_recorded_ids() {
        let d = |id: u8, formatted_now: bool| OpenedDisk {
            id: [id; 16],
            path: format!("/d{id}"),
            formatted_now,
        };
        let set = |ids: &[u8]| DiskSetRecord {
            disks: ids
                .iter()
                .map(|&id| DiskSlotRecord {
                    id: vec![id; 16],
                    path: format!("/d{id}"),
                })
                .collect(),
        };
        // First open: as named, and recorded.
        let a = arrange_disks(None, &[d(1, false), d(2, true)]).unwrap();
        assert_eq!(a.order, [0, 1]);
        assert_eq!(a.replaced, [false, true]);
        assert_eq!(a.record, Some(set(&[1, 2])));
        // Reordered: back in place, nothing to record.
        let a = arrange_disks(
            Some(&set(&[1, 2, 3])),
            &[d(3, false), d(1, false), d(2, false)],
        )
        .unwrap();
        assert_eq!(a.order, [1, 2, 0]);
        assert_eq!(a.replaced, [false; 3]);
        assert_eq!(a.record, None);
        // A blank one for a missing one, and one more at the end.
        let a = arrange_disks(
            Some(&set(&[1, 2, 3])),
            &[d(9, true), d(1, false), d(3, false), d(8, true)],
        )
        .unwrap();
        assert_eq!(a.order, [1, 0, 2, 3]);
        assert_eq!(a.replaced, [false, true, false, true]);
        assert_eq!(a.record, Some(set(&[1, 9, 3, 8])));
        // Missing, unknown, twice.
        let e = arrange_disks(Some(&set(&[1, 2, 3])), &[d(1, false), d(3, false)]).unwrap_err();
        assert!(e.contains("disk 1 (id 0202"), "{e}");
        let e = arrange_disks(Some(&set(&[1])), &[d(1, false), d(4, false)]).unwrap_err();
        assert!(e.contains("not one of this OSD's"), "{e}");
        let e = arrange_disks(None, &[d(1, false), d(1, false)]).unwrap_err();
        assert!(e.contains("same disk"), "{e}");
    }

    /// An index that places a shard on a disk past the OSD's (records from
    /// before the set was, with a disk gone) refuses the store.
    #[tokio::test]
    async fn a_location_past_the_disks_refuses_the_store() {
        let dir = tempfile::tempdir().unwrap();
        write_shards(dir.path(), &["a", "b"], 0..4).await;
        {
            let (store, meta) = open_disks(dir.path(), &["a", "b"]).unwrap();
            drop(store);
            meta.delete(&MetadataKey::from_bytes(DISK_SET_KEY.to_vec()))
                .unwrap();
        }
        let err = open_disks(dir.path(), &["a"])
            .err()
            .expect("opened short a disk");
        assert!(err.contains("on disk 1, and this OSD has 1 disks"), "{err}");
    }

    /// A metadata index whose disk-set record can't be read: `get` answers
    /// "none", as a store hiding its errors would; `try_get` the error.
    struct UnreadableDiskSet(Arc<dyn MetaIndex>);

    impl MetaIndex for UnreadableDiskSet {
        fn get(&self, key: &MetadataKey) -> Option<Vec<u8>> {
            if key.0 == DISK_SET_KEY {
                return None;
            }
            self.0.get(key)
        }
        fn try_get(&self, key: &MetadataKey) -> objectio_common::Result<Option<Vec<u8>>> {
            if key.0 == DISK_SET_KEY {
                return Err(objectio_common::Error::Storage(
                    "injected: page unreadable".into(),
                ));
            }
            self.0.try_get(key)
        }
        fn write(&self, ops: Vec<MetadataOp>) -> objectio_common::Result<()> {
            self.0.write(ops)
        }
        fn for_each_prefix(
            &self,
            prefix: &MetadataKey,
            after: Option<&MetadataKey>,
            f: &mut dyn FnMut(&[u8], &[u8]) -> bool,
        ) {
            self.0.for_each_prefix(prefix, after, f);
        }
        fn len(&self) -> u64 {
            self.0.len()
        }
        fn render_metrics(&self, out: &mut String, labels: &str) {
            self.0.render_metrics(out, labels);
        }
    }

    /// A record of the disks that can't be read, or doesn't decode, stops
    /// the store: it isn't a first start, which would record the disks
    /// again in the order named.
    #[tokio::test]
    async fn an_unreadable_disk_set_record_refuses_the_store() {
        let dir = tempfile::tempdir().unwrap();
        write_shards(dir.path(), &["a", "b", "c"], 0..9).await;
        let meta = objectio_storage::metadata::open(MetadataStoreConfig::with_data_dir(
            dir.path().join("state"),
        ))
        .unwrap();
        let unreadable: Arc<dyn MetaIndex> = Arc::new(UnreadableDiskSet(Arc::clone(&meta)));
        let err = open_disks_on(dir.path(), &["c", "a", "b"], unreadable)
            .err()
            .expect("opened on an unreadable record");
        assert!(err.contains("can't be read"), "{err}");

        meta.put(
            MetadataKey::from_bytes(DISK_SET_KEY.to_vec()),
            b"\xff\xff not a record".to_vec(),
        )
        .unwrap();
        let err = open_disks_on(dir.path(), &["a", "b", "c"], meta)
            .err()
            .expect("opened on an undecodable record");
        assert!(err.contains("unreadable"), "{err}");
    }

    /// A disk file not there is created on the OSD's first start only;
    /// after that it is a disk gone, refused, not made anew and taken for
    /// a blank replacement.
    #[tokio::test]
    async fn a_missing_disk_file_is_created_only_on_a_first_start() {
        let dir = tempfile::tempdir().unwrap();
        let path = |n: &str| dir.path().join(n).display().to_string();
        let open = |names: &[&str]| {
            let meta = objectio_storage::metadata::open(MetadataStoreConfig::with_data_dir(
                dir.path().join("state"),
            ))
            .unwrap();
            let paths: Vec<String> = names.iter().map(|n| path(n)).collect();
            let disks = Disks::open(&paths, BLOCK, meta.as_ref())?;
            BlockStore::new(disks, Arc::clone(&meta), dir.path().join("state")).map(|s| (s, meta))
        };
        {
            // First start: the files are made.
            let (store, _meta) = open(&["a", "b"]).unwrap();
            for o in 0..4 {
                let data = bytes_of(o);
                store
                    .write(&shard(o), &data, crc32c::crc32c(&data), false)
                    .await
                    .unwrap();
            }
        }
        std::fs::remove_file(dir.path().join("b")).unwrap();
        let err = open(&["a", "b"])
            .err()
            .expect("opened with a disk file gone");
        assert!(err.contains("does not exist"), "{err}");
        assert!(
            !dir.path().join("b").exists(),
            "a file made in the gone disk's place"
        );
        // A blank file put there by the operator is a replacement.
        std::fs::File::create(dir.path().join("b"))
            .unwrap()
            .set_len(1 << 30)
            .unwrap();
        let (store, _meta) = open(&["a", "b"]).unwrap();
        assert_eq!(store.dropped_at_open(), 2);
        assert!(store.read(&shard(0)).await.unwrap().0 == bytes_of(0));
    }
}
