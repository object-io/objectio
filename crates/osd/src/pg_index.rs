//! An OSD's metadata, indexed by placement group (B31 phase 2,
//! objectio-docs `core/pg-recovery.md`).
//!
//! Peering asks each member of a placement group what it holds of it. The
//! OSD's ObjectMeta copies are keyed by bucket and key (`m…`), the order
//! bucket listings read them in, so what one PG holds would be a scan of
//! everything. [`PgIndexed`] keeps, beside them, one entry per key under its
//! PG: `pg/{pool}\0{pg_id:u32be}{bucket}\0{key}` → the key's current object
//! (its write order, how many stripes and shard positions it has, and how
//! many of those name this OSD) or, when it has none, the tombstone of its
//! last delete; and, for a versioned key, one more per version,
//! `…{bucket}\0{key}\0{version_id}` → the version (`v…`) or the tombstone
//! of its delete. One PG's contents are then one prefix scan.
//!
//! The index is a layer over the metadata store, not a change to the
//! writers: every write that touches a key's current entry (`m…`), a
//! version (`v…`) or their tombstones (`t…`) has that index entry put or
//! deleted in the same
//! atomic write, under a lock on the key, so the two never disagree, a
//! crash included. Each PG's summary (counts, and an order-independent
//! digest of its entries) is kept in memory, changed by each write's delta
//! (the deltas commute, so concurrent writes to one PG need no lock
//! between them), and made again from the index when the OSD opens: it is
//! never stored, so it can't be stale.
//!
//! A key whose PG is known neither from its ObjectMeta (`pg_pool`,
//! `pg_id`, set by the gateway from level 7) nor from its tombstone is not
//! indexed: keys placed per key, written before placement groups.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use objectio_common::Result;
use objectio_proto::metadata::{ObjectMeta, StripeMeta};
use objectio_proto::storage::{PgEntry, PgSummary};
use objectio_storage::metadata::{MetaIndex, MetadataKey, MetadataOp};
use parking_lot::Mutex;
use prost::Message;
use tracing::info;

/// Where index entries live.
const PREFIX: &[u8] = b"pg/";

/// Present once the index has been made for every key the store held: a
/// store opened without it (made before the index existed) is indexed then.
const BUILT: &[u8] = b"pgindex:built";

/// Key locks: writes to different keys of one PG run in parallel.
const LOCKS: usize = 1024;

/// Entries written per batch when the index is made.
const BUILD_BATCH: usize = 1024;

/// A placement group: pool and id.
pub type PgId = (String, u32);

/// The index key of `bucket/key` in placement group `pool/pg`.
#[must_use]
pub fn entry_key(pool: &str, pg: u32, bucket: &str, key: &str) -> MetadataKey {
    let mut k = pg_prefix(pool, pg).0;
    k.extend_from_slice(bucket.as_bytes());
    k.push(0);
    k.extend_from_slice(key.as_bytes());
    MetadataKey::from_bytes(k)
}

/// The index key of version `version_id` of `bucket/key` in placement
/// group `pool/pg`.
#[must_use]
pub fn version_key(pool: &str, pg: u32, bucket: &str, key: &str, version_id: &str) -> MetadataKey {
    let mut k = entry_key(pool, pg, bucket, key).0;
    k.push(0);
    k.extend_from_slice(version_id.as_bytes());
    MetadataKey::from_bytes(k)
}

/// The index key of entry `e` (a key's, or one of its versions') in `pg`.
fn key_of(pg: &PgId, e: &PgEntry) -> MetadataKey {
    if e.version_id.is_empty() {
        entry_key(&pg.0, pg.1, &e.bucket, &e.key)
    } else {
        version_key(&pg.0, pg.1, &e.bucket, &e.key, &e.version_id)
    }
}

/// An entry's place in its PG's order: what ListPg's cursor names.
#[must_use]
pub fn cursor_of(e: &PgEntry) -> String {
    if e.version_id.is_empty() {
        format!("{}\0{}", e.bucket, e.key)
    } else {
        format!("{}\0{}\0{}", e.bucket, e.key, e.version_id)
    }
}

/// The prefix of every entry of placement group `pool/pg`.
#[must_use]
pub fn pg_prefix(pool: &str, pg: u32) -> MetadataKey {
    let mut k = Vec::with_capacity(PREFIX.len() + pool.len() + 5);
    k.extend_from_slice(PREFIX);
    k.extend_from_slice(pool.as_bytes());
    k.push(0);
    k.extend_from_slice(&pg.to_be_bytes());
    MetadataKey::from_bytes(k)
}

/// `(pool, pg, bucket, key, version_id)` of an index key (the version empty
/// for a key's own entry).
fn parse_entry_key(k: &[u8]) -> Option<(String, u32, String, String, String)> {
    let rest = k.strip_prefix(PREFIX)?;
    let nul = rest.iter().position(|&b| b == 0)?;
    let pool = std::str::from_utf8(&rest[..nul]).ok()?.to_string();
    let rest = &rest[nul + 1..];
    let pg = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?);
    let rest = &rest[4..];
    let nul = rest.iter().position(|&b| b == 0)?;
    let bucket = std::str::from_utf8(&rest[..nul]).ok()?.to_string();
    let rest = &rest[nul + 1..];
    let (key, version) = match rest.iter().position(|&b| b == 0) {
        Some(n) => (&rest[..n], &rest[n + 1..]),
        None => (rest, &rest[rest.len()..]),
    };
    Some((
        pool,
        pg,
        bucket,
        std::str::from_utf8(key).ok()?.to_string(),
        std::str::from_utf8(version).ok()?.to_string(),
    ))
}

/// The value of a tombstone: the delete's stamp, then (when known) the
/// placement group of its key, so a key that has only a tombstone left is
/// still indexed under its PG.
#[must_use]
pub fn tombstone_value(stamp: u64, pg: Option<(&str, u32)>) -> Vec<u8> {
    let mut v = stamp.to_be_bytes().to_vec();
    if let Some((pool, id)) = pg.filter(|(pool, _)| !pool.is_empty()) {
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(pool.as_bytes());
    }
    v
}

/// The stamp a tombstone's value holds.
#[must_use]
pub fn tombstone_stamp(v: &[u8]) -> u64 {
    v.get(..8)
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map_or(0, u64::from_be_bytes)
}

/// The placement group a tombstone's value names, if any.
#[must_use]
pub fn tombstone_pg(v: &[u8]) -> Option<PgId> {
    let id = u32::from_be_bytes(v.get(8..12)?.try_into().ok()?);
    let pool = std::str::from_utf8(v.get(12..)?).ok()?;
    (!pool.is_empty()).then(|| (pool.to_string(), id))
}

/// `(bucket, key, version)` whose index entry a write of `k` may change: the
/// key's own (its current object `m…`, or the tombstone of its last delete
/// `t…\0`), or one of its versions' (`v…`, or `t…\0{version_id}`).
fn touched(k: &MetadataKey) -> Option<(String, String, Option<String>)> {
    match k.as_bytes().first() {
        Some(b'm') => k.parse_object_meta().map(|(b, k)| (b, k, None)),
        Some(b'v') => k.parse_object_version().map(|(b, k, v)| (b, k, Some(v))),
        Some(b't') => {
            let rest = &k.as_bytes()[1..];
            let nul = rest.iter().position(|&b| b == 0)?;
            let after = &rest[nul + 1..];
            let nul2 = after.iter().position(|&b| b == 0)?;
            let version = std::str::from_utf8(&after[nul2 + 1..]).ok()?;
            Some((
                std::str::from_utf8(&rest[..nul]).ok()?.to_string(),
                std::str::from_utf8(&after[..nul2]).ok()?.to_string(),
                (!version.is_empty()).then(|| version.to_string()),
            ))
        }
        _ => None,
    }
}

/// The object (`m…`, or the version `v…`) and tombstone keys of a key's
/// entry, or of one of its versions'.
fn sources(bucket: &str, key: &str, version: Option<&str>) -> (MetadataKey, MetadataKey) {
    match version {
        None => (
            MetadataKey::object_meta(bucket, key),
            MetadataKey::tombstone(bucket, key, ""),
        ),
        Some(v) => (
            MetadataKey::object_version(bucket, key, v),
            MetadataKey::tombstone(bucket, key, v),
        ),
    }
}

/// `ix` as a version's entry (`version` set), or as it is.
fn as_version(mut ix: Indexed, version: Option<&str>) -> Indexed {
    if let Some(v) = version {
        ix.entry.version_id = v.to_string();
    }
    ix
}

/// A key's entry and the placement group it is under.
#[derive(Clone, Debug, PartialEq)]
struct Indexed {
    pg: PgId,
    entry: PgEntry,
}

/// The index entry of `bucket/key`, from its current ObjectMeta `m` and its
/// tombstone `t` as stored: the object when there is one (a write never
/// lands under a newer tombstone, and a delete removes it), else the
/// tombstone. Its PG comes from the object, else the tombstone, else
/// `hint` (the PG the key was indexed under before). None: not indexed.
fn derive(
    node_id: &[u8; 16],
    bucket: &str,
    key: &str,
    m: Option<&[u8]>,
    t: Option<&[u8]>,
    hint: Option<&PgId>,
) -> Option<Indexed> {
    let from_t = t.and_then(tombstone_pg);
    if let Some(m) = m {
        let o = ObjectMeta::decode(m).ok()?;
        let pg = if o.pg_pool.is_empty() {
            from_t.or_else(|| hint.cloned())?
        } else {
            (o.pg_pool.clone(), o.pg_id)
        };
        return Some(Indexed {
            pg,
            entry: object_entry(node_id, bucket, key, &o),
        });
    }
    let t = t?;
    let pg = from_t.or_else(|| hint.cloned())?;
    Some(Indexed {
        pg,
        entry: PgEntry {
            bucket: bucket.to_string(),
            key: key.to_string(),
            tombstone: true,
            stamp: tombstone_stamp(t),
            ..PgEntry::default()
        },
    })
}

/// The stripes of `o` that are its own: not a packed object's slice of a
/// pack, whose shards are the pack's (recorded in meta) and listed nowhere
/// in the object's metadata.
pub(crate) fn own_stripes(o: &ObjectMeta) -> impl Iterator<Item = &StripeMeta> {
    o.stripes.iter().filter(|s| s.pack_id.is_empty())
}

/// The entry of a current object.
fn object_entry(node_id: &[u8; 16], bucket: &str, key: &str, o: &ObjectMeta) -> PgEntry {
    let mut short = 0u32;
    let mut here = 0u32;
    for stripe in own_stripes(o) {
        let total = stripe.ec_k + stripe.ec_m;
        let mut listed: Vec<u32> = stripe.shards.iter().map(|s| s.position).collect();
        listed.sort_unstable();
        listed.dedup();
        short += total.saturating_sub(u32::try_from(listed.len()).unwrap_or(u32::MAX));
        let mut mine: Vec<u32> = stripe
            .shards
            .iter()
            .filter(|s| s.node_id.as_slice() == node_id.as_slice())
            .map(|s| s.position)
            .collect();
        mine.sort_unstable();
        mine.dedup();
        here += u32::try_from(mine.len()).unwrap_or(u32::MAX);
    }
    PgEntry {
        bucket: bucket.to_string(),
        key: key.to_string(),
        tombstone: false,
        stamp: o.stamp,
        object_id: o.object_id.clone(),
        update_stamp: o.update_stamp,
        stripes: u32::try_from(own_stripes(o).count()).unwrap_or(u32::MAX),
        positions_short: short,
        named_here: here,
        held_here: 0,
        needed: o.stripes.first().map_or(1, |s| s.ec_k.max(1)),
        size: o.size,
        version_id: String::new(),
    }
}

/// The 128-bit hash an entry adds to its PG's digest: of its key, its kind
/// and its write order.
#[must_use]
pub fn entry_hash(e: &PgEntry) -> u128 {
    let mut b = Vec::with_capacity(e.bucket.len() + e.key.len() + e.object_id.len() + 20);
    b.extend_from_slice(e.bucket.as_bytes());
    b.push(0);
    b.extend_from_slice(e.key.as_bytes());
    b.push(0);
    b.push(u8::from(e.tombstone));
    b.extend_from_slice(&e.stamp.to_be_bytes());
    b.extend_from_slice(&e.object_id);
    b.extend_from_slice(&e.update_stamp.to_be_bytes());
    if !e.version_id.is_empty() {
        b.push(0);
        b.extend_from_slice(e.version_id.as_bytes());
    }
    let hi = xxhash_rust::xxh64::xxh64(&b, 0);
    let lo = xxhash_rust::xxh64::xxh64(&b, 0x9e37_79b9_7f4a_7c15);
    (u128::from(hi) << 64) | u128::from(lo)
}

/// A PG's summary on this OSD, as kept in memory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub objects: u64,
    pub tombstones: u64,
    pub max_stamp: u64,
    pub digest: u128,
    pub stripes: u64,
    pub positions_short: u64,
    pub named_here: u64,
}

impl Summary {
    fn add(&mut self, e: &PgEntry) {
        if e.tombstone {
            self.tombstones += 1;
        } else {
            self.objects += 1;
            self.stripes += u64::from(e.stripes);
            self.positions_short += u64::from(e.positions_short);
            self.named_here += u64::from(e.named_here);
        }
        self.max_stamp = self.max_stamp.max(e.stamp);
        self.digest ^= entry_hash(e);
    }

    /// Take `e` out. The highest stamp stays: it is the highest written.
    fn sub(&mut self, e: &PgEntry) {
        if e.tombstone {
            self.tombstones = self.tombstones.saturating_sub(1);
        } else {
            self.objects = self.objects.saturating_sub(1);
            self.stripes = self.stripes.saturating_sub(u64::from(e.stripes));
            self.positions_short = self
                .positions_short
                .saturating_sub(u64::from(e.positions_short));
            self.named_here = self.named_here.saturating_sub(u64::from(e.named_here));
        }
        self.digest ^= entry_hash(e);
    }

    fn is_empty(&self) -> bool {
        self.objects == 0 && self.tombstones == 0
    }

    #[must_use]
    pub fn to_proto(&self) -> PgSummary {
        PgSummary {
            objects: self.objects,
            tombstones: self.tombstones,
            max_stamp: self.max_stamp,
            digest: self.digest.to_be_bytes().to_vec(),
            stripes: self.stripes,
            positions_short: self.positions_short,
            named_here: self.named_here,
        }
    }
}

/// The metadata store, with its keys indexed by placement group. See the
/// module documentation.
pub struct PgIndexed {
    inner: Arc<dyn MetaIndex>,
    node_id: [u8; 16],
    locks: Vec<Mutex<()>>,
    summaries: Mutex<HashMap<PgId, Summary>>,
    /// Writes of a current object whose PG isn't known (not indexed).
    unindexed: AtomicU64,
}

impl PgIndexed {
    /// `inner`, indexed by placement group for OSD `node_id`. A store that
    /// has no index yet (made before it existed) is indexed now, from its
    /// current objects and tombstones; then every PG's summary is made from
    /// the index.
    ///
    /// # Errors
    /// The index could not be written.
    pub fn open(inner: Arc<dyn MetaIndex>, node_id: [u8; 16]) -> Result<Self> {
        let me = Self {
            inner,
            node_id,
            locks: (0..LOCKS).map(|_| Mutex::new(())).collect(),
            summaries: Mutex::new(HashMap::new()),
            unindexed: AtomicU64::new(0),
        };
        let built = MetadataKey::from_bytes(BUILT.to_vec());
        if me.inner.get(&built).is_none() {
            let started = std::time::Instant::now();
            let n = me.build()?;
            me.inner.put(built, Vec::new())?;
            info!(
                "Indexed {n} keys by placement group in {:?}",
                started.elapsed()
            );
        }
        me.load();
        Ok(me)
    }

    /// Index every key from what the store holds.
    fn build(&self) -> Result<u64> {
        let mut batch = Vec::with_capacity(BUILD_BATCH);
        let mut n = 0u64;
        let mut seen_m: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();
        for (k, v) in self
            .inner
            .iter_prefix(&MetadataKey::all_object_meta_prefix())
        {
            let Some((bucket, key)) = k.parse_object_meta() else {
                continue;
            };
            let t = self.inner.get(&MetadataKey::tombstone(&bucket, &key, ""));
            if let Some(ix) = derive(&self.node_id, &bucket, &key, Some(&v), t.as_deref(), None) {
                batch.push(put_entry(&ix));
                n += 1;
            }
            seen_m.insert((bucket, key));
            if batch.len() >= BUILD_BATCH {
                self.inner.write(std::mem::take(&mut batch))?;
            }
        }
        // Versions.
        let mut seen_v: std::collections::HashSet<(String, String, String)> =
            std::collections::HashSet::new();
        for (k, v) in self.inner.iter_prefix(&MetadataKey::from_bytes(vec![b'v'])) {
            let Some((bucket, key, version)) = k.parse_object_version() else {
                continue;
            };
            let t = self
                .inner
                .get(&MetadataKey::tombstone(&bucket, &key, &version));
            if let Some(ix) = derive(&self.node_id, &bucket, &key, Some(&v), t.as_deref(), None) {
                batch.push(put_entry(&as_version(ix, Some(&version))));
                n += 1;
            }
            seen_v.insert((bucket, key, version));
            if batch.len() >= BUILD_BATCH {
                self.inner.write(std::mem::take(&mut batch))?;
            }
        }
        // Tombstones with nothing left beside them.
        for (k, v) in self.inner.iter_prefix(&MetadataKey::from_bytes(vec![b't'])) {
            let Some((bucket, key, version)) = touched(&k) else {
                continue;
            };
            let seen = match &version {
                None => seen_m.contains(&(bucket.clone(), key.clone())),
                Some(ver) => seen_v.contains(&(bucket.clone(), key.clone(), ver.clone())),
            };
            if seen {
                continue;
            }
            if let Some(ix) = derive(&self.node_id, &bucket, &key, None, Some(&v), None) {
                batch.push(put_entry(&as_version(ix, version.as_deref())));
                n += 1;
            }
            if batch.len() >= BUILD_BATCH {
                self.inner.write(std::mem::take(&mut batch))?;
            }
        }
        self.inner.write(batch)?;
        Ok(n)
    }

    /// Every PG's summary, from the index.
    fn load(&self) {
        let mut sums: HashMap<PgId, Summary> = HashMap::new();
        for (k, v) in self
            .inner
            .iter_prefix(&MetadataKey::from_bytes(PREFIX.to_vec()))
        {
            let Some((pool, pg, bucket, key, version)) = parse_entry_key(k.as_bytes()) else {
                continue;
            };
            let Ok(mut e) = PgEntry::decode(v.as_slice()) else {
                continue;
            };
            e.bucket = bucket;
            e.key = key;
            e.version_id = version;
            sums.entry((pool, pg)).or_default().add(&e);
        }
        *self.summaries.lock() = sums;
    }

    /// Placement group `pg`'s summary on this OSD (empty if it holds none).
    #[must_use]
    pub fn summary(&self, pg: &PgId) -> Summary {
        self.summaries.lock().get(pg).cloned().unwrap_or_default()
    }

    /// Up to `limit` of `pg`'s entries, in key order (a key's own entry,
    /// then its versions'), after `after` ([`cursor_of`] an entry; empty
    /// from the start), and the cursor of the next page (empty after the
    /// last).
    #[must_use]
    pub fn list(&self, pg: &PgId, after: &str, limit: usize) -> (Vec<PgEntry>, String) {
        let prefix = pg_prefix(&pg.0, pg.1);
        let after_key = (!after.is_empty()).then(|| {
            let mut k = prefix.0.clone();
            k.extend_from_slice(after.as_bytes());
            MetadataKey::from_bytes(k)
        });
        let mut out = Vec::new();
        let mut more = false;
        self.inner
            .for_each_prefix(&prefix, after_key.as_ref(), &mut |k, v| {
                if out.len() >= limit {
                    more = true;
                    return false;
                }
                if let (Some((_, _, bucket, key, version)), Ok(mut e)) =
                    (parse_entry_key(k), PgEntry::decode(v))
                {
                    e.bucket = bucket;
                    e.key = key;
                    e.version_id = version;
                    out.push(e);
                }
                true
            });
        let next = if more {
            out.last().map(cursor_of).unwrap_or_default()
        } else {
            String::new()
        };
        (out, next)
    }

    /// Writes of a current object whose PG wasn't known, since open.
    #[must_use]
    pub fn unindexed(&self) -> u64 {
        self.unindexed.load(Ordering::Relaxed)
    }

    /// The placement groups this OSD holds entries of, and how many.
    #[must_use]
    pub fn pg_count(&self) -> usize {
        self.summaries.lock().len()
    }

    fn lock_of(bucket: &str, key: &str) -> usize {
        let h = xxhash_rust::xxh64::xxh64(format!("{bucket}\0{key}").as_bytes(), 0);
        usize::try_from(h % LOCKS as u64).unwrap_or(0)
    }
}

/// The op that writes `ix`'s entry.
fn put_entry(ix: &Indexed) -> MetadataOp {
    let stored = PgEntry {
        bucket: String::new(),
        key: String::new(),
        version_id: String::new(),
        ..ix.entry.clone()
    };
    MetadataOp::Put {
        key: key_of(&ix.pg, &ix.entry),
        value: stored.encode_to_vec(),
    }
}

/// `ops` with every batch spelled out, in order (a batch is applied as its
/// operations, in one atomic write, as the whole write is).
fn flatten(ops: Vec<MetadataOp>, out: &mut Vec<MetadataOp>) {
    for op in ops {
        match op {
            MetadataOp::Batch { ops } => flatten(ops, out),
            op => out.push(op),
        }
    }
}

/// The key a put or delete writes.
fn op_key(op: &MetadataOp) -> Option<&MetadataKey> {
    match op {
        MetadataOp::Put { key, .. } | MetadataOp::Delete { key } => Some(key),
        MetadataOp::Batch { .. } => None,
    }
}

impl MetaIndex for PgIndexed {
    fn get(&self, key: &MetadataKey) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

    fn write(&self, ops: Vec<MetadataOp>) -> Result<()> {
        let mut flat = Vec::with_capacity(ops.len());
        flatten(ops, &mut flat);
        let ops = flat;
        let mut keys: Vec<(String, String, Option<String>)> = Vec::new();
        for op in &ops {
            if let Some(bk) = op_key(op).and_then(touched)
                && !keys.contains(&bk)
            {
                keys.push(bk);
            }
        }
        if keys.is_empty() {
            return self.inner.write(ops);
        }
        let mut locks: Vec<usize> = keys.iter().map(|(b, k, _)| Self::lock_of(b, k)).collect();
        locks.sort_unstable();
        locks.dedup();
        let _held: Vec<_> = locks.iter().map(|i| self.locks[*i].lock()).collect();

        let mut index_ops = Vec::new();
        let mut deltas: Vec<(Option<Indexed>, Option<Indexed>)> = Vec::new();
        for (bucket, key, version) in &keys {
            let version = version.as_deref();
            let (mk, tk) = sources(bucket, key, version);
            let m0 = self.inner.get(&mk);
            let t0 = self.inner.get(&tk);
            let (mut m1, mut t1) = (m0.clone(), t0.clone());
            for op in &ops {
                match op {
                    MetadataOp::Put { key, value } if *key == mk => m1 = Some(value.clone()),
                    MetadataOp::Delete { key } if *key == mk => m1 = None,
                    MetadataOp::Put { key, value } if *key == tk => t1 = Some(value.clone()),
                    MetadataOp::Delete { key } if *key == tk => t1 = None,
                    _ => {}
                }
            }
            let before = derive(
                &self.node_id,
                bucket,
                key,
                m0.as_deref(),
                t0.as_deref(),
                None,
            )
            .map(|ix| as_version(ix, version));
            let after = derive(
                &self.node_id,
                bucket,
                key,
                m1.as_deref(),
                t1.as_deref(),
                before.as_ref().map(|b| &b.pg),
            )
            .map(|ix| as_version(ix, version));
            if after.is_none() && m1.is_some() && version.is_none() {
                self.unindexed.fetch_add(1, Ordering::Relaxed);
            }
            if before == after {
                continue;
            }
            if let Some(b) = &before
                && after.as_ref().is_none_or(|a| a.pg != b.pg)
            {
                index_ops.push(MetadataOp::Delete {
                    key: key_of(&b.pg, &b.entry),
                });
            }
            if let Some(a) = &after {
                index_ops.push(put_entry(a));
            }
            deltas.push((before, after));
        }
        let mut ops = ops;
        ops.extend(index_ops);
        self.inner.write(ops)?;
        let mut sums = self.summaries.lock();
        for (before, after) in deltas {
            if let Some(b) = before
                && let Some(s) = sums.get_mut(&b.pg)
            {
                s.sub(&b.entry);
                if s.is_empty() {
                    sums.remove(&b.pg);
                }
            }
            if let Some(a) = after {
                sums.entry(a.pg.clone()).or_default().add(&a.entry);
            }
        }
        Ok(())
    }

    fn for_each_prefix(
        &self,
        prefix: &MetadataKey,
        after: Option<&MetadataKey>,
        f: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    ) {
        self.inner.for_each_prefix(prefix, after, f);
    }

    fn len(&self) -> u64 {
        self.inner.len()
    }

    fn render_metrics(&self, out: &mut String, labels: &str) {
        use std::fmt::Write as _;
        self.inner.render_metrics(out, labels);
        let _ = writeln!(
            out,
            "# HELP objectio_osd_pgs_held Placement groups this OSD holds entries of\n\
             # TYPE objectio_osd_pgs_held gauge\nobjectio_osd_pgs_held{{{labels}}} {}",
            self.pg_count()
        );
        let _ = writeln!(
            out,
            "# HELP objectio_osd_pg_unindexed_writes_total Writes of an object whose placement \
             group isn't known (not indexed)\n# TYPE objectio_osd_pg_unindexed_writes_total \
             counter\nobjectio_osd_pg_unindexed_writes_total{{{labels}}} {}",
            self.unindexed()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use objectio_proto::metadata::{ShardLocation, StripeMeta};
    use objectio_storage::metadata::MetadataStoreConfig;

    const ME: [u8; 16] = [1; 16];

    fn open(dir: &std::path::Path) -> PgIndexed {
        let inner =
            objectio_storage::metadata::open(MetadataStoreConfig::with_data_dir(dir)).unwrap();
        PgIndexed::open(inner, ME).unwrap()
    }

    fn object(key: &str, stamp: u64, pg: u32, here: bool) -> ObjectMeta {
        let other = [2u8; 16];
        ObjectMeta {
            bucket: "b".into(),
            key: key.into(),
            object_id: vec![stamp as u8; 16],
            stamp,
            pg_pool: "p".into(),
            pg_id: pg,
            stripes: vec![StripeMeta {
                stripe_id: 0,
                ec_k: 1,
                ec_m: 1,
                shards: vec![
                    ShardLocation {
                        position: 0,
                        node_id: if here { ME.to_vec() } else { other.to_vec() },
                        ..Default::default()
                    },
                    ShardLocation {
                        position: 1,
                        node_id: other.to_vec(),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn put(ix: &PgIndexed, o: &ObjectMeta) {
        ix.put(
            MetadataKey::object_meta(&o.bucket, &o.key),
            o.encode_to_vec(),
        )
        .unwrap();
    }

    fn delete(ix: &PgIndexed, key: &str, stamp: u64, pg: u32) {
        ix.write(vec![
            MetadataOp::Delete {
                key: MetadataKey::object_meta("b", key),
            },
            MetadataOp::Put {
                key: MetadataKey::tombstone("b", key, ""),
                value: tombstone_value(stamp, Some(("p", pg))),
            },
        ])
        .unwrap();
    }

    #[test]
    fn the_digest_is_independent_of_the_order_of_writes() {
        let (d1, d2) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let (a, b) = (open(d1.path()), open(d2.path()));
        let objects: Vec<ObjectMeta> = (0..20)
            .map(|i| object(&format!("k{i}"), 10 + i, 3, true))
            .collect();
        for o in &objects {
            put(&a, o);
        }
        for o in objects.iter().rev() {
            put(&b, o);
        }
        let pg = ("p".to_string(), 3);
        assert_eq!(a.summary(&pg), b.summary(&pg));
        assert_eq!(a.summary(&pg).objects, 20);
        assert_eq!(a.summary(&pg).named_here, 20);
        // One copy missing an overwrite differs.
        put(&a, &object("k3", 99, 3, true));
        assert_ne!(a.summary(&pg).digest, b.summary(&pg).digest);
        put(&b, &object("k3", 99, 3, true));
        assert_eq!(a.summary(&pg), b.summary(&pg));
    }

    #[test]
    fn a_delete_leaves_a_tombstone_entry_and_takes_the_object_out() {
        let d = tempfile::tempdir().unwrap();
        let ix = open(d.path());
        let pg = ("p".to_string(), 1);
        put(&ix, &object("k", 5, 1, true));
        let with = ix.summary(&pg);
        delete(&ix, "k", 6, 1);
        let s = ix.summary(&pg);
        assert_eq!((s.objects, s.tombstones, s.stripes), (0, 1, 0));
        let (entries, next) = ix.list(&pg, "", 10);
        assert!(next.is_empty());
        assert_eq!(entries.len(), 1);
        assert!(entries[0].tombstone);
        assert_eq!(entries[0].stamp, 6);
        // A copy that took the delete differs from one that didn't.
        assert_ne!(with.digest, s.digest);
        // Written again: the object, not the tombstone.
        put(&ix, &object("k", 7, 1, true));
        let s = ix.summary(&pg);
        assert_eq!((s.objects, s.tombstones), (1, 0));
    }

    #[test]
    fn summaries_are_made_again_from_the_index_on_open() {
        let d = tempfile::tempdir().unwrap();
        let pg = ("p".to_string(), 2);
        let before = {
            let ix = open(d.path());
            for i in 0..50 {
                put(&ix, &object(&format!("k{i}"), 100 + i, 2, i % 2 == 0));
            }
            delete(&ix, "k7", 500, 2);
            ix.summary(&pg)
        };
        let ix = open(d.path());
        assert_eq!(ix.summary(&pg), before);
        assert_eq!(before.objects, 49);
        assert_eq!(before.named_here, 25); // even keys name this OSD; k7 is odd
    }

    #[test]
    fn a_store_without_the_index_is_indexed_when_opened() {
        let d = tempfile::tempdir().unwrap();
        let pg = ("p".to_string(), 4);
        {
            let inner =
                objectio_storage::metadata::open(MetadataStoreConfig::with_data_dir(d.path()))
                    .unwrap();
            for i in 0..10 {
                let o = object(&format!("k{i}"), 10 + i, 4, true);
                inner
                    .put(MetadataKey::object_meta("b", &o.key), o.encode_to_vec())
                    .unwrap();
            }
            inner
                .put(
                    MetadataKey::tombstone("b", "gone", ""),
                    tombstone_value(9, Some(("p", 4))),
                )
                .unwrap();
        }
        let ix = open(d.path());
        let s = ix.summary(&pg);
        assert_eq!((s.objects, s.tombstones), (10, 1));
    }

    /// A versioned key: its own entry (the current object), then one entry
    /// per version, each with its id, in that order; a version's delete
    /// leaves its tombstone entry in place of the version's.
    #[test]
    fn each_version_is_an_entry_of_its_own() {
        let d = tempfile::tempdir().unwrap();
        let ix = open(d.path());
        let pg = ("p".to_string(), 5);
        let v1 = ObjectMeta {
            version_id: "v1".into(),
            ..object("k", 10, 5, true)
        };
        let v2 = ObjectMeta {
            version_id: "v2".into(),
            ..object("k", 11, 5, true)
        };
        // As a versioned PUT stores them: the version entries, and the
        // newest also as the current object.
        for v in [&v1, &v2] {
            ix.put(
                MetadataKey::object_version("b", "k", &v.version_id),
                v.encode_to_vec(),
            )
            .unwrap();
        }
        put(&ix, &v2);
        let (entries, next) = ix.list(&pg, "", 10);
        assert!(next.is_empty());
        let names: Vec<(String, String, bool)> = entries
            .iter()
            .map(|e| (e.key.clone(), e.version_id.clone(), e.tombstone))
            .collect();
        assert_eq!(
            names,
            [
                ("k".to_string(), String::new(), false),
                ("k".to_string(), "v1".to_string(), false),
                ("k".to_string(), "v2".to_string(), false),
            ]
        );
        assert_eq!(entries[1].object_id, v1.object_id);
        assert_eq!(ix.summary(&pg).objects, 3);

        // v1 deleted: its entry is now the delete.
        ix.write(vec![
            MetadataOp::Delete {
                key: MetadataKey::object_version("b", "k", "v1"),
            },
            MetadataOp::Put {
                key: MetadataKey::tombstone("b", "k", "v1"),
                value: tombstone_value(12, Some(("p", 5))),
            },
        ])
        .unwrap();
        let (entries, _) = ix.list(&pg, "", 10);
        let v1e = entries.iter().find(|e| e.version_id == "v1").unwrap();
        assert!(v1e.tombstone);
        assert_eq!(v1e.stamp, 12);
        let s = ix.summary(&pg);
        assert_eq!((s.objects, s.tombstones), (2, 1));

        // Paged one at a time, every entry once, versions included.
        let mut after = String::new();
        let mut seen = Vec::new();
        loop {
            let (page, next) = ix.list(&pg, &after, 1);
            seen.extend(page.into_iter().map(|e| e.version_id));
            if next.is_empty() {
                break;
            }
            after = next;
        }
        assert_eq!(seen, ["", "v1", "v2"]);
    }

    #[test]
    fn a_stores_versions_are_indexed_when_it_is_opened() {
        let d = tempfile::tempdir().unwrap();
        let pg = ("p".to_string(), 6);
        {
            let inner =
                objectio_storage::metadata::open(MetadataStoreConfig::with_data_dir(d.path()))
                    .unwrap();
            let v1 = ObjectMeta {
                version_id: "v1".into(),
                ..object("k", 10, 6, true)
            };
            inner
                .put(
                    MetadataKey::object_version("b", "k", "v1"),
                    v1.encode_to_vec(),
                )
                .unwrap();
            inner
                .put(
                    MetadataKey::tombstone("b", "k", "v0"),
                    tombstone_value(9, Some(("p", 6))),
                )
                .unwrap();
        }
        let ix = open(d.path());
        let s = ix.summary(&pg);
        assert_eq!((s.objects, s.tombstones), (1, 1));
        let (entries, _) = ix.list(&pg, "", 10);
        let versions: Vec<&str> = entries.iter().map(|e| e.version_id.as_str()).collect();
        assert_eq!(versions, ["v0", "v1"]);
    }

    #[test]
    fn listing_pages_through_one_pg_only() {
        let d = tempfile::tempdir().unwrap();
        let ix = open(d.path());
        for i in 0..25 {
            put(&ix, &object(&format!("k{i:02}"), 10 + i, 1, true));
            put(&ix, &object(&format!("x{i:02}"), 10 + i, 2, true));
        }
        let pg = ("p".to_string(), 1);
        let mut all = Vec::new();
        let mut after = String::new();
        loop {
            let (page, next) = ix.list(&pg, &after, 10);
            all.extend(page);
            if next.is_empty() {
                break;
            }
            after = next;
        }
        assert_eq!(all.len(), 25);
        assert!(all.iter().all(|e| e.key.starts_with('k')));
    }

    #[test]
    fn a_key_moved_to_another_pg_leaves_the_first() {
        let d = tempfile::tempdir().unwrap();
        let ix = open(d.path());
        put(&ix, &object("k", 5, 1, true));
        put(&ix, &object("k", 6, 2, true));
        assert_eq!(ix.summary(&("p".to_string(), 1)).objects, 0);
        assert_eq!(ix.summary(&("p".to_string(), 2)).objects, 1);
    }

    /// What indexing costs a write, and what listing one PG costs: run with
    /// `cargo test --release -p objectio-osd pg_index::tests::cost -- --ignored --nocapture`.
    #[test]
    #[ignore = "a measurement, not a check"]
    fn cost() {
        let n = 20_000u64;
        let objects: Vec<ObjectMeta> = (0..n)
            .map(|i| {
                let mut o = object(&format!("k{i:06}"), 1000 + i, (i % 256) as u32, true);
                for s in &mut o.stripes {
                    s.ec_k = 4;
                    s.ec_m = 2;
                    s.shards = (0..6)
                        .map(|p| ShardLocation {
                            position: p,
                            node_id: if p == 0 {
                                ME.to_vec()
                            } else {
                                vec![p as u8 + 2; 16]
                            },
                            ..Default::default()
                        })
                        .collect();
                }
                o
            })
            .collect();
        // Without fsync, so the CPU cost shows rather than the disk's.
        let time = |indexed: bool| {
            let d = tempfile::tempdir().unwrap();
            let mut config = MetadataStoreConfig::with_data_dir(d.path());
            config.wal.sync_on_write = false;
            let inner = objectio_storage::metadata::open(config).unwrap();
            let store: Arc<dyn MetaIndex> = if indexed {
                Arc::new(PgIndexed::open(inner, ME).unwrap())
            } else {
                inner
            };
            let started = std::time::Instant::now();
            for o in &objects {
                store
                    .put(
                        MetadataKey::object_meta(&o.bucket, &o.key),
                        o.encode_to_vec(),
                    )
                    .unwrap();
            }
            (started.elapsed(), store)
        };
        let (plain, _) = time(false);
        let (indexed, store) = time(true);
        println!(
            "{n} ObjectMeta writes: plain {plain:?} ({:.1} µs each), indexed {indexed:?} ({:.1} µs each)",
            plain.as_secs_f64() * 1e6 / n as f64,
            indexed.as_secs_f64() * 1e6 / n as f64
        );
        drop(store);
        let d = tempfile::tempdir().unwrap();
        let inner =
            objectio_storage::metadata::open(MetadataStoreConfig::with_data_dir(d.path())).unwrap();
        let ix = PgIndexed::open(inner, ME).unwrap();
        for o in objects.iter().take(800) {
            let mut o = o.clone();
            o.pg_id = 7;
            put(&ix, &o);
        }
        let started = std::time::Instant::now();
        let (entries, _) = ix.list(&("p".to_string(), 7), "", 1000);
        println!(
            "list of an 800-key PG: {:?} ({} entries)",
            started.elapsed(),
            entries.len()
        );
        let started = std::time::Instant::now();
        let s = ix.summary(&("p".to_string(), 7));
        println!("summary: {:?} ({} objects)", started.elapsed(), s.objects);
    }

    #[test]
    fn a_key_with_no_pg_is_not_indexed() {
        let d = tempfile::tempdir().unwrap();
        let ix = open(d.path());
        let mut o = object("k", 5, 1, true);
        o.pg_pool.clear();
        put(&ix, &o);
        assert_eq!(ix.pg_count(), 0);
        assert_eq!(ix.unindexed(), 1);
    }

    /// A packed object's stripe is its slice of a pack, whose shards the
    /// pack's record in meta lists: it names none itself, and isn't counted
    /// as short of them (which kept every PG holding one degraded).
    #[test]
    fn a_packed_objects_slice_is_not_counted_as_shards_missing() {
        let mut o = object("k", 5, 1, true);
        o.stripes = vec![StripeMeta {
            stripe_id: 0,
            ec_k: 4,
            ec_m: 2,
            pack_id: vec![9; 16],
            slice_length: 100,
            ..StripeMeta::default()
        }];
        let e = object_entry(&ME, "b", "k", &o);
        assert_eq!((e.stripes, e.positions_short, e.named_here), (0, 0, 0));
        assert_eq!(e.size, o.size);
    }
}
