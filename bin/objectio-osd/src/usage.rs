//! Per-bucket usage accounting for the objects this OSD is primary for.
//!
//! ObjectMeta is written to every OSD in the key's placement, so if every
//! OSD counted every entry it holds, summing across the cluster would count
//! a 4+2 object six times. Instead each OSD counts only the objects whose
//! `usage_owner` it is — one node the gateway picks from the placement on
//! write — and a caller summing `GetStatus` across OSDs gets each object
//! once. Objects written before `usage_owner` existed fall back to the
//! holder of shard 0 of stripe 0.
//!
//! Counts are kept in memory, rebuilt from the metadata store on startup
//! and adjusted on every ObjectMeta put / delete / copy. Nothing is
//! persisted, so there is no on-disk counter that can drift from the
//! entries it summarises.

use objectio_proto::metadata::ObjectMeta;
use objectio_proto::storage::{BucketUsage, ObjectSafety};
use objectio_storage::metadata::MetadataKey;
use parking_lot::{Mutex, MutexGuard, RwLock};
use prost::Message;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

/// Which of the two ObjectMeta key spaces an entry lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// `m:{bucket}\0{key}` — the current version.
    Current,
    /// `v:{bucket}\0{key}\0{version}` — one entry per version, current
    /// included, written only while versioning is enabled.
    Version,
}

/// Objects / logical bytes / stored bytes for one slice of a bucket.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Tally {
    objects: u64,
    logical: u64,
    stored: u64,
}

impl Tally {
    fn add(&mut self, o: &ObjectMeta) {
        self.objects += 1;
        self.logical += o.size;
        self.stored += stored_bytes(o);
    }

    fn sub(&mut self, o: &ObjectMeta) {
        self.objects = self.objects.saturating_sub(1);
        self.logical = self.logical.saturating_sub(o.size);
        self.stored = self.stored.saturating_sub(stored_bytes(o));
    }
}

/// Raw counters for one bucket. The exported figures are derived from
/// these in [`Counters::to_proto`].
///
/// A versioned PUT writes the same ObjectMeta under both `m:` and `v:`, so
/// the current version appears in `current` *and* `versions`. `current_v`
/// tracks the current entries that carry a version id, which is exactly
/// the overlap: `versions - current_v` is the noncurrent versions.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Counters {
    current: Tally,
    current_v: Tally,
    versions: Tally,
    last_modified: u64,
}

impl Counters {
    fn is_empty(&self) -> bool {
        self.current == Tally::default() && self.versions == Tally::default()
    }

    fn to_proto(self, bucket: &str) -> BucketUsage {
        BucketUsage {
            bucket: bucket.to_string(),
            objects: self.current.objects,
            logical_bytes: self.current.logical,
            stored_bytes: self.current.stored
                + self.versions.stored.saturating_sub(self.current_v.stored),
            noncurrent_versions: self.versions.objects.saturating_sub(self.current_v.objects),
            noncurrent_bytes: self.versions.logical.saturating_sub(self.current_v.logical),
            last_modified: self.last_modified,
        }
    }
}

/// Bytes an object occupies on disk across all its shards, parity
/// included: each stripe is split into `k` data shards of
/// `ceil(data_size / k)` bytes and `m` parity shards of the same length.
///
/// Stripes that predate `data_size` report 0; the object's size is then
/// spread by the first stripe's scheme instead. An object with no stripes
/// (a delete marker) occupies nothing.
#[must_use]
pub fn stored_bytes(o: &ObjectMeta) -> u64 {
    let per_stripe: u64 = o
        .stripes
        .iter()
        .map(|s| {
            let k = u64::from(s.ec_k.max(1));
            let m = u64::from(s.ec_m);
            s.data_size.div_ceil(k) * (k + m)
        })
        .sum();
    if per_stripe > 0 || o.size == 0 {
        return per_stripe;
    }
    o.stripes.first().map_or(0, |s| {
        let k = u64::from(s.ec_k.max(1));
        o.size.div_ceil(k) * (k + u64::from(s.ec_m))
    })
}

/// The node that owns shard 0 of stripe 0, if the object has stripes.
fn primary_node(o: &ObjectMeta) -> Option<&[u8]> {
    o.stripes
        .first()?
        .shards
        .iter()
        .min_by_key(|s| s.position)
        .map(|s| s.node_id.as_slice())
}

struct StripeHealth {
    k: usize,
    available: usize,
    missing: usize,
}

/// The stripe with the fewest reachable shards, or `None` for an object
/// with no stripes. Reachable = the shard's node is in `up`. A replicated
/// stripe is `k = 1`.
fn worst_stripe(o: &ObjectMeta, up: &HashSet<Vec<u8>>) -> Option<StripeHealth> {
    o.stripes
        .iter()
        .filter(|s| !s.shards.is_empty())
        .map(|s| {
            let available = s
                .shards
                .iter()
                .filter(|sh| up.contains(&sh.node_id))
                .count();
            StripeHealth {
                k: s.ec_k.max(1) as usize,
                available,
                missing: s.shards.len() - available,
            }
        })
        .min_by_key(|h| (h.available.saturating_sub(h.k), h.available))
}

/// Number of stripes for per-key serialisation. Enough that unrelated keys
/// rarely wait on each other.
const KEY_LOCKS: usize = 256;

pub struct UsageTracker {
    node_id: [u8; 16],
    buckets: RwLock<HashMap<String, Counters>>,
    /// Serialises read-old → write-new → adjust for one key, so two
    /// concurrent overwrites of the same key cannot both subtract the same
    /// old entry. Striped by key hash rather than one global lock, which
    /// would serialise every ObjectMeta write on the OSD.
    key_locks: Vec<Mutex<()>>,
}

impl UsageTracker {
    #[must_use]
    pub fn new(node_id: [u8; 16]) -> Self {
        Self {
            node_id,
            buckets: RwLock::new(HashMap::new()),
            key_locks: (0..KEY_LOCKS).map(|_| Mutex::new(())).collect(),
        }
    }

    /// Hold while reading the old entry, writing the new one and calling
    /// [`Self::apply`].
    pub fn lock_key(&self, bucket: &str, key: &str) -> MutexGuard<'_, ()> {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        bucket.hash(&mut h);
        key.hash(&mut h);
        #[allow(clippy::cast_possible_truncation)]
        let idx = (h.finish() as usize) % self.key_locks.len();
        self.key_locks[idx].lock()
    }

    fn is_primary(&self, o: &ObjectMeta) -> bool {
        if o.usage_owner.is_empty() {
            primary_node(o) == Some(self.node_id.as_slice())
        } else {
            o.usage_owner == self.node_id
        }
    }

    /// Whether this OSD reports `o` in [`Self::safety`]: its owner does,
    /// unless the owner is down — the objects a down owner holds are the
    /// ones most likely degraded, so the first reachable shard holder (by
    /// position) reports them instead. That holder has the ObjectMeta for
    /// single-part objects; a multipart object's shard holders may not.
    fn checks_safety_of(&self, o: &ObjectMeta, up: &HashSet<Vec<u8>>) -> bool {
        let owner: Option<&[u8]> = if o.usage_owner.is_empty() {
            primary_node(o)
        } else {
            Some(o.usage_owner.as_slice())
        };
        match owner {
            Some(n) if up.contains(n) => n == self.node_id,
            _ => {
                let Some(stripe) = o.stripes.first() else {
                    return false;
                };
                let mut shards: Vec<_> = stripe.shards.iter().collect();
                shards.sort_by_key(|s| s.position);
                shards
                    .into_iter()
                    .find(|s| up.contains(&s.node_id))
                    .is_some_and(|s| s.node_id == self.node_id)
            }
        }
    }

    /// Account for `old` being replaced by `new` under one key. Either may
    /// be `None` (a create or a delete). Entries this OSD is not primary
    /// for are ignored on both sides, so an object whose primary moved
    /// away stops being counted here.
    pub fn apply(
        &self,
        bucket: &str,
        kind: EntryKind,
        old: Option<&ObjectMeta>,
        new: Option<&ObjectMeta>,
    ) {
        let old = old.filter(|o| !o.is_delete_marker && self.is_primary(o));
        let marker_time = new.filter(|o| o.is_delete_marker).map(|o| o.modified_at);
        let new = new.filter(|o| !o.is_delete_marker && self.is_primary(o));
        if old.is_none() && new.is_none() && marker_time.is_none() {
            return;
        }

        let mut buckets = self.buckets.write();
        let c = buckets.entry(bucket.to_string()).or_default();
        if let Some(o) = old {
            Self::adjust(c, kind, o, false);
        }
        if let Some(o) = new {
            Self::adjust(c, kind, o, true);
            c.last_modified = c.last_modified.max(o.modified_at);
        }
        // A delete marker is activity too. Every shard holder sees it, which
        // is harmless: callers merge last_modified with max, not sum.
        if let Some(t) = marker_time {
            c.last_modified = c.last_modified.max(t);
        }
        if c.is_empty() && c.last_modified == 0 {
            buckets.remove(bucket);
        }
    }

    fn adjust(c: &mut Counters, kind: EntryKind, o: &ObjectMeta, add: bool) {
        let op = |t: &mut Tally| if add { t.add(o) } else { t.sub(o) };
        match kind {
            EntryKind::Current => {
                op(&mut c.current);
                if !o.version_id.is_empty() {
                    op(&mut c.current_v);
                }
            }
            EntryKind::Version => op(&mut c.versions),
        }
    }

    /// Replace all counters with a fresh count over `entries`.
    pub fn rebuild<I>(&self, entries: I)
    where
        I: IntoIterator<Item = (MetadataKey, Vec<u8>)>,
    {
        let mut fresh: HashMap<String, Counters> = HashMap::new();
        for (k, v) in entries {
            let (bucket, kind) = if let Some((b, _)) = k.parse_object_meta() {
                (b, EntryKind::Current)
            } else if let Some((b, _, _)) = k.parse_object_version() {
                (b, EntryKind::Version)
            } else {
                continue;
            };
            let Ok(o) = ObjectMeta::decode(&v[..]) else {
                continue;
            };
            if o.is_delete_marker || !self.is_primary(&o) {
                continue;
            }
            let c = fresh.entry(bucket).or_default();
            Self::adjust(c, kind, &o, true);
            c.last_modified = c.last_modified.max(o.modified_at);
        }
        *self.buckets.write() = fresh;
    }

    /// Check the shard availability of every object this OSD owns against
    /// the set of nodes that are up.
    ///
    /// A versioned write stores the current version under both `m:` and
    /// `v:`; it is counted once, from `v:`. `m:` entries count only when
    /// they carry no version id.
    pub fn safety<I>(&self, entries: I, up: &HashSet<Vec<u8>>) -> ObjectSafety
    where
        I: IntoIterator<Item = (MetadataKey, Vec<u8>)>,
    {
        let mut s = ObjectSafety::default();
        for (k, v) in entries {
            let is_current = k.parse_object_meta().is_some();
            if !is_current && k.parse_object_version().is_none() {
                continue;
            }
            let Ok(o) = ObjectMeta::decode(&v[..]) else {
                continue;
            };
            if o.is_delete_marker
                || !self.checks_safety_of(&o, up)
                || (is_current && !o.version_id.is_empty())
            {
                continue;
            }
            s.objects_checked += 1;
            let Some(worst) = worst_stripe(&o, up) else {
                continue;
            };
            if worst.missing > 0 {
                s.objects_degraded += 1;
                s.bytes_degraded += o.size;
            }
            if worst.available <= worst.k {
                s.objects_at_risk += 1;
                s.bytes_at_risk += o.size;
            }
            if worst.available < worst.k {
                s.objects_unreadable += 1;
                s.bytes_unreadable += o.size;
            }
        }
        s
    }

    /// Current usage per bucket, sorted by name.
    #[must_use]
    pub fn snapshot(&self) -> Vec<BucketUsage> {
        let mut out: Vec<BucketUsage> = self
            .buckets
            .read()
            .iter()
            .map(|(b, c)| c.to_proto(b))
            .collect();
        out.sort_by(|a, b| a.bucket.cmp(&b.bucket));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use objectio_proto::metadata::{ShardLocation, StripeMeta};

    const ME: [u8; 16] = [1; 16];
    const OTHER: [u8; 16] = [2; 16];

    /// A 4+2 object of `size` bytes in one stripe, primary on `primary`.
    fn obj(size: u64, primary: [u8; 16], version: &str, modified: u64) -> ObjectMeta {
        let shards = (0..6)
            .map(|p| ShardLocation {
                position: p,
                node_id: if p == 0 {
                    primary.to_vec()
                } else {
                    vec![p as u8 + 10; 16]
                },
                ..Default::default()
            })
            .collect();
        ObjectMeta {
            size,
            version_id: version.to_string(),
            modified_at: modified,
            stripes: vec![StripeMeta {
                ec_k: 4,
                ec_m: 2,
                data_size: size,
                shards,
                ..Default::default()
            }],
            ..Default::default()
        }
    }

    fn only(t: &UsageTracker) -> BucketUsage {
        let s = t.snapshot();
        assert_eq!(s.len(), 1, "{s:?}");
        s.into_iter().next().unwrap()
    }

    #[test]
    fn stored_bytes_include_parity() {
        // 4 MB over 4+2: six 1 MB shards.
        assert_eq!(stored_bytes(&obj(4_000_000, ME, "", 0)), 6_000_000);
        // Shards round up: 5 bytes over k=4 is four 2-byte data shards.
        assert_eq!(stored_bytes(&obj(5, ME, "", 0)), 12);
        assert_eq!(stored_bytes(&ObjectMeta::default()), 0);
    }

    /// The same ObjectMeta lands on all six shard holders. Only the primary
    /// may count it, or a cluster-wide sum is six times too big.
    #[test]
    fn only_the_primary_counts_an_object() {
        let t = UsageTracker::new(ME);
        t.apply("b", EntryKind::Current, None, Some(&obj(100, OTHER, "", 1)));
        assert!(t.snapshot().is_empty());
        t.apply("b", EntryKind::Current, None, Some(&obj(100, ME, "", 1)));
        assert_eq!(only(&t).objects, 1);
    }

    /// A multipart object's stripes sit wherever its parts were placed, so
    /// shard 0 of stripe 0 may be a node that never received the
    /// ObjectMeta. The gateway-chosen `usage_owner` wins over the stripes.
    #[test]
    fn usage_owner_overrides_the_stripe_primary() {
        let t = UsageTracker::new(ME);
        let mut o = obj(100, OTHER, "", 1);
        o.usage_owner = ME.to_vec();
        t.apply("b", EntryKind::Current, None, Some(&o));
        assert_eq!(only(&t).objects, 1);

        let t = UsageTracker::new(ME);
        let mut o = obj(100, ME, "", 1);
        o.usage_owner = OTHER.to_vec();
        t.apply("b", EntryKind::Current, None, Some(&o));
        assert!(t.snapshot().is_empty());
    }

    #[test]
    fn overwrite_replaces_rather_than_adds() {
        let t = UsageTracker::new(ME);
        let v1 = obj(100, ME, "", 1);
        let v2 = obj(40, ME, "", 2);
        t.apply("b", EntryKind::Current, None, Some(&v1));
        t.apply("b", EntryKind::Current, Some(&v1), Some(&v2));
        let u = only(&t);
        assert_eq!((u.objects, u.logical_bytes, u.last_modified), (1, 40, 2));
    }

    #[test]
    fn delete_returns_counts_to_zero() {
        let t = UsageTracker::new(ME);
        let o = obj(100, ME, "", 1);
        t.apply("b", EntryKind::Current, None, Some(&o));
        t.apply("b", EntryKind::Current, Some(&o), None);
        let u = only(&t);
        assert_eq!((u.objects, u.logical_bytes, u.stored_bytes), (0, 0, 0));
    }

    /// Versioned PUT writes the same meta under `m:` and `v:`. The current
    /// version must not also show up as noncurrent, and superseded versions
    /// must still count toward stored bytes.
    #[test]
    fn versions_are_split_into_current_and_noncurrent() {
        let t = UsageTracker::new(ME);
        let a = obj(100, ME, "va", 1);
        let b = obj(40, ME, "vb", 2);
        for (old, new) in [(None, &a), (Some(&a), &b)] {
            t.apply("b", EntryKind::Current, old, Some(new));
            t.apply("b", EntryKind::Version, None, Some(new));
        }
        let u = only(&t);
        assert_eq!(u.objects, 1);
        assert_eq!(u.logical_bytes, 40);
        assert_eq!(u.noncurrent_versions, 1);
        assert_eq!(u.noncurrent_bytes, 100);
        assert_eq!(u.stored_bytes, stored_bytes(&a) + stored_bytes(&b));
    }

    /// A versioned delete replaces the current entry with a marker: the
    /// object stops counting as current and its data becomes noncurrent.
    #[test]
    fn delete_marker_makes_the_version_noncurrent() {
        let t = UsageTracker::new(ME);
        let a = obj(100, ME, "va", 1);
        t.apply("b", EntryKind::Current, None, Some(&a));
        t.apply("b", EntryKind::Version, None, Some(&a));
        let marker = ObjectMeta {
            is_delete_marker: true,
            version_id: "vm".into(),
            modified_at: 5,
            ..Default::default()
        };
        t.apply("b", EntryKind::Current, Some(&a), Some(&marker));
        let u = only(&t);
        assert_eq!((u.objects, u.noncurrent_versions), (0, 1));
        assert_eq!(u.noncurrent_bytes, 100);
        assert_eq!(u.last_modified, 5);
    }

    fn up(nodes: &[[u8; 16]]) -> HashSet<Vec<u8>> {
        nodes.iter().map(|n| n.to_vec()).collect()
    }

    /// `obj` places shards on ME (pos 0) and nodes 11..=15 (pos 1..=5).
    fn shard_nodes(skip: usize) -> Vec<[u8; 16]> {
        let mut v = vec![ME];
        v.extend((1..6u8).map(|p| [p + 10; 16]));
        v.truncate(6 - skip);
        v
    }

    #[test]
    fn safety_counts_are_nested_by_how_many_shards_are_reachable() {
        let t = UsageTracker::new(ME);
        let o = obj(100, ME, "", 1);
        let entries = || vec![(MetadataKey::object_meta("b", "k"), o.encode_to_vec())];

        let all = t.safety(entries(), &up(&shard_nodes(0)));
        assert_eq!((all.objects_checked, all.objects_degraded), (1, 0));

        // 4+2 with one shard gone: degraded, still k+1 left.
        let one = t.safety(entries(), &up(&shard_nodes(1)));
        assert_eq!((one.objects_degraded, one.objects_at_risk), (1, 0));

        // Two gone: exactly k left — one more loss makes it unreadable.
        let two = t.safety(entries(), &up(&shard_nodes(2)));
        assert_eq!((two.objects_at_risk, two.objects_unreadable), (1, 0));
        assert_eq!(two.bytes_at_risk, 100);

        let three = t.safety(entries(), &up(&shard_nodes(3)));
        assert_eq!(
            (
                three.objects_degraded,
                three.objects_at_risk,
                three.objects_unreadable
            ),
            (1, 1, 1)
        );
    }

    /// The current version of a versioned object is stored twice; it must
    /// be checked once. Objects owned elsewhere are not checked here.
    /// Objects whose owner is down are reported by the first reachable
    /// shard holder instead of by nobody.
    #[test]
    fn safety_covers_objects_whose_owner_is_down() {
        let owner_down = obj(100, OTHER, "", 1);
        let mut up_set = up(&shard_nodes(0));
        up_set.remove(OTHER.as_slice());
        // Shard 0 is on OTHER (down); shard 1 is on node 11.
        let t = UsageTracker::new([11; 16]);
        let s = t.safety(
            vec![(
                MetadataKey::object_meta("b", "k"),
                owner_down.encode_to_vec(),
            )],
            &up_set,
        );
        assert_eq!((s.objects_checked, s.objects_degraded), (1, 1));
        // …and only it: node 12 does not also report it.
        let t = UsageTracker::new([12; 16]);
        let s = t.safety(
            vec![(
                MetadataKey::object_meta("b", "k"),
                owner_down.encode_to_vec(),
            )],
            &up_set,
        );
        assert_eq!(s.objects_checked, 0);
    }

    #[test]
    fn safety_checks_each_version_once_and_only_owned_objects() {
        let t = UsageTracker::new(ME);
        let a = obj(100, ME, "va", 1);
        let foreign = obj(100, OTHER, "", 1);
        let s = t.safety(
            vec![
                (MetadataKey::object_meta("b", "k"), a.encode_to_vec()),
                (
                    MetadataKey::object_version("b", "k", "va"),
                    a.encode_to_vec(),
                ),
                (MetadataKey::object_meta("b", "x"), foreign.encode_to_vec()),
            ],
            &up(&shard_nodes(0)),
        );
        assert_eq!(s.objects_checked, 1);
    }

    #[test]
    fn rebuild_matches_incremental() {
        let t = UsageTracker::new(ME);
        let a = obj(100, ME, "va", 1);
        let b = obj(40, ME, "vb", 2);
        let foreign = obj(999, OTHER, "", 3);
        let enc = |o: &ObjectMeta| o.encode_to_vec();
        t.rebuild(vec![
            (MetadataKey::object_meta("b", "k"), enc(&b)),
            (MetadataKey::object_version("b", "k", "va"), enc(&a)),
            (MetadataKey::object_version("b", "k", "vb"), enc(&b)),
            (MetadataKey::object_meta("b", "x"), enc(&foreign)),
        ]);
        let rebuilt = only(&t);

        let t2 = UsageTracker::new(ME);
        for (old, new) in [(None, &a), (Some(&a), &b)] {
            t2.apply("b", EntryKind::Current, old, Some(new));
            t2.apply("b", EntryKind::Version, None, Some(new));
        }
        assert_eq!(rebuilt, only(&t2));
    }
}
