//! The OSD's metadata index (objectio-docs `core/storage-engine.md`,
//! "Memory, and the index on disk"): recent changes in a memtable, the rest
//! in a B-tree file (redb) whose page cache is bounded. Memory does not grow
//! with the number of entries.
//!
//! The WAL in front of it is the durability boundary: a change is in the
//! WAL (synced) before it is applied here, and the WAL is cut only through
//! the LSN a checkpoint has made durable in the file.

use super::types::{MetadataEntry, MetadataKey};
use objectio_common::{Error, Result};
use parking_lot::RwLock;
use redb::{Database, ReadableTableMetadata, TableDefinition};
use std::collections::BTreeMap;
use std::ops::Bound;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const ENTRIES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("entries");
const STATE: TableDefinition<&str, u64> = TableDefinition::new("state");
/// The LSN through which the file holds every change.
const CHECKPOINT_LSN: &str = "checkpoint_lsn";

fn storage_err<E: Into<redb::Error>>(what: &str) -> impl Fn(E) -> Error + '_ {
    move |e| Error::Storage(format!("metadata index: {what}: {}", e.into()))
}

/// An entry of a memtable: its key and value, `None` for a delete.
type Change = (Vec<u8>, Option<Vec<u8>>);

/// Changes not yet in the file; `None` is a delete.
#[derive(Default)]
struct Memtable {
    map: RwLock<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
    bytes: AtomicUsize,
}

impl Memtable {
    fn set(&self, key: Vec<u8>, value: Option<Vec<u8>>) {
        let size = key.len() + value.as_ref().map_or(0, Vec::len) + 64;
        self.map.write().insert(key, value);
        self.bytes.fetch_add(size, Ordering::Relaxed);
    }

    /// Up to `limit` of the entries under `prefix` after `after`, as they
    /// are now; and whether they are all of them.
    fn range(&self, prefix: &[u8], after: Option<&[u8]>, limit: usize) -> (Vec<Change>, bool) {
        let start = after.map_or(Bound::Included(prefix), Bound::Excluded);
        let map = self.map.read();
        let mut range = map
            .range::<[u8], _>((start, Bound::Unbounded))
            .take_while(|(k, _)| k.starts_with(prefix));
        let out: Vec<_> = range
            .by_ref()
            .take(limit)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let all = out.len() < limit || range.next().is_none();
        (out, all)
    }
}

/// The memtables' entries under a prefix, in key order, the active one's
/// over the frozen one's, copied a window at a time. A scan reads them
/// beside the file; copying the whole range up front cost each call the
/// memtables' share of everything after its start, so a large prefix read
/// a page per call (`iter_prefix`) cost pages × memtable: 16 s to read the
/// object metadata of an OSD of a million shards at start, with the WAL's
/// tail in the memtable.
struct Overlay<'a> {
    /// Frozen first, then active: a later one's entry replaces an earlier's.
    tables: Vec<Arc<Memtable>>,
    prefix: &'a [u8],
    /// Where the next window starts (after this key).
    after: Option<Vec<u8>>,
    window: std::vec::IntoIter<Change>,
    /// Every entry has been in a window.
    done: bool,
}

impl<'a> Overlay<'a> {
    const WINDOW: usize = 1024;

    fn new(tables: Vec<Arc<Memtable>>, prefix: &'a [u8], after: Option<&[u8]>) -> Self {
        Self {
            tables,
            prefix,
            after: after.map(<[u8]>::to_vec),
            window: Vec::new().into_iter(),
            done: false,
        }
    }

    /// The next window: each memtable's next entries, up to the first key
    /// past which one of them was cut short (each holds all of its own
    /// entries up to there).
    fn fill(&mut self) {
        let mut merged: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        let mut upto: Option<Vec<u8>> = None;
        for t in &self.tables {
            let (entries, all) = t.range(self.prefix, self.after.as_deref(), Self::WINDOW);
            if !all
                && let Some((last, _)) = entries.last()
                && upto.as_ref().is_none_or(|u| last < u)
            {
                upto = Some(last.clone());
            }
            merged.extend(entries);
        }
        if let Some(upto) = &upto {
            // Keep the keys through `upto`; the rest come in a later window.
            let mut later = merged.split_off(upto);
            if let Some(v) = later.remove(upto) {
                merged.insert(upto.clone(), v);
            }
        }
        self.done = upto.is_none();
        self.after = upto;
        self.window = merged.into_iter().collect::<Vec<_>>().into_iter();
    }
}

impl Iterator for Overlay<'_> {
    type Item = Change;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(e) = self.window.next() {
                return Some(e);
            }
            if self.done {
                return None;
            }
            self.fill();
        }
    }
}

struct Tables {
    active: Arc<Memtable>,
    /// Being written to the file by a checkpoint; read until it is in.
    frozen: Option<Arc<Memtable>>,
}

pub struct DiskIndex {
    db: Database,
    tables: RwLock<Tables>,
}

/// Make sure a redb database file exists at `path`, created whole: redb
/// writes a new file's header and first pages in place, so a process killed
/// while creating one (a restart a moment after a first start) left a file
/// that never opened again ("invalid data"). It is created under another
/// name, made durable, then renamed into place: there is a whole database
/// at `path`, or none, and a leftover from an interrupted creation is
/// thrown away. An existing file is left as it is.
fn create_whole(path: &Path) -> std::io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    let mut new = path.as_os_str().to_owned();
    new.push(".new");
    let new = std::path::PathBuf::from(new);
    let _ = std::fs::remove_file(&new);
    drop(redb::Database::create(&new).map_err(std::io::Error::other)?);
    std::fs::File::open(&new)?.sync_all()?;
    std::fs::rename(&new, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

impl DiskIndex {
    /// Open the index file at `path`, creating it if there is none, with a
    /// page cache of at most `cache_bytes`.
    pub fn open(path: &Path, cache_bytes: usize) -> Result<Self> {
        create_whole(path).map_err(storage_err("create"))?;
        let db = Database::builder()
            .set_cache_size(cache_bytes)
            .create(path)
            .map_err(storage_err("open"))?;
        let mut tx = db.begin_write().map_err(storage_err("open"))?;
        tx.set_quick_repair(true);
        {
            tx.open_table(ENTRIES).map_err(storage_err("open"))?;
            tx.open_table(STATE).map_err(storage_err("open"))?;
        }
        tx.commit().map_err(storage_err("open"))?;
        Ok(Self {
            db,
            tables: RwLock::new(Tables {
                active: Arc::default(),
                frozen: None,
            }),
        })
    }

    /// The LSN through which the file holds every change: replay the WAL
    /// from the one after.
    pub fn checkpoint_lsn(&self) -> Result<u64> {
        let tx = self.db.begin_read().map_err(storage_err("read"))?;
        let state = tx.open_table(STATE).map_err(storage_err("read"))?;
        Ok(state
            .get(CHECKPOINT_LSN)
            .map_err(storage_err("read"))?
            .map_or(0, |v| v.value()))
    }

    pub fn put(&self, key: Vec<u8>, value: Vec<u8>) {
        self.tables.read().active.set(key, Some(value));
    }

    pub fn delete(&self, key: Vec<u8>) {
        self.tables.read().active.set(key, None);
    }

    /// Apply a change replayed from the WAL.
    pub fn apply_entry(&self, entry: MetadataEntry) {
        if entry.deleted {
            self.delete(entry.key.0);
        } else {
            self.put(entry.key.0, entry.value);
        }
    }

    /// Bytes in the memtable a checkpoint would write next.
    pub fn memtable_bytes(&self) -> usize {
        self.tables.read().active.bytes.load(Ordering::Relaxed)
    }

    fn memtables(&self) -> (Arc<Memtable>, Option<Arc<Memtable>>) {
        let t = self.tables.read();
        (Arc::clone(&t.active), t.frozen.clone())
    }

    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // Memtables first, newest first. Their handles are taken before the
        // file is read: a checkpoint commits to the file before it lets go
        // of the frozen memtable, so nothing falls between.
        let (active, frozen) = self.memtables();
        if let Some(v) = active.map.read().get(key) {
            return Ok(v.clone());
        }
        if let Some(v) = frozen.as_ref().and_then(|f| f.map.read().get(key).cloned()) {
            return Ok(v);
        }
        let tx = self.db.begin_read().map_err(storage_err("read"))?;
        let entries = tx.open_table(ENTRIES).map_err(storage_err("read"))?;
        Ok(entries
            .get(key)
            .map_err(storage_err("read"))?
            .map(|v| v.value().to_vec()))
    }

    /// Call `f` on each entry under `prefix`, in key order, starting after
    /// `after` (or at the prefix), until `f` returns false. Memory stays at
    /// a window of the memtables ([`Overlay`]), whatever the size of the
    /// range.
    pub fn for_each_prefix(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        mut f: impl FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<()> {
        let (active, frozen) = self.memtables();
        let overlay = Overlay::new(frozen.into_iter().chain([active]).collect(), prefix, after);

        let tx = self.db.begin_read().map_err(storage_err("scan"))?;
        let entries = tx.open_table(ENTRIES).map_err(storage_err("scan"))?;
        let start = after.map_or(Bound::Included(prefix), Bound::Excluded);
        let mut file = entries
            .range::<&[u8]>((start, Bound::Unbounded))
            .map_err(storage_err("scan"))?
            .map_while(|r| r.ok())
            .take_while(|(k, _)| k.value().starts_with(prefix))
            .peekable();
        let mut mem = overlay.into_iter().peekable();
        loop {
            let take_mem = match (file.peek(), mem.peek()) {
                (None, None) => return Ok(()),
                (Some(_), None) => false,
                (None, Some(_)) => true,
                (Some((fk, _)), Some((mk, _))) => mk.as_slice() <= fk.value(),
            };
            if take_mem {
                let (k, v) = mem.next().expect("peeked");
                // The memtable's entry replaces the file's.
                if file
                    .peek()
                    .is_some_and(|(fk, _)| fk.value() == k.as_slice())
                {
                    file.next();
                }
                if let Some(v) = v
                    && !f(&k, &v)
                {
                    return Ok(());
                }
            } else {
                let (k, v) = file.next().expect("peeked");
                if !f(k.value(), v.value()) {
                    return Ok(());
                }
            }
        }
    }

    /// The index as it is now, for reading while writes go on: the file
    /// through a read transaction (redb keeps what it sees), the memtables
    /// copied. Taken with the memtables locked, so no change is half in.
    ///
    /// # Errors
    /// The file could not be read.
    pub fn snapshot(&self) -> Result<Snapshot> {
        let t = self.tables.write();
        let mut mem: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        if let Some(frozen) = &t.frozen {
            mem.extend(
                frozen
                    .map
                    .read()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone())),
            );
        }
        mem.extend(
            t.active
                .map
                .read()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        let tx = self.db.begin_read().map_err(storage_err("snapshot"))?;
        let entries = tx.open_table(ENTRIES).map_err(storage_err("snapshot"))?;
        drop(t);
        Ok(Snapshot { entries, mem })
    }

    /// Every entry under `prefix`, collected: for prefixes known to be small.
    pub fn scan_prefix(&self, prefix: &[u8]) -> Result<Vec<(MetadataKey, Vec<u8>)>> {
        let mut out = Vec::new();
        self.for_each_prefix(prefix, None, |k, v| {
            out.push((MetadataKey::from_bytes(k.to_vec()), v.to_vec()));
            true
        })?;
        Ok(out)
    }

    /// The number of entries. Counts the file and checks each memtable
    /// entry against it: for stats and tests, not a hot path.
    pub fn len(&self) -> Result<u64> {
        let (active, frozen) = self.memtables();
        let mut overlay: BTreeMap<Vec<u8>, bool> = BTreeMap::new();
        for m in frozen.iter().chain(std::iter::once(&active)) {
            for (k, v) in m.map.read().iter() {
                overlay.insert(k.clone(), v.is_some());
            }
        }
        let tx = self.db.begin_read().map_err(storage_err("count"))?;
        let entries = tx.open_table(ENTRIES).map_err(storage_err("count"))?;
        let mut n = entries.len().map_err(storage_err("count"))?;
        for (k, present) in overlay {
            let in_file = entries
                .get(k.as_slice())
                .map_err(storage_err("count"))?
                .is_some();
            match (present, in_file) {
                (true, false) => n += 1,
                (false, true) => n -= 1,
                _ => {}
            }
        }
        Ok(n)
    }

    /// Start a checkpoint: the memtable stops taking changes, a new one
    /// takes them. Call with no change between its WAL append and its
    /// apply (the store's gate held exclusively), so the frozen memtable
    /// holds exactly the changes through the WAL's current LSN. False if a
    /// checkpoint is already under way (its frozen memtable not yet in).
    pub fn freeze(&self) -> bool {
        let mut t = self.tables.write();
        if t.frozen.is_some() {
            return false;
        }
        let full = std::mem::take(&mut t.active);
        t.frozen = Some(full);
        true
    }

    /// Write the frozen memtable to the file, durably, as holding every
    /// change through `lsn`; then let it go. On an error it stays frozen
    /// (and readable), for the next attempt.
    pub fn flush_frozen(&self, lsn: u64) -> Result<()> {
        let Some(frozen) = self.tables.read().frozen.clone() else {
            return Ok(());
        };
        let mut tx = self.db.begin_write().map_err(storage_err("checkpoint"))?;
        // Every commit saves redb's allocator state (quick repair): after a
        // crash or a power cut the file opens at once, instead of redb
        // walking all of it to rebuild that state (18 s for a 1 GB index on
        // a soak VM, and growing with it). It costs each commit an extra
        // flush, and commits here are one a checkpoint.
        tx.set_quick_repair(true);
        {
            let mut entries = tx.open_table(ENTRIES).map_err(storage_err("checkpoint"))?;
            for (k, v) in frozen.map.read().iter() {
                match v {
                    Some(v) => entries.insert(k.as_slice(), v.as_slice()),
                    None => entries.remove(k.as_slice()).map(|_| None),
                }
                .map_err(storage_err("checkpoint"))?;
            }
            let mut state = tx.open_table(STATE).map_err(storage_err("checkpoint"))?;
            state
                .insert(CHECKPOINT_LSN, lsn)
                .map_err(storage_err("checkpoint"))?;
        }
        // Durable (redb's default): the WAL is cut on the strength of it.
        tx.commit().map_err(storage_err("checkpoint"))?;
        self.tables.write().frozen = None;
        Ok(())
    }

    /// Whether a checkpoint's frozen memtable is still waiting to go in.
    pub fn has_frozen(&self) -> bool {
        self.tables.read().frozen.is_some()
    }
}

/// [`DiskIndex::snapshot`]: the file as a read transaction saw it, and the
/// memtables as they were.
pub struct Snapshot {
    entries: redb::ReadOnlyTable<&'static [u8], &'static [u8]>,
    mem: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Snapshot {
    /// Call `f` on each entry under `prefix` in key order, until it returns
    /// false.
    ///
    /// # Errors
    /// The file could not be read.
    pub fn for_each_prefix(
        &self,
        prefix: &[u8],
        mut f: impl FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<()> {
        let mut file = self
            .entries
            .range::<&[u8]>((Bound::Included(prefix), Bound::Unbounded))
            .map_err(storage_err("scan"))?
            .map_while(|r| r.ok())
            .take_while(|(k, _)| k.value().starts_with(prefix))
            .peekable();
        let mut mem = self
            .mem
            .range::<[u8], _>((Bound::Included(prefix), Bound::Unbounded))
            .take_while(|(k, _)| k.starts_with(prefix))
            .peekable();
        loop {
            let take_mem = match (file.peek(), mem.peek()) {
                (None, None) => return Ok(()),
                (Some(_), None) => false,
                (None, Some(_)) => true,
                (Some((fk, _)), Some((mk, _))) => mk.as_slice() <= fk.value(),
            };
            if take_mem {
                let (k, v) = mem.next().expect("peeked");
                if file
                    .peek()
                    .is_some_and(|(fk, _)| fk.value() == k.as_slice())
                {
                    file.next();
                }
                if let Some(v) = v
                    && !f(k, v)
                {
                    return Ok(());
                }
            } else {
                let (k, v) = file.next().expect("peeked");
                if !f(k.value(), v.value()) {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn open(dir: &Path) -> DiskIndex {
        DiskIndex::open(&dir.join("index.redb"), 1 << 20).unwrap()
    }

    fn keys(idx: &DiskIndex, prefix: &[u8], after: Option<&[u8]>) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        idx.for_each_prefix(prefix, after, |k, _| {
            out.push(k.to_vec());
            true
        })
        .unwrap();
        out
    }

    #[test]
    fn reads_see_memtable_frozen_and_file_newest_first() {
        let dir = tempdir().unwrap();
        let idx = open(dir.path());
        idx.put(b"a1".to_vec(), b"old".to_vec());
        idx.put(b"a2".to_vec(), b"gone soon".to_vec());
        assert!(idx.freeze());
        idx.flush_frozen(10).unwrap();
        assert_eq!(idx.checkpoint_lsn().unwrap(), 10);

        idx.put(b"a3".to_vec(), b"frozen".to_vec());
        assert!(idx.freeze());
        idx.put(b"a1".to_vec(), b"new".to_vec());
        idx.delete(b"a2".to_vec());

        assert_eq!(idx.get(b"a1").unwrap(), Some(b"new".to_vec()));
        assert_eq!(idx.get(b"a2").unwrap(), None);
        assert_eq!(idx.get(b"a3").unwrap(), Some(b"frozen".to_vec()));
        assert_eq!(keys(&idx, b"a", None), vec![b"a1".to_vec(), b"a3".to_vec()]);
        assert_eq!(idx.len().unwrap(), 2);

        idx.flush_frozen(20).unwrap();
        assert!(idx.freeze());
        idx.flush_frozen(30).unwrap();
        assert_eq!(idx.get(b"a1").unwrap(), Some(b"new".to_vec()));
        assert_eq!(idx.get(b"a2").unwrap(), None);
        assert_eq!(keys(&idx, b"a", None), vec![b"a1".to_vec(), b"a3".to_vec()]);
        assert_eq!(idx.len().unwrap(), 2);
    }

    #[test]
    fn scans_merge_in_order_start_after_and_stop() {
        let dir = tempdir().unwrap();
        let idx = open(dir.path());
        for i in (0..100u32).step_by(2) {
            idx.put(format!("k{i:03}").into_bytes(), vec![1]);
        }
        idx.put(b"other".to_vec(), vec![1]);
        assert!(idx.freeze());
        idx.flush_frozen(1).unwrap();
        for i in (1..100u32).step_by(2) {
            idx.put(format!("k{i:03}").into_bytes(), vec![2]);
        }
        idx.delete(b"k050".to_vec());

        let all = keys(&idx, b"k", None);
        assert_eq!(all.len(), 99);
        assert!(all.windows(2).all(|w| w[0] < w[1]));
        assert!(!all.contains(&b"k050".to_vec()));

        assert_eq!(
            keys(&idx, b"k", Some(b"k096")),
            vec![b"k097".to_vec(), b"k098".to_vec(), b"k099".to_vec()]
        );

        let mut first = Vec::new();
        idx.for_each_prefix(b"k", None, |k, _| {
            first.push(k.to_vec());
            first.len() < 3
        })
        .unwrap();
        assert_eq!(
            first,
            vec![b"k000".to_vec(), b"k001".to_vec(), b"k002".to_vec()]
        );
    }

    #[test]
    fn scans_across_many_memtable_windows_match_a_model() {
        // File, frozen and active memtables each hold several windows of
        // one prefix, interleaved, with deletes and replacements in each.
        let dir = tempdir().unwrap();
        let idx = open(dir.path());
        let mut model: BTreeMap<Vec<u8>, Vec<u8>> = BTreeMap::new();
        let k = |i: u32| format!("k{i:06}").into_bytes();
        let n = 5 * Overlay::WINDOW as u32;
        for i in (0..n).filter(|i| i % 3 == 0) {
            idx.put(k(i), b"file".to_vec());
            model.insert(k(i), b"file".to_vec());
        }
        assert!(idx.freeze());
        idx.flush_frozen(1).unwrap();
        for i in (0..n).filter(|i| i % 3 == 1 || i % 7 == 0) {
            if i % 5 == 0 {
                idx.delete(k(i));
                model.remove(&k(i));
            } else {
                idx.put(k(i), b"frozen".to_vec());
                model.insert(k(i), b"frozen".to_vec());
            }
        }
        assert!(idx.freeze());
        // The active memtable: few keys early in the prefix, many late.
        for i in (0..n).filter(|i| (i % 3 == 2 && *i > n / 2) || i % 11 == 0) {
            if i % 4 == 0 {
                idx.delete(k(i));
                model.remove(&k(i));
            } else {
                idx.put(k(i), b"active".to_vec());
                model.insert(k(i), b"active".to_vec());
            }
        }
        idx.put(b"l".to_vec(), vec![1]);

        let scan = |after: Option<&[u8]>| {
            let mut out = Vec::new();
            idx.for_each_prefix(b"k", after, |k, v| {
                out.push((k.to_vec(), v.to_vec()));
                true
            })
            .unwrap();
            out
        };
        let all: Vec<_> = model.clone().into_iter().collect();
        assert_eq!(scan(None), all);
        let after = k(n / 3);
        let rest: Vec<_> = model
            .range::<Vec<u8>, _>((Bound::Excluded(after.clone()), Bound::Unbounded))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        assert_eq!(scan(Some(&after)), rest);
    }

    #[test]
    fn a_snapshot_sees_the_index_as_it_was_through_checkpoints() {
        let dir = tempdir().unwrap();
        let idx = open(dir.path());
        let k = |i: u32| format!("k{i:04}").into_bytes();
        for i in 0..300 {
            idx.put(k(i), b"file".to_vec());
        }
        assert!(idx.freeze());
        idx.flush_frozen(1).unwrap();
        for i in 100..200 {
            idx.put(k(i), b"frozen".to_vec());
        }
        assert!(idx.freeze());
        for i in 150..250 {
            idx.put(k(i), b"active".to_vec());
        }
        idx.delete(k(10));
        let snap = idx.snapshot().unwrap();
        let expect = |i: u32| -> Option<&[u8]> {
            match i {
                10 => None,
                150..250 => Some(b"active"),
                100..150 => Some(b"frozen"),
                _ => Some(b"file"),
            }
        };

        // After it: writes, deletes, and both checkpoints taken into the file.
        for i in 0..300 {
            if i % 2 == 0 {
                idx.put(k(i), b"later".to_vec());
            } else {
                idx.delete(k(i));
            }
        }
        idx.put(k(400), b"later".to_vec());
        idx.flush_frozen(2).unwrap();
        assert!(idx.freeze());
        idx.flush_frozen(3).unwrap();

        let mut got = Vec::new();
        snap.for_each_prefix(b"k", |k, v| {
            got.push((k.to_vec(), v.to_vec()));
            true
        })
        .unwrap();
        let want: Vec<_> = (0..300)
            .filter_map(|i| expect(i).map(|v| (k(i), v.to_vec())))
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn a_reopened_file_has_what_was_checkpointed() {
        let dir = tempdir().unwrap();
        {
            let idx = open(dir.path());
            idx.put(b"x".to_vec(), b"1".to_vec());
            assert!(idx.freeze());
            idx.flush_frozen(7).unwrap();
            idx.put(b"y".to_vec(), b"not checkpointed".to_vec());
        }
        let idx = open(dir.path());
        assert_eq!(idx.checkpoint_lsn().unwrap(), 7);
        assert_eq!(idx.get(b"x").unwrap(), Some(b"1".to_vec()));
        assert_eq!(idx.get(b"y").unwrap(), None);
    }

    #[test]
    fn after_a_crash_the_file_opens_without_a_full_repair() {
        let dir = tempdir().unwrap();
        let idx = open(dir.path());
        for i in 0..1000u32 {
            idx.put(i.to_be_bytes().to_vec(), vec![1; 100]);
        }
        assert!(idx.freeze());
        idx.flush_frozen(1).unwrap();
        // A crash: the file as it is while open, never closed.
        let crashed = dir.path().join("crashed.redb");
        std::fs::copy(dir.path().join("index.redb"), &crashed).unwrap();
        drop(idx);
        let repaired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let r = repaired.clone();
        let db = Database::builder()
            .set_repair_callback(move |_| r.store(true, std::sync::atomic::Ordering::Relaxed))
            .create(&crashed)
            .unwrap();
        drop(db);
        assert!(
            !repaired.load(std::sync::atomic::Ordering::Relaxed),
            "a full repair ran"
        );
        let idx = DiskIndex::open(&crashed, 1 << 20).unwrap();
        assert_eq!(idx.checkpoint_lsn().unwrap(), 1);
        assert_eq!(idx.get(&7u32.to_be_bytes()).unwrap(), Some(vec![1; 100]));
    }
}
