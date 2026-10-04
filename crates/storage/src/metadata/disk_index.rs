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

    /// The entries under `prefix` after `after`, as they are now.
    fn range(&self, prefix: &[u8], after: Option<&[u8]>) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        let start = after.map_or(Bound::Included(prefix), Bound::Excluded);
        self.map
            .read()
            .range::<[u8], _>((start, Bound::Unbounded))
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
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

impl DiskIndex {
    /// Open the index file at `path`, creating it if there is none, with a
    /// page cache of at most `cache_bytes`.
    pub fn open(path: &Path, cache_bytes: usize) -> Result<Self> {
        let db = Database::builder()
            .set_cache_size(cache_bytes)
            .create(path)
            .map_err(storage_err("open"))?;
        let tx = db.begin_write().map_err(storage_err("open"))?;
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
    /// the memtables' share of the range, whatever the size of the range.
    pub fn for_each_prefix(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
        mut f: impl FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<()> {
        let (active, frozen) = self.memtables();
        let mut overlay: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
        if let Some(frozen) = &frozen {
            overlay.extend(frozen.range(prefix, after));
        }
        overlay.extend(active.range(prefix, after));

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
        let tx = self.db.begin_write().map_err(storage_err("checkpoint"))?;
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
}
