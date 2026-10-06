//! The OSD's metadata store (objectio-docs `core/storage-engine.md`): a
//! WAL, the durability boundary, in front of an index whose recent changes
//! are in memory and the rest on disk ([`DiskIndex`]). Checkpoints write
//! the memtable to the index file and cut the WAL.

use super::disk_index::DiskIndex;
use super::types::{MetadataKey, MetadataOp};
use super::wal::{MetadataWal, WalConfig};
use objectio_common::{Error, Result};
use parking_lot::{Condvar, Mutex, RwLock};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Metadata store configuration
#[derive(Clone, Debug)]
pub struct MetadataStoreConfig {
    /// Base directory for metadata files
    pub data_dir: PathBuf,
    /// WAL configuration
    pub wal: WalConfig,
    /// The index file's page cache, in bytes.
    pub cache_bytes: usize,
    /// A checkpoint is taken when the memtable reaches this many bytes.
    pub memtable_bytes: usize,
    /// Enable background compaction
    pub background_compaction: bool,
    /// How often the checkpoint thread looks, when no write wakes it.
    pub compaction_interval: Duration,
}

impl Default for MetadataStoreConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./metadata"),
            wal: WalConfig::default(),
            cache_bytes: 1 << 30,
            memtable_bytes: 64 << 20,
            background_compaction: true,
            compaction_interval: Duration::from_secs(60),
        }
    }
}

impl MetadataStoreConfig {
    /// Create config with data directory
    pub fn with_data_dir(data_dir: impl AsRef<Path>) -> Self {
        Self {
            data_dir: data_dir.as_ref().to_path_buf(),
            ..Default::default()
        }
    }
}

/// An index that can't be read: the OSD stops rather than answer "not
/// there" for what may be there. Its copies are outvoted and repaired.
fn fatal(e: &Error) -> ! {
    error!("metadata index unreadable, stopping: {e}");
    std::process::abort()
}

/// Unified metadata store for OSD
pub struct MetadataStore {
    wal: Arc<MetadataWal>,
    index: Arc<DiskIndex>,
    config: MetadataStoreConfig,
    /// One checkpoint at a time: explicit or background.
    compaction_lock: Arc<Mutex<()>>,
    /// Held shared by every write from its log append to its index update,
    /// and exclusively by a checkpoint to freeze the memtable with nothing
    /// in between ([`checkpoint`]).
    gate: Arc<RwLock<()>>,
    shutdown: Arc<AtomicBool>,
    /// Wakes the checkpoint thread: for shutdown, and when a write fills
    /// the memtable or the WAL.
    signal: Arc<(Mutex<()>, Condvar)>,
    compaction_handle: Mutex<Option<thread::JoinHandle<()>>>,
}

impl MetadataStore {
    /// Create a new metadata store
    pub fn create(config: MetadataStoreConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| Error::Storage(format!("failed to create data dir: {}", e)))?;
        let wal_path = config.data_dir.join("metadata.wal");
        let wal = Arc::new(MetadataWal::create(&wal_path, config.wal.clone())?);
        let index = Arc::new(DiskIndex::open(
            &config.data_dir.join("index.redb"),
            config.cache_bytes,
        )?);
        let store = Self::with(wal, index, config);
        info!("Created new metadata store at {:?}", store.config.data_dir);
        Ok(store)
    }

    /// Open an existing metadata store
    pub fn open(config: MetadataStoreConfig) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .map_err(|e| Error::Storage(format!("failed to create data dir: {}", e)))?;
        let wal_path = config.data_dir.join("metadata.wal");
        let wal = Arc::new(if wal_path.exists() {
            MetadataWal::open(&wal_path, config.wal.clone())?
        } else {
            MetadataWal::create(&wal_path, config.wal.clone())?
        });
        let index = Arc::new(DiskIndex::open(
            &config.data_dir.join("index.redb"),
            config.cache_bytes,
        )?);
        let checkpoint_lsn = index.checkpoint_lsn()?;
        wal.advance_past(checkpoint_lsn);

        info!("Replaying WAL from LSN {}", checkpoint_lsn + 1);
        let mut replayed = 0u64;
        wal.iter_entries(checkpoint_lsn + 1, |entry| {
            index.apply_entry(entry);
            replayed += 1;
            Ok(())
        })?;
        info!("Replayed {replayed} WAL entries");

        let store = Self::with(wal, index, config);
        info!("Opened metadata store at {:?}", store.config.data_dir);
        Ok(store)
    }

    fn with(wal: Arc<MetadataWal>, index: Arc<DiskIndex>, config: MetadataStoreConfig) -> Self {
        let store = Self {
            wal,
            index,
            config,
            compaction_lock: Arc::new(Mutex::new(())),
            gate: Arc::new(RwLock::new(())),
            shutdown: Arc::new(AtomicBool::new(false)),
            signal: Arc::new((Mutex::new(()), Condvar::new())),
            compaction_handle: Mutex::new(None),
        };
        if store.config.background_compaction {
            store.start_background_compaction();
        }
        store
    }

    /// Open or create a metadata store
    pub fn open_or_create(config: MetadataStoreConfig) -> Result<Self> {
        if config.data_dir.join("metadata.wal").exists()
            || config.data_dir.join("index.redb").exists()
        {
            Self::open(config)
        } else {
            Self::create(config)
        }
    }

    /// Wake the checkpoint thread if this write filled the memtable or WAL.
    fn after_write(&self) {
        if checkpoint_due(&self.wal, &self.index, &self.config) {
            let (lock, cv) = &*self.signal;
            let _g = lock.lock();
            cv.notify_all();
        }
    }

    /// Put a key-value pair
    pub fn put(&self, key: MetadataKey, value: Vec<u8>) -> Result<u64> {
        let op = MetadataOp::Put {
            key: key.clone(),
            value: value.clone(),
        };
        let lsn = {
            let _applying = self.gate.read();
            let lsn = self.wal.append(&op)?;
            self.index.put(key.0, value);
            lsn
        };
        self.after_write();
        debug!("put: lsn={}", lsn);
        Ok(lsn)
    }

    /// Delete a key
    pub fn delete(&self, key: &MetadataKey) -> Result<u64> {
        let op = MetadataOp::Delete { key: key.clone() };
        let lsn = {
            let _applying = self.gate.read();
            let lsn = self.wal.append(&op)?;
            self.index.delete(key.0.clone());
            lsn
        };
        self.after_write();
        debug!("delete: lsn={}", lsn);
        Ok(lsn)
    }

    /// Get a value by key
    pub fn get(&self, key: &MetadataKey) -> Option<Vec<u8>> {
        self.index.get(&key.0).unwrap_or_else(|e| fatal(&e))
    }

    /// Check if a key exists
    pub fn contains(&self, key: &MetadataKey) -> bool {
        self.get(key).is_some()
    }

    /// Apply `ops` (puts and deletes, in order) in one WAL record: durable
    /// and all or nothing.
    pub fn write(&self, ops: Vec<MetadataOp>) -> Result<u64> {
        if ops.is_empty() {
            return Ok(self.wal.current_lsn());
        }
        let lsn = {
            let _applying = self.gate.read();
            let lsn = self.wal.append_batch(&ops)?;
            for op in ops {
                self.apply(op);
            }
            lsn
        };
        self.after_write();
        Ok(lsn)
    }

    fn apply(&self, op: MetadataOp) {
        match op {
            MetadataOp::Put { key, value } => self.index.put(key.0, value),
            MetadataOp::Delete { key } => self.index.delete(key.0),
            MetadataOp::Batch { ops } => ops.into_iter().for_each(|op| self.apply(op)),
        }
    }

    /// This store's metrics: its WAL's fsyncs and their batching.
    pub fn render_metrics(&self, out: &mut String, labels: &str) {
        use std::fmt::Write;
        let st = self.wal.sync_stats();
        st.seconds.render(
            out,
            "objectio_osd_wal_fsync_seconds",
            "Time for one metadata WAL fdatasync",
            labels,
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
            let _ = writeln!(out, "{name}{{{labels}}} {v}");
        }
    }

    /// Batch write operations
    pub fn batch_put(&self, entries: Vec<(MetadataKey, Vec<u8>)>) -> Result<u64> {
        if entries.is_empty() {
            return Ok(self.wal.current_lsn());
        }
        let ops: Vec<MetadataOp> = entries
            .iter()
            .map(|(k, v)| MetadataOp::Put {
                key: k.clone(),
                value: v.clone(),
            })
            .collect();
        let lsn = {
            let _applying = self.gate.read();
            let lsn = self.wal.append_batch(&ops)?;
            for (key, value) in entries {
                self.index.put(key.0, value);
            }
            lsn
        };
        self.after_write();
        debug!("batch_put: {} entries, lsn={}", ops.len(), lsn);
        Ok(lsn)
    }

    /// Delete many keys with one WAL record.
    pub fn batch_delete(&self, keys: &[MetadataKey]) -> Result<u64> {
        if keys.is_empty() {
            return Ok(self.wal.current_lsn());
        }
        let ops: Vec<MetadataOp> = keys
            .iter()
            .map(|k| MetadataOp::Delete { key: k.clone() })
            .collect();
        let lsn = {
            let _applying = self.gate.read();
            let lsn = self.wal.append_batch(&ops)?;
            for key in keys {
                self.index.delete(key.0.clone());
            }
            lsn
        };
        self.after_write();
        debug!("batch_delete: {} entries, lsn={}", keys.len(), lsn);
        Ok(lsn)
    }

    /// Every entry with a key prefix, collected: for prefixes known to be
    /// small (one key's versions). Large ones go through
    /// [`Self::for_each_prefix`].
    pub fn scan_prefix(&self, prefix: &MetadataKey) -> Vec<(MetadataKey, Vec<u8>)> {
        self.index
            .scan_prefix(&prefix.0)
            .unwrap_or_else(|e| fatal(&e))
    }

    /// Call `f` on each entry under `prefix` in key order, from after
    /// `after` (or the start), until it returns false; memory stays flat
    /// however many entries the prefix has.
    pub fn for_each_prefix(
        &self,
        prefix: &MetadataKey,
        after: Option<&MetadataKey>,
        f: impl FnMut(&[u8], &[u8]) -> bool,
    ) {
        self.index
            .for_each_prefix(&prefix.0, after.map(|a| a.0.as_slice()), f)
            .unwrap_or_else(|e| fatal(&e));
    }

    /// Take a checkpoint now: the memtable into the index file, the WAL cut.
    pub fn checkpoint(&self) -> Result<()> {
        let _one = self.compaction_lock.lock();
        checkpoint(&self.wal, &self.index, &self.gate)
    }

    /// Take a checkpoint if one is due.
    pub fn maybe_compact(&self) -> Result<bool> {
        if self.needs_compaction() {
            self.checkpoint()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Whether a checkpoint is due.
    pub fn needs_compaction(&self) -> bool {
        checkpoint_due(&self.wal, &self.index, &self.config)
    }

    /// Start background compaction thread
    fn start_background_compaction(&self) {
        let wal = Arc::clone(&self.wal);
        let index = Arc::clone(&self.index);
        let shutdown = Arc::clone(&self.shutdown);
        let signal = Arc::clone(&self.signal);
        let interval = self.config.compaction_interval;
        let gate = Arc::clone(&self.gate);
        let compaction_lock = Arc::clone(&self.compaction_lock);
        let config = self.config.clone();

        let handle = thread::spawn(move || {
            info!("Background checkpoint thread started");
            while !shutdown.load(Ordering::Relaxed) {
                // A condvar, not a sleep: shutdown and full memtables wake
                // it (a sleep made shutdown wait out the interval, past
                // Kubernetes' grace period).
                {
                    let (lock, cv) = &*signal;
                    let mut guard = lock.lock();
                    if !shutdown.load(Ordering::Relaxed) && !checkpoint_due(&wal, &index, &config) {
                        cv.wait_for(&mut guard, interval);
                    }
                }
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                if checkpoint_due(&wal, &index, &config) {
                    let _one = compaction_lock.lock();
                    match checkpoint(&wal, &index, &gate) {
                        Ok(()) => debug!("checkpoint done"),
                        Err(e) => {
                            error!("checkpoint failed: {}", e);
                            thread::sleep(Duration::from_secs(1));
                        }
                    }
                }
            }
            info!("Background checkpoint thread stopped");
        });

        *self.compaction_handle.lock() = Some(handle);
    }

    /// Stop background compaction and shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
        {
            let (lock, cv) = &*self.signal;
            let guard = lock.lock();
            cv.notify_all();
            drop(guard);
        }
        if let Some(handle) = self.compaction_handle.lock().take() {
            let _ = handle.join();
        }
        if let Err(e) = self.wal.sync() {
            error!("Failed to sync WAL on shutdown: {}", e);
        }
    }

    /// Sync WAL to disk
    pub fn sync(&self) -> Result<()> {
        self.wal.sync()
    }

    /// Get current LSN
    pub fn current_lsn(&self) -> u64 {
        self.wal.current_lsn()
    }

    /// The number of entries (counts the index file: not for hot paths).
    pub fn len(&self) -> u64 {
        self.index.len().unwrap_or_else(|e| fatal(&e))
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// WAL fsync statistics for metrics.
    pub fn wal_sync_stats(&self) -> &super::wal::WalSyncStats {
        self.wal.sync_stats()
    }

    pub fn stats(&self) -> MetadataStoreStats {
        MetadataStoreStats {
            wal_size: self.wal.size(),
            wal_lsn: self.wal.current_lsn(),
            memtable_bytes: self.index.memtable_bytes() as u64,
        }
    }
}

/// Whether to checkpoint now: the memtable is full, or the WAL past its
/// limit, or a frozen memtable failed to go in and waits.
fn checkpoint_due(wal: &MetadataWal, index: &DiskIndex, config: &MetadataStoreConfig) -> bool {
    index.memtable_bytes() >= config.memtable_bytes || wal.needs_compaction() || index.has_frozen()
}

/// Write the memtable to the index file and drop the WAL records it holds.
///
/// The file must hold every record up to the LSN it is labelled with, or
/// the WAL is cut past one it lacks and that write, acknowledged, is gone
/// at the next restart. Writers hold `gate` shared from append to apply, so
/// with it held exclusively the memtable holds every record through the
/// WAL's mark. The WAL is cut only once the file is durable; a failure in
/// between leaves both, and the next restart replays what the file already
/// has (replaying a record twice is harmless: puts and deletes by key).
fn checkpoint(wal: &MetadataWal, index: &DiskIndex, gate: &RwLock<()>) -> Result<()> {
    // A frozen memtable left by a failed checkpoint goes first, with the
    // WAL left whole (its mark is gone): the next freeze's mark is later
    // and covers it.
    if index.has_frozen() {
        index.flush_frozen(index.checkpoint_lsn()?)?;
    }
    let mark = {
        let _nothing_in_flight = gate.write();
        let mark = wal.mark()?;
        index.freeze();
        mark
    };
    index.flush_frozen(mark.lsn)?;
    debug!("checkpoint at LSN {}", mark.lsn);
    if let Err(e) = wal.truncate_through(mark) {
        warn!("Failed to truncate WAL: {}", e);
    }
    Ok(())
}

impl Drop for MetadataStore {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Metadata store statistics
#[derive(Debug, Clone)]
pub struct MetadataStoreStats {
    /// WAL size in bytes
    pub wal_size: u64,
    /// Current WAL LSN
    pub wal_lsn: u64,
    /// Bytes in the memtable not yet checkpointed
    pub memtable_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config(dir: &Path) -> MetadataStoreConfig {
        MetadataStoreConfig {
            data_dir: dir.to_path_buf(),
            wal: WalConfig {
                sync_on_write: false, // Faster tests
                max_size_bytes: 1024 * 1024,
                write_buffer_size: 4096,
            },
            cache_bytes: 1 << 20,
            memtable_bytes: 4096,
            background_compaction: false, // Manual for tests
            compaction_interval: Duration::from_secs(1),
        }
    }

    #[test]
    fn test_store_create_and_put_get() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path());

        let store = MetadataStore::create(config).unwrap();

        // Put
        let key = MetadataKey::block(42);
        store.put(key.clone(), b"test value".to_vec()).unwrap();

        // Get
        let value = store.get(&key).unwrap();
        assert_eq!(value, b"test value");
    }

    #[test]
    fn test_store_delete() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path());

        let store = MetadataStore::create(config).unwrap();

        let key = MetadataKey::block(42);
        store.put(key.clone(), b"test value".to_vec()).unwrap();

        store.delete(&key).unwrap();
        assert!(store.get(&key).is_none());
    }

    #[test]
    fn test_store_batch_put() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path());

        let store = MetadataStore::create(config).unwrap();

        let entries: Vec<(MetadataKey, Vec<u8>)> = (1..=10)
            .map(|i| (MetadataKey::block(i), format!("value_{}", i).into_bytes()))
            .collect();

        store.batch_put(entries).unwrap();

        assert_eq!(store.len(), 10);
        assert_eq!(store.get(&MetadataKey::block(5)), Some(b"value_5".to_vec()));
    }

    /// What an OSD restart does with the ObjectMeta of a multi-GiB object:
    /// a value bigger than the WAL's read buffer. Opening used to hang.
    #[test]
    fn a_store_with_a_large_value_reopens() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path());
        let big = vec![3u8; 512 * 1024];
        {
            let store = MetadataStore::create(config.clone()).unwrap();
            store.put(MetadataKey::block(1), big.clone()).unwrap();
            store.put(MetadataKey::block(2), b"next".to_vec()).unwrap();
            store.sync().unwrap();
        }
        let store = MetadataStore::open(config).unwrap();
        assert_eq!(store.get(&MetadataKey::block(1)), Some(big));
        assert_eq!(store.get(&MetadataKey::block(2)), Some(b"next".to_vec()));
    }

    #[test]
    fn test_store_recovery() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path());

        // Create and populate
        {
            let store = MetadataStore::create(config.clone()).unwrap();

            for i in 1..=50 {
                store
                    .put(MetadataKey::block(i), format!("value_{}", i).into_bytes())
                    .unwrap();
            }

            store.sync().unwrap();
        }

        // Reopen and verify
        {
            let store = MetadataStore::open(config).unwrap();

            assert_eq!(store.len(), 50);

            for i in 1..=50 {
                let value = store.get(&MetadataKey::block(i)).unwrap();
                assert_eq!(value, format!("value_{}", i).into_bytes());
            }
        }
    }

    #[test]
    fn test_store_snapshot_and_recovery() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path());

        // Create, populate, and snapshot
        {
            let store = MetadataStore::create(config.clone()).unwrap();

            for i in 1..=100 {
                store
                    .put(MetadataKey::block(i), format!("value_{}", i).into_bytes())
                    .unwrap();
            }

            // Force snapshot
            store.checkpoint().unwrap();

            // Add more entries after snapshot
            for i in 101..=150 {
                store
                    .put(MetadataKey::block(i), format!("value_{}", i).into_bytes())
                    .unwrap();
            }

            store.sync().unwrap();
        }

        // Reopen and verify (should recover from snapshot + WAL replay)
        {
            let store = MetadataStore::open(config).unwrap();

            assert_eq!(store.len(), 150);

            // Check entries from before snapshot
            assert_eq!(
                store.get(&MetadataKey::block(50)),
                Some(b"value_50".to_vec())
            );

            // Check entries from after snapshot (WAL replay)
            assert_eq!(
                store.get(&MetadataKey::block(125)),
                Some(b"value_125".to_vec())
            );
        }
    }

    /// Writes that land while a snapshot is taken and the log cut must all
    /// be there after a restart. The cut copied the log's tail to a new
    /// file without stopping appends, so a record appended between the copy
    /// and the rename went into the file the rename then dropped.
    #[test]
    fn writes_during_compaction_survive_a_restart() {
        use std::sync::atomic::AtomicU64;
        let dir = tempdir().unwrap();
        let mut config = test_config(dir.path());
        config.wal.sync_on_write = true;
        let written = Arc::new(AtomicU64::new(0));
        {
            let store = Arc::new(MetadataStore::create(config.clone()).unwrap());
            let stop = Arc::new(AtomicBool::new(false));
            let writers: Vec<_> = (0..4u64)
                .map(|w| {
                    let (store, stop, written) =
                        (Arc::clone(&store), Arc::clone(&stop), Arc::clone(&written));
                    thread::spawn(move || {
                        let mut i = 0u64;
                        while !stop.load(Ordering::Relaxed) {
                            store
                                .put(MetadataKey::block(w << 32 | i), vec![1; 64])
                                .unwrap();
                            written.fetch_add(1, Ordering::Relaxed);
                            i += 1;
                        }
                    })
                })
                .collect();
            for _ in 0..30 {
                store.checkpoint().unwrap();
            }
            stop.store(true, Ordering::Relaxed);
            for w in writers {
                w.join().unwrap();
            }
        }
        let store = MetadataStore::open(config).unwrap();
        assert_eq!(store.len(), written.load(Ordering::Relaxed));
    }

    /// A compaction can leave the log empty. Reopened, it must go on from
    /// past the snapshot's LSN: numbered from 1 again, the next records
    /// sat below the snapshot and the replay after it skipped them.
    #[test]
    fn writes_after_an_emptying_compaction_survive_restarts() {
        let dir = tempdir().unwrap();
        let config = test_config(dir.path());
        {
            let store = MetadataStore::create(config.clone()).unwrap();
            for i in 0..10 {
                store.put(MetadataKey::block(i), vec![1]).unwrap();
            }
            store.checkpoint().unwrap();
        }
        {
            let store = MetadataStore::open(config.clone()).unwrap();
            store.put(MetadataKey::block(100), vec![2]).unwrap();
        }
        let store = MetadataStore::open(config).unwrap();
        assert_eq!(store.get(&MetadataKey::block(100)), Some(vec![2]));
        assert_eq!(store.len(), 11);
    }
}

#[cfg(test)]
mod shutdown_tests {
    use super::{MetadataStore, MetadataStoreConfig};
    use std::time::{Duration, Instant};

    /// Shutting down must not wait out the compaction interval.
    ///
    /// The compaction thread slept for the whole interval before looking at
    /// the shutdown flag, and `shutdown()` set the flag and then joined it —
    /// so closing a store took up to `compaction_interval`, 60 seconds by
    /// default. That is past Kubernetes' 30-second default grace period, so a
    /// terminating OSD was killed before the join returned and the WAL sync
    /// that shutdown performs *after* the join never ran.
    #[test]
    fn closing_a_store_does_not_wait_for_the_compaction_interval() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = MetadataStoreConfig::with_data_dir(dir.path());
        config.background_compaction = true;
        config.compaction_interval = Duration::from_secs(600);

        let store = MetadataStore::open_or_create(config).expect("open");
        let started = Instant::now();
        store.shutdown();
        let took = started.elapsed();

        assert!(
            took < Duration::from_secs(5),
            "shutdown took {took:?}; it is waiting out the compaction interval"
        );
    }

    /// Dropping is the path a real process takes, and it must be just as quick.
    #[test]
    fn dropping_a_store_does_not_wait_either() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = MetadataStoreConfig::with_data_dir(dir.path());
        config.background_compaction = true;
        config.compaction_interval = Duration::from_secs(600);

        let store = MetadataStore::open_or_create(config).expect("open");
        let started = Instant::now();
        drop(store);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "drop waited on the compaction thread"
        );
    }

    /// Shutting down twice is not an error — `Drop` runs after an explicit
    /// `shutdown()` on every store that is closed deliberately.
    #[test]
    fn shutting_down_twice_is_harmless() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store =
            MetadataStore::open_or_create(MetadataStoreConfig::with_data_dir(dir.path())).unwrap();
        store.shutdown();
        store.shutdown();
    }
}
