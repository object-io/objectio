//! Metadata Write-Ahead Log
//!
//! Append-only log for metadata operations with:
//! - Sequential LSN assignment
//! - CRC32C checksums per record
//! - Efficient replay from any LSN
//! - Truncation after snapshot
//!
//! Record format:
//! ```text
//! +--------+------+--------+------+--------+
//! | Magic  | LSN  | Length | Data | CRC32C |
//! | 4B     | 8B   | 4B     | var  | 4B     |
//! +--------+------+--------+------+--------+
//! ```

use super::types::{MetadataEntry, MetadataOp};
use objectio_common::{Error, Result};
use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// WAL record magic number
const WAL_MAGIC: u32 = 0x4D57414C; // "MWAL"

/// Record header size (magic + lsn + length)
const RECORD_HEADER_SIZE: usize = 16;

/// Metadata WAL configuration
#[derive(Clone, Debug)]
pub struct WalConfig {
    /// Sync after every write
    pub sync_on_write: bool,
    /// Maximum WAL size before triggering snapshot
    pub max_size_bytes: u64,
    /// Buffer size for writes
    pub write_buffer_size: usize,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            sync_on_write: true,
            max_size_bytes: 64 * 1024 * 1024, // 64MB
            write_buffer_size: 64 * 1024,     // 64KB
        }
    }
}

/// A single WAL record
#[derive(Debug)]
pub struct WalRecord {
    /// Log Sequence Number
    pub lsn: u64,
    /// Serialized operation
    pub data: Vec<u8>,
}

impl WalRecord {
    /// Serialize record to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let total_size = RECORD_HEADER_SIZE + self.data.len() + 4;
        let mut buf = Vec::with_capacity(total_size);

        buf.extend_from_slice(&WAL_MAGIC.to_le_bytes());
        buf.extend_from_slice(&self.lsn.to_le_bytes());
        buf.extend_from_slice(&(self.data.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.data);

        // CRC over everything except the CRC itself
        let crc = crc32c::crc32c(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());

        buf
    }

    /// Parse record from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < RECORD_HEADER_SIZE + 4 {
            return Err(Error::Storage("WAL record too small".into()));
        }

        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != WAL_MAGIC {
            return Err(Error::Storage("invalid WAL magic".into()));
        }

        let lsn = u64::from_le_bytes(data[4..12].try_into().unwrap());
        let data_len = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

        let total_size = RECORD_HEADER_SIZE + data_len + 4;
        if data.len() < total_size {
            return Err(Error::Storage("WAL record truncated".into()));
        }

        let record_data = data[RECORD_HEADER_SIZE..RECORD_HEADER_SIZE + data_len].to_vec();
        let stored_crc = u32::from_le_bytes(
            data[RECORD_HEADER_SIZE + data_len..total_size]
                .try_into()
                .unwrap(),
        );

        // Verify CRC
        let computed_crc = crc32c::crc32c(&data[..RECORD_HEADER_SIZE + data_len]);
        if computed_crc != stored_crc {
            return Err(Error::Storage("WAL record CRC mismatch".into()));
        }

        Ok((
            Self {
                lsn,
                data: record_data,
            },
            total_size,
        ))
    }
}

/// Metadata Write-Ahead Log
pub struct MetadataWal {
    /// WAL file path
    path: PathBuf,
    /// File handle for writing
    writer: Mutex<BufWriter<File>>,
    /// Current file size
    size: AtomicU64,
    /// Next LSN to assign
    next_lsn: AtomicU64,
    /// Configuration
    config: WalConfig,
    /// Highest LSN whose bytes have reached the OS. Written under `writer`,
    /// so it is monotonic and never claims more than was actually handed over.
    written_lsn: AtomicU64,
    /// Highest LSN covered by a completed `fdatasync`.
    synced_lsn: AtomicU64,
    /// Held only across the sync itself — deliberately *not* `writer`, so a
    /// thread waiting to sync does not block one that is still writing.
    sync_lock: Mutex<()>,
    /// Second descriptor for the same file, used to sync without taking
    /// `writer`. `fdatasync` acts on the inode, so syncing through this
    /// durably commits everything written through the other handle.
    sync_handle: File,
}

impl MetadataWal {
    /// Create a new WAL file
    pub fn create(path: impl AsRef<Path>, config: WalConfig) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| Error::Storage(format!("failed to create WAL: {}", e)))?;

        let sync_handle = file
            .try_clone()
            .map_err(|e| Error::Storage(format!("failed to clone WAL handle: {}", e)))?;
        let writer = BufWriter::with_capacity(config.write_buffer_size, file);

        Ok(Self {
            path,
            writer: Mutex::new(writer),
            size: AtomicU64::new(0),
            next_lsn: AtomicU64::new(1),
            config,
            written_lsn: AtomicU64::new(0),
            synced_lsn: AtomicU64::new(0),
            sync_lock: Mutex::new(()),
            sync_handle,
        })
    }

    /// Open an existing WAL file
    pub fn open(path: impl AsRef<Path>, config: WalConfig) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        // First, scan to find the last LSN
        let (last_lsn, file_size) = Self::scan_wal(&path)?;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| Error::Storage(format!("failed to open WAL: {}", e)))?;

        let sync_handle = file
            .try_clone()
            .map_err(|e| Error::Storage(format!("failed to clone WAL handle: {}", e)))?;
        let writer = BufWriter::with_capacity(config.write_buffer_size, file);

        Ok(Self {
            path,
            writer: Mutex::new(writer),
            size: AtomicU64::new(file_size),
            next_lsn: AtomicU64::new(last_lsn + 1),
            config,
            // Everything already on disk is durable by definition.
            written_lsn: AtomicU64::new(last_lsn),
            synced_lsn: AtomicU64::new(last_lsn),
            sync_lock: Mutex::new(()),
            sync_handle,
        })
    }

    /// Scan WAL to find last LSN and file size
    fn scan_wal(path: &Path) -> Result<(u64, u64)> {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok((0, 0));
            }
            Err(e) => {
                return Err(Error::Storage(format!("failed to open WAL: {}", e)));
            }
        };

        let file_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        if file_size == 0 {
            return Ok((0, 0));
        }

        let mut reader = BufReader::new(file);
        let mut buf = vec![0u8; 64 * 1024]; // 64KB read buffer
        let mut last_lsn = 0u64;
        let mut pos = 0u64;

        loop {
            // Read chunk
            let bytes_read = reader.read(&mut buf).unwrap_or(0);
            if bytes_read == 0 {
                break;
            }

            // Parse records from chunk
            let mut offset = 0;
            while offset + RECORD_HEADER_SIZE + 4 <= bytes_read {
                match WalRecord::from_bytes(&buf[offset..bytes_read]) {
                    Ok((record, size)) => {
                        last_lsn = record.lsn;
                        offset += size;
                        pos += size as u64;
                    }
                    Err(_) => {
                        // Partial or corrupted record - stop here
                        break;
                    }
                }
            }

            // If we didn't consume the whole buffer, seek back
            if offset < bytes_read {
                let _ = reader.seek(SeekFrom::Current(-((bytes_read - offset) as i64)));
            }
        }

        Ok((last_lsn, pos))
    }

    /// Append a metadata operation to the WAL.
    ///
    /// Durability is unchanged: this does not return until an `fdatasync`
    /// covering the record has completed. What changed is that concurrent
    /// appends now share one, instead of each paying for its own.
    ///
    /// The sync used to happen while holding `writer`, so N concurrent writers
    /// cost N serialized syncs. On the live cluster that was the dominant
    /// per-PUT cost: object metadata is written to every shard-carrying OSD,
    /// so a 4+2 PUT paid it six times over and write throughput came out flat
    /// at ~85 ops/s regardless of object size — the same shape at ~340 ops/s
    /// with one OSD. Measured on that NVMe, `fdatasync` is 0.75 ms at one
    /// stream and the device sustains ~2400/s across twelve, so the ceiling
    /// was the serialization, not the hardware.
    pub fn append(&self, op: &MetadataOp) -> Result<u64> {
        let data = op.to_bytes();

        let lsn = {
            let mut writer = self.writer.lock();
            // Assigned under the lock so LSN order matches write order, which
            // is what lets `written_lsn` be a watermark rather than a guess.
            let lsn = self.next_lsn.fetch_add(1, Ordering::SeqCst);
            let record = WalRecord { lsn, data };
            let bytes = record.to_bytes();

            writer
                .write_all(&bytes)
                .map_err(|e| Error::Storage(format!("WAL write failed: {}", e)))?;

            if self.config.sync_on_write {
                // Hand the bytes to the OS while still holding the lock, so
                // anything this watermark claims really is syncable.
                writer
                    .flush()
                    .map_err(|e| Error::Storage(format!("WAL flush failed: {}", e)))?;
            }

            self.size.fetch_add(bytes.len() as u64, Ordering::Relaxed);
            self.written_lsn.store(lsn, Ordering::SeqCst);
            lsn
        };

        if self.config.sync_on_write {
            self.sync_through(lsn)?;
        }

        Ok(lsn)
    }

    /// Block until an `fdatasync` covering `lsn` has completed.
    ///
    /// Group commit: the first thread in syncs everything written so far and
    /// publishes how far it got; anyone whose record was already covered by
    /// that sync returns without issuing another. Correctness rests on
    /// sampling the watermark *before* syncing — a record written after the
    /// sample may or may not be on the platter, so it is never claimed.
    fn sync_through(&self, lsn: u64) -> Result<()> {
        if self.synced_lsn.load(Ordering::SeqCst) >= lsn {
            return Ok(());
        }

        let _guard = self.sync_lock.lock();

        // Re-check: while waiting for the lock, another thread's sync may
        // already have covered this record.
        if self.synced_lsn.load(Ordering::SeqCst) >= lsn {
            return Ok(());
        }

        let covered = self.written_lsn.load(Ordering::SeqCst);
        self.sync_handle
            .sync_data()
            .map_err(|e| Error::Storage(format!("WAL sync failed: {}", e)))?;
        self.synced_lsn.fetch_max(covered, Ordering::SeqCst);

        Ok(())
    }

    /// Append a batch of operations atomically
    pub fn append_batch(&self, ops: &[MetadataOp]) -> Result<u64> {
        if ops.is_empty() {
            return Ok(self.current_lsn());
        }

        let batch_op = MetadataOp::Batch { ops: ops.to_vec() };
        self.append(&batch_op)
    }

    /// Sync WAL to disk
    pub fn sync(&self) -> Result<()> {
        let mut writer = self.writer.lock();
        writer
            .flush()
            .map_err(|e| Error::Storage(format!("WAL flush failed: {}", e)))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|e| Error::Storage(format!("WAL sync failed: {}", e)))
    }

    /// Replay WAL from a given LSN, calling the callback for each operation
    pub fn replay<F>(&self, from_lsn: u64, mut callback: F) -> Result<u64>
    where
        F: FnMut(u64, MetadataOp) -> Result<()>,
    {
        let file = File::open(&self.path)
            .map_err(|e| Error::Storage(format!("failed to open WAL for replay: {}", e)))?;

        let mut reader = BufReader::new(file);
        let mut buf = vec![0u8; 64 * 1024];
        let mut last_lsn = from_lsn.saturating_sub(1);

        loop {
            let bytes_read = reader.read(&mut buf).unwrap_or(0);
            if bytes_read == 0 {
                break;
            }

            let mut offset = 0;
            while offset + RECORD_HEADER_SIZE + 4 <= bytes_read {
                match WalRecord::from_bytes(&buf[offset..bytes_read]) {
                    Ok((record, size)) => {
                        if record.lsn >= from_lsn
                            && let Some(op) = MetadataOp::from_bytes(&record.data)
                        {
                            callback(record.lsn, op)?;
                        }
                        last_lsn = record.lsn;
                        offset += size;
                    }
                    Err(_) => break,
                }
            }

            if offset < bytes_read {
                let _ = reader.seek(SeekFrom::Current(-((bytes_read - offset) as i64)));
            }
        }

        Ok(last_lsn)
    }

    /// Iterate over all entries, converting operations to entries
    pub fn iter_entries<F>(&self, from_lsn: u64, mut callback: F) -> Result<u64>
    where
        F: FnMut(MetadataEntry) -> Result<()>,
    {
        self.replay(from_lsn, |lsn, op| {
            match op {
                MetadataOp::Put { key, value } => {
                    callback(MetadataEntry::new(key, value, lsn))?;
                }
                MetadataOp::Delete { key } => {
                    callback(MetadataEntry::tombstone(key, lsn))?;
                }
                MetadataOp::Batch { ops } => {
                    for sub_op in ops {
                        match sub_op {
                            MetadataOp::Put { key, value } => {
                                callback(MetadataEntry::new(key, value, lsn))?;
                            }
                            MetadataOp::Delete { key } => {
                                callback(MetadataEntry::tombstone(key, lsn))?;
                            }
                            MetadataOp::Batch { .. } => {
                                // Nested batches not supported
                            }
                        }
                    }
                }
            }
            Ok(())
        })
    }

    /// Truncate WAL up to (but not including) the given LSN
    ///
    /// This is called after a successful snapshot to reclaim space.
    /// Creates a new WAL file with only entries >= snapshot_lsn.
    pub fn truncate_before(&self, snapshot_lsn: u64) -> Result<()> {
        // Create new WAL file
        let new_path = self.path.with_extension("wal.new");

        {
            let new_wal = MetadataWal::create(&new_path, self.config.clone())?;

            // Copy entries >= snapshot_lsn to new file
            self.replay(snapshot_lsn, |_lsn, op| {
                new_wal.append(&op)?;
                Ok(())
            })?;

            new_wal.sync()?;
        }

        // Atomic rename
        std::fs::rename(&new_path, &self.path)
            .map_err(|e| Error::Storage(format!("WAL rename failed: {}", e)))?;

        // Reopen writer to new file
        let file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|e| Error::Storage(format!("failed to reopen WAL: {}", e)))?;

        let mut writer = self.writer.lock();
        *writer = BufWriter::with_capacity(self.config.write_buffer_size, file);

        // Update size
        let new_size = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        self.size.store(new_size, Ordering::Relaxed);

        Ok(())
    }

    /// Get current LSN (last assigned)
    pub fn current_lsn(&self) -> u64 {
        self.next_lsn.load(Ordering::SeqCst).saturating_sub(1)
    }

    /// Get current WAL size in bytes
    pub fn size(&self) -> u64 {
        self.size.load(Ordering::Relaxed)
    }

    /// Check if WAL needs compaction
    pub fn needs_compaction(&self) -> bool {
        self.size() > self.config.max_size_bytes
    }

    /// Get the path of the WAL file
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::MetadataKey;
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_wal_create_and_append() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wal");

        let wal = MetadataWal::create(&path, WalConfig::default()).unwrap();

        let op = MetadataOp::Put {
            key: MetadataKey::block(42),
            value: b"test value".to_vec(),
        };

        let lsn = wal.append(&op).unwrap();
        assert_eq!(lsn, 1);

        let lsn2 = wal.append(&op).unwrap();
        assert_eq!(lsn2, 2);
    }

    #[test]
    fn test_wal_replay() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wal");

        // Write some entries
        {
            let wal = MetadataWal::create(&path, WalConfig::default()).unwrap();

            wal.append(&MetadataOp::Put {
                key: MetadataKey::block(1),
                value: b"value1".to_vec(),
            })
            .unwrap();

            wal.append(&MetadataOp::Put {
                key: MetadataKey::block(2),
                value: b"value2".to_vec(),
            })
            .unwrap();

            wal.append(&MetadataOp::Delete {
                key: MetadataKey::block(1),
            })
            .unwrap();

            wal.sync().unwrap();
        }

        // Replay
        {
            let wal = MetadataWal::open(&path, WalConfig::default()).unwrap();
            let mut entries = vec![];

            wal.replay(1, |lsn, op| {
                entries.push((lsn, op));
                Ok(())
            })
            .unwrap();

            assert_eq!(entries.len(), 3);
        }
    }

    #[test]
    fn test_wal_batch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wal");

        let wal = MetadataWal::create(&path, WalConfig::default()).unwrap();

        let ops = vec![
            MetadataOp::Put {
                key: MetadataKey::block(1),
                value: b"v1".to_vec(),
            },
            MetadataOp::Put {
                key: MetadataKey::block(2),
                value: b"v2".to_vec(),
            },
        ];

        let lsn = wal.append_batch(&ops).unwrap();
        assert_eq!(lsn, 1);

        // Replay and count entries
        let mut count = 0;
        wal.iter_entries(1, |_entry| {
            count += 1;
            Ok(())
        })
        .unwrap();

        assert_eq!(count, 2);
    }

    #[test]
    fn test_wal_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("test.wal");

        // Write some entries
        {
            let wal = MetadataWal::create(&path, WalConfig::default()).unwrap();
            wal.append(&MetadataOp::Put {
                key: MetadataKey::block(1),
                value: b"value1".to_vec(),
            })
            .unwrap();
            wal.sync().unwrap();
        }

        // Reopen and continue
        {
            let wal = MetadataWal::open(&path, WalConfig::default()).unwrap();
            assert_eq!(wal.current_lsn(), 1);

            let lsn = wal
                .append(&MetadataOp::Put {
                    key: MetadataKey::block(2),
                    value: b"value2".to_vec(),
                })
                .unwrap();
            assert_eq!(lsn, 2);
        }
    }

    #[test]
    fn test_record_roundtrip() {
        let record = WalRecord {
            lsn: 42,
            data: b"test data for record".to_vec(),
        };

        let bytes = record.to_bytes();
        let (parsed, size) = WalRecord::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.lsn, 42);
        assert_eq!(parsed.data, b"test data for record");
        assert_eq!(size, bytes.len());
    }
}

#[cfg(test)]
mod group_commit_tests {
    use super::super::types::MetadataKey;
    use super::*;
    use std::sync::Arc;
    use std::time::Instant;

    fn wal(dir: &tempfile::TempDir) -> MetadataWal {
        MetadataWal::create(dir.path().join("g.wal"), WalConfig::default()).expect("create")
    }

    fn op(n: u64) -> MetadataOp {
        MetadataOp::Put {
            key: MetadataKey::block(n),
            value: vec![0u8; 128],
        }
    }

    /// Every appended record must survive a reopen.
    ///
    /// The whole point of sharing an fsync is that nobody returns before one
    /// covering their record has completed — so this is the property that must
    /// not have been traded away for the speed.
    #[test]
    fn every_acknowledged_append_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.wal");
        {
            let w = MetadataWal::create(&path, WalConfig::default()).unwrap();
            for i in 0..64 {
                w.append(&op(i)).expect("append");
            }
        }
        let reopened = MetadataWal::open(&path, WalConfig::default()).unwrap();
        let mut seen = 0usize;
        reopened
            .replay(1, |_, _| {
                seen += 1;
                Ok(())
            })
            .expect("replay");
        assert_eq!(seen, 64, "records acknowledged before close did not replay");
    }

    /// Concurrent appends are durable too — the case group commit changes.
    #[test]
    fn concurrent_appends_are_all_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.wal");
        {
            let w = Arc::new(MetadataWal::create(&path, WalConfig::default()).unwrap());
            let mut hs = Vec::new();
            for t in 0..8 {
                let w = Arc::clone(&w);
                hs.push(std::thread::spawn(move || {
                    for i in 0..25 {
                        w.append(&op(t * 100 + i)).expect("append");
                    }
                }));
            }
            for h in hs {
                h.join().unwrap();
            }
        }
        let reopened = MetadataWal::open(&path, WalConfig::default()).unwrap();
        let mut seen = 0usize;
        reopened
            .replay(1, |_, _| {
                seen += 1;
                Ok(())
            })
            .expect("replay");
        assert_eq!(seen, 200, "a concurrently appended record was lost");
    }

    /// LSNs stay unique and ordered when handed out under the writer lock.
    #[test]
    fn lsns_are_unique_under_concurrency() {
        let dir = tempfile::tempdir().unwrap();
        let w = Arc::new(wal(&dir));
        let mut hs = Vec::new();
        for _ in 0..8 {
            let w = Arc::clone(&w);
            hs.push(std::thread::spawn(move || {
                (0..25)
                    .map(|i| w.append(&op(i)).unwrap())
                    .collect::<Vec<_>>()
            }));
        }
        let mut all: Vec<u64> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
        let total = all.len();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), total, "two appends were given the same LSN");
    }

    /// Concurrent writers must actually share syncs rather than queue for them.
    ///
    /// Eight threads each appending 25 records is 200 records. One fsync
    /// apiece, serialized, cannot beat 200 x the device's sync latency; shared
    /// ones can. The bound is deliberately loose — this asserts the
    /// serialization is gone, not a particular speed on a particular disk.
    #[test]
    fn concurrent_writers_share_syncs() {
        let dir = tempfile::tempdir().unwrap();

        // Calibrate against this machine: how long does one synced append take?
        let solo = wal(&dir);
        let t = Instant::now();
        for i in 0..20 {
            solo.append(&op(i)).unwrap();
        }
        let per_append = t.elapsed() / 20;
        drop(solo);

        let dir2 = tempfile::tempdir().unwrap();
        let w = Arc::new(wal(&dir2));
        let t = Instant::now();
        let mut hs = Vec::new();
        for tid in 0..8 {
            let w = Arc::clone(&w);
            hs.push(std::thread::spawn(move || {
                for i in 0..25 {
                    w.append(&op(tid * 100 + i)).unwrap();
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        let elapsed = t.elapsed();

        let fully_serialized = per_append * 200;
        assert!(
            elapsed < fully_serialized,
            "200 concurrent appends took {elapsed:?}, no better than {fully_serialized:?} \
             of one-sync-each — writers are still serializing on the sync"
        );
    }

    /// Not an assertion — prints the achieved append rate so the effect of
    /// group commit is visible in test output. Ignored by default.
    #[test]
    #[ignore]
    fn measure_append_rate() {
        for threads in [1usize, 8, 32] {
            let dir = tempfile::tempdir().unwrap();
            let w = Arc::new(wal(&dir));
            let per = 200;
            let t = Instant::now();
            let mut hs = Vec::new();
            for tid in 0..threads {
                let w = Arc::clone(&w);
                hs.push(std::thread::spawn(move || {
                    for i in 0..per {
                        w.append(&op((tid * 1000 + i) as u64)).unwrap();
                    }
                }));
            }
            for h in hs {
                h.join().unwrap();
            }
            let el = t.elapsed();
            let total = threads * per;
            println!(
                "  {threads:>2} threads: {:>8.0} appends/s",
                total as f64 / el.as_secs_f64()
            );
        }
    }
    /// With syncing off there is nothing to group, and nothing should hang.
    #[test]
    fn an_unsynced_wal_still_appends() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = WalConfig {
            sync_on_write: false,
            ..Default::default()
        };
        let w = MetadataWal::create(dir.path().join("n.wal"), cfg).unwrap();
        for i in 0..32 {
            w.append(&op(i)).expect("append");
        }
        assert!(w.current_lsn() >= 32);
    }
}
