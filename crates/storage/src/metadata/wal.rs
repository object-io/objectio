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
//!
//! Fail-stop: a write or sync that fails leaves the log refusing every
//! write after it until it is opened again, and an open refuses a log
//! damaged anywhere but at its end (objectio-docs `core/storage-engine.md`).

use super::types::{MetadataEntry, MetadataOp};
use objectio_common::log_tail::whole_record_after;
use objectio_common::{Error, Result};
use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// WAL record magic number
const WAL_MAGIC: u32 = 0x4D57414C; // "MWAL"

/// Record header size (magic + lsn + length)
const RECORD_HEADER_SIZE: usize = 16;

/// A record's bytes besides its data: the header and the checksum.
const RECORD_OVERHEAD: usize = RECORD_HEADER_SIZE + 4;

/// Metadata WAL configuration
#[derive(Clone, Debug)]
pub struct WalConfig {
    /// Sync after every write
    pub sync_on_write: bool,
    /// Maximum WAL size before triggering snapshot
    pub max_size_bytes: u64,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            sync_on_write: true,
            max_size_bytes: 64 * 1024 * 1024, // 64MB
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
/// What group commit is buying: records per fsync is `records / syncs`.
pub struct WalSyncStats {
    pub seconds: objectio_common::histogram::Histogram,
    pub syncs: AtomicU64,
    pub records: AtomicU64,
}

impl Default for WalSyncStats {
    fn default() -> Self {
        Self {
            seconds: objectio_common::histogram::Histogram::new(
                objectio_common::histogram::LATENCY_BUCKETS,
            ),
            syncs: AtomicU64::new(0),
            records: AtomicU64::new(0),
        }
    }
}

/// The file appends go to, written unbuffered: a record is handed to the
/// OS in the append that makes it, whole or not at all as far as the log
/// is concerned. (Behind a `BufWriter`, a write that failed left its bytes
/// in the buffer, to go out ahead of the next record: the "failed" record
/// landed after all, and the log's size, which hadn't counted it, no
/// longer matched the file.)
struct LogFile {
    file: File,
    /// Failures to inject, shared with the log's other handles.
    #[cfg(test)]
    faults: std::sync::Arc<Faults>,
}

impl LogFile {
    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        #[cfg(test)]
        if let Some(after) = self.faults.write.lock().take() {
            self.file.write_all(&bytes[..after.min(bytes.len())])?;
            return Err(std::io::Error::other("injected write failure"));
        }
        self.file.write_all(bytes)
    }
}

/// Disk failures a test makes the log meet.
#[cfg(test)]
#[derive(Default)]
struct Faults {
    /// The next write fails after writing this many bytes.
    write: Mutex<Option<usize>>,
    /// The next sync fails.
    sync: std::sync::atomic::AtomicBool,
}

pub struct MetadataWal {
    /// fsync latency and how many records each fsync covered.
    sync_stats: WalSyncStats,
    /// WAL file path
    path: PathBuf,
    /// File handle for writing
    writer: Mutex<LogFile>,
    /// Bytes in the file: what the appends so far wrote.
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
    /// Second descriptor for the same file, used to sync without taking
    /// `writer`. `fdatasync` acts on the inode, so syncing through this
    /// durably commits everything written through the other handle. Locked
    /// across the sync itself — deliberately *not* `writer`, so a thread
    /// waiting to sync does not block one that is still writing.
    ///
    /// Compaction replaces the file, and this with it: a descriptor left on
    /// the old file syncs an inode nothing reads any more, and every record
    /// "synced" through it is lost at the next power cut.
    sync_handle: Mutex<File>,
    /// Truncations so far: a [`WalMark`] is only good in the file it was
    /// taken in.
    file: AtomicU64,
    /// The first write or sync that failed, if one has: the log takes no
    /// write after it. What a failed write left in the file is unknown (part
    /// of the record, or all of it), and after a failed `fdatasync` Linux
    /// marks the pages it couldn't write clean, so the next one can return
    /// success with them still not on disk: a record acknowledged then
    /// would sit behind a hole. Opening the log again finds where it really
    /// ends.
    failed: OnceLock<String>,
    #[cfg(test)]
    faults: std::sync::Arc<Faults>,
}

/// Where the log ends at some moment: the last LSN written, and the byte
/// its record ends at. [`MetadataWal::truncate_through`] drops everything
/// up to it.
#[derive(Clone, Copy, Debug)]
pub struct WalMark {
    pub lsn: u64,
    offset: u64,
    /// Which file the offset is in: each truncation starts a new one.
    file: u64,
}

/// Make a rename or a new file in `path`'s directory durable: until the
/// directory itself is synced, a power cut can bring back the old entry.
pub(super) fn sync_parent_dir(path: &Path) -> Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| Error::Storage(format!("failed to sync {}: {e}", dir.display())))
}

/// The whole records of a WAL file, in order. Ends at the end of the file
/// or at the first record that is torn or corrupt, whatever its size;
/// `end` then says where that record starts.
struct Records {
    reader: BufReader<File>,
    /// Bytes in the file.
    len: u64,
    /// Where the last whole record read so far ends.
    end: u64,
}

impl Records {
    fn new(file: File) -> Self {
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        Self {
            reader: BufReader::with_capacity(64 * 1024, file),
            len,
            end: 0,
        }
    }
}

impl Iterator for Records {
    type Item = WalRecord;

    fn next(&mut self) -> Option<WalRecord> {
        let mut header = [0u8; RECORD_HEADER_SIZE];
        self.reader.read_exact(&mut header).ok()?;
        if u32::from_le_bytes(header[0..4].try_into().unwrap()) != WAL_MAGIC {
            return None;
        }
        let data_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        let total = RECORD_HEADER_SIZE + data_len + 4;
        // A corrupt length must not make us allocate more than the file holds.
        if self.end + total as u64 > self.len {
            return None;
        }
        let mut buf = vec![0u8; total];
        buf[..RECORD_HEADER_SIZE].copy_from_slice(&header);
        self.reader
            .read_exact(&mut buf[RECORD_HEADER_SIZE..])
            .ok()?;
        let (record, size) = WalRecord::from_bytes(&buf).ok()?;
        self.end += size as u64;
        Some(record)
    }
}

/// Where a WAL file's records end, found by [`MetadataWal::scan_wal`].
struct Scanned {
    /// The last LSN in it, or 0.
    last_lsn: u64,
    /// Where its last whole record ends.
    end: u64,
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

        Self::with_file(path, file, config, 0, 0)
    }

    fn with_file(
        path: PathBuf,
        file: File,
        config: WalConfig,
        last_lsn: u64,
        size: u64,
    ) -> Result<Self> {
        let sync_handle = file
            .try_clone()
            .map_err(|e| Error::Storage(format!("failed to clone WAL handle: {}", e)))?;
        #[cfg(test)]
        let faults = std::sync::Arc::new(Faults::default());
        Ok(Self {
            path,
            writer: Mutex::new(LogFile {
                file,
                #[cfg(test)]
                faults: std::sync::Arc::clone(&faults),
            }),
            size: AtomicU64::new(size),
            next_lsn: AtomicU64::new(last_lsn + 1),
            config,
            // Everything already on disk is durable by definition.
            written_lsn: AtomicU64::new(last_lsn),
            synced_lsn: AtomicU64::new(last_lsn),
            sync_stats: WalSyncStats::default(),
            sync_handle: Mutex::new(sync_handle),
            file: AtomicU64::new(0),
            failed: OnceLock::new(),
            #[cfg(test)]
            faults,
        })
    }

    /// Open an existing WAL file
    pub fn open(path: impl AsRef<Path>, config: WalConfig) -> Result<Self> {
        Self::open_replaying(path, config, u64::MAX, |_| Ok(()))
    }

    /// Open an existing WAL file, replaying its entries from `from_lsn` in
    /// the pass that finds where it ends: a start reads the log once, not
    /// once to find its end and again to replay it (a 64 MiB log was read
    /// twice on every OSD start).
    ///
    /// # Errors
    /// I/O; a record that is whole but doesn't decode; records missing (a
    /// log that starts after `from_lsn`, or LSNs that skip one); or a
    /// damaged record with a whole one after it, which is damage, not the
    /// torn end of an append a crash interrupted.
    pub fn open_replaying<F>(
        path: impl AsRef<Path>,
        config: WalConfig,
        from_lsn: u64,
        mut callback: F,
    ) -> Result<Self>
    where
        F: FnMut(MetadataEntry) -> Result<()>,
    {
        let path = path.as_ref().to_path_buf();

        // The last LSN and where the last whole record ends, the entries
        // from `from_lsn` replayed on the way.
        let Scanned { last_lsn, end } = Self::scan_wal(&path, from_lsn, |lsn, op| {
            entries_of(lsn, op, &mut callback)
        })?;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| Error::Storage(format!("failed to open WAL: {}", e)))?;

        // Appends go at the end of the file. Left in place, a torn tail would
        // sit between the log and them, and the next scan, stopping at the
        // tail, would never reach them.
        let on_disk = file.metadata().map(|m| m.len()).unwrap_or(0);
        if on_disk > end {
            tracing::warn!(
                "WAL {}: cutting off {} bytes after the last whole record (LSN {last_lsn})",
                path.display(),
                on_disk - end
            );
            file.set_len(end)
                .and_then(|()| file.sync_all())
                .map_err(|e| Error::Storage(format!("failed to cut off WAL tail: {}", e)))?;
        }

        Self::with_file(path, file, config, last_lsn, end)
    }

    /// Scan the WAL for its last LSN and where its last whole record ends,
    /// calling `callback` for each operation from `from_lsn`.
    ///
    /// What follows the last whole record is the torn end of an append a
    /// crash interrupted, never acknowledged, unless a whole record follows
    /// it: then it is damage, and the log is refused (objectio-common
    /// `log_tail`).
    fn scan_wal<F>(path: &Path, from_lsn: u64, mut callback: F) -> Result<Scanned>
    where
        F: FnMut(u64, MetadataOp) -> Result<()>,
    {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Scanned {
                    last_lsn: 0,
                    end: 0,
                });
            }
            Err(e) => {
                return Err(Error::Storage(format!("failed to open WAL: {}", e)));
            }
        };
        let damaged = |what: String| {
            Error::Storage(format!(
                "metadata log {}: {what}; refusing to open rather than drop or \
                 misplace acknowledged changes",
                path.display()
            ))
        };
        let probe_file = file
            .try_clone()
            .map_err(|e| Error::Storage(format!("failed to clone WAL handle: {e}")))?;
        let mut records = Records::new(file);
        let mut last_lsn = 0u64;
        loop {
            let at = records.end;
            let Some(record) = records.next() else {
                break;
            };
            if last_lsn == 0 {
                // The log holds every record from the replay's start on: a
                // first record past it means some are missing.
                if record.lsn > from_lsn {
                    return Err(damaged(format!(
                        "it starts at record {}, but the index needs it from {from_lsn}: \
                         records are missing",
                        record.lsn
                    )));
                }
            } else if record.lsn != last_lsn + 1 {
                return Err(damaged(format!(
                    "record {} at byte {at} follows record {last_lsn}: records are missing",
                    record.lsn
                )));
            }
            if record.lsn >= from_lsn {
                callback(record.lsn, decode(path, &record)?)?;
            }
            last_lsn = record.lsn;
        }
        let (end, len) = (records.end, records.len);
        if end < len {
            let mut found = 0u64;
            let after = whole_record_after(
                &probe_file,
                end,
                len,
                RECORD_HEADER_SIZE,
                |at, head| {
                    if head.len() < RECORD_HEADER_SIZE
                        || u32::from_le_bytes(head[0..4].try_into().unwrap()) != WAL_MAGIC
                    {
                        return None;
                    }
                    // Records after it number on from the last whole one,
                    // one per at least `RECORD_OVERHEAD` bytes.
                    let lsn = u64::from_le_bytes(head[4..12].try_into().unwrap());
                    let most = last_lsn.saturating_add((len - at) / RECORD_OVERHEAD as u64 + 1);
                    if last_lsn > 0 && (lsn <= last_lsn || lsn > most) {
                        return None;
                    }
                    let data_len = u32::from_le_bytes(head[12..16].try_into().unwrap());
                    Some(RECORD_OVERHEAD as u64 + u64::from(data_len))
                },
                |_, bytes| match WalRecord::from_bytes(bytes) {
                    Ok((record, _)) => {
                        found = record.lsn;
                        true
                    }
                    Err(_) => false,
                },
            )
            .map_err(|e| Error::Storage(format!("failed to read WAL: {e}")))?;
            if let Some(at) = after {
                return Err(damaged(format!(
                    "the record at byte {end} (after record {last_lsn}) is damaged, and \
                     record {found} follows it whole at byte {at}: damage, not a torn append"
                )));
            }
        }
        Ok(Scanned { last_lsn, end })
    }

    /// The error for a write or sync that failed, which from now on fails
    /// every write: see `failed`.
    fn fail(&self, what: &str, e: impl std::fmt::Display) -> Error {
        let cause = format!("{what} failed: {e}");
        if self.failed.set(cause.clone()).is_ok() {
            tracing::error!(
                "metadata log {}: {cause}; refusing every write until it is reopened",
                self.path.display()
            );
        }
        Error::Storage(format!("metadata log {}: {cause}", self.path.display()))
    }

    /// Refuse if a write or sync has failed.
    fn check(&self) -> Result<()> {
        match self.failed.get() {
            None => Ok(()),
            Some(cause) => Err(Error::Storage(format!(
                "metadata log {}: takes no writes after an earlier failure ({cause}) \
                 until it is reopened",
                self.path.display()
            ))),
        }
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
    ///
    /// # Errors
    /// The write or the sync failed, now or earlier (`failed`).
    pub fn append(&self, op: &MetadataOp) -> Result<u64> {
        let data = op.to_bytes();
        if u32::try_from(data.len()).is_err() {
            return Err(Error::Storage(format!(
                "metadata log record of {} bytes is too large",
                data.len()
            )));
        }

        let lsn = {
            let mut writer = self.writer.lock();
            self.check()?;
            // Assigned under the lock so LSN order matches write order, which
            // is what lets `written_lsn` be a watermark rather than a guess;
            // taken only once the record is written, so a failed write
            // leaves no number behind.
            let lsn = self.next_lsn.load(Ordering::SeqCst);
            let bytes = WalRecord { lsn, data }.to_bytes();
            writer
                .write_all(&bytes)
                .map_err(|e| self.fail("write", e))?;
            self.next_lsn.store(lsn + 1, Ordering::SeqCst);
            self.size.fetch_add(bytes.len() as u64, Ordering::SeqCst);
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

        let handle = self.sync_handle.lock();

        // Re-check: while waiting for the lock, another thread's sync may
        // already have covered this record.
        if self.synced_lsn.load(Ordering::SeqCst) >= lsn {
            return Ok(());
        }
        // A sync that failed while this one waited was reported once, to
        // its caller: one now could succeed without this record on disk.
        self.check()?;

        let covered = self.written_lsn.load(Ordering::SeqCst);
        let started = std::time::Instant::now();
        #[cfg(test)]
        if self.faults.sync.swap(false, Ordering::SeqCst) {
            return Err(self.fail("sync", "injected sync failure"));
        }
        handle.sync_data().map_err(|e| self.fail("sync", e))?;
        self.sync_stats.seconds.observe_duration(started.elapsed());
        let previous = self.synced_lsn.fetch_max(covered, Ordering::SeqCst);
        self.sync_stats.syncs.fetch_add(1, Ordering::Relaxed);
        self.sync_stats
            .records
            .fetch_add(covered.saturating_sub(previous), Ordering::Relaxed);

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

    /// fsync statistics for metrics.
    pub fn sync_stats(&self) -> &WalSyncStats {
        &self.sync_stats
    }

    /// Make every record appended so far durable.
    ///
    /// # Errors
    /// The sync failed, now or a write or sync earlier (`failed`).
    pub fn sync(&self) -> Result<()> {
        self.check()?;
        self.sync_through(self.written_lsn.load(Ordering::SeqCst))
    }

    /// Replay WAL from a given LSN, calling the callback for each operation
    pub fn replay<F>(&self, from_lsn: u64, mut callback: F) -> Result<u64>
    where
        F: FnMut(u64, MetadataOp) -> Result<()>,
    {
        let file = File::open(&self.path)
            .map_err(|e| Error::Storage(format!("failed to open WAL for replay: {}", e)))?;

        let mut last_lsn = from_lsn.saturating_sub(1);
        // `Records` ends at the first damaged frame: the open checked the
        // log, so that is an append still being written. A whole,
        // checksummed record that doesn't decode is different: a newer
        // release wrote it, or the decoder broke. Skipping it would silently
        // drop a change this OSD acknowledged, so the replay stops instead.
        for record in Records::new(file) {
            if record.lsn >= from_lsn {
                callback(record.lsn, decode(&self.path, &record)?)?;
            }
            last_lsn = record.lsn;
        }

        Ok(last_lsn)
    }

    /// Iterate over all entries, converting operations to entries
    pub fn iter_entries<F>(&self, from_lsn: u64, mut callback: F) -> Result<u64>
    where
        F: FnMut(MetadataEntry) -> Result<()>,
    {
        self.replay(from_lsn, |lsn, op| entries_of(lsn, op, &mut callback))
    }

    /// Where the log ends now (see [`WalMark`]).
    ///
    /// # Errors
    /// A write or sync failed earlier (`failed`): where the log ends is
    /// then not known.
    pub fn mark(&self) -> Result<WalMark> {
        let writer = self.writer.lock();
        self.check()?;
        Ok(WalMark {
            lsn: self.current_lsn(),
            offset: self.file_len(&writer)?,
            file: self.file.load(Ordering::SeqCst),
        })
    }

    /// The length of the file appends go to: with `writer` held, where the
    /// last record written ends. Taken from the file, not counted, so a
    /// compaction copies from where a record really starts.
    fn file_len(&self, writer: &LogFile) -> Result<u64> {
        let len = writer
            .file
            .metadata()
            .map_err(|e| Error::Storage(format!("WAL stat failed: {e}")))?
            .len();
        self.size.store(len, Ordering::SeqCst);
        Ok(len)
    }

    /// Drop the records up to `mark`, which a durable snapshot now holds:
    /// the records after it go to a new file, which replaces this one.
    ///
    /// In two passes, so appends don't wait for the copy. First, without
    /// the locks, the records written so far are copied and synced; appends
    /// go on into the old file meanwhile. Then, with appends and syncs held
    /// (`writer`, `sync_handle`), only what came in since is copied, synced,
    /// and the new file renamed over the old: a record appended to the old
    /// file after the copy would be gone with it, and a sync of the old file
    /// covers nothing the new one holds. Held across the whole copy, the
    /// locks stalled every write for as long as the copy took: hundreds of
    /// milliseconds once B21's small shards went through the log.
    ///
    /// # Errors
    /// I/O, a stale mark, or a write or sync that failed earlier. Up to the
    /// rename the old file is left as the log; once the new file is renamed
    /// over it, appends go to the new one, and a failure to make the rename
    /// durable fails the log (`failed`).
    pub fn truncate_through(&self, mark: WalMark) -> Result<()> {
        let storage =
            |what: &str, e: std::io::Error| Error::Storage(format!("WAL truncation: {what}: {e}"));
        let new_path = self.path.with_extension("wal.new");
        let stale =
            || Error::Storage("WAL truncation: the mark is from a log since replaced".into());

        // Pass one: what is in the file now, copied without holding appends.
        let first = {
            let writer = self.writer.lock();
            self.check()?;
            let len = self.file_len(&writer)?;
            if mark.file != self.file.load(Ordering::SeqCst) || mark.offset > len {
                return Err(stale());
            }
            len
        };
        let mut new = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&new_path)
            .map_err(|e| storage("create", e))?;
        let mut old = File::open(&self.path).map_err(|e| storage("open", e))?;
        old.seek(SeekFrom::Start(mark.offset))
            .map_err(|e| storage("seek", e))?;
        let mut kept = std::io::copy(&mut (&mut old).take(first - mark.offset), &mut new)
            .map_err(|e| storage("copy", e))?;
        new.sync_data().map_err(|e| storage("sync", e))?;

        // Pass two: the rest, with appends and syncs held.
        let mut writer = self.writer.lock();
        let mut sync_handle = self.sync_handle.lock();
        self.check()?;
        let len = self.file_len(&writer)?;
        if mark.file != self.file.load(Ordering::SeqCst) || first > len {
            return Err(stale());
        }
        kept +=
            std::io::copy(&mut old.take(len - first), &mut new).map_err(|e| storage("copy", e))?;
        new.sync_all().map_err(|e| storage("sync", e))?;
        let new_sync = new.try_clone().map_err(|e| storage("clone", e))?;
        std::fs::rename(&new_path, &self.path).map_err(|e| storage("rename", e))?;

        // The log is the new file from here: appends and syncs go to it
        // whatever happens next. One left on the old file would write an
        // inode nothing reads any more.
        *sync_handle = new_sync;
        writer.file = new;
        self.size.store(kept, Ordering::SeqCst);
        self.file.fetch_add(1, Ordering::SeqCst);
        // Until the directory is synced a power cut can bring the old file
        // back, without whatever reached it unsynced: nothing is taken as
        // durable before then.
        sync_parent_dir(&self.path).map_err(|e| self.fail("sync of the replaced log", e))?;
        // Everything written is in the new file, and it was synced.
        self.synced_lsn
            .fetch_max(self.written_lsn.load(Ordering::SeqCst), Ordering::SeqCst);
        Ok(())
    }

    /// Never number a record at or below `lsn` (a snapshot's). A log that
    /// compaction left empty would otherwise restart at LSN 1, below the
    /// snapshot, and the next replay — which starts after it — skip them.
    pub fn advance_past(&self, lsn: u64) {
        let _writer = self.writer.lock();
        self.next_lsn.fetch_max(lsn + 1, Ordering::SeqCst);
        self.written_lsn.fetch_max(lsn, Ordering::SeqCst);
        self.synced_lsn.fetch_max(lsn, Ordering::SeqCst);
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

    /// Make the next write fail after writing `after` bytes of it.
    #[cfg(test)]
    fn fail_next_write(&self, after: usize) {
        *self.faults.write.lock() = Some(after);
    }

    /// Make the next sync fail.
    #[cfg(test)]
    fn fail_next_sync(&self) {
        self.faults.sync.store(true, Ordering::SeqCst);
    }
}

/// A whole, checksummed record that doesn't decode is not a torn write: a
/// newer release wrote it, or the decoder broke. Skipping it would silently
/// drop a change this OSD acknowledged, so the replay stops instead.
fn decode(path: &Path, record: &WalRecord) -> Result<MetadataOp> {
    MetadataOp::from_bytes(&record.data).ok_or_else(|| {
        Error::Storage(format!(
            "metadata log {}: record {} is intact but doesn't decode (written by a \
             newer release?); refusing to start rather than drop it",
            path.display(),
            record.lsn
        ))
    })
}

/// The entries `op` (logged at `lsn`) makes, each given to `callback`.
fn entries_of<F>(lsn: u64, op: MetadataOp, callback: &mut F) -> Result<()>
where
    F: FnMut(MetadataEntry) -> Result<()>,
{
    match op {
        MetadataOp::Put { key, value } => callback(MetadataEntry::new(key, value, lsn)),
        MetadataOp::Delete { key } => callback(MetadataEntry::tombstone(key, lsn)),
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
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::MetadataKey;
    use super::*;
    use tempfile::tempdir;

    /// A torn record ends the log; a whole, checksummed one that doesn't
    /// decode (a newer release wrote it) stops the replay instead of being
    /// skipped, which would drop an acknowledged change.
    #[test]
    fn an_intact_record_that_does_not_decode_stops_the_replay() {
        use std::io::Write as _;
        let dir = tempdir().unwrap();
        let path = dir.path().join("m.wal");
        {
            let wal = MetadataWal::create(&path, WalConfig::default()).unwrap();
            wal.append(&MetadataOp::Delete {
                key: MetadataKey::block(1),
            })
            .unwrap();
        }
        let record = WalRecord {
            lsn: 2,
            data: vec![0xEE; 9],
        };
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&record.to_bytes())
            .unwrap();

        let wal = MetadataWal::open(&path, WalConfig::default()).unwrap();
        let err = wal.replay(1, |_, _| Ok(())).unwrap_err();
        assert!(err.to_string().contains("record 2"), "{err}");
    }

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

    /// Opening replays from the LSN asked, in the pass that finds the log's
    /// end: the entries a replay after opening gives, and appends go on
    /// after the last record.
    #[test]
    fn opening_replays_what_a_replay_would() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.wal");
        {
            let wal = wal(&dir);
            for n in 1..=10 {
                wal.append(&op(n)).unwrap();
            }
            wal.append(&MetadataOp::Delete {
                key: MetadataKey::block(3),
            })
            .unwrap();
        }
        let summary = |e: &MetadataEntry| (e.key.clone(), e.deleted, e.lsn);
        let mut opened = Vec::new();
        let wal = MetadataWal::open_replaying(&path, WalConfig::default(), 5, |e| {
            opened.push(summary(&e));
            Ok(())
        })
        .unwrap();
        let mut replayed = Vec::new();
        wal.iter_entries(5, |e| {
            replayed.push(summary(&e));
            Ok(())
        })
        .unwrap();
        assert_eq!(opened, replayed);
        assert_eq!(opened.len(), 7);
        assert_eq!(wal.append(&op(11)).unwrap(), 12);
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
    /// Eight threads each appending 25 records is 200 records. Serialized,
    /// that is 200 fsyncs; shared, one a round. Counted rather than timed:
    /// a wall-clock bound failed on loaded CI runners. Nor left to chance:
    /// with a fast enough fsync, writers that merely happen to run at once
    /// take turns and share none. So each round holds the sync lock until
    /// all eight records are written; the round's first sync covers them.
    #[test]
    fn concurrent_writers_share_syncs() {
        const THREADS: u64 = 8;
        const ROUNDS: u64 = 25;
        let dir = tempfile::tempdir().unwrap();
        let w = wal(&dir);
        for round in 0..ROUNDS {
            let written = w.written_lsn.load(Ordering::SeqCst);
            std::thread::scope(|scope| {
                let gate = w.sync_handle.lock();
                for tid in 0..THREADS {
                    let w = &w;
                    scope.spawn(move || w.append(&op(round * 100 + tid)).unwrap());
                }
                while w.written_lsn.load(Ordering::SeqCst) < written + THREADS {
                    std::thread::yield_now();
                }
                drop(gate);
            });
        }

        let stats = w.sync_stats();
        let syncs = stats.syncs.load(Ordering::Relaxed);
        let records = stats.records.load(Ordering::Relaxed);
        assert_eq!(
            records,
            THREADS * ROUNDS,
            "every append must be made durable"
        );
        assert!(
            syncs <= ROUNDS,
            "{syncs} fsyncs for {records} appends in {ROUNDS} rounds: writers are not sharing syncs"
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

    /// Every key and value the WAL at `path` replays, in order.
    fn replayed(path: &Path) -> Vec<(u64, Vec<u8>)> {
        let wal = MetadataWal::open(path, WalConfig::default()).unwrap();
        let mut out = Vec::new();
        wal.replay(0, |lsn, op| {
            if let MetadataOp::Put { value, .. } = op {
                out.push((lsn, value));
            }
            Ok(())
        })
        .unwrap();
        out
    }

    fn put(wal: &MetadataWal, n: u64, value: Vec<u8>) -> u64 {
        wal.append(&MetadataOp::Put {
            key: MetadataKey::block(n),
            value,
        })
        .unwrap()
    }

    /// Scanning read the log in 64 KiB chunks and, on a record that did not
    /// fit in one, seeked back and read the same chunk again, forever: the
    /// OSD hung opening its metadata store. The ObjectMeta of an object of
    /// a few GiB — a couple of hundred stripes — is such a record.
    #[test]
    fn records_larger_than_the_read_buffer_replay() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.wal");
        let big = vec![7u8; 1024 * 1024];
        {
            let wal = MetadataWal::create(&path, WalConfig::default()).unwrap();
            put(&wal, 1, b"small".to_vec());
            put(&wal, 2, big.clone());
            put(&wal, 3, b"after".to_vec());
        }
        assert_eq!(
            replayed(&path),
            vec![(1, b"small".to_vec()), (2, big), (3, b"after".to_vec())]
        );
    }

    /// A crash mid-append leaves a torn record at the end. The log ends at
    /// the last whole record — and appends after the restart go there, not
    /// after the torn bytes, where the next restart would never reach them.
    #[test]
    fn a_torn_last_record_is_cut_off_and_later_appends_survive() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torn.wal");
        {
            let wal = MetadataWal::create(&path, WalConfig::default()).unwrap();
            put(&wal, 1, b"one".to_vec());
            put(&wal, 2, b"two".to_vec());
        }
        let len = std::fs::metadata(&path).unwrap().len();
        let f = OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(len - 3).unwrap();
        drop(f);

        {
            let wal = MetadataWal::open(&path, WalConfig::default()).unwrap();
            assert_eq!(wal.current_lsn(), 1);
            assert_eq!(put(&wal, 2, b"two again".to_vec()), 2);
        }
        assert_eq!(
            replayed(&path),
            vec![(1, b"one".to_vec()), (2, b"two again".to_vec())]
        );
    }

    /// The same for bytes that are not a record at all, including a header
    /// whose length field claims more than the file holds.
    #[test]
    fn garbage_after_the_last_record_is_cut_off() {
        for garbage in [
            vec![0xAB; 5],
            vec![0u8; 100],
            [
                &WAL_MAGIC.to_le_bytes()[..],
                &9u64.to_le_bytes(),
                &u32::MAX.to_le_bytes(),
            ]
            .concat(),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("junk.wal");
            {
                let wal = MetadataWal::create(&path, WalConfig::default()).unwrap();
                put(&wal, 1, b"one".to_vec());
            }
            let mut f = OpenOptions::new().append(true).open(&path).unwrap();
            f.write_all(&garbage).unwrap();
            drop(f);

            {
                let wal = MetadataWal::open(&path, WalConfig::default()).unwrap();
                assert_eq!(put(&wal, 2, b"two".to_vec()), 2);
            }
            assert_eq!(
                replayed(&path),
                vec![(1, b"one".to_vec()), (2, b"two".to_vec())],
                "after {} bytes of garbage",
                garbage.len()
            );
        }
    }

    /// After a truncation, the syncs that acknowledge appends must reach
    /// the file the log now is. They went to the replaced one, an inode
    /// nothing reads: every acknowledged write after the first compaction
    /// was durable only once the kernel wrote it back on its own, and a
    /// power cut before that lost it (found by the A6 chaos test).
    #[test]
    fn syncs_after_a_truncation_reach_the_new_file() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let w = wal(&dir);
        for i in 0..8 {
            w.append(&op(i)).unwrap();
        }
        let mark = w.mark().unwrap();
        w.append(&op(8)).unwrap();
        w.truncate_through(mark).unwrap();
        w.append(&op(9)).unwrap();

        let synced = w.sync_handle.lock().metadata().unwrap().ino();
        let current = std::fs::metadata(dir.path().join("g.wal")).unwrap().ino();
        assert_eq!(synced, current, "syncs go to a file the log no longer is");

        // And the log holds what came after the mark, then what came after
        // the truncation.
        let mut lsns = Vec::new();
        w.replay(1, |lsn, _| {
            lsns.push(lsn);
            Ok(())
        })
        .unwrap();
        assert_eq!(lsns, vec![9, 10]);
    }

    /// Appends go on while a truncation copies (it holds them only for the
    /// last few records): every record appended after the mark, before,
    /// during or after the copy, is in the log afterwards, in order, and in
    /// it again when the log is opened from disk.
    #[test]
    fn appends_during_a_truncation_are_all_kept() {
        let dir = tempfile::tempdir().unwrap();
        let w = wal(&dir);
        for i in 0..500 {
            w.append(&op(i)).unwrap();
        }
        let mark = w.mark().unwrap();
        let after_mark = w.current_lsn();
        std::thread::scope(|s| {
            let writer = s.spawn(|| {
                for i in 500..2500 {
                    w.append(&op(i)).unwrap();
                }
            });
            std::thread::sleep(std::time::Duration::from_millis(2));
            w.truncate_through(mark).unwrap();
            writer.join().unwrap();
        });
        let replayed = |w: &MetadataWal| {
            let mut lsns = Vec::new();
            w.replay(1, |lsn, _| {
                lsns.push(lsn);
                Ok(())
            })
            .unwrap();
            lsns
        };
        let want: Vec<u64> = (after_mark + 1..=w.current_lsn()).collect();
        assert_eq!(want.len(), 2000);
        assert_eq!(replayed(&w), want);
        drop(w);
        let reopened = MetadataWal::open(dir.path().join("g.wal"), WalConfig::default()).unwrap();
        assert_eq!(replayed(&reopened), want, "not so on disk");
    }

    /// A mark is a byte offset in one file: after another truncation it
    /// points into a different log, and cutting there would drop records.
    #[test]
    fn a_mark_from_a_replaced_log_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let w = wal(&dir);
        for i in 0..8 {
            w.append(&op(i)).unwrap();
        }
        let stale = w.mark().unwrap();
        w.truncate_through(w.mark().unwrap()).unwrap();
        for i in 8..16 {
            w.append(&op(i)).unwrap();
        }
        assert!(w.truncate_through(stale).is_err());
        let mut n = 0;
        w.replay(1, |_, _| {
            n += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 8);
    }
}

/// What the log does when the disk fails it: at open, damage in the middle
/// of the log stops it; while running, a failed write or sync stops every
/// write after it.
#[cfg(test)]
mod fail_stop_tests {
    use super::super::types::MetadataKey;
    use super::*;

    fn put(n: u64) -> MetadataOp {
        MetadataOp::Put {
            key: MetadataKey::block(n),
            value: format!("value {n}").into_bytes(),
        }
    }

    fn lsns(path: &Path) -> Vec<u64> {
        let wal = MetadataWal::open(path, WalConfig::default()).unwrap();
        let mut out = Vec::new();
        wal.replay(0, |lsn, _| {
            out.push(lsn);
            Ok(())
        })
        .unwrap();
        out
    }

    fn append_raw(path: &Path, bytes: &[u8]) {
        OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    fn raw(lsn: u64) -> Vec<u8> {
        WalRecord {
            lsn,
            data: put(lsn).to_bytes(),
        }
        .to_bytes()
    }

    /// A damaged record with whole ones after it is not a torn append: the
    /// open refuses, and the file is left as it was. It was cut there, the
    /// records after it (acknowledged) with it.
    #[test]
    fn damage_with_whole_records_after_it_refuses_the_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.wal");
        let second;
        {
            let wal = MetadataWal::create(&path, WalConfig::default()).unwrap();
            wal.append(&put(1)).unwrap();
            second = wal.size();
            wal.append(&put(2)).unwrap();
            wal.append(&put(3)).unwrap();
        }
        let mut data = std::fs::read(&path).unwrap();
        data[usize::try_from(second).unwrap() + RECORD_HEADER_SIZE + 2] ^= 0xff;
        std::fs::write(&path, &data).unwrap();
        let len = data.len() as u64;

        let err = MetadataWal::open(&path, WalConfig::default())
            .err()
            .expect("refused");
        assert!(err.to_string().contains("damage"), "{err}");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len);
    }

    /// The same with bytes that are no record at all between two whole
    /// records.
    #[test]
    fn garbage_between_whole_records_refuses_the_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.wal");
        MetadataWal::create(&path, WalConfig::default())
            .unwrap()
            .append(&put(1))
            .unwrap();
        append_raw(&path, &[0xAB; 37]);
        append_raw(&path, &raw(3));
        let len = std::fs::metadata(&path).unwrap().len();
        assert!(MetadataWal::open(&path, WalConfig::default()).is_err());
        assert_eq!(std::fs::metadata(&path).unwrap().len(), len);
    }

    /// Whole records whose LSNs skip one: a record is missing, and the log
    /// can't say what it was.
    #[test]
    fn a_gap_in_the_lsns_refuses_the_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.wal");
        std::fs::write(&path, [raw(1), raw(2), raw(4)].concat()).unwrap();
        let err = MetadataWal::open(&path, WalConfig::default())
            .err()
            .expect("refused");
        assert!(err.to_string().contains("record 4"), "{err}");
    }

    /// A log that starts after the LSN the replay must start from is missing
    /// the records in between.
    #[test]
    fn a_log_starting_past_the_replay_point_refuses_the_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.wal");
        std::fs::write(&path, [raw(5), raw(6)].concat()).unwrap();
        let open =
            |from| MetadataWal::open_replaying(&path, WalConfig::default(), from, |_| Ok(()));
        assert!(open(3).is_err());
        assert!(open(5).is_ok());
        assert!(open(6).is_ok());
    }

    /// A write that fails part way: that append fails, and so does every
    /// later one, and a sync. Reopened, the log holds every record
    /// acknowledged, the torn one cut off, and takes appends again.
    #[test]
    fn after_a_failed_write_every_append_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.wal");
        {
            let wal = MetadataWal::create(&path, WalConfig::default()).unwrap();
            assert_eq!(wal.append(&put(1)).unwrap(), 1);
            wal.fail_next_write(7);
            assert!(wal.append(&put(2)).is_err());
            assert!(
                wal.append(&put(3)).is_err(),
                "an append after a failed write"
            );
            assert!(wal.sync().is_err());
            assert!(wal.mark().is_err());
        }
        assert_eq!(lsns(&path), vec![1]);
        let wal = MetadataWal::open(&path, WalConfig::default()).unwrap();
        assert_eq!(wal.append(&put(2)).unwrap(), 2);
        drop(wal);
        assert_eq!(lsns(&path), vec![1, 2]);
    }

    /// A failed fsync: on Linux the pages it didn't write are marked clean,
    /// and the next fsync may succeed without writing them. So every append
    /// after it is refused, though a sync would now "succeed".
    #[test]
    fn after_a_failed_sync_every_append_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let wal = MetadataWal::create(dir.path().join("m.wal"), WalConfig::default()).unwrap();
        wal.append(&put(1)).unwrap();
        wal.fail_next_sync();
        assert!(wal.append(&put(2)).is_err());
        assert!(
            wal.append(&put(3)).is_err(),
            "an append after a failed sync"
        );
        assert!(wal.sync().is_err());
    }

    /// A write that fails whole, then more appends, a compaction and a
    /// reopen: every record acknowledged is in the log. (The buffered
    /// writer kept the failed record and wrote it with the next one, the
    /// log's size not counting it; the compaction then copied from the
    /// middle of a record, and the reopen lost every record after it.)
    #[test]
    fn a_failed_write_loses_nothing_acknowledged_through_a_compaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m.wal");
        let mut acked = Vec::new();
        {
            let wal = MetadataWal::create(&path, WalConfig::default()).unwrap();
            for n in 1..=3 {
                acked.push(wal.append(&put(n)).unwrap());
            }
            wal.fail_next_write(0);
            assert!(wal.append(&put(4)).is_err());
            for n in 5..=8 {
                if let Ok(lsn) = wal.append(&put(n)) {
                    acked.push(lsn);
                }
            }
            if let Ok(mark) = wal.mark() {
                for n in 9..=10 {
                    if let Ok(lsn) = wal.append(&put(n)) {
                        acked.push(lsn);
                    }
                }
                acked.retain(|lsn| *lsn > mark.lsn);
                let _ = wal.truncate_through(mark);
            }
        }
        let held = lsns(&path);
        for lsn in &acked {
            assert!(held.contains(lsn), "acknowledged {lsn} lost: {held:?}");
        }
    }
}
