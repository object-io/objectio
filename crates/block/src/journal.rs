//! Write-ahead journal for block storage durability
//!
//! Provides crash recovery for the write cache by persisting write operations
//! to a journal file before acknowledging them to the client.

use crate::chunk::ChunkId;
use crate::error::{BlockError, BlockResult};

use bytes::Bytes;
use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

/// Magic number for journal file header
const JOURNAL_MAGIC: u64 = 0x4F424A5F4A524E4C; // "OBJ_JRNL"

/// Journal file version
const JOURNAL_VERSION: u32 = 1;

/// Journal entry type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryType {
    /// Write data to a chunk
    Write = 1,
    /// Flush completed for a chunk
    Flush = 2,
    /// Checkpoint (all prior entries can be discarded)
    Checkpoint = 3,
}

impl TryFrom<u8> for EntryType {
    type Error = BlockError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(EntryType::Write),
            2 => Ok(EntryType::Flush),
            3 => Ok(EntryType::Checkpoint),
            _ => Err(BlockError::Journal(format!(
                "invalid entry type: {}",
                value
            ))),
        }
    }
}

/// Journal entry header (fixed size for easy reading)
#[derive(Debug, Clone)]
pub struct JournalEntry {
    /// Sequence number
    pub sequence: u64,
    /// Entry type
    pub entry_type: EntryType,
    /// Volume ID
    pub volume_id: String,
    /// Chunk ID
    pub chunk_id: ChunkId,
    /// Offset within chunk
    pub offset: u64,
    /// Data (for write entries)
    pub data: Option<Bytes>,
    /// CRC32 checksum
    pub checksum: u32,
}

impl JournalEntry {
    /// Create a write entry
    pub fn write(
        sequence: u64,
        volume_id: String,
        chunk_id: ChunkId,
        offset: u64,
        data: Bytes,
    ) -> Self {
        let mut entry = Self {
            sequence,
            entry_type: EntryType::Write,
            volume_id,
            chunk_id,
            offset,
            data: Some(data),
            checksum: 0,
        };
        entry.checksum = entry.compute_checksum();
        entry
    }

    /// Create a flush entry
    pub fn flush(sequence: u64, volume_id: String, chunk_id: ChunkId) -> Self {
        let mut entry = Self {
            sequence,
            entry_type: EntryType::Flush,
            volume_id,
            chunk_id,
            offset: 0,
            data: None,
            checksum: 0,
        };
        entry.checksum = entry.compute_checksum();
        entry
    }

    /// Create a checkpoint entry
    pub fn checkpoint(sequence: u64) -> Self {
        let mut entry = Self {
            sequence,
            entry_type: EntryType::Checkpoint,
            volume_id: String::new(),
            chunk_id: 0,
            offset: 0,
            data: None,
            checksum: 0,
        };
        entry.checksum = entry.compute_checksum();
        entry
    }

    /// Compute CRC32 checksum
    fn compute_checksum(&self) -> u32 {
        self.checksum_with_type(self.entry_type as u8)
    }

    /// The checksum, computed with `entry_type` as the type byte (which
    /// may be one this release has no variant for).
    fn checksum_with_type(&self, entry_type: u8) -> u32 {
        let mut data = Vec::new();
        data.extend_from_slice(&self.sequence.to_le_bytes());
        data.push(entry_type);
        data.extend_from_slice(self.volume_id.as_bytes());
        data.extend_from_slice(&self.chunk_id.to_le_bytes());
        data.extend_from_slice(&self.offset.to_le_bytes());
        if let Some(ref d) = self.data {
            data.extend_from_slice(d);
        }
        crc32c::crc32c(&data)
    }

    /// Verify checksum
    pub fn verify(&self) -> bool {
        self.checksum == self.compute_checksum()
    }

    /// Serialize to bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // Entry header
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.push(self.entry_type as u8);

        // Volume ID (length-prefixed)
        let vol_bytes = self.volume_id.as_bytes();
        buf.extend_from_slice(&(vol_bytes.len() as u16).to_le_bytes());
        buf.extend_from_slice(vol_bytes);

        // Chunk ID and offset
        buf.extend_from_slice(&self.chunk_id.to_le_bytes());
        buf.extend_from_slice(&self.offset.to_le_bytes());

        // Data (length-prefixed)
        if let Some(ref data) = self.data {
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
        } else {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }

        // Checksum
        buf.extend_from_slice(&self.checksum.to_le_bytes());

        buf
    }

    /// Deserialize from reader
    pub fn deserialize<R: Read>(reader: &mut R) -> BlockResult<Self> {
        let (entry_type, mut entry) = Self::read_raw(reader)?;
        entry.entry_type = EntryType::try_from(entry_type)?;
        Ok(entry)
    }

    /// Read an entry's fields whatever its type byte, which comes back
    /// separately (the entry's own `entry_type` is a placeholder): every
    /// type has the same layout, so an unknown one can still be read and
    /// its checksum checked.
    fn read_raw<R: Read>(reader: &mut R) -> BlockResult<(u8, Self)> {
        // Sequence number
        let mut seq_buf = [0u8; 8];
        reader
            .read_exact(&mut seq_buf)
            .map_err(|e| BlockError::Journal(e.to_string()))?;
        let sequence = u64::from_le_bytes(seq_buf);

        // Entry type
        let mut type_buf = [0u8; 1];
        reader
            .read_exact(&mut type_buf)
            .map_err(|e| BlockError::Journal(e.to_string()))?;
        let entry_type = type_buf[0];

        // Volume ID
        let mut vol_len_buf = [0u8; 2];
        reader
            .read_exact(&mut vol_len_buf)
            .map_err(|e| BlockError::Journal(e.to_string()))?;
        let vol_len = u16::from_le_bytes(vol_len_buf) as usize;
        let mut vol_buf = vec![0u8; vol_len];
        reader
            .read_exact(&mut vol_buf)
            .map_err(|e| BlockError::Journal(e.to_string()))?;
        let volume_id = String::from_utf8(vol_buf)
            .map_err(|e| BlockError::Journal(format!("invalid volume ID: {}", e)))?;

        // Chunk ID and offset
        let mut chunk_buf = [0u8; 8];
        reader
            .read_exact(&mut chunk_buf)
            .map_err(|e| BlockError::Journal(e.to_string()))?;
        let chunk_id = u64::from_le_bytes(chunk_buf);

        let mut offset_buf = [0u8; 8];
        reader
            .read_exact(&mut offset_buf)
            .map_err(|e| BlockError::Journal(e.to_string()))?;
        let offset = u64::from_le_bytes(offset_buf);

        // Data
        let mut data_len_buf = [0u8; 4];
        reader
            .read_exact(&mut data_len_buf)
            .map_err(|e| BlockError::Journal(e.to_string()))?;
        let data_len = u32::from_le_bytes(data_len_buf) as usize;
        let data = if data_len > 0 {
            let mut data_buf = vec![0u8; data_len];
            reader
                .read_exact(&mut data_buf)
                .map_err(|e| BlockError::Journal(e.to_string()))?;
            Some(Bytes::from(data_buf))
        } else {
            None
        };

        // Checksum
        let mut crc_buf = [0u8; 4];
        reader
            .read_exact(&mut crc_buf)
            .map_err(|e| BlockError::Journal(e.to_string()))?;
        let checksum = u32::from_le_bytes(crc_buf);

        Ok((
            entry_type,
            Self {
                sequence,
                entry_type: EntryType::Write,
                volume_id,
                chunk_id,
                offset,
                data,
                checksum,
            },
        ))
    }
}

/// Write-ahead journal for block storage
pub struct WriteJournal {
    /// Journal file path
    path: PathBuf,
    /// Journal file writer
    writer: Mutex<Option<BufWriter<File>>>,
    /// Next sequence number. Every entry numbered below it has been
    /// written to the OS (the writer is flushed before it moves on).
    sequence: AtomicU64,
    /// Every entry numbered below this is on stable storage.
    synced: AtomicU64,
    /// A second handle on the journal file, used to fsync it without
    /// holding the writer; held while syncing, so a rotation cannot swap
    /// the file under a sync. See [`Self::sync_to`].
    syncer: Mutex<Option<File>>,
    /// Fsyncs this journal has done.
    fsyncs: AtomicU64,
    /// Last checkpoint sequence
    last_checkpoint: AtomicU64,
    /// Maximum journal size before rotation
    max_size: u64,
    /// Current journal size
    current_size: AtomicU64,
}

impl WriteJournal {
    /// Create or open a journal at the given path
    pub fn open<P: AsRef<Path>>(path: P, max_size: u64) -> BlockResult<Self> {
        let path = path.as_ref().to_path_buf();

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BlockError::Journal(format!("failed to create journal dir: {}", e)))?;
        }

        // Open or create journal file
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| BlockError::Journal(format!("failed to open journal: {}", e)))?;

        let file_len = file
            .metadata()
            .map_err(|e| BlockError::Journal(format!("failed to stat journal: {}", e)))?
            .len();

        let (sequence, last_checkpoint) = if file_len > 0 {
            // Existing journal - recover state
            let (seq, checkpoint) = Self::read_header(&file)?;
            (seq, checkpoint)
        } else {
            // New journal - write header
            let mut writer = BufWriter::new(file);
            Self::write_header(&mut writer, 0, 0)?;
            let _file = writer
                .into_inner()
                .map_err(|e| BlockError::Journal(format!("flush failed: {}", e)))?;
            (0, 0)
        };

        // Reopen for appending
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .map_err(|e| BlockError::Journal(format!("failed to reopen journal: {}", e)))?;

        let current_size = file
            .metadata()
            .map_err(|e| BlockError::Journal(format!("failed to stat journal: {}", e)))?
            .len();

        info!(
            "Opened journal at {:?}: seq={}, checkpoint={}, size={}",
            path, sequence, last_checkpoint, current_size
        );

        let syncer = file
            .try_clone()
            .map_err(|e| BlockError::Journal(format!("failed to clone journal handle: {}", e)))?;
        Ok(Self {
            path,
            writer: Mutex::new(Some(BufWriter::new(file))),
            sequence: AtomicU64::new(sequence),
            synced: AtomicU64::new(sequence),
            syncer: Mutex::new(Some(syncer)),
            fsyncs: AtomicU64::new(0),
            last_checkpoint: AtomicU64::new(last_checkpoint),
            max_size,
            current_size: AtomicU64::new(current_size),
        })
    }

    /// Write journal header
    fn write_header<W: Write>(writer: &mut W, sequence: u64, checkpoint: u64) -> BlockResult<()> {
        writer
            .write_all(&JOURNAL_MAGIC.to_le_bytes())
            .map_err(|e| BlockError::Journal(format!("failed to write magic: {}", e)))?;
        writer
            .write_all(&JOURNAL_VERSION.to_le_bytes())
            .map_err(|e| BlockError::Journal(format!("failed to write version: {}", e)))?;
        writer
            .write_all(&sequence.to_le_bytes())
            .map_err(|e| BlockError::Journal(format!("failed to write sequence: {}", e)))?;
        writer
            .write_all(&checkpoint.to_le_bytes())
            .map_err(|e| BlockError::Journal(format!("failed to write checkpoint: {}", e)))?;
        writer
            .flush()
            .map_err(|e| BlockError::Journal(format!("failed to flush header: {}", e)))?;
        Ok(())
    }

    /// Read journal header
    fn read_header(file: &File) -> BlockResult<(u64, u64)> {
        let mut reader = BufReader::new(file);
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|e| BlockError::Journal(format!("failed to seek: {}", e)))?;

        let mut magic_buf = [0u8; 8];
        reader
            .read_exact(&mut magic_buf)
            .map_err(|e| BlockError::Journal(format!("failed to read magic: {}", e)))?;
        let magic = u64::from_le_bytes(magic_buf);
        if magic != JOURNAL_MAGIC {
            return Err(BlockError::Journal("invalid journal magic".to_string()));
        }

        let mut version_buf = [0u8; 4];
        reader
            .read_exact(&mut version_buf)
            .map_err(|e| BlockError::Journal(format!("failed to read version: {}", e)))?;
        let version = u32::from_le_bytes(version_buf);
        if version != JOURNAL_VERSION {
            return Err(BlockError::Journal(format!(
                "unsupported journal version: {}",
                version
            )));
        }

        let mut seq_buf = [0u8; 8];
        reader
            .read_exact(&mut seq_buf)
            .map_err(|e| BlockError::Journal(format!("failed to read sequence: {}", e)))?;
        let sequence = u64::from_le_bytes(seq_buf);

        let mut checkpoint_buf = [0u8; 8];
        reader
            .read_exact(&mut checkpoint_buf)
            .map_err(|e| BlockError::Journal(format!("failed to read checkpoint: {}", e)))?;
        let checkpoint = u64::from_le_bytes(checkpoint_buf);

        Ok((sequence, checkpoint))
    }

    /// Append a journal entry
    pub fn append(&self, entry: &JournalEntry) -> BlockResult<u64> {
        let data = entry.serialize();
        let data_len = data.len() as u64;

        let mut writer_guard = self.writer.lock();
        let writer = writer_guard
            .as_mut()
            .ok_or_else(|| BlockError::Journal("journal closed".to_string()))?;

        writer
            .write_all(&data)
            .map_err(|e| BlockError::Journal(format!("write failed: {}", e)))?;
        writer
            .flush()
            .map_err(|e| BlockError::Journal(format!("flush failed: {}", e)))?;

        self.current_size.fetch_add(data_len, Ordering::SeqCst);
        let seq = self.sequence.fetch_add(1, Ordering::SeqCst);

        Ok(seq)
    }

    /// Log a write operation
    pub fn log_write(
        &self,
        volume_id: &str,
        chunk_id: ChunkId,
        offset: u64,
        data: Bytes,
    ) -> BlockResult<u64> {
        let seq = self.sequence.load(Ordering::SeqCst);
        let entry = JournalEntry::write(seq, volume_id.to_string(), chunk_id, offset, data);
        self.append(&entry)
    }

    /// Log a flush completion
    pub fn log_flush(&self, volume_id: &str, chunk_id: ChunkId) -> BlockResult<u64> {
        let seq = self.sequence.load(Ordering::SeqCst);
        let entry = JournalEntry::flush(seq, volume_id.to_string(), chunk_id);
        self.append(&entry)
    }

    /// Write a checkpoint
    pub fn checkpoint(&self) -> BlockResult<u64> {
        let seq = self.sequence.load(Ordering::SeqCst);
        let entry = JournalEntry::checkpoint(seq);
        let result = self.append(&entry)?;
        self.last_checkpoint.store(seq, Ordering::SeqCst);
        debug!("Journal checkpoint at sequence {}", seq);
        Ok(result)
    }

    /// Recover unflushed writes from journal
    pub fn recover(&self) -> BlockResult<Vec<JournalEntry>> {
        let file = File::open(&self.path)
            .map_err(|e| BlockError::Journal(format!("failed to open for recovery: {}", e)))?;

        let mut reader = BufReader::new(file);

        // Skip header
        reader
            .seek(SeekFrom::Start(28)) // 8 + 4 + 8 + 8 bytes
            .map_err(|e| BlockError::Journal(format!("failed to seek past header: {}", e)))?;

        // Writes after the last checkpoint, in file order. Sequence numbers
        // are not compared: they restart whenever the journal is reopened,
        // so filtering on them dropped writes made since a restart.
        let mut entries = Vec::new();
        // The journal ends at the first entry that can't be read whole or
        // fails its checksum: a write torn by a crash, never acknowledged.
        while let Ok((entry_type, mut entry)) = JournalEntry::read_raw(&mut reader) {
            match EntryType::try_from(entry_type) {
                Ok(t) => entry.entry_type = t,
                // Whole and checksummed, with a type this release doesn't
                // know: a newer release wrote it. Stopping here would drop
                // it and every write after it, so refuse instead.
                Err(_) if entry.checksum == entry.checksum_with_type(entry_type) => {
                    return Err(BlockError::Journal(format!(
                        "journal entry {} has type {entry_type}, which this release doesn't \
                         know (written by a newer one?); refusing to recover rather than drop \
                         it and the writes after it",
                        entry.sequence
                    )));
                }
                Err(_) => {
                    warn!(
                        "Journal entry {} is torn (unknown type, bad checksum); stopping recovery",
                        entry.sequence
                    );
                    break;
                }
            }
            if !entry.verify() {
                warn!(
                    "Journal entry {} failed checksum, stopping recovery",
                    entry.sequence
                );
                break;
            }
            match entry.entry_type {
                EntryType::Checkpoint => entries.clear(),
                EntryType::Write => entries.push(entry),
                EntryType::Flush => {}
            }
        }

        info!("Recovered {} journal entries", entries.len());
        Ok(entries)
    }

    /// Check if journal needs rotation
    pub fn needs_rotation(&self) -> bool {
        self.current_size.load(Ordering::SeqCst) > self.max_size
    }

    /// Rotate journal (create new one, discard old)
    pub fn rotate(&self) -> BlockResult<()> {
        // No sync runs while the file is swapped: a sync started on the old
        // file must not be taken as covering entries in the new one.
        let mut syncer = self.syncer.lock();
        // Close current journal
        {
            let mut writer_guard = self.writer.lock();
            *writer_guard = None;
        }

        // Rename old journal
        let old_path = self.path.with_extension("old");
        std::fs::rename(&self.path, &old_path)
            .map_err(|e| BlockError::Journal(format!("failed to rename old journal: {}", e)))?;

        // Create new journal
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|e| BlockError::Journal(format!("failed to create new journal: {}", e)))?;

        *syncer =
            Some(file.try_clone().map_err(|e| {
                BlockError::Journal(format!("failed to clone journal handle: {}", e))
            })?);
        drop(syncer);
        let mut writer = BufWriter::new(file);
        let seq = self.sequence.load(Ordering::SeqCst);
        Self::write_header(&mut writer, seq, seq)?;

        {
            let mut writer_guard = self.writer.lock();
            *writer_guard = Some(writer);
        }

        self.last_checkpoint.store(seq, Ordering::SeqCst);
        self.current_size.store(28, Ordering::SeqCst); // Header size

        // Delete old journal
        if let Err(e) = std::fs::remove_file(&old_path) {
            warn!("Failed to remove old journal: {}", e);
        }

        info!("Rotated journal at sequence {}", seq);
        Ok(())
    }

    /// Fsyncs this journal has done.
    pub fn fsyncs(&self) -> u64 {
        self.fsyncs.load(Ordering::Relaxed)
    }

    /// Make every entry appended so far durable.
    pub fn sync(&self) -> BlockResult<()> {
        self.sync_to(self.sequence.load(Ordering::SeqCst))
    }

    /// Make every entry numbered below `upto` durable: group commit.
    ///
    /// One fsync covers every entry written to the OS before it started,
    /// so concurrent writers share it instead of queueing for one each:
    /// a writer that finds its entry already covered returns at once, and
    /// one that waited on the sync lock usually finds the sync just done
    /// covered it. The fsync goes through a second handle without the
    /// writer lock, so appends carry on while it runs. (It used to hold the
    /// writer lock, and the next writer held the cache lock waiting for it:
    /// every write in the gateway queued behind one fsync at a time.)
    pub fn sync_to(&self, upto: u64) -> BlockResult<()> {
        if self.synced.load(Ordering::SeqCst) >= upto {
            return Ok(());
        }
        let syncer = self.syncer.lock();
        if self.synced.load(Ordering::SeqCst) >= upto {
            return Ok(());
        }
        // Everything numbered below `target` is in the OS already: the
        // sequence moves on only after the writer is flushed.
        let target = self.sequence.load(Ordering::SeqCst);
        if let Some(file) = syncer.as_ref() {
            let started = std::time::Instant::now();
            file.sync_data()
                .map_err(|e| BlockError::Journal(format!("sync failed: {}", e)))?;
            SYNC_SECONDS.observe_duration(started.elapsed());
            self.fsyncs.fetch_add(1, Ordering::Relaxed);
            SYNCED_ENTRIES.fetch_add(
                target.saturating_sub(self.synced.load(Ordering::SeqCst)),
                Ordering::Relaxed,
            );
        }
        self.synced.fetch_max(target, Ordering::SeqCst);
        Ok(())
    }
}

/// Time of each journal fsync: every acknowledged block write waits for one.
static SYNC_SECONDS: std::sync::LazyLock<objectio_common::histogram::Histogram> =
    std::sync::LazyLock::new(|| {
        objectio_common::histogram::Histogram::new(objectio_common::histogram::LATENCY_BUCKETS)
    });

/// Journal entries made durable, counted once each: entries per fsync is
/// `objectio_block_journal_entries_synced_total / …_fsync_seconds_count`.
static SYNCED_ENTRIES: AtomicU64 = AtomicU64::new(0);

/// The journal's metrics, as Prometheus text.
pub fn render_metrics(out: &mut String) {
    let n = SYNCED_ENTRIES.load(Ordering::Relaxed);
    out.push_str(&format!(
        "# HELP objectio_block_journal_entries_synced_total Journal entries made durable; divided by fsyncs, the group-commit size\n\
         # TYPE objectio_block_journal_entries_synced_total counter\n\
         objectio_block_journal_entries_synced_total {n}\n"
    ));
    SYNC_SECONDS.render(
        out,
        "objectio_block_journal_fsync_seconds",
        "Time to fsync the block write journal; every acknowledged write waits for one",
        "",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An entry with a type this release doesn't know, appended to a
    /// journal holding one write: `checksum_ok` says whether it is whole.
    fn journal_with_unknown_entry(checksum_ok: bool) -> (tempfile::TempDir, WriteJournal) {
        use std::io::Write as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j");
        {
            let journal = WriteJournal::open(&path, 1 << 30).unwrap();
            let seq = journal
                .log_write("v", 0, 0, Bytes::from(vec![1u8; 512]))
                .unwrap();
            journal.sync_to(seq + 1).unwrap();
        }
        let mut entry = JournalEntry::write(99, "v".into(), 1, 0, Bytes::from(vec![2u8; 512]));
        if checksum_ok {
            entry.checksum = entry.checksum_with_type(9);
        }
        let mut bytes = entry.serialize();
        bytes[8] = 9; // the type byte, after the sequence
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&bytes)
            .unwrap();
        let journal = WriteJournal::open(&path, 1 << 30).unwrap();
        (dir, journal)
    }

    /// A whole entry of an unknown type was written by a newer release:
    /// recovery refuses rather than drop it and everything after it.
    #[test]
    fn recovery_refuses_an_entry_type_it_does_not_know() {
        let (_dir, journal) = journal_with_unknown_entry(true);
        let err = journal.recover().unwrap_err();
        assert!(err.to_string().contains("type 9"), "{err}");
    }

    /// A torn entry (its checksum doesn't match) is the end of the journal,
    /// as before.
    #[test]
    fn recovery_stops_at_a_torn_entry() {
        let (_dir, journal) = journal_with_unknown_entry(false);
        assert_eq!(journal.recover().unwrap().len(), 1);
    }

    /// Group commit: writers syncing at once share fsyncs, and every one
    /// of their entries is in the journal afterwards.
    #[test]
    fn concurrent_writers_share_fsyncs_and_lose_nothing() {
        const THREADS: u64 = 8;
        const EACH: u64 = 50;
        let dir = tempfile::tempdir().unwrap();
        let journal =
            std::sync::Arc::new(WriteJournal::open(dir.path().join("j"), 1 << 30).unwrap());
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let j = std::sync::Arc::clone(&journal);
                std::thread::spawn(move || {
                    for i in 0..EACH {
                        let seq = j
                            .log_write("v", t, i * 4096, Bytes::from(vec![t as u8; 4096]))
                            .unwrap();
                        j.sync_to(seq + 1).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let writes = THREADS * EACH;
        assert_eq!(journal.recover().unwrap().len() as u64, writes);
        assert!(
            journal.fsyncs() < writes,
            "{} fsyncs for {writes} writes: none were shared",
            journal.fsyncs()
        );
        // Everything is durable: another sync has nothing to do.
        let before = journal.fsyncs();
        journal.sync().unwrap();
        assert_eq!(journal.fsyncs(), before);
    }
    use tempfile::tempdir;

    #[test]
    fn test_journal_entry_serialization() {
        let entry = JournalEntry::write(
            42,
            "vol-123".to_string(),
            5,
            1024,
            Bytes::from(vec![0xAB; 100]),
        );

        assert!(entry.verify());

        let data = entry.serialize();
        let mut reader = std::io::Cursor::new(data);
        let recovered = JournalEntry::deserialize(&mut reader).unwrap();

        assert_eq!(recovered.sequence, 42);
        assert_eq!(recovered.volume_id, "vol-123");
        assert_eq!(recovered.chunk_id, 5);
        assert_eq!(recovered.offset, 1024);
        assert_eq!(recovered.data.as_ref().unwrap().len(), 100);
        assert!(recovered.verify());
    }

    #[test]
    fn test_journal_write_and_recover() {
        let dir = tempdir().unwrap();
        let journal_path = dir.path().join("test.journal");

        // Write some entries
        {
            let journal = WriteJournal::open(&journal_path, 1024 * 1024).unwrap();
            journal
                .log_write("vol1", 0, 0, Bytes::from(vec![1; 100]))
                .unwrap();
            journal
                .log_write("vol1", 1, 0, Bytes::from(vec![2; 100]))
                .unwrap();
            journal.checkpoint().unwrap();
            journal
                .log_write("vol1", 2, 0, Bytes::from(vec![3; 100]))
                .unwrap();
        }

        // Recover
        {
            let journal = WriteJournal::open(&journal_path, 1024 * 1024).unwrap();
            let entries = journal.recover().unwrap();

            // Only entry after checkpoint should be recovered
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].chunk_id, 2);
        }
    }
}
