//! Write-ahead journal for block storage durability
//!
//! Provides crash recovery for the write cache by persisting write operations
//! to a journal file before acknowledging them to the client.

use crate::chunk::ChunkId;
use crate::error::{BlockError, BlockResult};

use bytes::Bytes;
use objectio_common::log_tail::{ReadAt, whole_record_after};
use parking_lot::Mutex;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, error, info, warn};

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

/// The journal file's header: magic, version, sequence, checkpoint.
const HEADER_LEN: u64 = 8 + 4 + 8 + 8;

/// An entry's bytes before its volume ID: sequence, type, the ID's length.
const ENTRY_PREFIX: usize = 8 + 1 + 2;

/// An entry's bytes after its volume ID and before its data: chunk,
/// offset, the data's length.
const ENTRY_MIDDLE: usize = 8 + 8 + 4;

/// The smallest entry: no volume ID, no data.
const MIN_ENTRY: u64 = (ENTRY_PREFIX + ENTRY_MIDDLE + 4) as u64;

/// The most data one entry holds: the gateway takes no larger write (its
/// gRPC message limit; NBD requests are smaller still). A length past it
/// is damage, and is not allocated.
pub const MAX_ENTRY_DATA: usize = 64 << 20;

/// Bytes enough to find any entry's length from its start.
const PROBE_LEN: usize = ENTRY_PREFIX + u16::MAX as usize + ENTRY_MIDDLE;

/// The length of the entry at `offset` in `src`, if its header holds
/// together and the entry fits in the `remaining` bytes from there.
fn entry_len_at<R: ReadAt + ?Sized>(
    src: &R,
    offset: u64,
    remaining: u64,
) -> std::io::Result<Option<u64>> {
    if remaining < MIN_ENTRY {
        return Ok(None);
    }
    let mut prefix = [0u8; ENTRY_PREFIX];
    src.read_exact_at(&mut prefix, offset)?;
    let vol_len = u64::from(u16::from_le_bytes([prefix[9], prefix[10]]));
    let data_len_at = (ENTRY_PREFIX + ENTRY_MIDDLE - 4) as u64 + vol_len;
    if data_len_at + 8 > remaining {
        return Ok(None);
    }
    let mut data_len = [0u8; 4];
    src.read_exact_at(&mut data_len, offset + data_len_at)?;
    let data_len = u32::from_le_bytes(data_len);
    if data_len as usize > MAX_ENTRY_DATA {
        return Ok(None);
    }
    let total = data_len_at + 4 + u64::from(data_len) + 4;
    Ok((total <= remaining).then_some(total))
}

/// Make a new name (or a rename) in `path`'s directory durable.
fn sync_dir(path: &Path) -> BlockResult<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| BlockError::Journal(format!("failed to sync {}: {e}", dir.display())))
}

/// A journal holding only its header, at sequence `sequence`, written
/// beside `path` and synced; the caller renames it over `path` and syncs
/// the directory. A crash then leaves the old journal or this one under the
/// name, never a header cut short, nor a name that a power cut takes back
/// after writes to the new file were acknowledged.
fn new_journal(path: &Path, sequence: u64) -> BlockResult<(PathBuf, File)> {
    let tmp = path.with_extension("new");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)
        .map_err(|e| BlockError::Journal(format!("failed to create journal: {e}")))?;
    WriteJournal::write_header(&mut file, sequence, sequence)
        .and_then(|()| {
            file.sync_all()
                .map_err(|e| BlockError::Journal(format!("failed to sync new journal: {e}")))
        })
        .inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })?;
    Ok((tmp, file))
}

/// Write-ahead journal for block storage.
///
/// Fail-stop: a write or sync that fails leaves the journal refusing every
/// write after it until it is opened again, and an open refuses a journal
/// damaged anywhere but at its end (objectio-docs `block/block-write-path.md`).
pub struct WriteJournal {
    /// Journal file path
    path: PathBuf,
    /// The journal file, written unbuffered: an entry is handed to the OS
    /// in the append that makes it. (Behind a `BufWriter`, a write that
    /// failed stayed in the buffer, to go out ahead of the next entry.)
    writer: Mutex<Option<File>>,
    /// Next sequence number. Every entry numbered below it has been
    /// written to the OS (it moves on only once the entry is written).
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
    /// Bytes of whole entries in the file, and its header: where the next
    /// entry goes.
    current_size: AtomicU64,
    /// The first write or sync that failed, if one has: the journal takes
    /// no write after it. What a failed write left in the file is unknown,
    /// and after a failed `fdatasync` Linux marks the pages it couldn't
    /// write clean, so the next one can succeed without them: a write
    /// acknowledged then would sit behind a hole. Opening the journal again
    /// finds where it really ends.
    failed: OnceLock<String>,
    #[cfg(test)]
    faults: Faults,
}

/// Disk failures a test makes the journal meet.
#[cfg(test)]
#[derive(Default)]
struct Faults {
    /// The next write fails after writing this many bytes.
    write: Mutex<Option<usize>>,
    /// The next sync fails.
    sync: std::sync::atomic::AtomicBool,
}

impl WriteJournal {
    /// Create or open a journal at the given path.
    ///
    /// An existing journal is read whole: its torn end, an entry a crash
    /// cut short (never acknowledged), is cut off, so that what is written
    /// next follows the last whole entry.
    ///
    /// # Errors
    /// I/O; a header this release doesn't read; a whole entry of a type it
    /// doesn't know; or a damaged entry with a whole one after it, which is
    /// damage, not a torn write (objectio-common `log_tail`).
    pub fn open<P: AsRef<Path>>(path: P, max_size: u64) -> BlockResult<Self> {
        let path = path.as_ref().to_path_buf();

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| BlockError::Journal(format!("failed to create journal dir: {}", e)))?;
        }

        let existing = match File::open(&path) {
            Ok(f) => {
                let len = f
                    .metadata()
                    .map_err(|e| BlockError::Journal(format!("failed to stat journal: {e}")))?
                    .len();
                (len > 0).then_some((f, len))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(BlockError::Journal(format!("failed to open journal: {e}"))),
        };

        let (file, sequence, last_checkpoint, current_size) = match existing {
            Some((file, len)) => {
                let (sequence, checkpoint) = Self::read_header(&file)?;
                let end = Self::scan(&path, &file, len, |_, _| {})?;
                if end < len {
                    Self::refuse_damage(&path, &file, end, len, sequence)?;
                    warn!(
                        "Journal {}: cutting a torn entry at byte {end}, {} bytes (a crash \
                         during a write)",
                        path.display(),
                        len - end
                    );
                }
                let file = OpenOptions::new()
                    .read(true)
                    .append(true)
                    .open(&path)
                    .map_err(|e| BlockError::Journal(format!("failed to reopen journal: {e}")))?;
                if end < len {
                    file.set_len(end)
                        .and_then(|()| file.sync_all())
                        .map_err(|e| {
                            BlockError::Journal(format!("failed to cut the journal's tail: {e}"))
                        })?;
                }
                (file, sequence, checkpoint, end)
            }
            None => {
                let (tmp, file) = new_journal(&path, 0)?;
                std::fs::rename(&tmp, &path).map_err(|e| {
                    BlockError::Journal(format!("failed to put the new journal in place: {e}"))
                })?;
                sync_dir(&path)?;
                (file, 0, 0, HEADER_LEN)
            }
        };

        info!(
            "Opened journal at {:?}: seq={}, checkpoint={}, size={}",
            path, sequence, last_checkpoint, current_size
        );

        let syncer = file
            .try_clone()
            .map_err(|e| BlockError::Journal(format!("failed to clone journal handle: {}", e)))?;
        Ok(Self {
            path,
            writer: Mutex::new(Some(file)),
            sequence: AtomicU64::new(sequence),
            synced: AtomicU64::new(sequence),
            syncer: Mutex::new(Some(syncer)),
            fsyncs: AtomicU64::new(0),
            last_checkpoint: AtomicU64::new(last_checkpoint),
            max_size,
            current_size: AtomicU64::new(current_size),
            failed: OnceLock::new(),
            #[cfg(test)]
            faults: Faults::default(),
        })
    }

    /// Read the entries of the journal `file` (`len` bytes) after its
    /// header, giving each whole one to `f`; where the last whole one
    /// ends. That is short of `len` when an entry is cut short or fails
    /// its checksum.
    ///
    /// # Errors
    /// I/O, or a whole, checksummed entry of a type this release doesn't
    /// know: a newer release wrote it, and stopping there would drop it and
    /// every write after it.
    fn scan(
        path: &Path,
        file: &File,
        len: u64,
        mut f: impl FnMut(EntryType, JournalEntry),
    ) -> BlockResult<u64> {
        let io = |e: std::io::Error| {
            BlockError::Journal(format!("failed to read journal {}: {e}", path.display()))
        };
        let mut offset = HEADER_LEN;
        while offset < len {
            let Some(entry_len) = entry_len_at(file, offset, len - offset).map_err(io)? else {
                break;
            };
            let mut bytes = vec![0u8; usize::try_from(entry_len).unwrap_or(usize::MAX)];
            file.read_exact_at(&mut bytes, offset).map_err(io)?;
            let Ok((entry_type, mut entry)) =
                JournalEntry::read_raw(&mut std::io::Cursor::new(&bytes))
            else {
                break;
            };
            if entry.checksum != entry.checksum_with_type(entry_type) {
                break;
            }
            match EntryType::try_from(entry_type) {
                Ok(t) => entry.entry_type = t,
                Err(_) => {
                    return Err(BlockError::Journal(format!(
                        "journal entry {} has type {entry_type}, which this release doesn't \
                         know (written by a newer one?); refusing to recover rather than drop \
                         it and the writes after it",
                        entry.sequence
                    )));
                }
            }
            f(entry.entry_type, entry);
            offset += entry_len;
        }
        Ok(offset.min(len))
    }

    /// Refuse a journal whose entry at `bad` is damaged with a whole entry
    /// after it: that is damage to an entry that was synced, not a torn
    /// write, and the entries after it may have been acknowledged. Entries
    /// are numbered on from the header's `sequence`, one per
    /// [`MIN_ENTRY`] bytes at most.
    fn refuse_damage(
        path: &Path,
        file: &File,
        bad: u64,
        len: u64,
        sequence: u64,
    ) -> BlockResult<()> {
        let most = sequence.saturating_add(len / MIN_ENTRY);
        let mut found = 0u64;
        let after = whole_record_after(
            file,
            bad,
            len,
            PROBE_LEN,
            |at, head| {
                let seq = u64::from_le_bytes(head.get(..8)?.try_into().ok()?);
                if seq < sequence || seq > most {
                    return None;
                }
                entry_len_at(head, 0, len - at).ok().flatten()
            },
            |_, bytes| match JournalEntry::read_raw(&mut std::io::Cursor::new(bytes)) {
                Ok((t, entry)) if entry.checksum == entry.checksum_with_type(t) => {
                    found = entry.sequence;
                    true
                }
                _ => false,
            },
        )
        .map_err(|e| BlockError::Journal(format!("failed to read journal: {e}")))?;
        match after {
            None => Ok(()),
            Some(at) => Err(BlockError::Journal(format!(
                "journal {}: the entry at byte {bad} is damaged, and entry {found} follows it \
                 whole at byte {at}: damage, not a torn write; refusing to open rather than \
                 drop the writes after it",
                path.display()
            ))),
        }
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

    /// The error for a write or sync that failed, which from now on fails
    /// every write: see `failed`.
    fn fail(&self, what: &str, e: impl std::fmt::Display) -> BlockError {
        let cause = format!("{what} failed: {e}");
        if self.failed.set(cause.clone()).is_ok() {
            error!(
                "Journal {}: {cause}; refusing every write until it is reopened",
                self.path.display()
            );
        }
        BlockError::Journal(format!("journal {}: {cause}", self.path.display()))
    }

    /// Refuse if a write or sync has failed.
    fn check(&self) -> BlockResult<()> {
        match self.failed.get() {
            None => Ok(()),
            Some(cause) => Err(BlockError::Journal(format!(
                "journal {}: takes no writes after an earlier failure ({cause}) until it is \
                 reopened",
                self.path.display()
            ))),
        }
    }

    /// Append a journal entry
    ///
    /// # Errors
    /// The entry is larger than an entry may be, or the write failed, now
    /// or earlier (`failed`).
    pub fn append(&self, entry: &JournalEntry) -> BlockResult<u64> {
        if entry
            .data
            .as_ref()
            .is_some_and(|d| d.len() > MAX_ENTRY_DATA)
            || u16::try_from(entry.volume_id.len()).is_err()
        {
            return Err(BlockError::Journal(format!(
                "journal entry for {} is too large",
                entry.volume_id
            )));
        }
        let data = entry.serialize();
        let data_len = data.len() as u64;

        let mut writer_guard = self.writer.lock();
        self.check()?;
        let writer = writer_guard
            .as_mut()
            .ok_or_else(|| BlockError::Journal("journal closed".to_string()))?;

        #[cfg(test)]
        if let Some(after) = self.faults.write.lock().take() {
            let _ = writer.write_all(&data[..after.min(data.len())]);
            return Err(self.fail("write", "injected write failure"));
        }
        writer.write_all(&data).map_err(|e| self.fail("write", e))?;

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
    ///
    /// # Errors
    /// I/O, or an entry that no longer reads back whole: the open checked
    /// the journal, and every entry since was written whole.
    pub fn recover(&self) -> BlockResult<Vec<JournalEntry>> {
        let file = File::open(&self.path)
            .map_err(|e| BlockError::Journal(format!("failed to open for recovery: {}", e)))?;
        // What the appends so far wrote whole: not what a failed one left.
        let len = self.current_size.load(Ordering::SeqCst);

        // Writes after the last checkpoint, in file order. Sequence numbers
        // are not compared: they restart whenever the journal is reopened,
        // so filtering on them dropped writes made since a restart.
        let mut entries = Vec::new();
        let end = Self::scan(
            &self.path,
            &file,
            len,
            |entry_type, entry| match entry_type {
                EntryType::Checkpoint => entries.clear(),
                EntryType::Write => entries.push(entry),
                EntryType::Flush => {}
            },
        )?;
        if end < len {
            return Err(BlockError::Journal(format!(
                "journal {}: the entry at byte {end} no longer reads back whole (damage); \
                 refusing to recover rather than drop the writes after it",
                self.path.display()
            )));
        }

        info!("Recovered {} journal entries", entries.len());
        Ok(entries)
    }

    /// Check if journal needs rotation
    pub fn needs_rotation(&self) -> bool {
        self.current_size.load(Ordering::SeqCst) > self.max_size
    }

    /// Rotate journal: replace it with an empty one.
    ///
    /// The new journal is written and synced beside the old one, renamed
    /// over it, and the directory synced, before any write goes to it: the
    /// name of a new file is durable only once its directory is synced, and
    /// a power cut before that took the journal back to the old one,
    /// without the writes acknowledged since.
    ///
    /// # Errors
    /// I/O. Up to the rename the old journal stays; a failure to make the
    /// rename durable fails the journal (`failed`).
    pub fn rotate(&self) -> BlockResult<()> {
        // No sync runs while the file is swapped: a sync started on the old
        // file must not be taken as covering entries in the new one.
        let mut syncer = self.syncer.lock();
        let mut writer = self.writer.lock();
        self.check()?;
        let seq = self.sequence.load(Ordering::SeqCst);
        let (tmp, file) = new_journal(&self.path, seq)?;
        let new_syncer = file
            .try_clone()
            .map_err(|e| BlockError::Journal(format!("failed to clone journal handle: {}", e)))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            BlockError::Journal(format!("failed to put the new journal in place: {e}"))
        })?;

        // The journal is the new file from here: writes go to it whatever
        // happens next. One left on the old file would write an inode
        // nothing reads any more.
        *writer = Some(file);
        *syncer = Some(new_syncer);
        self.last_checkpoint.store(seq, Ordering::SeqCst);
        self.current_size.store(HEADER_LEN, Ordering::SeqCst);
        sync_dir(&self.path).map_err(|e| self.fail("sync of the rotated journal", e))?;

        info!("Rotated journal at sequence {}", seq);
        Ok(())
    }

    /// Fsyncs this journal has done.
    pub fn fsyncs(&self) -> u64 {
        self.fsyncs.load(Ordering::Relaxed)
    }

    /// Make every entry appended so far durable.
    ///
    /// # Errors
    /// The sync failed, now or a write or sync earlier (`failed`).
    pub fn sync(&self) -> BlockResult<()> {
        self.check()?;
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
    ///
    /// # Errors
    /// The sync failed, now or a write or sync earlier (`failed`).
    pub fn sync_to(&self, upto: u64) -> BlockResult<()> {
        if self.synced.load(Ordering::SeqCst) >= upto {
            return Ok(());
        }
        let syncer = self.syncer.lock();
        if self.synced.load(Ordering::SeqCst) >= upto {
            return Ok(());
        }
        // A sync that failed while this one waited was reported once, to
        // its caller: one now could succeed without this entry on disk.
        self.check()?;
        // Everything numbered below `target` is in the OS already: the
        // sequence moves on only after the entry is written.
        let target = self.sequence.load(Ordering::SeqCst);
        if let Some(file) = syncer.as_ref() {
            let started = std::time::Instant::now();
            #[cfg(test)]
            if self.faults.sync.swap(false, Ordering::SeqCst) {
                return Err(self.fail("sync", "injected sync failure"));
            }
            file.sync_data().map_err(|e| self.fail("sync", e))?;
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
    fn journal_with_unknown_entry(
        checksum_ok: bool,
    ) -> (tempfile::TempDir, BlockResult<WriteJournal>) {
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
        let journal = WriteJournal::open(&path, 1 << 30);
        (dir, journal)
    }

    /// A whole entry of an unknown type was written by a newer release:
    /// the open refuses rather than drop it and everything after it.
    #[test]
    fn recovery_refuses_an_entry_type_it_does_not_know() {
        let (_dir, journal) = journal_with_unknown_entry(true);
        let err = journal.err().expect("refused");
        assert!(err.to_string().contains("type 9"), "{err}");
    }

    /// A torn entry (its checksum doesn't match) is the end of the journal,
    /// as before.
    #[test]
    fn recovery_stops_at_a_torn_entry() {
        let (_dir, journal) = journal_with_unknown_entry(false);
        assert_eq!(journal.unwrap().recover().unwrap().len(), 1);
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

/// The journal at its ends: a torn tail is cut at open and what is written
/// after it survives; damage with whole entries after it stops the open;
/// a failed write or sync stops every write after it.
#[cfg(test)]
mod fail_stop_tests {
    use super::*;

    fn write_synced(journal: &WriteJournal, chunk: ChunkId) {
        let seq = journal
            .log_write(
                "v",
                chunk,
                0,
                Bytes::from(vec![u8::try_from(chunk).unwrap(); 512]),
            )
            .unwrap();
        journal.sync_to(seq + 1).unwrap();
    }

    fn chunks(journal: &WriteJournal) -> Vec<ChunkId> {
        journal
            .recover()
            .unwrap()
            .iter()
            .map(|e| e.chunk_id)
            .collect()
    }

    fn append_raw(path: &Path, bytes: &[u8]) {
        OpenOptions::new()
            .append(true)
            .open(path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
    }

    /// A crash tears the last entry; after the restart a write is
    /// acknowledged. It went in behind the torn bytes, and the next
    /// restart, stopping at them, lost it.
    #[test]
    fn a_write_after_a_torn_tail_survives_the_next_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j");
        write_synced(&WriteJournal::open(&path, 1 << 30).unwrap(), 1);
        let torn =
            JournalEntry::write(1, "v".into(), 2, 0, Bytes::from(vec![2u8; 512])).serialize();
        append_raw(&path, &torn[..100]);

        write_synced(&WriteJournal::open(&path, 1 << 30).unwrap(), 3);
        let journal = WriteJournal::open(&path, 1 << 30).unwrap();
        assert_eq!(chunks(&journal), vec![1, 3]);
    }

    /// Damage to an entry with whole ones after it is not a torn write:
    /// the open refuses, and leaves the file as it was.
    #[test]
    fn damage_with_whole_entries_after_it_refuses_the_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j");
        let second;
        {
            let journal = WriteJournal::open(&path, 1 << 30).unwrap();
            write_synced(&journal, 1);
            second = std::fs::metadata(&path).unwrap().len();
            write_synced(&journal, 2);
            write_synced(&journal, 3);
        }
        let mut data = std::fs::read(&path).unwrap();
        data[usize::try_from(second).unwrap() + 100] ^= 0xff;
        std::fs::write(&path, &data).unwrap();

        let refused = WriteJournal::open(&path, 1 << 30)
            .and_then(|j| j.recover().map(|_| ()))
            .expect_err("refused");
        assert!(refused.to_string().contains("damage"), "{refused}");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), data.len() as u64);
    }

    /// A length a corrupt header claims, past the end of the file, is a
    /// torn entry, cut, not read (it was allocated whole, up to 4 GiB).
    #[test]
    fn a_length_past_the_end_is_cut_not_allocated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j");
        write_synced(&WriteJournal::open(&path, 1 << 30).unwrap(), 1);
        let mut entry = JournalEntry::write(1, "v".into(), 2, 0, Bytes::new()).serialize();
        let len_at = entry.len() - 8;
        entry[len_at..len_at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        append_raw(&path, &entry);
        let journal = WriteJournal::open(&path, 1 << 30).unwrap();
        assert_eq!(chunks(&journal), vec![1]);
    }

    /// A write that fails part way fails, and so does every write after
    /// it, and a sync; reopened, the journal holds what was acknowledged
    /// and takes writes again.
    #[test]
    fn after_a_failed_write_every_write_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j");
        {
            let journal = WriteJournal::open(&path, 1 << 30).unwrap();
            write_synced(&journal, 1);
            journal.fail_next_write(40);
            assert!(
                journal
                    .log_write("v", 2, 0, Bytes::from(vec![2u8; 512]))
                    .is_err()
            );
            assert!(
                journal
                    .log_write("v", 3, 0, Bytes::from(vec![3u8; 512]))
                    .is_err(),
                "a write after a failed one"
            );
            assert!(journal.sync().is_err());
        }
        let journal = WriteJournal::open(&path, 1 << 30).unwrap();
        assert_eq!(chunks(&journal), vec![1]);
        write_synced(&journal, 4);
        drop(journal);
        assert_eq!(
            chunks(&WriteJournal::open(&path, 1 << 30).unwrap()),
            vec![1, 4]
        );
    }

    /// A failed fsync: the next one may succeed with the pages it didn't
    /// write still not on disk (Linux marks them clean), so every write
    /// after it is refused.
    #[test]
    fn after_a_failed_sync_every_write_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let journal = WriteJournal::open(dir.path().join("j"), 1 << 30).unwrap();
        write_synced(&journal, 1);
        journal.fail_next_sync();
        let seq = journal
            .log_write("v", 2, 0, Bytes::from(vec![2u8; 512]))
            .unwrap();
        assert!(journal.sync_to(seq + 1).is_err());
        let after = journal.log_write("v", 3, 0, Bytes::from(vec![3u8; 512]));
        assert!(
            after.is_err() || journal.sync().is_err(),
            "a write after a failed sync acknowledged"
        );
    }

    /// A rotation leaves the journal empty under its name, with nothing
    /// beside it, and writes after it survive a reopen.
    #[test]
    fn writes_after_a_rotation_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j");
        {
            let journal = WriteJournal::open(&path, 1 << 30).unwrap();
            write_synced(&journal, 1);
            journal.rotate().unwrap();
            assert!(chunks(&journal).is_empty());
            write_synced(&journal, 2);
        }
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("j")]);
        assert_eq!(
            chunks(&WriteJournal::open(&path, 1 << 30).unwrap()),
            vec![2]
        );
    }
}
