//! Meta's Raft log, in files of its own (B25; objectio-docs
//! `core/meta-log.md`).
//!
//! The log lives in a directory of segments, `<first index, 20 digits>.log`,
//! each up to [`SEGMENT_BYTES`]. A record is
//!
//! ```text
//! len u32 | crc32c u32 | index u64 | term u64 | entry (len bytes)
//! ```
//!
//! little-endian, the checksum over everything after it. An append is
//! written to the last segment and synced (`fdatasync`) before it returns;
//! a new segment is followed by a sync of the directory. Two small files
//! sit beside the segments: `purged` (the purged log id) and `committed`
//! (the commit index openraft last gave), each replaced whole through a
//! temporary file and a rename.
//!
//! A segment is sealed when the next one starts: an index of its records,
//! `<first index, 20 digits>.idx`, is written beside it (each record's
//! length and term, the segment's length, a checksum over all of it). It is
//! a shortcut only: written without a sync, and one that is missing, damaged
//! or describes another length is ignored and the segment read instead.
//!
//! Opening reads the last segment whole and checks every record; a sealed
//! segment with a valid index is not read (its records are checked when
//! they are read, as every record is), one without is read and checked and
//! its index written. So an open reads at most one segment and the indexes,
//! however long the log (B25: the reopen time bound). A torn record in the
//! last segment (a crash during an append, which was never acknowledged)
//! is cut off with everything after it; any other damage, or a gap in the
//! indexes, fails the open (or the read) with its position: a record is
//! never skipped.
//!
//! The log knows indexes and terms, not openraft: entries are opaque bytes
//! here, encoded by the caller.

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

/// A segment is closed, and a new one started, once it passes this size.
pub const SEGMENT_BYTES: u64 = 64 << 20;

/// `len`, `crc32c`, `index`, `term`.
const HEADER: usize = 4 + 4 + 8 + 8;

/// The unit a disk writes whole or not at all: what a crash leaves of a
/// write is some of its sectors, the rest reading as zeros.
const SECTOR: usize = 512;

/// The largest entry the log accepts (a corrupt length must not make the
/// open allocate gigabytes).
const MAX_ENTRY: u32 = 256 << 20;

const PURGED: &str = "purged";
const COMMITTED: &str = "committed";

/// A sealed segment's index: `magic | segment length u64 | first index u64
/// | first offset u64 | count u64 | (len u32, term u64) × count | crc32c
/// u32`, little-endian, the checksum over everything before it.
const INDEX_MAGIC: &[u8; 8] = b"OBIOIDX1";
const INDEX_HEADER: usize = 8 + 8 + 8 + 8 + 8;
const INDEX_RECORD: usize = 4 + 8;

/// Why the log couldn't be opened or written.
#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("raft log {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("raft log {path} at byte {offset}: {what}")]
    Corrupt {
        path: PathBuf,
        offset: u64,
        what: String,
    },
    #[error("raft log: {0}")]
    Misuse(String),
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> LogError + '_ {
    move |source| LogError::Io {
        path: path.to_path_buf(),
        source,
    }
}

struct Segment {
    first: u64,
    path: PathBuf,
    file: File,
    len: u64,
}

/// Where one record is.
#[derive(Clone, Copy)]
struct Pos {
    segment: usize,
    offset: u64,
    len: u32,
    term: u64,
}

/// The log: its segments, and where each record is.
pub struct RaftLog {
    dir: PathBuf,
    segments: Vec<Segment>,
    /// The position of every record from `first` on, in index order.
    positions: VecDeque<Pos>,
    /// The index of `positions[0]` (when there are records).
    first: u64,
}

fn sync_dir(dir: &Path) -> Result<(), LogError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io_err(dir))
}

fn segment_name(first: u64) -> String {
    format!("{first:020}.log")
}

fn index_name(first: u64) -> String {
    format!("{first:020}.idx")
}

/// The index of a sealed segment `seg_len` long whose records from
/// `first_index` on are `records` (the last ones in it).
fn encode_index(seg_len: u64, first_index: u64, records: &[Pos]) -> Vec<u8> {
    let mut b = Vec::with_capacity(INDEX_HEADER + records.len() * INDEX_RECORD + 4);
    b.extend_from_slice(INDEX_MAGIC);
    b.extend_from_slice(&seg_len.to_le_bytes());
    b.extend_from_slice(&first_index.to_le_bytes());
    b.extend_from_slice(&records.first().map_or(0, |p| p.offset).to_le_bytes());
    b.extend_from_slice(&(records.len() as u64).to_le_bytes());
    for p in records {
        b.extend_from_slice(&p.len.to_le_bytes());
        b.extend_from_slice(&p.term.to_le_bytes());
    }
    let crc = crc32c::crc32c(&b);
    b.extend_from_slice(&crc.to_le_bytes());
    b
}

/// The first index and the positions (in segment `segment`) an index
/// describes, if it is whole, and its records run exactly to the end of a
/// segment `seg_len` long. Anything else: `None`, and the segment is read.
fn decode_index(b: &[u8], segment: usize, seg_len: u64) -> Option<(u64, Vec<Pos>)> {
    let body_len = b.len().checked_sub(4)?;
    let (body, crc) = b.split_at(body_len);
    if body.len() < INDEX_HEADER || body[..8] != INDEX_MAGIC[..] {
        return None;
    }
    let crc: [u8; 4] = crc.try_into().ok()?;
    if crc32c::crc32c(body) != u32::from_le_bytes(crc) {
        return None;
    }
    let u64_at = |at: usize| u64::from_le_bytes(body[at..at + 8].try_into().unwrap());
    if u64_at(8) != seg_len {
        return None;
    }
    let first_index = u64_at(16);
    let mut offset = u64_at(24);
    let count = usize::try_from(u64_at(32)).ok()?;
    if body.len() != INDEX_HEADER + count.checked_mul(INDEX_RECORD)? {
        return None;
    }
    let mut positions = Vec::with_capacity(count);
    for r in body[INDEX_HEADER..].chunks_exact(INDEX_RECORD) {
        let len = u32::from_le_bytes(r[0..4].try_into().unwrap());
        let term = u64::from_le_bytes(r[4..12].try_into().unwrap());
        if len > MAX_ENTRY {
            return None;
        }
        positions.push(Pos {
            segment,
            offset,
            len,
            term,
        });
        offset = offset.checked_add(HEADER as u64 + u64::from(len))?;
    }
    (count > 0 && offset == seg_len).then_some((first_index, positions))
}

/// Remove segment `first`'s index, if it has one; whether it had.
fn remove_index(dir: &Path, first: u64) -> Result<bool, LogError> {
    let path = dir.join(index_name(first));
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(io_err(&path)(e)),
    }
}

/// Whether part of the record at `data[from..to]` never reached the disk:
/// one of its pieces between sector boundaries reads as zeros, as the
/// sectors of a write a crash cut short do. (A power cut during the last
/// append left its first sectors written and the rest, the file's new
/// length included, zeros: B2 soak run 37.)
fn never_written(data: &[u8], from: usize, to: usize) -> bool {
    let mut start = from;
    while start < to {
        let end = ((start / SECTOR + 1) * SECTOR).min(to);
        if data[start..end].iter().all(|b| *b == 0) {
            return true;
        }
        start = end;
    }
    false
}

fn checksum(index: u64, term: u64, entry: &[u8]) -> u32 {
    let crc = crc32c::crc32c(&index.to_le_bytes());
    let crc = crc32c::crc32c_append(crc, &term.to_le_bytes());
    crc32c::crc32c_append(crc, entry)
}

impl RaftLog {
    /// Open the log in `dir` (created if missing), dropping from memory the
    /// records at or below `purged_index`, which a purge left in a segment
    /// it couldn't remove whole.
    ///
    /// # Errors
    /// I/O, or a damaged record anywhere but the end of the last segment.
    pub fn open(dir: &Path) -> Result<Self, LogError> {
        fs::create_dir_all(dir).map_err(io_err(dir))?;
        let mut firsts: Vec<u64> = Vec::new();
        for entry in fs::read_dir(dir).map_err(io_err(dir))? {
            let entry = entry.map_err(io_err(dir))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(first) = name.strip_suffix(".log").and_then(|n| n.parse().ok()) {
                firsts.push(first);
            }
        }
        firsts.sort_unstable();
        let purged = Self::read_marker_at(dir, PURGED)?
            .map(|b| parse_purged(&b, &dir.join(PURGED)).map(|(i, _)| i))
            .transpose()?;
        let mut log = Self {
            dir: dir.to_path_buf(),
            segments: Vec::new(),
            positions: VecDeque::new(),
            first: 0,
        };
        let count = firsts.len();
        for (n, first) in firsts.into_iter().enumerate() {
            log.load_segment(first, n + 1 == count)?;
            // What a purge left in a segment it couldn't remove whole is
            // dropped before the next segment is checked against it: after
            // a snapshot is installed the log goes on well past it.
            if let Some(p) = purged {
                log.forget_upto(p);
            }
        }
        Ok(log)
    }

    /// Read one segment's records into `positions`, checking each, or, for
    /// a sealed segment, take them from its index if it has a valid one. On
    /// the last segment a torn record is cut off with everything after it.
    ///
    /// An append is one write and one sync, so a record of which some part
    /// never reached the disk was never synced, and neither was anything
    /// written after it: none of it was acknowledged. A record is torn when
    /// it is cut short by the end of the file, or fails its checksum and
    /// either ends the file or has a piece that reads as zeros (what a
    /// crash leaves of the sectors it didn't write). A record that fails
    /// its checksum otherwise is damage, and stops the open.
    fn load_segment(&mut self, first: u64, last: bool) -> Result<(), LogError> {
        let path = self.dir.join(segment_name(first));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(io_err(&path))?;
        let file_len = file.metadata().map_err(io_err(&path))?.len();
        let segment = self.segments.len();
        if !last
            && let Some((first_index, positions)) = fs::read(self.dir.join(index_name(first)))
                .ok()
                .and_then(|b| decode_index(&b, segment, file_len))
        {
            // It must carry on from the segments before it, as a read one
            // must; if it doesn't, the segment is read and that decides.
            let follows = match self.next_index() {
                Some(next) => first_index == next,
                None => first_index >= first,
            };
            if follows {
                if self.positions.is_empty() {
                    self.first = first_index;
                }
                self.positions.extend(positions);
                self.segments.push(Segment {
                    first,
                    path,
                    file,
                    len: file_len,
                });
                return Ok(());
            }
        }
        let mut data = Vec::with_capacity(usize::try_from(file_len).unwrap_or(0));
        (&file).read_to_end(&mut data).map_err(io_err(&path))?;
        let mut expect = first;
        if let Some(next) = self.next_index()
            && first != next
        {
            return Err(LogError::Corrupt {
                path,
                offset: 0,
                what: format!("segment starts at index {first}, the log is at {next}"),
            });
        }
        let mut offset = 0usize;
        let mut good_len = data.len();
        while offset < data.len() {
            let torn = |what: &str| -> Result<(), LogError> {
                if last {
                    Ok(())
                } else {
                    Err(LogError::Corrupt {
                        path: path.clone(),
                        offset: offset as u64,
                        what: what.to_string(),
                    })
                }
            };
            let rest = &data[offset..];
            if rest.len() < HEADER {
                torn("a record header cut short")?;
                good_len = offset;
                break;
            }
            let len = u32::from_le_bytes(rest[0..4].try_into().unwrap());
            let crc = u32::from_le_bytes(rest[4..8].try_into().unwrap());
            let index = u64::from_le_bytes(rest[8..16].try_into().unwrap());
            let term = u64::from_le_bytes(rest[16..24].try_into().unwrap());
            let end = HEADER + len as usize;
            if len > MAX_ENTRY || rest.len() < end {
                // A length running past the end is a record the crash cut
                // short (or a damaged length): only the last one may be.
                torn("a record runs past the end of its segment")?;
                good_len = offset;
                break;
            }
            let entry = &rest[HEADER..end];
            if checksum(index, term, entry) != crc {
                if last
                    && (offset + end == data.len() || never_written(&data, offset, offset + end))
                {
                    good_len = offset;
                    break;
                }
                return Err(LogError::Corrupt {
                    path,
                    offset: offset as u64,
                    what: format!("record {index} fails its checksum"),
                });
            }
            if index != expect {
                return Err(LogError::Corrupt {
                    path,
                    offset: offset as u64,
                    what: format!("record {index} where {expect} was expected"),
                });
            }
            if self.positions.is_empty() {
                self.first = index;
            }
            self.positions.push_back(Pos {
                segment,
                offset: offset as u64,
                len,
                term,
            });
            expect += 1;
            offset += end;
        }
        let len = good_len as u64;
        if len < file_len {
            tracing::warn!(
                "raft log {}: cutting a torn record at byte {len}, {} bytes (a crash during an append)",
                path.display(),
                file_len - len
            );
            file.set_len(len).map_err(io_err(&path))?;
            file.sync_all().map_err(io_err(&path))?;
        }
        self.segments.push(Segment {
            first,
            path,
            file,
            len,
        });
        if !last {
            // Read whole and checked: the next open needn't.
            self.write_index(segment);
        }
        Ok(())
    }

    /// Write the index of sealed segment `segment`, whose records are the
    /// last ones in `positions`. Best effort, unsynced: an open that finds
    /// it missing or damaged reads the segment instead.
    fn write_index(&self, segment: usize) {
        let held = self
            .positions
            .iter()
            .rev()
            .take_while(|p| p.segment == segment)
            .count();
        if held == 0 {
            return;
        }
        let skip = self.positions.len() - held;
        let records: Vec<Pos> = self.positions.iter().skip(skip).copied().collect();
        let first_index = self.first + skip as u64;
        let seg = &self.segments[segment];
        let bytes = encode_index(seg.len, first_index, &records);
        let path = self.dir.join(index_name(seg.first));
        let tmp = self.dir.join(format!("{}.tmp", index_name(seg.first)));
        if let Err(e) = fs::write(&tmp, &bytes).and_then(|()| fs::rename(&tmp, &path)) {
            tracing::warn!(
                "raft log {}: no index written ({e}); the next open reads the segment",
                path.display()
            );
        }
    }

    /// Whether `dir` holds a log: a segment or a purge record.
    #[must_use]
    pub fn exists(dir: &Path) -> bool {
        fs::read_dir(dir).is_ok_and(|entries| {
            entries.filter_map(Result::ok).any(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.ends_with(".log") || name == PURGED
            })
        })
    }

    /// The index the next append must have, if any record or segment says.
    fn next_index(&self) -> Option<u64> {
        if self.positions.is_empty() {
            None
        } else {
            Some(self.first + self.positions.len() as u64)
        }
    }

    /// The first and last index held, if any.
    #[must_use]
    pub fn range(&self) -> Option<(u64, u64)> {
        self.next_index().map(|next| (self.first, next - 1))
    }

    /// The term of the record at `index`, if held.
    #[must_use]
    pub fn term_of(&self, index: u64) -> Option<u64> {
        self.pos(index).map(|p| p.term)
    }

    fn pos(&self, index: u64) -> Option<Pos> {
        let i = index.checked_sub(self.first)?;
        self.positions.get(usize::try_from(i).ok()?).copied()
    }

    /// The entries from `from` up to, not including, `to`, that are held.
    ///
    /// # Errors
    /// I/O, or a record that no longer reads back as written.
    pub fn read(&self, from: u64, to: u64) -> Result<Vec<Vec<u8>>, LogError> {
        let mut out = Vec::new();
        let from = from.max(self.first);
        for index in from..to {
            let Some(p) = self.pos(index) else { break };
            let seg = &self.segments[p.segment];
            let mut buf = vec![0u8; HEADER + p.len as usize];
            seg.file
                .read_exact_at(&mut buf, p.offset)
                .map_err(io_err(&seg.path))?;
            let entry = &buf[HEADER..];
            let crc = u32::from_le_bytes(buf[4..8].try_into().unwrap());
            if checksum(index, p.term, entry) != crc {
                return Err(LogError::Corrupt {
                    path: seg.path.clone(),
                    offset: p.offset,
                    what: format!("record {index} fails its checksum on read"),
                });
            }
            out.push(entry.to_vec());
        }
        Ok(out)
    }

    /// Append `(index, term, entry)` records, which must follow the last
    /// one (or start the log), and sync them.
    ///
    /// # Errors
    /// I/O, or an index out of sequence.
    pub fn append(&mut self, records: &[(u64, u64, Vec<u8>)]) -> Result<(), LogError> {
        let Some(&(first_new, _, _)) = records.first() else {
            return Ok(());
        };
        if let Some(next) = self.next_index()
            && first_new != next
        {
            return Err(LogError::Misuse(format!(
                "append at {first_new}, the log is at {next}"
            )));
        }
        let mut new_segment = false;
        if self
            .segments
            .last()
            .is_none_or(|s| s.len >= SEGMENT_BYTES || self.positions.is_empty() && s.len > 0)
        {
            // The last segment is sealed: its index first (it holds
            // nothing after a purge of everything, and gets none then).
            if let Some(sealed) = self.segments.len().checked_sub(1) {
                self.write_index(sealed);
            }
            self.start_segment(first_new)?;
            new_segment = true;
        }
        let segment = self.segments.len() - 1;
        let mut buf = Vec::new();
        let mut positions = Vec::with_capacity(records.len());
        let base = self.segments[segment].len;
        let mut expect = first_new;
        for (index, term, entry) in records {
            if *index != expect {
                return Err(LogError::Misuse(format!(
                    "append of {index} where {expect} was expected"
                )));
            }
            let len = u32::try_from(entry.len())
                .ok()
                .filter(|l| *l <= MAX_ENTRY)
                .ok_or_else(|| LogError::Misuse(format!("entry {index} is too large")))?;
            positions.push(Pos {
                segment,
                offset: base + buf.len() as u64,
                len,
                term: *term,
            });
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(&checksum(*index, *term, entry).to_le_bytes());
            buf.extend_from_slice(&index.to_le_bytes());
            buf.extend_from_slice(&term.to_le_bytes());
            buf.extend_from_slice(entry);
            expect += 1;
        }
        let seg = &mut self.segments[segment];
        seg.file
            .write_all_at(&buf, base)
            .and_then(|()| seg.file.sync_data())
            .map_err(io_err(&seg.path))?;
        seg.len += buf.len() as u64;
        if new_segment {
            sync_dir(&self.dir)?;
        }
        if self.positions.is_empty() {
            self.first = first_new;
        }
        self.positions.extend(positions);
        Ok(())
    }

    fn start_segment(&mut self, first: u64) -> Result<(), LogError> {
        // An index left by an earlier segment of the same name describes
        // other records.
        remove_index(&self.dir, first)?;
        let path = self.dir.join(segment_name(first));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(io_err(&path))?;
        self.segments.push(Segment {
            first,
            path,
            file,
            len: 0,
        });
        Ok(())
    }

    /// Remove every record from `index` on (a conflicting suffix), durably.
    ///
    /// # Errors
    /// I/O.
    pub fn truncate_from(&mut self, index: u64) -> Result<(), LogError> {
        let Some(p) = self.pos(index) else {
            return Ok(()); // nothing held there
        };
        let keep = usize::try_from(index - self.first).unwrap_or(usize::MAX);
        self.positions.truncate(keep);
        // Later segments go whole; the one holding `index` is cut there
        // (and goes whole too if `index` was its first record).
        let mut removed = false;
        while self.segments.len() > p.segment + 1 {
            let seg = self.segments.pop().expect("checked");
            remove_index(&self.dir, seg.first)?;
            fs::remove_file(&seg.path).map_err(io_err(&seg.path))?;
            removed = true;
        }
        // The segment cut is the last again, unsealed: its index goes, and
        // durably (below), so it can't describe what is appended next.
        removed |= remove_index(&self.dir, self.segments[p.segment].first)?;
        let seg = &mut self.segments[p.segment];
        if p.offset == 0 && seg.first == index {
            let seg = self.segments.pop().expect("checked");
            fs::remove_file(&seg.path).map_err(io_err(&seg.path))?;
            removed = true;
        } else {
            seg.file
                .set_len(p.offset)
                .and_then(|()| seg.file.sync_all())
                .map_err(io_err(&seg.path))?;
            seg.len = p.offset;
        }
        if removed {
            sync_dir(&self.dir)?;
        }
        Ok(())
    }

    /// Forget the records up to and including `index`: the caller has
    /// recorded the purge (`write_marker("purged")`) first. Segments
    /// holding nothing after `index` are removed; one straddling it stays.
    ///
    /// # Errors
    /// I/O.
    pub fn purge_upto(&mut self, index: u64) -> Result<(), LogError> {
        self.forget_upto(index);
        let mut removed = false;
        // A segment can go when the next one starts at or below index + 1,
        // or, for the last one, when nothing in it is held any more.
        while let Some(seg) = self.segments.first() {
            let next_first = self.segments.get(1).map(|s| s.first);
            let whole = match next_first {
                Some(nf) => nf <= index + 1,
                None => self.positions.is_empty(),
            };
            if !whole {
                break;
            }
            remove_index(&self.dir, seg.first)?;
            fs::remove_file(&seg.path).map_err(io_err(&seg.path))?;
            self.segments.remove(0);
            for p in &mut self.positions {
                p.segment -= 1;
            }
            removed = true;
        }
        if removed {
            sync_dir(&self.dir)?;
        }
        Ok(())
    }

    fn forget_upto(&mut self, index: u64) {
        while !self.positions.is_empty() && self.first <= index {
            self.positions.pop_front();
            self.first += 1;
        }
        if self.positions.is_empty() {
            self.first = index + 1;
        }
    }

    /// Replace the small file `name` beside the segments with `bytes`:
    /// written to a temporary file, synced when `sync`, renamed over it.
    ///
    /// # Errors
    /// I/O.
    pub fn write_marker(&self, name: &str, bytes: &[u8], sync: bool) -> Result<(), LogError> {
        let tmp = self.dir.join(format!("{name}.tmp"));
        let path = self.dir.join(name);
        let mut f = File::create(&tmp).map_err(io_err(&tmp))?;
        f.write_all(bytes).map_err(io_err(&tmp))?;
        if sync {
            f.sync_all().map_err(io_err(&tmp))?;
        }
        fs::rename(&tmp, &path).map_err(io_err(&path))?;
        if sync {
            sync_dir(&self.dir)?;
        }
        Ok(())
    }

    /// The small file `name` beside the segments, if there is one.
    ///
    /// # Errors
    /// I/O other than its absence.
    pub fn read_marker(&self, name: &str) -> Result<Option<Vec<u8>>, LogError> {
        Self::read_marker_at(&self.dir, name)
    }

    fn read_marker_at(dir: &Path, name: &str) -> Result<Option<Vec<u8>>, LogError> {
        let path = dir.join(name);
        match fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err(&path)(e)),
        }
    }

    /// Record a purge up to `index`, durably, before [`Self::purge_upto`]:
    /// the `purged` file holds the index (so `open` can skip what a
    /// straddling segment still holds) and the caller's record of it.
    ///
    /// # Errors
    /// I/O.
    pub fn record_purge(&self, index: u64, caller: &[u8]) -> Result<(), LogError> {
        let mut bytes = format!("{index}\n").into_bytes();
        bytes.extend_from_slice(caller);
        self.write_marker(PURGED, &bytes, true)
    }

    /// The caller's record of the last purge, if any.
    ///
    /// # Errors
    /// I/O, or a `purged` file that doesn't parse.
    pub fn purged(&self) -> Result<Option<Vec<u8>>, LogError> {
        self.read_marker(PURGED)?
            .map(|b| parse_purged(&b, &self.dir.join(PURGED)).map(|(_, c)| c))
            .transpose()
    }

    /// Save the commit index's caller record (not synced: losing it costs
    /// only a later re-apply).
    ///
    /// # Errors
    /// I/O.
    pub fn save_committed(&self, caller: &[u8]) -> Result<(), LogError> {
        self.write_marker(COMMITTED, caller, false)
    }

    /// The commit index's caller record, if saved.
    ///
    /// # Errors
    /// I/O.
    pub fn committed(&self) -> Result<Option<Vec<u8>>, LogError> {
        self.read_marker(COMMITTED)
    }

    /// Remove every segment and marker: the log starts empty.
    ///
    /// # Errors
    /// I/O.
    pub fn clear(&mut self) -> Result<(), LogError> {
        for seg in self.segments.drain(..) {
            remove_index(&self.dir, seg.first)?;
            fs::remove_file(&seg.path).map_err(io_err(&seg.path))?;
        }
        for name in [PURGED, COMMITTED] {
            match fs::remove_file(self.dir.join(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(io_err(&self.dir.join(name))(e)),
            }
        }
        self.positions.clear();
        self.first = 0;
        sync_dir(&self.dir)
    }
}

/// The `purged` file: the index on its first line, then the caller's record.
fn parse_purged(b: &[u8], path: &Path) -> Result<(u64, Vec<u8>), LogError> {
    let nl = b.iter().position(|&c| c == b'\n');
    let index = nl
        .and_then(|n| std::str::from_utf8(&b[..n]).ok())
        .and_then(|s| s.parse().ok());
    match (nl, index) {
        (Some(n), Some(index)) => Ok((index, b[n + 1..].to_vec())),
        _ => Err(LogError::Corrupt {
            path: path.to_path_buf(),
            offset: 0,
            what: "not a purge record".to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(index: u64, term: u64) -> (u64, u64, Vec<u8>) {
        (index, term, format!("entry {index}").into_bytes())
    }

    fn texts(log: &RaftLog, from: u64, to: u64) -> Vec<String> {
        log.read(from, to)
            .unwrap()
            .into_iter()
            .map(|b| String::from_utf8(b).unwrap())
            .collect()
    }

    #[test]
    fn appends_read_back_and_survive_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), None);
        log.append(&[rec(1, 1), rec(2, 1)]).unwrap();
        log.append(&[rec(3, 2)]).unwrap();
        assert_eq!(log.range(), Some((1, 3)));
        assert_eq!(log.term_of(3), Some(2));
        assert_eq!(texts(&log, 2, 10), ["entry 2", "entry 3"]);
        drop(log);
        let log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), Some((1, 3)));
        assert_eq!(texts(&log, 1, 4), ["entry 1", "entry 2", "entry 3"]);
    }

    #[test]
    fn an_append_out_of_sequence_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        log.append(&[rec(5, 1)]).unwrap();
        assert!(log.append(&[rec(7, 1)]).is_err());
        assert!(log.append(&[rec(6, 1), rec(8, 1)]).is_err());
    }

    #[test]
    fn truncate_removes_the_suffix_durably() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        log.append(&[rec(1, 1), rec(2, 1), rec(3, 1), rec(4, 1)])
            .unwrap();
        log.truncate_from(3).unwrap();
        assert_eq!(log.range(), Some((1, 2)));
        log.append(&[rec(3, 2)]).unwrap();
        drop(log);
        let log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), Some((1, 3)));
        assert_eq!(log.term_of(3), Some(2));
    }

    #[test]
    fn segments_roll_over_and_purge_removes_whole_ones() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        let big = vec![0u8; (SEGMENT_BYTES / 3) as usize];
        for i in 1..=7 {
            log.append(&[(i, 1, big.clone())]).unwrap();
        }
        let segs = || {
            fs::read_dir(dir.path())
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .path()
                        .extension()
                        .is_some_and(|x| x == "log")
                })
                .count()
        };
        assert!(segs() >= 2, "{}", segs());
        log.record_purge(5, b"5").unwrap();
        log.purge_upto(5).unwrap();
        assert_eq!(log.range(), Some((6, 7)));
        let after = segs();
        drop(log);
        let log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), Some((6, 7)));
        assert_eq!(log.purged().unwrap().as_deref(), Some(&b"5"[..]));
        assert_eq!(segs(), after);
        assert_eq!(log.read(6, 8).unwrap().len(), 2);
    }

    #[test]
    fn purging_everything_then_appending_goes_on() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        log.append(&[rec(1, 1), rec(2, 1)]).unwrap();
        log.record_purge(2, b"2").unwrap();
        log.purge_upto(2).unwrap();
        assert_eq!(log.range(), None);
        log.append(&[rec(3, 1)]).unwrap();
        drop(log);
        let log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), Some((3, 3)));
    }

    #[test]
    fn a_torn_last_record_is_cut_off() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        log.append(&[rec(1, 1), rec(2, 1)]).unwrap();
        let path = log.segments[0].path.clone();
        drop(log);
        let len = fs::metadata(&path).unwrap().len();
        // A crash part way through the last append.
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(len - 3)
            .unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), Some((1, 1)));
        log.append(&[rec(2, 2)]).unwrap();
        drop(log);
        let log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.term_of(2), Some(2));
    }

    /// Records big enough that three fill a segment: 1..=3 in the first,
    /// the rest in the next.
    fn big(index: u64, term: u64) -> (u64, u64, Vec<u8>) {
        let fill = u8::try_from(index % 251).unwrap();
        (index, term, vec![fill; (SEGMENT_BYTES / 3) as usize])
    }

    #[test]
    fn a_sealed_segment_opens_from_its_index_and_is_checked_when_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        for i in 1..=5 {
            log.append(&[big(i, 1)]).unwrap();
        }
        assert_eq!(log.segments.len(), 2);
        let sealed = log.segments[0].path.clone();
        drop(log);
        assert!(dir.path().join(index_name(1)).exists(), "sealed, no index");
        assert!(!dir.path().join(index_name(4)).exists(), "the last is open");

        // Damage inside record 2: the open doesn't read the sealed segment…
        let mut data = fs::read(&sealed).unwrap();
        let record2 = HEADER + (SEGMENT_BYTES / 3) as usize;
        data[record2 + HEADER + 10] ^= 0xff;
        fs::write(&sealed, &data).unwrap();
        let log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), Some((1, 5)));
        assert_eq!(log.term_of(3), Some(1));
        // …a read of the record finds it; the others read back.
        let err = log.read(2, 3).expect_err("refused");
        assert!(err.to_string().contains("checksum"), "{err}");
        assert_eq!(log.read(3, 6).unwrap().len(), 3);
        drop(log);

        // Without its index the segment is read, and the open finds it.
        fs::remove_file(dir.path().join(index_name(1))).unwrap();
        let err = RaftLog::open(dir.path()).err().expect("refused");
        assert!(err.to_string().contains("checksum"), "{err}");
    }

    #[test]
    fn a_damaged_index_is_ignored_and_written_again() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        for i in 1..=4 {
            log.append(&[big(i, 1)]).unwrap();
        }
        drop(log);
        let index = dir.path().join(index_name(1));
        let mut bytes = fs::read(&index).unwrap();
        bytes[INDEX_HEADER + 2] ^= 0xff;
        fs::write(&index, &bytes).unwrap();
        let log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), Some((1, 4)));
        assert_eq!(log.read(1, 5).unwrap().len(), 4);
        let len = log.segments[0].len;
        drop(log);
        // Read whole at that open, the segment has a valid index again.
        let (first, positions) = decode_index(&fs::read(&index).unwrap(), 0, len).unwrap();
        assert_eq!((first, positions.len()), (1, 3));
        // An index of another length (the segment since cut) is ignored.
        assert!(decode_index(&fs::read(&index).unwrap(), 0, len - 1).is_none());
    }

    #[test]
    fn a_truncate_into_a_sealed_segment_drops_its_index() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        for i in 1..=5 {
            log.append(&[big(i, 1)]).unwrap();
        }
        log.truncate_from(2).unwrap();
        assert_eq!(log.range(), Some((1, 1)));
        assert!(!dir.path().join(index_name(1)).exists());
        for i in 2..=4 {
            log.append(&[big(i, 2)]).unwrap();
        }
        drop(log);
        let log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), Some((1, 4)));
        assert_eq!(log.term_of(2), Some(2));
        assert_eq!(log.term_of(4), Some(2));
        assert_eq!(log.read(1, 5).unwrap().len(), 4);
    }

    /// A power cut during an append: its first sectors written, the rest
    /// of them, to the file's new length, zeros. The record is cut off,
    /// with the zeros after it.
    #[test]
    fn a_record_the_crash_left_part_zeros_is_cut_off() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        log.append(&[rec(1, 1)]).unwrap();
        let path = log.segments[0].path.clone();
        let synced = fs::metadata(&path).unwrap().len();
        log.append(&[(2, 1, vec![b'x'; 3 * SECTOR]), (3, 1, vec![b'y'; 500])])
            .unwrap();
        drop(log);
        let mut data = fs::read(&path).unwrap();
        let cut = (usize::try_from(synced).unwrap() / SECTOR + 2) * SECTOR;
        data[cut..].fill(0);
        fs::write(&path, &data).unwrap();

        let mut log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), Some((1, 1)));
        assert_eq!(fs::metadata(&path).unwrap().len(), synced);
        log.append(&[rec(2, 2)]).unwrap();
        drop(log);
        let log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), Some((1, 2)));
        assert_eq!(log.term_of(2), Some(2));
    }

    /// The same with none of the append's sectors written: zeros from the
    /// end of the last record synced.
    #[test]
    fn zeros_after_the_last_record_are_cut_off() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        log.append(&[rec(1, 1), rec(2, 1)]).unwrap();
        let path = log.segments[0].path.clone();
        drop(log);
        let synced = fs::metadata(&path).unwrap().len();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(synced + 2 * SECTOR as u64)
            .unwrap();
        let log = RaftLog::open(dir.path()).unwrap();
        assert_eq!(log.range(), Some((1, 2)));
        assert_eq!(fs::metadata(&path).unwrap().len(), synced);
    }

    #[test]
    fn damage_before_the_end_stops_the_open() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        log.append(&[rec(1, 1), rec(2, 1), rec(3, 1)]).unwrap();
        let path = log.segments[0].path.clone();
        drop(log);
        let mut data = fs::read(&path).unwrap();
        data[HEADER + 2] ^= 0xff; // inside record 1's entry
        fs::write(&path, &data).unwrap();
        let err = RaftLog::open(dir.path()).err().expect("refused");
        assert!(err.to_string().contains("checksum"), "{err}");
    }

    /// Damage to the last append that isn't a crash's (no piece of the
    /// record zeros, a record after it) stops the open: it is never cut.
    #[test]
    fn damage_in_the_last_append_with_records_after_it_stops_the_open() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = RaftLog::open(dir.path()).unwrap();
        log.append(&[rec(1, 1)]).unwrap();
        log.append(&[(2, 1, vec![b'x'; 3 * SECTOR]), rec(3, 1)])
            .unwrap();
        let path = log.segments[0].path.clone();
        let record2 = log.pos(2).unwrap().offset;
        drop(log);
        let mut data = fs::read(&path).unwrap();
        data[usize::try_from(record2).unwrap() + HEADER + SECTOR] ^= 0xff;
        fs::write(&path, &data).unwrap();
        let err = RaftLog::open(dir.path()).err().expect("refused");
        assert!(
            err.to_string().contains("record 2 fails its checksum"),
            "{err}"
        );
    }
}
