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
//! Opening reads every segment and checks every record. A torn record at
//! the end of the last segment (a crash during an append, which was never
//! acknowledged) is cut off; any other damage, or a gap in the indexes,
//! fails the open with its position: a record is never skipped.
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

/// The largest entry the log accepts (a corrupt length must not make the
/// open allocate gigabytes).
const MAX_ENTRY: u32 = 256 << 20;

const PURGED: &str = "purged";
const COMMITTED: &str = "committed";

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

    /// Read one segment's records into `positions`, checking each. On the
    /// last segment a torn record at the end is cut off.
    fn load_segment(&mut self, first: u64, last: bool) -> Result<(), LogError> {
        let path = self.dir.join(segment_name(first));
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .map_err(io_err(&path))?;
        let file_len = file.metadata().map_err(io_err(&path))?.len();
        let mut data = Vec::with_capacity(usize::try_from(file_len).unwrap_or(0));
        (&file).read_to_end(&mut data).map_err(io_err(&path))?;
        let segment = self.segments.len();
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
                if last && offset + end == data.len() {
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
                "raft log {}: cutting a torn record at byte {len} (a crash during an append)",
                path.display()
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
        Ok(())
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
            fs::remove_file(&seg.path).map_err(io_err(&seg.path))?;
            removed = true;
        }
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
}
