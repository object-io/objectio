//! The audit spool (A8c): events on the gateway's disk before they are
//! delivered, so none is lost to a gateway killed or a receiver down.
//!
//! An event is appended to the current segment (`seg-<n>.ndjson`, one JSON
//! line each) as its request completes: one `write`, so it survives the
//! process being killed. A background thread fsyncs the segment every
//! [`SYNC_EVERY`]; only fsynced lines are delivered, so a power cut never
//! leaves a receiver holding an event the spool lost.
//!
//! Each target has a shipper: it reads lines from its cursor, keeps the
//! ones it delivers, sends them as a batch, and moves the cursor only once
//! the target took them — durably, in `cursors/`. A target that is down
//! lets the spool grow; it is caught up when it is back. A segment every
//! cursor has passed is deleted. Past `max_bytes` new events are dropped
//! and counted, never silently, and never holding up a request.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// How often the current segment is fsynced (and what was written becomes
/// deliverable).
pub const SYNC_EVERY: Duration = Duration::from_millis(50);

/// A segment is closed past this size.
const SEGMENT_BYTES: u64 = 64 << 20;

/// A position in the spool: a segment and a byte offset in it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Pos {
    pub seg: u64,
    pub off: u64,
}

struct Writer {
    file: File,
    pos: Pos,
    /// Bytes in every segment still on disk.
    total: u64,
    /// Written since the last fsync.
    dirty: bool,
}

pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
    writer: Mutex<Writer>,
    durable: watch::Sender<Pos>,
    /// Where each shipper is, so segments behind all of them can go.
    cursors: Mutex<HashMap<String, Pos>>,
    /// Names this gateway's objects in the system bucket, across restarts.
    pub id: String,
}

fn seg_path(dir: &Path, seg: u64) -> PathBuf {
    dir.join(format!("seg-{seg:020}.ndjson"))
}

fn segments(dir: &Path) -> std::io::Result<Vec<u64>> {
    let mut out: Vec<u64> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .filter_map(|e| {
            e.file_name()
                .to_str()?
                .strip_prefix("seg-")?
                .strip_suffix(".ndjson")?
                .parse()
                .ok()
        })
        .collect();
    out.sort_unstable();
    Ok(out)
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

impl Spool {
    /// Open (or create) the spool in `dir`, holding at most `max_bytes`.
    ///
    /// # Errors
    /// The directory or a segment can't be read or written.
    pub fn open(dir: &Path, max_bytes: u64) -> std::io::Result<Arc<Self>> {
        std::fs::create_dir_all(dir.join("cursors"))?;
        let id_path = dir.join("id");
        let id = match std::fs::read_to_string(&id_path) {
            Ok(s) if !s.trim().is_empty() => s.trim().to_string(),
            _ => {
                let id = uuid::Uuid::new_v4().simple().to_string();
                std::fs::write(&id_path, &id)?;
                sync_dir(dir)?;
                id
            }
        };
        let segs = segments(dir)?;
        let seg = segs.last().copied().unwrap_or(1);
        let path = seg_path(dir, seg);
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)?;
        // A line torn by a crash mid-write is not an event: cut it off.
        let len = file.metadata()?.len();
        let whole = last_line_end(&path, len)?;
        if whole < len {
            file.set_len(whole)?;
        }
        file.sync_all()?;
        let mut total = 0;
        for s in &segs {
            total += std::fs::metadata(seg_path(dir, *s)).map_or(0, |m| m.len());
        }
        if segs.is_empty() {
            sync_dir(dir)?;
        }
        let pos = Pos { seg, off: whole };
        let (durable, _) = watch::channel(pos);
        // Every saved cursor holds its segments from the start, before its
        // shipper is back: none is deleted under a target not yet running.
        let mut cursors = HashMap::new();
        for e in std::fs::read_dir(dir.join("cursors"))?.filter_map(Result::ok) {
            let name = e.file_name();
            let Some(key) = name
                .to_str()
                .and_then(|n| hex::decode(n).ok())
                .and_then(|k| String::from_utf8(k).ok())
            else {
                continue;
            };
            if let Some(p) = std::fs::read(e.path())
                .ok()
                .and_then(|b| serde_json::from_slice::<Pos>(&b).ok())
            {
                cursors.insert(key, p);
            }
        }
        let spool = Arc::new(Self {
            dir: dir.to_path_buf(),
            max_bytes,
            writer: Mutex::new(Writer {
                file,
                pos,
                total,
                dirty: false,
            }),
            durable,
            cursors: Mutex::new(cursors),
            id,
        });
        let weak = Arc::downgrade(&spool);
        std::thread::Builder::new()
            .name("audit-spool-sync".into())
            .spawn(move || {
                while let Some(spool) = weak.upgrade() {
                    spool.sync();
                    drop(spool);
                    std::thread::sleep(SYNC_EVERY);
                }
            })?;
        Ok(spool)
    }

    /// Append one event (a JSON line, without the newline). False when the
    /// spool is full or the write failed: the event is dropped.
    pub fn append(&self, json: &[u8]) -> bool {
        let mut w = self.writer.lock();
        let len = json.len() as u64 + 1;
        if w.total + len > self.max_bytes {
            return false;
        }
        let mut line = Vec::with_capacity(json.len() + 1);
        line.extend_from_slice(json);
        line.push(b'\n');
        if w.file.write_all(&line).is_err() {
            return false;
        }
        w.pos.off += len;
        w.total += len;
        w.dirty = true;
        if w.pos.off >= SEGMENT_BYTES {
            // The closed segment is made durable before writing moves on.
            if w.file.sync_data().is_ok() {
                let next = Pos {
                    seg: w.pos.seg + 1,
                    off: 0,
                };
                if let Ok(f) = OpenOptions::new()
                    .create(true)
                    .read(true)
                    .append(true)
                    .open(seg_path(&self.dir, next.seg))
                {
                    let _ = sync_dir(&self.dir);
                    let closed = w.pos;
                    w.file = f;
                    w.pos = next;
                    w.dirty = false;
                    // Everything in the closed segment is durable.
                    self.durable.send_if_modified(|d| {
                        let advance = *d < closed;
                        if advance {
                            *d = closed;
                        }
                        advance
                    });
                }
            }
        }
        true
    }

    /// Whether every shipper has delivered everything before `end`.
    pub fn caught_up(&self, end: Pos) -> bool {
        self.cursors.lock().values().all(|c| *c >= end)
    }

    /// Make what was written durable, and deliverable.
    pub fn sync(&self) {
        let (file, pos) = {
            let mut w = self.writer.lock();
            if !w.dirty {
                return;
            }
            w.dirty = false;
            match w.file.try_clone() {
                Ok(f) => (f, w.pos),
                Err(_) => {
                    w.dirty = true;
                    return;
                }
            }
        };
        if file.sync_data().is_ok() {
            self.durable.send_if_modified(|d| {
                let advance = *d < pos;
                if advance {
                    *d = pos;
                }
                advance
            });
        } else {
            self.writer.lock().dirty = true;
        }
    }

    /// The durable end, as it moves.
    pub fn durable(&self) -> watch::Receiver<Pos> {
        self.durable.subscribe()
    }

    /// Up to `max` lines from `from` (not past the durable end), each with
    /// the position just after it.
    ///
    /// # Errors
    /// A segment that can't be read.
    pub fn read(&self, from: Pos, max: usize) -> std::io::Result<Vec<(Pos, Vec<u8>)>> {
        let end = *self.durable.borrow();
        let mut out = Vec::new();
        let mut at = from;
        while out.len() < max && at < end {
            let path = seg_path(&self.dir, at.seg);
            let file = match File::open(&path) {
                Ok(f) => f,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound && at.seg < end.seg => {
                    at = Pos {
                        seg: at.seg + 1,
                        off: 0,
                    };
                    continue;
                }
                Err(e) => return Err(e),
            };
            let limit = if at.seg == end.seg {
                end.off
            } else {
                file.metadata()?.len()
            };
            let mut r = BufReader::new(file);
            r.seek(SeekFrom::Start(at.off))?;
            while out.len() < max && at.off < limit {
                let mut line = Vec::new();
                let n = r.read_until(b'\n', &mut line)? as u64;
                if n == 0 || line.last() != Some(&b'\n') || at.off + n > limit {
                    break;
                }
                line.pop();
                at.off += n;
                out.push((at, line));
            }
            if out.len() < max && at.seg < end.seg {
                at = Pos {
                    seg: at.seg + 1,
                    off: 0,
                };
            } else {
                break;
            }
        }
        Ok(out)
    }

    /// Where `key`'s shipper is: its saved cursor, or, for a new target,
    /// the durable end (saved at once, so a restart doesn't skip what
    /// arrives meanwhile): a new target gets events from now on.
    pub fn cursor(&self, key: &str) -> Pos {
        if let Some(p) = self.cursors.lock().get(key).copied() {
            return p;
        }
        let pos = *self.durable.borrow();
        if let Err(e) = self.advance(key, pos) {
            tracing::warn!("audit spool: cannot save cursor for {key}: {e}");
            self.cursors.lock().insert(key.to_string(), pos);
        }
        pos
    }

    /// `key`'s shipper delivered everything before `pos`: saved durably,
    /// and segments behind every shipper deleted.
    ///
    /// # Errors
    /// The cursor can't be written.
    pub fn advance(&self, key: &str, pos: Pos) -> std::io::Result<()> {
        let path = self.cursor_path(key);
        let tmp = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&serde_json::to_vec(&pos).unwrap_or_default())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        sync_dir(path.parent().unwrap_or(&self.dir))?;
        self.cursors.lock().insert(key.to_string(), pos);
        self.release();
        Ok(())
    }

    /// A target removed: its cursor no longer holds segments.
    pub fn forget(&self, key: &str) {
        let _ = std::fs::remove_file(self.cursor_path(key));
        self.cursors.lock().remove(key);
        self.release();
    }

    /// Delete the segments every shipper is past.
    fn release(&self) {
        let Some(min) = self.cursors.lock().values().min().copied() else {
            return;
        };
        let current = self.writer.lock().pos.seg;
        let Ok(segs) = segments(&self.dir) else {
            return;
        };
        for s in segs.into_iter().filter(|s| *s < min.seg && *s < current) {
            let path = seg_path(&self.dir, s);
            let len = std::fs::metadata(&path).map_or(0, |m| m.len());
            if std::fs::remove_file(&path).is_ok() {
                let mut w = self.writer.lock();
                w.total = w.total.saturating_sub(len);
            }
        }
    }

    /// Bytes waiting in the spool.
    pub fn bytes(&self) -> u64 {
        self.writer.lock().total
    }

    fn cursor_path(&self, key: &str) -> PathBuf {
        self.dir.join("cursors").join(hex::encode(key.as_bytes()))
    }
}

/// Where the last whole line of the file at `path` ends.
fn last_line_end(path: &Path, len: u64) -> std::io::Result<u64> {
    if len == 0 {
        return Ok(0);
    }
    let mut f = File::open(path)?;
    let mut back = len;
    let mut buf = vec![0u8; 64 << 10];
    while back > 0 {
        let n = buf.len().min(usize::try_from(back).unwrap_or(usize::MAX));
        back -= n as u64;
        f.seek(SeekFrom::Start(back))?;
        std::io::Read::read_exact(&mut f, &mut buf[..n])?;
        if let Some(i) = buf[..n].iter().rposition(|b| *b == b'\n') {
            return Ok(back + i as u64 + 1);
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait_durable(s: &Spool, want: Pos) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while *s.durable().borrow() < want {
            assert!(std::time::Instant::now() < deadline, "never durable");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Lines come back in order once durable; a shipper's cursor survives
    /// a reopen, and a new one starts at the end.
    #[test]
    fn lines_are_read_back_from_a_cursor_across_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let end;
        {
            let s = Spool::open(dir.path(), 1 << 20).unwrap();
            for i in 0..10 {
                assert!(s.append(format!("{{\"n\":{i}}}").as_bytes()));
            }
            end = s.writer.lock().pos;
            wait_durable(&s, end);
            let start = Pos { seg: 1, off: 0 };
            let got = s.read(start, 4).unwrap();
            assert_eq!(got.len(), 4);
            assert_eq!(got[0].1, b"{\"n\":0}");
            s.advance("t", got[3].0).unwrap();
        }
        let s = Spool::open(dir.path(), 1 << 20).unwrap();
        let from = s.cursor("t");
        let rest = s.read(from, 100).unwrap();
        assert_eq!(rest.len(), 6);
        assert_eq!(rest[0].1, b"{\"n\":4}");
        assert_eq!(rest.last().unwrap().0, end);
        assert_eq!(s.cursor("new"), end, "a new target starts at the end");
    }

    /// A line torn by a crash is cut off when the spool opens.
    #[test]
    fn a_torn_line_is_dropped_on_open() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = Spool::open(dir.path(), 1 << 20).unwrap();
            assert!(s.append(b"{\"a\":1}"));
            let p = s.writer.lock().pos;
            wait_durable(&s, p);
        }
        let mut f = OpenOptions::new()
            .append(true)
            .open(seg_path(dir.path(), 1))
            .unwrap();
        f.write_all(b"{\"torn\":").unwrap();
        let s = Spool::open(dir.path(), 1 << 20).unwrap();
        assert!(s.append(b"{\"b\":2}"));
        let p = s.writer.lock().pos;
        wait_durable(&s, p);
        let got: Vec<Vec<u8>> = s
            .read(Pos { seg: 1, off: 0 }, 10)
            .unwrap()
            .into_iter()
            .map(|(_, l)| l)
            .collect();
        assert_eq!(got, vec![b"{\"a\":1}".to_vec(), b"{\"b\":2}".to_vec()]);
    }

    /// Full: new events are refused (and counted by the caller), not
    /// blocking anything.
    #[test]
    fn a_full_spool_refuses_new_events() {
        let dir = tempfile::tempdir().unwrap();
        let s = Spool::open(dir.path(), 20).unwrap();
        assert!(s.append(b"0123456789"));
        assert!(!s.append(b"0123456789"));
    }
}
