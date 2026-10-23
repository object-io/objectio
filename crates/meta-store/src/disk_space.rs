//! Room on the filesystem under meta's data directory, and what meta may
//! still write there (objectio-docs `core/meta.md`, "A full disk").
//!
//! Meta can't meet a full filesystem and carry on. openraft 0.9 stops a
//! node for good on any storage error from its log or state machine, and
//! redb refuses every read and write after an I/O error until the database
//! is opened again. So meta keeps a reserve free and stops growing before
//! the filesystem fills:
//!
//! - the leader refuses new writes while less than the reserve is free
//!   ([`DiskSpace::admit_write`]);
//! - a follower takes entries and snapshots from its leader down to half
//!   the reserve ([`DiskSpace::admit_entries`]), so a leader that accepted
//!   a write can still commit it;
//! - a snapshot is built only with room for it above the reserve
//!   ([`DiskSpace::admit_snapshot`]), and stops if it would eat into it.
//!
//! Below the reserve meta writes only what is already under way: entries
//! proposed before, their applies and checkpoints, votes. A write that
//! still meets ENOSPC or EDQUOT (something else filled the filesystem, or a
//! quota statvfs doesn't show) is reported here ([`DiskSpace::out_of_space`])
//! and counts as no room for a while, whatever statvfs says.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// The reserve when none is configured: what meta writes after it stops
/// taking writes is a few MiB (entries in flight, their applies, a
/// checkpoint, votes), so this is ample, and small next to any volume
/// meant for meta.
pub const DEFAULT_RESERVE: u64 = 1 << 30;

/// How long a statvfs answer is used before asking again.
const PROBE_EVERY: Duration = Duration::from_millis(100);

/// How long after a write met a full filesystem meta counts it as having
/// no room, whatever statvfs says.
const STARVED_FOR: Duration = Duration::from_secs(10);

/// Why meta won't write: the filesystem has too little room.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{0}")]
pub struct NoRoom(String);

/// Where the free space is read from.
enum Source {
    /// statvfs of the directory.
    Filesystem,
    /// A file holding a byte count, when it exists; the filesystem
    /// otherwise. Tests can't fill a real filesystem without root.
    File(PathBuf),
}

/// The free space under one directory, and meta's reserve on it.
pub struct DiskSpace {
    dir: PathBuf,
    reserve: u64,
    source: Source,
    /// The last statvfs answer, and when it was read.
    probed: Mutex<Option<(Instant, Option<u64>)>>,
    /// Until when a write's ENOSPC or EDQUOT counts as no room.
    starved_until: Mutex<Option<Instant>>,
    /// Writes refused for want of room.
    refused: AtomicU64,
    /// Writes that met a full filesystem.
    out_of_space: AtomicU64,
}

impl DiskSpace {
    /// The filesystem under `dir`, keeping `reserve` bytes free.
    #[must_use]
    pub fn new(dir: &Path, reserve: u64) -> Self {
        Self::with_source(dir, reserve, Source::Filesystem)
    }

    /// As [`Self::new`], the free space read from `file` (a byte count)
    /// while it exists: a test's stand-in for a filesystem filling up.
    #[must_use]
    pub fn with_free_bytes_file(dir: &Path, reserve: u64, file: &Path) -> Self {
        Self::with_source(dir, reserve, Source::File(file.to_path_buf()))
    }

    fn with_source(dir: &Path, reserve: u64, source: Source) -> Self {
        Self {
            dir: dir.to_path_buf(),
            reserve,
            source,
            probed: Mutex::new(None),
            starved_until: Mutex::new(None),
            refused: AtomicU64::new(0),
            out_of_space: AtomicU64::new(0),
        }
    }

    /// The bytes kept free.
    #[must_use]
    pub const fn reserve(&self) -> u64 {
        self.reserve
    }

    /// The directory whose filesystem this is.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Bytes free to meta (an unprivileged writer), if it can be told.
    #[must_use]
    pub fn free(&self) -> Option<u64> {
        if let Source::File(file) = &self.source {
            match std::fs::read_to_string(file) {
                Ok(s) => return s.trim().parse().ok(),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return None,
            }
        }
        let mut probed = self.probed.lock();
        if let Some((at, free)) = *probed
            && at.elapsed() < PROBE_EVERY
        {
            return free;
        }
        let free = match nix::sys::statvfs::statvfs(&self.dir) {
            Ok(st) => {
                // u64 on Linux; u32 on macOS, where the aio is built too.
                #[allow(clippy::useless_conversion)]
                let blocks = u64::from(st.blocks_available());
                Some(blocks.saturating_mul(st.fragment_size()))
            }
            Err(e) => {
                tracing::warn!("free space of {}: {e}", self.dir.display());
                None
            }
        };
        *probed = Some((Instant::now(), free));
        free
    }

    /// A write met a full filesystem (ENOSPC, EDQUOT): for a while, count
    /// it as having no room, whatever statvfs says.
    pub fn out_of_space(&self) {
        self.out_of_space.fetch_add(1, Ordering::Relaxed);
        *self.starved_until.lock() = Some(Instant::now() + STARVED_FOR);
    }

    /// Whether a write met a full filesystem lately.
    #[must_use]
    pub fn starved(&self) -> bool {
        self.starved_until
            .lock()
            .is_some_and(|until| Instant::now() < until)
    }

    /// Whether the leader may propose a new write: the reserve is free.
    ///
    /// # Errors
    /// [`NoRoom`], saying why.
    pub fn admit_write(&self) -> Result<(), NoRoom> {
        self.has_room_for_writes().inspect_err(|_| {
            self.refused.fetch_add(1, Ordering::Relaxed);
        })
    }

    /// [`Self::admit_write`] without counting a refusal: whether a write
    /// would be taken.
    ///
    /// # Errors
    /// [`NoRoom`], saying why.
    pub fn has_room_for_writes(&self) -> Result<(), NoRoom> {
        self.room("new writes", self.reserve, 0)
    }

    /// Whether a follower may take `bytes` more of its leader's log or
    /// snapshot: they leave half the reserve free. Lower than for new
    /// writes, so what a leader accepted can still be committed.
    ///
    /// # Errors
    /// [`NoRoom`], saying why.
    pub fn admit_entries(&self, bytes: u64) -> Result<(), NoRoom> {
        self.room("entries from the leader", self.reserve / 2, bytes)
    }

    /// Whether a snapshot of `bytes` may be written: it leaves the reserve
    /// free.
    ///
    /// # Errors
    /// [`NoRoom`], saying why.
    pub fn admit_snapshot(&self, bytes: u64) -> Result<(), NoRoom> {
        self.room("a snapshot", self.reserve, bytes)
    }

    /// Whether `need` bytes fit and leave `floor` free.
    fn room(&self, what: &str, floor: u64, need: u64) -> Result<(), NoRoom> {
        if self.starved() {
            return Err(NoRoom(format!(
                "no room for {what}: a write on {} found its filesystem full",
                self.dir.display()
            )));
        }
        // Unknown is not full: refusing every write because statvfs failed
        // would turn a probe's fault into an outage.
        let Some(free) = self.free() else {
            return Ok(());
        };
        if free >= floor.saturating_add(need) {
            return Ok(());
        }
        Err(NoRoom(if need == 0 {
            format!(
                "no room for {what}: {free} bytes free on {}, under meta's reserve of {floor}",
                self.dir.display()
            )
        } else {
            format!(
                "no room for {what}: {free} bytes free on {}, {need} needed above {floor}",
                self.dir.display()
            )
        }))
    }

    /// This node's room, as Prometheus families.
    pub fn render_metrics(&self, out: &mut String) {
        use std::fmt::Write as _;
        let full = self.starved() || self.free().is_some_and(|f| f < self.reserve);
        let free = self.free().map_or(-1.0, |f| f as f64);
        let _ = write!(
            out,
            "# HELP objectio_meta_disk_free_bytes Bytes free on the filesystem of meta's data directory (-1: unknown)\n\
             # TYPE objectio_meta_disk_free_bytes gauge\n\
             objectio_meta_disk_free_bytes {free}\n\
             # HELP objectio_meta_disk_reserve_bytes Bytes meta keeps free: below it the leader refuses writes\n\
             # TYPE objectio_meta_disk_reserve_bytes gauge\n\
             objectio_meta_disk_reserve_bytes {}\n\
             # HELP objectio_meta_disk_full 1 while this node has less than its reserve free, or a write found its filesystem full lately\n\
             # TYPE objectio_meta_disk_full gauge\n\
             objectio_meta_disk_full {}\n\
             # HELP objectio_meta_writes_refused_no_room_total Writes this node refused, as leader, for want of room\n\
             # TYPE objectio_meta_writes_refused_no_room_total counter\n\
             objectio_meta_writes_refused_no_room_total {}\n\
             # HELP objectio_meta_disk_out_of_space_total Writes to the log or a snapshot that found the filesystem full\n\
             # TYPE objectio_meta_disk_out_of_space_total counter\n\
             objectio_meta_disk_out_of_space_total {}\n",
            self.reserve,
            u8::from(full),
            self.refused.load(Ordering::Relaxed),
            self.out_of_space.load(Ordering::Relaxed),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn space(free: u64) -> (tempfile::TempDir, DiskSpace) {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("free");
        std::fs::write(&file, free.to_string()).unwrap();
        let s = DiskSpace::with_free_bytes_file(dir.path(), 1000, &file);
        (dir, s)
    }

    fn set_free(dir: &tempfile::TempDir, free: u64) {
        std::fs::write(dir.path().join("free"), free.to_string()).unwrap();
    }

    /// New writes stop at the reserve; a follower takes entries down to
    /// half of it; a snapshot needs its own size above the reserve. Room
    /// coming back is seen at once.
    #[test]
    fn writes_stop_at_the_reserve_and_entries_at_half_of_it() {
        let (dir, s) = space(5000);
        s.admit_write().unwrap();
        s.admit_entries(4000).unwrap();
        s.admit_snapshot(4000).unwrap();
        assert!(s.admit_snapshot(4001).is_err());

        set_free(&dir, 999);
        let e = s.admit_write().unwrap_err();
        assert!(e.to_string().contains("999 bytes free"), "{e}");
        s.admit_entries(499).unwrap();
        assert!(s.admit_entries(500).is_err());
        assert!(s.admit_snapshot(0).is_err());

        set_free(&dir, 1000);
        s.admit_write().unwrap();
        let mut m = String::new();
        s.render_metrics(&mut m);
        assert!(
            m.contains("objectio_meta_writes_refused_no_room_total 1"),
            "{m}"
        );
        assert!(m.contains("objectio_meta_disk_full 0"), "{m}");
    }

    /// A write that met ENOSPC is no room for a while, whatever the
    /// free-space count says (a quota statvfs doesn't show).
    #[test]
    fn a_full_filesystem_met_by_a_write_is_no_room_whatever_statvfs_says() {
        let (_dir, s) = space(u64::MAX / 4);
        s.admit_write().unwrap();
        s.out_of_space();
        assert!(s.admit_write().is_err());
        assert!(s.admit_entries(0).is_err());
        assert!(s.admit_snapshot(0).is_err());
        *s.starved_until.lock() = Some(Instant::now());
        s.admit_write().unwrap();
    }

    /// Without the file, the filesystem's own free space counts; a free
    /// space that can't be told never refuses.
    #[test]
    fn the_filesystem_is_asked_when_the_file_is_gone() {
        let dir = tempfile::TempDir::new().unwrap();
        let s = DiskSpace::with_free_bytes_file(dir.path(), 0, &dir.path().join("absent"));
        assert!(s.free().is_some_and(|f| f > 0));
        s.admit_write().unwrap();
        let gone = DiskSpace::new(&dir.path().join("no-such-dir"), u64::MAX);
        assert_eq!(gone.free(), None);
        gone.admit_write().unwrap();
    }
}
