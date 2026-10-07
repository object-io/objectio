//! How long redb takes to commit a write transaction — the durable-write
//! (fsync) cost every metadata change pays — and Raft snapshots: built
//! (to send to a replica that fell behind or joined) and installed.

use objectio_common::histogram::{Histogram, HistogramVec, LATENCY_BUCKETS};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static COMMIT_SECONDS: LazyLock<HistogramVec> =
    LazyLock::new(|| HistogramVec::new(LATENCY_BUCKETS));
static SNAPSHOT_BUILD_SECONDS: LazyLock<Histogram> =
    LazyLock::new(|| Histogram::new(LATENCY_BUCKETS));
static SNAPSHOT_INSTALL_SECONDS: LazyLock<Histogram> =
    LazyLock::new(|| Histogram::new(LATENCY_BUCKETS));
static SNAPSHOT_BYTES: AtomicU64 = AtomicU64::new(0);

/// A snapshot of `bytes` was built in `elapsed`.
pub fn snapshot_built(bytes: usize, elapsed: std::time::Duration) {
    SNAPSHOT_BUILD_SECONDS.observe_duration(elapsed);
    SNAPSHOT_BYTES.store(bytes as u64, Ordering::Relaxed);
}

/// A snapshot from the leader was installed in `elapsed`.
pub fn snapshot_installed(elapsed: std::time::Duration) {
    SNAPSHOT_INSTALL_SECONDS.observe_duration(elapsed);
}

/// What a commit must guarantee (objectio-docs `core/meta-log.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Commit {
    /// On stable storage when it returns, with redb's allocator state saved
    /// (quick repair), so the file never needs a full repair after a crash.
    /// Every durable commit to meta's database is one of these.
    Durable,
    /// Committed entries applied to the state machine: visible at once,
    /// made durable by the next checkpoint. A crash before that rolls them
    /// back, with `last_applied`, and they are applied again from the log.
    Applied,
}

/// Commit `txn` as `kind` says, recording how long it took.
///
/// # Errors
/// Whatever `redb::WriteTransaction::commit` returns.
pub fn commit(mut txn: redb::WriteTransaction, kind: Commit) -> Result<(), redb::CommitError> {
    match kind {
        Commit::Durable => txn.set_quick_repair(true),
        Commit::Applied => txn.set_durability(redb::Durability::None),
    }
    let started = Instant::now();
    let res = txn.commit();
    COMMIT_SECONDS.observe_duration(
        match kind {
            Commit::Durable => "kind=\"durable\"",
            Commit::Applied => "kind=\"applied\"",
        },
        started.elapsed(),
    );
    res
}

/// Whether opening meta's database last had to walk all of it (a full
/// repair: the last durable commit didn't save the allocator state), and
/// how long the open took.
static OPEN_REPAIRED: AtomicU64 = AtomicU64::new(0);
static OPEN_MILLIS: AtomicU64 = AtomicU64::new(0);

/// Whether opening meta's database at start had to walk all of it.
#[must_use]
pub fn open_repaired() -> bool {
    OPEN_REPAIRED.load(Ordering::Relaxed) != 0
}

/// Record how the database open went.
pub fn opened(repaired: bool, elapsed: std::time::Duration) {
    OPEN_REPAIRED.store(u64::from(repaired), Ordering::Relaxed);
    OPEN_MILLIS.store(
        u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
}

/// Append the commit-latency family to `out`.
pub fn render(out: &mut String) {
    COMMIT_SECONDS.render(
        out,
        "objectio_meta_commit_seconds",
        "Time to commit one redb write transaction, by kind: durable (with its fsync) or applied (made durable by the next checkpoint)",
        "",
    );
    SNAPSHOT_BUILD_SECONDS.render(
        out,
        "objectio_meta_raft_snapshot_build_seconds",
        "Time to build a Raft snapshot of the whole state machine (built in memory)",
        "",
    );
    SNAPSHOT_INSTALL_SECONDS.render(
        out,
        "objectio_meta_raft_snapshot_install_seconds",
        "Time to install a Raft snapshot received from the leader",
        "",
    );
    let bytes = SNAPSHOT_BYTES.load(Ordering::Relaxed);
    let _ = std::fmt::Write::write_fmt(
        out,
        format_args!(
            "# HELP objectio_meta_raft_snapshot_bytes Size of the last Raft snapshot built (held in memory while sent)\n\
             # TYPE objectio_meta_raft_snapshot_bytes gauge\nobjectio_meta_raft_snapshot_bytes {bytes}\n"
        ),
    );
    let repaired = OPEN_REPAIRED.load(Ordering::Relaxed);
    #[allow(clippy::cast_precision_loss)]
    let open_s = OPEN_MILLIS.load(Ordering::Relaxed) as f64 / 1000.0;
    let _ = std::fmt::Write::write_fmt(
        out,
        format_args!(
            "# HELP objectio_meta_open_repair 1 if opening the metadata database had to walk all of it (B25: never expected)\n\
             # TYPE objectio_meta_open_repair gauge\nobjectio_meta_open_repair {repaired}\n\
             # HELP objectio_meta_open_seconds Time to open the metadata database at start\n\
             # TYPE objectio_meta_open_seconds gauge\nobjectio_meta_open_seconds {open_s}\n"
        ),
    );
}
