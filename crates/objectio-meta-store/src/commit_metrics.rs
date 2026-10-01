//! How long redb takes to commit a write transaction — the durable-write
//! (fsync) cost every metadata change pays — and Raft snapshots: built
//! (to send to a replica that fell behind or joined) and installed.

use objectio_common::histogram::{Histogram, LATENCY_BUCKETS};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

static COMMIT_SECONDS: LazyLock<Histogram> = LazyLock::new(|| Histogram::new(LATENCY_BUCKETS));
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

/// Commit `txn`, recording how long it took.
///
/// # Errors
/// Whatever `redb::WriteTransaction::commit` returns.
pub fn commit(txn: redb::WriteTransaction) -> Result<(), redb::CommitError> {
    let started = Instant::now();
    let res = txn.commit();
    COMMIT_SECONDS.observe_duration(started.elapsed());
    res
}

/// Append the commit-latency family to `out`.
pub fn render(out: &mut String) {
    COMMIT_SECONDS.render(
        out,
        "objectio_meta_commit_seconds",
        "Time to commit one redb write transaction (includes fsync)",
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
}
