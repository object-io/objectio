//! How long redb takes to commit a write transaction — the durable-write
//! (fsync) cost every metadata change pays.

use objectio_common::histogram::{Histogram, LATENCY_BUCKETS};
use std::sync::LazyLock;
use std::time::Instant;

static COMMIT_SECONDS: LazyLock<Histogram> = LazyLock::new(|| Histogram::new(LATENCY_BUCKETS));

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
}
