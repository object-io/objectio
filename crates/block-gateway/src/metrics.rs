//! Block gateway metrics: I/O by protocol, the write cache, the journal,
//! and the flushes that store chunks as erasure-coded stripes.
//!
//! Served on `--metrics-listen` when the block gateway runs on its own;
//! under aio, added to the gateway's `/metrics` through
//! `objectio_common::metrics_registry`.

use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use objectio_block::WriteCache;
use objectio_common::histogram::{CounterVec, HistogramVec, LATENCY_BUCKETS};

static IO_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| HistogramVec::new(LATENCY_BUCKETS));
static IO_BYTES: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static IO_ERRORS: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static CHUNK_READS: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static FLUSHED: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static FLUSH_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| HistogramVec::new(LATENCY_BUCKETS));
static STRIPES_FREED: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static FREE_FAILURES: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);

/// Which way a request came in.
#[derive(Clone, Copy)]
pub enum Protocol {
    Grpc,
    Nbd,
}

impl Protocol {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Grpc => "grpc",
            Self::Nbd => "nbd",
        }
    }
}

/// Times one block I/O request (`op`: read, write, trim, flush) and counts
/// its bytes. Dropped without [`Io::done`], it counts as an error, so an
/// early return is never mistaken for success.
pub struct Io {
    protocol: Protocol,
    op: &'static str,
    started: Instant,
    finished: bool,
}

impl Io {
    #[must_use]
    pub fn start(protocol: Protocol, op: &'static str) -> Self {
        Self {
            protocol,
            op,
            started: Instant::now(),
            finished: false,
        }
    }

    fn labels(&self) -> String {
        format!("protocol=\"{}\",op=\"{}\"", self.protocol.as_str(), self.op)
    }

    /// The request succeeded, moving `bytes`.
    pub fn done(mut self, bytes: u64) {
        self.finished = true;
        let labels = self.labels();
        IO_SECONDS.observe_duration(&labels, self.started.elapsed());
        IO_BYTES.add(&labels, bytes);
    }
}

impl Drop for Io {
    fn drop(&mut self) {
        if !self.finished {
            let labels = self.labels();
            IO_SECONDS.observe_duration(&labels, self.started.elapsed());
            IO_ERRORS.inc(&labels);
        }
    }
}

/// Where a chunk a read needed came from: `stored` (read and decoded from
/// its stripe) or `unwritten` (never written: zeros). Cache hits are reads
/// that never get here.
pub fn chunk_read(source: &str) {
    CHUNK_READS.inc(&format!("source=\"{source}\""));
}

/// One chunk flush and how it ended: `stored`, `conflict` (the chunk
/// changed meanwhile; retried), or `failed`.
pub fn flushed(result: &str, elapsed: Duration) {
    FLUSHED.inc(&format!("result=\"{result}\""));
    FLUSH_SECONDS.observe_duration(&format!("result=\"{result}\""), elapsed);
}

/// Stripes whose shards were deleted because nothing uses them any more,
/// and shard deletes that failed (leaked space), by why they were freed.
pub fn stripes_freed(reason: &str, stripes: usize, failed_deletes: usize) {
    STRIPES_FREED.add(&format!("reason=\"{reason}\""), stripes as u64);
    FREE_FAILURES.add(&format!("reason=\"{reason}\""), failed_deletes as u64);
}

/// Everything above, the write cache's state and the journal's fsyncs.
#[must_use]
pub fn render(cache: &WriteCache) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    IO_SECONDS.render(
        &mut out,
        "objectio_block_io_seconds",
        "Time to serve one block request, by protocol and operation",
        "",
    );
    IO_BYTES.render(
        &mut out,
        "objectio_block_io_bytes_total",
        "Bytes read or written by block requests that succeeded, by protocol and operation",
    );
    IO_ERRORS.render(
        &mut out,
        "objectio_block_io_errors_total",
        "Block requests that failed, by protocol and operation",
    );
    CHUNK_READS.render(
        &mut out,
        "objectio_block_chunk_reads_total",
        "Chunks a read had to fetch, not in the cache: stored (from their stripe) or unwritten (zeros)",
    );
    FLUSHED.render(
        &mut out,
        "objectio_block_chunks_flushed_total",
        "Chunk flushes, by result: stored, conflict (changed meanwhile, retried) or failed (retried)",
    );
    FLUSH_SECONDS.render(
        &mut out,
        "objectio_block_chunk_flush_seconds",
        "Time to store one chunk: encode, write its shards, record it in meta",
        "",
    );
    STRIPES_FREED.render(
        &mut out,
        "objectio_block_stripes_freed_total",
        "Stripes deleted because nothing uses them any more, by reason (overwrite, volume, snapshot)",
    );
    FREE_FAILURES.render(
        &mut out,
        "objectio_block_shard_delete_failures_total",
        "Shard deletes that failed while freeing stripes, leaving space allocated, by reason",
    );

    let s = cache.stats();
    for (name, help, v) in [
        (
            "objectio_block_cache_dirty_bytes",
            "Bytes written and journaled but not yet stored as stripes",
            s.dirty_bytes,
        ),
        (
            "objectio_block_cache_dirty_chunks",
            "Chunks written and journaled but not yet stored as stripes",
            s.dirty_chunks as u64,
        ),
        (
            "objectio_block_cache_clean_bytes",
            "Bytes of stored chunks held in the cache for reads",
            s.clean_bytes,
        ),
        (
            "objectio_block_cache_volumes",
            "Volumes with a cache on this gateway",
            s.volume_count as u64,
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
    }
    objectio_block::journal::render_metrics(&mut out);
    out
}

/// Add the block gateway's metrics to this process's `/metrics` (aio).
pub fn register(cache: Arc<WriteCache>) {
    objectio_common::metrics_registry::register("block-gateway", move || render(&cache));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_dropped_unfinished_counts_as_an_error() {
        drop(Io::start(Protocol::Nbd, "test-op"));
        Io::start(Protocol::Nbd, "test-op").done(512);
        let cache = WriteCache::new(
            Arc::new(objectio_block::chunk::ChunkMapper::default()),
            objectio_block::CacheConfig::default(),
        )
        .unwrap();
        let out = render(&cache);
        assert!(
            out.contains("objectio_block_io_errors_total{protocol=\"nbd\",op=\"test-op\"} 1"),
            "{out}"
        );
        assert!(
            out.contains("objectio_block_io_bytes_total{protocol=\"nbd\",op=\"test-op\"} 512"),
            "{out}"
        );
        objectio_common::exposition::check(&out).unwrap();
    }
}
