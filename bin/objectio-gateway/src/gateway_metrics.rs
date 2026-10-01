//! Request, auth and backend metrics recorded by the gateway itself, on
//! top of the per-operation counters in `objectio_s3::metrics`.
//!
//! Label values are bounded: operations come from the S3 operation enum,
//! HTTP codes and S3 error names are bucketed to known sets, and OSD
//! addresses are bounded by the cluster size.

use objectio_common::histogram::{
    CounterVec, GaugeVec, HistogramVec, LATENCY_BUCKETS, SIZE_BUCKETS, label_value,
};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

/// The S3 error name carried on an error response, set by whoever built
/// it, so the metrics layer can label the failure without parsing XML.
#[derive(Clone, Debug)]
pub struct S3ErrorCode(pub String);

static REQUEST_ERRORS: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static AUTH_FAILURES: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static IN_FLIGHT: LazyLock<GaugeVec> = LazyLock::new(GaugeVec::new);
static REQUEST_SIZE: LazyLock<HistogramVec> = LazyLock::new(|| HistogramVec::new(SIZE_BUCKETS));
static SHARD_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| HistogramVec::new(LATENCY_BUCKETS));
static OSD_ERRORS: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static SHARD_TRANSFERS: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static RDMA_FALLBACKS: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static SHARD_CHECKSUM_MISMATCHES: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static PHASE_LATENCY: LazyLock<HistogramVec> = LazyLock::new(|| HistogramVec::new(LATENCY_BUCKETS));
static SHARDS_RECLAIMED: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static RECLAIM_FAILURES: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static DEDUP_CHUNKS: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static DEDUP_BYTES: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static DEDUP_DROPPED: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static DEDUP_SKIPPED: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);

/// HTTP codes worth their own series; anything else is `4xx` / `5xx`.
const KNOWN_CODES: &[u16] = &[
    400, 401, 403, 404, 405, 409, 411, 412, 413, 416, 429, 500, 501, 502, 503, 504,
];

fn code_label(status: u16) -> String {
    if KNOWN_CODES.contains(&status) {
        status.to_string()
    } else {
        format!("{}xx", status / 100)
    }
}

/// S3 error names are CamelCase identifiers from a fixed vocabulary; keep
/// anything else out of the label.
fn error_label(name: Option<&str>) -> &str {
    match name {
        Some(n)
            if !n.is_empty() && n.len() <= 48 && n.chars().all(|c| c.is_ascii_alphanumeric()) =>
        {
            n
        }
        _ => "Unknown",
    }
}

/// A failed S3 request: `code` is the HTTP status, `error` the S3 error
/// name when the response carried one.
pub fn record_error(operation: &str, status: u16, error: Option<&str>) {
    REQUEST_ERRORS.inc(&format!(
        "operation=\"{operation}\",code=\"{}\",error=\"{}\"",
        code_label(status),
        error_label(error)
    ));
}

/// Why a request was refused before reaching its handler.
pub fn record_auth_failure(reason: &str) {
    AUTH_FAILURES.inc(&format!("reason=\"{reason}\""));
}

/// Tracks one in-flight request; decrements on drop, so a handler that
/// panics or is cancelled still leaves the gauge right.
pub struct InFlight(String);

impl InFlight {
    #[must_use]
    pub fn start(operation: &str) -> Self {
        let labels = format!("operation=\"{operation}\"");
        IN_FLIGHT.add(&labels, 1);
        Self(labels)
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.add(&self.0, -1);
    }
}

#[allow(clippy::cast_precision_loss)]
pub fn record_request_size(operation: &str, bytes: u64) {
    REQUEST_SIZE.observe(&format!("operation=\"{operation}\""), bytes as f64);
}

/// One shard read or write to an OSD, successful or not.
pub fn record_shard_io(address: &str, direction: &str, elapsed: Duration) {
    SHARD_LATENCY.observe_duration(
        &format!(
            "address=\"{}\",direction=\"{direction}\"",
            label_value(address)
        ),
        elapsed,
    );
}

/// A failed call to an OSD. `kind` is `timeout`, `refused` (could not
/// connect) or `error` (the OSD answered with an error).
pub fn record_osd_error(address: &str, kind: &str) {
    OSD_ERRORS.inc(&format!(
        "address=\"{}\",kind=\"{kind}\"",
        label_value(address)
    ));
}

/// A shard moved to or from an OSD. `direction` is `write` or `read`;
/// `transport` is `rdma` (Transfer Engine) or `grpc` (bytes in the message).
pub fn record_shard_transfer(direction: &str, transport: &str) {
    SHARD_TRANSFERS.inc(&format!(
        "direction=\"{direction}\",transport=\"{transport}\""
    ));
}

/// A shard that could have used Transfer Engine went over gRPC instead.
pub fn record_rdma_fallback(direction: &str, reason: crate::rdma::Fallback) {
    RDMA_FALLBACKS.inc(&format!(
        "direction=\"{direction}\",reason=\"{}\"",
        reason.label()
    ));
}

/// A shard sent as gRPC bytes that did not match its checksum: on `read`
/// the gateway dropped it, on `write` the OSD refused it. Transfer Engine
/// mismatches are counted as `rdma_fallbacks_total{reason="checksum"}`.
pub fn record_shard_checksum_mismatch(direction: &str) {
    SHARD_CHECKSUM_MISMATCHES.inc(&format!("direction=\"{direction}\""));
}

/// Shards deleted because nothing referenced them any more, and deletes
/// that failed (their blocks stay allocated). `reason` is a fixed label from
/// [`crate::osd_pool::Reclaim`].
pub fn record_reclaim(reason: &str, reclaimed: u64, failed: u64) {
    let labels = format!("reason=\"{reason}\"");
    SHARDS_RECLAIMED.add(&labels, reclaimed);
    RECLAIM_FAILURES.add(&labels, failed);
}

/// A chunk the dedup dry-run fingerprinted in `bucket` under `chunking`:
/// already stored in its domain (`duplicate`) or not (`new`).
pub fn record_dedup_chunk(bucket: &str, chunking: &str, duplicate: bool, bytes: u64) {
    let result = if duplicate { "duplicate" } else { "new" };
    let labels = format!("bucket=\"{bucket}\",chunking=\"{chunking}\",result=\"{result}\"");
    DEDUP_CHUNKS.inc(&labels);
    DEDUP_BYTES.add(&labels, bytes);
}

/// Dry-run work given up on, so its numbers undercount by this much.
pub fn record_dedup_dropped(reason: &str) {
    DEDUP_DROPPED.inc(&format!("reason=\"{reason}\""));
}

/// A write in a dry-run bucket that dry-run does not look at.
pub fn record_dedup_skipped(reason: &str) {
    DEDUP_SKIPPED.inc(&format!("reason=\"{reason}\""));
}

/// Splits one request's time into consecutive phases. Each [`mark`] records
/// the time since the previous one, so the phases of a request add up to the
/// part of it the handler spent between the first and last mark.
///
/// [`mark`]: Self::mark
pub struct PhaseTimer {
    operation: &'static str,
    last: Instant,
}

impl PhaseTimer {
    #[must_use]
    pub fn start(operation: &'static str) -> Self {
        Self {
            operation,
            last: Instant::now(),
        }
    }

    /// End the current phase and name it. `phase` is a fixed identifier
    /// from the handler, never request data.
    pub fn mark(&mut self, phase: &'static str) {
        let now = Instant::now();
        PHASE_LATENCY.observe_duration(
            &format!("operation=\"{}\",phase=\"{phase}\"", self.operation),
            now - self.last,
        );
        self.last = now;
    }
}

/// Everything above, plus erasure coding time, as Prometheus families.
#[must_use]
pub fn render() -> String {
    let mut out = String::new();
    REQUEST_ERRORS.render(
        &mut out,
        "objectio_s3_request_errors_total",
        "Failed S3 requests by HTTP code and S3 error name",
    );
    AUTH_FAILURES.render(
        &mut out,
        "objectio_auth_failures_total",
        "Requests refused by authentication or authorization, by reason",
    );
    IN_FLIGHT.render(
        &mut out,
        "objectio_s3_requests_in_flight",
        "S3 requests currently being served",
    );
    REQUEST_SIZE.render(
        &mut out,
        "objectio_s3_request_size_bytes",
        "Request body size (Content-Length) by operation",
        "",
    );
    SHARD_LATENCY.render(
        &mut out,
        "objectio_gateway_shard_latency_seconds",
        "Time for one shard read or write to an OSD, by OSD",
        "",
    );
    PHASE_LATENCY.render(
        &mut out,
        "objectio_gateway_request_phase_seconds",
        "Time spent in each phase of a request, by operation and phase",
        "",
    );
    OSD_ERRORS.render(
        &mut out,
        "objectio_gateway_osd_request_errors_total",
        "Failed shard calls to an OSD, by kind",
    );
    SHARD_TRANSFERS.render(
        &mut out,
        "objectio_gateway_shard_transfers_total",
        "Shards moved to or from OSDs, by direction and transport (rdma or grpc)",
    );
    RDMA_FALLBACKS.render(
        &mut out,
        "objectio_gateway_rdma_fallbacks_total",
        "Shards sent over gRPC to an OSD that offers Transfer Engine, by reason",
    );
    SHARD_CHECKSUM_MISMATCHES.render(
        &mut out,
        "objectio_gateway_shard_checksum_mismatches_total",
        "Shards sent over gRPC that did not match their checksum, by direction",
    );
    SHARDS_RECLAIMED.render(
        &mut out,
        "objectio_gateway_shards_reclaimed_total",
        "Shards deleted from OSDs because nothing references them any more, by reason",
    );
    RECLAIM_FAILURES.render(
        &mut out,
        "objectio_gateway_shard_reclaim_failures_total",
        "Shard deletes that failed, leaving the block allocated, by reason",
    );
    DEDUP_CHUNKS.render(
        &mut out,
        "objectio_dedup_dryrun_chunks_total",
        "Chunks the dedup dry-run fingerprinted, by bucket, chunking and whether already stored",
    );
    DEDUP_BYTES.render(
        &mut out,
        "objectio_dedup_dryrun_bytes_total",
        "Bytes the dedup dry-run fingerprinted, by bucket, chunking and whether already stored",
    );
    DEDUP_DROPPED.render(
        &mut out,
        "objectio_dedup_dryrun_dropped_total",
        "Dry-run work given up on (queue full, lookup failed), by reason",
    );
    DEDUP_SKIPPED.render(
        &mut out,
        "objectio_dedup_dryrun_skipped_total",
        "Writes in dry-run buckets that dry-run does not look at, by reason",
    );
    objectio_erasure::metrics::render(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_stay_bounded() {
        assert_eq!(code_label(404), "404");
        assert_eq!(code_label(418), "4xx");
        assert_eq!(
            error_label(Some("SignatureDoesNotMatch")),
            "SignatureDoesNotMatch"
        );
        assert_eq!(error_label(Some("x\" injected")), "Unknown");
        assert_eq!(error_label(None), "Unknown");
    }

    #[test]
    fn in_flight_returns_to_zero_on_drop() {
        {
            let _a = InFlight::start("TestOp");
            assert!(render().contains("objectio_s3_requests_in_flight{operation=\"TestOp\"} 1"));
        }
        assert!(render().contains("objectio_s3_requests_in_flight{operation=\"TestOp\"} 0"));
    }

    #[test]
    fn checksum_mismatches_are_counted_by_direction() {
        record_shard_checksum_mismatch("read");
        assert!(
            render()
                .contains("objectio_gateway_shard_checksum_mismatches_total{direction=\"read\"}")
        );
    }

    #[test]
    fn phase_timer_records_each_phase_once() {
        let mut t = PhaseTimer::start("PhaseTestOp");
        t.mark("first");
        t.mark("second");
        let out = render();
        for phase in ["first", "second"] {
            assert!(out.contains(&format!(
                "objectio_gateway_request_phase_seconds_count{{operation=\"PhaseTestOp\",phase=\"{phase}\"}} 1"
            )));
        }
    }
}
