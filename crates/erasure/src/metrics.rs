//! Time spent erasure coding in this process.

use objectio_common::histogram::{CounterVec, Histogram, HistogramVec, LATENCY_BUCKETS};
use std::sync::LazyLock;

pub static ENCODE_SECONDS: LazyLock<Histogram> = LazyLock::new(|| Histogram::new(LATENCY_BUCKETS));

/// Labelled `path="fast"` (all data shards present) or
/// `path="reconstruct"` (parity used).
pub static DECODE_SECONDS: LazyLock<HistogramVec> =
    LazyLock::new(|| HistogramVec::new(LATENCY_BUCKETS));

/// Decodes whose rebuilt data shards could not be shown to be the ones
/// written ([`crate::ErasureCodec::decode_verified`]): not served.
pub static REBUILDS_REJECTED: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);

/// Append the encode/decode families to `out`.
pub fn render(out: &mut String) {
    ENCODE_SECONDS.render(
        out,
        "objectio_erasure_encode_seconds",
        "Time to erasure-encode one stripe",
        "",
    );
    DECODE_SECONDS.render(
        out,
        "objectio_erasure_decode_seconds",
        "Time to decode one stripe; path=reconstruct means parity was needed",
        "",
    );
    REBUILDS_REJECTED.render(
        out,
        "objectio_erasure_rebuilds_rejected_total",
        "Decodes whose rebuilt data shards did not match the checksums their stripe records, or could not be checked; not served",
    );
}
