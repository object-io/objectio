//! Time spent erasure coding in this process.

use objectio_common::histogram::{Histogram, HistogramVec, LATENCY_BUCKETS};
use std::sync::LazyLock;

pub static ENCODE_SECONDS: LazyLock<Histogram> = LazyLock::new(|| Histogram::new(LATENCY_BUCKETS));

/// Labelled `path="fast"` (all data shards present) or
/// `path="reconstruct"` (parity used).
pub static DECODE_SECONDS: LazyLock<HistogramVec> =
    LazyLock::new(|| HistogramVec::new(LATENCY_BUCKETS));

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
}
