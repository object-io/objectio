//! The gateway's clock against meta's (core/object-metadata-quorum.md,
//! "Stamps"). A write's stamp is this gateway's wall time, and the copy
//! with the highest stamp wins: a gateway whose clock runs ahead would win
//! over later writes from the others, one running behind would lose its
//! own. So the gateway compares its clock with meta's every second and
//! refuses stamped writes (503) while the two differ by more than
//! [`MAX_SKEW_MS`].
//!
//! Until the first comparison, and against a meta that can't tell its time
//! (an older release, during a rolling upgrade), writes go ahead.

use objectio_proto::metadata::GetTimeRequest;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::time::Duration;
use tonic::transport::Channel;
use tracing::{error, info};

/// The most this gateway's clock may differ from meta's before it stops
/// stamping writes.
pub const MAX_SKEW_MS: i64 = 500;

const EVERY: Duration = Duration::from_secs(1);

/// This clock minus meta's, in milliseconds, at the last comparison.
static OFFSET_MS: AtomicI64 = AtomicI64::new(0);
/// Whether writes are refused now.
static SKEWED: AtomicBool = AtomicBool::new(false);

/// The clock this gateway stamps writes from.
fn now_ms() -> i64 {
    i64::try_from(objectio_common::stamp::wall_millis()).unwrap_or(i64::MAX)
}

/// The refusal, if this gateway's clock is too far from meta's to stamp a
/// write: a message for the error the write fails with.
pub fn refusal() -> Option<String> {
    SKEWED.load(Ordering::Relaxed).then(|| {
        format!(
            "this gateway's clock is {} ms from meta's (at most {MAX_SKEW_MS} ms allowed): \
             writes refused until it is synchronised",
            OFFSET_MS.load(Ordering::Relaxed)
        )
    })
}

/// Record one comparison: meta answered `meta_ms`, asked at `sent_ms` and
/// answered by `received_ms` on this clock. Meta read its clock somewhere
/// in between, so the offset is known to within half the round trip, and
/// only an offset beyond that uncertainty counts.
fn record(sent_ms: i64, received_ms: i64, meta_ms: i64) {
    let offset = (sent_ms + received_ms) / 2 - meta_ms;
    let uncertainty = (received_ms - sent_ms) / 2;
    OFFSET_MS.store(offset, Ordering::Relaxed);
    let skewed = offset.abs() - uncertainty > MAX_SKEW_MS;
    if skewed != SKEWED.swap(skewed, Ordering::Relaxed) {
        if skewed {
            error!(
                "clock is {offset} ms from meta's: refusing writes until it is within \
                 {MAX_SKEW_MS} ms (check NTP)"
            );
        } else {
            info!("clock is {offset} ms from meta's: writes resume");
        }
    }
}

/// Compare with meta's clock every second, for as long as the process runs.
pub fn spawn(meta: MetadataServiceClient<Channel>) {
    tokio::spawn(async move {
        loop {
            let mut client = meta.clone();
            let sent = now_ms();
            match client.get_time(GetTimeRequest {}).await {
                Ok(resp) => {
                    let meta_ms = i64::try_from(resp.into_inner().unix_millis).unwrap_or(0);
                    record(sent, now_ms(), meta_ms);
                }
                // An older meta: no comparison, no refusal.
                Err(s) if s.code() == tonic::Code::Unimplemented => {
                    SKEWED.store(false, Ordering::Relaxed);
                }
                // Meta unreachable: writes fail on their own; keep the last
                // comparison.
                Err(_) => {}
            }
            tokio::time::sleep(EVERY).await;
        }
    });
}

/// `objectio_gateway_clock_offset_seconds` and
/// `objectio_gateway_clock_skewed`, in Prometheus text.
pub fn render(out: &mut String) {
    #[allow(clippy::cast_precision_loss)]
    let offset = OFFSET_MS.load(Ordering::Relaxed) as f64 / 1000.0;
    out.push_str(
        "# HELP objectio_gateway_clock_offset_seconds This gateway's clock minus meta's\n\
         # TYPE objectio_gateway_clock_offset_seconds gauge\n",
    );
    out.push_str(&format!("objectio_gateway_clock_offset_seconds {offset}\n"));
    out.push_str(
        "# HELP objectio_gateway_clock_skewed 1 while writes are refused for clock skew\n\
         # TYPE objectio_gateway_clock_skewed gauge\n",
    );
    out.push_str(&format!(
        "objectio_gateway_clock_skewed {}\n",
        u8::from(SKEWED.load(Ordering::Relaxed))
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test: the state is process-wide.
    #[test]
    fn writes_are_refused_only_beyond_the_limit_and_the_round_trip() {
        let t = 1_000_000;
        record(t, t + 10, t + 5);
        assert!(refusal().is_none(), "in step");

        record(t, t + 10, t + 5 - 600);
        let why = refusal().expect("600 ms ahead");
        assert!(why.contains("600 ms"), "{why}");

        record(t, t + 10, t + 5 + 600);
        assert!(refusal().is_some(), "600 ms behind");

        // 520 ms off, but meta may have read its clock anywhere in a 200 ms
        // round trip: not provably beyond 500.
        record(t, t + 200, t + 100 - 520);
        assert!(refusal().is_none());

        record(t, t + 10, t + 5);
        assert!(refusal().is_none(), "back in step");
    }
}
