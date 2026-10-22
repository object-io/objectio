//! A read that found a stripe short of shards tells meta (B29, heal on
//! read), which records the object as degraded and has its placement group
//! recovered within seconds. A write or delete left behind on some metadata
//! copies marks its key's placement group too
//! ([`crate::osd_pool::OsdPool::queue_heal`]): peering finds the copies that
//! disagree and recovery brings them in line.

/// When each key was last reported short of shards, so a hot object read
/// many times a second is reported once a minute, not on every read.
static REPORTED: std::sync::LazyLock<
    parking_lot::Mutex<std::collections::HashMap<String, std::time::Instant>>,
> = std::sync::LazyLock::new(Default::default);

/// How long a report of a key holds before the key is reported again.
const REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// A read found `bucket/key`'s stripe without a shard at `unreadable`
/// (B29, heal on read): tell meta, which records the object as degraded
/// and has it repaired within seconds, not at the next walk. In the
/// background.
#[allow(clippy::too_many_arguments)]
pub(crate) fn report_degraded(
    state: &std::sync::Arc<crate::AppState>,
    bucket: &str,
    key: &str,
    object_id: &[u8],
    stripe_id: u64,
    unreadable: &[u32],
    read: usize,
    k: u32,
) {
    let name = format!("{bucket}/{key}");
    {
        let mut reported = REPORTED.lock();
        let now = std::time::Instant::now();
        if reported
            .get(&name)
            .is_some_and(|at| now.duration_since(*at) < REPORT_EVERY)
        {
            return;
        }
        reported.retain(|_, at| now.duration_since(*at) < REPORT_EVERY);
        reported.insert(name.clone(), now);
    }
    let mut unreadable = unreadable.to_vec();
    unreadable.sort_unstable();
    unreadable.dedup();
    let req = objectio_proto::metadata::ReportDegradedRequest {
        bucket: bucket.to_string(),
        key: key.to_string(),
        object_id: object_id.to_vec(),
        stripes: vec![objectio_proto::metadata::DegradedStripe {
            stripe_id,
            missing: unreadable,
            present: u32::try_from(read).unwrap_or(u32::MAX),
            needed: k,
        }],
    };
    let mut meta = state.meta_client.clone();
    tokio::spawn(async move {
        match meta.report_degraded(req).await {
            Ok(r) if r.get_ref().recorded => {
                tracing::info!("{name}: read short of shards; reported for repair");
            }
            Ok(_) => {}
            Err(e) => tracing::debug!("{name}: reporting it short of shards: {e}"),
        }
    });
}
