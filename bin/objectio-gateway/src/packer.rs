//! The packer: moves small objects into packs in the background, phase 2 of
//! small-object packing (objectio-docs
//! architecture/design/small-object-packing.md).
//!
//! Off unless `--pack-interval-secs` is set. Every gateway runs the worker;
//! a lease in meta lets one pack at a time, as for lifecycle. Each pass:
//!
//! 1. Reconciles packs older than [`RECONCILE_AFTER`]: whatever a packer
//!    that died left half done is finished or undone (see
//!    [`crate::packs::reconcile`]).
//! 2. Walks every bucket for current objects that are small (above the
//!    inline cut-off, at most [`crate::packs::PACK_MAX`]), have their own
//!    one stripe, and haven't been written for `min_age` (so short-lived
//!    objects are never packed).
//! 3. Packs them in batches of up to [`PACK_TARGET`] bytes, through the same
//!    steps as the test hook: intend, write, seal, switch (only over the
//!    object read), release.
//!
//! A batch is packed only if it saves space: two objects at least, and
//! fewer raw bytes than their own stripes. At most [`PACKS_PER_PASS`] packs
//! are written a pass, so the packer can't swamp a cluster.

use std::sync::Arc;
use std::time::Duration;

use objectio_proto::metadata::{
    AcquireLeaseRequest, GetBucketVersioningRequest, ListBucketsRequest, VersioningState,
};
use tracing::{debug, info, warn};

use crate::s3::AppState;

const LEASE: &str = "packer";
const PAGE: u32 = 1000;

/// Bytes of object data a pack is filled to.
pub const PACK_TARGET: u64 = 1024 * 1024;

/// Packs written in one pass at most.
const PACKS_PER_PASS: usize = 64;

/// A pack this old and still unsettled had a packer die on it: no packer
/// takes this long over one pack.
const RECONCILE_AFTER: Duration = Duration::from_secs(600);

#[derive(Clone, Copy, Debug)]
pub struct Timing {
    pub interval: Duration,
    /// Objects written more recently than this are left alone.
    pub min_age: Duration,
}

/// Start the packer. Every gateway runs one; the lease lets one pack at a
/// time.
pub fn spawn_worker(state: Arc<AppState>, timing: Timing) {
    tokio::spawn(async move {
        let holder = uuid::Uuid::new_v4().to_string();
        info!(
            "Packer started (interval={}s, min age={}s)",
            timing.interval.as_secs(),
            timing.min_age.as_secs()
        );
        tokio::time::sleep(timing.interval.min(Duration::from_secs(60))).await;
        let mut ticker = tokio::time::interval(timing.interval);
        loop {
            ticker.tick().await;
            if !lease(&state, &holder, timing).await {
                debug!("packer: another gateway holds the lease");
                continue;
            }
            pass(&state, &holder, timing).await;
        }
    });
}

async fn lease(state: &AppState, holder: &str, timing: Timing) -> bool {
    let ttl = (timing.interval.as_secs() * 2).max(120);
    state
        .meta_client
        .clone()
        .acquire_lease(AcquireLeaseRequest {
            name: LEASE.to_string(),
            holder: holder.to_string(),
            ttl_secs: ttl,
            release: false,
        })
        .await
        .is_ok_and(|r| r.into_inner().acquired)
}

/// One pass: reconcile, then pack what's due.
async fn pass(state: &Arc<AppState>, holder: &str, timing: Timing) {
    match crate::packs::reconcile(state, RECONCILE_AFTER).await {
        Ok(r) if r.aborted + r.released + r.finished > 0 => info!("packer: reconciled {r:?}"),
        Ok(_) => {}
        Err(e) => warn!("packer: reconciliation: {e}"),
    }
    let buckets = match state
        .meta_client
        .clone()
        .list_buckets(ListBucketsRequest::default())
        .await
    {
        Ok(r) => r.into_inner().buckets,
        Err(e) => {
            warn!("packer: cannot list buckets: {e}");
            return;
        }
    };
    let mut packs = 0;
    for b in buckets {
        if packs >= PACKS_PER_PASS {
            break;
        }
        if !lease(state, holder, timing).await {
            warn!("packer: lost the lease mid-pass; stopping");
            return;
        }
        match pack_bucket(state, &b.name, timing, PACKS_PER_PASS - packs).await {
            Ok(n) => packs += n,
            Err(e) => warn!("packer: bucket {}: {e}", b.name),
        }
    }
    if packs > 0 {
        info!("packer: wrote {packs} packs");
    }
}

/// Pack `bucket`'s due objects, `budget` packs at most. Returns the packs
/// written.
async fn pack_bucket(
    state: &Arc<AppState>,
    bucket: &str,
    timing: Timing,
    budget: usize,
) -> Result<usize, String> {
    let versioned = state
        .meta_client
        .clone()
        .get_bucket_versioning(GetBucketVersioningRequest {
            bucket: bucket.to_string(),
        })
        .await
        .map_err(|e| e.to_string())?
        .into_inner()
        .state()
        != VersioningState::VersioningDisabled;
    let now = crate::lifecycle::now_ms();
    let min_age_ms = u64::try_from(timing.min_age.as_millis()).unwrap_or(u64::MAX);

    let mut written = 0;
    let mut batch: Vec<(String, u64)> = Vec::new();
    let mut marker = String::new();
    loop {
        let (found, more) = crate::s3::gather_versions(state, bucket, "", &marker, "", PAGE)
            .await
            .map_err(|r| format!("listing failed ({})", r.status()))?;
        let mut last = None;
        for (key, mut versions) in found {
            if !marker.is_empty() && key <= marker {
                continue;
            }
            last = Some(key.clone());
            crate::s3::sort_versions(&mut versions);
            let Some(current) = versions.first() else {
                continue;
            };
            let old_enough = now.saturating_sub(crate::s3::version_time_ms(current)) >= min_age_ms;
            if !old_enough || crate::packs::unpackable(current, versioned).is_some() {
                continue;
            }
            let fits = batch_bytes(&batch) + aligned(current.size) <= PACK_TARGET;
            if !fits {
                written += usize::from(pack_batch(state, bucket, &mut batch).await);
                if written >= budget {
                    return Ok(written);
                }
            }
            batch.push((key, current.size));
        }
        match last {
            Some(k) if more => marker = k,
            _ => break,
        }
    }
    written += usize::from(pack_batch(state, bucket, &mut batch).await);
    Ok(written)
}

const fn aligned(size: u64) -> u64 {
    size.div_ceil(4096) * 4096
}

fn batch_bytes(batch: &[(String, u64)]) -> u64 {
    batch.iter().map(|(_, size)| aligned(*size)).sum()
}

/// Pack `batch` and empty it, if packing it saves space. Whether a pack
/// was written.
async fn pack_batch(state: &Arc<AppState>, bucket: &str, batch: &mut Vec<(String, u64)>) -> bool {
    let taken = std::mem::take(batch);
    if !worth_packing(&taken) {
        return false;
    }
    let keys: Vec<String> = taken.into_iter().map(|(k, _)| k).collect();
    match crate::packs::pack_objects(state, bucket, &keys, None).await {
        Ok(r) if !r.pack_id.is_empty() => {
            debug!(
                "packer: {bucket}: pack {} holds {} objects ({} skipped)",
                r.pack_id,
                r.packed.len(),
                r.skipped.len()
            );
            true
        }
        Ok(_) => false,
        Err(e) => {
            warn!("packer: {bucket}: {e}");
            false
        }
    }
}

/// Two objects at least, and fewer raw bytes as one 4+2 pack than as their
/// own stripes. (Judged at 4+2; the pack is written with the bucket's
/// scheme, which only changes how much is saved.)
fn worth_packing(batch: &[(String, u64)]) -> bool {
    let own: u64 = batch
        .iter()
        .map(|(_, size)| crate::packs::raw_size(*size, 4, 2))
        .sum();
    batch.len() >= 2 && crate::packs::raw_size(batch_bytes(batch), 4, 2) < own
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(sizes: &[u64]) -> Vec<(String, u64)> {
        sizes.iter().map(|s| (String::new(), *s)).collect()
    }

    #[test]
    fn small_objects_are_worth_packing_and_one_alone_is_not() {
        assert!(worth_packing(&batch(&[8 * 1024; 10])));
        assert!(worth_packing(&batch(&[5_000; 3])));
        // Same raw bytes packed or not (120 KiB): nothing to gain.
        assert!(!worth_packing(&batch(&[5_000, 60_000])));
        assert!(!worth_packing(&batch(&[8 * 1024])));
        assert!(!worth_packing(&batch(&[])));
    }

    #[test]
    fn a_batch_is_measured_in_whole_blocks() {
        assert_eq!(batch_bytes(&batch(&[1, 4096, 4097])), 4096 + 4096 + 8192);
    }
}
