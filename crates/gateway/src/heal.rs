//! Healing: makes a key's ObjectMeta copies agree again after a write or
//! delete reached the quorum but not every copy (objectio-docs
//! `core/object-metadata-quorum.md`, healing).
//!
//! Such a write queues its key in meta's heal queue before it is
//! acknowledged. Every gateway works the queue: it claims an entry (a lease
//! in meta, so two gateways don't heal one key at once), reads every copy
//! of the key's current entry (and of the version the write was of), and
//!
//! - writes the newest object, stamp and all, to the copies that hold an
//!   older one or none;
//! - or, when a delete is newest, carries it out on the copies that still
//!   hold the object;
//!
//! then frees what that displaced or removed once no copy references it,
//! and removes the entry (unless the key was queued again meanwhile). A copy
//! that can't be reached leaves the entry for a later pass.

use std::sync::Arc;
use std::time::Duration;

use objectio_proto::metadata::{
    GetPlacementRequest, HealClaimRequest, HealDoneRequest, HealEntry, HealListRequest,
    NodePlacement, ObjectMeta,
};
use objectio_proto::storage::{
    DeleteObjectMetaRequest, GetObjectMetaRequest, PutObjectMetaRequest,
};
use tracing::{debug, info, warn};

use crate::osd_pool::{Reclaim, reclaim_shards, stripe_targets_of, unreferenced};
use crate::s3::AppState;

/// Entries taken per pass.
const BATCH: u32 = 100;

/// How long a claim holds an entry: long enough to heal a key.
const LEASE: Duration = Duration::from_secs(120);

/// Work the heal queue every `every`; 0 turns healing off.
pub fn spawn(state: Arc<AppState>, every: Duration) {
    if every.is_zero() {
        return;
    }
    let claimer = format!("gateway-{}", uuid::Uuid::new_v4());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            pass(&state, &claimer).await;
        }
    });
}

/// One pass over the queue.
pub async fn pass(state: &Arc<AppState>, claimer: &str) {
    let mut meta = state.meta_client.clone();
    let entries = match meta.heal_list(HealListRequest { limit: BATCH }).await {
        Ok(r) => r.into_inner().entries,
        Err(e) => {
            debug!("heal: cannot list the queue: {e}");
            return;
        }
    };
    for entry in entries {
        let claimed = match meta
            .heal_claim(HealClaimRequest {
                entry: Some(entry),
                claimer: claimer.to_string(),
                lease_ms: u64::try_from(LEASE.as_millis()).unwrap_or(u64::MAX),
            })
            .await
        {
            Ok(r) => r.into_inner(),
            Err(e) => {
                debug!("heal: cannot claim: {e}");
                continue;
            }
        };
        let Some(entry) = claimed.entry.filter(|_| claimed.claimed) else {
            continue; // another gateway has it
        };
        if heal_key(state, &entry).await {
            let done = meta
                .heal_done(HealDoneRequest {
                    entry: Some(entry.clone()),
                })
                .await
                .is_ok_and(|r| r.into_inner().done);
            crate::gateway_metrics::record_heal(if done { "healed" } else { "requeued" });
        } else {
            // Left claimed: retried once the lease runs out.
            crate::gateway_metrics::record_heal("retry");
        }
    }
}

/// Make every copy of `entry`'s key agree. False when a copy couldn't be
/// reached (or the placement read), to retry later.
async fn heal_key(state: &Arc<AppState>, entry: &HealEntry) -> bool {
    let (bucket, key) = (entry.bucket.as_str(), entry.key.as_str());
    let placement = match state
        .meta_client
        .clone()
        .get_placement(GetPlacementRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            size: 0,
            storage_class: "STANDARD".to_string(),
        })
        .await
    {
        Ok(p) => p.into_inner(),
        Err(e) => {
            debug!("heal {bucket}/{key}: no placement: {e}");
            return false;
        }
    };
    let mut copies: Vec<NodePlacement> = Vec::new();
    for n in placement.nodes {
        if !copies.iter().any(|c| c.node_id == n.node_id) {
            copies.push(n);
        }
    }

    let mut freed = Vec::new();
    for version_id in
        std::iter::once("").chain(Some(entry.version_id.as_str()).filter(|v| !v.is_empty()))
    {
        match converge(state, &copies, bucket, key, version_id).await {
            Some(gone) => freed.extend(gone),
            None => return false,
        }
    }

    // Free what the copies let go of, once none of them still has it.
    let gone = unreferenced(&state.osd_pool, &copies, bucket, key, freed).await;
    for object in gone {
        reclaim_shards(
            &state.osd_pool,
            &mut state.meta_client.clone(),
            stripe_targets_of(&object),
            Reclaim::Delete,
        )
        .await;
    }
    // The listing too: a write or delete queued here may have reached its
    // copies while meta couldn't take the listing update.
    crate::s3::sync_listing(state, &copies, bucket, key).await;
    info!("healed {bucket}/{key} (version {:?})", entry.version_id);
    true
}

/// What one copy holds of the entry: its object (if any) and the stamp of
/// its last delete of it (0 if none).
struct Held {
    object: Option<ObjectMeta>,
    deleted_at: u64,
}

/// Bring every copy of `bucket/key`'s entry (`version_id` empty: the
/// current object) to the newest: the newest object, or deleted. Returns
/// the objects the copies displaced or removed doing so; `None` when a copy
/// couldn't be read or written.
async fn converge(
    state: &Arc<AppState>,
    copies: &[NodePlacement],
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Option<Vec<ObjectMeta>> {
    let pool = &state.osd_pool;
    let mut held = Vec::with_capacity(copies.len());
    for c in copies {
        let mut client = pool.get_client_for_placement(c).await.ok()?;
        let r = tokio::time::timeout(
            Duration::from_secs(10),
            client.get_object_meta(GetObjectMetaRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
                with_small_shard: false,
            }),
        )
        .await
        .ok()?
        .ok()?
        .into_inner();
        held.push(Held {
            object: r.object.filter(|_| r.found),
            deleted_at: r.tombstone_stamp,
        });
    }
    let newest = held
        .iter()
        .filter_map(|h| h.object.as_ref())
        .max_by(|a, b| a.write_order().cmp(&b.write_order()))
        .cloned();
    let deleted_at = held.iter().map(|h| h.deleted_at).max().unwrap_or(0);

    let mut gone = Vec::new();
    match newest {
        // The object is newest: every copy gets it, as it is.
        Some(newest) if deleted_at == 0 || deleted_at < newest.stamp => {
            for (c, h) in copies.iter().zip(&held) {
                if h.object
                    .as_ref()
                    .is_some_and(|o| o.write_order() == newest.write_order())
                {
                    continue;
                }
                let mut client = pool.get_client_for_placement(c).await.ok()?;
                let r = tokio::time::timeout(
                    Duration::from_secs(10),
                    client.put_object_meta(PutObjectMetaRequest {
                        bucket: bucket.to_string(),
                        key: key.to_string(),
                        object: Some(newest.clone()),
                        // The version entry alone, for a version; the current
                        // entry (and its own version entry) for the key.
                        version_only: !version_id.is_empty(),
                        ..Default::default()
                    }),
                )
                .await
                .ok()?
                .ok()?
                .into_inner();
                gone.extend(r.replaced.filter(|_| !r.replaced_version_kept));
            }
        }
        // A delete is newest: carried out wherever the object remains.
        Some(_) => {
            for (c, h) in copies.iter().zip(&held) {
                if h.object.is_none() {
                    continue;
                }
                let mut client = pool.get_client_for_placement(c).await.ok()?;
                let r = tokio::time::timeout(
                    Duration::from_secs(10),
                    client.delete_object_meta(DeleteObjectMetaRequest {
                        bucket: bucket.to_string(),
                        key: key.to_string(),
                        version_id: version_id.to_string(),
                        stamp: deleted_at,
                        ..Default::default()
                    }),
                )
                .await
                .ok()?
                .ok()?
                .into_inner();
                gone.extend(r.removed);
            }
        }
        None => {}
    }
    if !gone.is_empty() {
        warn!(
            "heal {bucket}/{key} (version {version_id:?}): {} stale copies brought up to date",
            gone.len()
        );
    }
    Some(gone)
}

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
/// background; a meta that doesn't know the call (the previous release)
/// is ignored.
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
            Err(e) if e.code() == tonic::Code::Unimplemented => {}
            Err(e) => tracing::debug!("{name}: reporting it short of shards: {e}"),
        }
    });
}
