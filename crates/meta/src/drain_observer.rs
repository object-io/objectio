//! Drain observer **and** migrator (Phase 3a + 3b).
//!
//! Per sweep on the Raft leader, this task:
//!
//!  1. Finds OSDs marked `admin_state = Draining`.
//!  2. Updates each one's `DrainProgress` entry (shards_remaining,
//!     initial_shards on first sight) from the OSD's `GetStatus`.
//!  3. Migrates ONE affected shard per Draining OSD per sweep — reads
//!     from the draining OSD, writes to a CRUSH-chosen target,
//!     rewrites the ObjectMeta's ShardLocation on the primary OSD,
//!     deletes the source. Bounded concurrency (one per OSD per sweep)
//!     keeps live-traffic impact small and makes the progress bar
//!     advance smoothly.
//!  4. Flips Draining → Out when the OSD's `shard_count` hits 0.
//!
//! Non-goals for this phase:
//!  - LRC / replication (only MDS EC for now).
//!  - Reading the object's own ec_k/ec_m from its ObjectMeta to
//!    recompute CRUSH with the right template. We use the meta
//!    service's `default_ec_k/m` — this is correct for the common
//!    case where every object in the cluster uses the same scheme.
//!    Phase 3c: look up the object's ec scheme from its metadata.
//!  - Crash-safe resume: progress is in-memory, lost on leader
//!    failover, reconstructed on the next sweep. Safe because
//!    migration operations are idempotent at the shard level.

use std::sync::Arc;
use std::time::Duration;

use objectio_proto::metadata::{ObjectMeta, ShardLocation, StripeMeta};
use objectio_proto::storage::{
    Checksum, FindObjectsReferencingNodeRequest, GetObjectMetaRequest, GetStatusRequest,
    PutObjectMetaRequest, ReadShardRequest, ReadShardResponse, ShardId, WriteShardRequest,
    storage_service_client::StorageServiceClient,
};
use tokio::time::{MissedTickBehavior, interval};
use tonic::transport::Channel;
use tracing::{debug, info, warn};

use crate::service::MetaService;

/// Shard moves in flight at once within a sweep.
const MOVES_AT_ONCE: usize = 16;

/// Shards moved per sweep from a lost OSD (Out, not yet emptied: B26), at
/// least: its shards are each one copy short until moved, so it goes as
/// fast as rebuilding allows, not at a drain's gentle pace.
const LOST_BATCH: usize = 512;

/// Per-RPC timeout when talking to an OSD during a sweep.
const PER_OSD_TIMEOUT: Duration = Duration::from_secs(10);

/// Fan out an ObjectMeta write to every OSD that currently holds a shard for
/// the object. With ObjectMeta replicated on all k+m shard hosts (MinIO
/// xl.meta / Ceph OMAP pattern), every shard migration, reconstruction, or
/// rebalance must refresh every replica so reads from any surviving host
/// stay consistent. `extra_addrs` lets callers (drain/rebalance) also update
/// stale copies on OSDs that just LOST a shard — without those the old
/// owner's local meta keeps claiming it holds the shard, the rebalancer
/// re-spots "drift" every sweep and the migration loop never converges.
/// Falls back to `fallback_addr` when neither source yields any addresses.
/// Succeeds if at least one write lands.
async fn fanout_put_object_meta(
    meta: &Arc<MetaService>,
    object: &objectio_proto::metadata::ObjectMeta,
    fallback_addr: &str,
    extra_addrs: &[&str],
) -> anyhow::Result<()> {
    let mut replica_ids: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    for stripe in &object.stripes {
        for shard in &stripe.shards {
            if !shard.node_id.is_empty() {
                replica_ids.insert(shard.node_id.clone());
            }
        }
    }
    let mut addr_set: std::collections::HashSet<String> = std::collections::HashSet::new();
    for nid in &replica_ids {
        if let Ok(arr) = <[u8; 16]>::try_from(nid.as_slice())
            && let Some(addr) = meta.osd_address_by_id(&arr)
        {
            addr_set.insert(addr);
        }
    }
    // A lost OSD has no address: nothing to tell it.
    for extra in extra_addrs.iter().filter(|a| !a.is_empty()) {
        addr_set.insert((*extra).to_string());
    }
    let mut addrs: Vec<String> = addr_set.into_iter().collect();
    if addrs.is_empty() {
        addrs.push(fallback_addr.to_string());
    }

    // An update of what was read: ordered after its other updates, the same
    // on every copy; its stamp stays, so a newer object still wins.
    let mut object = object.clone();
    object.update_stamp = objectio_common::stamp::CLOCK.next_after(object.update_stamp);
    let object = &object;
    let mut futs = Vec::with_capacity(addrs.len());
    for addr in &addrs {
        let addr = addr.clone();
        let req = PutObjectMetaRequest {
            require_existing: false,
            version_only: false,
            keep_newer_current: false,
            replication_update: false,
            replication_set: std::collections::HashMap::new(),
            shard: None,
            bucket: object.bucket.clone(),
            key: object.key.clone(),
            object: Some(object.clone()),
            versioning_enabled: false,
            // Built from an earlier read: refuse to put the object back if a
            // PUT has replaced it since (that PUT freed its shards).
            expected_object_id: object.object_id.clone(),
        };
        futs.push(async move {
            let ch = open_channel(&addr).await?;
            let mut client = StorageServiceClient::new(ch);
            tokio::time::timeout(PER_OSD_TIMEOUT, client.put_object_meta(req))
                .await
                .map_err(|_| anyhow::anyhow!("put_object_meta timeout on {addr}"))??;
            Ok::<_, anyhow::Error>(addr)
        });
    }

    let results = futures::future::join_all(futs).await;
    let mut ok = 0usize;
    for r in results {
        match r {
            Ok(addr) => {
                ok += 1;
                debug!("fanout_put_object_meta: ok on {addr}");
            }
            Err(e) => warn!("fanout_put_object_meta replica failed: {e}"),
        }
    }
    if ok == 0 {
        return Err(anyhow::anyhow!(
            "fanout_put_object_meta: every replica failed for {}/{}",
            object.bucket,
            object.key
        ));
    }
    Ok(())
}

/// Spawn the drain observer. Non-blocking; returns immediately.
pub fn spawn(meta: Arc<MetaService>, every: Duration, batch: usize) {
    tokio::spawn(async move {
        run(meta, every, batch).await;
    });
    info!("Drain observer spawned (sweep every {every:?}, up to {batch} shards a sweep)");
}

async fn run(meta: Arc<MetaService>, every: Duration, batch: usize) {
    let mut ticker = interval(every);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // CRUSH-drift per-shard rebalancer is disabled: the PG balancer
    // owns placement decisions now, and ObjectIO is greenfield — no
    // existing-data migration is required. The drain (evacuate-on-
    // admin-state=Draining) sweep stays.
    loop {
        ticker.tick().await;
        // While a sweep moves anything, the next follows at once: waiting
        // the interval between batches made a lost OSD's 158,000 shards an
        // eleven-hour job (B2 soak).
        loop {
            match sweep_once(&meta, batch).await {
                Ok(true) => tokio::task::yield_now().await,
                Ok(false) => break,
                Err(e) => {
                    warn!("drain observer sweep failed: {e}");
                    break;
                }
            }
        }
    }
}

/// One sweep; whether it moved anything (another may follow at once).
async fn sweep_once(meta: &Arc<MetaService>, batch: usize) -> anyhow::Result<bool> {
    if !meta.is_raft_leader() {
        debug!("drain observer: not leader, skipping sweep");
        return Ok(false);
    }

    // Drained OSDs whose purge hasn't been confirmed yet (it was offline,
    // or this is a new leader): try again.
    purge_pending(meta).await;

    // Evacuated: Draining OSDs, and Out ones not emptied yet (an OSD set
    // Out directly is gone for good: what it held is rebuilt from the
    // others, B26). An Out OSD that a drain emptied has a purge record.
    let draining: Vec<([u8; 16], String, bool)> = {
        let osds = meta.osd_nodes_read().clone();
        osds.into_iter()
            .filter(|n| {
                n.admin_state == objectio_common::OsdAdminState::Draining
                    || (n.admin_state == objectio_common::OsdAdminState::Out
                        && meta.purge_state(n.node_id).is_none())
            })
            .map(|n| {
                let out = n.admin_state == objectio_common::OsdAdminState::Out;
                (n.node_id, n.address, out)
            })
            .collect()
    };

    // Clean up stale progress entries for OSDs that are no longer
    // Draining (flipped back to In or removed). Keeps /_admin/drain-status
    // honest.
    {
        let draining_ids: std::collections::HashSet<[u8; 16]> =
            draining.iter().map(|(id, _, _)| *id).collect();
        let existing: Vec<[u8; 16]> = meta.drain_statuses_snapshot().keys().copied().collect();
        for id in existing {
            if !draining_ids.contains(&id) {
                meta.clear_drain_progress(&id);
            }
        }
    }

    if draining.is_empty() {
        return Ok(false);
    }
    let mut moved_any = false;

    debug!("drain observer: sweeping {} draining OSDs", draining.len());

    for (node_id, address, out) in draining {
        // Always update shard_count first — the auto-finalize check
        // depends on it. Progress mirrors the observed count so the
        // console shows "X of Y migrated" even when migration stalls.
        let observed = match query_shard_count(&address).await {
            Ok(s) => {
                meta.update_drain_progress(node_id, |p| {
                    if p.initial_shards == 0 {
                        p.initial_shards = s;
                    }
                    p.shards_remaining = s;
                    p.updated_at = now_unix();
                    p.last_error.clear();
                });
                Some(s)
            }
            Err(e) => {
                // It doesn't answer: what it held is rebuilt from the rest
                // of each stripe instead of copied (B26).
                meta.update_drain_progress(node_id, |p| {
                    p.last_error = format!("osd unreachable ({e}): rebuilding from the others");
                    p.updated_at = now_unix();
                });
                None
            }
        };

        // Move what refers to it; finalise once nothing does.
        let batch = if out { batch.max(LOST_BATCH) } else { batch };
        let scan = migrate_batch(meta, node_id, &address, observed.is_some(), batch).await;
        moved_any |= scan.moved > 0;
        if drain_step(Some(scan)) == DrainStep::Finalise {
            info!(
                "drain observer: nothing refers to OSD {} any more; finalising → Out",
                hex::encode(node_id)
            );
            if address.is_empty() {
                // Lost, its address taken by a replacement: nothing to
                // wipe, so its entry just goes.
                match meta.forget_osd(node_id).await {
                    Ok(()) => {
                        meta.clear_drain_progress(&node_id);
                        info!(
                            "drain observer: lost OSD {} evacuated; entry removed",
                            hex::encode(node_id)
                        );
                    }
                    Err(e) => warn!(
                        "drain observer: removing lost OSD {}: {e}",
                        hex::encode(node_id)
                    ),
                }
                continue;
            }
            let flipped = if out {
                Ok(())
            } else {
                meta.internal_set_osd_admin_state(
                    node_id,
                    objectio_common::OsdAdminState::Out,
                    "drain-observer".into(),
                )
                .await
            };
            match flipped {
                Ok(()) => {
                    meta.clear_drain_progress(&node_id);
                    // Nothing refers to anything on it now: its shards and
                    // metadata copies are garbage. Recorded first, so a purge
                    // that can't run now is retried, and the OSD can't be put
                    // back In with them.
                    if let Err(e) = meta.set_purge_state(node_id, Some(PURGE_PENDING)).await {
                        warn!(
                            "drain observer: recording purge for {}: {e}",
                            hex::encode(node_id)
                        );
                    } else {
                        purge_one(meta, node_id, &address).await;
                    }
                }
                Err(e) => warn!(
                    "drain observer: failed to flip {} → Out: {e}",
                    hex::encode(node_id)
                ),
            }
        }
    }

    Ok(moved_any)
}

/// Recorded for a drained OSD until its purge is confirmed.
pub const PURGE_PENDING: &str = "pending";
/// Recorded once a drained OSD has been purged.
pub const PURGE_DONE: &str = "done";

/// Retry the purge of every drained OSD still pending.
async fn purge_pending(meta: &Arc<MetaService>) {
    let pending = meta.pending_purges();
    if pending.is_empty() {
        return;
    }
    let osds = meta.osd_nodes_read().clone();
    for node_id in pending {
        let Some(node) = osds.iter().find(|n| n.node_id == node_id) else {
            // Removed from the cluster: nothing to purge any more.
            let _ = meta.set_purge_state(node_id, None).await;
            continue;
        };
        if node.admin_state != objectio_common::OsdAdminState::Out {
            // Only ever a drained, Out OSD. (It can't be put back In while
            // pending; anything else is left alone.)
            continue;
        }
        purge_one(meta, node_id, &node.address).await;
    }
}

/// Wipe a drained OSD and record it done.
async fn purge_one(meta: &Arc<MetaService>, node_id: [u8; 16], address: &str) {
    let result = async {
        let channel = tokio::time::timeout(
            PER_OSD_TIMEOUT,
            objectio_proto::transport::endpoint(address)
                .map_err(anyhow::Error::msg)?
                .connect(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout"))??;
        let mut client = StorageServiceClient::new(channel);
        let r = client
            .purge(objectio_proto::storage::PurgeRequest {
                node_id: node_id.to_vec(),
            })
            .await?
            .into_inner();
        anyhow::Ok(r)
    }
    .await;
    match result {
        Ok(r) => {
            info!(
                "drain observer: purged drained OSD {} ({} shards, {} metadata entries)",
                hex::encode(node_id),
                r.shards,
                r.entries
            );
            if let Err(e) = meta.set_purge_state(node_id, Some(PURGE_DONE)).await {
                warn!("drain observer: recording purge done: {e}");
            }
        }
        Err(e) => debug!(
            "drain observer: purge of {} not done yet: {e}",
            hex::encode(node_id)
        ),
    }
}

/// Ask one OSD for its shard count via GetStatus. Opens a fresh
/// channel per call — drain polling is low-frequency and it avoids
/// stale-connection issues after an OSD reboot.
async fn query_shard_count(address: &str) -> anyhow::Result<u64> {
    let channel = tokio::time::timeout(
        PER_OSD_TIMEOUT,
        objectio_proto::transport::endpoint(address)
            .map_err(anyhow::Error::msg)?
            .connect(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timeout"))??;

    let mut client = StorageServiceClient::new(channel);
    let resp = tokio::time::timeout(
        PER_OSD_TIMEOUT,
        client.get_status(GetStatusRequest::default()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("get_status timeout"))??;

    Ok(resp.into_inner().shard_count)
}

/// What one scan of the cluster found for a draining OSD.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Scan {
    /// Every OSD answered the scan (and meta's block tables were read).
    pub complete: bool,
    /// Shards on the draining OSD something still refers to.
    pub found: usize,
    /// Of those, moved in this sweep.
    pub moved: usize,
}

/// One shard on the draining OSD, and everything found referring to it:
/// ObjectMetas (one, or several sharing the stripe), block chunk records.
struct Move {
    shard: ShardId,
    objects: Vec<ObjectRef>,
    /// The stripe as a block chunk record has it, when one does.
    block_stripe: Option<StripeMeta>,
    /// The stripe as a pack record has it, when the shard is a pack's.
    pack_stripe: Option<StripeMeta>,
}

struct ObjectRef {
    owner_addr: String,
    bucket: String,
    key: String,
}

/// Move up to `batch` shards off the draining OSD, and report what is
/// left referring to it.
///
/// A shard is identified as it is stored: under its stripe's own id
/// (multipart parts, stripes shared by copies, block chunks), falling back
/// to the object's. Using the object's id for every stripe made each
/// multipart object and each copy unmovable: its shard was "not found"
/// under the object id, and the rebuild fallback used the same wrong id.
///
/// The shard is copied once, then everything referring to it is re-pointed.
/// The source is never deleted here: objects sharing the stripe that this
/// sweep did not reach still read it there. (Deleting it after re-pointing
/// one object left every other object sharing the stripe a shard short.)
/// The OSD is finalised when nothing refers to it any more; what is left
/// on it then is unreferenced.
async fn migrate_batch(
    meta: &Arc<MetaService>,
    draining: [u8; 16],
    draining_addr: &str,
    source_alive: bool,
    batch: usize,
) -> Scan {
    let mut scan = Scan {
        complete: true,
        ..Scan::default()
    };
    let mut moves: Vec<Move> = Vec::new();
    let mut index: std::collections::HashMap<(Vec<u8>, u64, u32), usize> =
        std::collections::HashMap::new();
    let mut slot = |moves: &mut Vec<Move>, shard: ShardId| -> usize {
        let k = (shard.object_id.clone(), shard.stripe_id, shard.position);
        *index.entry(k).or_insert_with(|| {
            moves.push(Move {
                shard,
                objects: Vec::new(),
                block_stripe: None,
                pack_stripe: None,
            });
            moves.len() - 1
        })
    };

    // ObjectMetas, from every OSD (each holds copies of its placement's):
    // not from Out ones (emptied, or being evacuated themselves), nor from
    // the evacuated one if it doesn't answer. Any other OSD that doesn't
    // answer may hold the only reference left: the scan is incomplete.
    let limit = u32::try_from(batch.saturating_mul(4)).unwrap_or(u32::MAX);
    let scanned: Vec<String> = meta
        .osd_nodes_read()
        .iter()
        .filter(|n| {
            if n.node_id == draining {
                source_alive
            } else {
                n.admin_state != objectio_common::OsdAdminState::Out
            }
        })
        .map(|n| n.address.clone())
        .collect();
    for addr in scanned {
        match find_affected_objects(&addr, &draining, limit).await {
            Ok(objects) => {
                for o in objects {
                    for s in o.shards {
                        let shard = ShardId {
                            object_id: if s.shard_object_id.is_empty() {
                                o.object_id.clone()
                            } else {
                                s.shard_object_id
                            },
                            stripe_id: s.stripe_id,
                            position: s.position,
                        };
                        let i = slot(&mut moves, shard);
                        moves[i].objects.push(ObjectRef {
                            owner_addr: addr.clone(),
                            bucket: o.bucket.clone(),
                            key: o.key.clone(),
                        });
                    }
                }
            }
            Err(e) => {
                debug!("drain: scan of {addr} failed: {e}");
                scan.complete = false;
            }
        }
    }
    // Block chunk stripes, recorded in meta's own tables.
    for stripe in meta.block_stripes() {
        for loc in &stripe.shards {
            if loc.node_id == draining {
                let i = slot(
                    &mut moves,
                    ShardId {
                        object_id: stripe.object_id.clone(),
                        stripe_id: stripe.stripe_id,
                        position: loc.position,
                    },
                );
                moves[i].block_stripe = Some(stripe.clone());
            }
        }
    }
    // Packs, recorded in meta's pack table. One not sealed yet can't be
    // moved (its writer is about to record where its shards landed), but it
    // holds the drain open: the OSD isn't empty until it is sealed and
    // moved, or abandoned.
    let mut unsealed = 0;
    for pack in meta.packs() {
        let Some(stripe) = pack.stripe else { continue };
        for loc in &stripe.shards {
            if loc.node_id != draining {
                continue;
            }
            if !pack.sealed {
                unsealed += 1;
                continue;
            }
            let i = slot(
                &mut moves,
                ShardId {
                    object_id: if stripe.object_id.is_empty() {
                        pack.pack_id.clone()
                    } else {
                        stripe.object_id.clone()
                    },
                    stripe_id: stripe.stripe_id,
                    position: loc.position,
                },
            );
            moves[i].pack_stripe = Some(stripe.clone());
        }
    }
    // Keys whose home has it, inline objects too (they have no shards for
    // the scan above to find): each gets its metadata copy on the OSD
    // that takes its place, and the home moves there (B26).
    let (homes, homes_left) = meta.homes_holding(&draining, batch);
    scan.found = moves.len() + unsealed + homes_left;

    // A few at a time: each reads and writes a shard.
    use futures::StreamExt;
    let results: Vec<anyhow::Result<()>> = futures::stream::iter(moves.into_iter().take(batch))
        .map(|mv| async move {
            let what = format!(
                "{} stripe={} pos={}",
                hex::encode(&mv.shard.object_id),
                mv.shard.stripe_id,
                mv.shard.position
            );
            move_shard(meta, &draining, draining_addr, source_alive, &mv)
                .await
                .map_err(|e| anyhow::anyhow!("{what}: {e}"))
        })
        .buffer_unordered(MOVES_AT_ONCE)
        .collect()
        .await;
    let homes_moved: Vec<anyhow::Result<()>> = futures::stream::iter(homes)
        .map(|(bucket, key, ids)| async move {
            move_home(meta, &draining, &bucket, &key, &ids)
                .await
                .map_err(|e| anyhow::anyhow!("{bucket}/{key}: {e}"))
        })
        .buffer_unordered(MOVES_AT_ONCE)
        .collect::<Vec<anyhow::Result<bool>>>()
        .await
        .into_iter()
        // A key whose shard there moves first (then its home with it).
        .filter(|r| !matches!(r, Ok(false)))
        .map(|r| r.map(|_| ()))
        .collect();
    for r in results.into_iter().chain(homes_moved) {
        match r {
            Ok(()) => {
                scan.moved += 1;
                meta.update_drain_progress(draining, |p| {
                    p.shards_migrated = p.shards_migrated.saturating_add(1);
                    p.updated_at = now_unix();
                });
            }
            Err(e) => {
                warn!("drain: {e}");
                meta.update_drain_progress(draining, |p| {
                    p.last_error = e.to_string();
                    p.updated_at = now_unix();
                });
            }
        }
    }
    scan
}

/// Copy one shard to its new home and re-point everything referring to it.
async fn move_shard(
    meta: &Arc<MetaService>,
    draining: &[u8; 16],
    draining_addr: &str,
    source_alive: bool,
    mv: &Move,
) -> anyhow::Result<()> {
    let id: [u8; 16] = mv
        .shard
        .object_id
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("shard id is not 16 bytes"))?;
    // The stripe as recorded: whose other shards are where.
    let stripe = match mv.block_stripe.as_ref().or(mv.pack_stripe.as_ref()) {
        Some(s) => s.clone(),
        None => stripe_of(mv).await?,
    };
    let holders: Vec<[u8; 16]> = stripe
        .shards
        .iter()
        .filter_map(|l| <[u8; 16]>::try_from(l.node_id.as_slice()).ok())
        .collect();
    let target_node = meta
        .pick_drain_target(&id, mv.shard.position, &holders)
        .ok_or_else(|| {
            anyhow::anyhow!("no in-service OSD without a shard of this stripe to move it to")
        })?;
    let target_addr = meta
        .osd_address_by_id(&target_node)
        .ok_or_else(|| anyhow::anyhow!("target not registered"))?;
    if target_addr == draining_addr {
        return Err(anyhow::anyhow!(
            "the target chosen is the draining OSD itself"
        ));
    }

    // The bytes: from the draining OSD, checked; or, if it cannot give
    // them, rebuilt from the rest of the stripe.
    // What the shard's object records of it (B23): the bytes moved are
    // checked against it, read or rebuilt.
    let expected = stripe
        .shards
        .iter()
        .find(|l| l.position == mv.shard.position)
        .and_then(|l| l.crc32c);
    let read = if source_alive {
        read_shard(draining_addr, &mv.shard, expected).await
    } else {
        Err(anyhow::anyhow!("it doesn't answer"))
    };
    let bytes = match read {
        Ok(b) => b,
        Err(e) => {
            debug!("drain: reading from the draining OSD failed ({e}); rebuilding");
            let rebuilt = rebuild_shard(meta, &stripe, &mv.shard, draining).await?;
            if let Some(recorded) = expected
                && crc32c::crc32c(&rebuilt) != recorded
            {
                return Err(anyhow::anyhow!(
                    "position {} rebuilt differs from the shard its object records; not moved",
                    mv.shard.position
                ));
            }
            rebuilt
        }
    };
    let crc32c = crc32c::crc32c(&bytes);
    let location = write_shard(&target_addr, &mv.shard, bytes).await?;
    let to = ShardLocation {
        position: mv.shard.position,
        node_id: target_node.to_vec(),
        disk_id: location.disk_id,
        offset: 0,
        shard_type: 0,
        local_group: 0,
        crc32c: Some(crc32c),
    };

    for o in &mv.objects {
        repoint_object(meta, o, &mv.shard, draining, draining_addr, &to).await?;
    }
    if mv.block_stripe.is_some() {
        meta.block_move_shard(&mv.shard.object_id, mv.shard.position, draining, &to)
            .await
            .map_err(|e| anyhow::anyhow!("block chunk records: {e}"))?;
    }
    if mv.pack_stripe.is_some() {
        // The pack id is the shard's object id.
        meta.move_pack_shard(&mv.shard.object_id, mv.shard.position, *draining, &to)
            .await
            .map_err(|e| anyhow::anyhow!("pack record: {e}"))?;
    }
    Ok(())
}

/// The stripe a shard belongs to, from one of the ObjectMetas referring
/// to it.
async fn stripe_of(mv: &Move) -> anyhow::Result<StripeMeta> {
    for o in &mv.objects {
        if let Ok(Some(object)) = get_object_meta(&o.owner_addr, &o.bucket, &o.key).await
            && let Some(s) = object.stripes.iter().find(|s| is_shard_of(s, &mv.shard))
        {
            return Ok(s.clone());
        }
    }
    Err(anyhow::anyhow!(
        "no ObjectMeta describes the stripe any more"
    ))
}

/// Whether `shard` belongs to `stripe` of `object`.
fn is_shard_of(stripe: &StripeMeta, shard: &ShardId) -> bool {
    stripe.stripe_id == shard.stripe_id && stripe.object_id == shard.object_id
}

/// Point one ObjectMeta's copy of `shard` at `to`, on every replica,
/// unless the object was replaced meanwhile.
async fn repoint_object(
    meta: &Arc<MetaService>,
    o: &ObjectRef,
    shard: &ShardId,
    draining: &[u8; 16],
    draining_addr: &str,
    to: &ShardLocation,
) -> anyhow::Result<()> {
    let Some(mut object) = get_object_meta(&o.owner_addr, &o.bucket, &o.key).await? else {
        return Ok(()); // deleted since: nothing to re-point
    };
    let mut changed = false;
    for stripe in &mut object.stripes {
        if stripe.stripe_id != shard.stripe_id || stripe.object_id != shard.object_id {
            continue;
        }
        for loc in &mut stripe.shards {
            if loc.position == shard.position && loc.node_id == draining.as_slice() {
                *loc = ShardLocation {
                    shard_type: loc.shard_type,
                    local_group: loc.local_group,
                    ..to.clone()
                };
                changed = true;
            }
        }
    }
    if !changed {
        return Ok(());
    }
    // The OSD that took the shard counts the object in usage, and repair
    // visits the object from there, if the evacuated one did (B26).
    if object.usage_owner == draining.as_slice() {
        object.usage_owner.clone_from(&to.node_id);
    }
    fanout_put_object_meta(meta, &object, &o.owner_addr, &[draining_addr]).await?;
    // The key's home follows its first stripe, as it is placed.
    if object
        .stripes
        .first()
        .is_some_and(|s| s.stripe_id == shard.stripe_id && s.object_id == shard.object_id)
        && let Err(e) = meta
            .move_object_home(
                &o.bucket,
                &o.key,
                &[(shard.position, draining.to_vec(), to.node_id.clone())],
            )
            .await
    {
        warn!("drain: {}/{}: home not moved: {e}", o.bucket, o.key);
    }
    Ok(())
}

/// The newest copy of `bucket/key`'s ObjectMeta among `addrs`, as a read
/// takes it: at least a read quorum of `copies` must answer, and a delete
/// newer than every copy means none. `Ok(None)`: no current object.
async fn newest_copy(
    addrs: &[String],
    copies: usize,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Option<ObjectMeta>> {
    let asks = addrs.iter().map(|addr| async move {
        let mut client = StorageServiceClient::new(open_channel(addr).await?)
            .max_decoding_message_size(100 * 1024 * 1024);
        let r = tokio::time::timeout(
            PER_OSD_TIMEOUT,
            client.get_object_meta(GetObjectMetaRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: String::new(),
                with_small_shard: false,
            }),
        )
        .await
        .map_err(|_| anyhow::anyhow!("get_object_meta timeout on {addr}"))??
        .into_inner();
        anyhow::Ok((r.object.filter(|_| r.found), r.tombstone_stamp))
    });
    let mut newest: Option<ObjectMeta> = None;
    let mut deleted_at = 0u64;
    let mut answered = 0;
    for answer in futures::future::join_all(asks).await {
        let Ok((found, tombstone)) = answer else {
            continue;
        };
        answered += 1;
        deleted_at = deleted_at.max(tombstone);
        if let Some(o) = found
            && newest
                .as_ref()
                .is_none_or(|n| o.write_order() > n.write_order())
        {
            newest = Some(o);
        }
    }
    // As a GET: W = a majority of the copies, R = copies - W + 1.
    let read_quorum = copies - (copies / 2 + 1) + 1;
    if answered < read_quorum {
        return Err(anyhow::anyhow!(
            "{answered} copies answered, a read needs {read_quorum}"
        ));
    }
    Ok(newest.filter(|o| deleted_at == 0 || deleted_at < o.stamp))
}

/// Give `bucket/key`'s positions on the evacuated OSD to OSDs in service
/// (B26): the newest metadata copy, read from the rest of its home, is
/// written to each, and the home moves to them. For an object with no
/// shard there (inline ones, above all), this is the only thing that
/// puts its copy back. `Ok(false)`: its shard there moves first, and the
/// home with it.
async fn move_home(
    meta: &Arc<MetaService>,
    draining: &[u8; 16],
    bucket: &str,
    key: &str,
    home: &[Vec<u8>],
) -> anyhow::Result<bool> {
    let others: Vec<String> = home
        .iter()
        .filter(|id| id.as_slice() != draining.as_slice())
        .filter_map(|id| <[u8; 16]>::try_from(id.as_slice()).ok())
        .filter_map(|id| meta.osd_address_by_id(&id))
        .collect();
    let object = newest_copy(&others, home.len(), bucket, key).await?;
    let positions: Vec<u32> = home
        .iter()
        .enumerate()
        .filter(|(_, id)| id.as_slice() == draining.as_slice())
        .filter_map(|(p, _)| u32::try_from(p).ok())
        .collect();
    if let Some(o) = &object
        && o.stripes.first().is_some_and(|s| {
            s.shards
                .iter()
                .any(|l| l.node_id == draining.as_slice() && positions.contains(&l.position))
        })
    {
        return Ok(false);
    }
    let seed: [u8; 16] = object
        .as_ref()
        .and_then(|o| <[u8; 16]>::try_from(o.object_id.as_slice()).ok())
        .unwrap_or_else(|| {
            let h = xxhash_rust::xxh64::xxh64(format!("{bucket}/{key}").as_bytes(), 0);
            let mut s = [0u8; 16];
            s[..8].copy_from_slice(&h.to_le_bytes());
            s[8..].copy_from_slice(&h.rotate_left(32).to_le_bytes());
            s
        });
    let mut taken: Vec<[u8; 16]> = home
        .iter()
        .filter_map(|id| <[u8; 16]>::try_from(id.as_slice()).ok())
        .collect();
    let mut moves = Vec::new();
    for position in positions {
        let target = meta
            .pick_drain_target(&seed, position, &taken)
            .ok_or_else(|| anyhow::anyhow!("no OSD in service outside its home to move it to"))?;
        taken.push(target);
        moves.push((position, draining.to_vec(), target.to_vec()));
    }
    if let Some(mut o) = object {
        let targets: Vec<String> = moves
            .iter()
            .filter_map(|(_, _, t)| <[u8; 16]>::try_from(t.as_slice()).ok())
            .filter_map(|t| meta.osd_address_by_id(&t))
            .collect();
        let mut extra: Vec<&str> = targets.iter().map(String::as_str).collect();
        if o.usage_owner == draining.as_slice() {
            o.usage_owner.clone_from(&moves[0].2);
            // Every copy changes: they all record the owner.
            extra.extend(others.iter().map(String::as_str));
        }
        fanout_put_object_meta(meta, &o, &targets[0], &extra).await?;
    }
    meta.move_object_home(bucket, key, &moves)
        .await
        .map_err(|e| anyhow::anyhow!("home: {e}"))?;
    Ok(true)
}

async fn get_object_meta(
    addr: &str,
    bucket: &str,
    key: &str,
) -> anyhow::Result<Option<ObjectMeta>> {
    let mut client = StorageServiceClient::new(open_channel(addr).await?)
        .max_decoding_message_size(100 * 1024 * 1024);
    let resp = tokio::time::timeout(
        PER_OSD_TIMEOUT,
        client.get_object_meta(GetObjectMetaRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            version_id: String::new(),
            with_small_shard: false,
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("get_object_meta timeout"))??
    .into_inner();
    Ok(resp.object.filter(|_| resp.found))
}

/// `expected_crc32c`: what the shard's object records (B23).
async fn read_shard(
    addr: &str,
    shard: &ShardId,
    expected_crc32c: Option<u32>,
) -> anyhow::Result<prost::bytes::Bytes> {
    let mut client = StorageServiceClient::new(open_channel(addr).await?)
        .max_decoding_message_size(100 * 1024 * 1024);
    let resp = tokio::time::timeout(
        PER_OSD_TIMEOUT,
        client.read_shard(ReadShardRequest {
            rdma_dest: None,
            shard_id: Some(shard.clone()),
            offset: 0,
            length: 0,
            expected_crc32c,
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("read_shard timeout"))??
    .into_inner();
    // Moving damaged bytes would store them under a checksum of the damage.
    let bytes = verified_shard(resp)?;
    if let Some(expected) = expected_crc32c
        && crc32c::crc32c(&bytes) != expected
    {
        return Err(anyhow::anyhow!("not the shard its object records"));
    }
    Ok(bytes)
}

async fn write_shard(
    addr: &str,
    shard: &ShardId,
    bytes: prost::bytes::Bytes,
) -> anyhow::Result<objectio_proto::storage::BlockLocation> {
    let mut client = StorageServiceClient::new(open_channel(addr).await?)
        .max_encoding_message_size(100 * 1024 * 1024);
    tokio::time::timeout(
        PER_OSD_TIMEOUT,
        client.write_shard(WriteShardRequest {
            rdma: None,
            shard_id: Some(shard.clone()),
            checksum: Some(checksum_of(&bytes)),
            data: bytes,
            ec_k: 0,
            ec_m: 0,
            // Restores redundancy: may use the space kept from client writes.
            use_reserve: true,
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("write_shard timeout"))??
    .into_inner()
    .location
    .ok_or_else(|| anyhow::anyhow!("write_shard returned no location"))
}

/// Rebuild `shard` from k other shards of its stripe (any but the one on
/// the draining OSD), each checked against its checksum.
async fn rebuild_shard(
    meta: &Arc<MetaService>,
    stripe: &StripeMeta,
    shard: &ShardId,
    draining: &[u8; 16],
) -> anyhow::Result<prost::bytes::Bytes> {
    use futures::StreamExt;
    let (k, m) = (stripe.ec_k as usize, stripe.ec_m as usize);
    if k == 0 || m == 0 {
        return Err(anyhow::anyhow!("not an erasure-coded stripe ({k}+{m})"));
    }
    let mut reads = futures::stream::FuturesUnordered::new();
    for loc in &stripe.shards {
        if loc.position == shard.position || loc.node_id == draining.as_slice() {
            continue;
        }
        let Some(addr) = <[u8; 16]>::try_from(loc.node_id.as_slice())
            .ok()
            .and_then(|n| meta.osd_address_by_id(&n))
        else {
            continue;
        };
        let id = ShardId {
            position: loc.position,
            ..shard.clone()
        };
        let expected = loc.crc32c;
        reads.push(async move { (id.position, read_shard(&addr, &id, expected).await) });
    }
    let mut survivors: Vec<Option<Vec<u8>>> = vec![None; k + m];
    let mut have = 0;
    while let Some((pos, r)) = reads.next().await {
        if let Ok(bytes) = r
            && let Some(slot) = survivors.get_mut(pos as usize)
        {
            *slot = Some(bytes.to_vec());
            have += 1;
            if have == k {
                break;
            }
        }
    }
    if have < k {
        return Err(anyhow::anyhow!(
            "only {have} good shards reachable, need {k}"
        ));
    }
    let codec =
        objectio_erasure::ErasureCodec::new(objectio_common::ErasureConfig::new(k as u8, m as u8))
            .map_err(|e| anyhow::anyhow!("codec: {e}"))?;
    let mut rebuilt = codec
        .reconstruct_shards(&survivors, &[shard.position as usize])
        .map_err(|e| anyhow::anyhow!("rebuild: {e}"))?;
    rebuilt
        .pop()
        .map(prost::bytes::Bytes::from)
        .ok_or_else(|| anyhow::anyhow!("rebuild returned nothing"))
}

async fn find_affected_objects(
    addr: &str,
    draining: &[u8; 16],
    limit: u32,
) -> anyhow::Result<Vec<objectio_proto::storage::AffectedObject>> {
    let channel = open_channel(addr).await?;
    let mut client = StorageServiceClient::new(channel);
    let resp = tokio::time::timeout(
        PER_OSD_TIMEOUT,
        client.find_objects_referencing_node(FindObjectsReferencingNodeRequest {
            draining_node_id: draining.to_vec(),
            limit,
        }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("find_objects timeout"))??;
    Ok(resp.into_inner().objects)
}

/// One channel per OSD address, kept: repair and drain made a connection
/// (with mTLS, a handshake) for every call, which bounded a rebuild at
/// about 50 shards a second (B24). A tonic channel reconnects by itself
/// after its OSD restarts; every call has its own timeout.
static CHANNELS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, Channel>>> =
    std::sync::LazyLock::new(Default::default);

pub(crate) async fn open_channel(address: &str) -> anyhow::Result<Channel> {
    if let Some(ch) = CHANNELS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(address)
    {
        return Ok(ch.clone());
    }
    let endpoint = objectio_proto::transport::endpoint(address).map_err(anyhow::Error::msg)?;
    let channel = tokio::time::timeout(PER_OSD_TIMEOUT, endpoint.connect())
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout"))??;
    CHANNELS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(address.to_string(), channel.clone());
    Ok(channel)
}

/// The shard in a ReadShard response, if it matches the checksum the OSD
/// sent with it. A response without one is taken as is.
pub(crate) fn verified_shard(resp: ReadShardResponse) -> anyhow::Result<prost::bytes::Bytes> {
    if let Some(expected) = resp.checksum.map(|c| c.crc32c) {
        let got = crc32c::crc32c(&resp.data);
        if got != expected {
            return Err(anyhow::anyhow!(
                "shard has crc32c {got:08x}, expected {expected:08x}"
            ));
        }
    }
    Ok(resp.data)
}

/// The checksum a shard is written with, so the target refuses it if it is
/// damaged on the way.
pub(crate) fn checksum_of(data: &[u8]) -> Checksum {
    Checksum {
        crc32c: crc32c::crc32c(data),
        xxhash64: 0,
        sha256: vec![],
    }
}

/// What a sweep should do with one draining OSD, given what it could learn
/// about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DrainStep {
    /// The scan could not run. Leave it Draining.
    Wait,
    /// Nothing refers to the OSD any more. Flip it to Out.
    Finalise,
    /// Something still refers to it, or the scan was incomplete.
    Migrate,
}

/// Decide the step, separately from performing it.
///
/// The property worth stating out loud: an OSD is finalised only when a scan
/// that every OSD answered found nothing referring to it. Finalising flips
/// it to Out, which is what the console shows the operator before they pull
/// the drive; an OSD that did not answer may hold the one ObjectMeta that
/// still points at it. (This used to finalise on the draining OSD's shard
/// count reaching zero, which it never did while shared or multipart
/// stripes were left on it.)
const fn drain_step(scan: Option<Scan>) -> DrainStep {
    match scan {
        None => DrainStep::Wait,
        Some(Scan {
            complete: true,
            found: 0,
            ..
        }) => DrainStep::Finalise,
        Some(_) => DrainStep::Migrate,
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{DrainStep, Scan, checksum_of, drain_step, verified_shard};
    use objectio_proto::storage::ReadShardResponse;

    fn response(data: &[u8], crc32c: Option<u32>) -> ReadShardResponse {
        ReadShardResponse {
            data: data.to_vec().into(),
            checksum: crc32c.map(|crc32c| objectio_proto::storage::Checksum {
                crc32c,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// A damaged shard is not migrated: the target would store it under a
    /// checksum of the damage and serve it as good.
    #[test]
    fn a_shard_that_does_not_match_its_checksum_is_not_moved() {
        let data = b"a shard on a draining osd";
        let good = checksum_of(data).crc32c;
        assert_eq!(
            &verified_shard(response(data, Some(good))).unwrap()[..],
            data
        );
        assert!(verified_shard(response(data, Some(good ^ 1))).is_err());
        assert_eq!(&verified_shard(response(data, None)).unwrap()[..], data);
    }

    fn scan(complete: bool, found: usize) -> Option<Scan> {
        Some(Scan {
            complete,
            found,
            moved: 0,
        })
    }

    /// Finalising sets the OSD to Out, which is what the console shows the
    /// operator before they pull the drive. It is done only when a scan that
    /// every OSD answered found nothing referring to the OSD: an OSD that
    /// did not answer may hold the one ObjectMeta that still does.
    #[test]
    fn an_osd_is_finalised_only_when_a_complete_scan_finds_nothing() {
        assert_eq!(drain_step(scan(true, 0)), DrainStep::Finalise);
        assert_eq!(drain_step(scan(false, 0)), DrainStep::Migrate);
        assert_eq!(drain_step(scan(true, 3)), DrainStep::Migrate);
        assert_eq!(drain_step(None), DrainStep::Wait);
    }
}
