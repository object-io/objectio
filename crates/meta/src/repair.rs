//! Repairer: finds stripes that have lost redundancy and restores it.
//!
//! A key is placed through a placement group (B31): scrubbed there
//! (`service/scrub.rs`), rebuilt by its recovery (`service/recovery.rs`),
//! its listing entry kept by its listing peering, and a degraded record of
//! it marks its PG. What no placement group holds is walked here: block
//! chunks and packs, recorded in meta's own tables (the only record of
//! where their shards are).
//!
//! Every `--repair-interval-secs` the Raft leader walks them, a page at a
//! time. For each erasure-coded stripe it asks the shard holders, in one
//! `CheckShards` call per OSD per page, whether each shard is there and
//! intact. A shard that is missing or corrupt, or a position the record
//! has no location for, is rebuilt from k good shards:
//!
//! - in place, on the OSD that should hold it, for a shard it lost or that
//!   rotted — the record already points there;
//! - on the position's placement OSD for one that was never written (unless
//!   that OSD holds another shard of the stripe); the new location is then
//!   added to the record (every chunk record holding the stripe, or the
//!   pack's).
//!
//! Out of scope here: replicated and LRC stripes, and shards on OSDs that
//! do not answer (they may be rebooting; drain handles OSDs that are gone).

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use objectio_proto::metadata::metadata_service_server::MetadataService;
use objectio_proto::metadata::{
    ErasureType, GetPlacementRequest, NodePlacement, ObjectMeta, ShardLocation, StripeMeta,
};
use objectio_proto::storage::{
    CheckShardsRequest, ReadShardRequest, ShardId, ShardState, WriteShardRequest,
    storage_service_client::StorageServiceClient,
};
use tracing::{debug, info, warn};

use crate::drain_observer::{checksum_of, open_channel, verified_shard};
use crate::service::MetaService;

/// Stripes audited per page.
const PAGE: usize = 200;

/// Per-RPC timeout. Shard reads and writes move up to 4 MiB.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// What the repairer has done since this node started.
#[derive(Default)]
struct Stats {
    passes: AtomicU64,
    objects: AtomicU64,
    rebuilt_missing: AtomicU64,
    rebuilt_corrupt: AtomicU64,
    unrecoverable: AtomicU64,
    errors: AtomicU64,
    block_stripes: AtomicU64,
    last_pass_ms: AtomicU64,
    last_pass_end: AtomicU64,
    degraded_repaired: AtomicU64,
}

static STATS: Stats = Stats {
    passes: AtomicU64::new(0),
    objects: AtomicU64::new(0),
    rebuilt_missing: AtomicU64::new(0),
    rebuilt_corrupt: AtomicU64::new(0),
    unrecoverable: AtomicU64::new(0),
    errors: AtomicU64::new(0),
    block_stripes: AtomicU64::new(0),
    last_pass_ms: AtomicU64::new(0),
    last_pass_end: AtomicU64::new(0),
    degraded_repaired: AtomicU64::new(0),
};

/// Start the repairer: a full pass every `interval`, on the Raft leader
/// only. A zero interval leaves it off.
pub fn spawn(meta: Arc<MetaService>, interval: Duration) {
    if interval.is_zero() {
        info!("Repairer off");
        return;
    }
    let degraded = Arc::clone(&meta);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                () = WALK_NOW.notified() => {}
            }
            if meta.is_raft_leader() {
                pass(&meta).await;
            }
        }
    });
    // Objects written short of shards, worked apart from the walk and far
    // more often (B29).
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(DEGRADED_EVERY).await;
            if degraded.is_raft_leader() {
                work_degraded(&degraded).await;
            }
        }
    });
    info!(
        "Repairer spawned (a pass every {interval:?}, degraded objects every {DEGRADED_EVERY:?})"
    );
}

/// Repairer metrics as Prometheus families.
pub fn render_metrics(out: &mut String) {
    let s = &STATS;
    for (name, help, v) in [
        (
            "objectio_meta_repair_last_pass_seconds",
            "How long the last completed repair pass took (on the node that ran it)",
            s.last_pass_ms.load(Ordering::Relaxed) as f64 / 1000.0,
        ),
        (
            "objectio_meta_repair_last_pass_timestamp_seconds",
            "When the last repair pass completed (Unix time; 0: none yet on this node)",
            s.last_pass_end.load(Ordering::Relaxed) as f64,
        ),
        (
            "objectio_meta_degraded_objects",
            "Objects acknowledged short of shards and not yet repaired (as last counted by the leader's repairer)",
            DEGRADED.load(Ordering::Relaxed) as f64,
        ),
        (
            "objectio_meta_lost_objects",
            "Objects recorded as lost: fewer than k shards left (B29). Anything above 0 is data loss: alert",
            LOST.load(Ordering::Relaxed) as f64,
        ),
        (
            "objectio_meta_degraded_oldest_seconds",
            "Age of the oldest object short of shards: alert when it grows while every OSD is up",
            DEGRADED_OLDEST_SECS.load(Ordering::Relaxed) as f64,
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
    }
    for (name, help, v) in [
        (
            "objectio_meta_repair_passes_total",
            "Completed repair passes",
            &s.passes,
        ),
        (
            "objectio_meta_repair_objects_checked_total",
            "Objects checked by the repairer",
            &s.objects,
        ),
        (
            "objectio_meta_repair_unrecoverable_stripes_total",
            "Stripes found with fewer than k good shards",
            &s.unrecoverable,
        ),
        (
            "objectio_meta_repair_errors_total",
            "Repairs that failed and will be retried next pass",
            &s.errors,
        ),
        (
            "objectio_meta_degraded_repaired_total",
            "Objects written short of shards that repair made whole",
            &s.degraded_repaired,
        ),
        (
            "objectio_meta_repair_block_stripes_checked_total",
            "Block chunk stripes checked by the repairer (also counted in objects checked)",
            &s.block_stripes,
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}");
        let _ = writeln!(out, "# TYPE {name} counter");
        let _ = writeln!(out, "{name} {}", v.load(Ordering::Relaxed));
    }
    let name = "objectio_meta_repair_shards_rebuilt_total";
    let _ = writeln!(
        out,
        "# HELP {name} Shards rebuilt from the rest of their stripe"
    );
    let _ = writeln!(out, "# TYPE {name} counter");
    let _ = writeln!(
        out,
        "{name}{{reason=\"missing\"}} {}",
        s.rebuilt_missing.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "{name}{{reason=\"corrupt\"}} {}",
        s.rebuilt_corrupt.load(Ordering::Relaxed)
    );
}

/// One full pass over every block chunk stripe and every sealed pack.
pub async fn pass(meta: &Arc<MetaService>) {
    let started = std::time::Instant::now();
    for page in meta.block_stripes().chunks(PAGE) {
        if !meta.is_raft_leader() {
            return;
        }
        let objects: Vec<ObjectMeta> = page.iter().cloned().map(block_object).collect();
        STATS
            .block_stripes
            .fetch_add(objects.len() as u64, Ordering::Relaxed);
        audit(meta, Source::Block, &objects).await;
    }
    // Packs: their shards are recorded once, in meta's pack table; the
    // objects in them name the pack and hold no shards of their own.
    let packs: Vec<ObjectMeta> = meta
        .packs()
        .into_iter()
        .filter(|p| p.sealed)
        .filter_map(pack_object)
        .collect();
    for page in packs.chunks(PAGE) {
        if !meta.is_raft_leader() {
            return;
        }
        audit(meta, Source::Pack, page).await;
    }
    STATS.passes.fetch_add(1, Ordering::Relaxed);
    STATS.last_pass_ms.store(
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        Ordering::Relaxed,
    );
    STATS.last_pass_end.store(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        Ordering::Relaxed,
    );
}

/// Where the stripes being audited are recorded, and so where a rebuilt
/// shard's new location goes.
#[derive(Clone, Copy)]
enum Source {
    /// Block chunk stripes, recorded in meta's block tables.
    Block,
    /// Pack stripes, recorded in meta's pack table.
    Pack,
}

/// Prefix of the key a pack is placed under, in its bucket.
pub const PACK_KEY_PREFIX: &str = ".objectio-pack/";

/// A pack in the shape `audit` takes, named and placed as it was written.
fn pack_object(pack: objectio_proto::metadata::PackRecord) -> Option<ObjectMeta> {
    let stripe = pack.stripe?;
    Some(ObjectMeta {
        key: format!("{PACK_KEY_PREFIX}{}", hex::encode(&pack.pack_id)),
        bucket: pack.bucket,
        object_id: pack.pack_id,
        size: stripe.data_size,
        stripes: vec![stripe],
        ..Default::default()
    })
}

/// A block stripe in the shape `audit` takes. The key is only a name for
/// logs and placement.
fn block_object(stripe: StripeMeta) -> ObjectMeta {
    ObjectMeta {
        bucket: BLOCK_BUCKET.into(),
        key: hex::encode(&stripe.object_id),
        object_id: stripe.object_id.clone(),
        size: stripe.data_size,
        stripes: vec![stripe],
        ..Default::default()
    }
}

/// Bucket name block chunks are placed under.
const BLOCK_BUCKET: &str = "__block__";

/// Where a shard stands, as far as this pass could tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Seen {
    Ok,
    /// Missing or corrupt on the OSD the ObjectMeta names.
    Lost {
        corrupt: bool,
    },
    /// The ObjectMeta has no location for this position.
    Unplaced,
    /// Its OSD did not answer.
    Unknown,
}

/// What to do with one stripe, given where its shards stand.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Healthy,
    /// Rebuild these positions from the good ones.
    Rebuild {
        bad: Vec<usize>,
        good: Vec<usize>,
    },
    /// Fewer than k good shards: nothing to rebuild from.
    Unrecoverable {
        good: usize,
    },
}

fn verdict(seen: &[Seen], k: usize) -> Verdict {
    let good: Vec<usize> = (0..seen.len()).filter(|&p| seen[p] == Seen::Ok).collect();
    let bad: Vec<usize> = (0..seen.len())
        .filter(|&p| matches!(seen[p], Seen::Lost { .. } | Seen::Unplaced))
        .collect();
    if bad.is_empty() {
        Verdict::Healthy
    } else if good.len() < k {
        Verdict::Unrecoverable { good: good.len() }
    } else {
        Verdict::Rebuild { bad, good }
    }
}

/// Stripes this pass can repair: erasure-coded with parity. An object's
/// slice of a pack is not a stripe of its own: the pack is repaired from
/// its record.
fn repairable(stripe: &StripeMeta) -> bool {
    let ec = ErasureType::try_from(stripe.ec_type).unwrap_or(ErasureType::ErasureMds);
    ec == ErasureType::ErasureMds && stripe.ec_k > 0 && stripe.ec_m > 0 && stripe.pack_id.is_empty()
}

/// Check `objects`' stripes and repair them.
async fn audit(meta: &Arc<MetaService>, source: Source, objects: &[ObjectMeta]) {
    // Every listed shard of every repairable stripe, grouped by node, so
    // each node is asked once for the whole page.
    let mut asks: HashMap<Vec<u8>, Vec<(usize, usize, u32)>> = HashMap::new();
    for (oi, o) in objects.iter().enumerate() {
        for (si, s) in o.stripes.iter().enumerate() {
            if repairable(s) {
                for loc in &s.shards {
                    asks.entry(loc.node_id.clone())
                        .or_default()
                        .push((oi, si, loc.position));
                }
            }
        }
    }
    let mut states: HashMap<(usize, usize, u32), Seen> = HashMap::new();
    // Every node at once: one slow or gone node no longer holds up the rest.
    let answers = futures::future::join_all(asks.into_iter().map(|(node, refs)| async move {
        let answer = match node_address(meta, &node) {
            Some(addr) => check_shards(&addr, objects, &refs).await,
            None => Err(anyhow::anyhow!("node not registered")),
        };
        (node, refs, answer)
    }))
    .await;
    for (node, refs, answer) in answers {
        match answer {
            Ok(got) => {
                for (r, st) in refs.into_iter().zip(got) {
                    states.insert(r, st);
                }
            }
            Err(e) => {
                debug!("repair: check_shards on {}: {e}", hex::encode(&node));
                for r in refs {
                    states.insert(r, Seen::Unknown);
                }
            }
        }
    }

    // Rebuilds, REBUILDS_AT_ONCE objects at a time (each one's reads are
    // parallel too): one at a time, a replaced disk took hours (B24).
    use futures::FutureExt;
    let states = &states;
    // The objects with the fewest shards to spare first (B29): one a
    // single loss from unreadable is rebuilt before one with a shard to
    // spare.
    let spare = |oi: usize| -> i64 {
        objects[oi]
            .stripes
            .iter()
            .enumerate()
            .filter(|(_, s)| repairable(s))
            .map(|(si, s)| {
                let ok = s
                    .shards
                    .iter()
                    .filter(|l| states.get(&(oi, si, l.position)) == Some(&Seen::Ok))
                    .count();
                i64::try_from(ok).unwrap_or(i64::MAX) - i64::from(s.ec_k)
            })
            .min()
            .unwrap_or(i64::MAX)
    };
    let mut order: Vec<usize> = (0..objects.len()).collect();
    order.sort_by_key(|&oi| spare(oi));
    let rebuilds: Vec<futures::future::BoxFuture<'_, ()>> = order
        .into_iter()
        .map(|oi| (oi, &objects[oi]))
        .map(|(oi, object)| {
            async move {
                STATS.objects.fetch_add(1, Ordering::Relaxed);
                for (si, stripe) in object.stripes.iter().enumerate() {
                    if !repairable(stripe) {
                        continue;
                    }
                    let total = (stripe.ec_k + stripe.ec_m) as usize;
                    let mut seen = vec![Seen::Unplaced; total];
                    for loc in &stripe.shards {
                        if let Some(slot) = seen.get_mut(loc.position as usize) {
                            *slot = states
                                .get(&(oi, si, loc.position))
                                .copied()
                                .unwrap_or(Seen::Unknown);
                        }
                    }
                    match verdict(&seen, stripe.ec_k as usize) {
                        Verdict::Healthy => {}
                        Verdict::Unrecoverable { good } => {
                            STATS.unrecoverable.fetch_add(1, Ordering::Relaxed);
                            warn!(
                                "repair: {}/{} stripe {} has {good} good shards, needs {}",
                                object.bucket, object.key, stripe.stripe_id, stripe.ec_k
                            );
                        }
                        Verdict::Rebuild { bad, good } => {
                            match rebuild(meta, source, object, stripe, &seen, &bad, &good).await
                            {
                                Ok(()) => info!(
                                    "repair: {}/{} stripe {}: rebuilt positions {bad:?} from {} good shards",
                                    object.bucket,
                                    object.key,
                                    stripe.stripe_id,
                                    good.len()
                                ),
                                Err(e) => {
                                    STATS.errors.fetch_add(1, Ordering::Relaxed);
                                    warn!(
                                        "repair: {}/{} stripe {}: positions {bad:?} not rebuilt: {e}",
                                        object.bucket, object.key, stripe.stripe_id
                                    );
                                }
                            }
                        }
                    }
                }
            }
            .boxed()
        })
        .collect();
    use futures::StreamExt;
    futures::stream::iter(rebuilds)
        .buffered(REBUILDS_AT_ONCE)
        .collect::<Vec<()>>()
        .await;
}

/// Wakes the walk before it is due: an OSD came back without the shards
/// it held (a replaced disk). Called on the leader, which serves every
/// registration; calls while a pass runs start one more after it.
static WALK_NOW: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Start a repair walk now, rather than when next due.
pub(crate) fn walk_now() {
    WALK_NOW.notify_one();
}

/// How often the objects recorded short of shards are worked (B29).
const DEGRADED_EVERY: Duration = Duration::from_secs(5);

/// Count the objects recorded as written short of shards (B29) and as
/// lost, and hand each degraded one to its placement group (B31 phase 3a):
/// its record marks the PG for peering, which recovery acts on, and goes
/// once the object is whole (recovery forgets it) or the PG has been found
/// clean since it was made. A record whose PG isn't made yet waits.
pub async fn work_degraded(meta: &Arc<MetaService>) {
    LOST.store(meta.lost_objects().len() as u64, Ordering::Relaxed);
    let records = meta.degraded_objects();
    DEGRADED.store(records.len() as u64, Ordering::Relaxed);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    DEGRADED_OLDEST_SECS.store(
        records
            .iter()
            .map(|(_, d, _)| now.saturating_sub(d.recorded_at))
            .max()
            .unwrap_or(0),
        Ordering::Relaxed,
    );

    for (key, record, bytes) in records {
        let Some((bucket, k)) = key.split_once('/') else {
            continue;
        };
        if meta.key_pg(bucket, k).is_none() {
            continue;
        }
        let (pg_id, pool) = meta.listing_pg(bucket, k);
        let clean_since = meta
            .pg_state(&pool, pg_id)
            .is_some_and(|s| s.state == "Clean" && s.computed_at > record.recorded_at);
        if clean_since {
            if let Err(e) = meta.forget_degraded(&key, bytes).await {
                debug!("repair: degraded {key}: {e}");
            }
        } else {
            meta.mark_key_dirty(bucket, k);
        }
    }
}

/// Degraded-object records, and the age of the oldest, as last counted.
static DEGRADED: AtomicU64 = AtomicU64::new(0);
static DEGRADED_OLDEST_SECS: AtomicU64 = AtomicU64::new(0);
/// Objects recorded as lost, as last counted.
static LOST: AtomicU64 = AtomicU64::new(0);

/// Objects one repair pass rebuilds at once.
const REBUILDS_AT_ONCE: usize = 16;

fn node_address(meta: &MetaService, node_id: &[u8]) -> Option<String> {
    let id = <[u8; 16]>::try_from(node_id).ok()?;
    meta.osd_address_by_id(&id)
}

async fn check_shards(
    address: &str,
    objects: &[ObjectMeta],
    refs: &[(usize, usize, u32)],
) -> anyhow::Result<Vec<Seen>> {
    let shards = refs
        .iter()
        .map(|&(oi, si, position)| {
            let s = &objects[oi].stripes[si];
            ShardId {
                object_id: s.object_id.clone(),
                stripe_id: s.stripe_id,
                position,
            }
        })
        .collect();
    let mut client = StorageServiceClient::new(open_channel(address).await?);
    let states = tokio::time::timeout(
        RPC_TIMEOUT,
        client.check_shards(CheckShardsRequest { shards }),
    )
    .await??
    .into_inner()
    .states;
    if states.len() != refs.len() {
        return Err(anyhow::anyhow!(
            "asked about {} shards, told about {}",
            refs.len(),
            states.len()
        ));
    }
    Ok(states
        .into_iter()
        .map(|s| match ShardState::try_from(s) {
            Ok(ShardState::Ok) => Seen::Ok,
            Ok(ShardState::Missing) => Seen::Lost { corrupt: false },
            Ok(ShardState::Corrupt) => Seen::Lost { corrupt: true },
            Err(_) => Seen::Unknown,
        })
        .collect())
}

/// Rebuild a stripe's `bad` positions from its `good` ones and write them
/// where they belong.
async fn rebuild(
    meta: &Arc<MetaService>,
    source: Source,
    object: &ObjectMeta,
    stripe: &StripeMeta,
    seen: &[Seen],
    bad: &[usize],
    good: &[usize],
) -> anyhow::Result<()> {
    let k = stripe.ec_k as usize;
    let total = seen.len();
    let id = stripe.object_id.clone();
    let located: HashMap<u32, &ShardLocation> =
        stripe.shards.iter().map(|l| (l.position, l)).collect();

    // k good shards, verified against their checksums.
    let mut survivors: Vec<Option<Vec<u8>>> = vec![None; total];
    let mut have = 0;
    // As many reads at once as shards still needed; a failed one is made
    // up from the next good positions.
    let mut candidates: std::collections::VecDeque<usize> = good.iter().copied().collect();
    while have < k && !candidates.is_empty() {
        let batch: Vec<usize> = (0..(k - have).min(candidates.len()))
            .filter_map(|_| candidates.pop_front())
            .collect();
        let reads = batch.into_iter().map(|p| {
            let loc = located.get(&(p as u32)).copied();
            let addr = loc.and_then(|l| node_address(meta, &l.node_id));
            let crc = loc.and_then(|l| l.crc32c);
            let id = &id;
            async move {
                let Some(addr) = addr else {
                    return (
                        p,
                        Err(anyhow::anyhow!("position {p} has no reachable holder")),
                    );
                };
                (
                    p,
                    read_shard(&addr, id, stripe.stripe_id, p as u32, crc).await,
                )
            }
        });
        for (p, r) in futures::future::join_all(reads).await {
            match r {
                Ok(bytes) => {
                    survivors[p] = Some(bytes);
                    have += 1;
                }
                Err(e) => debug!("repair: read of position {p}: {e}"),
            }
        }
    }
    if have < k {
        return Err(anyhow::anyhow!("read {have} good shards, need {k}"));
    }

    let codec = objectio_erasure::ErasureCodec::new(objectio_common::ErasureConfig::new(
        stripe.ec_k as u8,
        stripe.ec_m as u8,
    ))
    .map_err(|e| anyhow::anyhow!("codec: {e}"))?;
    let rebuilt = codec
        .reconstruct_shards(&survivors, bad)
        .map_err(|e| anyhow::anyhow!("decode: {e}"))?;

    // Positions with no location go to their placement OSD.
    let placement = if bad.iter().any(|&p| seen[p] == Seen::Unplaced) {
        Some(placement_of(meta, object).await?)
    } else {
        None
    };

    // OSDs holding a shard of the stripe: one of them gets no other. A
    // position whose placement OSD is one (the placement changed since the
    // stripe was written) is left missing, degraded, rather than put where
    // losing one disk loses two shards.
    let mut holders: std::collections::HashSet<Vec<u8>> =
        stripe.shards.iter().map(|l| l.node_id.clone()).collect();
    let mut added = Vec::new();
    for (&p, bytes) in bad.iter().zip(rebuilt) {
        let position = p as u32;
        // A rebuild is the shard as first written, byte for byte: one that
        // isn't (decoded from a bad source) is not stored as if it were.
        let crc = crc32c::crc32c(&bytes);
        if let Some(recorded) = located.get(&position).and_then(|l| l.crc32c)
            && recorded != crc
        {
            return Err(anyhow::anyhow!(
                "position {p} rebuilt as crc32c {crc:08x}, its object records {recorded:08x}; not stored"
            ));
        }
        let (node_id, addr, shard_type) = match (seen[p], located.get(&position)) {
            (Seen::Lost { .. }, Some(loc)) => (
                loc.node_id.clone(),
                node_address(meta, &loc.node_id)
                    .ok_or_else(|| anyhow::anyhow!("holder of position {p} not registered"))?,
                loc.shard_type,
            ),
            _ => {
                let target = placement
                    .as_ref()
                    .and_then(|nodes| nodes.iter().find(|n| n.position == position))
                    .ok_or_else(|| anyhow::anyhow!("no placement for position {p}"))?;
                if !holders.insert(target.node_id.clone()) {
                    warn!(
                        "repair: {}/{} stripe {} position {p}: its placement OSD {} holds \
                         another shard of the stripe; left missing",
                        object.bucket,
                        object.key,
                        stripe.stripe_id,
                        hex::encode(&target.node_id)
                    );
                    continue;
                }
                (
                    target.node_id.clone(),
                    target.node_address.clone(),
                    target.shard_type,
                )
            }
        };
        let location = write_shard(&addr, &id, stripe, position, bytes).await?;
        match seen[p] {
            Seen::Lost { corrupt: true } => STATS.rebuilt_corrupt.fetch_add(1, Ordering::Relaxed),
            _ => STATS.rebuilt_missing.fetch_add(1, Ordering::Relaxed),
        };
        info!(
            "repair: rebuilt {}/{} stripe {} position {p} on {addr}",
            object.bucket, object.key, stripe.stripe_id
        );
        if seen[p] == Seen::Unplaced {
            added.push(ShardLocation {
                position,
                node_id,
                disk_id: location.disk_id,
                offset: location.offset,
                shard_type,
                local_group: 0,
                crc32c: Some(crc),
            });
        }
    }

    if !added.is_empty() {
        match source {
            Source::Block => {
                meta.block_add_shard_locations(&object.object_id, &added)
                    .await
                    .map_err(|e| anyhow::anyhow!("record block shard locations: {e}"))?;
            }
            Source::Pack => {
                meta.pack_add_shard_locations(&object.object_id, &added)
                    .await
                    .map_err(|e| anyhow::anyhow!("record pack shard locations: {e}"))?;
            }
        }
    }
    Ok(())
}

/// `expected_crc32c`: what the shard's object records (B23); the OSD
/// refuses a shard that doesn't match it.
async fn read_shard(
    address: &str,
    object_id: &[u8],
    stripe_id: u64,
    position: u32,
    expected_crc32c: Option<u32>,
) -> anyhow::Result<Vec<u8>> {
    let mut client = StorageServiceClient::new(open_channel(address).await?)
        .max_decoding_message_size(100 * 1024 * 1024);
    let resp = tokio::time::timeout(
        RPC_TIMEOUT,
        client.read_shard(ReadShardRequest {
            shard_id: Some(ShardId {
                object_id: object_id.to_vec(),
                stripe_id,
                position,
            }),
            expected_crc32c,
            ..Default::default()
        }),
    )
    .await??
    .into_inner();
    let bytes = verified_shard(resp)?.to_vec();
    if let Some(expected) = expected_crc32c
        && crc32c::crc32c(&bytes) != expected
    {
        return Err(anyhow::anyhow!(
            "position {position}: not the shard its object records"
        ));
    }
    Ok(bytes)
}

async fn write_shard(
    address: &str,
    object_id: &[u8],
    stripe: &StripeMeta,
    position: u32,
    bytes: Vec<u8>,
) -> anyhow::Result<objectio_proto::storage::BlockLocation> {
    let mut client = StorageServiceClient::new(open_channel(address).await?)
        .max_encoding_message_size(100 * 1024 * 1024);
    let checksum = Some(checksum_of(&bytes));
    tokio::time::timeout(
        RPC_TIMEOUT,
        client.write_shard(WriteShardRequest {
            shard_id: Some(ShardId {
                object_id: object_id.to_vec(),
                stripe_id: stripe.stripe_id,
                position,
            }),
            data: bytes.into(),
            ec_k: stripe.ec_k,
            ec_m: stripe.ec_m,
            checksum,
            rdma: None,
            // Restores redundancy: may use the space kept from client writes.
            use_reserve: true,
            pg: None,
        }),
    )
    .await??
    .into_inner()
    .location
    .ok_or_else(|| anyhow::anyhow!("write_shard returned no location"))
}

async fn placement_of(
    meta: &Arc<MetaService>,
    object: &ObjectMeta,
) -> anyhow::Result<Vec<NodePlacement>> {
    let resp = MetadataService::get_placement(
        meta.as_ref(),
        tonic::Request::new(GetPlacementRequest {
            bucket: object.bucket.clone(),
            key: object.key.clone(),
            size: object.size,
            storage_class: "STANDARD".into(),
        }),
    )
    .await
    .map_err(|e| anyhow::anyhow!("placement: {e}"))?;
    Ok(resp.into_inner().nodes)
}

#[cfg(test)]
mod tests {
    use super::{Seen, Verdict, verdict};

    const LOST: Seen = Seen::Lost { corrupt: false };
    const ROT: Seen = Seen::Lost { corrupt: true };

    #[test]
    fn a_full_stripe_is_healthy() {
        assert_eq!(verdict(&[Seen::Ok; 6], 4), Verdict::Healthy);
    }

    #[test]
    fn lost_rotted_and_unplaced_shards_are_rebuilt_from_the_good_ones() {
        let seen = [Seen::Ok, LOST, Seen::Ok, ROT, Seen::Ok, Seen::Unplaced];
        assert_eq!(
            verdict(&seen, 3),
            Verdict::Rebuild {
                bad: vec![1, 3, 5],
                good: vec![0, 2, 4]
            }
        );
    }

    /// A shard whose OSD did not answer is neither: it may be rebooting.
    #[test]
    fn shards_on_silent_osds_are_left_alone() {
        let seen = [
            Seen::Ok,
            Seen::Ok,
            Seen::Ok,
            Seen::Ok,
            Seen::Unknown,
            Seen::Unknown,
        ];
        assert_eq!(verdict(&seen, 4), Verdict::Healthy);
    }

    #[test]
    fn fewer_than_k_good_shards_cannot_be_rebuilt_from() {
        let seen = [Seen::Ok, Seen::Ok, Seen::Ok, LOST, Seen::Unknown, ROT];
        assert_eq!(verdict(&seen, 4), Verdict::Unrecoverable { good: 3 });
    }
}
