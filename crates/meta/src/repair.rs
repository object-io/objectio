//! Repairer: finds objects that have lost redundancy and restores it.
//!
//! An object can be left with fewer than k+m good shards in three ways: a
//! PUT acknowledged with only some of them written (the write quorum is
//! k+1), a shard that rotted on disk (found by an OSD's scrubber or a
//! read), and a disk that was replaced, taking its shards with it. Left
//! alone, each one is a failure closer to loss.
//!
//! Every `--repair-interval-secs` the Raft leader walks every object, a page
//! of ObjectMetas per OSD at a time, each object once (from the OSD that
//! counts it in usage). For each erasure-coded stripe it asks the shard
//! holders, in one `CheckShards` call per OSD per page, whether each shard
//! is there and intact. A shard that is missing or corrupt, or a position
//! the ObjectMeta has no location for, is rebuilt from k good shards:
//!
//! - in place, on the OSD that should hold it, for a shard it lost or that
//!   rotted — the ObjectMeta already points there;
//! - on the position's placement OSD for one that was never written; the
//!   new location is then added to the ObjectMeta with a compare-and-set,
//!   so a PUT that replaced the object meanwhile is never rolled back.
//!
//! The same walk restores entries missing from Meta's listing index (a
//! PUT's listing commit that failed while its ObjectMeta landed), so such
//! objects show up in ListObjects again.
//!
//! Block storage chunks are walked too, from meta's own block tables (the
//! only record of where a chunk's shards are): a lost shard is rebuilt in
//! place, and one never written is rebuilt on its placement OSD and its
//! location added to every chunk record holding the stripe.
//!
//! A stripe whose shards are all good but two of them on one OSD (written
//! while an OSD was out, so placement doubled up) is spread (B20,
//! backfill): the extra shard is copied to an active OSD holding none of
//! the stripe, every ObjectMeta copy and the key's home are moved to it,
//! and the old copy is deleted once reads that may still use it are done.
//! A few moves per pass, so a returning OSD is filled without a storm.
//!
//! Out of scope here: replicated and LRC stripes, shards on OSDs that do
//! not answer (they may be rebooting; drain handles OSDs that are gone),
//! and version entries other than the current one.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use objectio_proto::metadata::metadata_service_server::MetadataService;
use objectio_proto::metadata::{
    CreateObjectRequest, ErasureType, GetPlacementRequest, NodePlacement, ObjectMeta,
    ShardLocation, StripeMeta,
};
use objectio_proto::storage::{
    CheckShardsRequest, DeleteShardRequest, GetObjectMetaRequest, ListObjectsMetaRequest,
    PutObjectMetaRequest, ReadShardRequest, ShardId, ShardState, WriteShardRequest,
    storage_service_client::StorageServiceClient,
};
use tracing::{debug, info, warn};

use crate::drain_observer::{checksum_of, open_channel, verified_shard};
use crate::service::MetaService;

/// ObjectMetas fetched from an OSD per page.
const PAGE: u32 = 200;

/// Per-RPC timeout. Shard reads and writes move up to 4 MiB.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Shards moved per pass at most (backfill).
const MOVES_PER_PASS: usize = 64;

/// How long a moved shard's old copy is kept: a read that fetched the
/// ObjectMeta before the move may still be reading it.
const MOVED_GRACE: Duration = Duration::from_secs(2 * 30);

/// Old copies of moved shards, deleted once due: (due, OSD address, shard).
static MOVED: std::sync::Mutex<Vec<(std::time::Instant, String, ShardId)>> =
    std::sync::Mutex::new(Vec::new());

/// What the repairer has done since this node started.
#[derive(Default)]
struct Stats {
    passes: AtomicU64,
    objects: AtomicU64,
    rebuilt_missing: AtomicU64,
    rebuilt_corrupt: AtomicU64,
    unrecoverable: AtomicU64,
    listings_restored: AtomicU64,
    moved: AtomicU64,
    errors: AtomicU64,
    block_stripes: AtomicU64,
    last_pass_ms: AtomicU64,
    last_pass_end: AtomicU64,
}

static STATS: Stats = Stats {
    passes: AtomicU64::new(0),
    objects: AtomicU64::new(0),
    rebuilt_missing: AtomicU64::new(0),
    rebuilt_corrupt: AtomicU64::new(0),
    unrecoverable: AtomicU64::new(0),
    listings_restored: AtomicU64::new(0),
    moved: AtomicU64::new(0),
    errors: AtomicU64::new(0),
    block_stripes: AtomicU64::new(0),
    last_pass_ms: AtomicU64::new(0),
    last_pass_end: AtomicU64::new(0),
};

/// Start the repairer: a full pass every `interval`, on the Raft leader
/// only. A zero interval leaves it off.
pub fn spawn(meta: Arc<MetaService>, interval: Duration) {
    if interval.is_zero() {
        info!("Repairer off");
        return;
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(interval).await;
            if meta.is_raft_leader() {
                pass(&meta).await;
            }
        }
    });
    info!("Repairer spawned (a pass every {interval:?})");
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
            "objectio_meta_repair_listings_restored_total",
            "Listing entries restored for objects missing from ListObjects",
            &s.listings_restored,
        ),
        (
            "objectio_meta_repair_shards_moved_total",
            "Shards moved off an OSD holding two of their stripe (backfill)",
            &s.moved,
        ),
        (
            "objectio_meta_repair_errors_total",
            "Repairs that failed and will be retried next pass",
            &s.errors,
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

/// One full pass over every object on every OSD that is not Out.
pub async fn pass(meta: &Arc<MetaService>) {
    let started = std::time::Instant::now();
    release_moved().await;
    let mut moves = MOVES_PER_PASS;
    let osds: Vec<([u8; 16], String)> = meta
        .osd_nodes_snapshot()
        .into_iter()
        .filter(|n| n.admin_state != objectio_common::OsdAdminState::Out)
        .map(|n| (n.node_id, n.address))
        .collect();
    for (node_id, address) in osds {
        let mut cursor = String::new();
        loop {
            if !meta.is_raft_leader() {
                return;
            }
            let (page, next) = match list_page(&address, &cursor).await {
                Ok(p) => p,
                Err(e) => {
                    debug!("repair: cannot list {address}: {e}");
                    break;
                }
            };
            let owned: Vec<ObjectMeta> = page
                .into_iter()
                .filter(|o| owner(o) == Some(node_id.as_slice()))
                .collect();
            audit(meta, Source::Osd(&address), &owned, &mut moves).await;
            if next.is_empty() {
                break;
            }
            cursor = next;
        }
    }
    for page in meta.block_stripes().chunks(PAGE as usize) {
        if !meta.is_raft_leader() {
            return;
        }
        let objects: Vec<ObjectMeta> = page.iter().cloned().map(block_object).collect();
        STATS
            .block_stripes
            .fetch_add(objects.len() as u64, Ordering::Relaxed);
        audit(meta, Source::Block, &objects, &mut 0).await;
    }
    // Packs: their shards are recorded once, in meta's pack table; the
    // objects in them name the pack and hold no shards of their own.
    let packs: Vec<ObjectMeta> = meta
        .packs()
        .into_iter()
        .filter(|p| p.sealed)
        .filter_map(pack_object)
        .collect();
    for page in packs.chunks(PAGE as usize) {
        if !meta.is_raft_leader() {
            return;
        }
        audit(meta, Source::Pack, page, &mut 0).await;
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

/// Where the objects being audited are recorded, and so where a rebuilt
/// shard's new location goes.
#[derive(Clone, Copy)]
enum Source<'a> {
    /// ObjectMetas listed from the OSD at this address, which owns them.
    Osd(&'a str),
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

/// The node that answers for this object: the one that counts it in usage,
/// or for objects written before that existed, the holder of its first
/// shard. Walking only the objects a node owns visits each object once.
fn owner(o: &ObjectMeta) -> Option<&[u8]> {
    if !o.usage_owner.is_empty() {
        return Some(&o.usage_owner);
    }
    o.stripes
        .first()
        .and_then(|s| s.shards.first())
        .map(|s| s.node_id.as_slice())
}

/// A page of the ObjectMetas an OSD holds, and the cursor for the next one
/// (empty after the last page).
async fn list_page(address: &str, cursor: &str) -> anyhow::Result<(Vec<ObjectMeta>, String)> {
    let mut client = StorageServiceClient::new(open_channel(address).await?)
        .max_decoding_message_size(100 * 1024 * 1024);
    let resp = tokio::time::timeout(
        RPC_TIMEOUT,
        client.list_objects_meta(ListObjectsMetaRequest {
            bucket: String::new(),
            start_after: cursor.to_string(),
            max_keys: PAGE,
            ..Default::default()
        }),
    )
    .await??
    .into_inner();
    let next = if resp.is_truncated {
        resp.next_continuation_token
    } else {
        String::new()
    };
    Ok((resp.objects, next))
}

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

/// Check `objects`' stripes and repair them; spread doubled-up ones (an
/// object's own, from an OSD listing) while `moves` lasts.
async fn audit(
    meta: &Arc<MetaService>,
    source: Source<'_>,
    objects: &[ObjectMeta],
    moves: &mut usize,
) {
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
    for (node, refs) in asks {
        let answer = match node_address(meta, &node) {
            Some(addr) => check_shards(&addr, objects, &refs).await,
            None => Err(anyhow::anyhow!("node not registered")),
        };
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

    for (oi, object) in objects.iter().enumerate() {
        STATS.objects.fetch_add(1, Ordering::Relaxed);
        let mut healthy = true;
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
            let v = verdict(&seen, stripe.ec_k as usize);
            healthy &= v == Verdict::Healthy && !seen.contains(&Seen::Unknown);
            match v {
                Verdict::Healthy => {}
                Verdict::Unrecoverable { good } => {
                    STATS.unrecoverable.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "repair: {}/{} stripe {} has {good} good shards, needs {}",
                        object.bucket, object.key, stripe.stripe_id, stripe.ec_k
                    );
                }
                Verdict::Rebuild { bad, good } => {
                    if let Err(e) = rebuild(meta, source, object, stripe, &seen, &bad, &good).await
                    {
                        STATS.errors.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "repair: {}/{} stripe {}: {e}",
                            object.bucket, object.key, stripe.stripe_id
                        );
                    }
                }
            }
        }
        let Source::Osd(owner_addr) = source else {
            continue;
        };
        if healthy && *moves > 0 && doubled_up(object) {
            match spread(meta, owner_addr, object, moves).await {
                Ok(n) => {
                    STATS.moved.fetch_add(n as u64, Ordering::Relaxed);
                }
                Err(e) => {
                    STATS.errors.fetch_add(1, Ordering::Relaxed);
                    warn!("backfill: {}/{}: {e}", object.bucket, object.key);
                }
            }
        }
        if let Err(e) = restore_listing(meta, owner_addr, object).await {
            STATS.errors.fetch_add(1, Ordering::Relaxed);
            warn!("repair: listing for {}/{}: {e}", object.bucket, object.key);
        }
    }
}

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
    source: Source<'_>,
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
    for &p in good {
        if have == k {
            break;
        }
        let Some(loc) = located.get(&(p as u32)) else {
            continue;
        };
        let Some(addr) = node_address(meta, &loc.node_id) else {
            continue;
        };
        match read_shard(&addr, &id, stripe.stripe_id, p as u32, loc.crc32c).await {
            Ok(bytes) => {
                survivors[p] = Some(bytes);
                have += 1;
            }
            Err(e) => debug!("repair: read of position {p} from {addr}: {e}"),
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
            Source::Osd(owner_addr) => {
                record_locations(meta, owner_addr, object, stripe.stripe_id, added).await?;
            }
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

/// Whether any of the object's stripes has two shards on one OSD.
fn doubled_up(object: &ObjectMeta) -> bool {
    object.stripes.iter().filter(|s| repairable(s)).any(|s| {
        let mut nodes = std::collections::HashSet::new();
        s.shards.iter().any(|l| !nodes.insert(l.node_id.as_slice()))
    })
}

/// Move the extra shards off OSDs holding two of a stripe to active OSDs
/// holding none (B20). The object's stripes are all good (checked by the
/// caller). Each shard is copied first; then every ObjectMeta copy and the
/// key's home follow; the old copies are deleted after [`MOVED_GRACE`].
/// Returns the shards moved.
async fn spread(
    meta: &Arc<MetaService>,
    owner_addr: &str,
    object: &ObjectMeta,
    budget: &mut usize,
) -> anyhow::Result<usize> {
    // (stripe id, the shard's old location, its new one, old OSD's address)
    let mut moved: Vec<(u64, ShardLocation, ShardLocation, String)> = Vec::new();
    for stripe in object.stripes.iter().filter(|s| repairable(s)) {
        let mut holders: std::collections::HashSet<Vec<u8>> =
            stripe.shards.iter().map(|l| l.node_id.clone()).collect();
        let mut kept = std::collections::HashSet::new();
        let mut shards = stripe.shards.clone();
        shards.sort_by_key(|l| l.position);
        for old in shards {
            if kept.insert(old.node_id.clone()) || *budget == 0 {
                continue;
            }
            let Some((to, to_addr)) = meta.spread_target(&object.object_id, &holders) else {
                break; // every active OSD holds a shard of it already
            };
            let from_addr = node_address(meta, &old.node_id).ok_or_else(|| {
                anyhow::anyhow!("holder of position {} not registered", old.position)
            })?;
            let bytes = read_shard(
                &from_addr,
                &stripe.object_id,
                stripe.stripe_id,
                old.position,
                old.crc32c,
            )
            .await?;
            let at = write_shard(&to_addr, &stripe.object_id, stripe, old.position, bytes).await?;
            holders.insert(to.to_vec());
            *budget -= 1;
            info!(
                "backfill: {}/{} stripe {} position {} from {from_addr} to {to_addr}",
                object.bucket, object.key, stripe.stripe_id, old.position
            );
            let new = ShardLocation {
                node_id: to.to_vec(),
                disk_id: at.disk_id,
                offset: at.offset,
                ..old.clone()
            };
            moved.push((stripe.stripe_id, old, new, from_addr));
        }
    }
    if moved.is_empty() {
        return Ok(0);
    }

    let changes: Vec<(u64, ShardLocation, ShardLocation)> = moved
        .iter()
        .map(|(id, old, new, _)| (*id, old.clone(), new.clone()))
        .collect();
    // On failure the new copies are left: some ObjectMeta copies may name
    // them already. A leak, never a loss.
    update_locations(meta, owner_addr, object, |fresh| {
        for (stripe_id, old, new) in changes {
            let loc = fresh
                .stripes
                .iter_mut()
                .find(|s| s.stripe_id == stripe_id)
                .and_then(|s| s.shards.iter_mut().find(|l| l.position == old.position))
                .filter(|l| l.node_id == old.node_id)
                .ok_or_else(|| anyhow::anyhow!("position {} moved meanwhile", old.position))?;
            *loc = new;
        }
        Ok(())
    })
    .await?;

    // The key's home: by position, as stripe 0 is placed.
    let home_moves: Vec<(u32, Vec<u8>, Vec<u8>)> = moved
        .iter()
        .filter(|(id, ..)| Some(*id) == object.stripes.first().map(|s| s.stripe_id))
        .map(|(_, old, new, _)| (old.position, old.node_id.clone(), new.node_id.clone()))
        .collect();
    if let Err(e) = meta
        .move_object_home(&object.bucket, &object.key, &home_moves)
        .await
    {
        // The shards moved; a later write of the key may double up again.
        warn!(
            "backfill: {}/{}: home not moved: {e}",
            object.bucket, object.key
        );
    }

    let due = std::time::Instant::now() + MOVED_GRACE;
    let mut queue = MOVED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let stripes: HashMap<u64, &StripeMeta> =
        object.stripes.iter().map(|s| (s.stripe_id, s)).collect();
    for (stripe_id, old, _, from_addr) in &moved {
        if let Some(stripe) = stripes.get(stripe_id) {
            queue.push((
                due,
                from_addr.clone(),
                ShardId {
                    object_id: stripe.object_id.clone(),
                    stripe_id: *stripe_id,
                    position: old.position,
                },
            ));
        }
    }
    Ok(moved.len())
}

/// Delete moved shards' old copies that are due. One that can't be deleted
/// now is tried again next pass.
async fn release_moved() {
    let now = std::time::Instant::now();
    let due: Vec<(std::time::Instant, String, ShardId)> = {
        let mut queue = MOVED
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (due, later) = queue.drain(..).partition(|(at, ..)| *at <= now);
        *queue = later;
        due
    };
    for (at, addr, shard) in due {
        let deleted = async {
            let mut client = StorageServiceClient::new(open_channel(&addr).await?);
            tokio::time::timeout(
                RPC_TIMEOUT,
                client.delete_shard(DeleteShardRequest {
                    shard_id: Some(shard.clone()),
                }),
            )
            .await??;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if let Err(e) = deleted {
            debug!("backfill: old copy on {addr} not deleted yet: {e}");
            MOVED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((at, addr, shard));
        }
    }
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

/// Add rebuilt shards' locations to the object's ObjectMeta on every node
/// that holds a copy — only if the key still holds this object.
async fn record_locations(
    meta: &Arc<MetaService>,
    owner_addr: &str,
    object: &ObjectMeta,
    stripe_id: u64,
    added: Vec<ShardLocation>,
) -> anyhow::Result<()> {
    update_locations(meta, owner_addr, object, |fresh| {
        let stripe = fresh
            .stripes
            .iter_mut()
            .find(|s| s.stripe_id == stripe_id)
            .ok_or_else(|| anyhow::anyhow!("stripe {stripe_id} is gone"))?;
        for loc in added {
            if stripe.shards.iter().all(|l| l.position != loc.position) {
                stripe.shards.push(loc);
            }
        }
        stripe.shards.sort_by_key(|l| l.position);
        Ok(())
    })
    .await
}

/// Change where the object's shards are, with `edit`, in its ObjectMeta on
/// every node that holds a copy (and every node that holds a shard after
/// the change) — only if the key still holds this object.
async fn update_locations(
    meta: &Arc<MetaService>,
    owner_addr: &str,
    object: &ObjectMeta,
    edit: impl FnOnce(&mut ObjectMeta) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let Some(mut fresh) = get_object_meta(owner_addr, object).await? else {
        return Err(anyhow::anyhow!("object is gone"));
    };
    if fresh.object_id != object.object_id {
        return Err(anyhow::anyhow!("object was replaced meanwhile"));
    }
    edit(&mut fresh)?;

    // Every copy: the key's placement, plus anyone holding a shard.
    let mut targets: BTreeSet<String> = placement_of(meta, object)
        .await?
        .into_iter()
        .map(|n| n.node_address)
        .collect();
    for s in &fresh.stripes {
        for l in &s.shards {
            if let Some(a) = node_address(meta, &l.node_id) {
                targets.insert(a);
            }
        }
    }
    // An update of what was read: ordered after its other updates, the same
    // on every copy; its stamp stays, so a newer object still wins.
    fresh.update_stamp = objectio_common::stamp::CLOCK.next_after(fresh.update_stamp);
    let mut stored_on_owner = false;
    for addr in targets {
        let req = PutObjectMetaRequest {
            bucket: fresh.bucket.clone(),
            key: fresh.key.clone(),
            object: Some(fresh.clone()),
            versioning_enabled: false,
            expected_object_id: fresh.object_id.clone(),
            // An object deleted since it was read must not come back.
            require_existing: true,
            version_only: false,
            keep_newer_current: false,
            replication_update: false,
            replication_set: std::collections::HashMap::new(),
        };
        let result = async {
            let mut client = StorageServiceClient::new(open_channel(&addr).await?);
            tokio::time::timeout(RPC_TIMEOUT, client.put_object_meta(req)).await??;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        match result {
            Ok(()) => stored_on_owner |= addr == owner_addr,
            // A copy that no longer holds this object, or a node that is
            // down: the next pass looks again.
            Err(e) => debug!("repair: ObjectMeta update on {addr}: {e}"),
        }
    }
    if stored_on_owner {
        Ok(())
    } else {
        Err(anyhow::anyhow!("could not update the owner's ObjectMeta"))
    }
}

async fn get_object_meta(address: &str, object: &ObjectMeta) -> anyhow::Result<Option<ObjectMeta>> {
    let mut client = StorageServiceClient::new(open_channel(address).await?)
        .max_decoding_message_size(100 * 1024 * 1024);
    let resp = tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_object_meta(GetObjectMetaRequest {
            bucket: object.bucket.clone(),
            key: object.key.clone(),
            version_id: String::new(),
        }),
    )
    .await??
    .into_inner();
    Ok(resp.object.filter(|_| resp.found))
}

/// Meta's listing entry for `object`.
async fn list(meta: &Arc<MetaService>, object: &ObjectMeta) -> anyhow::Result<()> {
    MetadataService::create_object(
        meta.as_ref(),
        tonic::Request::new(CreateObjectRequest {
            bucket: object.bucket.clone(),
            key: object.key.clone(),
            size: object.size,
            content_type: object.content_type.clone(),
            etag: object.etag.clone(),
            user_metadata: object.user_metadata.clone(),
            stripes: object.stripes.clone(),
            object_id: object.object_id.clone(),
            pg_id: 0,
            pool: String::new(),
            // Its home, if it has one, is where it was found.
            home_osd_ids: Vec::new(),
            ..Default::default()
        }),
    )
    .await
    .map_err(|e| anyhow::anyhow!("create_object: {e}"))?;
    Ok(())
}

/// The key's current object as a read quorum of its copies has it, as a
/// GET reads it (objectio-docs core/object-metadata-quorum.md): the newest
/// object, unless a tombstone is newer. `None`: deleted, or absent. An
/// error when fewer than a read quorum answer.
async fn quorum_current(
    meta: &Arc<MetaService>,
    object: &ObjectMeta,
) -> anyhow::Result<Option<ObjectMeta>> {
    let mut addrs: Vec<String> = Vec::new();
    let mut seen_nodes: Vec<Vec<u8>> = Vec::new();
    for n in placement_of(meta, object).await? {
        if !seen_nodes.contains(&n.node_id) {
            seen_nodes.push(n.node_id.clone());
            addrs.push(n.node_address);
        }
    }
    let copies = addrs.len();
    let read_quorum = copies - (copies / 2 + 1) + 1;
    let asks = addrs.iter().map(|addr| async move {
        let mut client = StorageServiceClient::new(open_channel(addr).await?)
            .max_decoding_message_size(100 * 1024 * 1024);
        let resp = tokio::time::timeout(
            RPC_TIMEOUT,
            client.get_object_meta(GetObjectMetaRequest {
                bucket: object.bucket.clone(),
                key: object.key.clone(),
                version_id: String::new(),
            }),
        )
        .await??
        .into_inner();
        Ok::<_, anyhow::Error>((resp.object.filter(|_| resp.found), resp.tombstone_stamp))
    });
    let mut answered = 0;
    let mut newest: Option<ObjectMeta> = None;
    let mut deleted_at = 0u64;
    for answer in futures::future::join_all(asks).await.into_iter().flatten() {
        answered += 1;
        deleted_at = deleted_at.max(answer.1);
        if let Some(o) = answer.0
            && newest
                .as_ref()
                .is_none_or(|n| o.write_order() > n.write_order())
        {
            newest = Some(o);
        }
    }
    if answered < read_quorum {
        return Err(anyhow::anyhow!(
            "{answered} of {copies} copies answered, need {read_quorum}"
        ));
    }
    Ok(newest.filter(|o| deleted_at == 0 || deleted_at < o.stamp))
}

/// Put an object missing from Meta's listing index back, so ListObjects
/// shows it: only if a read quorum of its copies has it as the current
/// object, as a GET would. Checked against the owner alone it listed
/// objects deleted moments before (a copy that missed or hadn't yet taken
/// the delete; the B2 soak). And checked again after, in case a delete
/// landed in between: then the entry goes again.
async fn restore_listing(
    meta: &Arc<MetaService>,
    _owner_addr: &str,
    object: &ObjectMeta,
) -> anyhow::Result<()> {
    if object.is_delete_marker || meta.object_listed(&object.bucket, &object.key) {
        return Ok(());
    }
    let is_current = |c: &Option<ObjectMeta>| {
        c.as_ref()
            .is_some_and(|c| c.object_id == object.object_id && !c.is_delete_marker)
    };
    if !is_current(&quorum_current(meta, object).await?) {
        return Ok(());
    }
    list(meta, object).await?;
    // A delete or a replacement may have landed since the check: the entry
    // follows what is current now.
    match quorum_current(meta, object).await? {
        Some(c) if c.object_id == object.object_id && !c.is_delete_marker => {}
        Some(c) if !c.is_delete_marker => {
            list(meta, &c).await?;
            return Ok(());
        }
        _ => {
            MetadataService::delete_object(
                meta.as_ref(),
                tonic::Request::new(objectio_proto::metadata::DeleteObjectRequest {
                    bucket: object.bucket.clone(),
                    key: object.key.clone(),
                    version_id: String::new(),
                    forget_home: false,
                }),
            )
            .await
            .map_err(|e| anyhow::anyhow!("delete_object: {e}"))?;
            return Ok(());
        }
    }
    STATS.listings_restored.fetch_add(1, Ordering::Relaxed);
    info!(
        "repair: restored the listing entry of {}/{}",
        object.bucket, object.key
    );
    Ok(())
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
