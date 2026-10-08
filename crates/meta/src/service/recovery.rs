//! Recovery (B31 phase 3a, objectio-docs `core/pg-recovery.md`): peering
//! says what each placement group's members lack; recovery makes them
//! whole. One operation does it all: bring every object of the PG to its
//! acting set, position by position. That is
//!
//! - **recovery**, for members that missed writes (a metadata copy, an
//!   up-to-date one, the shard at their position), or a shard that rotted;
//! - **backfill**, for a member that holds nothing of the PG yet: a
//!   stand-in (`filling`, made by `pgs.rs` for a member gone or down past
//!   the grace), or a member of `up` that acting isn't on yet. A remap is
//!   committed first, as a stand-in is (acting takes the up member, filled
//!   from the member it replaces), so both are one path; and a draining or
//!   lost OSD is emptied the same way, since its PGs stand in for it.
//!
//! Per object: the newest copy is read whole from a member that holds it;
//! each position whose acting member doesn't hold the shard gets it, copied
//! from where the object says it is or rebuilt from k others; and every
//! acting member gets the object's metadata, its locations updated. A
//! rebuilt copy keeps the object's write order (only its update stamp is
//! raised, for new locations), so a newer write always wins; an object
//! whose newest copy changed since the listing is left for the next round.
//! A newer delete is applied to members that missed it.
//!
//! A PG is worked only after reserving a slot on every OSD it reads from
//! or writes to (`pg/backfills_per_osd`, 2), and each object's writes take
//! a rebuild slot on each member (`pg/rebuilds_per_osd`, 16). A member to
//! fill past `pg/backfill_full_ratio` (0.90) holds the PG in `WaitTooFull`
//! until it has room. PGs with the fewest copies to spare go first; within
//! a PG, objects with none to spare, then the rest in key order. Progress
//! (a cursor in key order, counts) is kept in the PG's `pg_state` through
//! Raft, so a new leader resumes rather than starts again. An object with
//! fewer than k shards anywhere is recorded unfound, and not tried again
//! until a member comes back.
//!
//! Every protection scheme (phase 3b): an MDS stripe's missing shards are
//! rebuilt from k others; a replicated stripe's missing copy is copied
//! from an intact one; an LRC stripe's missing shard is rebuilt from its
//! local group (the group's other data and its local parity, kept in one
//! failure domain by the pool's rule) when the group has them, and from
//! the whole stripe only when it doesn't. A stray's copies (a member a PG no longer has) of the
//! PG's objects are withdrawn once the PG is filled; its shards stay
//! allocated (a leak, not a loss) until the OSD is purged.

use super::*;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use objectio_proto::metadata::{PgState, ShardLocation, StripeMeta};
use objectio_proto::storage::{
    CheckShardsRequest, DeleteObjectMetaRequest, GetObjectMetaRequest, GetStatusRequest, PgEntry,
    PgRef, PutObjectMetaRequest, ReadShardRequest, ShardId, ShardState, SmallShard,
    WriteShardRequest, storage_service_client::StorageServiceClient,
};

use super::peering::{list_of, needs, order, split_entry_name};
use super::pgs::{pg_placement, set_filling};

/// How often the leader looks for placement groups to recover.
const TICK: Duration = Duration::from_secs(2);

/// Placement groups recovered at once on the leader (`pg/recover_at_once`).
const PGS_AT_ONCE: usize = 8;

/// PGs one OSD takes part in recovering at once (`pg/backfills_per_osd`).
const BACKFILLS_PER_OSD: usize = 2;

/// Objects one OSD takes writes for at once (`pg/rebuilds_per_osd`).
const REBUILDS_PER_OSD: usize = 16;

/// A member to fill past this share of its capacity is too full
/// (`pg/backfill_full_ratio`): the PG waits. Ceph's `backfillfull_ratio`.
const BACKFILL_FULL_RATIO: f64 = 0.90;

/// How long a PG waits when a member to fill is too full
/// (`pg/too_full_retry_seconds`).
const TOO_FULL_RETRY_SECS: u64 = 30;

/// Objects worked between saves of the cursor.
const CHUNK: usize = 64;

/// Objects of one PG worked at once.
const OBJECTS_AT_ONCE: usize = 16;

/// Per-RPC timeout. Shard reads and writes move up to 4 MiB.
const RPC_TIMEOUT: Duration = Duration::from_secs(30);

/// Unfound keys kept in a PG's state.
const UNFOUND_KEPT: usize = 64;

/// A placement group: its pool and id.
type PgId = (String, u32);

/// A member's entries of a PG, by (bucket, key).
type Listing = HashMap<(String, String), PgEntry>;

/// A PG's epoch, members down and objects degraded, as recovery last left
/// it unable to change anything more.
type StuckAt = (u64, u32, u64);

/// Wakes the next look before the tick: a PG's recovery finished.
static NEXT: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Placement groups being recovered on this leader.
static BUSY: LazyLock<parking_lot::Mutex<HashSet<(String, u32)>>> = LazyLock::new(Default::default);

/// PGs each OSD is reserved for.
static SLOTS: LazyLock<parking_lot::Mutex<HashMap<Vec<u8>, usize>>> =
    LazyLock::new(Default::default);

/// Each OSD's rebuild slots.
static REBUILDS: LazyLock<parking_lot::Mutex<HashMap<Vec<u8>, Arc<tokio::sync::Semaphore>>>> =
    LazyLock::new(Default::default);

/// What each PG recovering has left: objects, bytes.
static LEFT: LazyLock<parking_lot::Mutex<HashMap<PgId, (u64, u64)>>> =
    LazyLock::new(Default::default);

/// PGs whose last recovery could change nothing more (what is left is
/// unfound, or on a member that is down), with their epoch, members down
/// and objects degraded then: not tried again until one of them changes.
static STUCK: LazyLock<parking_lot::Mutex<HashMap<PgId, StuckAt>>> =
    LazyLock::new(Default::default);

/// PGs whose last recovery pass got nowhere (a member it needed didn't
/// answer, a remap or plan that failed, nothing written): how many such
/// passes in a row, and not before when the next. Doubling from
/// [`BACKOFF_BASE`] to [`BACKOFF_MAX`]: a pass that can't succeed is
/// retried less and less often, never in a tight loop.
/// The PG's epoch and members down when it was set end it early when they
/// change: a member back, or another epoch, is worth a pass at once.
static BACKOFF: LazyLock<parking_lot::Mutex<HashMap<PgId, Backoff>>> =
    LazyLock::new(Default::default);
struct Backoff {
    passes: u32,
    until: std::time::Instant,
    epoch: u64,
    members_down: u32,
}
const BACKOFF_BASE: Duration = Duration::from_secs(2);
const BACKOFF_MAX: Duration = Duration::from_secs(300);

/// The wait before the next pass after `n` in a row that got nowhere.
fn backoff_after(n: u32) -> Duration {
    BACKOFF_BASE
        .saturating_mul(1u32 << n.min(16))
        .min(BACKOFF_MAX)
}

/// Note a pass of `id` that got nowhere, at `epoch` with `members_down`:
/// the next waits longer.
fn no_progress(id: &PgId, epoch: u64, members_down: u32) {
    RETRIES.fetch_add(1, Ordering::Relaxed);
    let mut b = BACKOFF.lock();
    let n = b.get(id).map_or(0, |b| b.passes);
    b.insert(
        id.clone(),
        Backoff {
            passes: n + 1,
            until: std::time::Instant::now() + backoff_after(n),
            epoch,
            members_down,
        },
    );
}

static RETRIES: AtomicU64 = AtomicU64::new(0);
static REFUSED: AtomicU64 = AtomicU64::new(0);
static TOO_FULL: AtomicU64 = AtomicU64::new(0);
static OBJECTS: AtomicU64 = AtomicU64::new(0);
static SHARDS: AtomicU64 = AtomicU64::new(0);
static COPIES: AtomicU64 = AtomicU64::new(0);
static REMAPS: AtomicU64 = AtomicU64::new(0);
static LRC_LOCAL: AtomicU64 = AtomicU64::new(0);
static LRC_GLOBAL: AtomicU64 = AtomicU64::new(0);
static LRC_LOCAL_READS: AtomicU64 = AtomicU64::new(0);
static LRC_GLOBAL_READS: AtomicU64 = AtomicU64::new(0);
static REPLICAS: AtomicU64 = AtomicU64::new(0);

/// The members down peering last recorded of `pg`.
fn held_down(meta: &MetaService, pg: &PlacementGroup) -> u32 {
    meta.pg_state(&pg.pool, pg.pg_id)
        .map_or(0, |s| s.members_down)
}

/// Whether recovery is working `pool/pg` on this leader (peering leaves it).
pub(crate) fn is_busy(id: &(String, u32)) -> bool {
    BUSY.lock().contains(id)
}

/// Keep, in a state peering computed, recovery's progress from the one it
/// replaces: the cursor (if for this epoch), the counts, the unfound keys
/// and when to try a too-full PG again.
pub(crate) fn keep_progress(state: &mut PgState, held: &PgState) {
    if held.cursor_epoch == state.epoch {
        state.cursor.clone_from(&held.cursor);
        state.cursor_epoch = held.cursor_epoch;
    }
    state.recovered = held.recovered;
    state.remaining = held.remaining;
    state.bytes_remaining = held.bytes_remaining;
    if state.objects_unfound > 0 {
        state.unfound_keys.clone_from(&held.unfound_keys);
    }
    state.retry_at = held.retry_at;
}

/// Recovery's metrics as Prometheus families (the leader's view).
pub fn render_metrics(out: &mut String) {
    use std::fmt::Write as _;
    let held: usize = SLOTS.lock().values().sum();
    let (objects, bytes) = LEFT
        .lock()
        .values()
        .fold((0, 0), |(o, b), (lo, lb)| (o + lo, b + lb));
    for (name, help, v) in [
        (
            "objectio_meta_pg_reservations",
            "Recovery reservations held: (OSD, PG) pairs",
            held as u64,
        ),
        (
            "objectio_meta_pg_recovering",
            "Placement groups being recovered on the leader",
            BUSY.lock().len() as u64,
        ),
        (
            "objectio_meta_pg_recovery_backing_off",
            "Placement groups whose recovery is waiting out a backoff",
            BACKOFF
                .lock()
                .values()
                .filter(|b| std::time::Instant::now() < b.until)
                .count() as u64,
        ),
        (
            "objectio_meta_pg_recovery_objects_remaining",
            "Objects recovery has left to do in the PGs it is working",
            objects,
        ),
        (
            "objectio_meta_pg_recovery_bytes_remaining",
            "Bytes of the objects recovery has left to do in the PGs it is working",
            bytes,
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
    }
    for (name, help, v) in [
        (
            "objectio_meta_pg_reservations_refused_total",
            "Times a PG could not reserve a slot on every OSD it needed",
            &REFUSED,
        ),
        (
            "objectio_meta_pg_recovery_retries_total",
            "Recovery passes that got nowhere (each waits twice as long for the next, to 5 min)",
            &RETRIES,
        ),
        (
            "objectio_meta_pg_too_full_total",
            "Times a PG waited for a member to fill that was too full",
            &TOO_FULL,
        ),
        (
            "objectio_meta_pg_recovered_objects_total",
            "Objects recovery made whole",
            &OBJECTS,
        ),
        (
            "objectio_meta_pg_recovered_shards_total",
            "Shards recovery wrote to the member at their position",
            &SHARDS,
        ),
        (
            "objectio_meta_pg_recovered_copies_total",
            "Metadata copies recovery wrote",
            &COPIES,
        ),
        (
            "objectio_meta_pg_remaps_total",
            "Placement groups moved to their up set",
            &REMAPS,
        ),
        (
            "objectio_meta_pg_replica_copies_total",
            "Replicated copies recovery made from an intact one",
            &REPLICAS,
        ),
    ] {
        let _ = writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}",
            v.load(Ordering::Relaxed)
        );
    }
    render_lrc(out);
}

/// Rebuilds of LRC shards and the shards they read, by kind: from the
/// shard's local group, or from the whole stripe.
fn render_lrc(out: &mut String) {
    use std::fmt::Write as _;
    for (name, help, local, global) in [
        (
            "objectio_meta_pg_lrc_rebuilds_total",
            "LRC shards recovery rebuilt, from their local group or the whole stripe",
            &LRC_LOCAL,
            &LRC_GLOBAL,
        ),
        (
            "objectio_meta_pg_lrc_shards_read_total",
            "Shards LRC rebuilds read, inside the local group or across the stripe",
            &LRC_LOCAL_READS,
            &LRC_GLOBAL_READS,
        ),
    ] {
        let _ = writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} counter\n{name}{{kind=\"local\"}} {}\n{name}{{kind=\"global\"}} {}",
            local.load(Ordering::Relaxed),
            global.load(Ordering::Relaxed)
        );
    }
}

/// A PG's reservation: a slot on each OSD, released when dropped.
struct Reservation(Vec<Vec<u8>>);

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut slots = SLOTS.lock();
        for id in &self.0 {
            if let Some(n) = slots.get_mut(id) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    slots.remove(id);
                }
            }
        }
    }
}

/// Reserve a slot on every OSD of `osds`, or none (`limit` per OSD).
fn reserve(osds: &BTreeSet<Vec<u8>>, limit: usize) -> Option<Reservation> {
    let mut slots = SLOTS.lock();
    if osds
        .iter()
        .any(|id| slots.get(id).copied().unwrap_or(0) >= limit)
    {
        return None;
    }
    for id in osds {
        *slots.entry(id.clone()).or_insert(0) += 1;
    }
    Some(Reservation(osds.iter().cloned().collect()))
}

/// OSD `id`'s rebuild slots.
fn rebuild_slots(id: &[u8], permits: usize) -> Arc<tokio::sync::Semaphore> {
    REBUILDS
        .lock()
        .entry(id.to_vec())
        .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(permits.max(1))))
        .clone()
}

/// Removes a PG from [`BUSY`] when its recovery ends, however it ends.
struct Busy((String, u32));

impl Drop for Busy {
    fn drop(&mut self) {
        BUSY.lock().remove(&self.0);
        LEFT.lock().remove(&self.0);
    }
}

/// One object recovery has to work on, as the listings show it.
#[derive(Clone, Debug)]
struct Work {
    bucket: String,
    key: String,
    /// A version's entry: its id (`null` for the version written while
    /// versioning was off); empty for the key's own.
    version_id: String,
    /// The newest entry any member or stray holds.
    newest: PgEntry,
    /// Addresses of the OSDs holding that entry.
    holders: Vec<String>,
    /// Acting positions whose member holds no copy of it, or an older one
    /// (an object, where the newest is a delete).
    behind: Vec<usize>,
    /// Complete copies beyond what a read needs.
    spare: i64,
}

/// What recovery found to do in a PG.
#[derive(Default)]
struct Plan {
    work: Vec<Work>,
    /// Each acting member's address, if it is usable and answered the
    /// listing: one that didn't is left alone this pass (its positions are
    /// what an object can't be made whole of yet).
    members: Vec<Option<String>>,
    /// Entries strays hold of the PG: (address, bucket, key, object id).
    strays: Vec<(String, String, String, Vec<u8>)>,
}

/// How one object went.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Every acting member holds it, every shard at its position.
    Done,
    /// What could be done is: a position whose member can't be used (down,
    /// undersized) is left.
    Partial,
    /// It changed since the listing: the next round sees it again.
    Changed,
    /// Fewer than k of a stripe's shards could be read anywhere: the
    /// stripe, the good shards found, and how many a read needs.
    Unfound(u64, u32, u32),
    /// Not done now (a member didn't answer, a write failed): later.
    Failed(String),
}

/// The positions of `pg` whose up member is usable and not the acting one:
/// where the PG is to move (the balancer's choice, or a member back).
fn remap_positions(meta: &MetaService, pg: &PlacementGroup) -> Vec<usize> {
    if pg.up.len() != pg.acting.len() {
        return Vec::new();
    }
    (0..pg.up.len())
        .filter(|&p| pg.up[p] != pg.acting[p])
        .filter(|&p| meta.usable_address(&pg.up[p]).is_some())
        // Not onto a member already holding another position of the PG.
        .filter(|&p| !pg.acting.contains(&pg.up[p]))
        .collect()
}

/// Whether a stripe is one recovery rebuilds: the object's own (not a
/// pack's slice), with redundancy to rebuild from: MDS or LRC parity, or
/// more than one replicated copy (`ec_k` 1, `ec_m` the copies but one).
fn recoverable(stripe: &StripeMeta) -> bool {
    stripe.pack_id.is_empty() && stripe.ec_k > 0 && stripe.ec_m > 0
}

/// The positions an LRC shard is rebuilt from inside its local group: the
/// group's other data shards and its local parity (positions are data
/// `0..k`, then one local parity per group, then the global parities). None
/// for a global parity, or a stripe that isn't LRC with local groups.
fn lrc_local_set(stripe: &StripeMeta, position: usize) -> Option<Vec<usize>> {
    let ec = ErasureType::try_from(stripe.ec_type).unwrap_or(ErasureType::ErasureMds);
    let (k, l) = (stripe.ec_k as usize, stripe.ec_local_parity as usize);
    if ec != ErasureType::ErasureLrc || l == 0 || k % l != 0 {
        return None;
    }
    let size = k / l;
    let group = if position < k {
        position / size
    } else if position < k + l {
        position - k
    } else {
        return None;
    };
    let mut set: Vec<usize> = (group * size..(group + 1) * size)
        .chain(std::iter::once(k + group))
        .filter(|&p| p != position)
        .collect();
    set.sort_unstable();
    Some(set)
}

/// The id a stripe's shards are stored under: its own, else its object's.
fn shard_object(object: &ObjectMeta, stripe: &StripeMeta) -> Vec<u8> {
    if stripe.object_id.is_empty() {
        object.object_id.clone()
    } else {
        stripe.object_id.clone()
    }
}

/// Run recovery on the leader (B31 phase 3a).
pub fn spawn(meta: Arc<MetaService>) {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = tokio::time::sleep(TICK) => {}
                () = NEXT.notified() => {}
            }
            if meta.is_raft_leader() {
                meta.recovery_round().await;
            } else {
                STUCK.lock().clear();
                BACKOFF.lock().clear();
            }
        }
    });
}

impl MetaService {
    /// One look (leader, level 7): start recovering the placement groups
    /// that need it, those with the fewest copies to spare first, up to
    /// `pg/recover_at_once` at a time.
    pub(crate) async fn recovery_round(self: &Arc<Self>) {
        if !self.is_raft_leader()
            || !pg_placement()
            || !self.config_parsed("pg/recovery_enabled", true)
        {
            return;
        }
        let at_once = self.config_parsed("pg/recover_at_once", PGS_AT_ONCE).max(1);
        let busy = BUSY.lock().len();
        if busy >= at_once {
            return;
        }
        let now = Self::current_timestamp();
        let pools: HashMap<String, PoolConfig> = self
            .pools_snapshot()
            .into_iter()
            .filter(|p| p.pg_count > 0)
            .map(|p| (p.name.clone(), p))
            .collect();
        let mut due: Vec<((i64, u8, u64), PlacementGroup)> = Vec::new();
        for pool in pools.keys() {
            let states = self.pg_states(pool);
            for pg in self.placement_groups_for_pool(pool) {
                let id = (pg.pool.clone(), pg.pg_id);
                if is_busy(&id) {
                    continue;
                }
                if let Some(rank) = self.recovery_need(&pg, states.get(&pg.pg_id), now) {
                    due.push((rank, pg));
                }
            }
        }
        due.sort_by_key(|(rank, pg)| (*rank, pg.pool.clone(), pg.pg_id));
        // In that order, those that can reserve every OSD they need; one
        // that can't waits for a later look, the rest go on.
        let limit = self
            .config_parsed("pg/backfills_per_osd", BACKFILLS_PER_OSD)
            .max(1);
        let mut started = 0;
        for (_, pg) in due {
            if busy + started >= at_once {
                break;
            }
            let Some(pool) = pools.get(&pg.pool).cloned() else {
                continue;
            };
            let Some(reservation) = reserve(&self.recovery_osds(&pg), limit) else {
                REFUSED.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let id = (pg.pool.clone(), pg.pg_id);
            if !BUSY.lock().insert(id.clone()) {
                continue;
            }
            started += 1;
            let me = Arc::clone(self);
            tokio::spawn(async move {
                let _busy = Busy(id);
                me.recover_pg(pg, pool, reservation).await;
                // A slot is free: the next look needn't wait for the tick.
                NEXT.notify_one();
            });
        }
    }

    /// The OSDs recovering `pg` reads from or writes to: its acting members,
    /// those it is filled from, and the up members it is to move to, those
    /// that can be used.
    fn recovery_osds(&self, pg: &PlacementGroup) -> BTreeSet<Vec<u8>> {
        let remap = remap_positions(self, pg);
        pg.acting
            .iter()
            .chain(pg.filling.iter().map(|f| &f.from))
            .chain(remap.iter().map(|&p| &pg.up[p]))
            .filter(|m| self.usable_address(m).is_some())
            .cloned()
            .collect()
    }

    /// Whether `pg` needs recovering, and how urgently (lowest first): its
    /// fewest copies to spare, then recovery before a move, then how long
    /// it has waited. None: nothing to do, or nothing that can be done.
    fn recovery_need(
        &self,
        pg: &PlacementGroup,
        state: Option<&PgState>,
        now: u64,
    ) -> Option<(i64, u8, u64)> {
        let moving = !pg.filling.is_empty() || !remap_positions(self, pg).is_empty();
        // The last pass got nowhere: not before its backoff ends, unless the
        // PG's epoch or the members down changed since.
        {
            let mut b = BACKOFF.lock();
            let id = (pg.pool.clone(), pg.pg_id);
            if let Some(off) = b.get(&id) {
                let down = state.map_or(off.members_down, |s| s.members_down);
                if off.epoch != pg.epoch || off.members_down != down {
                    b.remove(&id);
                } else if std::time::Instant::now() < off.until {
                    return None;
                }
            }
        }
        if let Some(s) = state {
            // Too few members answer to know what is current: nothing is
            // rebuilt from a view that may be old.
            if s.state == "Down" || s.state == "Incomplete" {
                return None;
            }
            if s.state == "WaitTooFull" && now < s.retry_at {
                return None;
            }
        }
        let resume = state.is_some_and(|s| {
            matches!(
                s.state.as_str(),
                "Recovering" | "Backfilling" | "WaitTooFull"
            )
        });
        let degraded = state.is_some_and(|s| {
            s.epoch == pg.epoch
                && s.objects_degraded > 0
                && matches!(s.state.as_str(), "Degraded" | "Undersized")
        });
        if !(moving || resume || degraded) {
            return None;
        }
        // The last pass could change nothing more, and nothing has changed
        // since.
        let id = (pg.pool.clone(), pg.pg_id);
        if !moving
            && state.is_some_and(|s| {
                STUCK.lock().get(&id) == Some(&(pg.epoch, s.members_down, s.objects_degraded))
            })
        {
            return None;
        }
        let spare = state.map_or(i64::MAX, |s| s.min_spare);
        Some((spare, u8::from(!degraded), state.map_or(0, |s| s.since)))
    }

    /// Recover one placement group, its OSDs reserved: move it to its up set
    /// if it is to move, plan, work every object, record progress, then
    /// peer it.
    async fn recover_pg(
        self: &Arc<Self>,
        mut pg: PlacementGroup,
        pool: PoolConfig,
        reservation: Reservation,
    ) {
        let id = (pg.pool.clone(), pg.pg_id);
        let remap = remap_positions(self, &pg);
        let reserved_on: Vec<Vec<u8>> = reservation.0.clone();

        // Members to fill must have room: the up members to move to, and
        // the stand-ins being filled.
        let mut to_fill: Vec<Vec<u8>> = remap.iter().map(|&p| pg.up[p].clone()).collect();
        to_fill.extend(
            pg.filling
                .iter()
                .filter_map(|f| pg.acting.get(f.position as usize).cloned()),
        );
        if let Some(why) = self.too_full(&to_fill).await {
            TOO_FULL.fetch_add(1, Ordering::Relaxed);
            let retry = self.config_parsed("pg/too_full_retry_seconds", TOO_FULL_RETRY_SECS);
            self.note_recovery(&pg, |s| {
                s.state = "WaitTooFull".into();
                s.retry_at = Self::current_timestamp() + retry;
                s.last_error = why.clone();
                s.reserved_on.clear();
            })
            .await;
            info!("pg {}/{}: waiting for room: {why}", pg.pool, pg.pg_id);
            return;
        }

        if !remap.is_empty() {
            match self.commit_remap(&pg, &remap).await {
                Ok(new) => pg = new,
                Err(e) => {
                    debug!("pg {}/{}: remap not committed: {e}", pg.pool, pg.pg_id);
                    no_progress(&id, pg.epoch, held_down(self, &pg));
                    return;
                }
            }
        }

        let filling = !pg.filling.is_empty();
        let working = if filling { "Backfilling" } else { "Recovering" };
        let held = self.pg_state(&pg.pool, pg.pg_id);
        let mut cursor = held
            .as_ref()
            .filter(|h| h.cursor_epoch == pg.epoch)
            .map(|h| h.cursor.clone())
            .unwrap_or_default();
        let mut recovered = held.as_ref().map_or(0, |h| h.recovered);

        let plan = match self.recovery_plan(&pg, &pool).await {
            Ok(plan) => plan,
            Err(e) => {
                self.note_recovery(&pg, |s| s.last_error = e.clone()).await;
                debug!("pg {}/{}: not planned: {e}", pg.pool, pg.pg_id);
                no_progress(&id, pg.epoch, held_down(self, &pg));
                return;
            }
        };

        // What there is to do: objects with none to spare first, whatever
        // the cursor says; then the rest in key order, after the cursor.
        let urgent: Vec<Work> = plan.work.iter().filter(|w| w.spare <= 0).cloned().collect();
        let mut ordered: Vec<Work> = plan
            .work
            .iter()
            .filter(|w| w.spare > 0)
            .filter(|w| cursor.is_empty() || w.cursor() > cursor)
            .cloned()
            .collect();
        ordered.sort_by(|a, b| (&a.bucket, &a.key).cmp(&(&b.bucket, &b.key)));
        let total = urgent.len() + ordered.len();
        let mut left_bytes: u64 = urgent.iter().chain(&ordered).map(|w| w.newest.size).sum();
        LEFT.lock().insert(id.clone(), (total as u64, left_bytes));
        if total > 0 {
            info!(
                "pg {}/{} (epoch {}): {working}: {total} objects ({} with nothing to spare)",
                pg.pool,
                pg.pg_id,
                pg.epoch,
                urgent.len()
            );
        }
        self.note_recovery(&pg, |s| {
            s.state = working.into();
            s.cursor.clone_from(&cursor);
            s.cursor_epoch = pg.epoch;
            s.recovered = recovered;
            s.remaining = total as u64;
            s.bytes_remaining = left_bytes;
            s.reserved_on.clone_from(&reserved_on);
            s.last_error.clear();
        })
        .await;

        let mut failed: Option<String> = None;
        let mut unfound: Vec<String> = Vec::new();
        let mut lost: Vec<(String, objectio_proto::metadata::LostObject)> = Vec::new();
        let mut left = total;
        let wrote_before = SHARDS.load(Ordering::Relaxed) + COPIES.load(Ordering::Relaxed);
        // Urgent ones don't move the cursor; ordered ones move it past each
        // chunk that finished without a failure, while none has failed yet.
        let chunks: Vec<(bool, Vec<Work>)> = urgent
            .chunks(CHUNK)
            .map(|c| (false, c.to_vec()))
            .chain(ordered.chunks(CHUNK).map(|c| (true, c.to_vec())))
            .collect();
        let mut cursor_moves = true;
        for (moves_cursor, chunk) in chunks {
            if !self.is_raft_leader()
                || self
                    .placement_group(&pg.pool, pg.pg_id)
                    .is_none_or(|now| now.epoch != pg.epoch)
            {
                // Another leader, or another epoch: this one stops here.
                debug!("pg {}/{}: recovery interrupted", pg.pool, pg.pg_id);
                return;
            }
            let outcomes = self.recover_chunk(&pg, &plan.members, chunk.clone()).await;
            let mut chunk_failed = false;
            for (w, outcome) in chunk.iter().zip(outcomes) {
                left -= 1;
                left_bytes = left_bytes.saturating_sub(w.newest.size);
                match outcome {
                    Outcome::Done => {
                        recovered += 1;
                        OBJECTS.fetch_add(1, Ordering::Relaxed);
                        // The key's record (B29) is of its current object.
                        if w.version_id.is_empty() {
                            self.forget_degraded_key(&w.bucket, &w.key).await;
                        }
                    }
                    Outcome::Partial | Outcome::Changed => {}
                    Outcome::Unfound(stripe_id, good, needed) => {
                        let name = w.name();
                        lost.push((
                            name.clone(),
                            objectio_proto::metadata::LostObject {
                                object_id: w.newest.object_id.clone(),
                                stripe_id,
                                good,
                                needed,
                                recorded_at: Self::current_timestamp(),
                                found_by: "recovery".into(),
                            },
                        ));
                        unfound.push(name);
                    }
                    Outcome::Failed(e) => {
                        chunk_failed = true;
                        debug!("pg {}/{}: {}: {e}", pg.pool, pg.pg_id, w.name());
                        failed.get_or_insert(format!("{}: {e}", w.name()));
                    }
                }
            }
            cursor_moves &= !chunk_failed;
            if moves_cursor
                && cursor_moves
                && let Some(last) = chunk.last()
            {
                cursor = last.cursor();
            }
            LEFT.lock().insert(id.clone(), (left as u64, left_bytes));
            self.note_recovery(&pg, |s| {
                s.state = working.into();
                s.cursor.clone_from(&cursor);
                s.cursor_epoch = pg.epoch;
                s.recovered = recovered;
                s.remaining = left as u64;
                s.bytes_remaining = left_bytes;
                s.reserved_on.clone_from(&reserved_on);
                if let Some(e) = &failed {
                    s.last_error.clone_from(e);
                }
            })
            .await;
        }
        drop(reservation);
        let wrote = SHARDS.load(Ordering::Relaxed) + COPIES.load(Ordering::Relaxed) > wrote_before;

        // Every object done, every member filled reachable: the stand-ins
        // are filled, and the members they were filled from are strays.
        let fillers_up = pg
            .filling
            .iter()
            .filter_map(|f| pg.acting.get(f.position as usize))
            .all(|id| self.usable_address(id).is_some());
        // Objects left unfound with every acting member answering, while
        // what they would need was on members gone for good (those filled
        // from): lost (B29). Recorded, and the fill finishes rather than
        // hold the gone member's evacuation forever. With a member only
        // down, it may have their shards: nothing is decided.
        let all_answered = plan.members.iter().all(Option::is_some);
        let sources_gone = pg
            .filling
            .iter()
            .all(|f| self.usable_address(&f.from).is_none());
        let settled = !unfound.is_empty() && all_answered && sources_gone && filling;
        if settled {
            for (name, record) in &lost {
                if let Err(e) = self.record_lost(name, record).await {
                    warn!("pg {}/{}: recording {name} lost: {e}", pg.pool, pg.pg_id);
                }
            }
            error!(
                "pg {}/{}: {} objects lost: fewer than k shards anywhere, every member \
                 answering, the rest gone with a member lost for good (e.g. {})",
                pg.pool,
                pg.pg_id,
                lost.len(),
                unfound[0]
            );
        }
        if failed.is_none() && (unfound.is_empty() || settled) && filling && fillers_up {
            self.finish_filling(&pg, &plan).await;
        }
        if !unfound.is_empty() {
            warn!(
                "pg {}/{}: {} objects unfound (fewer than k shards anywhere), e.g. {}",
                pg.pool,
                pg.pg_id,
                unfound.len(),
                unfound[0]
            );
        }

        // Peer it again: its state as its members show it now.
        let Some(now) = self.placement_group(&pg.pool, pg.pg_id) else {
            return;
        };
        let mut state = self.peer(&now, &pool, false).await;
        // Nothing more to change now: left until something does. "Members
        // down" as the plan saw them: one that didn't answer then but does
        // now (back meanwhile) makes the next look differ, so it is tried
        // again; counted as the peer now sees them, it would wait forever.
        let down_at_plan =
            u32::try_from(plan.members.iter().filter(|m| m.is_none()).count()).unwrap_or(u32::MAX);
        // Got somewhere (wrote something, or it is clean): the next pass may
        // go at once. Otherwise it waits, longer each time.
        if wrote || state.state == "Clean" {
            BACKOFF.lock().remove(&id);
        } else {
            no_progress(&id, now.epoch, state.members_down);
        }
        if (!unfound.is_empty() || !wrote) && failed.is_none() && state.state != "Clean" {
            STUCK.lock().insert(
                id.clone(),
                (now.epoch, down_at_plan, state.objects_degraded),
            );
        } else {
            STUCK.lock().remove(&id);
        }
        if !unfound.is_empty() {
            unfound.truncate(UNFOUND_KEPT);
            state.unfound_keys = unfound;
        }
        let held = self.pg_state(&now.pool, now.pg_id);
        state.since = match &held {
            Some(h) if h.state == state.state => h.since,
            _ => state.computed_at,
        };
        if state.state != "Clean" {
            state.recovered = recovered;
            // After a failure, resume from the cursor next time (it stopped
            // before the first chunk that failed); the pass having finished,
            // start from the beginning.
            state.cursor = if failed.is_some() {
                cursor.clone()
            } else {
                String::new()
            };
            state.cursor_epoch = pg.epoch;
            if let Some(e) = failed {
                state.last_error = e;
            }
        }
        self.replace_pg_state(state).await;
    }

    /// Commit `pg` moved to its up set at `positions`: each takes its up
    /// member, filled from the member it replaces, in one commit that
    /// raises the epoch; the members old and new are told.
    async fn commit_remap(
        &self,
        pg: &PlacementGroup,
        positions: &[usize],
    ) -> anyhow::Result<PlacementGroup> {
        let mut new = pg.clone();
        new.epoch = pg.epoch + 1;
        for &p in positions {
            let from = std::mem::replace(&mut new.acting[p], pg.up[p].clone());
            set_filling(&mut new.filling, p as u32, from, new.epoch);
        }
        new.updated_at = Self::current_timestamp();
        self.commit_pgs(&[(pg.clone(), new.clone())], "pg-remap")
            .await?;
        REMAPS.fetch_add(1, Ordering::Relaxed);
        info!(
            "pg {}/{}: epoch {} → {}: moving to its up set at positions {positions:?}",
            new.pool, new.pg_id, pg.epoch, new.epoch
        );
        let mut notify = pg.acting.clone();
        notify.extend(new.acting.iter().cloned());
        self.push_pg_epochs(std::slice::from_ref(&new), &notify)
            .await;
        Ok(new)
    }

    /// Whether any of `members` is past `pg/backfill_full_ratio`: why, if so.
    async fn too_full(&self, members: &[Vec<u8>]) -> Option<String> {
        if members.is_empty() {
            return None;
        }
        let ratio = self.config_parsed("pg/backfill_full_ratio", BACKFILL_FULL_RATIO);
        for id in members {
            let Some(address) = self.usable_address(id) else {
                continue;
            };
            let status = async {
                let channel = crate::drain_observer::open_channel(&address).await?;
                let r = tokio::time::timeout(
                    RPC_TIMEOUT,
                    StorageServiceClient::new(channel).get_status(GetStatusRequest::default()),
                )
                .await??
                .into_inner();
                Ok::<_, anyhow::Error>(r)
            }
            .await;
            match status {
                Ok(s) if s.total_capacity > 0 => {
                    #[allow(clippy::cast_precision_loss)]
                    let used = s.used_capacity as f64 / s.total_capacity as f64;
                    if used >= ratio {
                        return Some(format!(
                            "{} is {:.0}% full (backfill stops at {:.0}%)",
                            hex::encode(id),
                            used * 100.0,
                            ratio * 100.0
                        ));
                    }
                }
                Ok(_) => {}
                Err(e) => debug!("recovery: status of {address}: {e}"),
            }
        }
        None
    }

    /// What there is to do in `pg`: every member's and stray's entries,
    /// merged into the newest of each key, and the keys some acting member
    /// lacks something of. An error when fewer acting members answer than a
    /// read needs copies (nothing is decided on a view that may be old).
    async fn recovery_plan(&self, pg: &PlacementGroup, pool: &PoolConfig) -> Result<Plan, String> {
        let copies = pg.acting.len();
        let (_, read_quorum) = needs(pool, copies);
        let addresses: Vec<Option<String>> =
            pg.acting.iter().map(|id| self.usable_address(id)).collect();
        let listings = futures::future::join_all(addresses.iter().map(|a| async move {
            match a {
                Some(a) => list_of(a, &pg.pool, pg.pg_id).await.ok(),
                None => None,
            }
        }))
        .await;
        let answered = listings.iter().flatten().count();
        if answered < read_quorum {
            return Err(format!(
                "{answered} of {copies} members answered, a read needs {read_quorum}"
            ));
        }
        // Strays: members filled from, up members acting isn't on.
        let mut stray_ids: Vec<Vec<u8>> = pg.filling.iter().map(|f| f.from.clone()).collect();
        stray_ids.extend(pg.up.iter().cloned());
        stray_ids.sort();
        stray_ids.dedup();
        stray_ids.retain(|id| !pg.acting.contains(id));
        let mut strays: Vec<(String, Listing)> = Vec::new();
        for id in stray_ids {
            if let Some(address) = self.usable_address(&id)
                && let Ok(entries) = list_of(&address, &pg.pool, pg.pg_id).await
            {
                strays.push((address, entries));
            }
        }

        // The newest entry of each key, and who holds it.
        let mut newest: HashMap<(String, String), (PgEntry, Vec<String>)> = HashMap::new();
        let all = addresses
            .iter()
            .zip(&listings)
            .filter_map(|(a, l)| Some((a.as_ref()?, l.as_ref()?)))
            .chain(strays.iter().map(|(a, l)| (a, l)));
        for (address, entries) in all {
            for (k, e) in entries {
                match newest.get_mut(k) {
                    Some((n, holders)) => {
                        if order(e) > order(n) {
                            *n = e.clone();
                            *holders = vec![address.clone()];
                        } else if order(e) == order(n) {
                            holders.push(address.clone());
                        }
                    }
                    None => {
                        newest.insert(k.clone(), (e.clone(), vec![address.clone()]));
                    }
                }
            }
        }

        let mut plan = Plan {
            members: addresses
                .iter()
                .zip(&listings)
                .map(|(a, l)| a.clone().filter(|_| l.is_some()))
                .collect(),
            ..Plan::default()
        };
        for (address, entries) in &strays {
            for (k, e) in entries {
                // A stray's copy of the key's current object (its versions'
                // copies are left: a withdrawal is of the current object).
                if !e.tombstone && e.version_id.is_empty() {
                    plan.strays.push((
                        address.clone(),
                        k.0.clone(),
                        k.1.clone(),
                        e.object_id.clone(),
                    ));
                }
            }
        }
        for ((bucket, name), (n, holders)) in newest {
            let key = name.clone();
            let mut behind = Vec::new();
            let mut complete = 0usize;
            let mut short = n.positions_short > 0;
            for (p, listing) in listings.iter().enumerate() {
                let Some(entries) = listing else {
                    continue; // didn't answer: unknown
                };
                let e = entries.get(&(bucket.clone(), key.clone()));
                if n.tombstone {
                    if e.is_some_and(|e| !e.tombstone) {
                        behind.push(p);
                    }
                    continue;
                }
                match e {
                    Some(e) if order(e) == order(&n) => {
                        if e.named_here < e.stripes || e.held_here < e.named_here {
                            short = true;
                        } else {
                            complete += 1;
                        }
                    }
                    _ => behind.push(p),
                }
            }
            if behind.is_empty() && !short {
                continue;
            }
            let needed = if n.stripes == 0 {
                1
            } else {
                n.needed.max(1) as usize
            };
            let (real_key, version_id) = split_entry_name(&name);
            plan.work.push(Work {
                bucket,
                key: real_key.to_string(),
                version_id: version_id.to_string(),
                spare: i64::try_from(complete).unwrap_or(i64::MAX)
                    - i64::try_from(needed).unwrap_or(i64::MAX),
                newest: n,
                holders,
                behind,
            });
        }
        plan.work.sort_by_cached_key(|w| (w.spare, w.cursor()));
        Ok(plan)
    }

    /// Recover `chunk`'s objects, a few at a time; their outcomes in order.
    async fn recover_chunk(
        &self,
        pg: &PlacementGroup,
        members: &[Option<String>],
        chunk: Vec<Work>,
    ) -> Vec<Outcome> {
        use futures::StreamExt;
        let permits = self
            .config_parsed("pg/rebuilds_per_osd", REBUILDS_PER_OSD)
            .max(1);
        let jobs: Vec<futures::future::BoxFuture<'_, Outcome>> = chunk
            .into_iter()
            .map(|w| -> futures::future::BoxFuture<'_, Outcome> {
                Box::pin(async move {
                    // A rebuild slot on every member it writes to.
                    let mut slots = Vec::new();
                    for (id, member) in pg.acting.iter().zip(members) {
                        if member.is_none() {
                            continue;
                        }
                        if let Ok(permit) = rebuild_slots(id, permits).acquire_owned().await {
                            slots.push(permit);
                        }
                    }
                    let outcome = self.recover_object(pg, members, &w).await;
                    drop(slots);
                    outcome
                })
            })
            .collect();
        futures::stream::iter(jobs)
            .buffered(OBJECTS_AT_ONCE)
            .collect()
            .await
    }

    /// Bring one object to `pg`'s acting set: `members` are the acting
    /// members' addresses, None for one left alone this pass.
    async fn recover_object(
        &self,
        pg: &PlacementGroup,
        members: &[Option<String>],
        w: &Work,
    ) -> Outcome {
        let pg_ref = PgRef {
            pool: pg.pool.clone(),
            pg_id: pg.pg_id,
            epoch: pg.epoch,
        };

        if w.newest.tombstone {
            // Members still holding an object a newer delete removed.
            let mut outcome = Outcome::Done;
            let mut displaced: Vec<ObjectMeta> = Vec::new();
            for &p in &w.behind {
                let Some(address) = &members[p] else {
                    outcome = Outcome::Partial;
                    continue;
                };
                let request = DeleteObjectMetaRequest {
                    bucket: w.bucket.clone(),
                    key: w.key.clone(),
                    version_id: w.version_id.clone(),
                    stamp: w.newest.stamp,
                    withdraw_object_id: Vec::new(),
                    pg: Some(pg_ref.clone()),
                };
                match delete_meta(address, request).await {
                    Ok(removed) => {
                        COPIES.fetch_add(1, Ordering::Relaxed);
                        displaced.extend(removed);
                    }
                    Err(e) => outcome = Outcome::Failed(format!("delete on {address}: {e}")),
                }
            }
            if outcome == Outcome::Done {
                self.free_displaced(&w.bucket, &[], displaced).await;
            }
            return outcome;
        }

        // The newest copy, whole, from a member that holds it.
        let mut object = None;
        for holder in &w.holders {
            match whole_copy(holder, &w.bucket, &w.key, &w.version_id).await {
                Ok(Some(o)) => {
                    let listed = (
                        w.newest.stamp,
                        w.newest.object_id.as_slice(),
                        w.newest.update_stamp,
                    );
                    let held = (o.stamp, o.object_id.as_slice(), o.update_stamp);
                    if held > listed {
                        return Outcome::Changed;
                    }
                    if held == listed {
                        object = Some(o);
                        break;
                    }
                }
                Ok(None) => {}
                Err(e) => debug!("recovery: {} from {holder}: {e}", w.name()),
            }
        }
        let Some(mut object) = object else {
            return Outcome::Failed("no member holding its newest copy answered".into());
        };

        // Each recoverable stripe: the shard at each position on the member
        // at that position.
        let mut moved = false;
        let mut left_out = false;
        let mut small: HashMap<usize, SmallShard> = HashMap::new();
        let mut written_to: HashSet<usize> = HashSet::new();
        let stripes = object.stripes.clone();
        for (si, stripe) in stripes.iter().enumerate() {
            if !recoverable(stripe) {
                continue;
            }
            let id = shard_object(&object, stripe);
            let total = (stripe.ec_k + stripe.ec_m) as usize;
            let located: HashMap<u32, ShardLocation> = stripe
                .shards
                .iter()
                .map(|l| (l.position, l.clone()))
                .collect();
            // Positions whose member already names and holds its shard.
            let mut in_place: Vec<u32> = Vec::new();
            let mut ask: HashMap<usize, Vec<u32>> = HashMap::new();
            for (p, member) in members.iter().enumerate().take(total) {
                let position = p as u32;
                let named_there = located
                    .get(&position)
                    .is_some_and(|l| l.node_id == pg.acting[p]);
                if member.is_none() {
                    // Nobody usable there (down, undersized): left.
                    left_out |= !named_there;
                    continue;
                }
                if named_there {
                    ask.entry(p).or_default().push(position);
                }
            }
            for (p, positions) in ask {
                let address = members[p].as_deref().unwrap_or_default();
                match shard_states(address, &id, stripe.stripe_id, &positions).await {
                    Ok(states) => {
                        for (position, state) in positions.iter().zip(states) {
                            if state == ShardState::Ok {
                                in_place.push(*position);
                            }
                        }
                    }
                    Err(e) => {
                        return Outcome::Failed(format!("checking shards on {address}: {e}"));
                    }
                }
            }
            let wanted: Vec<u32> = (0..total.min(pg.acting.len()))
                .filter(|&p| members[p].is_some())
                .map(|p| p as u32)
                .filter(|p| !in_place.contains(p))
                .collect();
            if wanted.is_empty() {
                continue;
            }

            // The bytes: copied from where the object says each is, or
            // rebuilt from k others.
            let mut bytes: HashMap<u32, Vec<u8>> = HashMap::new();
            for &position in &wanted {
                let Some(loc) = located.get(&position) else {
                    continue;
                };
                if loc.node_id == pg.acting[position as usize] {
                    continue; // its member lost it: rebuilt
                }
                if let Some(address) = self.node_addr(&loc.node_id)
                    && let Ok(b) =
                        read_shard(&address, &id, stripe.stripe_id, position, loc.crc32c).await
                {
                    bytes.insert(position, b);
                }
            }
            let missing: Vec<usize> = wanted
                .iter()
                .filter(|p| !bytes.contains_key(p))
                .map(|&p| p as usize)
                .collect();
            if !missing.is_empty() {
                match self
                    .rebuild_positions(stripe, &id, &located, &bytes, &missing, &in_place)
                    .await
                {
                    Ok(rebuilt) => bytes.extend(rebuilt),
                    Err(RebuildError::TooFew(good)) => {
                        return Outcome::Unfound(stripe.stripe_id, good, stripe.ec_k);
                    }
                    Err(RebuildError::Other(e)) => return Outcome::Failed(e),
                }
            }

            // Written to the member at each position.
            let mut new_locations: Vec<ShardLocation> = Vec::new();
            for &position in &wanted {
                let p = position as usize;
                let Some(data) = bytes.remove(&position) else {
                    return Outcome::Failed(format!("position {position}: no bytes"));
                };
                let crc = crc32c::crc32c(&data);
                let old = located.get(&position);
                let (disk_id, offset) = if si == 0 && stripe.shards_in_metadata {
                    // A small object's shard goes with its metadata (B21).
                    small.insert(
                        p,
                        SmallShard {
                            shard_id: Some(ShardId {
                                object_id: id.clone(),
                                stripe_id: stripe.stripe_id,
                                position,
                            }),
                            data,
                            crc32c: crc,
                        },
                    );
                    (vec![0u8; 16], 0)
                } else {
                    let address = members[p].as_deref().unwrap_or_default();
                    match write_shard(address, &id, stripe, position, data, &pg_ref).await {
                        Ok(loc) => (loc.disk_id, loc.offset),
                        Err(e) => {
                            return Outcome::Failed(format!(
                                "writing position {position} to {address}: {e}"
                            ));
                        }
                    }
                };
                SHARDS.fetch_add(1, Ordering::Relaxed);
                written_to.insert(p);
                new_locations.push(ShardLocation {
                    position,
                    node_id: pg.acting[p].clone(),
                    disk_id,
                    offset,
                    shard_type: old.map_or(0, |l| l.shard_type),
                    local_group: old.map_or(0, |l| l.local_group),
                    crc32c: Some(crc),
                });
            }
            let s = &mut object.stripes[si];
            for loc in new_locations {
                s.shards.retain(|l| l.position != loc.position);
                s.shards.push(loc);
            }
            s.shards.sort_by_key(|l| l.position);
            moved = true;
        }

        // One member counts the object in usage: an acting one.
        if !pg.acting.contains(&object.usage_owner)
            && let Some((p, _)) = members.iter().enumerate().find(|(_, a)| a.is_some())
        {
            object.usage_owner.clone_from(&pg.acting[p]);
            moved = true;
        }
        if moved {
            // Ordered after the copies it changes; its stamp stays, so a
            // newer object still wins.
            object.update_stamp = objectio_common::stamp::CLOCK.next_after(object.update_stamp);
        }

        // The metadata: to every member when it changed, else to those
        // behind; and to every member given a small shard.
        let mut to: BTreeSet<usize> = if moved {
            (0..pg.acting.len()).collect()
        } else {
            w.behind.iter().copied().collect()
        };
        to.extend(small.keys().copied());
        to.extend(written_to.iter().copied());
        let mut outcome = if left_out || w.behind.iter().any(|&p| members[p].is_none()) {
            Outcome::Partial
        } else {
            Outcome::Done
        };
        let mut displaced: Vec<ObjectMeta> = Vec::new();
        for p in to {
            let Some(address) = &members[p] else {
                continue;
            };
            let request = PutObjectMetaRequest {
                bucket: w.bucket.clone(),
                key: w.key.clone(),
                object: Some(object.clone()),
                versioning_enabled: false,
                // Applied unless the copy holds a newer write, or a newer
                // delete: the write order decides, so a copy that missed
                // the object gets it and one that moved on keeps its own.
                expected_object_id: Vec::new(),
                require_existing: false,
                // A version: its own entry alone, current or not (the
                // key's own entry recovers the current object).
                version_only: !w.version_id.is_empty(),
                keep_newer_current: false,
                replication_update: false,
                replication_set: HashMap::new(),
                shard: small.remove(&p),
                pg: Some(pg_ref.clone()),
            };
            match put_meta(address, request).await {
                Ok(replaced) => {
                    COPIES.fetch_add(1, Ordering::Relaxed);
                    displaced.extend(replaced);
                }
                Err(e) => outcome = Outcome::Failed(format!("metadata to {address}: {e}")),
            }
        }
        if outcome == Outcome::Done {
            self.free_displaced(&w.bucket, &object.object_id, displaced)
                .await;
        }
        outcome
    }

    /// Free the shards of objects recovery's writes displaced from stale
    /// copies (an overwrite or a delete they missed), as the gateway's heal
    /// would have: every acting member now holds the newest, so those were
    /// the last copies naming them. Through meta's shared-stripe registry,
    /// so a stripe another object (a copy, a pack) still uses stays. Not in
    /// a bucket that has had versioning (an object replaced on one copy
    /// may be a version kept on the others), and not `current` itself (a
    /// location update displaces the same object).
    async fn free_displaced(&self, bucket: &str, current: &[u8], displaced: Vec<ObjectMeta>) {
        use objectio_proto::metadata::{ReleaseStripesRequest, VersioningState};
        let unversioned = self
            .buckets
            .read()
            .get(bucket)
            .is_some_and(|b| b.versioning == VersioningState::VersioningDisabled as i32);
        if !unversioned {
            return;
        }
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for object in displaced {
            if object.object_id.is_empty()
                || object.object_id == current
                || !seen.insert(object.object_id.clone())
            {
                continue;
            }
            let stripe_ids: Vec<Vec<u8>> = object
                .stripes
                .iter()
                .filter_map(|s| {
                    if !s.pack_id.is_empty() {
                        Some(s.pack_id.clone())
                    } else if !s.object_id.is_empty() {
                        Some(s.object_id.clone())
                    } else {
                        None
                    }
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            if stripe_ids.is_empty() {
                continue; // inline: nothing on disk
            }
            let released = MetadataService::release_stripes(
                self,
                tonic::Request::new(ReleaseStripesRequest {
                    stripe_ids,
                    referrer: object.object_id.clone(),
                }),
            )
            .await;
            let released = match released {
                Ok(r) => r.into_inner(),
                Err(e) => {
                    debug!(
                        "recovery: releasing {}: {e}",
                        hex::encode(&object.object_id)
                    );
                    continue;
                }
            };
            let free: HashSet<Vec<u8>> = released.freeable.into_iter().collect();
            let stripes = object
                .stripes
                .iter()
                .filter(|s| s.pack_id.is_empty() && free.contains(&s.object_id))
                .chain(&released.freed_packs);
            for stripe in stripes {
                for loc in &stripe.shards {
                    let Some(address) = self.node_addr(&loc.node_id) else {
                        continue;
                    };
                    let shard = ShardId {
                        object_id: stripe.object_id.clone(),
                        stripe_id: stripe.stripe_id,
                        position: loc.position,
                    };
                    if let Err(e) = delete_shard(&address, shard).await {
                        debug!("recovery: freeing a displaced shard on {address}: {e}");
                    }
                }
            }
        }
    }

    /// Rebuild `missing` positions of `stripe` from k good shards: those
    /// already in hand (`have`), then the rest read where the object says
    /// they are, the positions its members hold in place first.
    async fn rebuild_positions(
        &self,
        stripe: &StripeMeta,
        id: &[u8],
        located: &HashMap<u32, ShardLocation>,
        have: &HashMap<u32, Vec<u8>>,
        missing: &[usize],
        in_place: &[u32],
    ) -> Result<HashMap<u32, Vec<u8>>, RebuildError> {
        match ErasureType::try_from(stripe.ec_type).unwrap_or(ErasureType::ErasureMds) {
            ErasureType::ErasureReplication => {
                self.copy_replica(stripe, id, located, have, missing, in_place)
                    .await
            }
            ErasureType::ErasureLrc => {
                self.rebuild_lrc(stripe, id, located, have, missing, in_place)
                    .await
            }
            ErasureType::ErasureMds => {
                self.rebuild_mds(stripe, id, located, have, missing, in_place)
                    .await
            }
        }
    }

    /// A replicated stripe's missing copies: one intact copy (its checksum
    /// the one recorded), read from a member holding it in place first,
    /// given to every position that lacks it.
    async fn copy_replica(
        &self,
        stripe: &StripeMeta,
        id: &[u8],
        located: &HashMap<u32, ShardLocation>,
        have: &HashMap<u32, Vec<u8>>,
        missing: &[usize],
        in_place: &[u32],
    ) -> Result<HashMap<u32, Vec<u8>>, RebuildError> {
        let mut copy = have
            .iter()
            .find(|(p, _)| !missing.contains(&(**p as usize)))
            .map(|(_, b)| b.clone());
        if copy.is_none() {
            let mut candidates: Vec<u32> = in_place.to_vec();
            candidates.extend(located.keys().copied().filter(|p| !in_place.contains(p)));
            candidates.retain(|p| !missing.contains(&(*p as usize)));
            for position in candidates {
                let Some(loc) = located.get(&position) else {
                    continue;
                };
                let Some(address) = self.node_addr(&loc.node_id) else {
                    continue;
                };
                if let Ok(b) =
                    read_shard(&address, id, stripe.stripe_id, position, loc.crc32c).await
                {
                    copy = Some(b);
                    break;
                }
            }
        }
        let Some(copy) = copy else {
            return Err(RebuildError::TooFew(0));
        };
        let crc = crc32c::crc32c(&copy);
        let mut out = HashMap::new();
        for &p in missing {
            if let Some(recorded) = located.get(&(p as u32)).and_then(|l| l.crc32c)
                && recorded != crc
            {
                return Err(RebuildError::Other(format!(
                    "position {p}: its copy is not the one its object records"
                )));
            }
            REPLICAS.fetch_add(1, Ordering::Relaxed);
            out.insert(p as u32, copy.clone());
        }
        Ok(out)
    }

    /// An LRC stripe's missing positions. Each one whose local group (its
    /// other data and local parity) is whole and readable is rebuilt from
    /// those alone, reads that stay in the group's failure domain; the
    /// rest from the whole stripe: its data decoded from what is left, then
    /// encoded again for any parity among them.
    async fn rebuild_lrc(
        &self,
        stripe: &StripeMeta,
        id: &[u8],
        located: &HashMap<u32, ShardLocation>,
        have: &HashMap<u32, Vec<u8>>,
        missing: &[usize],
        in_place: &[u32],
    ) -> Result<HashMap<u32, Vec<u8>>, RebuildError> {
        use objectio_erasure::backend::{
            ErasureBackend, LrcBackend, LrcConfig, RustSimdLrcBackend,
        };
        let (k, l, g) = (
            stripe.ec_k as usize,
            stripe.ec_local_parity as usize,
            stripe.ec_global_parity as usize,
        );
        let total = k + l + g;
        let backend = RustSimdLrcBackend::new(LrcConfig::new(k as u8, l as u8, g as u8))
            .map_err(|e| RebuildError::Other(format!("codec: {e}")))?;
        let mut shards: Vec<Option<Vec<u8>>> = vec![None; total];
        for (p, b) in have {
            let p = *p as usize;
            if p < total && !missing.contains(&p) {
                shards[p] = Some(b.clone());
            }
        }
        let mut out: HashMap<u32, Vec<u8>> = HashMap::new();
        let mut global: Vec<usize> = Vec::new();

        // From its local group, each that can be.
        for &p in missing {
            let local = lrc_local_set(stripe, p).filter(|set| {
                set.iter().all(|q| {
                    !missing.contains(q)
                        && (shards[*q].is_some() || located.contains_key(&(*q as u32)))
                })
            });
            let Some(set) = local else {
                global.push(p);
                continue;
            };
            let mut whole = true;
            let mut from: Vec<String> = Vec::new();
            for &q in &set {
                if shards[q].is_some() {
                    continue;
                }
                let loc = &located[&(q as u32)];
                let Some(address) = self.node_addr(&loc.node_id) else {
                    whole = false;
                    break;
                };
                match read_shard(&address, id, stripe.stripe_id, q as u32, loc.crc32c).await {
                    Ok(b) => {
                        shards[q] = Some(b);
                        from.push(hex::encode(&loc.node_id));
                    }
                    Err(_) => {
                        whole = false;
                        break;
                    }
                }
            }
            if !whole {
                global.push(p);
                continue;
            }
            let size = set
                .iter()
                .find_map(|q| shards[*q].as_ref().map(Vec::len))
                .unwrap_or(0);
            let refs: Vec<Option<&[u8]>> = shards.iter().map(|s| s.as_deref()).collect();
            match backend.decode_local(&refs, size, p) {
                Ok(Some(b)) => {
                    LRC_LOCAL.fetch_add(1, Ordering::Relaxed);
                    LRC_LOCAL_READS.fetch_add(set.len() as u64, Ordering::Relaxed);
                    debug!(
                        "recovery: LRC {} stripe {} position {p} rebuilt from its local group \
                         {set:?} (read from {from:?})",
                        hex::encode(id),
                        stripe.stripe_id
                    );
                    out.insert(p as u32, b);
                }
                _ => global.push(p),
            }
        }

        if !global.is_empty() {
            // Everything else that is there, read.
            let mut reads = 0u64;
            let mut candidates: Vec<u32> = in_place.to_vec();
            candidates.extend(located.keys().copied().filter(|p| !in_place.contains(p)));
            for position in candidates {
                let q = position as usize;
                if q >= total || missing.contains(&q) || shards[q].is_some() {
                    continue;
                }
                let loc = &located[&position];
                let Some(address) = self.node_addr(&loc.node_id) else {
                    continue;
                };
                if let Ok(b) =
                    read_shard(&address, id, stripe.stripe_id, position, loc.crc32c).await
                {
                    shards[q] = Some(b);
                    reads += 1;
                }
            }
            let present = shards.iter().filter(|s| s.is_some()).count();
            if present < k {
                return Err(RebuildError::TooFew(
                    u32::try_from(present).unwrap_or(u32::MAX),
                ));
            }
            let size = shards
                .iter()
                .find_map(|s| s.as_ref().map(Vec::len))
                .ok_or(RebuildError::TooFew(0))?;
            // The data, whole: each data shard lost decoded, one at a time
            // (the backend's decode returns the ones it rebuilt locally
            // ahead of the global ones, so a batch would lose their order).
            let lost_data: Vec<usize> = (0..k).filter(|q| shards[*q].is_none()).collect();
            let mut decoded: Vec<(usize, Vec<u8>)> = Vec::new();
            {
                let refs: Vec<Option<&[u8]>> = shards.iter().map(|s| s.as_deref()).collect();
                for &q in &lost_data {
                    let b = backend
                        .decode(&refs, size, &[q])
                        .map_err(|e| RebuildError::Other(format!("decode: {e}")))?
                        .into_iter()
                        .next()
                        .ok_or_else(|| {
                            RebuildError::Other(format!("decode gave nothing for {q}"))
                        })?;
                    decoded.push((q, b));
                }
            }
            for (q, b) in decoded {
                shards[q] = Some(b);
            }
            let data: Vec<&[u8]> = shards[..k]
                .iter()
                .map(|s| s.as_deref().unwrap_or_default())
                .collect();
            let encoded = backend
                .encode(&data, size)
                .map_err(|e| RebuildError::Other(format!("encode: {e}")))?;
            for &p in &global {
                let b = encoded
                    .get(p)
                    .cloned()
                    .ok_or_else(|| RebuildError::Other(format!("no shard {p} in the stripe")))?;
                out.insert(p as u32, b);
            }
            LRC_GLOBAL.fetch_add(global.len() as u64, Ordering::Relaxed);
            LRC_GLOBAL_READS.fetch_add(reads, Ordering::Relaxed);
            debug!(
                "recovery: LRC {} stripe {} positions {global:?} rebuilt from the whole stripe \
                 ({reads} read)",
                hex::encode(id),
                stripe.stripe_id
            );
        }
        // Each the shard as first written.
        for (p, bytes) in &out {
            if let Some(recorded) = located.get(p).and_then(|l| l.crc32c)
                && crc32c::crc32c(bytes) != recorded
            {
                return Err(RebuildError::Other(format!(
                    "position {p} rebuilt differs from the shard its object records"
                )));
            }
        }
        Ok(out)
    }

    /// An MDS stripe's missing positions, from k good shards.
    async fn rebuild_mds(
        &self,
        stripe: &StripeMeta,
        id: &[u8],
        located: &HashMap<u32, ShardLocation>,
        have: &HashMap<u32, Vec<u8>>,
        missing: &[usize],
        in_place: &[u32],
    ) -> Result<HashMap<u32, Vec<u8>>, RebuildError> {
        let (k, m) = (stripe.ec_k as usize, stripe.ec_m as usize);
        let mut survivors: Vec<Option<Vec<u8>>> = vec![None; k + m];
        let mut count = 0;
        for (p, b) in have {
            if let Some(slot) = survivors.get_mut(*p as usize)
                && !missing.contains(&(*p as usize))
            {
                *slot = Some(b.clone());
                count += 1;
            }
        }
        let mut candidates: Vec<u32> = in_place.to_vec();
        candidates.extend(located.keys().copied().filter(|p| !in_place.contains(p)));
        candidates.retain(|p| !missing.contains(&(*p as usize)) && !have.contains_key(p));
        for position in candidates {
            if count >= k {
                break;
            }
            let Some(loc) = located.get(&position) else {
                continue;
            };
            let Some(address) = self.node_addr(&loc.node_id) else {
                continue;
            };
            if let Ok(b) = read_shard(&address, id, stripe.stripe_id, position, loc.crc32c).await {
                survivors[position as usize] = Some(b);
                count += 1;
            }
        }
        if count < k {
            return Err(RebuildError::TooFew(
                u32::try_from(count).unwrap_or(u32::MAX),
            ));
        }
        let codec = objectio_erasure::ErasureCodec::new(objectio_common::ErasureConfig::new(
            stripe.ec_k as u8,
            stripe.ec_m as u8,
        ))
        .map_err(|e| RebuildError::Other(format!("codec: {e}")))?;
        let rebuilt = codec
            .reconstruct_shards(&survivors, missing)
            .map_err(|e| RebuildError::Other(format!("decode: {e}")))?;
        let mut out = HashMap::new();
        for (&p, bytes) in missing.iter().zip(rebuilt) {
            // A rebuild is the shard as first written: one that isn't
            // (decoded from a bad source) is not stored as if it were.
            if let Some(recorded) = located.get(&(p as u32)).and_then(|l| l.crc32c)
                && crc32c::crc32c(&bytes) != recorded
            {
                return Err(RebuildError::Other(format!(
                    "position {p} rebuilt differs from the shard its object records"
                )));
            }
            out.insert(p as u32, bytes);
        }
        Ok(out)
    }

    /// A filled PG: its fills recorded done (`filling` emptied), and the
    /// copies the members it was filled from hold of objects every acting
    /// member now has withdrawn.
    async fn finish_filling(&self, pg: &PlacementGroup, plan: &Plan) {
        let Some(current) = self.placement_group(&pg.pool, pg.pg_id) else {
            return;
        };
        if current.epoch != pg.epoch || current.filling != pg.filling {
            return;
        }
        let filled = PlacementGroup {
            filling: Vec::new(),
            updated_at: Self::current_timestamp(),
            ..current.clone()
        };
        if let Err(e) = self.commit_pgs(&[(current, filled)], "pg-filled").await {
            debug!("pg {}/{}: fill not recorded: {e}", pg.pool, pg.pg_id);
            return;
        }
        info!("pg {}/{}: filled", pg.pool, pg.pg_id);
        // Strays' copies: every object of the PG is on every acting member
        // now (the pass finished with none failed), so the strays' are
        // extra. Withdrawn only where they hold the very object the PG
        // has, or an older one.
        for (address, bucket, key, object_id) in &plan.strays {
            let request = DeleteObjectMetaRequest {
                bucket: bucket.clone(),
                key: key.clone(),
                version_id: String::new(),
                stamp: 0,
                withdraw_object_id: object_id.clone(),
                pg: None,
            };
            if let Err(e) = delete_meta(address, request).await {
                debug!(
                    "pg {}/{}: stray {bucket}/{key} on {address}: {e}",
                    pg.pool, pg.pg_id
                );
            }
        }
    }

    /// Update `pg`'s state with `change`, as recovery sees it (the state
    /// peering last recorded, recovery's fields changed), and record it.
    async fn note_recovery(&self, pg: &PlacementGroup, change: impl FnOnce(&mut PgState)) {
        let mut state = self
            .pg_state(&pg.pool, pg.pg_id)
            .unwrap_or_else(|| PgState {
                pool: pg.pool.clone(),
                pg_id: pg.pg_id,
                ..PgState::default()
            });
        let before = state.state.clone();
        state.epoch = pg.epoch;
        change(&mut state);
        let now = Self::current_timestamp();
        state.computed_at = now;
        if state.state != before {
            state.since = now;
        }
        self.replace_pg_state(state).await;
    }

    /// Record `state` as `pool/pg`'s, as it is (unlike peering's, which
    /// keeps recovery's progress from what is there).
    async fn replace_pg_state(&self, state: PgState) {
        use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
        let key = MetaStore::pg_key(&state.pool, state.pg_id);
        let held = self
            .store
            .as_ref()
            .and_then(|s| s.read_named(super::peering::PG_STATE_TABLE, &key));
        super::peering::set_latest(state.clone());
        if let Some(raft) = self.raft_handle() {
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Named(super::peering::PG_STATE_TABLE.into()),
                    key,
                    expected: held,
                    new_value: Some(state.encode_to_vec()),
                }],
                requested_by: "pg-recovery".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    other => debug!("pg state not recorded: {other:?}"),
                },
                Err(e) => debug!("pg state not recorded: {e}"),
            }
        } else if let Some(store) = &self.store {
            store.write_named(
                super::peering::PG_STATE_TABLE,
                &key,
                Some(&state.encode_to_vec()),
            );
        }
    }

    /// Forget `bucket/key`'s degraded record (B29), if it has one: its
    /// object is whole.
    async fn forget_degraded_key(&self, bucket: &str, key: &str) {
        let name = format!("{bucket}/{key}");
        if let Some(bytes) = self.store.as_ref().and_then(|s| s.read_degraded(&name))
            && let Err(e) = self.forget_degraded(&name, bytes).await
        {
            debug!("recovery: degraded record of {name}: {e}");
        }
    }

    /// The address of OSD `id`, if registered with one.
    fn node_addr(&self, id: &[u8]) -> Option<String> {
        <[u8; 16]>::try_from(id)
            .ok()
            .and_then(|id| self.osd_address_by_id(&id))
            .filter(|a| !a.is_empty())
    }
}

/// Why a rebuild didn't happen.
enum RebuildError {
    /// Fewer than k good shards could be read: how many were.
    TooFew(u32),
    Other(String),
}

impl Work {
    /// Its place in the PG's order: the key, then each of its versions.
    fn cursor(&self) -> String {
        if self.version_id.is_empty() {
            format!("{}\0{}", self.bucket, self.key)
        } else {
            format!("{}\0{}\0{}", self.bucket, self.key, self.version_id)
        }
    }

    /// `bucket/key`, and `?versionId=` for a version's.
    fn name(&self) -> String {
        if self.version_id.is_empty() {
            format!("{}/{}", self.bucket, self.key)
        } else {
            format!("{}/{}?versionId={}", self.bucket, self.key, self.version_id)
        }
    }
}

/// `bucket/key`'s current ObjectMeta (or version `version_id`'s) on the OSD
/// at `address`, as stored (an inline object's bytes included).
async fn whole_copy(
    address: &str,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> anyhow::Result<Option<ObjectMeta>> {
    let channel = crate::drain_observer::open_channel(address).await?;
    let r = tokio::time::timeout(
        RPC_TIMEOUT,
        StorageServiceClient::new(channel)
            .max_decoding_message_size(100 * 1024 * 1024)
            .get_object_meta(GetObjectMetaRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
                with_small_shard: false,
            }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))??
    .into_inner();
    Ok(r.object.filter(|_| r.found))
}

/// Whether the OSD at `address` holds each of `positions` of a stripe.
async fn shard_states(
    address: &str,
    object_id: &[u8],
    stripe_id: u64,
    positions: &[u32],
) -> anyhow::Result<Vec<ShardState>> {
    let channel = crate::drain_observer::open_channel(address).await?;
    let shards = positions
        .iter()
        .map(|&position| ShardId {
            object_id: object_id.to_vec(),
            stripe_id,
            position,
        })
        .collect();
    let states = tokio::time::timeout(
        RPC_TIMEOUT,
        StorageServiceClient::new(channel).check_shards(CheckShardsRequest { shards }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))??
    .into_inner()
    .states;
    if states.len() != positions.len() {
        return Err(anyhow::anyhow!(
            "asked about {} shards, told about {}",
            positions.len(),
            states.len()
        ));
    }
    Ok(states
        .into_iter()
        .map(|s| ShardState::try_from(s).unwrap_or(ShardState::Missing))
        .collect())
}

/// A shard, checked against what its object records (B23).
async fn read_shard(
    address: &str,
    object_id: &[u8],
    stripe_id: u64,
    position: u32,
    expected_crc32c: Option<u32>,
) -> anyhow::Result<Vec<u8>> {
    let channel = crate::drain_observer::open_channel(address).await?;
    let resp = tokio::time::timeout(
        RPC_TIMEOUT,
        StorageServiceClient::new(channel)
            .max_decoding_message_size(100 * 1024 * 1024)
            .read_shard(ReadShardRequest {
                shard_id: Some(ShardId {
                    object_id: object_id.to_vec(),
                    stripe_id,
                    position,
                }),
                expected_crc32c,
                ..Default::default()
            }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))??
    .into_inner();
    let bytes = crate::drain_observer::verified_shard(resp)?.to_vec();
    if let Some(expected) = expected_crc32c
        && crc32c::crc32c(&bytes) != expected
    {
        return Err(anyhow::anyhow!(
            "position {position}: not the shard its object records"
        ));
    }
    Ok(bytes)
}

/// Write a shard to the member at its position.
async fn write_shard(
    address: &str,
    object_id: &[u8],
    stripe: &StripeMeta,
    position: u32,
    bytes: Vec<u8>,
    pg: &PgRef,
) -> anyhow::Result<objectio_proto::storage::BlockLocation> {
    let channel = crate::drain_observer::open_channel(address).await?;
    let checksum = Some(crate::drain_observer::checksum_of(&bytes));
    tokio::time::timeout(
        RPC_TIMEOUT,
        StorageServiceClient::new(channel)
            .max_encoding_message_size(100 * 1024 * 1024)
            .write_shard(WriteShardRequest {
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
                // Restores redundancy: may use the space kept from client
                // writes.
                use_reserve: true,
                pg: Some(pg.clone()),
            }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))??
    .into_inner()
    .location
    .ok_or_else(|| anyhow::anyhow!("no location returned"))
}

/// Delete one shard (a displaced object's, nothing referring to it).
async fn delete_shard(address: &str, shard: ShardId) -> anyhow::Result<()> {
    let channel = crate::drain_observer::open_channel(address).await?;
    tokio::time::timeout(
        RPC_TIMEOUT,
        StorageServiceClient::new(channel).delete_shard(
            objectio_proto::storage::DeleteShardRequest {
                shard_id: Some(shard),
            },
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))??;
    Ok(())
}

/// Write a metadata copy; the object it displaced on that copy, if any
/// (and not kept there as a version).
async fn put_meta(
    address: &str,
    request: PutObjectMetaRequest,
) -> anyhow::Result<Option<ObjectMeta>> {
    let channel = crate::drain_observer::open_channel(address).await?;
    let r = tokio::time::timeout(
        RPC_TIMEOUT,
        StorageServiceClient::new(channel)
            .max_encoding_message_size(100 * 1024 * 1024)
            .max_decoding_message_size(100 * 1024 * 1024)
            .put_object_meta(request),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))??
    .into_inner();
    Ok(r.replaced.filter(|_| !r.replaced_version_kept))
}

/// Apply a delete (or a withdrawal) to a copy; the object it removed there.
async fn delete_meta(
    address: &str,
    request: DeleteObjectMetaRequest,
) -> anyhow::Result<Option<ObjectMeta>> {
    let channel = crate::drain_observer::open_channel(address).await?;
    let r = tokio::time::timeout(
        RPC_TIMEOUT,
        StorageServiceClient::new(channel)
            .max_decoding_message_size(100 * 1024 * 1024)
            .delete_object_meta(request),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))??
    .into_inner();
    Ok(r.removed)
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    #[test]
    fn passes_that_get_nowhere_wait_longer_each_time_up_to_five_minutes() {
        assert_eq!(backoff_after(0), Duration::from_secs(2));
        assert_eq!(backoff_after(1), Duration::from_secs(4));
        assert_eq!(backoff_after(5), Duration::from_secs(64));
        assert_eq!(backoff_after(8), Duration::from_secs(300));
        assert_eq!(backoff_after(60), Duration::from_secs(300));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(n: &[u8]) -> BTreeSet<Vec<u8>> {
        n.iter().map(|&i| vec![i; 16]).collect()
    }

    #[test]
    fn a_reservation_is_all_or_nothing_and_released_when_dropped() {
        let a = reserve(&ids(&[201, 202]), 1).expect("free");
        // 202 is taken: nothing is reserved, 203 included.
        assert!(reserve(&ids(&[202, 203]), 1).is_none());
        assert!(SLOTS.lock().get(&vec![203u8; 16]).is_none());
        let b = reserve(&ids(&[203]), 1).expect("203 is free");
        drop(a);
        let c = reserve(&ids(&[202]), 1).expect("released with its reservation");
        assert!(reserve(&ids(&[201]), 2).is_some(), "under a higher limit");
        drop((b, c));
        assert!(SLOTS.lock().get(&vec![202u8; 16]).is_none());
    }

    #[test]
    fn progress_is_kept_for_the_same_epoch_only() {
        let held = PgState {
            epoch: 4,
            cursor: "b\0k9".into(),
            cursor_epoch: 4,
            recovered: 30,
            unfound_keys: vec!["b/k1".into()],
            retry_at: 99,
            ..PgState::default()
        };
        let mut same = PgState {
            epoch: 4,
            objects_unfound: 1,
            ..PgState::default()
        };
        keep_progress(&mut same, &held);
        assert_eq!(
            (same.cursor.as_str(), same.recovered, same.retry_at),
            ("b\0k9", 30, 99)
        );
        assert_eq!(same.unfound_keys, vec!["b/k1".to_string()]);
        let mut next = PgState {
            epoch: 5,
            ..PgState::default()
        };
        keep_progress(&mut next, &held);
        assert!(next.cursor.is_empty(), "another epoch starts again");
        assert!(next.unfound_keys.is_empty(), "none unfound now");
        assert_eq!(next.recovered, 30, "the count goes on until clean");
    }

    #[test]
    fn every_scheme_with_redundancy_is_recovered_a_packs_slice_is_not() {
        let mds = StripeMeta {
            ec_k: 4,
            ec_m: 2,
            ..StripeMeta::default()
        };
        assert!(recoverable(&mds));
        assert!(recoverable(&StripeMeta {
            ec_type: ErasureType::ErasureReplication as i32,
            ec_k: 1,
            ec_m: 2,
            ..mds.clone()
        }));
        assert!(recoverable(&StripeMeta {
            ec_type: ErasureType::ErasureLrc as i32,
            ec_k: 4,
            ec_m: 3,
            ec_local_parity: 2,
            ec_global_parity: 1,
            ..mds.clone()
        }));
        assert!(!recoverable(&StripeMeta {
            pack_id: vec![1],
            ..mds.clone()
        }));
        // One copy: nothing to rebuild it from.
        assert!(!recoverable(&StripeMeta {
            ec_type: ErasureType::ErasureReplication as i32,
            ec_k: 1,
            ec_m: 0,
            ..mds.clone()
        }));
        assert!(!recoverable(&StripeMeta { ec_m: 0, ..mds }));
    }

    #[test]
    fn an_lrc_shard_is_rebuilt_from_its_own_group_a_global_parity_from_none() {
        // LRC 4+2+1: groups {0,1} with local parity 4, {2,3} with 5; 6 global.
        let lrc = StripeMeta {
            ec_type: ErasureType::ErasureLrc as i32,
            ec_k: 4,
            ec_m: 3,
            ec_local_parity: 2,
            ec_global_parity: 1,
            local_group_size: 2,
            ..StripeMeta::default()
        };
        assert_eq!(lrc_local_set(&lrc, 0), Some(vec![1, 4]));
        assert_eq!(lrc_local_set(&lrc, 3), Some(vec![2, 5]));
        assert_eq!(lrc_local_set(&lrc, 4), Some(vec![0, 1]));
        assert_eq!(lrc_local_set(&lrc, 5), Some(vec![2, 3]));
        assert_eq!(lrc_local_set(&lrc, 6), None);
        let mds = StripeMeta {
            ec_k: 4,
            ec_m: 2,
            ..StripeMeta::default()
        };
        assert_eq!(lrc_local_set(&mds, 0), None);
    }

    /// The codec does what the rebuild relies on: a shard from its group
    /// alone, and the stripe's parities encoded again from its data.
    #[test]
    fn local_and_global_lrc_rebuilds_give_back_the_shards_written() {
        use objectio_erasure::backend::{
            ErasureBackend, LrcBackend, LrcConfig, RustSimdLrcBackend,
        };
        let backend = RustSimdLrcBackend::new(LrcConfig::new(4, 2, 1)).unwrap();
        let size = 64;
        let data: Vec<Vec<u8>> = (0..4u8)
            .map(|i| (0..size).map(|b| (b as u8).wrapping_mul(7) ^ i).collect())
            .collect();
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let all = backend.encode(&refs, size).unwrap();
        assert_eq!(all.len(), 7);

        // Position 1 from 0 and 4 only.
        let mut shards: Vec<Option<&[u8]>> = vec![None; 7];
        shards[0] = Some(&all[0]);
        shards[4] = Some(&all[4]);
        assert_eq!(
            backend.decode_local(&shards, size, 1).unwrap().as_deref(),
            Some(all[1].as_slice())
        );

        // A data shard and its group's local parity lost: no local rebuild,
        // so the data is decoded with the global parity, and the stripe
        // encoded again gives the local parity back too.
        let mut shards: Vec<Option<&[u8]>> = all.iter().map(|s| Some(s.as_slice())).collect();
        shards[0] = None;
        shards[4] = None;
        assert_eq!(backend.decode_local(&shards, size, 0).unwrap(), None);
        let d0 = backend.decode(&shards, size, &[0]).unwrap().remove(0);
        assert_eq!(d0, all[0]);
        let again = backend
            .encode(&[d0.as_slice(), &all[1], &all[2], &all[3]], size)
            .unwrap();
        assert_eq!(again, all);

        // Both of a group's data lost is past this code: 2 data and the 1
        // global parity are short of the 4 a decode needs.
        let mut shards: Vec<Option<&[u8]>> = all.iter().map(|s| Some(s.as_slice())).collect();
        shards[0] = None;
        shards[1] = None;
        assert!(backend.decode(&shards, size, &[0]).is_err());
    }
}
