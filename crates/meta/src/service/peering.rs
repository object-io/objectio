//! Peering (B31 phase 2, objectio-docs `core/pg-recovery.md`): what each
//! placement group's members hold of it, compared, and the PG's state
//! recorded. Observed only: nothing is rebuilt from it yet (phase 3).
//!
//! For a PG, the leader asks every acting member for its summary
//! (GetPgInfo). Members that answer with the same digest and counts, and
//! whose every object's shard positions are named on them, agree: the PG is
//! `Clean` without listing anything. Otherwise it lists every member's
//! entries (ListPg), and the stand-ins' predecessors' and the up set's when
//! they still answer (strays), merges them into the authoritative view (for
//! each key the newest write, a delete included), and counts what each
//! acting member lacks: a metadata copy, an up-to-date one, or the shards
//! it should hold at its position.
//!
//! States, most severe first: `Down` (fewer members answered than a read
//! needs shards), `Incomplete` (fewer than a read quorum of metadata copies
//! answered: a newer write may be on those that didn't), `Undersized` (a
//! position has no usable member), `Degraded` (something is missing), and
//! `Clean`. The result is kept in the Raft table `pg_state` when it
//! changes, with when the PG entered its state, and with recovery's
//! progress through the PG (phase 3a, `recovery.rs`), which acts on it. A
//! PG recovery is working is not peered meanwhile: recovery peers it when
//! it is done.

use super::*;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use objectio_proto::metadata::{PgMemberState, PgState};
use objectio_proto::storage::{
    GetPgInfoRequest, ListPgRequest, PgEntry, PgSummary,
    storage_service_client::StorageServiceClient,
};

use super::pgs::pg_placement;

/// The Raft table peering's results are kept in.
pub(crate) const PG_STATE_TABLE: &str = "pg_state";

/// How often the leader looks for placement groups to peer.
const TICK: Duration = Duration::from_secs(5);

/// Every placement group is peered at least this often (config
/// `pg/peer_every_seconds`).
const PEER_EVERY_SECS: u64 = 60;

/// Placement groups peered in one look (config `pg/peer_per_look`), and at
/// once.
const PER_LOOK: usize = 64;
const AT_ONCE: usize = 8;

/// One RPC to an OSD.
const RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Entries per ListPg page.
const PAGE: u32 = 1000;

/// Placement groups to peer at the next look: a degraded write or read
/// reported for one of their keys.
static DIRTY: LazyLock<parking_lot::Mutex<HashSet<(String, u32)>>> =
    LazyLock::new(Default::default);

/// When each placement group was last peered, on this leader.
static LAST: LazyLock<parking_lot::Mutex<HashMap<(String, u32), Instant>>> =
    LazyLock::new(Default::default);

/// Each placement group's last result, on this leader: for the metrics.
static LATEST: LazyLock<parking_lot::Mutex<HashMap<(String, u32), PgState>>> =
    LazyLock::new(Default::default);

/// Make `state` the leader's latest of its PG (recovery's own writes).
pub(crate) fn set_latest(state: PgState) {
    LATEST
        .lock()
        .insert((state.pool.clone(), state.pg_id), state);
}

/// Placement groups peered, and those that needed a listing.
static PEERED: AtomicU64 = AtomicU64::new(0);
static LISTED: AtomicU64 = AtomicU64::new(0);
static LISTINGS_ADDED: AtomicU64 = AtomicU64::new(0);
/// In-service OSDs (In) not up, as the leader last counted.
static OSDS_DOWN: AtomicU64 = AtomicU64::new(0);
static LISTINGS_REMOVED: AtomicU64 = AtomicU64::new(0);

/// How long after its write a key's listing entry may still lag its copies
/// (a PUT commits its listing entry and its copies side by side): a
/// listing peering leaves the key's entry alone until then
/// (`pg/listing_grace_seconds`).
const LISTING_GRACE_SECS: u64 = 60;

/// The states, most severe first: peering's, then recovery's.
pub(crate) const STATES: [&str; 8] = [
    "Down",
    "Incomplete",
    "Undersized",
    "Degraded",
    "Clean",
    "Recovering",
    "Backfilling",
    "WaitTooFull",
];

/// Peering metrics as Prometheus families (the leader's view).
pub fn render_metrics(out: &mut String) {
    use std::fmt::Write as _;
    let latest = LATEST.lock();
    let _ = writeln!(
        out,
        "# HELP objectio_meta_pgs Placement groups by the state peering last found \
         (the leader's)\n# TYPE objectio_meta_pgs gauge"
    );
    for state in STATES {
        let n = latest.values().filter(|s| s.state == state).count();
        let _ = writeln!(out, "objectio_meta_pgs{{state=\"{state}\"}} {n}");
    }
    let now = MetaService::current_timestamp();
    let not_clean: Vec<&PgState> = latest.values().filter(|s| s.state != "Clean").collect();
    for (name, help, v) in [
        (
            "objectio_meta_pgs_not_clean",
            "Placement groups in any state but Clean",
            not_clean.len() as u64,
        ),
        (
            "objectio_meta_pg_not_clean_oldest_seconds",
            "How long the placement group longest out of Clean has been: alert when it passes \
             an hour while objectio_meta_osds_down is 0",
            not_clean
                .iter()
                .map(|s| now.saturating_sub(s.since))
                .max()
                .unwrap_or(0),
        ),
        (
            "objectio_meta_osds_down",
            "OSDs in service (In) that aren't up",
            OSDS_DOWN.load(Ordering::Relaxed),
        ),
        (
            "objectio_meta_pg_objects_degraded",
            "Objects some acting member of their placement group lacks something of",
            latest.values().map(|s| s.objects_degraded).sum::<u64>(),
        ),
        (
            "objectio_meta_pg_objects_unfound",
            "Objects with fewer complete copies than a read needs among the members that answered",
            latest.values().map(|s| s.objects_unfound).sum::<u64>(),
        ),
        (
            "objectio_meta_pg_copies_missing",
            "Metadata copies acting members lack",
            latest.values().map(|s| s.copies_missing).sum::<u64>(),
        ),
        (
            "objectio_meta_pg_shards_missing",
            "Shards acting members should hold at their position and don't",
            latest.values().map(|s| s.shards_missing).sum::<u64>(),
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
    }
    for (name, help, v) in [
        (
            "objectio_meta_pg_peered_total",
            "Placement groups peered",
            PEERED.load(Ordering::Relaxed),
        ),
        (
            "objectio_meta_pg_listed_total",
            "Placement groups whose members disagreed by summary, so were listed",
            LISTED.load(Ordering::Relaxed),
        ),
        (
            "objectio_meta_pg_listings_added_total",
            "Listing entries a listing peering put back: their copies hold the object",
            LISTINGS_ADDED.load(Ordering::Relaxed),
        ),
        (
            "objectio_meta_pg_listings_removed_total",
            "Listing entries a listing peering removed: their copies hold the key deleted",
            LISTINGS_REMOVED.load(Ordering::Relaxed),
        ),
    ] {
        let _ = writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}"
        );
    }
}

/// The order of a key's writes: a delete wins a tie with an object of its
/// stamp (a write never lands under a newer or equal delete).
pub(crate) fn order(e: &PgEntry) -> (u64, bool, &[u8], u64) {
    (e.stamp, e.tombstone, e.object_id.as_slice(), e.update_stamp)
}

/// The authoritative view: for each key (and version), the newest entry
/// any of `acting` or `strays` holds, a delete winning a tie.
pub(crate) fn newest_entries(
    acting: &[Option<&HashMap<(String, String), PgEntry>>],
    strays: &[&HashMap<(String, String), PgEntry>],
) -> HashMap<(String, String), PgEntry> {
    let mut newest: HashMap<(String, String), PgEntry> = HashMap::new();
    for entries in acting.iter().flatten().chain(strays.iter()) {
        for (k, e) in entries.iter() {
            match newest.get(k) {
                Some(n) if order(n) >= order(e) => {}
                _ => {
                    newest.insert(k.clone(), e.clone());
                }
            }
        }
    }
    newest
}

/// What a listing peering does about a key's listing entry, given the
/// authoritative entry and the entry meta's listing index holds (its object
/// id and when it was made, in ms), at `now_ms`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ListingFix {
    /// It agrees, or it is too soon to tell.
    Leave,
    /// List the current object (unless it turns out a delete marker).
    Add,
    /// Remove the entry: the key's newest write is a delete.
    Remove,
}

pub(crate) fn listing_fix(
    auth: &PgEntry,
    listed: Option<(&[u8], u64)>,
    now_ms: u64,
    grace_ms: u64,
) -> ListingFix {
    let written_ms = auth.stamp >> 16;
    if now_ms.saturating_sub(written_ms) < grace_ms {
        return ListingFix::Leave;
    }
    if let Some((_, listed_ms)) = listed
        && now_ms.saturating_sub(listed_ms) < grace_ms
    {
        // Listed lately: a write whose copies may still be landing.
        return ListingFix::Leave;
    }
    match (auth.tombstone, listed) {
        (true, Some(_)) => ListingFix::Remove,
        (true, None) => ListingFix::Leave,
        (false, Some((id, _))) if id == auth.object_id.as_slice() => ListingFix::Leave,
        (false, _) => ListingFix::Add,
    }
}

/// Why a PG is Down, Incomplete or Undersized, for the admin API and
/// `obioctl pg`: what an operator has to bring back. Empty otherwise.
fn stuck_reason(
    state: &PgState,
    members: &[Member],
    copies: usize,
    k: usize,
    quorum: usize,
) -> String {
    let answered = copies.saturating_sub(state.members_down as usize);
    match state.state.as_str() {
        "Down" => format!(
            "{answered} of {copies} members answered and a read needs {k}: no reads or writes \
             until members come back"
        ),
        "Incomplete" => format!(
            "{answered} of {copies} members answered and a read needs {quorum} metadata copies: \
             a newer write may be on those that didn't, so nothing is rebuilt until they answer \
             or are declared lost"
        ),
        "Undersized" => {
            let empty: Vec<String> = members
                .iter()
                .filter(|m| m.address.is_none())
                .map(|m| m.position.to_string())
                .collect();
            format!(
                "position{} {} {} no usable OSD and none can stand in within the pool's rule: \
                 add OSDs or bring the member back",
                if empty.len() == 1 { "" } else { "s" },
                empty.join(", "),
                if empty.len() == 1 { "has" } else { "have" }
            )
        }
        _ => String::new(),
    }
}

/// A member's entries, by bucket and entry name.
type Entries = HashMap<(String, String), PgEntry>;

/// A member, as peering sees it.
struct Member {
    id: Vec<u8>,
    position: u32,
    address: Option<String>,
}

/// What a member answered.
#[derive(Default)]
struct Answer {
    summary: Option<PgSummary>,
    entries: HashMap<(String, String), PgEntry>,
    error: Option<String>,
}

/// How many shards a read of the pool's objects needs (its k; 1 for
/// replicas), and how many metadata copies a read must hear from.
pub(crate) fn needs(pool: &PoolConfig, copies: usize) -> (usize, usize) {
    let k = match pool.ec_type() {
        ErasureType::ErasureMds | ErasureType::ErasureLrc => pool.ec_k.max(1) as usize,
        ErasureType::ErasureReplication => 1,
    };
    let write_quorum = copies / 2 + 1;
    (k, copies - write_quorum + 1)
}

/// What the authoritative view and the members' entries say: the counts of
/// a [`PgState`], and per acting member what it lacks.
#[derive(Default, Debug, PartialEq, Eq)]
pub(crate) struct Merged {
    pub objects: u64,
    pub tombstones: u64,
    pub objects_degraded: u64,
    pub objects_unfound: u64,
    pub copies_missing: u64,
    pub copies_stale: u64,
    pub shards_missing: u64,
    /// Per acting member (by position): missing, stale, shards missing.
    pub members: Vec<(u64, u64, u64)>,
    /// The fewest complete copies beyond what a read needs, over every
    /// object (None: no objects).
    pub min_spare: Option<i64>,
}

/// Merge what members answered. `acting[i]` is the entries of the member
/// at position `i`, None if it didn't answer; `strays` add to the
/// authoritative view only.
pub(crate) fn merge(
    acting: &[Option<&HashMap<(String, String), PgEntry>>],
    strays: &[&HashMap<(String, String), PgEntry>],
) -> Merged {
    let mut newest: HashMap<&(String, String), &PgEntry> = HashMap::new();
    for entries in acting.iter().flatten().chain(strays.iter()) {
        for (k, e) in entries.iter() {
            match newest.get(k) {
                Some(n) if order(n) >= order(e) => {}
                _ => {
                    newest.insert(k, e);
                }
            }
        }
    }
    let mut m = Merged {
        members: vec![(0, 0, 0); acting.len()],
        ..Merged::default()
    };
    for (k, auth) in &newest {
        let mut degraded = false;
        if auth.tombstone {
            m.tombstones += 1;
            for (i, member) in acting.iter().enumerate() {
                // A member still holding an object the key's delete removed.
                if let Some(e) = member.and_then(|entries| entries.get(*k))
                    && !e.tombstone
                {
                    m.copies_stale += 1;
                    m.members[i].1 += 1;
                    degraded = true;
                }
            }
        } else {
            m.objects += 1;
            let mut complete = 0usize;
            let mut unknown = 0usize;
            for (i, member) in acting.iter().enumerate() {
                let Some(entries) = member else {
                    unknown += 1;
                    continue; // didn't answer: unknown
                };
                match entries.get(*k) {
                    None => {
                        m.copies_missing += 1;
                        m.members[i].0 += 1;
                        degraded = true;
                    }
                    Some(e) if order(e) < order(auth) => {
                        m.copies_stale += 1;
                        m.members[i].1 += 1;
                        degraded = true;
                    }
                    Some(e) => {
                        let lacking = u64::from(e.stripes.saturating_sub(e.held_here));
                        if lacking > 0 {
                            m.shards_missing += lacking;
                            m.members[i].2 += lacking;
                            degraded = true;
                        } else {
                            complete += 1;
                        }
                    }
                }
            }
            if auth.positions_short > 0 {
                m.shards_missing += u64::from(auth.positions_short);
                degraded = true;
            }
            let needed = if auth.stripes == 0 {
                1
            } else {
                auth.needed.max(1) as usize
            };
            // Unfound: too few complete copies even if every member that
            // didn't answer holds one. A member slow to answer (soak run 20:
            // a busy OSD timing out) doesn't make a PG's objects unfound;
            // its spare (below) counts it out, so recovery still ranks
            // the PG as short.
            if complete + unknown < needed {
                m.objects_unfound += 1;
            }
            let spare = i64::try_from(complete).unwrap_or(i64::MAX)
                - i64::try_from(needed).unwrap_or(i64::MAX);
            m.min_spare = Some(m.min_spare.map_or(spare, |s| s.min(spare)));
        }
        if degraded {
            m.objects_degraded += 1;
        }
    }
    m
}

impl MetaService {
    /// Mark `bucket/key`'s placement group for peering at the next look: a
    /// write or read found it short.
    pub(crate) fn mark_key_dirty(&self, bucket: &str, key: &str) {
        let (pg, pool) = self.listing_pg(bucket, key);
        if !pool.is_empty() {
            DIRTY.lock().insert((pool, pg));
        }
    }

    /// Mark `pool/pg_id` for peering, by listing, at the next look.
    pub(crate) fn mark_pg_dirty(&self, pool: &str, pg_id: u32) {
        DIRTY.lock().insert((pool.to_string(), pg_id));
    }

    /// Mark every placement group OSD `node` is an acting member of for
    /// peering at the next look: it came back without shards it held (a
    /// replaced or wiped disk), which only a listing shows.
    pub(crate) fn mark_osd_dirty(&self, node: &[u8]) {
        let ids: Vec<(String, u32)> = self
            .placement_groups
            .read()
            .values()
            .filter(|pg| pg.acting.iter().any(|m| m.as_slice() == node))
            .map(|pg| (pg.pool.clone(), pg.pg_id))
            .collect();
        DIRTY.lock().extend(ids);
    }

    /// What peering last found of `pool/pg_id`: on the leader, its latest
    /// result (the table keeps a result only when it changes, so its
    /// `computed_at` is when it last changed); elsewhere, the table's.
    pub(crate) fn pg_state(&self, pool: &str, pg_id: u32) -> Option<PgState> {
        if let Some(s) = LATEST.lock().get(&(pool.to_string(), pg_id)) {
            return Some(s.clone());
        }
        self.store
            .as_ref()
            .and_then(|s| s.read_named(PG_STATE_TABLE, &MetaStore::pg_key(pool, pg_id)))
            .and_then(|b| PgState::decode(b.as_slice()).ok())
    }

    /// What peering last found of every PG of `pool` (as [`Self::pg_state`]).
    pub(crate) fn pg_states(&self, pool: &str) -> HashMap<u32, PgState> {
        let prefix = format!("{pool}\0");
        let mut states: HashMap<u32, PgState> = self
            .store
            .as_ref()
            .map(|s| s.list_named(PG_STATE_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .filter_map(|(_, v)| PgState::decode(v.as_slice()).ok())
            .map(|s| (s.pg_id, s))
            .collect();
        for ((p, id), s) in LATEST.lock().iter() {
            if p == pool {
                states.insert(*id, s.clone());
            }
        }
        states
    }

    /// One look (leader, level 7): peer the placement groups that need it
    /// (a degraded report, an epoch peering hasn't seen, or not peered for
    /// [`PEER_EVERY_SECS`]: longest first), at most [`PER_LOOK`],
    /// [`AT_ONCE`] at a time.
    pub(crate) async fn peer_round(&self) {
        use futures::StreamExt;
        if !self.is_raft_leader() || !pg_placement() {
            return;
        }
        let every =
            Duration::from_secs(self.config_parsed("pg/peer_every_seconds", PEER_EVERY_SECS));
        let per_look = self.config_parsed("pg/peer_per_look", PER_LOOK).max(1);
        let pools: HashMap<String, PoolConfig> = self
            .pools_snapshot()
            .into_iter()
            .filter(|p| p.pg_count > 0)
            .map(|p| (p.name.clone(), p))
            .collect();
        let in_service: HashSet<[u8; 16]> = self
            .osd_nodes
            .read()
            .iter()
            .filter(|n| n.admin_state == objectio_common::OsdAdminState::In)
            .map(|n| n.node_id)
            .collect();
        let down = self
            .topology
            .read()
            .all_nodes()
            .filter(|n| {
                in_service.contains(n.id.as_bytes())
                    && n.status != objectio_common::NodeStatus::Active
            })
            .count();
        OSDS_DOWN.store(down as u64, Ordering::Relaxed);
        let dirty: HashSet<(String, u32)> = std::mem::take(&mut *DIRTY.lock());
        let last = LAST.lock().clone();
        let mut due: Vec<(u8, Option<Instant>, PlacementGroup)> = Vec::new();
        for pool in pools.keys() {
            let states = self.pg_states(pool);
            for pg in self.placement_groups_for_pool(pool) {
                let id = (pg.pool.clone(), pg.pg_id);
                // Recovery is working it, and peers it when done; marked
                // meanwhile, it is peered (listed) after.
                if super::recovery::is_busy(&id) {
                    if dirty.contains(&id) {
                        DIRTY.lock().insert(id);
                    }
                    continue;
                }
                let peered = last.get(&id).copied();
                let rank = if dirty.contains(&id) {
                    0
                } else if states.get(&pg.pg_id).is_none_or(|s| s.epoch != pg.epoch) {
                    1
                } else if peered.is_none_or(|t| t.elapsed() >= every) {
                    2
                } else {
                    continue;
                };
                due.push((rank, peered, pg));
            }
        }
        // Most urgent first; among the rest, the longest unpeered.
        due.sort_by_key(|(rank, peered, pg)| (*rank, *peered, pg.pool.clone(), pg.pg_id));
        // What isn't peered this look stays due.
        for (rank, _, pg) in due.iter().skip(per_look) {
            if *rank == 0 {
                DIRTY.lock().insert((pg.pool.clone(), pg.pg_id));
            }
        }
        let due: Vec<(bool, PlacementGroup)> = due
            .into_iter()
            .take(per_look)
            .map(|(rank, _, pg)| (rank == 0, pg))
            .collect();
        futures::stream::iter(due)
            .map(|(marked, pg)| {
                let pools = &pools;
                async move {
                    let Some(pool) = pools.get(&pg.pool) else {
                        return;
                    };
                    // Marked by a report of something missing: listed, as
                    // a summary can't see a shard lost under its metadata.
                    let state = self.peer(&pg, pool, marked).await;
                    LAST.lock()
                        .insert((pg.pool.clone(), pg.pg_id), Instant::now());
                    PEERED.fetch_add(1, Ordering::Relaxed);
                    self.record_pg_state(state).await;
                }
            })
            .buffer_unordered(AT_ONCE)
            .collect::<Vec<()>>()
            .await;
    }

    /// Peer one placement group: its state as its members show it now.
    /// With `list`, every member is listed even if their summaries agree:
    /// a summary counts the shards an object names on a member, not those
    /// it holds, so a shard lost or rotted under intact metadata (a wiped
    /// disk, rot the scrubber found) shows only in a listing.
    pub(crate) async fn peer(&self, pg: &PlacementGroup, pool: &PoolConfig, list: bool) -> PgState {
        let members: Vec<Member> = pg
            .acting
            .iter()
            .enumerate()
            .map(|(i, id)| Member {
                id: id.clone(),
                position: u32::try_from(i).unwrap_or(u32::MAX),
                address: self.usable_address(id),
            })
            .collect();
        let copies = members.len();
        let (k, read_quorum) = needs(pool, copies);
        let undersized = members.iter().any(|m| m.address.is_none());
        let remapped = !pg.up.is_empty() && pg.up != pg.acting;

        // GetInfo.
        let infos = futures::future::join_all(members.iter().map(|m| async move {
            match &m.address {
                Some(a) => info_of(a, &pg.pool, pg.pg_id).await,
                None => Err("no usable OSD at this position".to_string()),
            }
        }))
        .await;
        let mut answers: Vec<Answer> = infos
            .into_iter()
            .map(|r| match r {
                Ok(s) => Answer {
                    summary: Some(s),
                    ..Answer::default()
                },
                Err(e) => Answer {
                    error: Some(e),
                    ..Answer::default()
                },
            })
            .collect();
        let answered = answers.iter().filter(|a| a.summary.is_some()).count();
        let mut last_error = members
            .iter()
            .zip(&answers)
            .find_map(|(m, a)| {
                a.error
                    .as_ref()
                    .map(|e| format!("position {} ({}): {e}", m.position, hex::encode(&m.id)))
            })
            .unwrap_or_default();

        let now = Self::current_timestamp();
        let mut state = PgState {
            pool: pg.pool.clone(),
            pg_id: pg.pg_id,
            epoch: pg.epoch,
            members_down: u32::try_from(copies - answered).unwrap_or(u32::MAX),
            remapped,
            computed_at: now,
            ..PgState::default()
        };

        let agree = !list
            && answered == copies
            && pg.filling.is_empty()
            && answers.windows(2).all(|w| {
                let (a, b) = (w[0].summary.as_ref(), w[1].summary.as_ref());
                a.zip(b).is_some_and(|(a, b)| {
                    a.digest == b.digest && a.objects == b.objects && a.tombstones == b.tombstones
                })
            })
            && answers.iter().all(|a| {
                a.summary
                    .as_ref()
                    .is_some_and(|s| s.positions_short == 0 && s.named_here == s.stripes)
            });

        if answered < k {
            state.state = "Down".into();
        } else if agree {
            let s = answers[0].summary.clone().unwrap_or_default();
            state.objects = s.objects;
            state.tombstones = s.tombstones;
            state.by_summary = true;
            state.members = members
                .iter()
                .map(|m| PgMemberState {
                    node_id: m.id.clone(),
                    position: m.position,
                    answered: true,
                    ..PgMemberState::default()
                })
                .collect();
            state.min_spare =
                i64::try_from(copies).unwrap_or(i64::MAX) - i64::try_from(k).unwrap_or(i64::MAX);
            state.state = if undersized { "Undersized" } else { "Clean" }.into();
        } else {
            // GetMissing: every answering member's entries, and the strays'.
            LISTED.fetch_add(1, Ordering::Relaxed);
            let listings =
                futures::future::join_all(members.iter().zip(&answers).map(|(m, a)| async move {
                    match (&m.address, &a.summary) {
                        (Some(addr), Some(_)) => Some(list_of(addr, &pg.pool, pg.pg_id).await),
                        _ => None,
                    }
                }))
                .await;
            for (a, l) in answers.iter_mut().zip(listings) {
                match l {
                    Some(Ok(entries)) => a.entries = entries,
                    Some(Err(e)) => {
                        a.summary = None;
                        a.error = Some(e);
                    }
                    None => {}
                }
            }
            let mut stray_ids: Vec<Vec<u8>> = pg.filling.iter().map(|f| f.from.clone()).collect();
            stray_ids.extend(pg.up.iter().cloned());
            stray_ids.sort();
            stray_ids.dedup();
            stray_ids.retain(|id| !pg.acting.contains(id));
            let mut strays: Vec<HashMap<(String, String), PgEntry>> = Vec::new();
            for id in stray_ids {
                if let Some(addr) = self.usable_address(&id)
                    && let Ok(entries) = list_of(&addr, &pg.pool, pg.pg_id).await
                {
                    strays.push(entries);
                }
            }
            let acting: Vec<Option<&HashMap<(String, String), PgEntry>>> = answers
                .iter()
                .map(|a| a.summary.as_ref().map(|_| &a.entries))
                .collect();
            let stray_refs: Vec<&HashMap<(String, String), PgEntry>> = strays.iter().collect();
            let merged = merge(&acting, &stray_refs);
            let answered = acting.iter().flatten().count();
            // A listing peering also brings meta's listing index in line
            // with what the members hold, once a read quorum answered: what
            // the gateways' heal queue did for keys in placement groups.
            if list && answered >= read_quorum.max(k) {
                let newest = newest_entries(&acting, &stray_refs);
                let holders: Vec<(&str, &Entries)> = members
                    .iter()
                    .zip(&answers)
                    .filter(|(_, a)| a.summary.is_some())
                    .filter_map(|(m, a)| Some((m.address.as_deref()?, &a.entries)))
                    .collect();
                self.sync_listings(&newest, &holders).await;
            }
            state.members_down = u32::try_from(copies - answered).unwrap_or(u32::MAX);
            state.objects = merged.objects;
            state.tombstones = merged.tombstones;
            state.objects_degraded = merged.objects_degraded;
            state.objects_unfound = merged.objects_unfound;
            state.copies_missing = merged.copies_missing;
            state.copies_stale = merged.copies_stale;
            state.shards_missing = merged.shards_missing;
            state.min_spare = merged.min_spare.unwrap_or_else(|| {
                i64::try_from(answered).unwrap_or(i64::MAX) - i64::try_from(k).unwrap_or(i64::MAX)
            });
            state.members = members
                .iter()
                .zip(&acting)
                .zip(&merged.members)
                .map(|((m, a), (missing, stale, shards))| PgMemberState {
                    node_id: m.id.clone(),
                    position: m.position,
                    answered: a.is_some(),
                    copies_missing: *missing,
                    copies_stale: *stale,
                    shards_missing: *shards,
                })
                .collect();
            if last_error.is_empty() {
                last_error = members
                    .iter()
                    .zip(&answers)
                    .find_map(|(m, a)| {
                        a.error.as_ref().map(|e| {
                            format!("position {} ({}): {e}", m.position, hex::encode(&m.id))
                        })
                    })
                    .unwrap_or_default();
            }
            state.state = if answered < k {
                "Down"
            } else if answered < read_quorum {
                "Incomplete"
            } else if undersized {
                "Undersized"
            } else if merged.objects_degraded > 0 || answered < copies || !pg.filling.is_empty() {
                "Degraded"
            } else {
                "Clean"
            }
            .into();
        }
        let reason = stuck_reason(&state, &members, copies, k, read_quorum);
        if !reason.is_empty() {
            last_error = if last_error.is_empty() {
                reason
            } else {
                format!("{reason} ({last_error})")
            };
        }
        state.last_error = last_error;
        state
    }

    /// Bring meta's listing entries of the current objects in `newest` in
    /// line with them: a key whose newest write is an object gets it listed
    /// (unless it is a delete marker), one whose newest write is a delete
    /// gets its entry removed. Writes newer than [`LISTING_GRACE_SECS`], and
    /// entries listed as recently, are left alone: their copies or their
    /// listing may still be landing.
    async fn sync_listings(
        &self,
        newest: &HashMap<(String, String), PgEntry>,
        holders: &[(&str, &Entries)],
    ) {
        let now_ms = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX);
        let grace_ms = self
            .config_parsed("pg/listing_grace_seconds", LISTING_GRACE_SECS)
            .saturating_mul(1000);
        for ((bucket, name), auth) in newest {
            if name.contains('\0') {
                continue; // a version's entry: the listing names current objects
            }
            let key = name.as_str();
            let listed = self
                .store
                .as_ref()
                .and_then(|s| s.read_object_listing(&format!("{bucket}\0{key}\0")))
                .and_then(|b| {
                    objectio_proto::metadata::ObjectListingEntry::decode(b.as_slice()).ok()
                });
            let fix = listing_fix(
                auth,
                listed
                    .as_ref()
                    .map(|l| (l.object_id.as_slice(), l.modified_at.saturating_mul(1000))),
                now_ms,
                grace_ms,
            );
            let remove = match fix {
                ListingFix::Leave => continue,
                ListingFix::Remove => true,
                ListingFix::Add => {
                    // The object as a holder of it has it, whole.
                    let mut object = None;
                    for (address, entries) in holders {
                        if entries
                            .get(&(bucket.clone(), name.clone()))
                            .is_some_and(|e| e.object_id == auth.object_id && !e.tombstone)
                            && let Ok(Some(o)) = current_meta(address, bucket, key).await
                            && o.object_id == auth.object_id
                        {
                            object = Some(o);
                            break;
                        }
                    }
                    let Some(o) = object else { continue };
                    if o.is_delete_marker {
                        if listed.is_none() {
                            continue;
                        }
                        true
                    } else {
                        let (pg_id, pool) = self.listing_pg(bucket, key);
                        let r = self
                            .create_object(tonic::Request::new(CreateObjectRequest {
                                bucket: bucket.clone(),
                                key: key.to_string(),
                                size: o.size,
                                content_type: o.content_type.clone(),
                                etag: o.etag.clone(),
                                user_metadata: o.user_metadata.clone(),
                                stripes: o.stripes.clone(),
                                object_id: o.object_id.clone(),
                                pg_id,
                                pool,
                                ..Default::default()
                            }))
                            .await;
                        match r {
                            Ok(_) => {
                                LISTINGS_ADDED.fetch_add(1, Ordering::Relaxed);
                                info!("pg peering: listed {bucket}/{key}, which its copies hold");
                            }
                            Err(e) => debug!("pg peering: listing {bucket}/{key}: {e}"),
                        }
                        continue;
                    }
                }
            };
            if remove {
                let r = MetadataService::delete_object(
                    self,
                    tonic::Request::new(objectio_proto::metadata::DeleteObjectRequest {
                        bucket: bucket.clone(),
                        key: key.to_string(),
                        version_id: String::new(),
                    }),
                )
                .await;
                match r {
                    Ok(_) => {
                        LISTINGS_REMOVED.fetch_add(1, Ordering::Relaxed);
                        info!("pg peering: unlisted {bucket}/{key}, which its copies hold deleted");
                    }
                    Err(e) => debug!("pg peering: unlisting {bucket}/{key}: {e}"),
                }
            }
        }
    }

    /// The address of OSD `id`, if it can be a member: registered, `In`,
    /// with an address.
    pub(crate) fn usable_address(&self, id: &[u8]) -> Option<String> {
        let id = <[u8; 16]>::try_from(id).ok()?;
        self.osd_nodes
            .read()
            .iter()
            .find(|n| n.node_id == id && n.admin_state == objectio_common::OsdAdminState::In)
            .map(|n| n.address.clone())
            .filter(|a| !a.is_empty())
    }

    /// Keep `state` in `pg_state` if it differs from what is there (other
    /// than when it was computed), with when the PG entered its state.
    /// Recovery's progress (cursor, counts, unfound keys, retry time) is
    /// kept from what is there, until the PG is clean.
    pub(crate) async fn record_pg_state(&self, mut state: PgState) {
        use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
        let key = MetaStore::pg_key(&state.pool, state.pg_id);
        let held_bytes = self
            .store
            .as_ref()
            .and_then(|s| s.read_named(PG_STATE_TABLE, &key));
        let held = held_bytes
            .as_ref()
            .and_then(|b| PgState::decode(b.as_slice()).ok());
        if let Some(h) = &held
            && state.state != "Clean"
        {
            super::recovery::keep_progress(&mut state, h);
        }
        state.since = match &held {
            Some(h) if h.state == state.state => h.since,
            _ => state.computed_at,
        };
        let id = (state.pool.clone(), state.pg_id);
        if let Some(h) = &held {
            let same = PgState {
                computed_at: 0,
                ..h.clone()
            } == PgState {
                computed_at: 0,
                ..state.clone()
            };
            if same {
                LATEST.lock().insert(id, state);
                return;
            }
        }
        if held.as_ref().is_none_or(|h| h.state != state.state) {
            info!(
                "pg {}/{}: {} (epoch {}, {} objects, {} degraded, {} unfound{})",
                state.pool,
                state.pg_id,
                state.state,
                state.epoch,
                state.objects,
                state.objects_degraded,
                state.objects_unfound,
                if state.last_error.is_empty() {
                    String::new()
                } else {
                    format!("; {}", state.last_error)
                }
            );
        }
        let Some(raft) = self.raft_handle() else {
            if let Some(store) = &self.store {
                store.write_named(PG_STATE_TABLE, &key, Some(&state.encode_to_vec()));
            }
            LATEST.lock().insert(id, state);
            return;
        };
        let cmd = MetaCommand::MultiCas {
            ops: vec![CasOp {
                table: CasTable::Named(PG_STATE_TABLE.into()),
                key,
                expected: held_bytes,
                new_value: Some(state.encode_to_vec()),
            }],
            requested_by: "pg-peering".into(),
        };
        match raft.client_write(cmd).await {
            Ok(r) => match r.data {
                MetaResponse::MultiCasOk => {}
                other => debug!("pg state not recorded: {other:?}"),
            },
            Err(e) => debug!("pg state not recorded: {e}"),
        }
        LATEST.lock().insert(id, state);
    }
}

/// OSD `address`'s summary of `pool/pg_id`.
pub(crate) async fn info_of(address: &str, pool: &str, pg_id: u32) -> Result<PgSummary, String> {
    let channel = crate::drain_observer::open_channel(address)
        .await
        .map_err(|e| e.to_string())?;
    let r = tokio::time::timeout(
        RPC_TIMEOUT,
        StorageServiceClient::new(channel).get_pg_info(GetPgInfoRequest {
            pool: pool.to_string(),
            pg_id,
        }),
    )
    .await
    .map_err(|_| "timed out".to_string())?
    .map_err(|e| e.message().to_string())?;
    Ok(r.into_inner().summary.unwrap_or_default())
}

/// What a listing keys an entry by, beside its bucket: its key, then for a
/// version's entry `\0{version_id}` (keys can't hold a NUL), so each version
/// is merged and recovered as an entry of its own.
pub(crate) fn entry_name(e: &PgEntry) -> String {
    if e.version_id.is_empty() {
        e.key.clone()
    } else {
        format!("{}\0{}", e.key, e.version_id)
    }
}

/// The key and version id an [`entry_name`] stands for.
pub(crate) fn split_entry_name(name: &str) -> (&str, &str) {
    name.split_once('\0').unwrap_or((name, ""))
}

/// The current object OSD `address` holds of `bucket/key`, if any.
async fn current_meta(
    address: &str,
    bucket: &str,
    key: &str,
) -> Result<Option<ObjectMeta>, String> {
    let channel = crate::drain_observer::open_channel(address)
        .await
        .map_err(|e| e.to_string())?;
    let r = tokio::time::timeout(
        RPC_TIMEOUT,
        StorageServiceClient::new(channel)
            .max_decoding_message_size(100 * 1024 * 1024)
            .get_object_meta(objectio_proto::storage::GetObjectMetaRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: String::new(),
                with_small_shard: false,
            }),
    )
    .await
    .map_err(|_| "timed out".to_string())?
    .map_err(|e| e.message().to_string())?
    .into_inner();
    Ok(r.object.filter(|_| r.found))
}

/// Every entry OSD `address` holds of `pool/pg_id`.
pub(crate) async fn list_of(
    address: &str,
    pool: &str,
    pg_id: u32,
) -> Result<HashMap<(String, String), PgEntry>, String> {
    let channel = crate::drain_observer::open_channel(address)
        .await
        .map_err(|e| e.to_string())?;
    let mut client = StorageServiceClient::new(channel).max_decoding_message_size(64 * 1024 * 1024);
    let mut out = HashMap::new();
    let mut after = String::new();
    loop {
        let r = tokio::time::timeout(
            RPC_TIMEOUT,
            client.list_pg(ListPgRequest {
                pool: pool.to_string(),
                pg_id,
                after: after.clone(),
                limit: PAGE,
            }),
        )
        .await
        .map_err(|_| "timed out".to_string())?
        .map_err(|e| e.message().to_string())?
        .into_inner();
        for e in r.entries {
            out.insert((e.bucket.clone(), entry_name(&e)), e);
        }
        if r.next.is_empty() {
            return Ok(out);
        }
        after = r.next;
    }
}

/// Run peering on the leader (B31 phase 2).
pub fn spawn(meta: Arc<MetaService>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TICK).await;
            if meta.is_raft_leader() {
                meta.peer_round().await;
            } else {
                LAST.lock().clear();
                LATEST.lock().clear();
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(key: &str, stamp: u64, stripes: u32, held: u32) -> ((String, String), PgEntry) {
        (
            ("b".to_string(), key.to_string()),
            PgEntry {
                bucket: "b".into(),
                key: key.into(),
                stamp,
                object_id: vec![stamp as u8; 16],
                stripes,
                named_here: stripes,
                held_here: held,
                needed: 2,
                ..PgEntry::default()
            },
        )
    }

    fn tomb(key: &str, stamp: u64) -> ((String, String), PgEntry) {
        (
            ("b".to_string(), key.to_string()),
            PgEntry {
                bucket: "b".into(),
                key: key.into(),
                tombstone: true,
                stamp,
                ..PgEntry::default()
            },
        )
    }

    #[test]
    fn a_listing_entry_follows_the_newest_write_once_it_has_settled() {
        let now = 10_000_000u64;
        let at = |ms: u64| ms << 16;
        let grace = 60_000;
        let object = |stamp_ms: u64, id: &[u8]| PgEntry {
            stamp: at(stamp_ms),
            object_id: id.to_vec(),
            ..PgEntry::default()
        };
        let delete = |stamp_ms: u64| PgEntry {
            stamp: at(stamp_ms),
            tombstone: true,
            ..PgEntry::default()
        };
        let old = now - 120_000;
        // Listed as it should be, or not listed and deleted: left.
        assert_eq!(
            listing_fix(&object(old, b"a"), Some((b"a", old)), now, grace),
            ListingFix::Leave
        );
        assert_eq!(
            listing_fix(&delete(old), None, now, grace),
            ListingFix::Leave
        );
        // Missing, or listing another object: listed.
        assert_eq!(
            listing_fix(&object(old, b"a"), None, now, grace),
            ListingFix::Add
        );
        assert_eq!(
            listing_fix(&object(old, b"a"), Some((b"b", old)), now, grace),
            ListingFix::Add
        );
        // Deleted, still listed: unlisted.
        assert_eq!(
            listing_fix(&delete(old), Some((b"a", old)), now, grace),
            ListingFix::Remove
        );
        // A write or a listing entry within the grace: may still be landing.
        assert_eq!(
            listing_fix(&object(now - 1000, b"a"), None, now, grace),
            ListingFix::Leave
        );
        assert_eq!(
            listing_fix(&delete(old), Some((b"a", now - 1000)), now, grace),
            ListingFix::Leave
        );
    }

    #[test]
    fn members_that_agree_lack_nothing() {
        let a: HashMap<_, _> = [obj("k1", 5, 1, 1), obj("k2", 6, 1, 1)].into();
        let m = merge(&[Some(&a), Some(&a), Some(&a)], &[]);
        assert_eq!(
            (m.objects, m.objects_degraded, m.objects_unfound),
            (2, 0, 0)
        );
    }

    #[test]
    fn a_member_that_missed_writes_lacks_them_and_holds_older_copies_stale() {
        let full: HashMap<_, _> =
            [obj("k1", 5, 1, 1), obj("k2", 9, 1, 1), obj("k3", 7, 1, 1)].into();
        let behind: HashMap<_, _> = [obj("k1", 5, 1, 1), obj("k2", 6, 1, 1)].into();
        let m = merge(&[Some(&full), Some(&behind), Some(&full)], &[]);
        assert_eq!(m.objects, 3);
        assert_eq!((m.copies_missing, m.copies_stale), (1, 1));
        assert_eq!(m.objects_degraded, 2);
        assert_eq!(m.members[1], (1, 1, 0));
        assert_eq!(m.members[0], (0, 0, 0));
    }

    #[test]
    fn a_delete_wins_over_an_older_object_and_a_tie() {
        let deleted: HashMap<_, _> = [tomb("k", 8)].into();
        let held: HashMap<_, _> = [obj("k", 8, 1, 1)].into();
        let m = merge(&[Some(&deleted), Some(&held)], &[]);
        assert_eq!((m.objects, m.tombstones, m.copies_stale), (0, 1, 1));
        let newer: HashMap<_, _> = [obj("k", 9, 1, 1)].into();
        let m = merge(&[Some(&deleted), Some(&newer)], &[]);
        assert_eq!((m.objects, m.tombstones), (1, 0));
        // The member that only took the delete lacks the newer object.
        assert_eq!(m.members[0].1, 1);
    }

    #[test]
    fn missing_shards_count_and_too_few_complete_copies_are_unfound() {
        let a: HashMap<_, _> = [obj("k", 5, 2, 2)].into();
        let short: HashMap<_, _> = [obj("k", 5, 2, 0)].into();
        let m = merge(&[Some(&a), Some(&short), Some(&short)], &[]);
        assert_eq!(m.shards_missing, 4);
        assert_eq!(m.objects_degraded, 1);
        assert_eq!(m.objects_unfound, 1, "one complete copy, two needed");
        // A member that didn't answer is unknown, not missing.
        let m = merge(&[Some(&a), None, Some(&a)], &[]);
        assert_eq!(
            (m.copies_missing, m.objects_degraded, m.objects_unfound),
            (0, 0, 0)
        );
        // One complete copy and one member silent: not unfound (it may hold
        // the second), though its spare counts it out.
        let m = merge(&[Some(&a), None, Some(&short)], &[]);
        assert_eq!((m.objects_degraded, m.objects_unfound), (1, 0));
        assert_eq!(m.min_spare, Some(-1));
    }

    #[test]
    fn a_stray_adds_to_the_view_but_is_not_counted() {
        let a: HashMap<_, _> = [obj("k", 5, 1, 1)].into();
        let stray: HashMap<_, _> = [obj("k", 7, 1, 1)].into();
        let m = merge(&[Some(&a), Some(&a)], &[&stray]);
        assert_eq!(m.copies_stale, 2);
        assert_eq!(m.members.len(), 2);
    }
}
