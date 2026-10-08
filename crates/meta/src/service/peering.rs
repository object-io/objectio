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
//! changes, with when the PG entered its state.

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

/// Placement groups peered, and those that needed a listing.
static PEERED: AtomicU64 = AtomicU64::new(0);
static LISTED: AtomicU64 = AtomicU64::new(0);

/// The states, most severe first.
pub(crate) const STATES: [&str; 5] = ["Down", "Incomplete", "Undersized", "Degraded", "Clean"];

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
    for (name, help, v) in [
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
    ] {
        let _ = writeln!(
            out,
            "# HELP {name} {help}\n# TYPE {name} counter\n{name} {v}"
        );
    }
}

/// The order of a key's writes: a delete wins a tie with an object of its
/// stamp (a write never lands under a newer or equal delete).
fn order(e: &PgEntry) -> (u64, bool, &[u8], u64) {
    (e.stamp, e.tombstone, e.object_id.as_slice(), e.update_stamp)
}

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
fn needs(pool: &PoolConfig, copies: usize) -> (usize, usize) {
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
            for (i, member) in acting.iter().enumerate() {
                let Some(entries) = member else {
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
            if complete < needed {
                m.objects_unfound += 1;
            }
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
        let dirty: HashSet<(String, u32)> = std::mem::take(&mut *DIRTY.lock());
        let last = LAST.lock().clone();
        let mut due: Vec<(u8, Option<Instant>, PlacementGroup)> = Vec::new();
        for pool in pools.keys() {
            let states = self.pg_states(pool);
            for pg in self.placement_groups_for_pool(pool) {
                let id = (pg.pool.clone(), pg.pg_id);
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
        let due: Vec<PlacementGroup> = due
            .into_iter()
            .take(per_look)
            .map(|(_, _, pg)| pg)
            .collect();
        futures::stream::iter(due)
            .map(|pg| {
                let pools = &pools;
                async move {
                    let Some(pool) = pools.get(&pg.pool) else {
                        return;
                    };
                    let state = self.peer(&pg, pool).await;
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
    pub(crate) async fn peer(&self, pg: &PlacementGroup, pool: &PoolConfig) -> PgState {
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

        let agree = answered == copies
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
            state.members_down = u32::try_from(copies - answered).unwrap_or(u32::MAX);
            state.objects = merged.objects;
            state.tombstones = merged.tombstones;
            state.objects_degraded = merged.objects_degraded;
            state.objects_unfound = merged.objects_unfound;
            state.copies_missing = merged.copies_missing;
            state.copies_stale = merged.copies_stale;
            state.shards_missing = merged.shards_missing;
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
        state.last_error = last_error;
        state
    }

    /// The address of OSD `id`, if it can be a member: registered, `In`,
    /// with an address.
    fn usable_address(&self, id: &[u8]) -> Option<String> {
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
    async fn record_pg_state(&self, mut state: PgState) {
        use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
        let key = MetaStore::pg_key(&state.pool, state.pg_id);
        let held_bytes = self
            .store
            .as_ref()
            .and_then(|s| s.read_named(PG_STATE_TABLE, &key));
        let held = held_bytes
            .as_ref()
            .and_then(|b| PgState::decode(b.as_slice()).ok());
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
async fn info_of(address: &str, pool: &str, pg_id: u32) -> Result<PgSummary, String> {
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

/// Every entry OSD `address` holds of `pool/pg_id`.
async fn list_of(
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
            out.insert((e.bucket.clone(), e.key.clone()), e);
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
