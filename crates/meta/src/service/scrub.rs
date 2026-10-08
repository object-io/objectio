//! Scrub by placement group (B31 phase 4, objectio-docs core/pg-recovery.md).
//!
//! Each placement group is scrubbed every `scrub/every_seconds` (a week by
//! default): every acting member reads back the shards it holds of the
//! PG's objects and checks each against its checksum (`ScrubPg`), at no
//! more than `scrub/bytes_per_second` per OSD. A shard that is missing or
//! fails its checksum marks its PG to be peered by listing, and the PG's
//! recovery rebuilds it. Where each member got to is kept in Raft (table
//! `pg_scrub`), so a new leader resumes rather than starts again; a PG
//! whose epoch changes starts again. A finished scrub marks the PG too, so
//! a listing peering compares every member's entries and brings meta's
//! listing index in line with them.
//!
//! The walk (`repair.rs`) no longer looks at keys in placement groups: it
//! checks block chunks, packs, and keys written before placement groups.

use super::*;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use objectio_proto::metadata::PgScrub;
use objectio_proto::storage::{ScrubPgRequest, storage_service_client::StorageServiceClient};

use super::pgs::pg_placement;

/// Raft table of each placement group's scrub.
pub(crate) const SCRUB_TABLE: &str = "pg_scrub";

/// How often the leader takes a step: each member of each PG being
/// scrubbed reads a second's worth of its byte rate.
const TICK: Duration = Duration::from_secs(1);

/// Default time between scrubs of a PG (`scrub/every_seconds`).
const EVERY_SECS: u64 = 7 * 24 * 60 * 60;

/// Default read rate per OSD (`scrub/bytes_per_second`): 50 MiB/s.
const BYTES_PER_SECOND: u64 = 50 * 1024 * 1024;

/// Default PGs scrubbed at once (`scrub/pgs_at_once`). An OSD in several
/// shares its byte rate between them.
const PGS_AT_ONCE: usize = 8;

/// Entries a member looks at per step, whatever their size.
const ENTRIES_PER_STEP: u32 = 1000;

/// A scrub's progress is written to Raft at most this often (and when it
/// finishes): a new leader repeats at most this much.
const SAVE_EVERY: Duration = Duration::from_secs(10);

const RPC_TIMEOUT: Duration = Duration::from_secs(60);

type PgId = (String, u32);

/// The leader's scrubs under way, and when each was last written.
static RUNNING: LazyLock<parking_lot::Mutex<HashMap<PgId, (PgScrub, Instant)>>> =
    LazyLock::new(Default::default);

/// PGs whose last step got nowhere (no member answered), and OSDs that
/// didn't answer a step (left out of every PG's steps meanwhile): steps in
/// a row that did, and not before when the next. Doubling to
/// [`BACKOFF_MAX`].
type Backoffs<K> = parking_lot::Mutex<HashMap<K, (u32, Instant)>>;
static BACKOFF: LazyLock<Backoffs<PgId>> = LazyLock::new(Default::default);
static MEMBER_BACKOFF: LazyLock<Backoffs<String>> = LazyLock::new(Default::default);

/// Note one more step in a row that got nowhere under `key`.
fn back_off<K: std::hash::Hash + Eq>(map: &mut HashMap<K, (u32, Instant)>, key: K) {
    let n = map.get(&key).map_or(0, |(n, _)| *n);
    let wait = TICK.saturating_mul(1u32 << n.min(16)).min(BACKOFF_MAX);
    map.insert(key, (n + 1, Instant::now() + wait));
}

/// Whether `key` is waiting out a backoff.
fn backing_off<K: std::hash::Hash + Eq>(map: &HashMap<K, (u32, Instant)>, key: &K) -> bool {
    map.get(key)
        .is_some_and(|(_, until)| Instant::now() < *until)
}
const BACKOFF_MAX: Duration = Duration::from_secs(300);

static BYTES: AtomicU64 = AtomicU64::new(0);
static SHARDS: AtomicU64 = AtomicU64::new(0);
static BAD_MISSING: AtomicU64 = AtomicU64::new(0);
static BAD_CORRUPT: AtomicU64 = AtomicU64::new(0);
static COMPLETED: AtomicU64 = AtomicU64::new(0);
static ERRORS: AtomicU64 = AtomicU64::new(0);
/// As last counted by the leader: PGs never scrubbed, and the age of the
/// oldest scrub of the rest.
static NEVER: AtomicU64 = AtomicU64::new(0);
static OLDEST_SECS: AtomicU64 = AtomicU64::new(0);

/// Scrub metrics as Prometheus families.
pub fn render_metrics(out: &mut String) {
    use std::fmt::Write as _;
    for (name, help, v) in [
        (
            "objectio_meta_scrub_bytes_total",
            "Shard bytes read back and checked by placement-group scrubs",
            &BYTES,
        ),
        (
            "objectio_meta_scrub_shards_total",
            "Shards checked by placement-group scrubs",
            &SHARDS,
        ),
        (
            "objectio_meta_scrub_pgs_completed_total",
            "Placement-group scrubs completed",
            &COMPLETED,
        ),
        (
            "objectio_meta_scrub_errors_total",
            "Scrub steps a member couldn't take (it didn't answer); retried next step",
            &ERRORS,
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} counter");
        let _ = writeln!(out, "{name} {}", v.load(Ordering::Relaxed));
    }
    let name = "objectio_meta_scrub_shards_bad_total";
    let _ = writeln!(
        out,
        "# HELP {name} Shards a scrub found missing or failing their checksum (their PG's recovery \
         rebuilds them)\n# TYPE {name} counter"
    );
    let _ = writeln!(
        out,
        "{name}{{reason=\"missing\"}} {}",
        BAD_MISSING.load(Ordering::Relaxed)
    );
    let _ = writeln!(
        out,
        "{name}{{reason=\"corrupt\"}} {}",
        BAD_CORRUPT.load(Ordering::Relaxed)
    );
    for (name, help, v) in [
        (
            "objectio_meta_scrub_pgs_never",
            "Placement groups not yet scrubbed (as last counted by the leader)",
            &NEVER,
        ),
        (
            "objectio_meta_scrub_oldest_seconds",
            "Age of the oldest completed scrub of a placement group: alert when it passes \
             twice scrub/every_seconds",
            &OLDEST_SECS,
        ),
    ] {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge");
        let _ = writeln!(out, "{name} {}", v.load(Ordering::Relaxed));
    }
}

/// Run scrubs on the leader.
pub fn spawn(meta: Arc<MetaService>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(TICK).await;
            if meta.is_raft_leader() {
                meta.scrub_round().await;
            } else {
                RUNNING.lock().clear();
                BACKOFF.lock().clear();
                MEMBER_BACKOFF.lock().clear();
            }
        }
    });
}

/// Whether `scrub` is under way: started, and not through every member.
fn under_way(scrub: &PgScrub) -> bool {
    scrub.started_at > 0
}

/// How urgent `scrub` is, if due at all: asked for, then under way, then
/// (oldest first) due by age. A PG never scrubbed is due `every` after it
/// was made or last changed (`since`), not at once: a new cluster doesn't
/// scrub every PG the moment it starts.
fn rank(scrub: Option<&PgScrub>, now: u64, every: u64, since: u64) -> Option<(u8, u64)> {
    match scrub {
        Some(s) if s.requested => Some((0, 0)),
        Some(s) if under_way(s) => Some((1, s.started_at)),
        Some(s) if s.last_complete > 0 => {
            (now.saturating_sub(s.last_complete) >= every).then_some((2, s.last_complete))
        }
        _ => (now.saturating_sub(since) >= every).then_some((2, since)),
    }
}

impl MetaService {
    /// What `pool/pg_id`'s scrub is: the leader's, while one is under way
    /// here; otherwise the table's.
    pub(crate) fn pg_scrub(&self, pool: &str, pg_id: u32) -> Option<PgScrub> {
        if let Some((s, _)) = RUNNING.lock().get(&(pool.to_string(), pg_id)) {
            return Some(s.clone());
        }
        self.store
            .as_ref()
            .and_then(|s| s.read_named(SCRUB_TABLE, &MetaStore::pg_key(pool, pg_id)))
            .and_then(|b| PgScrub::decode(b.as_slice()).ok())
    }

    /// Every scrub record of `pool` (as [`Self::pg_scrub`]).
    pub(crate) fn pg_scrubs(&self, pool: &str) -> HashMap<u32, PgScrub> {
        let prefix = format!("{pool}\0");
        let mut scrubs: HashMap<u32, PgScrub> = self
            .store
            .as_ref()
            .map(|s| s.list_named(SCRUB_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .filter_map(|(_, v)| PgScrub::decode(v.as_slice()).ok())
            .map(|s| (s.pg_id, s))
            .collect();
        for ((p, id), (s, _)) in RUNNING.lock().iter() {
            if p == pool {
                scrubs.insert(*id, s.clone());
            }
        }
        scrubs
    }

    /// Ask for `pool/pg_id` to be scrubbed before any PG merely due.
    pub(crate) async fn request_pg_scrub(&self, pool: &str, pg_id: u32) -> Result<(), Status> {
        if !self
            .placement_groups
            .read()
            .contains_key(&(pool.to_string(), pg_id))
        {
            return Err(Status::not_found(format!(
                "no placement group {pg_id} in pool '{pool}'"
            )));
        }
        let key = MetaStore::pg_key(pool, pg_id);
        for _ in 0..5 {
            let held = self
                .store
                .as_ref()
                .and_then(|s| s.read_named(SCRUB_TABLE, &key));
            let mut scrub = held
                .as_ref()
                .and_then(|b| PgScrub::decode(b.as_slice()).ok())
                .unwrap_or_else(|| PgScrub {
                    pool: pool.to_string(),
                    pg_id,
                    ..PgScrub::default()
                });
            scrub.requested = true;
            match self
                .cas_one(
                    objectio_meta_store::CasTable::Named(SCRUB_TABLE.into()),
                    &key,
                    held,
                    Some(scrub.encode_to_vec()),
                    "pg-scrub-request",
                )
                .await
            {
                Ok(()) => {
                    if let Some((s, _)) = RUNNING.lock().get_mut(&(pool.to_string(), pg_id)) {
                        s.requested = true;
                    }
                    return Ok(());
                }
                Err(e) if e.code() == tonic::Code::Aborted => {}
                Err(e) => return Err(e),
            }
        }
        Err(Status::aborted("the scrub record kept changing; retry"))
    }

    /// One step (leader, level 7): choose the PGs to scrub now (asked for,
    /// under way, then due, no OSD in two), and have each of their members
    /// read a second's worth.
    pub(crate) async fn scrub_round(&self) {
        if !self.is_raft_leader() || !pg_placement() || !self.config_parsed("scrub/enabled", true) {
            return;
        }
        let every = self.config_parsed("scrub/every_seconds", EVERY_SECS);
        let rate = self.config_parsed("scrub/bytes_per_second", BYTES_PER_SECOND);
        let at_once = self.config_parsed("scrub/pgs_at_once", PGS_AT_ONCE).max(1);
        let now = Self::current_timestamp();

        let mut due: Vec<((u8, u64), PlacementGroup, PgScrub)> = Vec::new();
        let (mut never, mut oldest) = (0u64, 0u64);
        for pool in self.pools_snapshot().into_iter().filter(|p| p.pg_count > 0) {
            let scrubs = self.pg_scrubs(&pool.name);
            let states = self.pg_states(&pool.name);
            for pg in self.placement_groups_for_pool(&pool.name) {
                let held = scrubs.get(&pg.pg_id);
                match held {
                    Some(s) if s.last_complete > 0 => {
                        oldest = oldest.max(now.saturating_sub(s.last_complete));
                    }
                    _ => never += 1,
                }
                // Only a Clean PG is scrubbed: one that isn't is recovery's
                // first (a scrub would find what peering already has), and
                // one Down or Incomplete has members that don't answer.
                // Recovery working it, or its last step got nowhere: later.
                let id = (pg.pool.clone(), pg.pg_id);
                if states.get(&pg.pg_id).is_some_and(|s| s.state != "Clean")
                    || super::recovery::is_busy(&id)
                    || backing_off(&BACKOFF.lock(), &id)
                {
                    continue;
                }
                if let Some(r) = rank(held, now, every, pg.updated_at) {
                    let scrub = held.cloned().unwrap_or_else(|| PgScrub {
                        pool: pg.pool.clone(),
                        pg_id: pg.pg_id,
                        ..PgScrub::default()
                    });
                    due.push((r, pg, scrub));
                }
            }
        }
        NEVER.store(never, Ordering::Relaxed);
        OLDEST_SECS.store(oldest, Ordering::Relaxed);
        due.sort_by(|a, b| (a.0, &a.1.pool, a.1.pg_id).cmp(&(b.0, &b.1.pool, b.1.pg_id)));
        let chosen: Vec<(PlacementGroup, PgScrub)> = due
            .into_iter()
            .take(at_once)
            .map(|(_, pg, scrub)| (pg, scrub))
            .collect();
        // Each OSD's rate, shared between the PGs it is in this step.
        let mut shares: HashMap<Vec<u8>, u64> = HashMap::new();
        for (pg, _) in &chosen {
            for m in &pg.acting {
                *shares.entry(m.clone()).or_default() += 1;
            }
        }
        // What isn't chosen this step and isn't under way is left to the
        // table; what is under way stays in memory.
        let chosen_ids: HashSet<PgId> = chosen
            .iter()
            .map(|(pg, _)| (pg.pool.clone(), pg.pg_id))
            .collect();
        RUNNING
            .lock()
            .retain(|id, (s, _)| chosen_ids.contains(id) || under_way(s));
        let budget = rate.saturating_mul(TICK.as_secs().max(1));
        futures::future::join_all(chosen.into_iter().map(|(pg, scrub)| {
            let budgets: HashMap<String, u64> = pg
                .acting
                .iter()
                .map(|m| {
                    (
                        hex::encode(m),
                        budget / shares.get(m).copied().unwrap_or(1).max(1),
                    )
                })
                .collect();
            self.scrub_step(pg, scrub, budgets, now)
        }))
        .await;
    }

    /// One step of `pg`'s scrub: each member not through reads up to its
    /// budget's bytes from where it got to.
    async fn scrub_step(
        &self,
        pg: PlacementGroup,
        mut scrub: PgScrub,
        budgets: HashMap<String, u64>,
        now: u64,
    ) {
        let id = (pg.pool.clone(), pg.pg_id);
        if let Some((running, _)) = RUNNING.lock().get(&id) {
            scrub = running.clone();
        }
        // Started now, or again under another epoch (other members).
        if !under_way(&scrub) || scrub.epoch != pg.epoch {
            scrub.epoch = pg.epoch;
            scrub.started_at = now.max(1);
            scrub.cursors.clear();
            scrub.done.clear();
            scrub.bytes = 0;
            scrub.shards = 0;
            scrub.bad = 0;
            info!("pg {}/{}: scrub started", pg.pool, pg.pg_id);
        }
        // Members the topology knows are down are left for a later step,
        // not asked (and failed) every second.
        let up: HashSet<[u8; 16]> = self
            .topology
            .read()
            .all_nodes()
            .filter(|n| n.status == objectio_common::NodeStatus::Active)
            .map(|n| *n.id.as_bytes())
            .collect();
        let members: Vec<(String, String)> = pg
            .acting
            .iter()
            .filter(|id| <[u8; 16]>::try_from(id.as_slice()).is_ok_and(|id| up.contains(&id)))
            .map(hex::encode)
            .filter(|m| !scrub.done.contains(m))
            .filter(|m| !backing_off(&MEMBER_BACKOFF.lock(), m))
            .filter_map(|m| {
                let id = hex::decode(&m).ok()?;
                Some((m, self.usable_address(&id)?))
            })
            .collect();
        let steps = futures::future::join_all(members.iter().map(|(m, address)| {
            let after = scrub.cursors.get(m).cloned().unwrap_or_default();
            let budget = budgets.get(m).copied().unwrap_or(1).max(1);
            let (pool, pg_id) = (pg.pool.clone(), pg.pg_id);
            async move {
                let channel = crate::drain_observer::open_channel(address).await?;
                let r = tokio::time::timeout(
                    RPC_TIMEOUT,
                    StorageServiceClient::new(channel).scrub_pg(ScrubPgRequest {
                        pool,
                        pg_id,
                        after,
                        max_bytes: budget,
                        max_entries: ENTRIES_PER_STEP,
                    }),
                )
                .await??;
                Ok::<_, anyhow::Error>(r.into_inner())
            }
        }))
        .await;
        let mut marked = false;
        let mut answered = 0usize;
        for ((m, address), step) in members.iter().zip(steps) {
            let r = match step {
                Ok(r) => {
                    answered += 1;
                    MEMBER_BACKOFF.lock().remove(m);
                    r
                }
                Err(e) => {
                    ERRORS.fetch_add(1, Ordering::Relaxed);
                    back_off(&mut MEMBER_BACKOFF.lock(), m.clone());
                    debug!("scrub {}/{} on {address}: {e}", pg.pool, pg.pg_id);
                    continue;
                }
            };
            BYTES.fetch_add(r.bytes, Ordering::Relaxed);
            SHARDS.fetch_add(u64::from(r.shards), Ordering::Relaxed);
            scrub.bytes += r.bytes;
            scrub.shards += u64::from(r.shards);
            for bad in &r.bad {
                scrub.bad += 1;
                if bad.corrupt {
                    BAD_CORRUPT.fetch_add(1, Ordering::Relaxed);
                } else {
                    BAD_MISSING.fetch_add(1, Ordering::Relaxed);
                }
                warn!(
                    "scrub: {}/{}{} stripe {} position {} on {address}: {}",
                    bad.bucket,
                    bad.key,
                    if bad.version_id.is_empty() {
                        String::new()
                    } else {
                        format!(" (version {})", bad.version_id)
                    },
                    bad.stripe_id,
                    bad.position,
                    if bad.corrupt {
                        "fails its checksum"
                    } else {
                        "missing"
                    }
                );
                if !marked {
                    self.mark_key_dirty(&bad.bucket, &bad.key);
                    marked = true;
                }
            }
            if r.next.is_empty() {
                scrub.cursors.remove(m);
                scrub.done.push(m.clone());
            } else {
                scrub.cursors.insert(m.clone(), r.next);
            }
        }
        if answered == 0 {
            back_off(&mut BACKOFF.lock(), id.clone());
        } else {
            BACKOFF.lock().remove(&id);
        }
        let through = pg
            .acting
            .iter()
            .all(|m| scrub.done.contains(&hex::encode(m)));
        if through {
            info!(
                "pg {}/{}: scrubbed ({} shards, {} bytes, {} bad)",
                pg.pool, pg.pg_id, scrub.shards, scrub.bytes, scrub.bad
            );
            COMPLETED.fetch_add(1, Ordering::Relaxed);
            scrub.last_complete = now.max(1);
            scrub.started_at = 0;
            scrub.requested = false;
            scrub.cursors.clear();
            scrub.done.clear();
            // Peered by listing: every member's entries compared, and meta's
            // listing index brought in line with them.
            self.mark_pg_dirty(&pg.pool, pg.pg_id);
            self.save_scrub(&scrub).await;
            RUNNING.lock().remove(&id);
            return;
        }
        let saved = RUNNING.lock().get(&id).map(|(_, at)| *at);
        if saved.is_none_or(|at| at.elapsed() >= SAVE_EVERY) {
            self.save_scrub(&scrub).await;
            RUNNING.lock().insert(id, (scrub, Instant::now()));
        } else if let Some(at) = saved {
            RUNNING.lock().insert(id, (scrub, at));
        }
    }

    /// Write `scrub` to its table, over whatever is there (only the leader
    /// writes it, but for a request, which the next save keeps).
    async fn save_scrub(&self, scrub: &PgScrub) {
        let key = MetaStore::pg_key(&scrub.pool, scrub.pg_id);
        for _ in 0..3 {
            let held = self
                .store
                .as_ref()
                .and_then(|s| s.read_named(SCRUB_TABLE, &key));
            let mut scrub = scrub.clone();
            if held
                .as_ref()
                .and_then(|b| PgScrub::decode(b.as_slice()).ok())
                .is_some_and(|h| h.requested && scrub.started_at > 0)
            {
                // Asked for again while this one runs: kept for the next.
                scrub.requested = true;
            }
            match self
                .cas_one(
                    objectio_meta_store::CasTable::Named(SCRUB_TABLE.into()),
                    &key,
                    held,
                    Some(scrub.encode_to_vec()),
                    "pg-scrub",
                )
                .await
            {
                Ok(()) => return,
                Err(e) if e.code() == tonic::Code::Aborted => {}
                Err(e) => {
                    debug!("scrub {}/{} not recorded: {e}", scrub.pool, scrub.pg_id);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(requested: bool, started_at: u64, last_complete: u64) -> PgScrub {
        PgScrub {
            requested,
            started_at,
            last_complete,
            ..PgScrub::default()
        }
    }

    #[test]
    fn asked_for_then_under_way_then_oldest_due() {
        let now = 1_000_000;
        let every = 100;
        let made = now - 500;
        assert_eq!(rank(Some(&s(true, 0, now)), now, every, made), Some((0, 0)));
        assert_eq!(
            rank(Some(&s(false, 50, now)), now, every, made),
            Some((1, 50))
        );
        assert_eq!(
            rank(Some(&s(false, 0, now - 200)), now, every, made),
            Some((2, now - 200))
        );
        // Scrubbed lately: not due.
        assert_eq!(rank(Some(&s(false, 0, now - 10)), now, every, made), None);
        // Never scrubbed: due once it is `every` old, not before.
        assert_eq!(rank(None, now, every, made), Some((2, made)));
        assert_eq!(rank(None, now, every, now - 10), None);
    }
}
