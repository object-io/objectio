//! Placement groups as the unit of placement (B31, objectio-docs
//! `core/pg-recovery.md`, phase 1).
//!
//! From format level 7 every key is placed through a placement group: the
//! default pool is a pool like any other, with PGs, and a key's copies are
//! its PG's acting set. An acting set changes only by a Raft commit that
//! raises the PG's epoch, made before any write uses it: a member that
//! can't take writes is stood in for here, by the leader, never per
//! request. OSDs learn the epochs and refuse a request placed under an
//! older one, so a write lands only where the record says its copies are.
//!
//! Keys written before level 7 keep the placement they were written with
//! (per-key CRUSH): their listing entry names no pool.

use super::*;
use std::time::Duration;

use objectio_common::FailureDomain;
use objectio_common::version::{self, PG_PLACEMENT_LEVEL};
use objectio_placement::PlacementRule;
use objectio_placement::copyset::{domain_name, unit_name};
use objectio_placement::topology::NodeInfo;
use objectio_proto::storage::{
    PgRef, SetPgEpochsRequest, storage_service_client::StorageServiceClient,
};

/// The pool a bucket that names none is placed in.
pub const DEFAULT_POOL: &str = "default";

/// The fewest placement groups a pool made without a count gets. Fixed for
/// the pool's life: capacity grows by adding pools.
pub const DEFAULT_PG_COUNT: u32 = 256;

/// The most a pool made without a count gets: each PG is peered, scrubbed
/// and recovered on its own, so their number has a cost of its own.
pub const MAX_PG_COUNT: u32 = 4096;

/// PG members each OSD in service should hold when a pool is made without
/// a count (config `pg/members_per_osd`). A lost drive's PGs are rebuilt
/// onto as many drives as they have members on it, so with few PGs a drive
/// a big cluster rebuilds barely faster than a small one (B24). Ceph aims
/// at 100 PGs an OSD too.
const MEMBERS_PER_OSD: u32 = 100;

/// The PG count for a pool made without one: `per_osd` members on each of
/// `osds` OSDs, `copies` members a PG, rounded up to a power of two, from
/// [`DEFAULT_PG_COUNT`] to [`MAX_PG_COUNT`].
pub(crate) fn sized_pg_count(osds: usize, copies: usize, per_osd: u32) -> u32 {
    let members = u64::try_from(osds)
        .unwrap_or(u64::MAX)
        .saturating_mul(u64::from(per_osd));
    let pgs = members.div_ceil(u64::try_from(copies.max(1)).unwrap_or(1));
    pgs.checked_next_power_of_two()
        .and_then(|p| u32::try_from(p).ok())
        .unwrap_or(MAX_PG_COUNT)
        .clamp(DEFAULT_PG_COUNT, MAX_PG_COUNT)
}

/// How long an acting member may be down before another OSD stands in for
/// it (config `pg/down_out_seconds`). Shorter than this, a write goes to
/// the others (k + 1 of k + m suffice) and repair catches the member up
/// when it is back; an OSD restarting, or a host rebooting, moves nothing.
/// Ceph's `mon_osd_down_out_interval` is 600 s.
const DOWN_OUT_SECS: u64 = 120;

/// Placement groups changed in one Raft command.
const PG_CHUNK: usize = 64;

/// How long a push of epochs to one OSD may take.
const PUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// Whether keys are placed through placement groups (format level 7).
pub(crate) fn pg_placement() -> bool {
    version::allows(PG_PLACEMENT_LEVEL)
}

/// The failure-domain level a pool's `failure_domain` names. Empty is a
/// host.
pub(crate) fn fd_level(name: &str) -> Option<FailureDomain> {
    Some(match name {
        "host" | "" => FailureDomain::Host,
        "node" | "osd" => FailureDomain::Node,
        "rack" => FailureDomain::Rack,
        "datacenter" => FailureDomain::Datacenter,
        "zone" => FailureDomain::Zone,
        "region" => FailureDomain::Region,
        "disk" => FailureDomain::Disk,
        _ => return None,
    })
}

/// Placement groups with a member no OSD can stand in for within their
/// pool's placement rule, as the leader last counted.
static PGS_UNDERSIZED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Positions already logged as undersized: logged once, not every pass.
static UNDERSIZED_LOGGED: std::sync::LazyLock<
    parking_lot::Mutex<std::collections::HashSet<(String, u32, usize)>>,
> = std::sync::LazyLock::new(Default::default);

/// Placement-group metrics as Prometheus families.
pub fn render_metrics(out: &mut String) {
    use std::fmt::Write as _;
    let name = "objectio_meta_pgs_undersized";
    let _ = writeln!(
        out,
        "# HELP {name} Placement groups with a member no OSD can stand in for within the \
         pool's placement rule (as the leader last counted)\n# TYPE {name} gauge\n{name} {}",
        PGS_UNDERSIZED.load(std::sync::atomic::Ordering::Relaxed)
    );
}

/// The placement group `bucket/key` maps to in a pool of `pg_count`.
pub(crate) fn pg_of_key(bucket: &str, key: &str, pg_count: u32) -> u32 {
    let hash = xxhash_rust::xxh64::xxh64(format!("{bucket}/{key}").as_bytes(), 0);
    objectio_placement::jump_consistent_hash(hash, i32::try_from(pg_count).unwrap_or(i32::MAX))
        as u32
}

/// How many copies a pool's PGs have.
pub(crate) fn copy_count(pool: &PoolConfig) -> usize {
    match pool.ec_type() {
        ErasureType::ErasureMds => (pool.ec_k + pool.ec_m) as usize,
        ErasureType::ErasureLrc => {
            (pool.ec_k + pool.ec_local_parity + pool.ec_global_parity) as usize
        }
        ErasureType::ErasureReplication => pool.replication_count as usize,
    }
}

/// A pool's placement rule (B31 phase 1b): its copies over
/// `spread_domains` domains at its failure-domain level, at most
/// `per_domain` in one; an LRC pool with `lrc_groups_per_domain` keeps each
/// local group (data and local parity) in a domain of its own, its global
/// parity in others. Unset (0, 0, false): one copy per domain.
///
/// # Errors
/// What is wrong with the pool's rule fields.
pub(crate) fn placement_rule(pool: &PoolConfig) -> Result<PlacementRule, String> {
    let level = fd_level(&pool.failure_domain)
        .ok_or_else(|| format!("failure_domain '{}' not recognised", pool.failure_domain))?;
    let copies = copy_count(pool);
    let mut together: Vec<Vec<usize>> = Vec::new();
    if pool.lrc_groups_per_domain {
        if pool.ec_type() != ErasureType::ErasureLrc {
            return Err("lrc_groups_per_domain is for an LRC pool".into());
        }
        let (k, l) = (pool.ec_k as usize, pool.ec_local_parity as usize);
        if l == 0 || k % l != 0 {
            return Err(format!(
                "LRC {k} data shards don't split into {l} local groups"
            ));
        }
        // The layout `pg_position_local_group` gives: data in groups of
        // k / l, then one local parity per group, then global parity.
        let size = k / l;
        together = (0..l)
            .map(|g| {
                let mut positions: Vec<usize> = (g * size..(g + 1) * size).collect();
                positions.push(k + g);
                positions
            })
            .collect();
    }
    let per_domain = match pool.per_domain {
        // A local group needs its whole size in one domain.
        0 => together.iter().map(Vec::len).max().unwrap_or(1),
        n => n as usize,
    };
    let singles = copies - together.iter().map(Vec::len).sum::<usize>();
    let domains = match pool.spread_domains {
        0 => together.len() + singles.div_ceil(per_domain),
        n => n as usize,
    };
    let rule = PlacementRule {
        level,
        copy_count: copies,
        domains,
        per_domain,
        together,
    };
    rule.validate().map_err(|e| e.to_string())?;
    Ok(rule)
}

/// Whether losing any one domain of `rule` leaves `pool`'s objects
/// readable: for erasure coding no domain holds more than m shards; for
/// LRC with groups per domain, a whole group lost (its local parity with
/// it) is rebuilt from global parity, so a group's data is no more than
/// the global parity count; for replication a copy survives elsewhere.
pub(crate) fn tolerates_domain_loss(pool: &PoolConfig, rule: &PlacementRule) -> bool {
    let most_in_one = rule.slots().iter().map(Vec::len).max().unwrap_or(0);
    match pool.ec_type() {
        ErasureType::ErasureReplication => most_in_one < pool.replication_count as usize,
        ErasureType::ErasureLrc if !rule.together.is_empty() => {
            // A group: its data positions are all but its local parity.
            rule.together
                .iter()
                .all(|g| g.len().saturating_sub(1) <= pool.ec_global_parity as usize)
        }
        _ => most_in_one <= pool.ec_m as usize,
    }
}

impl MetaService {
    /// The pool `bucket`'s keys are placed in: its own, or (from level 7)
    /// the default pool. Empty below level 7 for a bucket that names none.
    pub(crate) fn bucket_pool_name(&self, bucket: &str) -> String {
        let named = self
            .buckets
            .read()
            .get(bucket)
            .map(|b| b.pool.clone())
            .unwrap_or_default();
        if named.is_empty() && pg_placement() {
            DEFAULT_POOL.to_string()
        } else {
            named
        }
    }

    /// Whether `bucket/key` was written before placement groups and stays
    /// where it was placed: its listing entry names no pool.
    pub(crate) fn key_is_legacy(&self, bucket: &str, key: &str) -> bool {
        self.store
            .as_ref()
            .and_then(|s| s.read_object_listing(&format!("{bucket}\0{key}\0")))
            .and_then(|b| ObjectListingEntry::decode(b.as_slice()).ok())
            .is_some_and(|e| e.pool.is_empty())
    }

    /// The placement group holding `bucket/key`'s copies, when it is
    /// placed through one with a committed acting set (level 7).
    pub(crate) fn key_pg(&self, bucket: &str, key: &str) -> Option<PlacementGroup> {
        if !pg_placement() {
            return None;
        }
        let pool_name = self.bucket_pool_name(bucket);
        let pg_count = self.pools.read().get(&pool_name).map(|p| p.pg_count)?;
        if pg_count == 0 || self.key_is_legacy(bucket, key) {
            return None;
        }
        self.placement_group(&pool_name, pg_of_key(bucket, key, pg_count))
    }

    /// The placement group and pool a listing entry for `bucket/key` names
    /// when meta itself lists the key (repair restoring an entry): the PG
    /// it is placed through from level 7, none below.
    pub(crate) fn listing_pg(&self, bucket: &str, key: &str) -> (u32, String) {
        if !pg_placement() {
            return (0, String::new());
        }
        let pool = self.bucket_pool_name(bucket);
        match self.pools.read().get(&pool).map(|p| p.pg_count) {
            Some(n) if n > 0 => (pg_of_key(bucket, key, n), pool),
            _ => (0, String::new()),
        }
    }

    /// Where `bucket/key`'s metadata copies are, other than on `except`:
    /// the addresses of its PG's acting members, and how many copies the
    /// PG has. None for a key not placed through a PG.
    pub(crate) fn key_copy_addrs(
        &self,
        bucket: &str,
        key: &str,
        except: &[u8],
    ) -> Option<(Vec<String>, usize)> {
        let pg = self.key_pg(bucket, key)?;
        let osds = self.osd_nodes.read();
        let addrs = pg
            .acting
            .iter()
            .filter(|id| id.as_slice() != except)
            .filter_map(|id| osds.iter().find(|n| n.node_id.as_slice() == id.as_slice()))
            .filter(|n| !n.address.is_empty())
            .map(|n| n.address.clone())
            .collect();
        Some((addrs, pg.acting.len()))
    }

    /// The placement groups that still hold `node`: an acting or up member,
    /// or the member a stand-in is being filled from. An OSD being emptied
    /// is done only when there are none.
    pub(crate) fn pgs_holding(&self, node: &[u8]) -> usize {
        if !pg_placement() {
            return 0; // nothing stands in for members below level 7
        }
        self.placement_groups
            .read()
            .values()
            .filter(|pg| {
                pg.acting.iter().any(|id| id.as_slice() == node)
                    || pg.up.iter().any(|id| id.as_slice() == node)
                    || pg.filling.iter().any(|f| f.from.as_slice() == node)
            })
            .count()
    }

    /// The PG count for a pool made now without one, of `copies` members
    /// a PG: sized from the OSDs in service ([`sized_pg_count`]).
    pub(crate) fn sized_pg_count(&self, copies: usize) -> u32 {
        let osds = self.topology.read().active_nodes().count();
        let per_osd = self
            .config_parsed("pg/members_per_osd", MEMBERS_PER_OSD)
            .max(1);
        sized_pg_count(osds, copies, per_osd)
    }

    /// The widest failure-domain level with at least `copies` domains in
    /// service: a host if there are enough, else each OSD. None while there
    /// are fewer OSDs than copies.
    pub(crate) fn widest_feasible_domain(&self, copies: usize) -> Option<&'static str> {
        let topology = self.topology.read();
        let hosts: std::collections::HashSet<&str> = topology
            .active_nodes()
            .map(|n| n.failure_domain.host.as_str())
            .collect();
        if hosts.len() >= copies {
            Some("host")
        } else if topology.active_nodes().count() >= copies {
            Some("node")
        } else {
            None
        }
    }

    /// The default pool's row: the cluster's default protection, spread
    /// over `failure_domain`.
    fn default_pool_config(&self, failure_domain: &str) -> PoolConfig {
        let mut pool = PoolConfig {
            name: DEFAULT_POOL.to_string(),
            failure_domain: failure_domain.to_string(),
            description: "Buckets that name no pool".to_string(),
            enabled: true,
            pg_count: DEFAULT_PG_COUNT,
            ..Default::default()
        };
        match &self.default_ec {
            EcConfig::Mds { k, m } => {
                pool.set_ec_type(ErasureType::ErasureMds);
                pool.ec_k = u32::from(*k);
                pool.ec_m = u32::from(*m);
            }
            EcConfig::Lrc { k, l, g } => {
                pool.set_ec_type(ErasureType::ErasureLrc);
                pool.ec_k = u32::from(*k);
                pool.ec_local_parity = u32::from(*l);
                pool.ec_global_parity = u32::from(*g);
                pool.ec_m = u32::from(*l) + u32::from(*g);
            }
            EcConfig::Replication { count } => {
                pool.set_ec_type(ErasureType::ErasureReplication);
                pool.replication_count = u32::from(*count);
            }
        }
        pool
    }

    /// Make the default pool and its placement groups (leader, level 7),
    /// once there are OSDs enough to spread them, and every OSD registered
    /// is up (or `ready_since` is [`SETTLE`] ago): at the widest
    /// failure-domain level with enough domains, so a one-host cluster
    /// spreads over OSDs. A pool whose PGs were left short (a commit that
    /// failed) gets the rest.
    ///
    /// Not at the first k + m OSDs: a PG's members are fixed until recovery
    /// can move its data (B31 phase 3), so an OSD that joins after the pool
    /// is made holds none of it.
    pub(crate) async fn ensure_default_pool(&self, ready_since: &mut Option<std::time::Instant>) {
        if !self.is_raft_leader() || !pg_placement() {
            return;
        }
        let existing = self.pools.read().get(DEFAULT_POOL).cloned();
        let pool = match existing {
            Some(pool) => pool,
            None => {
                let copies = copy_count(&self.default_pool_config(""));
                let Some(domain) = self.widest_feasible_domain(copies) else {
                    *ready_since = None;
                    return; // not enough OSDs yet
                };
                let since = *ready_since.get_or_insert_with(std::time::Instant::now);
                let registered = self
                    .osd_nodes
                    .read()
                    .iter()
                    .filter(|n| {
                        n.admin_state == objectio_common::OsdAdminState::In && !n.address.is_empty()
                    })
                    .count();
                let up = self.topology.read().active_nodes().count();
                if up < registered && since.elapsed() < SETTLE {
                    return; // some OSD registered isn't up yet
                }
                let mut pool = self.default_pool_config(domain);
                pool.pg_count = self.sized_pg_count(copies);
                match self
                    .create_pool(Request::new(CreatePoolRequest {
                        pool: Some(pool.clone()),
                    }))
                    .await
                {
                    Ok(_) => {
                        info!(
                            "default pool made: {} PGs over {domain}s, {copies} copies each",
                            pool.pg_count
                        );
                    }
                    Err(e) => {
                        warn!("default pool not made yet: {}", e.message());
                    }
                }
                return;
            }
        };
        if self.placement_groups_for_pool(DEFAULT_POOL).len() < pool.pg_count as usize
            && let Err(e) = self.preallocate_placement_groups(&pool).await
        {
            warn!("default pool's placement groups: {}", e.message());
        }
    }

    /// Whether OSD `id` can be an acting member: registered, `In`, with an
    /// address, and not down past the grace (`down_since`).
    fn acting_usable(
        &self,
        id: &[u8],
        down_since: &HashMap<[u8; 16], std::time::Instant>,
        grace: Duration,
    ) -> bool {
        let Ok(id) = <[u8; 16]>::try_from(id) else {
            return false;
        };
        let registered = self.osd_nodes.read().iter().any(|n| {
            n.node_id == id
                && n.admin_state == objectio_common::OsdAdminState::In
                && !n.address.is_empty()
        });
        registered
            && down_since
                .get(&id)
                .is_none_or(|since| since.elapsed() < grace)
    }

    /// Keep every placement group's acting set usable (leader, level 7). A
    /// member that can't take writes (gone, set out or draining, with no
    /// address, or down past the grace) is replaced by an OSD that can,
    /// preferably in a failure domain the PG doesn't use yet, chosen the
    /// same way by any leader; the change is one commit that raises the
    /// PG's epoch, and the members old and new are told the epoch. The
    /// stand-in is recorded as filling: recovery's backfill (`recovery.rs`)
    /// gives it the PG's existing objects and their shards at its position.
    /// A position no OSD can take is left as it is (the PG is undersized).
    ///
    /// `down_since` is this leader's record of when each OSD was first seen
    /// down.
    pub(crate) async fn keep_acting_sets(
        &self,
        down_since: &mut HashMap<[u8; 16], std::time::Instant>,
    ) {
        if !self.is_raft_leader() || !pg_placement() {
            return;
        }
        let grace = Duration::from_secs(self.config_parsed("pg/down_out_seconds", DOWN_OUT_SECS));
        {
            let topology = self.topology.read();
            let now = std::time::Instant::now();
            for node in topology.all_nodes() {
                let id = *node.id.as_bytes();
                if node.status == NodeStatus::Active {
                    down_since.remove(&id);
                } else {
                    down_since.entry(id).or_insert(now);
                }
            }
        }
        let mut changed: Vec<(PlacementGroup, PlacementGroup)> = Vec::new();
        let mut undersized = 0u64;
        for pool in self.pools_snapshot() {
            if pool.pg_count == 0 {
                continue;
            }
            let rule = match placement_rule(&pool) {
                Ok(rule) => rule,
                Err(e) => {
                    warn!(
                        "pool '{}': {e}; its placement groups are left as they are",
                        pool.name
                    );
                    continue;
                }
            };
            for pg in self.placement_groups_for_pool(&pool.name) {
                let usable = |pg: &PlacementGroup| {
                    pg.acting
                        .iter()
                        .all(|id| self.acting_usable(id, down_since, grace))
                };
                // An up member gone for good where acting is elsewhere: up
                // goes back to acting there (recovery would move the PG
                // onto nothing, and a drain would wait on it forever).
                let fixed = self.without_gone_up(&pg);
                let base = fixed.clone().unwrap_or_else(|| pg.clone());
                if usable(&base) {
                    if let Some(f) = fixed {
                        changed.push((pg, f));
                    }
                    continue;
                }
                match self.stand_in(&base, &rule, down_since, grace) {
                    Some(new) => {
                        undersized += u64::from(!usable(&new));
                        changed.push((pg, new));
                    }
                    None => {
                        undersized += 1;
                        if let Some(f) = fixed {
                            changed.push((pg, f));
                        }
                    }
                }
            }
        }
        PGS_UNDERSIZED.store(undersized, std::sync::atomic::Ordering::Relaxed);
        for chunk in changed.chunks(PG_CHUNK) {
            if let Err(e) = self.commit_pgs(chunk, "pg-stand-in").await {
                warn!("stand-ins not committed: {e}");
                continue;
            }
            for (old, new) in chunk {
                info!(
                    "pg {}/{}: epoch {} → {}: {}",
                    new.pool,
                    new.pg_id,
                    old.epoch,
                    new.epoch,
                    describe_change(&old.acting, &new.acting)
                );
            }
            let mut notify: Vec<Vec<u8>> = Vec::new();
            for (old, new) in chunk {
                notify.extend(old.acting.iter().cloned());
                notify.extend(new.acting.iter().cloned());
            }
            let pgs: Vec<PlacementGroup> = chunk.iter().map(|(_, new)| new.clone()).collect();
            self.push_pg_epochs(&pgs, &notify).await;
        }
    }

    /// `pg`, with a stand-in committed first for any acting member that
    /// can't take a write at all (set out or draining, lost, unregistered),
    /// for a placement about to be handed out: a write then never goes to a
    /// member that can't take it, the way Ceph holds a PG's I/O until its
    /// new interval is recorded. Members merely down are left to the grace
    /// ([`Self::keep_acting_sets`]). Leader, level 7.
    pub(crate) async fn with_usable_acting(&self, pg: PlacementGroup) -> PlacementGroup {
        let none = HashMap::new();
        if !self.is_raft_leader()
            || !pg_placement()
            || pg
                .acting
                .iter()
                .all(|id| self.acting_usable(id, &none, Duration::MAX))
        {
            return pg;
        }
        let Some(rule) = self
            .pools
            .read()
            .get(&pg.pool)
            .and_then(|p| placement_rule(p).ok())
        else {
            return pg;
        };
        let Some(new) = self.stand_in(&pg, &rule, &none, Duration::MAX) else {
            return pg; // nothing can stand in: undersized
        };
        match self
            .commit_pgs(&[(pg.clone(), new.clone())], "pg-stand-in")
            .await
        {
            Ok(()) => {
                info!(
                    "pg {}/{}: epoch {} → {} before placing: {}",
                    new.pool,
                    new.pg_id,
                    pg.epoch,
                    new.epoch,
                    describe_change(&pg.acting, &new.acting)
                );
                let mut notify = pg.acting.clone();
                notify.extend(new.acting.iter().cloned());
                self.push_pg_epochs(std::slice::from_ref(&new), &notify)
                    .await;
                new
            }
            // Another call committed one meanwhile: that is current.
            Err(_) => self.placement_group(&pg.pool, pg.pg_id).unwrap_or(pg),
        }
    }

    /// `pg` with each up member that is gone for good (set out or draining,
    /// lost, unregistered), where acting has another, replaced by the acting
    /// one; None if there is none such.
    fn without_gone_up(&self, pg: &PlacementGroup) -> Option<PlacementGroup> {
        if pg.up.len() != pg.acting.len() {
            return None;
        }
        let none = HashMap::new();
        let mut up = pg.up.clone();
        let mut any = false;
        for (p, member) in up.iter_mut().enumerate() {
            if *member != pg.acting[p] && !self.acting_usable(member, &none, Duration::MAX) {
                member.clone_from(&pg.acting[p]);
                any = true;
            }
        }
        any.then(|| PlacementGroup {
            up,
            updated_at: Self::current_timestamp(),
            ..pg.clone()
        })
    }

    /// `pg` with every unusable acting member stood in for, or None if no
    /// position could change. A stand-in keeps the pool's placement rule
    /// (phase 1b): in the domain of the rest of its LRC group, or in a
    /// domain under its limit of copies and holding no group, on a host
    /// none of that domain's members are on; preferably a domain the PG
    /// doesn't use yet. A position no OSD can take within the rule is left
    /// as it is: the PG is undersized rather than less spread.
    fn stand_in(
        &self,
        pg: &PlacementGroup,
        rule: &PlacementRule,
        down_since: &HashMap<[u8; 16], std::time::Instant>,
        grace: Duration,
    ) -> Option<PlacementGroup> {
        let topology = self.topology.read().clone();
        let node = |id: &[u8]| -> Option<NodeInfo> {
            let id = <[u8; 16]>::try_from(id).ok()?;
            topology.get_node(NodeId::from_bytes(id)).cloned()
        };
        let mut acting = pg.acting.clone();
        let mut up = pg.up.clone();
        let mut filling = pg.filling.clone();
        let epoch = pg.epoch + 1;
        let mut any = false;
        let no_grace = HashMap::new();
        for position in 0..acting.len() {
            if self.acting_usable(&acting[position], down_since, grace) {
                continue;
            }
            // Gone for good (set out or draining, lost, unregistered), not
            // merely down: the up set lets it go too, so recovery doesn't
            // move the PG back onto it (phase 3a). A member only down stays
            // in `up`: when it is back, recovery moves the PG back to it.
            let gone = !self.acting_usable(&acting[position], &no_grace, Duration::MAX);
            // The other members, where they are, for the rule: an unusable
            // one too, until it is replaced (it still holds its domain's
            // share; counted out, a stand-in for another position could
            // take that share, and its own stand-in then break the rule).
            // A member the topology no longer knows holds nothing.
            let others: Vec<(usize, String, String)> = acting
                .iter()
                .enumerate()
                .filter(|(p, _)| *p != position)
                .filter_map(|(p, id)| {
                    let n = node(id)?;
                    Some((p, domain_name(&n, rule.level), unit_name(&n, rule)))
                })
                .collect();
            let spare = topology
                .active_nodes()
                .filter(|n| !acting.contains(&n.id.as_bytes().to_vec()))
                .filter(|n| self.acting_usable(n.id.as_bytes(), down_since, grace))
                .filter(|n| {
                    rule.admits(
                        position,
                        &domain_name(n, rule.level),
                        &unit_name(n, rule),
                        &others,
                    )
                })
                .map(|n| {
                    let domain = domain_name(n, rule.level);
                    let shared = others.iter().any(|(_, d, _)| *d == domain);
                    let id = n.id.as_bytes().to_vec();
                    let mut seed = pg.pool.as_bytes().to_vec();
                    seed.extend_from_slice(&pg.pg_id.to_le_bytes());
                    seed.extend_from_slice(&(position as u64).to_le_bytes());
                    seed.extend_from_slice(&id);
                    ((shared, xxhash_rust::xxh64::xxh64(&seed, 0)), id)
                })
                .min_by(|a, b| a.0.cmp(&b.0))
                .map(|(_, id)| id);
            let Some(spare) = spare else {
                if UNDERSIZED_LOGGED
                    .lock()
                    .insert((pg.pool.clone(), pg.pg_id, position))
                {
                    warn!(
                        "pg {}/{} position {position}: no OSD can stand in for {} within the \
                         pool's placement rule; undersized",
                        pg.pool,
                        pg.pg_id,
                        hex::encode(&acting[position])
                    );
                }
                continue;
            };
            UNDERSIZED_LOGGED
                .lock()
                .remove(&(pg.pool.clone(), pg.pg_id, position));
            let from = std::mem::replace(&mut acting[position], spare.clone());
            if gone && up.get(position) == Some(&from) {
                up[position] = spare;
            }
            set_filling(&mut filling, position as u32, from, epoch);
            any = true;
        }
        any.then(|| PlacementGroup {
            acting,
            up,
            epoch,
            filling,
            updated_at: Self::current_timestamp(),
            ..pg.clone()
        })
    }

    /// Commit `(old, new)` placement groups in one command, each only if
    /// it is still `old`.
    pub(crate) async fn commit_pgs(
        &self,
        changes: &[(PlacementGroup, PlacementGroup)],
        why: &str,
    ) -> anyhow::Result<()> {
        use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
        let ops: Vec<CasOp> = changes
            .iter()
            .map(|(old, new)| CasOp {
                table: CasTable::PlacementGroups,
                key: MetaStore::pg_key(&new.pool, new.pg_id),
                expected: Some(old.encode_to_vec()),
                new_value: Some(new.encode_to_vec()),
            })
            .collect();
        if let Some(raft) = self.raft_handle() {
            let cmd = MetaCommand::MultiCas {
                ops,
                requested_by: why.into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => Ok(()),
                    MetaResponse::MultiCasConflict { .. } => {
                        Err(anyhow::anyhow!("a placement group changed meanwhile"))
                    }
                    other => Err(anyhow::anyhow!("unexpected raft response: {other:?}")),
                },
                Err(e) => Err(anyhow::anyhow!("raft: {e}")),
            }
        } else if let Some(store) = &self.store {
            for (_, new) in changes {
                store.put_placement_group(&new.pool, new.pg_id, &new.encode_to_vec());
                self.placement_groups
                    .write()
                    .insert((new.pool.clone(), new.pg_id), new.clone());
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    /// Every placement group's epoch, for an OSD registering (level 7).
    pub(crate) fn pg_epochs(&self) -> Vec<PgEpoch> {
        if !pg_placement() {
            return Vec::new();
        }
        self.placement_groups
            .read()
            .values()
            .map(|pg| PgEpoch {
                pool: pg.pool.clone(),
                pg_id: pg.pg_id,
                epoch: pg.epoch,
            })
            .collect()
    }

    /// Tell the OSDs in `members` (and, when empty, every registered OSD)
    /// the epochs of `pgs`. Best effort: an OSD that misses it asks meta
    /// when it sees a newer epoch, and learns them all when it registers.
    pub(crate) async fn push_pg_epochs(&self, pgs: &[PlacementGroup], members: &[Vec<u8>]) {
        let epochs: Vec<PgRef> = pgs
            .iter()
            .map(|pg| PgRef {
                pool: pg.pool.clone(),
                pg_id: pg.pg_id,
                epoch: pg.epoch,
            })
            .collect();
        let addresses: std::collections::BTreeSet<String> = self
            .osd_nodes
            .read()
            .iter()
            .filter(|n| members.is_empty() || members.iter().any(|m| m.as_slice() == n.node_id))
            .filter(|n| !n.address.is_empty())
            .map(|n| n.address.clone())
            .collect();
        let pushes = addresses.into_iter().map(|address| {
            let request = SetPgEpochsRequest {
                epochs: epochs.clone(),
            };
            async move {
                let sent = async {
                    let channel = crate::drain_observer::open_channel(&address).await?;
                    tokio::time::timeout(
                        PUSH_TIMEOUT,
                        StorageServiceClient::new(channel).set_pg_epochs(request),
                    )
                    .await
                    .map_err(|_| anyhow::anyhow!("timed out"))??;
                    Ok::<_, anyhow::Error>(())
                };
                if let Err(e) = sent.await {
                    debug!("pg epochs to {address}: {e}");
                }
            }
        });
        futures::future::join_all(pushes).await;
    }
}

/// How long the default pool waits for OSDs registered but not up yet,
/// once there are enough to make it.
const SETTLE: Duration = Duration::from_secs(30);

/// How often the leader looks after placement groups.
const KEEP_EVERY: Duration = Duration::from_secs(2);

/// Run the leader's placement-group upkeep (B31): make the default pool,
/// stand in for acting members that can't take writes. Recovery
/// (`recovery.rs`) fills the stand-ins.
pub fn spawn(meta: Arc<MetaService>) {
    tokio::spawn(async move {
        let mut down_since = HashMap::new();
        let mut ready_since = None;
        loop {
            tokio::time::sleep(KEEP_EVERY).await;
            if !meta.is_raft_leader() {
                // A new leader times members' downtime from its election.
                down_since.clear();
                continue;
            }
            meta.ensure_default_pool(&mut ready_since).await;
            meta.keep_acting_sets(&mut down_since).await;
        }
    });
}

/// Record that `position` is now filled from `from` (the member that held
/// it until `epoch`, which holds what was written there), replacing an
/// earlier fill of that position.
pub(crate) fn set_filling(filling: &mut Vec<PgFill>, position: u32, from: Vec<u8>, epoch: u64) {
    filling.retain(|f| f.position != position);
    filling.push(PgFill {
        position,
        from,
        epoch,
    });
}

/// "position 2: 1a2b… → 3c4d…" for each position that changed.
fn describe_change(old: &[Vec<u8>], new: &[Vec<u8>]) -> String {
    old.iter()
        .zip(new)
        .enumerate()
        .filter(|(_, (a, b))| a != b)
        .map(|(p, (a, b))| {
            let short = |id: &[u8]| hex::encode(&id[..id.len().min(4)]);
            format!("position {p}: {} → {}", short(a), short(b))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    //! The leader's stand-in rule (B31): which acting member is replaced,
    //! by which OSD, and when not.

    use super::*;
    use objectio_proto::metadata::metadata_service_server::MetadataService;
    use objectio_proto::metadata::{FailureDomainInfo, RegisterOsdRequest};

    fn id(n: u8) -> Vec<u8> {
        vec![n; 16]
    }

    #[test]
    fn a_pool_made_without_a_count_has_about_100_members_a_drive() {
        // Small clusters keep the floor.
        assert_eq!(sized_pg_count(6, 6, 100), 256);
        assert_eq!(sized_pg_count(0, 6, 100), 256);
        // 40 drives, 4+2: 4000 / 6 = 667, rounded up to 1024.
        assert_eq!(sized_pg_count(40, 6, 100), 1024);
        // 3-way replicas: 40 * 100 / 3 = 1334 -> 2048.
        assert_eq!(sized_pg_count(40, 3, 100), 2048);
        // Large clusters stop at the ceiling.
        assert_eq!(sized_pg_count(1000, 6, 100), MAX_PG_COUNT);
        assert_eq!(sized_pg_count(usize::MAX, 6, u32::MAX), MAX_PG_COUNT);
    }

    /// A service with OSDs `1..=count` registered, OSD `n` on host `hosts(n)`.
    async fn cluster(count: u8, hosts: impl Fn(u8) -> String) -> MetaService {
        racked(count, |n| (String::new(), hosts(n))).await
    }

    /// As [`cluster`], OSD `n` in rack and host `place(n)`.
    async fn racked(count: u8, place: impl Fn(u8) -> (String, String)) -> MetaService {
        let svc = MetaService::new();
        for n in 1..=count {
            let (rack, host) = place(n);
            MetadataService::register_osd(
                &svc,
                Request::new(RegisterOsdRequest {
                    node_id: id(n),
                    address: format!("http://10.0.0.{n}:9200"),
                    disk_ids: vec![id(n)],
                    disk_capacity_bytes: vec![1 << 30],
                    failure_domain: Some(FailureDomainInfo {
                        rack,
                        host,
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
            )
            .await
            .unwrap();
        }
        svc
    }

    fn pg(members: &[u8]) -> PlacementGroup {
        PlacementGroup {
            pool: DEFAULT_POOL.into(),
            pg_id: 3,
            acting: members.iter().map(|&n| id(n)).collect(),
            up: members.iter().map(|&n| id(n)).collect(),
            epoch: 4,
            ..Default::default()
        }
    }

    /// `n` down since long before the grace.
    fn down(n: u8) -> HashMap<[u8; 16], std::time::Instant> {
        let long_ago = std::time::Instant::now()
            .checked_sub(Duration::from_secs(3600))
            .unwrap();
        HashMap::from([([n; 16], long_ago)])
    }

    const GRACE: Duration = Duration::from_secs(120);

    /// One copy per host, six copies: the rule a pool has unless it asks.
    fn host_rule() -> PlacementRule {
        PlacementRule::spread(FailureDomain::Host, 6)
    }

    #[tokio::test]
    async fn a_member_down_past_the_grace_is_stood_in_for_with_a_new_epoch() {
        let svc = cluster(7, |n| format!("h{n}")).await;
        let new = svc
            .stand_in(&pg(&[1, 2, 3, 4, 5, 6]), &host_rule(), &down(2), GRACE)
            .expect("a stand-in");
        assert_eq!(new.acting, [1, 7, 3, 4, 5, 6].map(id));
        assert_eq!(new.epoch, 5);
        // Where the balancer wants it doesn't change.
        assert_eq!(new.up, [1, 2, 3, 4, 5, 6].map(id));
        assert_eq!(
            new.filling,
            [PgFill {
                position: 1,
                from: id(2),
                epoch: 5,
            }]
        );
    }

    #[tokio::test]
    async fn a_member_down_within_the_grace_stays() {
        let svc = cluster(7, |n| format!("h{n}")).await;
        let just_now = HashMap::from([([2u8; 16], std::time::Instant::now())]);
        assert!(
            svc.stand_in(&pg(&[1, 2, 3, 4, 5, 6]), &host_rule(), &just_now, GRACE)
                .is_none()
        );
    }

    #[tokio::test]
    async fn with_no_osd_to_spare_the_pg_is_left_undersized() {
        let svc = cluster(6, |n| format!("h{n}")).await;
        assert!(
            svc.stand_in(&pg(&[1, 2, 3, 4, 5, 6]), &host_rule(), &down(2), GRACE)
                .is_none()
        );
    }

    /// An OSD in a failure domain the PG doesn't use yet is taken before one
    /// sharing a member's host, whatever the hash says.
    #[tokio::test]
    async fn the_stand_in_comes_from_a_failure_domain_the_pg_does_not_use() {
        // 7 shares host h3 with member 3; 8 is on a host of its own.
        let svc = cluster(8, |n| if n == 7 { "h3".into() } else { format!("h{n}") }).await;
        for pg_id in 0..32 {
            let mut p = pg(&[1, 2, 3, 4, 5, 6]);
            p.pg_id = pg_id;
            let new = svc.stand_in(&p, &host_rule(), &down(2), GRACE).unwrap();
            assert_eq!(new.acting[1], id(8), "pg {pg_id}");
        }
    }

    /// 4+2 over three racks, two per rack (B31 phase 1b). Racks: A holds
    /// 1, 2 and 7; B 3 and 4; C 5 and 6. A member of rack B lost can't be
    /// stood in for: the only spare, 7, is in rack A, which has its two
    /// already. The PG is left undersized rather than spread less. A
    /// member of rack A lost is stood in for by 7.
    #[tokio::test]
    async fn a_stand_in_keeps_the_rules_limit_per_rack() {
        let rack = |n: u8| match n {
            1 | 2 | 7 => "A",
            3 | 4 => "B",
            _ => "C",
        };
        let svc = racked(7, |n| (rack(n).into(), format!("h{n}"))).await;
        let rule = PlacementRule {
            level: FailureDomain::Rack,
            copy_count: 6,
            domains: 3,
            per_domain: 2,
            together: Vec::new(),
        };
        let p = pg(&[1, 2, 3, 4, 5, 6]);
        assert!(svc.stand_in(&p, &rule, &down(3), GRACE).is_none());
        let new = svc.stand_in(&p, &rule, &down(1), GRACE).unwrap();
        assert_eq!(new.acting, [7, 2, 3, 4, 5, 6].map(id));
        // Both out: 3's position, looked at first if 1 didn't count, would
        // take 7 and leave rack A with three once 1 stays. 1 still holds
        // rack A's share until it is replaced, so 7 goes to 1's place.
        let mut both = down(1);
        both.extend(down(3));
        let new = svc.stand_in(&p, &rule, &both, GRACE).unwrap();
        assert_eq!(new.acting, [7, 2, 3, 4, 5, 6].map(id));
    }

    /// LRC 4+2+1 with each local group in a rack of its own: positions 0,
    /// 1 and 4 in rack A, 2, 3 and 5 in rack B, the global parity (6) in
    /// rack C. A lost member of a group is stood in for from its group's
    /// rack only; the global parity from a rack holding no group.
    #[tokio::test]
    async fn an_lrc_stand_in_stays_in_its_groups_rack() {
        let rack = |n: u8| match n {
            1 | 2 | 3 | 8 => "A",
            4 | 5 | 6 | 9 => "B",
            _ => "C",
        };
        let svc = racked(10, |n| (rack(n).into(), format!("h{n}"))).await;
        let rule = PlacementRule {
            level: FailureDomain::Rack,
            copy_count: 7,
            domains: 3,
            per_domain: 3,
            together: vec![vec![0, 1, 4], vec![2, 3, 5]],
        };
        // Positions 0..6: 1 2 | 4 5 data, 3 6 local parity, 7 global.
        let p = pg(&[1, 2, 4, 5, 3, 6, 7]);
        for pg_id in 0..16 {
            let mut p = p.clone();
            p.pg_id = pg_id;
            let new = svc.stand_in(&p, &rule, &down(2), GRACE).unwrap();
            assert_eq!(new.acting[1], id(8), "pg {pg_id}: out of its group's rack");
            let new = svc.stand_in(&p, &rule, &down(7), GRACE).unwrap();
            assert_eq!(
                new.acting[6],
                id(10),
                "pg {pg_id}: global parity with a group"
            );
        }
    }

    #[test]
    fn a_pools_fields_make_its_rule() {
        let lrc = PoolConfig {
            ec_type: ErasureType::ErasureLrc as i32,
            ec_k: 4,
            ec_local_parity: 2,
            ec_global_parity: 1,
            ec_m: 3,
            failure_domain: "rack".into(),
            lrc_groups_per_domain: true,
            ..Default::default()
        };
        let rule = placement_rule(&lrc).unwrap();
        assert_eq!(rule.together, vec![vec![0, 1, 4], vec![2, 3, 5]]);
        assert_eq!((rule.domains, rule.per_domain), (3, 3));
        // A whole group lost is 2 data shards, more than 1 global parity.
        assert!(!tolerates_domain_loss(&lrc, &rule));

        let spread = PoolConfig {
            ec_type: ErasureType::ErasureMds as i32,
            ec_k: 4,
            ec_m: 2,
            failure_domain: "rack".into(),
            per_domain: 2,
            ..Default::default()
        };
        let rule = placement_rule(&spread).unwrap();
        assert_eq!((rule.domains, rule.per_domain), (3, 2));
        assert!(tolerates_domain_loss(&spread, &rule));
        // Three per rack loses data with a rack.
        let three = PoolConfig {
            per_domain: 3,
            ..spread.clone()
        };
        let rule = placement_rule(&three).unwrap();
        assert!(!tolerates_domain_loss(&three, &rule));
        // An MDS pool can't ask for LRC groups.
        let wrong = PoolConfig {
            lrc_groups_per_domain: true,
            ..spread
        };
        assert!(placement_rule(&wrong).is_err());
    }

    /// Any leader picks the same: the choice depends on the PG and position,
    /// not on the order OSDs are found in.
    #[tokio::test]
    async fn the_choice_is_the_same_on_every_leader() {
        let a = cluster(9, |n| format!("h{n}")).await;
        let b = cluster(9, |n| format!("h{n}")).await;
        let p = pg(&[1, 2, 3, 4, 5, 6]);
        let pick = |svc: &MetaService| svc.stand_in(&p, &host_rule(), &down(2), GRACE);
        assert_eq!(pick(&a).unwrap().acting, pick(&b).unwrap().acting);
    }

    #[test]
    fn a_key_maps_to_the_same_pg_every_time() {
        let first = pg_of_key("b", "k", 256);
        assert!(first < 256);
        assert_eq!(pg_of_key("b", "k", 256), first);
        assert_eq!(
            describe_change(&[id(1), id(2)], &[id(1), id(9)]),
            "position 1: 02020202 → 09090909"
        );
    }

    #[test]
    fn finer_than_a_host_each_osd_is_its_own_failure_domain() {
        assert_eq!(fd_level(""), Some(FailureDomain::Host));
        assert_eq!(fd_level("node"), Some(FailureDomain::Node));
        assert_eq!(fd_level("osd"), Some(FailureDomain::Node));
        assert_eq!(fd_level("galaxy"), None);
    }
}
