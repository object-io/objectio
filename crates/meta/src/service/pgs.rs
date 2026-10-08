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
use objectio_placement::topology::NodeInfo;
use objectio_proto::storage::{
    PgRef, SetPgEpochsRequest, storage_service_client::StorageServiceClient,
};

/// The pool a bucket that names none is placed in.
pub const DEFAULT_POOL: &str = "default";

/// Placement groups in the default pool, and in a pool made without a
/// count. Fixed for the pool's life: capacity grows by adding pools.
pub const DEFAULT_PG_COUNT: u32 = 256;

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

/// The failure domain `node` is in at `level`. Finer than a host each OSD
/// is its own.
fn domain_of(node: &NodeInfo, level: FailureDomain) -> String {
    match level {
        FailureDomain::Node | FailureDomain::Disk => node.id.to_string(),
        _ => node.failure_domain.at_level(level).to_string(),
    }
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

    /// The placement groups that still hold `node`: an acting member, or a
    /// stand-in for it not yet filled. An OSD being emptied is done only
    /// when there are none.
    pub(crate) fn pgs_holding(&self, node: &[u8]) -> usize {
        if !pg_placement() {
            return 0; // nothing stands in for members below level 7
        }
        self.placement_groups
            .read()
            .values()
            .filter(|pg| {
                pg.acting.iter().any(|id| id.as_slice() == node)
                    || pg.filling.iter().any(|f| f.from.as_slice() == node)
            })
            .count()
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
                let pool = self.default_pool_config(domain);
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
    /// stand-in is recorded as filling: it gets the PG's existing objects'
    /// metadata from the others ([`Self::fill_stand_ins`]). A position no
    /// OSD can take is left as it is (the PG is undersized).
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
        for pool in self.pools_snapshot() {
            if pool.pg_count == 0 {
                continue;
            }
            let Some(level) = fd_level(&pool.failure_domain) else {
                continue;
            };
            for pg in self.placement_groups_for_pool(&pool.name) {
                if pg
                    .acting
                    .iter()
                    .all(|id| self.acting_usable(id, down_since, grace))
                {
                    continue;
                }
                if let Some(new) = self.stand_in(&pg, level, down_since, grace) {
                    changed.push((pg, new));
                }
            }
        }
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
        let Some(level) = self
            .pools
            .read()
            .get(&pg.pool)
            .and_then(|p| fd_level(&p.failure_domain))
        else {
            return pg;
        };
        let Some(new) = self.stand_in(&pg, level, &none, Duration::MAX) else {
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

    /// `pg` with every unusable acting member stood in for, or None if no
    /// position could change.
    fn stand_in(
        &self,
        pg: &PlacementGroup,
        level: FailureDomain,
        down_since: &HashMap<[u8; 16], std::time::Instant>,
        grace: Duration,
    ) -> Option<PlacementGroup> {
        let topology = self.topology.read().clone();
        let domain = |id: &[u8]| -> Option<String> {
            let id = <[u8; 16]>::try_from(id).ok()?;
            topology
                .get_node(NodeId::from_bytes(id))
                .map(|n| domain_of(n, level))
        };
        let mut acting = pg.acting.clone();
        let mut filling = pg.filling.clone();
        let epoch = pg.epoch + 1;
        let mut any = false;
        for position in 0..acting.len() {
            if self.acting_usable(&acting[position], down_since, grace) {
                continue;
            }
            let used: std::collections::HashSet<String> = acting
                .iter()
                .filter(|id| self.acting_usable(id, down_since, grace))
                .filter_map(|id| domain(id))
                .collect();
            let spare = topology
                .active_nodes()
                .map(|n| n.id.as_bytes().to_vec())
                .filter(|id| !acting.contains(id))
                .filter(|id| self.acting_usable(id, down_since, grace))
                .min_by_key(|id| {
                    let shared = domain(id).is_some_and(|d| used.contains(&d));
                    let mut seed = pg.pool.as_bytes().to_vec();
                    seed.extend_from_slice(&pg.pg_id.to_le_bytes());
                    seed.extend_from_slice(&(position as u64).to_le_bytes());
                    seed.extend_from_slice(id);
                    (shared, xxhash_rust::xxh64::xxh64(&seed, 0))
                });
            let Some(spare) = spare else {
                warn!(
                    "pg {}/{} position {position}: no OSD can stand in for {}; undersized",
                    pg.pool,
                    pg.pg_id,
                    hex::encode(&acting[position])
                );
                continue;
            };
            let from = std::mem::replace(&mut acting[position], spare);
            filling.retain(|f| f.position != position as u32);
            filling.push(PgFill {
                position: position as u32,
                from,
                epoch,
            });
            any = true;
        }
        any.then(|| PlacementGroup {
            acting,
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

/// A placement group's keys: the newest copy of each, and the OSD it was
/// listed on.
type Newest = HashMap<(String, String), (ObjectMeta, String)>;

/// How long the default pool waits for OSDs registered but not up yet,
/// once there are enough to make it.
const SETTLE: Duration = Duration::from_secs(30);

/// How often the leader looks after placement groups.
const KEEP_EVERY: Duration = Duration::from_secs(2);

/// Stand-ins are filled every this many looks.
const FILL_EVERY: u64 = 5;

/// Run the leader's placement-group upkeep (B31): make the default pool,
/// stand in for acting members that can't take writes, fill stand-ins.
pub fn spawn(meta: Arc<MetaService>) {
    tokio::spawn(async move {
        let mut down_since = HashMap::new();
        let mut ready_since = None;
        let mut looks: u64 = 0;
        loop {
            tokio::time::sleep(KEEP_EVERY).await;
            if !meta.is_raft_leader() {
                // A new leader times members' downtime from its election.
                down_since.clear();
                continue;
            }
            meta.ensure_default_pool(&mut ready_since).await;
            meta.keep_acting_sets(&mut down_since).await;
            if looks.is_multiple_of(FILL_EVERY) {
                meta.fill_stand_ins().await;
            }
            looks += 1;
        }
    });
}

impl MetaService {
    /// Give each stand-in the metadata of the objects its placement group
    /// held before it joined (leader, level 7): the newest copy of each,
    /// read from every other acting member, written to it unless it has
    /// one as new. A PG whose members all answered a whole walk, and whose
    /// every object reached its stand-ins, is filled: the entries go (the
    /// epoch stays). Shards are not copied here: a shard on a member that
    /// was set out or lost is moved by its evacuation; one on a member that
    /// was only down stays where its object says it is.
    ///
    /// Current objects only: versions of a versioned key are not filled
    /// (B31 phase 2's listing covers them).
    pub(crate) async fn fill_stand_ins(&self) {
        use objectio_proto::storage::{GetObjectMetaRequest, PutObjectMetaRequest};
        if !self.is_raft_leader() || !pg_placement() {
            return;
        }
        let filling: Vec<PlacementGroup> = self
            .placement_groups
            .read()
            .values()
            .filter(|pg| !pg.filling.is_empty())
            .cloned()
            .collect();
        if filling.is_empty() {
            return;
        }
        let wanted: std::collections::HashSet<(String, u32)> = filling
            .iter()
            .map(|pg| (pg.pool.clone(), pg.pg_id))
            .collect();
        let filling_at = |pg: &PlacementGroup, position: usize| {
            pg.filling.iter().any(|f| f.position as usize == position)
        };
        // Every acting member that isn't a stand-in still being filled.
        let mut sources: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
        for pg in &filling {
            for (position, id) in pg.acting.iter().enumerate() {
                if !filling_at(pg, position) {
                    sources.insert(id.clone());
                }
            }
        }
        // The newest copy of each key, by PG, and the OSD it was listed on;
        // the sources walked whole.
        let mut newest: HashMap<(String, u32), Newest> = HashMap::new();
        let mut walked: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
        for source in &sources {
            let Some(address) = <[u8; 16]>::try_from(source.as_slice())
                .ok()
                .and_then(|id| self.osd_address_by_id(&id))
            else {
                continue;
            };
            let mut cursor = String::new();
            let complete = loop {
                let (page, next) = match crate::repair::list_page(&address, &cursor).await {
                    Ok(p) => p,
                    Err(e) => {
                        debug!("fill: walking {address}: {e}");
                        break false;
                    }
                };
                for object in page {
                    let pool = self.bucket_pool_name(&object.bucket);
                    let Some(pg_count) = self.pools.read().get(&pool).map(|p| p.pg_count) else {
                        continue;
                    };
                    if pg_count == 0 {
                        continue;
                    }
                    let pg = (pool, pg_of_key(&object.bucket, &object.key, pg_count));
                    if !wanted.contains(&pg) || self.key_is_legacy(&object.bucket, &object.key) {
                        continue;
                    }
                    let slot = newest
                        .entry(pg)
                        .or_default()
                        .entry((object.bucket.clone(), object.key.clone()));
                    match slot {
                        std::collections::hash_map::Entry::Occupied(mut held) => {
                            if object.write_order() > held.get().0.write_order() {
                                held.insert((object, address.clone()));
                            }
                        }
                        std::collections::hash_map::Entry::Vacant(v) => {
                            v.insert((object, address.clone()));
                        }
                    }
                }
                if next.is_empty() {
                    break true;
                }
                cursor = next;
            };
            if complete {
                walked.insert(source.clone());
            }
        }

        let mut filled: Vec<(PlacementGroup, PlacementGroup)> = Vec::new();
        for pg in &filling {
            let mut whole = pg
                .acting
                .iter()
                .enumerate()
                .filter(|(position, _)| !filling_at(pg, *position))
                .all(|(_, id)| walked.contains(id));
            let objects = newest
                .remove(&(pg.pool.clone(), pg.pg_id))
                .unwrap_or_default();
            for fill in &pg.filling {
                let Some(address) = pg
                    .acting
                    .get(fill.position as usize)
                    .and_then(|id| <[u8; 16]>::try_from(id.as_slice()).ok())
                    .and_then(|id| self.osd_address_by_id(&id))
                else {
                    whole = false;
                    continue;
                };
                let Ok(channel) = crate::drain_observer::open_channel(&address).await else {
                    whole = false;
                    continue;
                };
                let mut client =
                    StorageServiceClient::new(channel).max_decoding_message_size(100 * 1024 * 1024);
                for ((bucket, key), (listed, source)) in &objects {
                    let held = client
                        .get_object_meta(GetObjectMetaRequest {
                            bucket: bucket.clone(),
                            key: key.clone(),
                            version_id: String::new(),
                            with_small_shard: false,
                        })
                        .await
                        .map(|r| r.into_inner());
                    let current = match held {
                        Ok(r) => r.object.filter(|_| r.found),
                        Err(e) => {
                            debug!("fill: {bucket}/{key} on {address}: {e}");
                            whole = false;
                            continue;
                        }
                    };
                    if current.is_some_and(|c| c.write_order() >= listed.write_order()) {
                        continue;
                    }
                    // Whole, from the copy it was listed on: a listing
                    // leaves out an inline object's bytes.
                    let object = match whole_copy(source, bucket, key).await {
                        Ok(Some(o)) if o.write_order() >= listed.write_order() => o,
                        Ok(_) => continue, // gone or replaced there since: next round
                        Err(e) => {
                            debug!("fill: reading {bucket}/{key} from {source}: {e}");
                            whole = false;
                            continue;
                        }
                    };
                    let put = client
                        .put_object_meta(PutObjectMetaRequest {
                            bucket: bucket.clone(),
                            key: key.clone(),
                            object: Some(object.clone()),
                            ..Default::default()
                        })
                        .await;
                    if let Err(e) = put {
                        debug!("fill: {bucket}/{key} to {address}: {e}");
                        whole = false;
                    }
                }
            }
            if whole {
                filled.push((
                    pg.clone(),
                    PlacementGroup {
                        filling: Vec::new(),
                        updated_at: Self::current_timestamp(),
                        ..pg.clone()
                    },
                ));
            }
        }
        for chunk in filled.chunks(PG_CHUNK) {
            match self.commit_pgs(chunk, "pg-filled").await {
                Ok(()) => {
                    for (_, pg) in chunk {
                        info!("pg {}/{}: stand-ins filled", pg.pool, pg.pg_id);
                    }
                }
                Err(e) => debug!("fill: not recorded yet: {e}"),
            }
        }
    }
}

/// `bucket/key`'s current ObjectMeta on the OSD at `address`, as stored
/// (an inline object's bytes included).
async fn whole_copy(address: &str, bucket: &str, key: &str) -> anyhow::Result<Option<ObjectMeta>> {
    use objectio_proto::storage::GetObjectMetaRequest;
    let channel = crate::drain_observer::open_channel(address).await?;
    let r = tokio::time::timeout(
        PUSH_TIMEOUT,
        StorageServiceClient::new(channel)
            .max_decoding_message_size(100 * 1024 * 1024)
            .get_object_meta(GetObjectMetaRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: String::new(),
                with_small_shard: false,
            }),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out"))??
    .into_inner();
    Ok(r.object.filter(|_| r.found))
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

    /// A service with OSDs `1..=count` registered, OSD `n` on host `hosts(n)`.
    async fn cluster(count: u8, hosts: impl Fn(u8) -> String) -> MetaService {
        let svc = MetaService::new();
        for n in 1..=count {
            MetadataService::register_osd(
                &svc,
                Request::new(RegisterOsdRequest {
                    node_id: id(n),
                    address: format!("http://10.0.0.{n}:9200"),
                    disk_ids: vec![id(n)],
                    disk_capacity_bytes: vec![1 << 30],
                    failure_domain: Some(FailureDomainInfo {
                        host: hosts(n),
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

    #[tokio::test]
    async fn a_member_down_past_the_grace_is_stood_in_for_with_a_new_epoch() {
        let svc = cluster(7, |n| format!("h{n}")).await;
        let new = svc
            .stand_in(
                &pg(&[1, 2, 3, 4, 5, 6]),
                FailureDomain::Host,
                &down(2),
                GRACE,
            )
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
            svc.stand_in(
                &pg(&[1, 2, 3, 4, 5, 6]),
                FailureDomain::Host,
                &just_now,
                GRACE
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn with_no_osd_to_spare_the_pg_is_left_undersized() {
        let svc = cluster(6, |n| format!("h{n}")).await;
        assert!(
            svc.stand_in(
                &pg(&[1, 2, 3, 4, 5, 6]),
                FailureDomain::Host,
                &down(2),
                GRACE
            )
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
            let new = svc
                .stand_in(&p, FailureDomain::Host, &down(2), GRACE)
                .unwrap();
            assert_eq!(new.acting[1], id(8), "pg {pg_id}");
        }
    }

    /// Any leader picks the same: the choice depends on the PG and position,
    /// not on the order OSDs are found in.
    #[tokio::test]
    async fn the_choice_is_the_same_on_every_leader() {
        let a = cluster(9, |n| format!("h{n}")).await;
        let b = cluster(9, |n| format!("h{n}")).await;
        let p = pg(&[1, 2, 3, 4, 5, 6]);
        let pick = |svc: &MetaService| svc.stand_in(&p, FailureDomain::Host, &down(2), GRACE);
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
