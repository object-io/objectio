//! The cluster: OSD registry and admin state, pools, placement groups, drain and rebalance, config, leases, upgrades, the heal queue, metrics.

use super::*;

impl MetaService {
    /// Mirror a Raft-committed Config write into the in-memory cache.
    /// Writes made via direct handlers (set_config, rebalance/pause,
    /// balancer knobs) update the cache themselves and then the
    /// Raft commit re-applies this same event — idempotent, harmless.
    /// Writes made via cluster_uuid()'s direct Raft path rely entirely
    /// on this handler to populate the cache.
    pub(super) fn apply_config_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        {
            let mut map = self.config.write();
            match new_value {
                Some(bytes) => match ConfigEntry::decode(bytes) {
                    Ok(entry) => {
                        map.insert(key.to_string(), entry);
                    }
                    Err(e) => {
                        warn!("apply: decode ConfigEntry('{key}') failed: {e}");
                    }
                },
                None => {
                    map.remove(key);
                }
            }
        }
        if key == objectio_common::version::ACTIVE_LEVEL_KEY {
            self.note_active_level();
        }
    }

    /// Mirror a replicated OSD record into this node's caches.
    pub(super) fn apply_osd_node_event(&self, key: &str, new_value: Option<&[u8]>) {
        match new_value {
            Some(bytes) => match objectio_meta_store::record::deserialize::<OsdNode>(bytes) {
                Ok(node) => {
                    {
                        let mut nodes = self.osd_nodes.write();
                        // A replacement at the same address doesn't remove the
                        // entry it replaces: registration records that one
                        // as lost (out, no address) in a write of its own.
                        match nodes.iter_mut().find(|n| n.node_id == node.node_id) {
                            Some(existing) => *existing = node.clone(),
                            None => nodes.push(node.clone()),
                        }
                    }
                    self.refresh_topology_node(&node);
                }
                Err(e) => warn!("apply: decode OsdNode('{key}') failed: {e}"),
            },
            None => {
                let Ok(id) = hex::decode(key) else { return };
                self.osd_nodes
                    .write()
                    .retain(|n| n.node_id.as_slice() != id.as_slice());
                if let Ok(id) = <[u8; 16]>::try_from(id.as_slice()) {
                    self.topology.write().remove_node(NodeId::from_bytes(id));
                }
            }
        }
    }

    /// The pool a new bucket in `tenant` goes to, `requested` or not.
    ///
    /// A system bucket may go to any enabled pool. A tenant's bucket goes to
    /// the pool it asks for only if the tenant may use it (its default, or
    /// one of its allowed pools), otherwise to the tenant's default pool;
    /// empty means the cluster's default placement.
    #[allow(clippy::result_large_err)]
    pub(super) fn resolve_bucket_pool(
        &self,
        tenant: &str,
        requested: &str,
    ) -> Result<String, Status> {
        let (default_pool, allowed) = if tenant.is_empty() {
            (String::new(), None)
        } else {
            let tenants = self.tenants.read();
            let t = tenants.get(tenant);
            (
                t.map(|t| t.default_pool.clone()).unwrap_or_default(),
                Some(t.map(|t| t.allowed_pools.clone()).unwrap_or_default()),
            )
        };
        let pool = if requested.is_empty() {
            default_pool.clone()
        } else {
            requested.to_string()
        };
        if pool.is_empty() {
            return Ok(pool);
        }
        if let Some(allowed) = &allowed
            && pool != default_pool
            && !allowed.contains(&pool)
        {
            return Err(Status::permission_denied(format!(
                "tenant '{tenant}' may not use pool '{pool}'"
            )));
        }
        match self.pools.read().get(&pool) {
            Some(p) if p.enabled => Ok(pool),
            Some(_) => Err(Status::failed_precondition(format!(
                "pool '{pool}' is disabled"
            ))),
            None => Err(Status::not_found(format!("pool '{pool}' does not exist"))),
        }
    }

    /// Apply a committed PlacementGroup mutation to the in-memory
    /// cache. Key format is "{pool}\0{pg_id:010}" — same as the redb
    /// key produced by `objectio_meta_store::MetaStore::pg_key`. A
    /// delete (`new_value = None`) removes the entry; a put decodes
    /// the prost bytes and upserts.
    pub(super) fn apply_placement_group_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let Some((pool, pg_id)) = Self::parse_pg_key(key) else {
            warn!("apply: malformed placement_group key '{key}'");
            return;
        };
        let mut map = self.placement_groups.write();
        match new_value {
            Some(bytes) => match PlacementGroup::decode(bytes) {
                Ok(pg) => {
                    map.insert((pool, pg_id), pg);
                }
                Err(e) => warn!("apply: decode PlacementGroup('{key}') failed: {e}"),
            },
            None => {
                map.remove(&(pool, pg_id));
            }
        }
    }

    /// Apply a committed pool row (key: the pool's name) to the cache.
    pub(super) fn apply_pool_event(&self, key: &str, new_value: Option<&[u8]>) {
        use prost::Message;
        let mut map = self.pools.write();
        match new_value {
            Some(bytes) => match PoolConfig::decode(bytes) {
                Ok(pool) => {
                    map.insert(key.to_string(), pool);
                }
                Err(e) => warn!("apply: decode PoolConfig('{key}') failed: {e}"),
            },
            None => {
                map.remove(key);
            }
        }
    }

    /// Inverse of `objectio_meta_store::MetaStore::pg_key`. Returns
    /// (pool, pg_id) from "{pool}\0{pg_id:010}".
    pub(super) fn parse_pg_key(key: &str) -> Option<(String, u32)> {
        let (pool, tail) = key.split_once('\0')?;
        let pg_id: u32 = tail.parse().ok()?;
        Some((pool.to_string(), pg_id))
    }

    /// Look up a placement group from the in-memory cache.
    pub fn placement_group(&self, pool: &str, pg_id: u32) -> Option<PlacementGroup> {
        self.placement_groups
            .read()
            .get(&(pool.to_string(), pg_id))
            .cloned()
    }

    /// Pre-allocate `pool.pg_count` placement groups using the
    /// copyset allocator. Called from `create_pool` once the pool
    /// row has been committed. Returns Ok(()) when every PG is
    /// written (or on the non-Raft fallback path). Commits in
    /// MultiCas batches of ≤128 ops to stay under the storage
    /// limit (see `raft_storage::MAX_OPS = 256`).
    /// The copysets a pool's placement groups would be drawn from, on the
    /// topology as it is, each keeping the pool's placement rule (B31
    /// phase 1b): the copy count, the rule, the copysets. An error when the
    /// rule is inconsistent (invalid argument) or the topology can't hold
    /// it (failed precondition).
    #[allow(clippy::result_large_err)] // a gRPC status, as every handler returns
    fn pg_copysets(
        &self,
        pool: &PoolConfig,
    ) -> Result<
        (
            usize,
            objectio_placement::PlacementRule,
            objectio_placement::CopysetPool,
        ),
        Status,
    > {
        use objectio_placement::CopysetPool;

        let copy_count = super::pgs::copy_count(pool);
        if copy_count == 0 {
            return Err(Status::invalid_argument(
                "pool has zero shards per PG — check ec_k / ec_m / replication_count",
            ));
        }
        let rule = super::pgs::placement_rule(pool).map_err(Status::invalid_argument)?;

        let topology = self.topology.read().clone();
        // Seed = topology.version × pg_count so concurrent pool creates
        // with the same topology get distinct pools.
        let seed = topology
            .version
            .wrapping_mul(1_000_003)
            .wrapping_add(u64::from(pool.pg_count));
        // scatter_width matches the balancer's knob so pre-alloc and
        // later rebalance see copyset pools of equivalent shape.
        let scatter_width = self
            .config_parsed::<usize>("balancer/scatter_width", 10)
            .max(1);
        let cs_pool = CopysetPool::build_with_rule(&topology, &rule, scatter_width, seed)
            .map_err(|e| Status::failed_precondition(format!("copyset pool build failed: {e}")))?;
        if cs_pool.sets.is_empty() {
            return Err(Status::failed_precondition(
                "no feasible copysets for current topology",
            ));
        }
        Ok((copy_count, rule, cs_pool))
    }

    pub(super) async fn preallocate_placement_groups(
        &self,
        pool: &PoolConfig,
    ) -> Result<(), Status> {
        let (copy_count, rule, cs_pool) = self.pg_copysets(pool)?;
        let fd_level = rule.level;

        let now = Self::current_timestamp();
        let mut pgs: Vec<PlacementGroup> = Vec::with_capacity(pool.pg_count as usize);
        for pg_id in 0..pool.pg_count {
            // One made before (a pre-allocation cut short) is kept as it is.
            if self.placement_group(&pool.name, pg_id).is_some() {
                continue;
            }
            let cs = &cs_pool.sets[pg_id as usize % cs_pool.sets.len()];
            let mut members: Vec<Vec<u8>> = cs.osds.iter().map(|n| n.as_bytes().to_vec()).collect();
            // Positions in an order of the PG's own. With as many failure
            // domains as copies there is a single copyset, and every PG
            // had the same order: the same OSDs held every object's parity
            // and every read went to the others. The order changes nothing
            // about how the copies are spread: it stays within the rule (an
            // LRC local group keeps its domain).
            {
                use rand::SeedableRng;
                let seed =
                    xxhash_rust::xxh64::xxh64(format!("{}/{pg_id}", pool.name).as_bytes(), 0);
                rule.shuffle(&mut members, &mut rand::rngs::StdRng::seed_from_u64(seed));
            }
            pgs.push(PlacementGroup {
                pool: pool.name.clone(),
                pg_id,
                acting: members.clone(),
                up: members,
                epoch: 1,
                updated_at: now,
                filling: Vec::new(),
            });
        }

        // Commit in batches. MAX_OPS in raft_storage is 256 — stay
        // well under to leave headroom for other MultiCas calls that
        // land in the same raft entry.
        const CHUNK: usize = 128;
        let raft = self.raft_handle();
        for chunk in pgs.chunks(CHUNK) {
            if let Some(raft) = raft.clone() {
                use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
                let ops: Vec<CasOp> = chunk
                    .iter()
                    .map(|pg| CasOp {
                        table: CasTable::PlacementGroups,
                        key: MetaStore::pg_key(&pg.pool, pg.pg_id),
                        expected: None,
                        new_value: Some(pg.encode_to_vec()),
                    })
                    .collect();
                let cmd = MetaCommand::MultiCas {
                    ops,
                    requested_by: "create-pool:init-pgs".into(),
                };
                match raft.client_write(cmd).await {
                    Ok(r) => match r.data {
                        MetaResponse::MultiCasOk => {}
                        MetaResponse::MultiCasConflict { .. } => {
                            return Err(Status::aborted("PG conflict during pre-allocation"));
                        }
                        other => {
                            error!("unexpected raft response during PG pre-alloc: {other:?}");
                            return Err(Status::internal("raft commit wrong variant"));
                        }
                    },
                    Err(e) => return Err(raft_write_to_status(&e)),
                }
            } else if let Some(store) = &self.store {
                for pg in chunk {
                    store.put_placement_group(&pg.pool, pg.pg_id, &pg.encode_to_vec());
                }
            }
        }

        info!(
            "pool '{}' pre-allocated {} PGs (copy_count={}, fd={}, pool.size={})",
            pool.name,
            pgs.len(),
            copy_count,
            fd_level,
            cs_pool.sets.len(),
        );
        if super::pgs::pg_placement() {
            self.push_pg_epochs(&pgs, &[]).await;
        }
        Ok(())
    }

    /// Read-only snapshot of the registered OSD list. Exposed for
    /// internal background tasks (drain observer) that need to
    /// iterate without acquiring the lock for an async scope.
    pub fn osd_nodes_read(&self) -> parking_lot::RwLockReadGuard<'_, Vec<OsdNode>> {
        self.osd_nodes.read()
    }

    /// Clone-snapshot of all pools. Background tasks use this instead
    /// of holding the lock across awaits.
    pub fn pools_snapshot(&self) -> Vec<PoolConfig> {
        self.pools.read().values().cloned().collect()
    }

    /// Clone-snapshot of all placement groups for a given pool.
    pub fn placement_groups_for_pool(&self, pool: &str) -> Vec<PlacementGroup> {
        let map = self.placement_groups.read();
        let mut pgs: Vec<PlacementGroup> = map
            .iter()
            .filter(|((p, _), _)| p == pool)
            .map(|(_, pg)| pg.clone())
            .collect();
        pgs.sort_by_key(|p| p.pg_id);
        pgs
    }

    /// Clone-snapshot of the cluster topology.
    pub fn topology_snapshot(&self) -> ClusterTopology {
        self.topology.read().clone()
    }

    /// Snapshot of all OSD drain progresses — node_id → progress.
    /// Consumed by the gateway's `/_admin/drain-status` endpoint.
    pub fn drain_statuses_snapshot(&self) -> HashMap<[u8; 16], DrainProgress> {
        self.drain_statuses.read().clone()
    }

    /// Mutate a single OSD's drain progress. Creates a default entry
    /// if absent. Background-task entrypoint — not exposed over gRPC.
    pub fn update_drain_progress<F: FnOnce(&mut DrainProgress)>(&self, node_id: [u8; 16], f: F) {
        let mut statuses = self.drain_statuses.write();
        let entry = statuses.entry(node_id).or_default();
        f(entry);
    }

    /// Remove a node from the drain-progress map — called once an OSD
    /// leaves the Draining state (either finalised to Out or rolled
    /// back to In).
    pub fn clear_drain_progress(&self, node_id: &[u8; 16]) {
        self.drain_statuses.write().remove(node_id);
    }

    /// Snapshot of the cluster-wide rebalance progress — consumed by
    /// `/_admin/rebalance-status`.
    pub fn rebalance_progress_snapshot(&self) -> RebalanceProgress {
        self.rebalance_progress.read().clone()
    }

    /// Mutate rebalance progress. Used by the reconciler sweep.
    pub fn update_rebalance_progress<F: FnOnce(&mut RebalanceProgress)>(&self, f: F) {
        let mut p = self.rebalance_progress.write();
        f(&mut p);
    }

    /// Is the rebalancer currently paused via the `rebalance/paused`
    /// config key? Checked on every reconciler sweep so paused state
    /// stays hot-swappable without restarting the process.
    pub fn is_rebalance_paused(&self) -> bool {
        // The config map mirrors what `set_config` has committed via
        // Raft; a bool cast from the stored "true"/"false" byte
        // string. Any parse error is treated as not-paused so a
        // garbled config can't lock the cluster into a no-rebalance
        // state.
        let cfg = self.config.read();
        cfg.get("rebalance/paused")
            .and_then(|e| std::str::from_utf8(&e.value).ok())
            .map(|s| s.trim().eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    /// Look up the address of an OSD by its node_id. Used by the drain
    /// migrator to open client channels.
    pub fn osd_address_by_id(&self, node_id: &[u8; 16]) -> Option<String> {
        self.osd_nodes
            .read()
            .iter()
            .find(|n| &n.node_id == node_id)
            .map(|n| n.address.clone())
            // A lost OSD whose address a replacement took (B26): nothing
            // answers for it any more.
            .filter(|a| !a.is_empty())
    }

    /// Remove a lost OSD's entry (B26): one a replacement took the address
    /// of, once nothing refers to it any more. It has no disk left to wipe.
    pub(crate) async fn forget_osd(&self, node_id: [u8; 16]) -> Result<(), Status> {
        self.replicate(
            vec![(OSD_NODES_TABLE, hex::encode(node_id), None)],
            "forget-lost-osd",
        )
        .await?;
        self.osd_nodes.write().retain(|n| n.node_id != node_id);
        self.topology
            .write()
            .remove_node(NodeId::from_bytes(node_id));
        Ok(())
    }

    pub fn osd_nodes_snapshot(&self) -> Vec<OsdNode> {
        self.osd_nodes.read().clone()
    }

    /// Set one node's observed status in the topology and rebuild CRUSH.
    ///
    /// Nothing outside registration used to touch node status, which is why a
    /// dead OSD stayed in the placement set: `NodeStatus::Down` existed and
    /// `active_nodes()` already skipped it, but there was no path that ever
    /// set it.
    pub fn set_topology_node_status(&self, node_id: NodeId, status: NodeStatus) {
        {
            let mut topology = self.topology.write();
            let Some(current) = topology.get_node(node_id) else {
                return;
            };
            if current.status == status {
                return;
            }
            let mut updated = current.clone();
            updated.status = status;
            topology.upsert_node(updated);
        }
        // Same rebuild the registration path does — replacing the engine
        // wholesale would drop its stripe-group configuration.
        let topology = self.topology.read().clone();
        self.crush.write().update_topology(topology);
    }

    /// List addresses of every registered OSD (any admin_state).
    /// Drain migrator uses this to fan out the
    /// `FindObjectsReferencingNode` scan.
    pub fn all_osd_addresses(&self) -> Vec<(String, [u8; 16])> {
        self.osd_nodes
            .read()
            .iter()
            .map(|n| (n.address.clone(), n.node_id))
            .collect()
    }

    /// Compute a CRUSH replacement for a single shard at `position` in
    /// the placement set for `object_id`, excluding the `exclude` node
    /// (typically the draining / current-owner OSD). Only returns
    /// candidates that are currently **registered** on this meta —
    /// a stale topology entry for an unregistered node is skipped
    /// rather than returned, so the caller can rely on
    /// `osd_address_by_id(target)` succeeding.
    ///
    /// Returns `None` if CRUSH can't find a valid alternative (too few
    /// eligible OSDs, or every CRUSH-picked node is unregistered /
    /// the excluded one). Caller logs and retries next sweep.
    pub fn pick_migration_target(
        &self,
        object_id: &[u8; 16],
        position: u32,
        exclude: &[u8; 16],
    ) -> Option<[u8; 16]> {
        use objectio_placement::crush2::PlacementTemplate;

        let template = PlacementTemplate::mds(self.default_ec_k as u8, self.default_ec_m as u8);

        let crush = self.crush.read();
        let obj_id = objectio_common::ObjectId::from_uuid(uuid::Uuid::from_bytes(*object_id));
        let placements = crush.select_placement(&obj_id, &template);
        drop(crush);

        let registered: std::collections::HashSet<[u8; 16]> =
            self.osd_nodes.read().iter().map(|n| n.node_id).collect();

        let eligible = |cand: &[u8; 16]| cand != exclude && registered.contains(cand);

        // Prefer the CRUSH pick for the exact stripe position. This
        // preserves the intended role (Data vs Parity) and keeps
        // placement deterministic for the other shards in the stripe.
        for p in &placements {
            if p.position as u32 == position {
                let cand = *p.node_id.as_bytes();
                if eligible(&cand) {
                    return Some(cand);
                }
            }
        }
        // Fallback: any CRUSH-eligible node in the returned set that
        // isn't excluded. Role becomes a soft hint — better than
        // failing the migration outright.
        placements
            .iter()
            .map(|p| *p.node_id.as_bytes())
            .find(eligible)
    }

    /// Where a drain moves shard `position` of a stripe: an OSD in
    /// service (not Draining or Out) that holds no other shard of the
    /// stripe (`holders`), so the stripe keeps one shard per OSD and still
    /// survives the failures it was written to survive. The CRUSH choice
    /// for `object_id` if it qualifies; otherwise the first in-service OSD
    /// that does, in a fixed order per stripe.
    pub fn pick_drain_target(
        &self,
        object_id: &[u8; 16],
        position: u32,
        holders: &[[u8; 16]],
    ) -> Option<[u8; 16]> {
        let in_service: Vec<[u8; 16]> = self
            .osd_nodes
            .read()
            .iter()
            .filter(|n| n.admin_state == objectio_common::OsdAdminState::In)
            .map(|n| n.node_id)
            .collect();
        let ok = |c: &[u8; 16]| in_service.contains(c) && !holders.contains(c);
        if let Some(c) = self.pick_migration_target(object_id, position, &[0u8; 16])
            && ok(&c)
        {
            return Some(c);
        }
        // Spread the fallback by stripe rather than always the same OSD.
        let mut candidates: Vec<[u8; 16]> = in_service.iter().copied().filter(|c| ok(c)).collect();
        candidates.sort_by_key(|c| {
            let mut h = [0u8; 16];
            for (i, b) in c.iter().enumerate() {
                h[i] = b ^ object_id[i] ^ (position as u8);
            }
            h
        });
        candidates.first().copied()
    }

    /// Invoke `SetOsdAdminState` from internal code (background tasks,
    /// not from an incoming RPC). Same Raft-routed path as the public
    /// gRPC handler; just skips the request-parsing / authz layer and
    /// always supplies `requested_by` so the audit log shows which
    /// subsystem triggered the change.
    ///
    /// # Errors
    /// Propagates any Raft `client_write` error (leader loss, timeout,
    /// shutdown).
    pub async fn internal_set_osd_admin_state(
        &self,
        node_id: [u8; 16],
        state: objectio_common::OsdAdminState,
        requested_by: String,
    ) -> anyhow::Result<()> {
        let raft = self
            .raft_handle()
            .ok_or_else(|| anyhow::anyhow!("raft handle unavailable"))?;
        raft.client_write(objectio_meta_store::MetaCommand::SetOsdAdminState {
            node_id,
            state,
            requested_by,
        })
        .await
        .map_err(|e| anyhow::anyhow!("client_write: {e}"))?;

        // Mirror into in-memory osd_nodes so the next get_listing_nodes
        // response reflects the new state immediately on this leader.
        let mut nodes = self.osd_nodes.write();
        if let Some(n) = nodes.iter_mut().find(|n| n.node_id == node_id) {
            n.admin_state = state;
        }
        // Rebuild placement topology to apply the change to CRUSH
        // without waiting for the next registration.
        let snapshot = nodes.clone();
        drop(nodes);
        for osd in &snapshot {
            self.refresh_topology_node(osd);
        }
        Ok(())
    }

    /// Update CRUSH topology with a new OSD node
    /// Whether a topology update is backed by evidence the node is reachable
    /// *now*.
    ///
    /// An OSD that has just registered is: it opened a connection and said so.
    /// A record read from the store at startup, or re-read during a
    /// rebuild-everything pass, is not — it describes the cluster as it was
    /// when meta last wrote it down.
    ///
    /// The distinction existed nowhere, so status was derived from
    /// `admin_state` alone in every case. That is the exact defect the liveness
    /// prober was written to fix, still present on these paths: a node the
    /// prober had marked `Down` came back `Active` on the next restart or the
    /// next admin-state change, and placement handed it out again. On the live
    /// deployment that meant every restart served 500s for thirty seconds from
    /// an address that had been dead for days.
    pub(super) fn update_topology_with_node(&self, osd_node: &OsdNode) {
        self.upsert_topology_node(osd_node, NodeEvidence::Observed);
    }

    /// As [`Self::update_topology_with_node`], for a node we have not heard
    /// from — loaded from the store, or swept up in a rebuild of every node.
    pub(super) fn refresh_topology_node(&self, osd_node: &OsdNode) {
        self.upsert_topology_node(osd_node, NodeEvidence::FromStore);
    }

    pub(super) fn upsert_topology_node(&self, osd_node: &OsdNode, evidence: NodeEvidence) {
        // An OSD that registered without a topology is placed in a
        // default one.
        let (region, zone, dc, rack, host) = osd_node.topology.clone().unwrap_or_else(|| {
            (
                "default".to_string(),
                String::new(),
                "dc1".to_string(),
                "rack1".to_string(),
                String::new(),
            )
        });

        let node_id = NodeId::from_bytes(osd_node.node_id);

        let disks: Vec<DiskInfo> = osd_node
            .disk_ids
            .iter()
            .map(|disk_id| {
                DiskInfo {
                    id: objectio_common::DiskId::from_bytes(*disk_id),
                    path: String::new(),
                    total_capacity: 1_000_000_000_000, // 1TB default
                    used_capacity: 0,
                    status: objectio_common::DiskStatus::Healthy,
                    weight: 1.0,
                }
            })
            .collect();

        // Merge operator intent (admin_state) with observed status. Draining
        // and Out are intent and win outright, so placement's `active_nodes()`
        // filter skips them either way. `In` means the operator does not
        // object — which is not the same as the node being there.
        let known = self.topology.read().get_node(node_id).map(|n| n.status);
        let status = topology_status(osd_node.admin_state, evidence, known);

        let node_info = NodeInfo {
            id: node_id,
            name: hex::encode(&osd_node.node_id[..4]),
            address: osd_node
                .address
                .parse()
                .unwrap_or_else(|_| "0.0.0.0:9200".parse().unwrap()),
            failure_domain: FailureDomainInfo::new_full(&region, &zone, &dc, &rack, &host),
            status,
            disks,
            weight: 1.0,
            last_heartbeat: Self::current_timestamp(),
        };

        // Update topology and rebuild CRUSH
        {
            let mut topology = self.topology.write();
            topology.upsert_node(node_info);
        }

        // Rebuild CRUSH with updated topology
        {
            let topology = self.topology.read().clone();
            let mut crush = self.crush.write();
            crush.update_topology(topology);
        }

        debug!(
            "Updated CRUSH topology with node {}",
            hex::encode(osd_node.node_id)
        );
    }

    /// The heal queue's entry for `key`, as stored.
    pub(super) fn heal_entry(&self, key: &str) -> Option<Vec<u8>> {
        self.store.as_ref()?.read_named(HEAL_TABLE, key)
    }

    /// Where to move a shard of a stripe whose shards are on `holders`
    /// (B20, backfill): an active OSD holding none of them, picked by the
    /// highest hash of the object and the OSD, so moves spread over the
    /// cluster. `None` when every active OSD already holds one.
    pub(crate) fn spread_target(
        &self,
        object_id: &[u8],
        holders: &std::collections::HashSet<Vec<u8>>,
    ) -> Option<([u8; 16], String)> {
        let topology = self.topology.read();
        let osd_nodes = self.osd_nodes.read();
        topology
            .active_nodes()
            .map(|n| *n.id.as_bytes())
            .filter(|id| !holders.contains(id.as_slice()))
            .filter_map(|id| {
                let node = osd_nodes.iter().find(|n| n.node_id == id)?;
                (node.admin_state == objectio_common::OsdAdminState::In)
                    .then(|| (id, node.address.clone()))
            })
            .max_by_key(|(id, _)| {
                let mut seed = object_id.to_vec();
                seed.extend_from_slice(id);
                xxhash_rust::xxh64::xxh64(&seed, 0)
            })
    }

    /// Placement computed from the topology (or the bucket's pool's
    /// placement groups), whatever the key's home.
    pub(super) async fn computed_placement(
        &self,
        request: Request<GetPlacementRequest>,
    ) -> Result<Response<GetPlacementResponse>, Status> {
        let req = request.into_inner();

        // Check if we have any nodes in the topology
        let active_node_count = {
            let topology = self.topology.read();
            topology.active_nodes().count()
        };

        if active_node_count == 0 {
            // Not until the liveness probe has seen OSDs: placing on the
            // bare OSD list would ignore failure domains.
            return Err(Status::unavailable(
                "no OSD is known to be up yet (the liveness probe runs every few seconds); retry",
            ));
        }

        // Create object ID from bucket/key for deterministic placement
        let object_id = {
            let key_str = format!("{}/{}", req.bucket, req.key);
            let hash = xxhash_rust::xxh64::xxh64(key_str.as_bytes(), 0);
            let mut bytes = [0u8; 16];
            bytes[..8].copy_from_slice(&hash.to_le_bytes());
            bytes[8..16].copy_from_slice(&hash.to_be_bytes());
            objectio_common::ObjectId::from_uuid(Uuid::from_bytes(bytes))
        };

        // The bucket's pool: its own, or (from level 7) the default pool.
        let pool_name = self.bucket_pool_name(&req.bucket);
        let pg_placement = super::pgs::pg_placement();
        // Written before placement groups: stays where CRUSH put it.
        let legacy = pg_placement && self.key_is_legacy(&req.bucket, &req.key);
        let pool_known = self.pools.read().contains_key(&pool_name);
        if pg_placement && !legacy && !pool_known {
            return Err(Status::unavailable(format!(
                "pool '{pool_name}' has no placement groups yet (made once enough OSDs are up); retry"
            )));
        }
        let (pool_ec, pool_pg_count) = if !pool_name.is_empty() {
            self.pools
                .read()
                .get(&pool_name)
                .map(|p| {
                    (
                        Some((
                            p.ec_type(),
                            p.ec_k,
                            p.ec_m,
                            p.ec_local_parity,
                            p.ec_global_parity,
                            p.replication_count,
                        )),
                        p.pg_count,
                    )
                })
                .unwrap_or((None, 0))
        } else {
            (None, 0)
        };

        // Select placement template based on pool EC config or global default
        let (
            template,
            ec_type,
            ec_k,
            ec_local_parity,
            ec_global_parity,
            local_group_size,
            replication_count,
        ) = if let Some((p_ec_type, p_k, p_m, p_lp, p_gp, p_rep)) = pool_ec {
            match p_ec_type {
                ErasureType::ErasureLrc => (
                    PlacementTemplate::lrc(p_k as u8, p_lp as u8, p_gp as u8),
                    ErasureType::ErasureLrc,
                    p_k,
                    p_lp,
                    p_gp,
                    if p_lp > 0 { p_k / p_lp } else { 0 },
                    0u32,
                ),
                ErasureType::ErasureReplication => (
                    PlacementTemplate::mds(p_rep as u8, 0),
                    ErasureType::ErasureReplication,
                    1u32,
                    0u32,
                    0u32,
                    0u32,
                    p_rep,
                ),
                _ => (
                    PlacementTemplate::mds(p_k as u8, p_m as u8),
                    ErasureType::ErasureMds,
                    p_k,
                    0u32,
                    p_m,
                    0u32,
                    0u32,
                ),
            }
        } else {
            // Fall back to global default EC config
            match &self.default_ec {
                EcConfig::Mds { k, m } => (
                    PlacementTemplate::mds(*k, *m),
                    ErasureType::ErasureMds,
                    *k as u32,
                    0u32,
                    *m as u32,
                    0u32,
                    0u32,
                ),
                EcConfig::Lrc { k, l, g } => (
                    PlacementTemplate::lrc(*k, *l, *g),
                    ErasureType::ErasureLrc,
                    *k as u32,
                    *l as u32,
                    *g as u32,
                    (*k / *l) as u32,
                    0u32,
                ),
                EcConfig::Replication { count } => (
                    PlacementTemplate::mds(*count, 0),
                    ErasureType::ErasureReplication,
                    1u32,
                    0u32,
                    0u32,
                    0u32,
                    *count as u32,
                ),
            }
        };

        // Through the key's placement group: its acting set, committed with
        // an epoch before any write used it (level 7), which every write
        // carries and OSDs check.
        if pool_pg_count > 0 && !pool_name.is_empty() && !legacy {
            let pg_id = super::pgs::pg_of_key(&req.bucket, &req.key, pool_pg_count);
            let expected_shards = match ec_type {
                ErasureType::ErasureMds => ec_k as usize + ec_global_parity as usize,
                ErasureType::ErasureLrc => {
                    ec_k as usize + ec_local_parity as usize + ec_global_parity as usize
                }
                ErasureType::ErasureReplication => replication_count as usize,
            };
            let pg = self
                .placement_group(&pool_name, pg_id)
                .filter(|pg| pg.acting.len() == expected_shards && expected_shards > 0);
            let pg = match pg {
                Some(pg) => Some(self.with_usable_acting(pg).await),
                None => None,
            };
            if let Some(pg) = pg {
                let nodes_snap = self.osd_nodes.read();
                let placements: Vec<NodePlacement> = pg
                    .acting
                    .iter()
                    .enumerate()
                    .map(|(pos, osd_bytes)| {
                        let node = nodes_snap
                            .iter()
                            .find(|n| n.node_id.as_slice() == osd_bytes.as_slice());
                        // A member set out (or draining) that nothing could
                        // stand in for is placed with no address: nothing
                        // new goes to it, the write lands on the others and
                        // is recorded short, as Ceph writes an undersized
                        // PG. Repair fills the position once it has a home.
                        let (node_address, disk_id) = match node {
                            Some(n) => (
                                if n.admin_state == objectio_common::OsdAdminState::In {
                                    n.address.clone()
                                } else {
                                    String::new()
                                },
                                n.disk_ids
                                    .first()
                                    .map(|d| d.to_vec())
                                    .unwrap_or_else(|| vec![0u8; 16]),
                            ),
                            None => (String::new(), vec![0u8; 16]),
                        };
                        let te_segment = node.map(|n| n.te_segment.clone()).unwrap_or_default();
                        let shard_type = pg_position_shard_type(
                            ec_type,
                            pos,
                            ec_k as usize,
                            ec_local_parity as usize,
                            local_group_size as usize,
                        );
                        let local_group = pg_position_local_group(
                            ec_type,
                            pos,
                            ec_k as usize,
                            ec_local_parity as usize,
                            local_group_size as usize,
                        );
                        NodePlacement {
                            position: pos as u32,
                            node_id: osd_bytes.clone(),
                            node_address,
                            disk_id,
                            shard_type: shard_type.into(),
                            local_group,
                            te_segment,
                        }
                    })
                    .collect();
                drop(nodes_snap);
                debug!(
                    "PG placement for {}/{}: pool={}, pg_id={}, epoch {}, {} shards",
                    req.bucket,
                    req.key,
                    pool_name,
                    pg_id,
                    pg.epoch,
                    placements.len()
                );
                return Ok(Response::new(self.with_dedup(
                    &req.bucket,
                    GetPlacementResponse {
                        storage_class: req.storage_class.clone(),
                        ec_k,
                        ec_m: ec_local_parity + ec_global_parity,
                        nodes: placements,
                        ec_type: ec_type.into(),
                        ec_local_parity,
                        ec_global_parity,
                        local_group_size,
                        replication_count,
                        pg_id,
                        // Below level 7 an acting set is not committed
                        // before use, and OSDs don't check.
                        pg_epoch: if pg_placement { pg.epoch } else { 0 },
                        pool: pool_name.clone(),
                        dedup_mode: 0,
                        dedup_domain: String::new(),
                    },
                )));
            }
            if pg_placement {
                return Err(Status::unavailable(format!(
                    "placement group {pool_name}/{pg_id} is not ready; retry"
                )));
            }
            warn!("PG {pool_name}/{pg_id} missing or of the wrong size; falling back to CRUSH");
        }

        // Use CRUSH 2.0 for placement
        let crush = self.crush.read();
        let hrw_placements = crush.select_placement(&object_id, &template);
        drop(crush);

        // Convert HRW placements to NodePlacement responses
        let nodes = self.osd_nodes.read();
        let placements: Vec<NodePlacement> = hrw_placements
            .iter()
            .map(|hrw| {
                // Find the OSD node by NodeId
                let node = nodes
                    .iter()
                    .find(|n| NodeId::from_bytes(n.node_id) == hrw.node_id);

                let (node_address, disk_id) = match node {
                    Some(n) => {
                        let disk = n
                            .disk_ids
                            .first()
                            .map(|d| d.to_vec())
                            .unwrap_or_else(|| vec![0u8; 16]);
                        (n.address.clone(), disk)
                    }
                    None => {
                        // Node not found in legacy list, use placeholder
                        warn!("Node {} not found in OSD list", hrw.node_id);
                        (String::new(), hrw.node_id.as_bytes().to_vec())
                    }
                };

                let te_segment = node.map(|n| n.te_segment.clone()).unwrap_or_default();

                let shard_type = match hrw.role {
                    ShardRole::Data => ShardType::ShardData.into(),
                    ShardRole::LocalParity => ShardType::ShardLocalParity.into(),
                    ShardRole::GlobalParity => ShardType::ShardGlobalParity.into(),
                };

                NodePlacement {
                    position: hrw.position as u32,
                    node_id: hrw.node_id.as_bytes().to_vec(),
                    node_address,
                    disk_id,
                    shard_type,
                    local_group: hrw.local_group.unwrap_or(0) as u32,
                    te_segment,
                }
            })
            .collect();

        debug!(
            "CRUSH 2.0 placement for {}/{}: {} shards using {:?}",
            req.bucket,
            req.key,
            placements.len(),
            ec_type
        );

        Ok(Response::new(self.with_dedup(
            &req.bucket,
            GetPlacementResponse {
                storage_class: req.storage_class.clone(),
                ec_k,
                ec_m: ec_local_parity + ec_global_parity,
                nodes: placements,
                ec_type: ec_type.into(),
                ec_local_parity,
                ec_global_parity,
                local_group_size,
                replication_count,
                // Placed without a placement group: a key written before
                // level 7, or a pool made before it without PGs.
                pg_id: 0,
                pg_epoch: 0,
                pool: String::new(),
                dedup_mode: 0,
                dedup_domain: String::new(),
            },
        )))
    }

    pub(crate) async fn get_metrics(
        &self,
        _request: Request<objectio_proto::metadata::GetMetricsRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetMetricsResponse>, Status> {
        Ok(Response::new(
            objectio_proto::metadata::GetMetricsResponse {
                text: self.metrics_renderer.get().map(|f| f()).unwrap_or_default(),
                process_instance: objectio_common::process_metrics::instance_id().to_string(),
            },
        ))
    }

    pub(crate) async fn register_osd(
        &self,
        request: Request<RegisterOsdRequest>,
    ) -> Result<Response<RegisterOsdResponse>, Status> {
        let req = request.into_inner();

        // Validate node_id is 16 bytes
        if req.node_id.len() != 16 {
            return Err(Status::invalid_argument("node_id must be 16 bytes"));
        }
        // Back on a blank disk (the documented replacement: same OSD, new
        // drive): every shard it held is one short until rebuilt, and the
        // walk would get to them only when next due.
        if req.shards_dropped > 0 {
            warn!(
                "OSD {} at {} came back without {} shards (its disk was replaced or wiped); \
                 repair walk starting now",
                hex::encode(&req.node_id),
                req.address,
                req.shards_dropped
            );
            crate::repair::walk_now();
            // Its placement groups are listed at the next look, and
            // recovery rebuilds what they lack (B31 phase 3a).
            self.mark_osd_dirty(&req.node_id);
        }

        // Resolve cluster_uuid upfront — any resolution that goes to
        // Raft needs to finish before we grab the osd_nodes write lock,
        // otherwise the parking_lot guard would be held across an
        // await and poison the future's Send bound.
        let cluster_uuid = self.cluster_uuid().await;

        let mut node_id = [0u8; 16];
        node_id.copy_from_slice(&req.node_id);

        // Parse disk IDs
        let mut disk_ids = Vec::new();
        for disk_id in &req.disk_ids {
            if disk_id.len() != 16 {
                return Err(Status::invalid_argument("disk_id must be 16 bytes"));
            }
            let mut id = [0u8; 16];
            id.copy_from_slice(disk_id);
            disk_ids.push(id);
        }

        // An OSD must advertise an address others can reach.
        if req.address.is_empty()
            || req.address.contains("://0.0.0.0")
            || req.address.contains("://[::]")
        {
            return Err(Status::invalid_argument(format!(
                "OSD address {:?} is not reachable by others; set --advertise-addr",
                req.address
            )));
        }

        // One capacity per disk, index-aligned with disk_ids.
        if req.disk_capacity_bytes.len() != disk_ids.len() {
            return Err(Status::invalid_argument(
                "disk_capacity_bytes length must match disk_ids",
            ));
        }
        let disk_capacity_bytes = req.disk_capacity_bytes.clone();

        // Register the OSD, with its 5-level topology.
        let topology_tuple = req.failure_domain.as_ref().map(|fd| {
            (
                fd.region.clone(),
                fd.zone.clone(),
                fd.datacenter.clone(),
                fd.rack.clone(),
                fd.host.clone(),
            )
        });
        let num_disks = disk_ids.len();
        // Preserve operator intent across re-registrations: an OSD marked
        // Out or Draining that re-registers stays out of placement until an
        // admin flips it back. Only for the same OSD: a new one at another's
        // address is a replacement and joins In.
        let prev_admin_state = {
            let nodes = self.osd_nodes.read();
            nodes
                .iter()
                .find(|n| n.node_id == node_id)
                .map(|n| n.admin_state)
                .unwrap_or_default()
        };
        let node = OsdNode {
            node_id,
            address: req.address.clone(),
            disk_ids,
            topology: topology_tuple,
            disk_capacity_bytes,
            admin_state: prev_admin_state,
            te_segment: req.te_segment.clone(),
        };

        // Check if node already exists and update, or add new. A new
        // node_id at an address another OSD holds is a replacement: the old
        // OSD lost its drive or its state (an OSD's identity is on both), so
        // what it held must be rebuilt elsewhere (B26). It stays registered,
        // Out and with no address (nothing answers for it now), and is
        // evacuated from the other copies; its entry goes once that is done.
        // One that a drain already emptied (it has a purge record) goes now.
        let mut lost: Vec<OsdNode> = Vec::new();
        let evicted_ids = {
            let mut nodes = self.osd_nodes.write();
            let mut evicted_ids: Vec<[u8; 16]> = Vec::new();
            if let Some(existing) = nodes.iter_mut().find(|n| n.node_id == node_id) {
                existing.address = node.address.clone();
                existing.disk_ids = node.disk_ids.clone();
                existing.disk_capacity_bytes = node.disk_capacity_bytes.clone();
                existing.topology = node.topology.clone();
                existing.te_segment = node.te_segment.clone();
                info!(
                    "Updated OSD registration: {} at {}",
                    hex::encode(node_id),
                    req.address
                );
            } else {
                for n in nodes.iter_mut() {
                    if n.address != req.address || n.node_id == node_id {
                        continue;
                    }
                    if self.purge_state(n.node_id).is_some() {
                        evicted_ids.push(n.node_id);
                    } else {
                        warn!(
                            "OSD {} at {} was replaced by {}: it is lost; setting it out to \
                             rebuild what it held from the other copies",
                            hex::encode(n.node_id),
                            req.address,
                            hex::encode(node_id)
                        );
                        n.admin_state = objectio_common::OsdAdminState::Out;
                        n.address = String::new();
                        lost.push(n.clone());
                    }
                }
                nodes.retain(|n| !evicted_ids.contains(&n.node_id));
                if !evicted_ids.is_empty() {
                    info!(
                        "Removed {} drained OSD entry/entries at address {} (node_id changed)",
                        evicted_ids.len(),
                        req.address
                    );
                }
                info!(
                    "Registered new OSD: {} at {} with {} disks",
                    hex::encode(node_id),
                    req.address,
                    num_disks
                );
                nodes.push(node.clone());
            }
            evicted_ids
        };

        // Drop the drained entries from the CRUSH topology so listings and
        // placement see a clean view. A lost OSD stays in it, Out (which
        // placement skips), as its stored entry puts it on every node: it
        // was removed here, and stayed removed on this node whenever the
        // apply of its entry ran first, so this node's listings lost it
        // while it was still being evacuated, and differed from the
        // followers'.
        if !evicted_ids.is_empty() {
            let mut topology = self.topology.write();
            for id in &evicted_ids {
                topology.remove_node(NodeId::from_bytes(*id));
            }
        }
        for n in &lost {
            self.refresh_topology_node(n);
        }

        // Add (or refresh) THIS OSD in the topology. Without this, a
        // freshly-registered OSD whose state PVC was wiped — so it comes
        // back with a new node_id — never joins the CRUSH placement set,
        // because the old node_id was evicted but the new one was never
        // inserted. Symptom on the cluster: writes and rebalance both
        // skip the OSD forever, its shard count stays at 0. Update the
        // topology now so `active_nodes()` sees the new node_id right
        // away; the CRUSH engine gets rebuilt inside
        // `update_topology_with_node`.
        self.update_topology_with_node(&node);

        // Persist through Raft, so a new leader knows every OSD (it used to
        // know only those that registered with it: none, after failover).
        // The topology is rebuilt from the OSD records on load.
        let mut writes = vec![(
            OSD_NODES_TABLE,
            hex::encode(node_id),
            Some(
                objectio_meta_store::record::serialize(&node)
                    .map_err(|e| Status::internal(format!("OSD encode: {e}")))?,
            ),
        )];
        writes.extend(
            evicted_ids
                .iter()
                .map(|id| (OSD_NODES_TABLE, hex::encode(id), None)),
        );
        for n in &lost {
            writes.push((
                OSD_NODES_TABLE,
                hex::encode(n.node_id),
                Some(
                    objectio_meta_store::record::serialize(n)
                        .map_err(|e| Status::internal(format!("OSD encode: {e}")))?,
                ),
            ));
        }
        self.replicate(writes, "register-osd").await?;

        // Get current topology version
        let topology_version = self.topology.read().version;

        Ok(Response::new(RegisterOsdResponse {
            success: true,
            topology_version,
            cluster_uuid,
            // Every PG's epoch, members or not: an OSD dropped from a PG
            // while it was down must still refuse writes placed under the
            // epoch it was a member in.
            pg_epochs: self.pg_epochs(),
        }))
    }

    pub(crate) async fn get_config(
        &self,
        request: Request<GetConfigRequest>,
    ) -> Result<Response<GetConfigResponse>, Status> {
        let req = request.into_inner();
        let config = self.config.read();
        match config.get(&req.key) {
            Some(entry) => Ok(Response::new(GetConfigResponse {
                entry: Some(entry.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetConfigResponse {
                entry: None,
                found: false,
            })),
        }
    }

    pub(crate) async fn set_config(
        &self,
        request: Request<SetConfigRequest>,
    ) -> Result<Response<SetConfigResponse>, Status> {
        let req = request.into_inner();

        if req.key.is_empty() {
            return Err(Status::invalid_argument("config key is required"));
        }
        if req.key == objectio_common::version::ACTIVE_LEVEL_KEY {
            return Err(Status::permission_denied(
                "the active format level is raised only by finalizing an upgrade",
            ));
        }

        // Consensus path: if Raft is wired, every config write has to
        // commit through the log. Non-leader nodes reject with a leader
        // hint so the client (gateway) can retry against the right pod.
        if let Some(raft) = self.raft_handle() {
            match raft
                .client_write(objectio_meta_store::MetaCommand::SetConfig {
                    key: req.key.clone(),
                    value: req.value.clone(),
                    updated_by: req.updated_by.clone(),
                    updated_at: Self::current_timestamp(),
                })
                .await
            {
                Ok(resp) => {
                    // The state machine wrote to the CONFIG redb table
                    // with a monotonic version inside apply. Mirror that
                    // entry into the in-memory map on the leader so
                    // local reads see the new value without a redb hit.
                    // Followers pick it up via apply on their own copy,
                    // but their in-memory map is not updated until R1's
                    // follow-up adds an apply listener.
                    let version = match resp.data {
                        objectio_meta_store::MetaResponse::ConfigSet { version } => version,
                        _ => 0,
                    };
                    let now = Self::current_timestamp();
                    let entry = ConfigEntry {
                        key: req.key.clone(),
                        value: req.value.clone(),
                        updated_at: now,
                        updated_by: req.updated_by.clone(),
                        version,
                    };
                    self.config.write().insert(req.key.clone(), entry.clone());
                    self.config_version
                        .store(version, std::sync::atomic::Ordering::SeqCst);

                    info!(
                        "Config set via Raft: key={} version={} log_id={:?}",
                        req.key, version, resp.log_id
                    );
                    return Ok(Response::new(SetConfigResponse { entry: Some(entry) }));
                }
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        }

        // Legacy direct-redb path — tests without a Raft handle fall
        // through here; production deployments always have Raft set.
        let version = self
            .config_version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        let now = Self::current_timestamp();

        let entry = ConfigEntry {
            key: req.key.clone(),
            value: req.value,
            updated_at: now,
            updated_by: req.updated_by,
            version,
        };

        if let Some(store) = &self.store {
            store.put_config(&req.key, &entry.encode_to_vec());
        }
        self.config.write().insert(req.key.clone(), entry.clone());

        info!(
            "Config set (legacy path): key={}, version={}",
            req.key, version
        );
        Ok(Response::new(SetConfigResponse { entry: Some(entry) }))
    }

    pub(crate) async fn delete_config(
        &self,
        request: Request<DeleteConfigRequest>,
    ) -> Result<Response<DeleteConfigResponse>, Status> {
        let req = request.into_inner();
        if req.key == objectio_common::version::ACTIVE_LEVEL_KEY {
            return Err(Status::permission_denied(
                "the active format level is raised only by finalizing an upgrade",
            ));
        }

        if let Some(raft) = self.raft_handle() {
            match raft
                .client_write(objectio_meta_store::MetaCommand::DeleteConfig {
                    key: req.key.clone(),
                })
                .await
            {
                Ok(resp) => {
                    let existed = matches!(
                        resp.data,
                        objectio_meta_store::MetaResponse::ConfigDeleted { existed: true }
                    );
                    if existed {
                        self.config.write().remove(&req.key);
                        info!(
                            "Config deleted via Raft: key={} log_id={:?}",
                            req.key, resp.log_id
                        );
                    }
                    return Ok(Response::new(DeleteConfigResponse { success: existed }));
                }
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        }

        // Legacy direct path.
        let removed = self.config.write().remove(&req.key).is_some();
        if removed {
            if let Some(store) = &self.store {
                store.delete_config(&req.key);
            }
            info!("Config deleted (legacy path): key={}", req.key);
        }

        Ok(Response::new(DeleteConfigResponse { success: removed }))
    }

    pub(crate) async fn set_osd_admin_state(
        &self,
        request: Request<SetOsdAdminStateRequest>,
    ) -> Result<Response<SetOsdAdminStateResponse>, Status> {
        let req = request.into_inner();

        // node_id must be 16 bytes (UUID).
        let node_id: [u8; 16] = req
            .node_id
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("node_id must be 16 bytes"))?;

        // Map wire enum → internal enum. Proto's numeric `i32` reaches us
        // here; rely on the generated accessor to handle unknown values.
        // prost prefixes the proto enum variants with the enum name; map
        // them back to our internal OsdAdminState.
        let state = match objectio_proto::metadata::OsdAdminState::try_from(req.state) {
            Ok(objectio_proto::metadata::OsdAdminState::OsdAdminIn) => {
                objectio_common::OsdAdminState::In
            }
            Ok(objectio_proto::metadata::OsdAdminState::OsdAdminOut) => {
                objectio_common::OsdAdminState::Out
            }
            Ok(objectio_proto::metadata::OsdAdminState::OsdAdminDraining) => {
                objectio_common::OsdAdminState::Draining
            }
            Err(_) => {
                return Err(Status::invalid_argument(format!(
                    "unknown OsdAdminState: {}",
                    req.state
                )));
            }
        };

        let requested_by = if req.requested_by.is_empty() {
            "meta".to_string()
        } else {
            req.requested_by.clone()
        };

        // A drained OSD comes back only once it's been wiped: until then it
        // holds stale copies of metadata (objects deleted since would
        // reappear) and shards nothing refers to.
        let purge = self.purge_state(node_id);
        if state != objectio_common::OsdAdminState::Out
            && purge.as_deref() == Some(crate::drain_observer::PURGE_PENDING)
        {
            return Err(Status::failed_precondition(
                "this OSD was drained and is still being purged; it can rejoin once that's done",
            ));
        }

        // Raft is the only write path. set_osd_admin_state persists to
        // OSD_NODES inside apply, which every follower also observes.
        let raft = self.raft_handle().ok_or_else(|| {
            Status::failed_precondition(
                "raft is not initialized — run POST /init on meta admin port",
            )
        })?;

        let resp = raft
            .client_write(objectio_meta_store::MetaCommand::SetOsdAdminState {
                node_id,
                state,
                requested_by,
            })
            .await
            .map_err(|e| raft_write_to_status(&e))?;

        let (found, changed) = match resp.data {
            objectio_meta_store::MetaResponse::OsdAdminStateSet { found, changed } => {
                (found, changed)
            }
            _ => (false, false),
        };

        // Mirror the change into the in-memory OsdNode list at once, for
        // this call's own topology rebuild; every node (this one too) also
        // gets it from the apply event the command emits.
        if found && changed {
            let mut nodes = self.osd_nodes.write();
            if let Some(n) = nodes.iter_mut().find(|n| n.node_id == node_id) {
                n.admin_state = state;
            }
        }

        // Rebuild the placement topology so the next `place_object`
        // call respects the new state immediately.
        if found && changed {
            let snapshot = self.osd_nodes.read().clone();
            for osd in &snapshot {
                self.refresh_topology_node(osd);
            }
            info!(
                "OSD {} admin_state → {} (via Raft, log_id={:?})",
                hex::encode(node_id),
                state.as_str(),
                resp.log_id
            );
        } else if !found {
            warn!(
                "set_osd_admin_state: no OSD with node_id={}",
                hex::encode(node_id)
            );
        }

        // Back in service after a purge: it starts clean, and a later
        // drain starts a new record.
        if found
            && state != objectio_common::OsdAdminState::Out
            && purge.as_deref() == Some(crate::drain_observer::PURGE_DONE)
            && let Err(e) = self.set_purge_state(node_id, None).await
        {
            warn!("clearing purge state for {}: {e}", hex::encode(node_id));
        }

        Ok(Response::new(SetOsdAdminStateResponse {
            found,
            changed,
            effective: req.state,
        }))
    }

    pub(crate) async fn get_drain_status(
        &self,
        _request: Request<GetDrainStatusRequest>,
    ) -> Result<Response<GetDrainStatusResponse>, Status> {
        let snapshot = self.drain_statuses_snapshot();
        let drains: Vec<ProtoDrainStatus> = snapshot
            .into_iter()
            .map(|(node_id, p)| ProtoDrainStatus {
                node_id: node_id.to_vec(),
                shards_remaining: p.shards_remaining,
                initial_shards: p.initial_shards,
                shards_migrated: p.shards_migrated,
                updated_at: p.updated_at,
                last_error: p.last_error,
            })
            .collect();
        Ok(Response::new(GetDrainStatusResponse { drains }))
    }

    pub(crate) async fn get_rebalance_status(
        &self,
        _request: Request<GetRebalanceStatusRequest>,
    ) -> Result<Response<GetRebalanceStatusResponse>, Status> {
        let p = self.rebalance_progress_snapshot();
        // `paused` is sourced from the live config each request; the
        // cached field is kept for the reconciler's fast path.
        let paused = self.is_rebalance_paused();
        // `paused` merges two sources: the live `rebalance/paused`
        // config (legacy gate) and `balancer/paused` (PG engine). The
        // balancer itself mirrors its flag into `p.paused`, so OR'ing
        // with `is_rebalance_paused()` gives a single "anything
        // paused" signal to the UI.
        let paused = paused || p.paused;
        Ok(Response::new(GetRebalanceStatusResponse {
            started: p.started,
            paused,
            last_sweep_at: p.last_sweep_at,
            scanned_this_pass: p.scanned_this_pass,
            drifts_seen_this_pass: p.drifts_seen_this_pass,
            shards_rebalanced_total: p.shards_rebalanced_total,
            last_error: p.last_error,
            pgs_moved_total: p.pgs_moved_total,
            pg_candidates_last_tick: p.pg_candidates_last_tick,
            pgs_scanned_last_tick: p.pgs_scanned_last_tick,
        }))
    }

    pub(crate) async fn list_config(
        &self,
        request: Request<ListConfigRequest>,
    ) -> Result<Response<ListConfigResponse>, Status> {
        let req = request.into_inner();
        let config = self.config.read();

        let entries: Vec<ConfigEntry> = if req.prefix.is_empty() {
            config.values().cloned().collect()
        } else {
            config
                .iter()
                .filter(|(k, _)| k.starts_with(&req.prefix))
                .map(|(_, v)| v.clone())
                .collect()
        };

        Ok(Response::new(ListConfigResponse { entries }))
    }

    pub(crate) async fn create_pool(
        &self,
        request: Request<CreatePoolRequest>,
    ) -> Result<Response<CreatePoolResponse>, Status> {
        let pool = request
            .into_inner()
            .pool
            .ok_or_else(|| Status::invalid_argument("missing pool"))?;
        if pool.name.is_empty() {
            return Err(Status::invalid_argument("pool name is required"));
        }
        if self.pools.read().contains_key(&pool.name) {
            return Err(Status::already_exists(format!(
                "pool '{}' already exists",
                pool.name
            )));
        }
        let mut pool = pool;
        // From level 7 every pool places through placement groups (B31): a
        // pool made without a count gets the default, and one that names no
        // failure domain spreads over the widest level with enough domains.
        if super::pgs::pg_placement() {
            if pool.pg_count == 0 {
                pool.pg_count = super::pgs::DEFAULT_PG_COUNT;
            }
            if pool.failure_domain.is_empty() {
                let copies = super::pgs::copy_count(&pool);
                pool.failure_domain = self
                    .widest_feasible_domain(copies)
                    .ok_or_else(|| {
                        Status::failed_precondition(format!(
                            "pool '{}' needs {copies} OSDs in service to spread its copies over",
                            pool.name
                        ))
                    })?
                    .to_string();
            }
        }
        // A pool with placement groups is refused up front when the
        // topology can't spread a PG's copies across failure domains: it
        // used to be created anyway, with no PGs, a warning in meta's log,
        // and its objects placed some other way.
        if pool.pg_count > 0 {
            let (_, rule, _) = self.pg_copysets(&pool).map_err(|e| {
                let why = format!(
                    "pool '{}' can't have placement groups on this topology: {}",
                    pool.name,
                    e.message()
                );
                if e.code() == tonic::Code::InvalidArgument {
                    Status::invalid_argument(why)
                } else {
                    Status::failed_precondition(why)
                }
            })?;
            if !super::pgs::tolerates_domain_loss(&pool, &rule) {
                warn!(
                    "pool '{}': its placement rule ({} {:?}s, up to {} copies in one) does \
                     not survive a whole {:?} lost; objects are unreadable while one is down",
                    pool.name, rule.domains, rule.level, rule.per_domain, rule.level
                );
            }
        }
        pool.created_at = Self::current_timestamp();
        pool.updated_at = pool.created_at;
        let bytes = pool.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Pools,
                    key: pool.name.clone(),
                    expected: None,
                    new_value: Some(bytes),
                }],
                requested_by: "create-pool".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::already_exists("pool already exists"));
                    }
                    other => {
                        error!("unexpected raft response for create_pool: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_pool(&pool.name, &pool.encode_to_vec());
        }

        self.pools.write().insert(pool.name.clone(), pool.clone());
        info!("Created pool: {}", pool.name);

        // Pre-allocate placement groups if the pool opted in. Done
        // after the pool row is committed so a partial failure here
        // leaves a pool with pg_count>0 but no PGs — the balancer
        // (Phase 4) will detect that and regenerate. Fatal errors
        // from allocation surface as status; gateway retries.
        if pool.pg_count > 0
            && let Err(e) = self.preallocate_placement_groups(&pool).await
        {
            warn!(
                "pool '{}' created but PG pre-allocation failed: {}",
                pool.name, e
            );
        }

        Ok(Response::new(CreatePoolResponse { pool: Some(pool) }))
    }

    pub(crate) async fn get_pool(
        &self,
        request: Request<GetPoolRequest>,
    ) -> Result<Response<GetPoolResponse>, Status> {
        let name = request.into_inner().name;
        let pools = self.pools.read();
        match pools.get(&name) {
            Some(pool) => Ok(Response::new(GetPoolResponse {
                pool: Some(pool.clone()),
                found: true,
            })),
            None => Ok(Response::new(GetPoolResponse {
                pool: None,
                found: false,
            })),
        }
    }

    pub(crate) async fn list_pools(
        &self,
        _request: Request<ListPoolsRequest>,
    ) -> Result<Response<ListPoolsResponse>, Status> {
        let pools = self.pools.read();
        Ok(Response::new(ListPoolsResponse {
            pools: pools.values().cloned().collect(),
        }))
    }

    pub(crate) async fn update_pool(
        &self,
        request: Request<UpdatePoolRequest>,
    ) -> Result<Response<UpdatePoolResponse>, Status> {
        let mut pool = request
            .into_inner()
            .pool
            .ok_or_else(|| Status::invalid_argument("missing pool"))?;
        let expected_bytes = {
            let pools = self.pools.read();
            let current = pools
                .get(&pool.name)
                .ok_or_else(|| Status::not_found(format!("pool '{}' not found", pool.name)))?;
            // Its placement groups were made by these: changed, a PG's
            // members would no longer keep the pool's rule (B31 phase 1b).
            let placement = |p: &PoolConfig| {
                (
                    p.pg_count,
                    p.failure_domain.clone(),
                    p.spread_domains,
                    p.per_domain,
                    p.lrc_groups_per_domain,
                    (
                        p.ec_type,
                        p.ec_k,
                        p.ec_m,
                        p.ec_local_parity,
                        p.ec_global_parity,
                    ),
                    p.replication_count,
                )
            };
            if current.pg_count > 0 && placement(current) != placement(&pool) {
                return Err(Status::failed_precondition(format!(
                    "pool '{}': its protection, failure domain, placement rule and placement \
                     groups are fixed when it is made; make a new pool for others",
                    pool.name
                )));
            }
            current.encode_to_vec()
        };
        pool.updated_at = Self::current_timestamp();
        let new_bytes = pool.encode_to_vec();

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Pools,
                    key: pool.name.clone(),
                    expected: Some(expected_bytes),
                    new_value: Some(new_bytes),
                }],
                requested_by: "update-pool".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("pool changed since read; retry update"));
                    }
                    other => {
                        error!("unexpected raft response for update_pool: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.put_pool(&pool.name, &pool.encode_to_vec());
        }

        self.pools.write().insert(pool.name.clone(), pool.clone());
        info!("Updated pool: {}", pool.name);
        Ok(Response::new(UpdatePoolResponse { pool: Some(pool) }))
    }

    pub(crate) async fn delete_pool(
        &self,
        request: Request<DeletePoolRequest>,
    ) -> Result<Response<DeletePoolResponse>, Status> {
        let name = request.into_inner().name;
        if name == "default" {
            return Err(Status::invalid_argument("cannot delete the default pool"));
        }
        // Its buckets' objects were placed by it: without it they'd be
        // looked for where the default placement puts them.
        let users: Vec<String> = self
            .buckets
            .read()
            .values()
            .filter(|b| b.pool == name)
            .map(|b| b.name.clone())
            .take(5)
            .collect();
        if !users.is_empty() {
            return Err(Status::failed_precondition(format!(
                "pool '{name}' holds buckets ({}{}); delete them first",
                users.join(", "),
                if users.len() == 5 { ", ..." } else { "" }
            )));
        }
        // Tenants that default to it, or may choose it, are reconfigured
        // first.
        if let Some(t) = self
            .tenants
            .read()
            .values()
            .find(|t| t.default_pool == name || t.allowed_pools.contains(&name))
        {
            return Err(Status::failed_precondition(format!(
                "tenant '{}' refers to pool '{name}'; change its pools first",
                t.name
            )));
        }
        let expected_bytes = self.pools.read().get(&name).map(|p| p.encode_to_vec());
        if expected_bytes.is_none() {
            return Ok(Response::new(DeletePoolResponse { success: false }));
        }

        if let Some(raft) = self.raft_handle() {
            use objectio_meta_store::{CasOp, CasTable, MetaCommand, MetaResponse};
            let cmd = MetaCommand::MultiCas {
                ops: vec![CasOp {
                    table: CasTable::Pools,
                    key: name.clone(),
                    expected: expected_bytes,
                    new_value: None,
                }],
                requested_by: "delete-pool".into(),
            };
            match raft.client_write(cmd).await {
                Ok(r) => match r.data {
                    MetaResponse::MultiCasOk => {}
                    MetaResponse::MultiCasConflict { .. } => {
                        return Err(Status::aborted("pool changed since read; retry delete"));
                    }
                    other => {
                        error!("unexpected raft response for delete_pool: {:?}", other);
                        return Err(Status::internal("raft commit wrong variant"));
                    }
                },
                Err(e) => return Err(raft_write_to_status(&e)),
            }
        } else if let Some(store) = &self.store {
            store.delete_pool(&name);
        }

        self.pools.write().remove(&name);
        info!("Deleted pool: {}", name);
        Ok(Response::new(DeletePoolResponse { success: true }))
    }

    // Placement groups: the balancer owns writes (via
    // CasTable::PlacementGroups MultiCas); the gateway only reads, so only
    // Get + List are exposed.
    pub(crate) async fn get_placement_group(
        &self,
        request: Request<GetPlacementGroupRequest>,
    ) -> Result<Response<GetPlacementGroupResponse>, Status> {
        let req = request.into_inner();
        let pg = self.placement_group(&req.pool, req.pg_id);
        let found = pg.is_some();
        let state = self.pg_state(&req.pool, req.pg_id);
        let scrub = self.pg_scrub(&req.pool, req.pg_id);
        Ok(Response::new(GetPlacementGroupResponse {
            pg,
            found,
            state,
            scrub,
        }))
    }

    pub(crate) async fn list_placement_groups(
        &self,
        request: Request<ListPlacementGroupsRequest>,
    ) -> Result<Response<ListPlacementGroupsResponse>, Status> {
        let req = request.into_inner();
        let max = if req.max_results == 0 {
            1000usize
        } else {
            (req.max_results as usize).min(10_000)
        };
        let mut pgs: Vec<PlacementGroup> = self
            .placement_groups
            .read()
            .iter()
            .filter(|((p, id), _)| p == &req.pool && *id >= req.start_at_pg_id)
            .map(|(_, v)| v.clone())
            .collect();
        pgs.sort_by_key(|p| p.pg_id);
        // The first PG not listed starts the next page.
        let next_pg_id = pgs.get(max).map_or(0, |p| p.pg_id);
        pgs.truncate(max);
        let mut all_states = self.pg_states(&req.pool);
        let states = pgs
            .iter()
            .filter_map(|pg| all_states.remove(&pg.pg_id))
            .collect();
        let mut all_scrubs = self.pg_scrubs(&req.pool);
        let scrubs = pgs
            .iter()
            .filter_map(|pg| all_scrubs.remove(&pg.pg_id))
            .collect();
        Ok(Response::new(ListPlacementGroupsResponse {
            pgs,
            next_pg_id,
            states,
            scrubs,
        }))
    }

    pub(crate) async fn report_version(
        &self,
        request: Request<objectio_proto::metadata::ReportVersionRequest>,
    ) -> Result<Response<objectio_proto::metadata::ReportVersionResponse>, Status> {
        let active_level = self.record_version(request.into_inner());
        Ok(Response::new(
            objectio_proto::metadata::ReportVersionResponse { active_level },
        ))
    }

    pub(crate) async fn get_upgrade_status(
        &self,
        _request: Request<objectio_proto::metadata::GetUpgradeStatusRequest>,
    ) -> Result<Response<objectio_proto::metadata::GetUpgradeStatusResponse>, Status> {
        let plan = self.upgrade_plan();
        Ok(Response::new(
            objectio_proto::metadata::GetUpgradeStatusResponse {
                active_level: plan.active,
                nodes: plan.nodes,
                finalize_to: plan.target,
                blockers: plan.blockers,
            },
        ))
    }

    pub(crate) async fn finalize_upgrade(
        &self,
        request: Request<objectio_proto::metadata::FinalizeUpgradeRequest>,
    ) -> Result<Response<objectio_proto::metadata::FinalizeUpgradeResponse>, Status> {
        let active_level = self.finalize(&request.into_inner().requested_by).await?;
        Ok(Response::new(
            objectio_proto::metadata::FinalizeUpgradeResponse { active_level },
        ))
    }

    pub(crate) async fn acquire_lease(
        &self,
        request: Request<objectio_proto::metadata::AcquireLeaseRequest>,
    ) -> Result<Response<objectio_proto::metadata::AcquireLeaseResponse>, Status> {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Lease {
            holder: String,
            expires_at: u64,
        }
        let req = request.into_inner();
        if req.name.is_empty() || req.holder.is_empty() {
            return Err(Status::invalid_argument("name and holder are required"));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let current_bytes = self
            .store
            .as_ref()
            .and_then(|s| s.read_named(LEASES_TABLE, &req.name));
        let current = current_bytes
            .as_deref()
            .and_then(|b| serde_json::from_slice::<Lease>(b).ok());
        let held_by_other = current
            .as_ref()
            .is_some_and(|l| l.holder != req.holder && l.expires_at > now);
        if held_by_other {
            let l = current.unwrap_or(Lease {
                holder: String::new(),
                expires_at: 0,
            });
            return Ok(Response::new(
                objectio_proto::metadata::AcquireLeaseResponse {
                    acquired: false,
                    holder: l.holder,
                    expires_at: l.expires_at,
                },
            ));
        }
        let (new_value, lease) = if req.release {
            (
                None,
                Lease {
                    holder: String::new(),
                    expires_at: 0,
                },
            )
        } else {
            let lease = Lease {
                holder: req.holder.clone(),
                expires_at: now + req.ttl_secs.max(1),
            };
            (serde_json::to_vec(&lease).ok(), lease)
        };
        if req.release && current.is_none() {
            return Ok(Response::new(
                objectio_proto::metadata::AcquireLeaseResponse::default(),
            ));
        }
        // Compare-and-swap on what was read: of two callers racing for a
        // free lease, one commit wins and the other is refused.
        match self
            .cas_one(
                objectio_meta_store::CasTable::Named(LEASES_TABLE.into()),
                &req.name,
                current_bytes,
                new_value,
                "acquire-lease",
            )
            .await
        {
            Ok(()) => Ok(Response::new(
                objectio_proto::metadata::AcquireLeaseResponse {
                    acquired: !req.release,
                    holder: lease.holder,
                    expires_at: lease.expires_at,
                },
            )),
            Err(e) if e.code() == tonic::Code::Aborted => Ok(Response::new(
                objectio_proto::metadata::AcquireLeaseResponse::default(),
            )),
            Err(e) => Err(e),
        }
    }

    pub(crate) async fn heal_enqueue(
        &self,
        request: Request<objectio_proto::metadata::HealEnqueueRequest>,
    ) -> Result<Response<objectio_proto::metadata::HealEnqueueResponse>, Status> {
        let req = request.into_inner();
        // A key in a placement group is its PG's (B31 phase 4): marked, its
        // PG is peered by listing, its copies brought to agree by recovery
        // and its listing entry by the peering. The queue is for keys
        // written before placement groups (the rolling upgrade's; it goes
        // in the release after).
        if self.key_pg(&req.bucket, &req.key).is_some() {
            self.mark_key_dirty(&req.bucket, &req.key);
            return Ok(Response::new(
                objectio_proto::metadata::HealEnqueueResponse {},
            ));
        }
        let key = heal_key(&req.bucket, &req.key, &req.version_id);
        // Always a fresh, unclaimed entry: a heal in progress finds it
        // changed when done, and the key is healed again.
        let entry = objectio_proto::metadata::HealEntry {
            bucket: req.bucket,
            key: req.key,
            version_id: req.version_id,
            enqueued_at_ms: unix_ms(),
            claimed_by: String::new(),
            claimed_until_ms: 0,
        };
        for _ in 0..5 {
            match self
                .cas_one(
                    objectio_meta_store::CasTable::Named(HEAL_TABLE.into()),
                    &key,
                    self.heal_entry(&key),
                    Some(entry.encode_to_vec()),
                    "heal-enqueue",
                )
                .await
            {
                Ok(()) => {
                    return Ok(Response::new(
                        objectio_proto::metadata::HealEnqueueResponse {},
                    ));
                }
                Err(s) if s.code() == tonic::Code::Aborted => {}
                Err(s) => return Err(s),
            }
        }
        Err(Status::aborted("heal-enqueue: contended; retry"))
    }

    pub(crate) async fn heal_list(
        &self,
        request: Request<objectio_proto::metadata::HealListRequest>,
    ) -> Result<Response<objectio_proto::metadata::HealListResponse>, Status> {
        let limit = match request.into_inner().limit {
            0 => 100,
            n => n as usize,
        };
        let mut entries: Vec<objectio_proto::metadata::HealEntry> = self
            .store
            .as_ref()
            .map(|s| s.list_named(HEAL_TABLE))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(_, v)| objectio_proto::metadata::HealEntry::decode(v.as_slice()).ok())
            .collect();
        entries.sort_by_key(|e| e.enqueued_at_ms);
        entries.truncate(limit);
        Ok(Response::new(objectio_proto::metadata::HealListResponse {
            entries,
        }))
    }

    pub(crate) async fn heal_claim(
        &self,
        request: Request<objectio_proto::metadata::HealClaimRequest>,
    ) -> Result<Response<objectio_proto::metadata::HealClaimResponse>, Status> {
        let req = request.into_inner();
        let listed = req
            .entry
            .ok_or_else(|| Status::invalid_argument("missing entry"))?;
        let now = unix_ms();
        if !listed.claimed_by.is_empty() && listed.claimed_until_ms > now {
            return Ok(Response::new(objectio_proto::metadata::HealClaimResponse {
                claimed: false,
                entry: Some(listed),
            }));
        }
        let key = heal_key(&listed.bucket, &listed.key, &listed.version_id);
        let claimed = objectio_proto::metadata::HealEntry {
            claimed_by: req.claimer,
            claimed_until_ms: now.saturating_add(req.lease_ms),
            ..listed.clone()
        };
        match self
            .cas_one(
                objectio_meta_store::CasTable::Named(HEAL_TABLE.into()),
                &key,
                Some(listed.encode_to_vec()),
                Some(claimed.encode_to_vec()),
                "heal-claim",
            )
            .await
        {
            Ok(()) => Ok(Response::new(objectio_proto::metadata::HealClaimResponse {
                claimed: true,
                entry: Some(claimed),
            })),
            Err(s) if s.code() == tonic::Code::Aborted => {
                Ok(Response::new(objectio_proto::metadata::HealClaimResponse {
                    claimed: false,
                    entry: None,
                }))
            }
            Err(s) => Err(s),
        }
    }

    pub(crate) async fn heal_done(
        &self,
        request: Request<objectio_proto::metadata::HealDoneRequest>,
    ) -> Result<Response<objectio_proto::metadata::HealDoneResponse>, Status> {
        let entry = request
            .into_inner()
            .entry
            .ok_or_else(|| Status::invalid_argument("missing entry"))?;
        let key = heal_key(&entry.bucket, &entry.key, &entry.version_id);
        let done = match self
            .cas_one(
                objectio_meta_store::CasTable::Named(HEAL_TABLE.into()),
                &key,
                Some(entry.encode_to_vec()),
                None,
                "heal-done",
            )
            .await
        {
            Ok(()) => true,
            Err(s) if s.code() == tonic::Code::Aborted => false,
            Err(s) => return Err(s),
        };
        Ok(Response::new(objectio_proto::metadata::HealDoneResponse {
            done,
        }))
    }
}
