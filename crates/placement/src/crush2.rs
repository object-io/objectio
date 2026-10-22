//! CRUSH 2.0 - Enhanced placement algorithm
//!
//! Improvements over traditional CRUSH:
//! - Rendezvous/HRW (Highest Random Weight) hashing for node selection
//! - EC-aware placement templates
//! - Stripe group mapping for deterministic rack assignment
//! - SIMD/RDMA-friendly design
//!
//! # Algorithm Overview
//!
//! 1. **Object → Stripe Group**: `hash(object_id) % num_groups` determines participating racks
//! 2. **EC Placement Template**: Pre-defined shard layout (e.g., LRC groups)
//! 3. **HRW Hashing per Domain**: `score(node) = hash(object_id, node_id)`, pick top K
//! 4. **Optional Scoring**: For hot data, consider network distance and load

use crate::topology::{ClusterTopology, NodeInfo};
use objectio_common::{FailureDomain, NodeId, NodeStatus, ObjectId};
use std::collections::HashMap;

/// Shard type for placement
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ShardRole {
    /// Data shard
    Data,
    /// Local parity (within group)
    LocalParity,
    /// Global parity (across groups)
    GlobalParity,
}

/// A single shard in the placement template
#[derive(Clone, Debug)]
pub struct TemplateShard {
    /// Position in the stripe (0-indexed)
    pub position: u8,
    /// Role of this shard
    pub role: ShardRole,
    /// Local group index (None for global parity)
    pub local_group: Option<u8>,
    /// Which domain slot this shard belongs to (for spreading)
    pub domain_slot: u8,
}

/// EC placement template - defines the layout for a specific EC configuration
#[derive(Clone, Debug)]
pub struct PlacementTemplate {
    /// Template name (e.g., "lrc_6_2_2")
    pub name: String,
    /// Number of data shards
    pub data_shards: u8,
    /// Number of local parity shards
    pub local_parity: u8,
    /// Number of global parity shards
    pub global_parity: u8,
    /// Shard definitions
    pub shards: Vec<TemplateShard>,
    /// Number of domain slots required
    pub domain_slots: u8,
    /// Minimum shards per domain slot
    pub shards_per_slot: u8,
}

impl PlacementTemplate {
    /// Create an MDS (Reed-Solomon) template
    ///
    /// All shards spread across different domains
    pub fn mds(k: u8, m: u8) -> Self {
        let total = k + m;
        let shards = (0..total)
            .map(|i| TemplateShard {
                position: i,
                role: if i < k {
                    ShardRole::Data
                } else {
                    ShardRole::GlobalParity
                },
                local_group: None,
                domain_slot: i, // Each shard in different domain
            })
            .collect();

        Self {
            name: format!("mds_{}_{}", k, m),
            data_shards: k,
            local_parity: 0,
            global_parity: m,
            shards,
            domain_slots: total,
            shards_per_slot: 1,
        }
    }

    /// Create an LRC template
    ///
    /// Example LRC(6,2,2):
    /// ```text
    /// Domain A (Group 0): D0 D1 D2 LP0
    /// Domain B (Group 1): D3 D4 D5 LP1
    /// Domain C (Global):  GP0 GP1
    /// ```
    pub fn lrc(k: u8, l: u8, g: u8) -> Self {
        let group_size = k / l;
        let mut shards = Vec::with_capacity((k + l + g) as usize);
        let mut position: u8 = 0;

        // Create local groups
        for group_idx in 0..l {
            // Data shards in this group
            for _ in 0..group_size {
                shards.push(TemplateShard {
                    position,
                    role: ShardRole::Data,
                    local_group: Some(group_idx),
                    domain_slot: group_idx,
                });
                position += 1;
            }
            // Local parity for this group
            shards.push(TemplateShard {
                position,
                role: ShardRole::LocalParity,
                local_group: Some(group_idx),
                domain_slot: group_idx,
            });
            position += 1;
        }

        // Global parity shards - in separate domain(s)
        let global_domain_start = l;
        for gp_idx in 0..g {
            shards.push(TemplateShard {
                position,
                role: ShardRole::GlobalParity,
                local_group: None,
                domain_slot: global_domain_start + (gp_idx / 2), // 2 global parity per domain
            });
            position += 1;
        }

        // Calculate domain slots needed
        let domain_slots = l + (g + 1).div_ceil(2); // local groups + global parity domains

        Self {
            name: format!("lrc_{}_{}_{}", k, l, g),
            data_shards: k,
            local_parity: l,
            global_parity: g,
            shards,
            domain_slots,
            shards_per_slot: group_size + 1, // data + local parity
        }
    }

    /// Total number of shards
    pub fn total_shards(&self) -> u8 {
        self.data_shards + self.local_parity + self.global_parity
    }
}

/// Stripe group - defines which domains participate for an object
#[derive(Clone, Debug)]
pub struct StripeGroup {
    /// Group ID
    pub id: u32,
    /// Domains participating in this group (ordered)
    pub domains: Vec<String>,
}

/// Detail on why a pool's placement cannot be satisfied by the current
/// topology. Returned by [`Crush2::validate_placement_feasibility`].
#[derive(Clone, Debug)]
pub enum PlacementFeasibility {
    /// Fewer distinct domain values at the required level than the pool's
    /// shard count needs. The pool can't place without either lowering the
    /// required spread or adding more failure domains.
    InsufficientDomainSpread {
        required_level: FailureDomain,
        required_count: usize,
        available_count: usize,
    },
}

impl std::fmt::Display for PlacementFeasibility {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InsufficientDomainSpread {
                required_level,
                required_count,
                available_count,
            } => write!(
                f,
                "insufficient {} spread: pool needs {} distinct {}s but topology has only {}",
                required_level, required_count, required_level, available_count
            ),
        }
    }
}

impl std::error::Error for PlacementFeasibility {}

/// Success payload: which domain keys exist at the requested level.
#[derive(Clone, Debug)]
pub struct PlacementFeasibilityReport {
    pub level: FailureDomain,
    pub available_domains: Vec<String>,
}

/// A stripe that can't be placed with every shard on an OSD of its own.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "a stripe of {needed} shards needs {needed} distinct OSDs and {usable} can take one; \
     add OSDs or bring the down ones back"
)]
pub struct TooFewOsds {
    /// Positions in the stripe.
    pub needed: usize,
    /// OSDs that can hold one: the active ones, and the down ones a write
    /// may do without.
    pub usable: usize,
}

/// Result of HRW node selection
#[derive(Clone, Debug)]
pub struct HrwPlacement {
    /// Shard position
    pub position: u8,
    /// Selected node
    pub node_id: NodeId,
    /// Shard role
    pub role: ShardRole,
    /// Local group (if applicable)
    pub local_group: Option<u8>,
    /// HRW score (for debugging/logging)
    pub score: u64,
}

/// CRUSH 2.0 placement engine
pub struct Crush2 {
    topology: ClusterTopology,
    /// Pre-computed stripe groups (domains grouped by hash)
    stripe_groups: Vec<StripeGroup>,
    /// Number of stripe groups
    num_groups: u32,
}

impl Crush2 {
    /// Create a new CRUSH 2.0 engine
    pub fn new(topology: ClusterTopology, num_groups: u32) -> Self {
        let mut engine = Self {
            topology,
            stripe_groups: Vec::new(),
            num_groups,
        };
        engine.rebuild_stripe_groups();
        engine
    }

    /// Update topology and rebuild stripe groups
    pub fn update_topology(&mut self, topology: ClusterTopology) {
        self.topology = topology;
        self.rebuild_stripe_groups();
    }

    /// Rebuild stripe groups based on current topology
    fn rebuild_stripe_groups(&mut self) {
        // Group all nodes by their rack (or other domain level)
        let domains = self.group_nodes_by_domain(FailureDomain::Rack);
        let domain_keys: Vec<String> = domains.keys().cloned().collect();

        if domain_keys.is_empty() {
            self.stripe_groups = Vec::new();
            return;
        }

        // Create stripe groups by rotating through domains
        self.stripe_groups = (0..self.num_groups)
            .map(|group_id| {
                // Rotate domains based on group ID for even distribution
                let rotation = (group_id as usize) % domain_keys.len();
                let mut group_domains: Vec<String> = domain_keys.clone();
                group_domains.rotate_left(rotation);

                StripeGroup {
                    id: group_id,
                    domains: group_domains,
                }
            })
            .collect();
    }

    /// Select placement for an object using CRUSH 2.0 algorithm
    ///
    /// # Steps:
    /// 1. Map object to stripe group
    /// 2. Apply EC placement template
    /// 3. Use HRW hashing within each domain
    ///
    /// Every position is on an OSD of its own: two shards on one OSD are
    /// lost together, and the stripe survives one failure fewer than it
    /// was written to. The failure domain is a preference (an unused OSD
    /// elsewhere beats none); a distinct OSD is not.
    ///
    /// # Errors
    /// [`TooFewOsds`] when fewer OSDs than positions can take one: the
    /// active ones, and the down ones a write may do without.
    pub fn select_placement(
        &self,
        object_id: &ObjectId,
        template: &PlacementTemplate,
    ) -> Result<Vec<HrwPlacement>, TooFewOsds> {
        // Step 1: Object → stripe group
        let object_hash = self.hash_object(object_id);
        let group_idx = (object_hash as u32) % self.num_groups;
        let stripe_group = self
            .stripe_groups
            .get(group_idx as usize)
            .cloned()
            .unwrap_or_else(|| StripeGroup {
                id: group_idx,
                domains: Vec::new(),
            });

        // Group nodes by domain
        let domain_nodes = self.group_nodes_by_domain(FailureDomain::Rack);
        let all_nodes: Vec<&NodeInfo> = self.topology.active_nodes().collect();
        // OSDs that are in but not answering: still the stripe's, for now.
        let down_nodes: Vec<&NodeInfo> = self
            .topology
            .all_nodes()
            .filter(|n| n.status == NodeStatus::Down)
            .collect();
        // How many positions may go to them: their shards aren't written
        // until they answer again, so a write must still reach its quorum,
        // k + 1, without them. Erasure-coded (MDS) stripes only.
        let mut down_allowed = if template.local_parity == 0 {
            usize::from(template.global_parity.saturating_sub(1))
        } else {
            0
        };
        let too_few = TooFewOsds {
            needed: template.shards.len(),
            usable: all_nodes.len() + down_nodes.len().min(down_allowed),
        };
        if too_few.usable < too_few.needed {
            return Err(too_few);
        }

        // Step 2 & 3: Apply template with HRW hashing per domain
        let mut placements = Vec::with_capacity(template.total_shards() as usize);

        // Nodes already holding a shard of this stripe. Tracked across the
        // whole stripe, not per domain slot: with fewer racks than slots
        // (one rack is the common case) several slots map to the same rack,
        // and per-slot tracking let every shard land on the same OSD — a
        // 4+2 object that one disk failure destroys.
        let mut used: Vec<NodeId> = Vec::with_capacity(template.shards.len());

        for shard in &template.shards {
            // Get the domain for this shard
            let domain_idx = shard.domain_slot as usize % stripe_group.domains.len().max(1);
            let domain_key = stripe_group
                .domains
                .get(domain_idx)
                .cloned()
                .unwrap_or_default();

            // Get nodes in this domain
            let nodes = domain_nodes.get(&domain_key).cloned().unwrap_or_default();

            // Prefer an unused node in the shard's own domain, then an
            // unused node anywhere (relaxing the domain beats doubling up on
            // a disk). Then an unused node that is down: the write goes on
            // without its shard (within `down_allowed`), and the repairer
            // writes it there once it is back. Never a node already holding
            // a shard of the stripe: that leaves the object one failure
            // short of its protection.
            let (node_id, score) = self
                .hrw_pick(object_id, &nodes, &used)
                .or_else(|| self.hrw_pick(object_id, &all_nodes, &used))
                .or_else(|| {
                    let pick = (down_allowed > 0)
                        .then(|| self.hrw_pick(object_id, &down_nodes, &used))
                        .flatten();
                    down_allowed -= usize::from(pick.is_some());
                    pick
                })
                .ok_or_else(|| too_few.clone())?;

            used.push(node_id);

            placements.push(HrwPlacement {
                position: shard.position,
                node_id,
                role: shard.role,
                local_group: shard.local_group,
                score,
            });
        }

        Ok(placements)
    }

    /// HRW score: `hash(object_id || node_id) * weight`.
    fn hrw_score(&self, object_id: &ObjectId, node: &NodeInfo) -> u64 {
        let node_hash = xxhash_rust::xxh64::xxh64(node.id.as_bytes(), self.hash_object(object_id));
        // Apply weight (multiply by weight * 1000 for precision)
        let weight_factor = (node.weight * 1000.0) as u64;
        node_hash.wrapping_mul(weight_factor)
    }

    /// HRW (Highest Random Weight) / Rendezvous hashing: the highest-scoring
    /// node not in `exclude`, or `None` when every node is excluded.
    ///
    /// This used to fall back to `nodes[0]` when everything was excluded,
    /// silently placing a second shard on a node that already had one.
    fn hrw_pick(
        &self,
        object_id: &ObjectId,
        nodes: &[&NodeInfo],
        exclude: &[NodeId],
    ) -> Option<(NodeId, u64)> {
        nodes
            .iter()
            .filter(|n| !exclude.contains(&n.id))
            .map(|n| (n.id, self.hrw_score(object_id, n)))
            .max_by_key(|(_, score)| *score)
    }

    /// Select multiple nodes using HRW (for simple replication/MDS)
    pub fn hrw_select_n(
        &self,
        object_id: &ObjectId,
        nodes: &[&NodeInfo],
        count: usize,
    ) -> Vec<(NodeId, u64)> {
        if nodes.is_empty() {
            return Vec::new();
        }

        let object_hash = self.hash_object(object_id);

        // Calculate scores for all nodes
        let mut scored: Vec<(NodeId, u64)> = nodes
            .iter()
            .map(|node| {
                let node_hash = xxhash_rust::xxh64::xxh64(node.id.as_bytes(), object_hash);
                let weight_factor = (node.weight * 1000.0) as u64;
                let score = node_hash.wrapping_mul(weight_factor);
                (node.id, score)
            })
            .collect();

        // Sort by score descending
        scored.sort_by(|a, b| b.1.cmp(&a.1));

        // Take top N
        scored.truncate(count);
        scored
    }

    /// Validate that the current topology can satisfy a placement that
    /// needs `required_count` distinct values at `level`.
    ///
    /// This is the hard-enforce hook: callers (meta at write time, or the
    /// admin `/placement/validate` endpoint) use this to refuse writes
    /// up-front instead of quietly degrading to a weaker spread.
    ///
    /// # Errors
    /// [`PlacementFeasibility::InsufficientDomainSpread`] when fewer than
    /// `required_count` distinct domain keys exist at the requested level
    /// (counts only active, healthy nodes).
    pub fn validate_placement_feasibility(
        &self,
        level: FailureDomain,
        required_count: usize,
    ) -> Result<PlacementFeasibilityReport, PlacementFeasibility> {
        let domains = self.group_nodes_by_domain(level);
        let available_count = domains.len();
        if available_count < required_count {
            return Err(PlacementFeasibility::InsufficientDomainSpread {
                required_level: level,
                required_count,
                available_count,
            });
        }
        Ok(PlacementFeasibilityReport {
            level,
            available_domains: domains.keys().cloned().collect(),
        })
    }

    /// Group active nodes by failure domain
    fn group_nodes_by_domain(&self, level: FailureDomain) -> HashMap<String, Vec<&NodeInfo>> {
        let mut groups: HashMap<String, Vec<&NodeInfo>> = HashMap::new();

        for node in self.topology.active_nodes() {
            let domain_key = self.get_domain_key(node, level);
            groups.entry(domain_key).or_default().push(node);
        }

        groups
    }

    /// Get domain key for a node — colon-joined prefix of topology tuple up
    /// to and including `level`. Two nodes share a key at level X iff they
    /// also share every enclosing level.
    fn get_domain_key(&self, node: &NodeInfo, level: FailureDomain) -> String {
        let fd = &node.failure_domain;
        match level {
            FailureDomain::Disk => format!("{}:disk", node.id),
            FailureDomain::Node => node.id.to_string(),
            FailureDomain::Host => format!(
                "{}:{}:{}:{}:{}",
                fd.region, fd.zone, fd.datacenter, fd.rack, fd.host
            ),
            FailureDomain::Rack => {
                format!("{}:{}:{}:{}", fd.region, fd.zone, fd.datacenter, fd.rack)
            }
            FailureDomain::Datacenter => {
                format!("{}:{}:{}", fd.region, fd.zone, fd.datacenter)
            }
            FailureDomain::Zone => format!("{}:{}", fd.region, fd.zone),
            FailureDomain::Region => fd.region.clone(),
        }
    }

    /// Hash an object ID
    fn hash_object(&self, object_id: &ObjectId) -> u64 {
        xxhash_rust::xxh64::xxh64(object_id.as_bytes(), 0)
    }

    /// Get stripe group for an object (for debugging/inspection)
    pub fn get_stripe_group(&self, object_id: &ObjectId) -> Option<&StripeGroup> {
        let object_hash = self.hash_object(object_id);
        let group_idx = (object_hash as u32) % self.num_groups;
        self.stripe_groups.get(group_idx as usize)
    }
}

/// Common placement templates
pub mod templates {
    use super::PlacementTemplate;

    /// MDS 4+2 (standard Reed-Solomon)
    pub fn mds_4_2() -> PlacementTemplate {
        PlacementTemplate::mds(4, 2)
    }

    /// MDS 8+4
    pub fn mds_8_4() -> PlacementTemplate {
        PlacementTemplate::mds(8, 4)
    }

    /// LRC 6+2+2 (Azure-like, small)
    pub fn lrc_6_2_2() -> PlacementTemplate {
        PlacementTemplate::lrc(6, 2, 2)
    }

    /// LRC 12+2+2 (Azure-like, standard)
    pub fn lrc_12_2_2() -> PlacementTemplate {
        PlacementTemplate::lrc(12, 2, 2)
    }

    /// LRC 8+2+2
    pub fn lrc_8_2_2() -> PlacementTemplate {
        PlacementTemplate::lrc(8, 2, 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::{ClusterTopology, FailureDomainInfo, NodeInfo};
    use objectio_common::NodeStatus;

    fn create_test_topology() -> ClusterTopology {
        let mut topology = ClusterTopology::new();

        // 3 racks, 4 nodes each
        for rack in 0..3 {
            for node in 0..4 {
                let info = NodeInfo {
                    id: NodeId::new(),
                    name: format!("node-r{}-n{}", rack, node),
                    address: format!("10.0.{}.{}:9002", rack, node).parse().unwrap(),
                    failure_domain: FailureDomainInfo::new(
                        "us-east",
                        "dc1",
                        &format!("rack{}", rack),
                    ),
                    status: NodeStatus::Active,
                    disks: vec![],
                    weight: 1.0,
                    last_heartbeat: 0,
                };
                topology.upsert_node(info);
            }
        }

        topology
    }

    fn single_rack_topology(nodes: usize) -> ClusterTopology {
        let mut topology = ClusterTopology::new();
        for n in 0..nodes {
            topology.upsert_node(NodeInfo {
                id: NodeId::new(),
                name: format!("node-{n}"),
                address: format!("10.0.0.{n}:9002").parse().unwrap(),
                failure_domain: FailureDomainInfo::new("us-east", "dc1", "rack0"),
                status: NodeStatus::Active,
                disks: vec![],
                weight: 1.0,
                last_heartbeat: 0,
            });
        }
        topology
    }

    fn distinct_nodes(p: &[HrwPlacement]) -> usize {
        p.iter()
            .map(|x| x.node_id)
            .collect::<std::collections::HashSet<_>>()
            .len()
    }

    /// One rack, six OSDs, 4+2: every shard of a stripe must be on a
    /// different OSD. This placed all six on one OSD before, so losing that
    /// disk lost the object.
    #[test]
    fn single_rack_spreads_a_stripe_over_distinct_osds() {
        let crush = Crush2::new(single_rack_topology(6), 16);
        let template = PlacementTemplate::mds(4, 2);
        for _ in 0..200 {
            let p = crush.select_placement(&ObjectId::new(), &template).unwrap();
            assert_eq!(p.len(), 6);
            assert_eq!(distinct_nodes(&p), 6, "{p:?}");
        }
    }

    fn set_status(topology: &mut ClusterTopology, id: NodeId, status: NodeStatus) {
        let mut n = topology.get_node(id).unwrap().clone();
        n.status = status;
        topology.upsert_node(n);
    }

    fn mark_down(topology: &mut ClusterTopology, id: NodeId) {
        set_status(topology, id, NodeStatus::Down);
    }

    /// Fewer OSDs than shards: refused, not two shards on one OSD. Three
    /// OSDs used to take two shards of a 4+2 stripe each, so losing any one
    /// lost two, and a second loss the object.
    #[test]
    fn fewer_osds_than_shards_is_refused() {
        let template = PlacementTemplate::mds(4, 2);
        for osds in 1..6 {
            let crush = Crush2::new(single_rack_topology(osds), 16);
            for _ in 0..50 {
                let err = crush
                    .select_placement(&ObjectId::new(), &template)
                    .unwrap_err();
                assert_eq!(
                    err,
                    TooFewOsds {
                        needed: 6,
                        usable: osds
                    }
                );
            }
        }
        // No OSD at all: refused too, not a made-up node.
        let crush = Crush2::new(ClusterTopology::new(), 16);
        assert!(crush.select_placement(&ObjectId::new(), &template).is_err());
    }

    /// Three hosts of two OSDs each, 4+2, one host a rack (the failure
    /// domain): three domains for six shards, so the domain is relaxed and
    /// each OSD takes one shard. With one OSD down it keeps its position
    /// (the write does without it); with one drained there are five OSDs
    /// for six shards, and the stripe is refused.
    #[test]
    fn three_hosts_of_two_osds_hold_a_four_two_stripe_one_shard_each() {
        let mut topology = ClusterTopology::new();
        for host in 0..3 {
            for osd in 0..2 {
                topology.upsert_node(NodeInfo {
                    id: NodeId::new(),
                    name: format!("h{host}-osd{osd}"),
                    address: format!("10.0.{host}.{osd}:9200").parse().unwrap(),
                    failure_domain: FailureDomainInfo::new_full(
                        "r",
                        "z",
                        "dc",
                        &format!("rack{host}"),
                        &format!("host{host}"),
                    ),
                    status: NodeStatus::Active,
                    disks: vec![],
                    weight: 1.0,
                    last_heartbeat: 0,
                });
            }
        }
        let ids: Vec<NodeId> = topology.all_nodes().map(|n| n.id).collect();
        let template = PlacementTemplate::mds(4, 2);
        let crush = Crush2::new(topology.clone(), 16);
        for _ in 0..200 {
            let p = crush.select_placement(&ObjectId::new(), &template).unwrap();
            assert_eq!(distinct_nodes(&p), 6, "{p:?}");
        }

        mark_down(&mut topology, ids[0]);
        let crush = Crush2::new(topology.clone(), 16);
        for _ in 0..200 {
            let p = crush.select_placement(&ObjectId::new(), &template).unwrap();
            assert_eq!(distinct_nodes(&p), 6, "{p:?}");
        }

        set_status(&mut topology, ids[0], NodeStatus::Active);
        set_status(&mut topology, ids[1], NodeStatus::Draining);
        let crush = Crush2::new(topology, 16);
        let err = crush
            .select_placement(&ObjectId::new(), &template)
            .unwrap_err();
        assert_eq!(
            err,
            TooFewOsds {
                needed: 6,
                usable: 5
            }
        );
    }

    /// One OSD of six down: its position stays on it rather than doubling
    /// up on a live one, so the repairer can fill it when it is back. Two
    /// down: only one position may wait (a write needs k + 1 = 5 shards),
    /// and the other has no OSD of its own: refused. It doubled up on a
    /// live OSD before.
    #[test]
    fn a_down_osd_keeps_its_position_within_the_write_quorum() {
        let mut topology = single_rack_topology(6);
        let ids: Vec<NodeId> = topology.all_nodes().map(|n| n.id).collect();
        let template = PlacementTemplate::mds(4, 2);

        mark_down(&mut topology, ids[0]);
        let crush = Crush2::new(topology.clone(), 16);
        for _ in 0..200 {
            let p = crush.select_placement(&ObjectId::new(), &template).unwrap();
            assert_eq!(distinct_nodes(&p), 6, "{p:?}");
        }

        mark_down(&mut topology, ids[1]);
        let crush = Crush2::new(topology.clone(), 16);
        for _ in 0..200 {
            let err = crush
                .select_placement(&ObjectId::new(), &template)
                .unwrap_err();
            assert_eq!(
                err,
                TooFewOsds {
                    needed: 6,
                    usable: 5
                }
            );
        }

        // A seventh OSD: the stripe has six of its own again, one of them
        // down.
        topology.upsert_node(NodeInfo {
            id: NodeId::new(),
            name: "node-6".into(),
            address: "10.0.0.6:9002".parse().unwrap(),
            failure_domain: FailureDomainInfo::new("us-east", "dc1", "rack0"),
            status: NodeStatus::Active,
            disks: vec![],
            weight: 1.0,
            last_heartbeat: 0,
        });
        let crush = Crush2::new(topology, 16);
        for _ in 0..200 {
            let p = crush.select_placement(&ObjectId::new(), &template).unwrap();
            let on_down = p
                .iter()
                .filter(|x| x.node_id == ids[0] || x.node_id == ids[1])
                .count();
            assert_eq!(on_down, 1, "{p:?}");
            assert_eq!(distinct_nodes(&p), 6, "{p:?}");
        }
    }

    /// Random topologies, statuses and schemes: a stripe is placed with
    /// every shard on an OSD of its own, none on an OSD that can't take it,
    /// no more on down OSDs than a write can do without, the same every
    /// time; or it is refused, exactly when there aren't OSDs enough.
    #[test]
    fn any_topology_places_on_distinct_osds_or_refuses() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let templates = [
            PlacementTemplate::mds(4, 2),
            PlacementTemplate::mds(2, 1),
            PlacementTemplate::mds(8, 4),
            PlacementTemplate::mds(3, 0), // three copies
            PlacementTemplate::lrc(6, 2, 2),
        ];
        let statuses = [
            NodeStatus::Active,
            NodeStatus::Active,
            NodeStatus::Active,
            NodeStatus::Down,
            NodeStatus::Draining,
            NodeStatus::Decommissioning,
        ];
        let mut rng = StdRng::seed_from_u64(0x0b10);
        let (mut placed, mut refused) = (0, 0);
        for _ in 0..300 {
            let mut topology = ClusterTopology::new();
            let racks = rng.gen_range(1..=5);
            for rack in 0..racks {
                for host in 0..rng.gen_range(1..=3) {
                    for osd in 0..rng.gen_range(1..=3) {
                        topology.upsert_node(NodeInfo {
                            id: NodeId::new(),
                            name: format!("r{rack}-h{host}-o{osd}"),
                            address: "10.0.0.1:9200".parse().unwrap(),
                            failure_domain: FailureDomainInfo::new_full(
                                "r",
                                "z",
                                "dc",
                                &format!("rack{rack}"),
                                &format!("r{rack}-host{host}"),
                            ),
                            status: statuses[rng.gen_range(0..statuses.len())],
                            disks: vec![],
                            weight: 1.0,
                            last_heartbeat: 0,
                        });
                    }
                }
            }
            let status: HashMap<NodeId, NodeStatus> =
                topology.all_nodes().map(|n| (n.id, n.status)).collect();
            let active = status
                .values()
                .filter(|s| **s == NodeStatus::Active)
                .count();
            let down = status.values().filter(|s| **s == NodeStatus::Down).count();
            let crush = Crush2::new(topology, 16);
            for template in &templates {
                let width = template.shards.len();
                let may_wait = if template.local_parity == 0 {
                    usize::from(template.global_parity.saturating_sub(1))
                } else {
                    0
                };
                let enough = active + down.min(may_wait) >= width;
                for _ in 0..5 {
                    let object = ObjectId::new();
                    match crush.select_placement(&object, template) {
                        Ok(p) => {
                            assert!(enough, "placed with too few OSDs: {p:?}");
                            assert_eq!(p.len(), width);
                            assert_eq!(distinct_nodes(&p), width, "{p:?}");
                            let on_down = p
                                .iter()
                                .filter(|x| status[&x.node_id] == NodeStatus::Down)
                                .count();
                            assert!(on_down <= may_wait, "{on_down} on down OSDs: {p:?}");
                            assert!(
                                p.iter().all(|x| matches!(
                                    status[&x.node_id],
                                    NodeStatus::Active | NodeStatus::Down
                                )),
                                "{p:?}"
                            );
                            let again = crush.select_placement(&object, template).unwrap();
                            assert!(
                                p.iter().zip(&again).all(|(a, b)| a.node_id == b.node_id),
                                "not deterministic"
                            );
                            placed += 1;
                        }
                        Err(e) => {
                            assert!(!enough, "refused with OSDs enough: {e}");
                            refused += 1;
                        }
                    }
                }
            }
        }
        assert!(
            placed > 100 && refused > 100,
            "{placed} placed, {refused} refused"
        );
    }

    /// The multi-rack layout the existing tests use keeps working: still
    /// distinct OSDs.
    #[test]
    fn multi_rack_placement_stays_distinct() {
        let crush = Crush2::new(create_test_topology(), 16);
        let template = PlacementTemplate::mds(4, 2);
        for _ in 0..200 {
            let p = crush.select_placement(&ObjectId::new(), &template).unwrap();
            assert_eq!(distinct_nodes(&p), 6, "{p:?}");
        }
    }

    #[test]
    fn test_hrw_deterministic() {
        let topology = create_test_topology();
        let crush = Crush2::new(topology, 64);
        let template = templates::mds_4_2();

        let object_id = ObjectId::new();

        // Same object should always get same placement
        let p1 = crush.select_placement(&object_id, &template).unwrap();
        let p2 = crush.select_placement(&object_id, &template).unwrap();

        assert_eq!(p1.len(), p2.len());
        for (a, b) in p1.iter().zip(p2.iter()) {
            assert_eq!(a.position, b.position);
            assert_eq!(a.node_id, b.node_id);
            assert_eq!(a.role, b.role);
        }
    }

    #[test]
    fn test_lrc_template() {
        let template = templates::lrc_6_2_2();

        assert_eq!(template.data_shards, 6);
        assert_eq!(template.local_parity, 2);
        assert_eq!(template.global_parity, 2);
        assert_eq!(template.total_shards(), 10);

        // Verify shard roles
        let data_count = template
            .shards
            .iter()
            .filter(|s| s.role == ShardRole::Data)
            .count();
        let lp_count = template
            .shards
            .iter()
            .filter(|s| s.role == ShardRole::LocalParity)
            .count();
        let gp_count = template
            .shards
            .iter()
            .filter(|s| s.role == ShardRole::GlobalParity)
            .count();

        assert_eq!(data_count, 6);
        assert_eq!(lp_count, 2);
        assert_eq!(gp_count, 2);

        // Verify local groups
        let group_0: Vec<_> = template
            .shards
            .iter()
            .filter(|s| s.local_group == Some(0))
            .collect();
        let group_1: Vec<_> = template
            .shards
            .iter()
            .filter(|s| s.local_group == Some(1))
            .collect();

        assert_eq!(group_0.len(), 4); // 3 data + 1 local parity
        assert_eq!(group_1.len(), 4);
    }

    #[test]
    fn test_validate_placement_feasibility_ok() {
        // 3 racks × 4 nodes → satisfies a 4+2 pool requiring 6 distinct
        // nodes (with failure_domain=node) but NOT one requiring 6 distinct
        // racks (only 3).
        let topology = create_test_topology();
        let crush = Crush2::new(topology, 64);
        let ok = crush.validate_placement_feasibility(FailureDomain::Node, 6);
        assert!(
            ok.is_ok(),
            "6 nodes across 3 racks should satisfy node spread"
        );
        let ok_ranks = crush
            .validate_placement_feasibility(FailureDomain::Rack, 3)
            .expect("3 racks exist");
        assert_eq!(ok_ranks.available_domains.len(), 3);
    }

    #[test]
    fn test_validate_placement_feasibility_insufficient_racks() {
        let topology = create_test_topology();
        let crush = Crush2::new(topology, 64);
        // Asking for 6 distinct racks when only 3 exist must fail with the
        // exact counts so callers can render a useful error.
        let err = crush
            .validate_placement_feasibility(FailureDomain::Rack, 6)
            .unwrap_err();
        match err {
            PlacementFeasibility::InsufficientDomainSpread {
                required_level,
                required_count,
                available_count,
            } => {
                assert_eq!(required_level, FailureDomain::Rack);
                assert_eq!(required_count, 6);
                assert_eq!(available_count, 3);
            }
        }
    }

    #[test]
    fn test_lrc_placement() {
        let topology = create_test_topology();
        let crush = Crush2::new(topology, 64);
        let template = templates::lrc_6_2_2();

        let object_id = ObjectId::new();
        let placements = crush.select_placement(&object_id, &template).unwrap();

        assert_eq!(placements.len(), 10);

        // Verify all positions are filled
        let positions: Vec<u8> = placements.iter().map(|p| p.position).collect();
        for i in 0..10 {
            assert!(positions.contains(&i), "Missing position {}", i);
        }
    }

    #[test]
    fn test_hrw_balance() {
        let topology = create_test_topology();
        let crush = Crush2::new(topology.clone(), 64);

        // Get all nodes
        let nodes: Vec<&NodeInfo> = topology.active_nodes().collect();

        // Count selections across many objects
        let mut selection_count: HashMap<NodeId, usize> = HashMap::new();
        for _i in 0..1000 {
            let object_id = ObjectId::new();
            let selected = crush.hrw_select_n(&object_id, &nodes, 1);
            if let Some((node_id, _)) = selected.first() {
                *selection_count.entry(*node_id).or_default() += 1;
            }
        }

        // With 12 nodes and 1000 objects, each should get ~83 objects
        // Allow 50% variance (42-125)
        for count in selection_count.values() {
            assert!(
                *count > 40 && *count < 130,
                "Unbalanced selection: {} (expected ~83)",
                count
            );
        }
    }
}
