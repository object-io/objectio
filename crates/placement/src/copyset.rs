//! Copyset allocator — Cidon & Stutsman pattern for PG → OSD picking.
//!
//! Reference: "Copysets: Reducing the Frequency of Data Loss in Cloud
//! Storage" (USENIX ATC '13).
//!
//! # Why copysets
//!
//! With N OSDs and `(k+m)` shards per object, the naive pick-any-k+m
//! policy can form `C(N, k+m)` distinct "copysets" — the set of OSDs
//! that share any single object. If `k+m` OSDs fail concurrently, the
//! probability of data loss is proportional to the fraction of
//! copysets those OSDs cover. More unique copysets = higher
//! correlated-loss probability.
//!
//! The Cidon/Stutsman insight: don't let placement choose freely.
//! Pre-compute a small pool of copysets and only assign PGs from that
//! pool. With `scatter_width = S`, each OSD appears in ≈ S copysets,
//! so the total pool size is `(N × S) / (k + m)`. This caps the
//! number of distinct copysets to something much smaller than
//! `C(N, k+m)` — data loss probability drops by orders of magnitude
//! for realistic failure rates.
//!
//! # What this module does
//!
//! 1. Group OSDs by their value at a chosen failure-domain level
//!    (e.g. group by rack, so every copyset spans distinct racks).
//! 2. Sample copysets of size `k+m` such that each element comes from
//!    a distinct group (enforcing the failure-domain constraint).
//! 3. Run until every OSD appears in at least `scatter_width`
//!    copysets, or we exhaust the feasible combinations.
//!
//! The resulting [`CopysetPool`] is the input the PG allocator
//! samples from — one pool per `(tier, failure_domain_level, k+m)`
//! triple.

use objectio_common::{FailureDomain, NodeId};
use rand::rngs::StdRng;
use rand::seq::{IteratorRandom, SliceRandom};
use rand::{Rng, SeedableRng};
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::topology::ClusterTopology;

/// A single copyset — a `k+m`-tuple of OSD node ids, ordered by
/// position. The allocator assigns shard position `i` to
/// `osds[i]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Copyset {
    pub osds: Vec<NodeId>,
}

impl Copyset {
    /// Construct a copyset of specified size. Used by the allocator.
    #[must_use]
    pub fn new(osds: Vec<NodeId>) -> Self {
        Self { osds }
    }

    /// Number of OSDs in this copyset (= k+m).
    #[must_use]
    pub fn size(&self) -> usize {
        self.osds.len()
    }

    /// Does this copyset contain the given OSD?
    #[must_use]
    pub fn contains(&self, id: &NodeId) -> bool {
        self.osds.contains(id)
    }
}

/// A precomputed pool of valid copysets.
///
/// Built once per `(failure_domain_level, k+m)` configuration, then
/// consulted by the PG allocator (Phase 3) and the balancer (Phase 4)
/// every time they need to pick a new OSD tuple. Recomputed on
/// topology changes (OSD add/remove or failure-domain reshuffles).
#[derive(Clone, Debug)]
pub struct CopysetPool {
    /// Failure-domain level every copyset respects. Typically
    /// `FailureDomain::Host` for on-prem, `Rack` or `Datacenter` for
    /// larger clusters.
    pub level: FailureDomain,
    /// `k + m` — size of each copyset.
    pub copy_count: usize,
    /// The generated copyset set. Order is stable between two builds
    /// with the same seed, so logs and tests reproduce.
    pub sets: Vec<Copyset>,
}

/// Errors from pool construction.
#[derive(Debug, thiserror::Error)]
pub enum CopysetError {
    #[error("copy_count must be >= 1")]
    ZeroCopyCount,
    #[error("not enough distinct failure-domain groups: have {have}, need {need}")]
    InsufficientGroups { have: usize, need: usize },
    #[error("no viable OSDs in the topology")]
    EmptyTopology,
    #[error("placement rule: {0}")]
    InvalidRule(String),
    #[error("the topology can't satisfy the placement rule: {0}")]
    Infeasible(String),
}

/// How a pool's copies are spread over failure domains (B31 phase 1b,
/// objectio-docs `core/pg-recovery.md`), as a Ceph CRUSH rule says "choose
/// 3 racks, then 2 hosts in each".
///
/// Each copyset uses `domains` distinct domains at `level`, at most
/// `per_domain` positions in any one. Positions in a `together` group (an
/// LRC local group: its data and its local parity) share one domain, and
/// no other position goes there. Above the host level, the positions in
/// one domain are on distinct hosts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementRule {
    /// The failure-domain level copies are spread over.
    pub level: FailureDomain,
    /// Positions per copyset (k + m).
    pub copy_count: usize,
    /// Domains each copyset uses.
    pub domains: usize,
    /// Most positions in one domain.
    pub per_domain: usize,
    /// Groups of positions that share a domain of their own.
    pub together: Vec<Vec<usize>>,
}

impl PlacementRule {
    /// One position per domain, as many domains as positions: the rule a
    /// pool has unless it asks for another.
    #[must_use]
    pub fn spread(level: FailureDomain, copy_count: usize) -> Self {
        Self {
            level,
            copy_count,
            domains: copy_count,
            per_domain: 1,
            together: Vec::new(),
        }
    }

    /// Whether positions in one domain must be on distinct hosts: the
    /// level is above a host.
    #[must_use]
    pub fn hosts_distinct(&self) -> bool {
        matches!(
            self.level,
            FailureDomain::Rack
                | FailureDomain::Datacenter
                | FailureDomain::Zone
                | FailureDomain::Region
        )
    }

    /// The `together` group `position` is in.
    #[must_use]
    pub fn group_of(&self, position: usize) -> Option<usize> {
        self.together.iter().position(|g| g.contains(&position))
    }

    /// Positions in no `together` group, in order.
    #[must_use]
    pub fn singles(&self) -> Vec<usize> {
        (0..self.copy_count)
            .filter(|p| self.group_of(*p).is_none())
            .collect()
    }

    /// The positions each of the rule's domains holds: one slot per
    /// `together` group, then the other positions spread evenly over the
    /// rest of the domains, in order.
    #[must_use]
    pub fn slots(&self) -> Vec<Vec<usize>> {
        let mut out: Vec<Vec<usize>> = self.together.clone();
        let singles = self.singles();
        let free = self.domains.saturating_sub(self.together.len());
        if free == 0 || singles.is_empty() {
            return out;
        }
        let (each, extra) = (singles.len() / free, singles.len() % free);
        let mut it = singles.into_iter();
        for d in 0..free {
            let n = each + usize::from(d < extra);
            out.push(it.by_ref().take(n).collect());
        }
        out
    }

    /// Check the rule is consistent.
    ///
    /// # Errors
    /// [`CopysetError::InvalidRule`], saying what is wrong.
    pub fn validate(&self) -> Result<(), CopysetError> {
        let bad = |m: String| Err(CopysetError::InvalidRule(m));
        if self.copy_count == 0 {
            return Err(CopysetError::ZeroCopyCount);
        }
        if self.per_domain == 0 {
            return bad("at most 0 copies per domain".into());
        }
        if matches!(self.level, FailureDomain::Node | FailureDomain::Disk) && self.per_domain > 1 {
            return bad("an OSD is its own failure domain: one copy per domain".into());
        }
        let mut seen = HashSet::new();
        for g in &self.together {
            if g.is_empty() {
                return bad("an empty group".into());
            }
            for p in g {
                if *p >= self.copy_count || !seen.insert(*p) {
                    return bad(format!(
                        "group position {p} is out of range or in two groups"
                    ));
                }
            }
            if g.len() > self.per_domain {
                return bad(format!(
                    "a group of {} needs at least {} copies per domain, not {}",
                    g.len(),
                    g.len(),
                    self.per_domain
                ));
            }
        }
        if self.domains < self.together.len() {
            return bad(format!(
                "{} domains can't hold {} groups, a domain each",
                self.domains,
                self.together.len()
            ));
        }
        let singles = self.copy_count - seen.len();
        let free = self.domains - self.together.len();
        if singles == 0 && free > 0 {
            return bad(format!("{free} domains with nothing to hold"));
        }
        if singles > 0 {
            if free == 0 {
                return bad(format!(
                    "no domain left for {singles} copies outside the groups"
                ));
            }
            if free > singles {
                return bad(format!(
                    "{} domains for {} copies: some would hold none",
                    self.domains, self.copy_count
                ));
            }
            if singles.div_ceil(free) > self.per_domain {
                return bad(format!(
                    "{singles} copies over {free} domains puts {} in one, more than {} per domain",
                    singles.div_ceil(free),
                    self.per_domain
                ));
            }
        }
        Ok(())
    }

    /// Put `members` (one per position) in an order of their own, within
    /// the rule: groups swap places with groups of their size, members of
    /// a group change places inside it, and the other positions among
    /// themselves. Each domain keeps the same members, so the copies are
    /// spread just as before; what changes is which position (data, local
    /// or global parity) each holds.
    pub fn shuffle<T: Clone>(&self, members: &mut [T], rng: &mut impl Rng) {
        if self.together.is_empty() {
            members.shuffle(rng);
            return;
        }
        let original = members.to_vec();
        // Groups of one size trade places, whole.
        let mut by_len: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (i, g) in self.together.iter().enumerate() {
            by_len.entry(g.len()).or_default().push(i);
        }
        for idxs in by_len.values() {
            let mut order = idxs.clone();
            order.shuffle(rng);
            for (to, from) in idxs.iter().zip(order) {
                let mut group: Vec<T> = self.together[from]
                    .iter()
                    .map(|p| original[*p].clone())
                    .collect();
                group.shuffle(rng);
                for (p, m) in self.together[*to].iter().zip(group) {
                    members[*p] = m;
                }
            }
        }
        let singles = self.singles();
        let mut rest: Vec<T> = singles.iter().map(|p| original[*p].clone()).collect();
        rest.shuffle(rng);
        for (p, m) in singles.iter().zip(rest) {
            members[*p] = m;
        }
    }

    /// Whether an OSD in `domain` (on `unit`: its host above the host
    /// level, else itself) may hold `position`, the other positions'
    /// members being `others` (position, domain, unit; members that can't
    /// take writes left out). A member standing in must keep the rule.
    #[must_use]
    pub fn admits(
        &self,
        position: usize,
        domain: &str,
        unit: &str,
        others: &[(usize, String, String)],
    ) -> bool {
        let here: Vec<&(usize, String, String)> = others
            .iter()
            .filter(|(p, d, _)| *p != position && d == domain)
            .collect();
        if here.iter().any(|(_, _, u)| u == unit) {
            return false;
        }
        match self.group_of(position) {
            // With what is left of its group, and alone with it.
            Some(g) => {
                others
                    .iter()
                    .filter(|(p, _, _)| *p != position && self.group_of(*p) == Some(g))
                    .all(|(_, d, _)| d == domain)
                    && here.iter().all(|(p, _, _)| self.group_of(*p) == Some(g))
            }
            None => {
                here.iter().all(|(p, _, _)| self.group_of(*p).is_none())
                    && here.len() < self.per_domain
            }
        }
    }
}

impl CopysetPool {
    /// Build a copyset pool from the live topology.
    ///
    /// - `level` — failure-domain level to enforce distinctness on.
    /// - `copy_count` — k+m per copyset.
    /// - `scatter_width` — target minimum appearances per OSD. The
    ///   Cidon/Stutsman paper recommends S ≈ 10 for a good balance of
    ///   MTTDL reduction and pool diversity. Smaller S → fewer
    ///   distinct copysets → lower correlated-loss probability →
    ///   fewer choices for the balancer.
    /// - `seed` — RNG seed. Pass the topology version for
    ///   reproducible pools across meta replicas.
    ///
    /// # Errors
    /// Returns [`CopysetError::InsufficientGroups`] when the topology
    /// has fewer than `copy_count` distinct values at `level` — no
    /// FD-respecting copyset exists in that case.
    pub fn build(
        topology: &ClusterTopology,
        level: FailureDomain,
        copy_count: usize,
        scatter_width: usize,
        seed: u64,
    ) -> Result<Self, CopysetError> {
        Self::build_with_rule(
            topology,
            &PlacementRule::spread(level, copy_count),
            scatter_width,
            seed,
        )
    }

    /// As [`Self::build`], every copyset keeping `rule`: `rule.domains`
    /// domains, at most `rule.per_domain` positions in one, a `together`
    /// group in a domain of its own, distinct hosts inside a domain above
    /// the host level. Position `i` of a copyset is the member for shard
    /// position `i`.
    ///
    /// # Errors
    /// [`CopysetError::InvalidRule`] for an inconsistent rule;
    /// [`CopysetError::InsufficientGroups`] with fewer domains than the
    /// rule uses; [`CopysetError::Infeasible`] when there are domains
    /// enough but too few hosts (or OSDs) in them.
    pub fn build_with_rule(
        topology: &ClusterTopology,
        rule: &PlacementRule,
        scatter_width: usize,
        seed: u64,
    ) -> Result<Self, CopysetError> {
        rule.validate()?;
        let level = rule.level;
        let copy_count = rule.copy_count;

        // Active OSDs by domain, then by unit (the host above the host
        // level, else the OSD itself).
        let groups = units_by_domain(topology, rule);
        if groups.is_empty() {
            return Err(CopysetError::EmptyTopology);
        }
        if groups.len() < rule.domains {
            return Err(CopysetError::InsufficientGroups {
                have: groups.len(),
                need: rule.domains,
            });
        }
        // Feasible exactly when, both sorted largest first, every slot fits
        // the domain matched with it.
        let slots = rule.slots();
        let mut need: Vec<usize> = slots.iter().map(Vec::len).collect();
        need.sort_unstable_by(|a, b| b.cmp(a));
        let mut have: Vec<usize> = groups.values().map(BTreeMap::len).collect();
        have.sort_unstable_by(|a, b| b.cmp(a));
        if need.iter().zip(&have).any(|(n, h)| n > h) {
            let unit = if rule.hosts_distinct() {
                "hosts"
            } else {
                "OSDs"
            };
            return Err(CopysetError::Infeasible(format!(
                "it needs {} {level:?}s holding {need:?} copies, each on distinct {unit}; \
                 the {level:?}s have {have:?} {unit}",
                rule.domains
            )));
        }

        // Target pool size — each OSD should appear in ≈ scatter_width
        // copysets. Total node-slots in the pool = pool_size × copy_count,
        // so pool_size ≈ (N × S) / (k+m).
        let total_osds: usize = groups
            .values()
            .flat_map(BTreeMap::values)
            .map(Vec::len)
            .sum();
        let target_pool_size = ((total_osds * scatter_width) / copy_count).max(1);

        let mut rng = StdRng::seed_from_u64(seed);
        let mut coverage: HashMap<NodeId, usize> = groups
            .values()
            .flat_map(BTreeMap::values)
            .flatten()
            .map(|n| (*n, 0_usize))
            .collect();
        let mut sets: Vec<Copyset> = Vec::with_capacity(target_pool_size);
        let mut seen: HashSet<Vec<[u8; 16]>> = HashSet::new();

        // Keep sampling until either every OSD hits scatter_width or
        // we exhaust a generous budget of attempts. The budget
        // accounts for the fact that late iterations often hit
        // duplicates once the pool is saturated.
        let attempt_budget = target_pool_size.saturating_mul(10).max(256);
        let mut attempts = 0usize;
        while attempts < attempt_budget
            && (sets.len() < target_pool_size || coverage.values().any(|&c| c < scatter_width))
        {
            attempts += 1;
            if let Some(cs) = sample_copyset(&groups, &slots, copy_count, &coverage, &mut rng) {
                // Canonicalise for dedup: sort ids (by raw bytes — NodeId
                // doesn't impl Ord) so (A,B,C) = (C,A,B).
                let mut canon: Vec<[u8; 16]> = cs.osds.iter().map(|id| *id.as_bytes()).collect();
                canon.sort();
                if seen.insert(canon) {
                    for n in &cs.osds {
                        *coverage.entry(*n).or_insert(0) += 1;
                    }
                    sets.push(cs);
                }
            }
        }

        Ok(Self {
            level,
            copy_count,
            sets,
        })
    }

    /// Pick a uniformly random copyset from the pool.
    #[must_use]
    pub fn pick_random(&self, rng: &mut impl Rng) -> Option<&Copyset> {
        self.sets.choose(rng)
    }

    /// Pick the copyset with the smallest "cost" under the given
    /// function — used by the balancer to pick the least-loaded
    /// tuple. Ties broken uniformly at random among equally-best
    /// options.
    pub fn pick_min_cost<F>(&self, rng: &mut impl Rng, mut cost: F) -> Option<&Copyset>
    where
        F: FnMut(&Copyset) -> f64,
    {
        if self.sets.is_empty() {
            return None;
        }
        let mut best_cost = f64::INFINITY;
        let mut ties: Vec<&Copyset> = Vec::new();
        for cs in &self.sets {
            let c = cost(cs);
            if c < best_cost {
                best_cost = c;
                ties.clear();
                ties.push(cs);
            } else if (c - best_cost).abs() < f64::EPSILON {
                ties.push(cs);
            }
        }
        ties.choose(rng).copied()
    }
}

/// Active OSDs by their domain at the rule's level, then by unit: the host
/// above the host level (positions in one domain go on distinct hosts),
/// else the OSD itself. Finer than a host each OSD is its own domain:
/// `at_level` has no name for that level, and every OSD would fall into
/// one.
fn units_by_domain(
    topology: &ClusterTopology,
    rule: &PlacementRule,
) -> BTreeMap<String, BTreeMap<String, Vec<NodeId>>> {
    let mut out: BTreeMap<String, BTreeMap<String, Vec<NodeId>>> = BTreeMap::new();
    for node in topology.active_nodes() {
        out.entry(domain_name(node, rule.level))
            .or_default()
            .entry(unit_name(node, rule))
            .or_default()
            .push(node.id);
    }
    out
}

/// The domain `node` is in at `level`.
#[must_use]
pub fn domain_name(node: &crate::topology::NodeInfo, level: FailureDomain) -> String {
    match level {
        FailureDomain::Node | FailureDomain::Disk => node.id.to_string(),
        _ => node.failure_domain.at_level(level).to_string(),
    }
}

/// The unit `node` is inside its domain: its host when the rule puts the
/// positions of one domain on distinct hosts, else itself.
#[must_use]
pub fn unit_name(node: &crate::topology::NodeInfo, rule: &PlacementRule) -> String {
    if rule.hosts_distinct() && !node.failure_domain.host.is_empty() {
        node.failure_domain.host.clone()
    } else {
        node.id.to_string()
    }
}

/// One OSD of `candidates`, weighted inversely by how many copysets each is
/// in already (1 / (1 + covered)): under-covered OSDs are favoured, and
/// none ever has no chance.
fn pick_weighted(
    candidates: &[NodeId],
    coverage: &HashMap<NodeId, usize>,
    rng: &mut impl Rng,
) -> Option<NodeId> {
    let weights: Vec<f64> = candidates
        .iter()
        .map(|id| 1.0 / (1.0 + *coverage.get(id).unwrap_or(&0) as f64))
        .collect();
    let total: f64 = weights.iter().sum();
    if total <= 0.0 {
        return None;
    }
    // `gen` is a reserved keyword in Rust 2024; use the raw form.
    let mut pick = rng.r#gen::<f64>() * total;
    for (id, w) in candidates.iter().zip(weights.iter()) {
        pick -= w;
        if pick <= 0.0 {
            return Some(*id);
        }
    }
    candidates.first().copied()
}

/// Sample one copyset: a domain for each of the rule's slots (largest slots
/// first, the domains in random order, each used once), then distinct
/// units inside it and an OSD in each unit, favouring under-covered OSDs so
/// every node converges to `scatter_width`.
fn sample_copyset(
    groups: &BTreeMap<String, BTreeMap<String, Vec<NodeId>>>,
    slots: &[Vec<usize>],
    copy_count: usize,
    coverage: &HashMap<NodeId, usize>,
    rng: &mut impl Rng,
) -> Option<Copyset> {
    let mut domains: Vec<&BTreeMap<String, Vec<NodeId>>> = groups.values().collect();
    domains.shuffle(rng);
    let mut order: Vec<&Vec<usize>> = slots.iter().collect();
    order.sort_by_key(|slot| std::cmp::Reverse(slot.len()));
    let mut used = vec![false; domains.len()];
    let mut osds: Vec<Option<NodeId>> = vec![None; copy_count];
    for slot in order {
        let d = (0..domains.len()).find(|d| !used[*d] && domains[*d].len() >= slot.len())?;
        used[d] = true;
        let units: Vec<&Vec<NodeId>> = domains[d]
            .values()
            .choose_multiple(rng, slot.len())
            .into_iter()
            .collect();
        if units.len() != slot.len() {
            return None;
        }
        for (position, unit) in slot.iter().zip(units) {
            osds[*position] = Some(pick_weighted(unit, coverage, rng)?);
        }
    }
    osds.into_iter()
        .collect::<Option<Vec<NodeId>>>()
        .map(Copyset::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::{ClusterTopology, NodeInfo};
    use objectio_common::NodeStatus;
    use std::net::SocketAddr;

    use crate::topology::FailureDomainInfo;

    fn mk_node(id_seed: u8, host: &str, rack: &str) -> NodeInfo {
        NodeInfo {
            id: NodeId::from_bytes([id_seed; 16]),
            name: format!("osd-{id_seed}"),
            address: "127.0.0.1:9200".parse().unwrap(),
            failure_domain: FailureDomainInfo::new_full("local", "zone-a", "dc1", rack, host),
            status: NodeStatus::Active,
            disks: Vec::new(),
            weight: 1.0,
            last_heartbeat: 0,
        }
    }

    fn topology_with(hosts_per_rack: &[(usize, &str)]) -> ClusterTopology {
        let mut t = ClusterTopology::new();
        let mut seed = 1u8;
        for (count, rack) in hosts_per_rack {
            for i in 0..*count {
                let host = format!("{rack}-host-{i}");
                t.upsert_node(mk_node(seed, &host, rack));
                seed = seed.wrapping_add(1);
            }
        }
        t
    }

    #[test]
    fn rejects_copy_count_larger_than_groups() {
        // 2 racks → can't place 3 shards with Rack-level distinctness.
        let t = topology_with(&[(3, "rackA"), (3, "rackB")]);
        let err = CopysetPool::build(&t, FailureDomain::Rack, 3, 5, 0).unwrap_err();
        assert!(matches!(
            err,
            CopysetError::InsufficientGroups { have: 2, need: 3 }
        ));
    }

    #[test]
    fn every_copyset_spans_distinct_fd_values() {
        // 5 racks, 2 hosts each → 10 OSDs. k+m=3, scatter=10.
        let t = topology_with(&[
            (2, "rackA"),
            (2, "rackB"),
            (2, "rackC"),
            (2, "rackD"),
            (2, "rackE"),
        ]);
        let pool = CopysetPool::build(&t, FailureDomain::Rack, 3, 10, 42).unwrap();
        assert!(!pool.sets.is_empty());
        for cs in &pool.sets {
            // Resolve each OSD's rack and check distinctness.
            let mut racks: Vec<String> = cs
                .osds
                .iter()
                .map(|id| {
                    t.all_nodes()
                        .find(|n| n.id == *id)
                        .map(|n| n.failure_domain.rack.clone())
                        .unwrap()
                })
                .collect();
            racks.sort();
            let before = racks.len();
            racks.dedup();
            assert_eq!(racks.len(), before, "duplicate rack in copyset {cs:?}");
        }
    }

    #[test]
    fn each_osd_hits_scatter_width() {
        let t = topology_with(&[
            (2, "rackA"),
            (2, "rackB"),
            (2, "rackC"),
            (2, "rackD"),
            (2, "rackE"),
        ]);
        let pool = CopysetPool::build(&t, FailureDomain::Rack, 3, 5, 42).unwrap();
        let mut counts: HashMap<NodeId, usize> = HashMap::new();
        for cs in &pool.sets {
            for id in &cs.osds {
                *counts.entry(*id).or_insert(0) += 1;
            }
        }
        assert_eq!(counts.len(), 10, "every OSD should appear");
        let min = counts.values().copied().min().unwrap();
        assert!(min >= 5, "min coverage {min} < scatter_width 5");
    }

    #[test]
    fn pool_is_deterministic_for_same_seed() {
        let t = topology_with(&[(3, "rackA"), (3, "rackB"), (3, "rackC")]);
        let a = CopysetPool::build(&t, FailureDomain::Rack, 3, 5, 0xdead).unwrap();
        let b = CopysetPool::build(&t, FailureDomain::Rack, 3, 5, 0xdead).unwrap();
        assert_eq!(a.sets, b.sets);
    }

    #[test]
    fn pick_min_cost_picks_the_cheapest() {
        let t = topology_with(&[(2, "r1"), (2, "r2"), (2, "r3")]);
        let pool = CopysetPool::build(&t, FailureDomain::Rack, 3, 5, 1).unwrap();
        // Assign cost = 0 to exactly one copyset, all others 10.
        let target = pool.sets[0].clone();
        let mut rng = StdRng::seed_from_u64(1);
        let got = pool
            .pick_min_cost(
                &mut rng,
                |cs| {
                    if cs.osds == target.osds { 0.0 } else { 10.0 }
                },
            )
            .unwrap();
        assert_eq!(got.osds, target.osds);
    }

    /// The rack of `id` in `t`.
    fn rack_of(t: &ClusterTopology, id: &NodeId) -> String {
        t.all_nodes()
            .find(|n| n.id == *id)
            .map(|n| n.failure_domain.rack.clone())
            .unwrap()
    }

    fn host_of(t: &ClusterTopology, id: &NodeId) -> String {
        t.all_nodes()
            .find(|n| n.id == *id)
            .map(|n| n.failure_domain.host.clone())
            .unwrap()
    }

    /// 4+2 over 3 racks, 2 per rack.
    fn four_two_over_three_racks() -> PlacementRule {
        PlacementRule {
            level: FailureDomain::Rack,
            copy_count: 6,
            domains: 3,
            per_domain: 2,
            together: Vec::new(),
        }
    }

    /// LRC 4+2+1 (two local groups of 2 data + a local parity, one global
    /// parity): positions 0 1 | 2 3 data, 4 5 local parity, 6 global.
    fn lrc_groups_per_rack() -> PlacementRule {
        PlacementRule {
            level: FailureDomain::Rack,
            copy_count: 7,
            domains: 3,
            per_domain: 3,
            together: vec![vec![0, 1, 4], vec![2, 3, 5]],
        }
    }

    #[test]
    fn a_spread_rule_keeps_its_limit_per_domain_on_distinct_hosts() {
        let t = topology_with(&[(3, "rackA"), (3, "rackB"), (3, "rackC")]);
        let rule = four_two_over_three_racks();
        let pool = CopysetPool::build_with_rule(&t, &rule, 10, 7).unwrap();
        assert!(!pool.sets.is_empty());
        for cs in &pool.sets {
            let mut per_rack: HashMap<String, Vec<String>> = HashMap::new();
            for id in &cs.osds {
                per_rack
                    .entry(rack_of(&t, id))
                    .or_default()
                    .push(host_of(&t, id));
            }
            assert_eq!(per_rack.len(), 3, "{cs:?}");
            for hosts in per_rack.values_mut() {
                assert_eq!(hosts.len(), 2, "{cs:?}");
                hosts.dedup();
                assert_eq!(hosts.len(), 2, "two copies on one host: {cs:?}");
            }
        }
    }

    #[test]
    fn a_rule_the_topology_cannot_hold_is_refused() {
        // Three racks, but one has a single host: it can't hold two copies.
        let t = topology_with(&[(3, "rackA"), (3, "rackB"), (1, "rackC")]);
        let err =
            CopysetPool::build_with_rule(&t, &four_two_over_three_racks(), 10, 7).unwrap_err();
        assert!(matches!(err, CopysetError::Infeasible(_)), "{err}");
        // Two racks: too few domains.
        let t = topology_with(&[(3, "rackA"), (3, "rackB")]);
        let err =
            CopysetPool::build_with_rule(&t, &four_two_over_three_racks(), 10, 7).unwrap_err();
        assert!(
            matches!(err, CopysetError::InsufficientGroups { have: 2, need: 3 }),
            "{err}"
        );
    }

    #[test]
    fn an_inconsistent_rule_is_refused() {
        let mut rule = four_two_over_three_racks();
        rule.per_domain = 1; // 6 copies over 3 racks, 1 each: impossible
        assert!(matches!(rule.validate(), Err(CopysetError::InvalidRule(_))));
        let mut rule = lrc_groups_per_rack();
        rule.per_domain = 2; // a group of 3 can't fit
        assert!(matches!(rule.validate(), Err(CopysetError::InvalidRule(_))));
        let mut rule = lrc_groups_per_rack();
        rule.domains = 2; // no domain left for the global parity
        assert!(matches!(rule.validate(), Err(CopysetError::InvalidRule(_))));
    }

    #[test]
    fn each_local_group_is_in_a_rack_of_its_own() {
        let t = topology_with(&[(3, "rackA"), (3, "rackB"), (2, "rackC"), (2, "rackD")]);
        let rule = lrc_groups_per_rack();
        let pool = CopysetPool::build_with_rule(&t, &rule, 10, 3).unwrap();
        assert!(!pool.sets.is_empty());
        for cs in &pool.sets {
            let racks: Vec<String> = cs.osds.iter().map(|id| rack_of(&t, id)).collect();
            let group_rack = |g: &[usize]| {
                let r: Vec<&String> = g.iter().map(|p| &racks[*p]).collect();
                assert!(r.iter().all(|x| *x == r[0]), "group split: {racks:?}");
                r[0].clone()
            };
            let a = group_rack(&rule.together[0]);
            let b = group_rack(&rule.together[1]);
            assert_ne!(a, b, "{racks:?}");
            assert_ne!(racks[6], a, "global parity with a group: {racks:?}");
            assert_ne!(racks[6], b, "global parity with a group: {racks:?}");
        }
    }

    #[test]
    fn the_shuffle_keeps_the_rule() {
        let rule = lrc_groups_per_rack();
        let racks = ["A", "A", "B", "B", "A", "B", "C"];
        for seed in 0..50 {
            let mut members: Vec<&str> = racks.to_vec();
            rule.shuffle(&mut members, &mut StdRng::seed_from_u64(seed));
            for g in &rule.together {
                assert!(
                    g.iter().all(|p| members[*p] == members[g[0]]),
                    "{members:?}"
                );
            }
            assert_eq!(members[6], "C", "{members:?}");
        }
        // Without groups any order keeps a spread rule.
        let mut v = vec![1, 2, 3, 4, 5, 6];
        four_two_over_three_racks().shuffle(&mut v, &mut StdRng::seed_from_u64(1));
        v.sort_unstable();
        assert_eq!(v, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn a_stand_in_must_keep_the_rule() {
        let others = |v: &[(usize, &str, &str)]| -> Vec<(usize, String, String)> {
            v.iter()
                .map(|(p, d, u)| (*p, (*d).to_string(), (*u).to_string()))
                .collect()
        };
        // 4+2 over 3 racks, 2 per rack; position 5 (rack C) lost.
        let rule = four_two_over_three_racks();
        let rest = others(&[
            (0, "A", "a1"),
            (1, "A", "a2"),
            (2, "B", "b1"),
            (3, "B", "b2"),
            (4, "C", "c1"),
        ]);
        assert!(rule.admits(5, "C", "c2", &rest));
        assert!(!rule.admits(5, "C", "c1", &rest), "same host");
        assert!(!rule.admits(5, "A", "a3", &rest), "a third in rack A");
        assert!(rule.admits(5, "D", "d1", &rest), "a new rack");
        // LRC: position 1 (group 0, rack A) lost.
        let rule = lrc_groups_per_rack();
        let rest = others(&[
            (0, "A", "a1"),
            (4, "A", "a2"),
            (2, "B", "b1"),
            (3, "B", "b2"),
            (5, "B", "b3"),
            (6, "C", "c1"),
        ]);
        assert!(rule.admits(1, "A", "a3", &rest));
        assert!(!rule.admits(1, "D", "d1", &rest), "out of its group's rack");
        assert!(!rule.admits(1, "C", "c2", &rest), "out of its group's rack");
        // The global parity can't go with a group.
        let rest = others(&[
            (0, "A", "a1"),
            (1, "A", "a2"),
            (4, "A", "a3"),
            (2, "B", "b1"),
            (3, "B", "b2"),
            (5, "B", "b3"),
        ]);
        assert!(!rule.admits(6, "A", "a4", &rest));
        assert!(rule.admits(6, "D", "d1", &rest));
    }

    // Silence unused import warnings in builds that don't run tests.
    #[allow(dead_code)]
    fn _unused(_: SocketAddr) {}
}
