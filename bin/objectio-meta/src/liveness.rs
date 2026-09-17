//! OSD liveness prober.
//!
//! Meta decides placement, so meta has to know which OSDs are actually there.
//! It did not. `NodeStatus::Down` existed and `active_nodes()` already
//! excluded it, but nothing ever set it: node status was derived from
//! `admin_state` alone — operator intent — so an OSD that had crashed, been
//! renamed, or moved ports stayed `Active` and kept receiving writes until an
//! operator noticed and marked it out by hand.
//!
//! The OSD-side heartbeat is a stub that logs "Would send heartbeat" and there
//! is no heartbeat RPC to receive, so rather than invent a protocol this
//! probes from the side that needs the answer. Meta already holds every OSD's
//! address and already opens `StorageServiceClient` elsewhere
//! (see `drain_observer`).
//!
//! Deliberately conservative in both directions:
//!
//!  * A node is only marked down after `FAILURES_BEFORE_DOWN` consecutive
//!    misses, so one slow probe during a GC pause does not evict a healthy
//!    OSD and trigger a pointless rebalance.
//!  * A node is restored on the first success, because refusing writes to a
//!    node that is demonstrably answering is worse than admitting it slightly
//!    early.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use objectio_common::{NodeId, NodeStatus, OsdAdminState};
use objectio_proto::storage::{GetStatusRequest, storage_service_client::StorageServiceClient};
use tokio::time::{MissedTickBehavior, interval};
use tracing::{debug, info, warn};

use crate::service::MetaService;

/// How often to sweep every registered OSD.
const PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// Per-probe timeout. Short: this is a liveness check, not a request, and a
/// node that cannot answer a status call in this long is not one to hand a
/// write to.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Consecutive failures before a node is taken out of placement. At a 15s
/// interval that is 45 seconds of silence.
const FAILURES_BEFORE_DOWN: u32 = 3;

pub fn spawn(meta: Arc<MetaService>) {
    tokio::spawn(async move {
        run(meta).await;
    });
    info!(
        "OSD liveness prober spawned (every {:?}, down after {} misses)",
        PROBE_INTERVAL, FAILURES_BEFORE_DOWN
    );
}

async fn run(meta: Arc<MetaService>) {
    let mut ticker = interval(PROBE_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // Consecutive failure counts, keyed by node_id. Only nodes that have
    // missed at least once appear here.
    let mut misses: HashMap<[u8; 16], u32> = HashMap::new();

    loop {
        ticker.tick().await;
        // Only the leader mutates topology; followers get it through Raft.
        if !meta.is_raft_leader() {
            continue;
        }
        sweep(&meta, &mut misses).await;
    }
}

async fn sweep(meta: &Arc<MetaService>, misses: &mut HashMap<[u8; 16], u32>) {
    // Snapshot so the lock is not held across the network calls below.
    let targets: Vec<([u8; 16], String, OsdAdminState)> = {
        let nodes = meta.osd_nodes_snapshot();
        nodes
            .iter()
            .map(|n| (n.node_id, n.address.clone(), n.admin_state))
            .collect()
    };
    if targets.is_empty() {
        return;
    }

    let probes = targets
        .into_iter()
        .map(|(node_id, address, admin_state)| async move {
            (node_id, address.clone(), admin_state, probe(&address).await)
        });
    let results = futures::future::join_all(probes).await;

    // Drop counters for nodes that are no longer registered, so a long-lived
    // meta does not accumulate an entry per OSD that ever existed.
    let live: std::collections::HashSet<[u8; 16]> =
        results.iter().map(|(id, _, _, _)| *id).collect();
    misses.retain(|id, _| live.contains(id));

    for (node_id, address, admin_state, reachable) in results {
        let previous = misses.get(&node_id).copied().unwrap_or(0);
        let consecutive = if reachable { 0 } else { previous + 1 };

        if reachable {
            misses.remove(&node_id);
            if previous >= FAILURES_BEFORE_DOWN {
                info!(
                    "OSD {} at {address} is answering again",
                    hex::encode(&node_id[..4])
                );
            }
        } else {
            misses.insert(node_id, consecutive);
            if consecutive < FAILURES_BEFORE_DOWN {
                debug!(
                    "OSD {} at {address} missed probe {consecutive}/{FAILURES_BEFORE_DOWN}",
                    hex::encode(&node_id[..4])
                );
            } else if consecutive == FAILURES_BEFORE_DOWN {
                warn!(
                    "OSD {} at {address} has missed {consecutive} probes — taking it out of placement",
                    hex::encode(&node_id[..4])
                );
            }
        }

        if let Some(want) = decide(reachable, consecutive, admin_state) {
            meta.set_topology_node_status(NodeId::from_bytes(node_id), want);
        }
    }
}

/// What a node's status should become, given this probe.
///
/// `None` means "not enough evidence yet, leave it alone" — the grace period
/// before a node is taken out of placement.
fn decide(reachable: bool, consecutive_misses: u32, admin: OsdAdminState) -> Option<NodeStatus> {
    if reachable {
        // Observed liveness never overrides operator intent: an OSD the
        // operator marked Out stays out even though it is answering.
        return Some(match admin {
            OsdAdminState::In => NodeStatus::Active,
            OsdAdminState::Draining => NodeStatus::Draining,
            OsdAdminState::Out => NodeStatus::Decommissioning,
        });
    }
    if consecutive_misses >= FAILURES_BEFORE_DOWN {
        Some(NodeStatus::Down)
    } else {
        None
    }
}

/// One status call. Any error — connect, timeout, or an error response — is a
/// miss; this only asks "would a write to you have worked".
async fn probe(address: &str) -> bool {
    let endpoint = match tonic::transport::Endpoint::from_shared(address.to_string()) {
        Ok(e) => e.connect_timeout(PROBE_TIMEOUT).timeout(PROBE_TIMEOUT),
        Err(_) => return false,
    };
    let Ok(channel) = endpoint.connect().await else {
        return false;
    };
    let mut client = StorageServiceClient::new(channel);
    tokio::time::timeout(PROBE_TIMEOUT, client.get_status(GetStatusRequest {}))
        .await
        .is_ok_and(|r| r.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reachable_node_follows_operator_intent() {
        assert_eq!(decide(true, 0, OsdAdminState::In), Some(NodeStatus::Active));
        assert_eq!(
            decide(true, 0, OsdAdminState::Draining),
            Some(NodeStatus::Draining)
        );
        // Up but marked out: intent wins, or an operator could never take a
        // healthy OSD out of service.
        assert_eq!(
            decide(true, 0, OsdAdminState::Out),
            Some(NodeStatus::Decommissioning)
        );
    }

    #[test]
    fn one_missed_probe_is_not_enough_to_evict() {
        // A single slow probe during a GC pause must not evict a healthy OSD
        // and set off a rebalance.
        for n in 1..FAILURES_BEFORE_DOWN {
            assert_eq!(decide(false, n, OsdAdminState::In), None, "miss {n}");
        }
    }

    #[test]
    fn sustained_silence_takes_a_node_out_of_placement() {
        assert_eq!(
            decide(false, FAILURES_BEFORE_DOWN, OsdAdminState::In),
            Some(NodeStatus::Down)
        );
        assert_eq!(
            decide(false, FAILURES_BEFORE_DOWN + 5, OsdAdminState::In),
            Some(NodeStatus::Down)
        );
    }

    #[test]
    fn recovery_is_immediate() {
        // Asymmetric on purpose: slow to evict, quick to restore. Refusing
        // writes to a node that is demonstrably answering is the worse error.
        assert_eq!(
            decide(true, 0, OsdAdminState::In),
            Some(NodeStatus::Active),
            "a node that answers should come straight back"
        );
    }
}
