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
use tracing::{debug, info, warn};

use crate::service::MetaService;

/// How often to sweep every registered OSD.
const PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// Per-probe timeout. Short: this is a liveness check, not a request, and a
/// node that cannot answer a status call in this long is not one to hand a
/// write to.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Consecutive failures before a node is taken out of placement.
const FAILURES_BEFORE_DOWN: u32 = 3;

/// Sweep interval for the first few rounds after meta starts.
///
/// Startup is the one moment when the node list is least trustworthy: it was
/// read from the store, so it describes the cluster as it was when meta last
/// wrote it down, not as it is now. Meanwhile placement treats every loaded
/// node as live, so a registration for an OSD that has been gone for days is
/// handed out for reads until this prober catches up.
///
/// At the steady-state interval that took 30 seconds, and it was visible in
/// production: after every restart of a single-node deployment, object reads
/// answered 500 `InternalError` for half a minute while the gateway tried a
/// dead address. Sweeping quickly at first closes that to a few seconds
/// without weakening the evidence required — it still takes
/// `FAILURES_BEFORE_DOWN` consecutive misses, they just arrive sooner. A node
/// that is merely slow to accept connections (every OSD rebooting alongside
/// meta) is restored on its first success, 2 seconds later rather than 15.
const STARTUP_PROBE_INTERVAL: Duration = Duration::from_secs(2);

/// How many sweeps run at the fast interval before settling down. Five covers
/// the first ten seconds, which is longer than a dead node needs to be
/// condemned and long enough for a live one to finish binding its port.
const STARTUP_SWEEPS: u32 = 5;

/// How long to wait before the next sweep, given how many have run.
const fn probe_interval(sweeps_done: u32) -> Duration {
    if sweeps_done < STARTUP_SWEEPS {
        STARTUP_PROBE_INTERVAL
    } else {
        PROBE_INTERVAL
    }
}

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
    // Consecutive failure counts, keyed by node_id. Only nodes that have
    // missed at least once appear here.
    let mut misses: HashMap<[u8; 16], u32> = HashMap::new();
    // Sweeps completed. Only used to pick the interval, so it stops mattering
    // once it passes STARTUP_SWEEPS.
    let mut sweeps: u32 = 0;

    loop {
        // Only the leader mutates topology; followers get it through Raft.
        if meta.is_raft_leader() {
            sweep(&meta, &mut misses).await;
        }
        sweeps = sweeps.saturating_add(1);
        tokio::time::sleep(probe_interval(sweeps)).await;
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

    /// A dead node must be condemned in seconds after a restart, not half a
    /// minute.
    ///
    /// The node list is loaded from the store, so at startup it describes the
    /// cluster as it was, and placement treats every loaded node as live. On
    /// the live deployment that meant object reads answered 500 for thirty
    /// seconds after every restart while the gateway tried an address that had
    /// been dead for days.
    #[test]
    fn a_dead_node_is_out_within_seconds_of_a_restart() {
        // Sweeps run at t=0 and then after each interval, so the Nth miss
        // lands at the sum of the first N-1 intervals.
        let time_to_down: Duration = (1..u32::from(u8::try_from(FAILURES_BEFORE_DOWN).unwrap()))
            .map(probe_interval)
            .sum();
        assert!(
            time_to_down <= Duration::from_secs(5),
            "a dead node stays in placement for {time_to_down:?} after a restart"
        );
    }

    #[test]
    fn sweeps_settle_to_the_steady_state_interval() {
        // The fast schedule is for startup only — probing every 2s forever
        // would be a status call per OSD per 2 seconds, for nothing.
        assert_eq!(probe_interval(0), STARTUP_PROBE_INTERVAL);
        assert_eq!(probe_interval(STARTUP_SWEEPS - 1), STARTUP_PROBE_INTERVAL);
        assert_eq!(probe_interval(STARTUP_SWEEPS), PROBE_INTERVAL);
        assert_eq!(probe_interval(u32::MAX), PROBE_INTERVAL);
    }

    /// The evidence required is unchanged — only how fast it arrives.
    ///
    /// Sweeping quickly must not become "condemn on the first miss": a node
    /// that is slow to bind its port while meta restarts alongside it would
    /// otherwise be taken out of placement for no reason.
    #[test]
    fn a_fast_schedule_still_needs_three_consecutive_misses() {
        assert_eq!(decide(false, 1, OsdAdminState::In), None);
        assert_eq!(decide(false, 2, OsdAdminState::In), None);
        assert_eq!(decide(false, 3, OsdAdminState::In), Some(NodeStatus::Down));
    }

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
