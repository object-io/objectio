//! Meta's gRPC calls (counts by status, and latency, every method, via
//! the transport layer in `objectio_proto::rpc_metrics`) and its redb
//! commits.

use std::sync::LazyLock;

use objectio_proto::rpc_metrics::RpcMetrics;

/// Every gRPC call meta serves, Raft's included.
pub static RPC_METRICS: LazyLock<RpcMetrics> = LazyLock::new(RpcMetrics::default);

/// Everything meta's metrics endpoint adds for operations and storage.
pub fn render() -> String {
    let mut out = String::new();
    RPC_METRICS.render(&mut out, "objectio_meta_grpc", "meta", "");
    objectio_meta_store::commit_metrics::render(&mut out);
    out
}

/// This node's view of Raft: role, term, log positions, and on the leader
/// how far each follower has replicated.
pub fn render_raft(meta: &crate::service::MetaService, out: &mut String) {
    use std::fmt::Write as _;
    let Some(raft) = meta.raft_handle() else {
        return;
    };
    let m = raft.metrics().borrow().clone();
    let gauge = |out: &mut String, name: &str, help: &str, v: u64| {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {v}");
    };
    let leader = m.current_leader == Some(m.id);
    gauge(
        out,
        "objectio_meta_raft_is_leader",
        "1 on the Raft leader, 0 elsewhere",
        u64::from(leader),
    );
    gauge(
        out,
        "objectio_meta_raft_has_leader",
        "1 while this node knows a leader; 0 means no writes can commit",
        u64::from(m.current_leader.is_some()),
    );
    gauge(
        out,
        "objectio_meta_raft_term",
        "Current Raft term; a rising term means elections",
        m.current_term,
    );
    gauge(
        out,
        "objectio_meta_raft_last_log_index",
        "Index of the last entry in this node's Raft log",
        m.last_log_index.unwrap_or(0),
    );
    gauge(
        out,
        "objectio_meta_raft_applied_index",
        "Index of the last entry applied to this node's state",
        m.last_applied.map_or(0, |l| l.index),
    );
    gauge(
        out,
        "objectio_meta_raft_snapshot_index",
        "Index the last snapshot covers",
        m.snapshot.map_or(0, |l| l.index),
    );
    gauge(
        out,
        "objectio_meta_raft_purged_index",
        "Index up to which the log has been compacted away",
        m.purged.map_or(0, |l| l.index),
    );
    let voters = m.membership_config.membership().voter_ids().count();
    gauge(
        out,
        "objectio_meta_raft_voters",
        "Voting members of the Raft cluster",
        voters as u64,
    );
    if let (true, Some(replication)) = (leader, m.replication.as_ref()) {
        let last = m.last_log_index.unwrap_or(0);
        let _ = writeln!(
            out,
            "# HELP objectio_meta_raft_replication_lag_entries Entries a follower is behind the leader's log (leader only)\n\
             # TYPE objectio_meta_raft_replication_lag_entries gauge"
        );
        for (peer, matched) in replication {
            if *peer == m.id {
                continue;
            }
            let lag = last.saturating_sub(matched.map_or(0, |l| l.index));
            let _ = writeln!(
                out,
                "objectio_meta_raft_replication_lag_entries{{peer=\"{peer}\"}} {lag}"
            );
        }
    }
}
