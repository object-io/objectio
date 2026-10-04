//! A meta node campaigns for leadership only while it can reach a majority
//! of the voters.
//!
//! A node cut off from the others times out waiting for the leader and
//! starts an election every election timeout (0.5-1 s), raising its term
//! each time, though it can never win. When it is reachable again its
//! term is far ahead, the leader that served all along sees it and steps
//! down, and the cluster goes without a leader for an election: in the A6
//! chaos test, a partition healing cost every write a few seconds. Raft's
//! answer is pre-vote, which openraft 0.9 doesn't have; this is the same
//! effect from outside it: every [`EVERY`] each other voter's Raft port is
//! tried (a TCP connection), and openraft's elections are turned off while
//! fewer than a majority, counting this node, answer.
//!
//! It never stops a reachable majority from electing: any node that can
//! reach one keeps campaigning. A leader is unaffected (elections only
//! start on a follower).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use tracing::{info, warn};

/// How often reachability is checked: the heartbeat interval.
const EVERY: Duration = Duration::from_millis(250);

/// How long a voter has to accept a connection.
const CONNECT_TIMEOUT: Duration = Duration::from_millis(300);

type Raft = openraft::Raft<objectio_meta_store::MetaTypeConfig>;

pub fn spawn(raft: Arc<Raft>, self_id: u64) {
    tokio::spawn(async move {
        let mut electing = true;
        loop {
            tokio::time::sleep(EVERY).await;
            let peers: Vec<String> = {
                let metrics = raft.metrics().borrow().clone();
                let membership = metrics.membership_config.membership();
                let voters: BTreeSet<u64> = membership.voter_ids().collect();
                if voters.len() <= 1 || !voters.contains(&self_id) {
                    set(&raft, &mut electing, true, 0, voters.len());
                    continue;
                }
                membership
                    .nodes()
                    .filter(|(id, _)| **id != self_id && voters.contains(id))
                    .map(|(_, node)| node.addr.clone())
                    .collect()
            };
            let voters = peers.len() + 1;
            let answered = futures::future::join_all(peers.iter().map(|a| reachable(a)))
                .await
                .into_iter()
                .filter(|ok| *ok)
                .count();
            set(
                &raft,
                &mut electing,
                answered + 1 > voters / 2,
                answered + 1,
                voters,
            );
        }
    });
}

fn set(raft: &Raft, electing: &mut bool, want: bool, reachable: usize, voters: usize) {
    if *electing == want {
        return;
    }
    raft.runtime_config().elect(want);
    *electing = want;
    if want {
        info!("campaign: {reachable} of {voters} voters reachable; elections on");
    } else {
        warn!(
            "campaign: only {reachable} of {voters} voters reachable; no elections until a majority is"
        );
    }
}

/// Whether the Raft endpoint at `addr` (host:port, or a URL) accepts a TCP
/// connection.
async fn reachable(addr: &str) -> bool {
    let hostport = addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    matches!(
        tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(hostport)).await,
        Ok(Ok(_))
    )
}
