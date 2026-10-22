// `tonic::Status` is large — clippy complains about every fn that returns
// `Result<_, Status>`. Boxing here would obscure the tonic handler
// signatures without payoff. Allow at the module level.
#![allow(clippy::result_large_err)]

//! Server-side tonic handler for the `RaftRpc` service.
//!
//! Mirrors the client-side transport in [`objectio_meta_store::raft_network`].
//! For each of the three inter-meta RPCs we:
//!
//! 1. JSON-decode the envelope payload into an openraft request type.
//! 2. Hand the request to the local [`openraft::Raft`] instance.
//! 3. JSON-encode the response (or encode the error body) back into an
//!    envelope.
//!
//! Error semantics: network/decode failures come back as a `tonic::Status`
//! so the client sees `RPCError::Network`. Raft-protocol-level errors
//! (vote rejected, log gap, etc.) are already carried inside the response
//! type by openraft; they're normal successes from the transport's view.
//! Only genuine bugs (Fatal) escape as `Status::internal`.
//!
//! The handler owns an `Arc<Raft<MetaTypeConfig>>` — clone for each
//! request is a pointer bump.
//!
//! It also closes this node's read gate ([`crate::read_gate`]) whenever
//! another node may be about to lead: on every vote request, before the
//! answer leaves, and on entries or a snapshot from another leader.

use std::sync::Arc;

use objectio_meta_store::MetaTypeConfig;
use objectio_proto::raft::{RaftEnvelope, raft_rpc_server::RaftRpc};
use openraft::Raft;
use openraft::Vote;
use openraft::raft::{AppendEntriesRequest, InstallSnapshotRequest, VoteRequest};
use tonic::{Request, Response, Status};

use crate::read_gate::ReadGate;

/// tonic service implementation. Constructed by the meta binary once the
/// [`Raft`] instance is live.
pub struct RaftRpcService {
    pub raft: Arc<Raft<MetaTypeConfig>>,
    pub self_id: u64,
    /// The gate in front of this node's client calls (`forward`).
    gate: Arc<ReadGate>,
}

impl RaftRpcService {
    pub fn new(raft: Arc<Raft<MetaTypeConfig>>, self_id: u64, gate: Arc<ReadGate>) -> Self {
        Self {
            raft,
            self_id,
            gate,
        }
    }

    /// A message from the leader `vote` names: if that isn't this node,
    /// another node leads or did, and this one must not serve from a
    /// confirmation it made before hearing of it.
    fn heard_from(&self, vote: &Vote<u64>) {
        if vote.leader_id().voted_for() != Some(self.self_id) {
            self.gate.revoke();
        }
    }

    fn envelope<T: serde::Serialize>(&self, v: &T) -> Result<RaftEnvelope, Status> {
        Ok(RaftEnvelope {
            from: self.self_id,
            payload: serde_json::to_vec(v)
                .map_err(|e| Status::internal(format!("encode raft response: {e}")))?,
        })
    }
}

#[tonic::async_trait]
impl RaftRpc for RaftRpcService {
    async fn append_entries(
        &self,
        req: Request<RaftEnvelope>,
    ) -> Result<Response<RaftEnvelope>, Status> {
        let bytes = req.into_inner().payload;
        let req: AppendEntriesRequest<MetaTypeConfig> = serde_json::from_slice(&bytes)
            .map_err(|e| Status::invalid_argument(format!("decode append_entries: {e}")))?;
        self.heard_from(&req.vote);
        let resp = self
            .raft
            .append_entries(req)
            .await
            .map_err(|e| Status::internal(format!("append_entries: {e}")))?;
        Ok(Response::new(self.envelope(&resp)?))
    }

    async fn vote(&self, req: Request<RaftEnvelope>) -> Result<Response<RaftEnvelope>, Status> {
        let bytes = req.into_inner().payload;
        let req: VoteRequest<u64> = serde_json::from_slice(&bytes)
            .map_err(|e| Status::invalid_argument(format!("decode vote: {e}")))?;
        let resp = self.raft.vote(req).await;
        // This node may have granted the vote and stepped down, and the
        // candidate may lead once the answer arrives. openraft lets a
        // leader vote once its own lease has run out, which is never
        // extended, so the lease of the followers that confirmed it may
        // not hold that candidate back: close the gate, after the vote
        // is decided and before the answer leaves (`read_gate`).
        self.gate.revoke();
        let resp = resp.map_err(|e| Status::internal(format!("vote: {e}")))?;
        Ok(Response::new(self.envelope(&resp)?))
    }

    async fn install_snapshot(
        &self,
        req: Request<RaftEnvelope>,
    ) -> Result<Response<RaftEnvelope>, Status> {
        let bytes = req.into_inner().payload;
        let req: InstallSnapshotRequest<MetaTypeConfig> = serde_json::from_slice(&bytes)
            .map_err(|e| Status::invalid_argument(format!("decode install_snapshot: {e}")))?;
        self.heard_from(&req.vote);
        let resp = self
            .raft
            .install_snapshot(req)
            .await
            .map_err(|e| Status::internal(format!("install_snapshot: {e}")))?;
        Ok(Response::new(self.envelope(&resp)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::raft::VoteResponse;
    use std::time::Duration;

    /// openraft never extends a leader's own lease, so a leader of more
    /// than a lease grants its vote to a candidate of a higher term whose
    /// log is as long as its own, and steps down. A confirmation it made
    /// just before must then serve no call: the candidate may be elected
    /// with this vote, without the lease of the followers that confirmed
    /// this node, and commit writes this node doesn't have.
    #[tokio::test]
    async fn a_leader_that_answers_a_vote_serves_nothing_from_its_last_confirmation() {
        let dir = tempfile::TempDir::new().unwrap();
        let raft = crate::raft_batch::tests::single_node(dir.path()).await;
        // A window far longer than the test, so only the vote ends it.
        let gate = ReadGate::for_raft_with(
            raft.clone(),
            Duration::from_secs(60),
            Duration::from_secs(2),
        );
        let svc = RaftRpcService::new(raft.clone(), 1, gate.clone());
        // This leader's own lease, from its election, runs out.
        let lease = Duration::from_millis(raft.config().election_timeout_max);
        tokio::time::sleep(lease + Duration::from_millis(100)).await;
        let m = raft.metrics().borrow().clone();
        let term = m.current_term;
        gate.check(term)
            .await
            .expect("the leader confirms it leads");
        gate.check(term).await.expect("and is served from it");
        // It doesn't stand again on its own, after stepping down.
        raft.runtime_config().elect(false);

        // Its log as long as this one's: idle, all of it is applied.
        let req = VoteRequest::new(Vote::new(term + 1, 2), m.last_applied);
        let envelope = RaftEnvelope {
            from: 2,
            payload: serde_json::to_vec(&req).unwrap(),
        };
        let resp = svc.vote(Request::new(envelope)).await.unwrap().into_inner();
        let resp: VoteResponse<u64> = serde_json::from_slice(&resp.payload).unwrap();
        assert!(
            resp.vote_granted,
            "the test needs the leader to grant the vote: {resp:?}"
        );

        let served = gate.check(term).await;
        assert!(
            served.is_err(),
            "a leader that voted for another candidate was served from its confirmation"
        );
    }
}
