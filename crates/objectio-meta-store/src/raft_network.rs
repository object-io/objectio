//! gRPC transport for openraft RPCs between meta pods.
//!
//! Openraft calls [`RaftNetwork`] whenever it needs to talk to a peer —
//! AppendEntries replications, leader-election votes, snapshot installs.
//! We implement that over a tonic `RaftRpcClient` that wraps the
//! `RaftRpc` service defined in `proto/raft.proto`.
//!
//! ## Wire format
//!
//! `RaftEnvelope { from, payload }`, where `payload` is the JSON-encoded
//! openraft request or response. JSON lets us evolve openraft's types
//! without churning the proto schema; the cost is a bit of bandwidth we
//! don't care about at meta-RPC rates.
//!
//! ## Factory / connection model
//!
//! One `MetaRaftNetwork` per peer node_id. Tonic channels are created
//! lazily on first use and cached on the network instance — subsequent
//! RPCs reuse the HTTP/2 connection. We clone the network per RPC batch
//! (openraft takes `&mut self`), so the underlying Channel is `Arc`-like
//! and shareable.

use std::collections::HashMap;
use std::sync::Arc;

use openraft::BasicNode;
use openraft::error::{InstallSnapshotError, NetworkError, RPCError, RaftError};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use parking_lot::Mutex;
use tonic::transport::Channel;

use crate::raft::MetaTypeConfig;

type NodeId = u64;

/// Channel cache shared across every network instance — keyed by peer
/// address. Tonic `Channel` is cheap to clone (`Arc` inside), so a single
/// connected channel is reused across all concurrent RPC paths.
#[derive(Clone, Default)]
struct ChannelCache {
    inner: Arc<Mutex<HashMap<String, Channel>>>,
}

impl ChannelCache {
    fn get_or_connect(&self, addr: &str) -> Result<Channel, String> {
        if let Some(c) = self.inner.lock().get(addr) {
            return Ok(c.clone());
        }
        let uri = normalize_uri(addr);
        // A peer that went away without closing its connections (a pod
        // rescheduled to a new IP, a host powered off) is noticed in about
        // two seconds, not after the kernel's retransmission timeout: on
        // Raft's timescale (elections in under a second) a hung connection
        // otherwise blocks votes and replication for minutes.
        let channel = Channel::from_shared(uri)
            .map_err(|e| format!("invalid meta address `{addr}`: {e}"))?
            .connect_timeout(std::time::Duration::from_secs(1))
            .tcp_keepalive(Some(std::time::Duration::from_secs(5)))
            .http2_keep_alive_interval(std::time::Duration::from_secs(1))
            .keep_alive_timeout(std::time::Duration::from_secs(2))
            .keep_alive_while_idle(true)
            .connect_lazy();
        self.inner.lock().insert(addr.to_string(), channel.clone());
        Ok(channel)
    }

    /// Drop the channel to `addr`: the next RPC dials again, resolving the
    /// address again (a restarted pod's new IP).
    fn forget(&self, addr: &str) {
        self.inner.lock().remove(addr);
    }
}

fn normalize_uri(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.to_string()
    } else {
        format!("http://{addr}")
    }
}

/// Factory openraft calls on startup / membership change to get a network
/// handle per peer. Owns the shared connection cache.
#[derive(Clone, Default)]
pub struct MetaRaftNetworkFactory {
    self_id: u64,
    channels: ChannelCache,
}

impl MetaRaftNetworkFactory {
    #[must_use]
    pub fn new(self_id: u64) -> Self {
        Self {
            self_id,
            channels: ChannelCache::default(),
        }
    }
}

impl RaftNetworkFactory<MetaTypeConfig> for MetaRaftNetworkFactory {
    type Network = MetaRaftNetwork;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Self::Network {
        MetaRaftNetwork {
            self_id: self.self_id,
            target,
            target_addr: node.addr.clone(),
            channels: self.channels.clone(),
        }
    }
}

/// RaftNetwork for a single peer. Holds enough state to (re)dial the
/// target; every RPC opens a fresh tonic client using the cached channel.
pub struct MetaRaftNetwork {
    self_id: u64,
    /// Target peer node id — preserved for telemetry / future retry
    /// logic that differentiates per-peer error budgets.
    #[allow(dead_code)]
    target: u64,
    target_addr: String,
    channels: ChannelCache,
}

impl MetaRaftNetwork {
    fn client(
        &self,
    ) -> Result<objectio_proto::raft::raft_rpc_client::RaftRpcClient<Channel>, TransportErr> {
        let ch = self
            .channels
            .get_or_connect(&self.target_addr)
            .map_err(TransportErr)?;
        Ok(objectio_proto::raft::raft_rpc_client::RaftRpcClient::new(
            ch,
        ))
    }

    /// One RPC, bounded by openraft's deadline for it. A timeout or a
    /// transport failure drops the cached channel.
    async fn call<F, Fut>(
        &self,
        option: &RPCOption,
        rpc: F,
    ) -> Result<tonic::Response<objectio_proto::raft::RaftEnvelope>, RpcErr>
    where
        F: FnOnce(objectio_proto::raft::raft_rpc_client::RaftRpcClient<Channel>) -> Fut,
        Fut: std::future::Future<
                Output = Result<tonic::Response<objectio_proto::raft::RaftEnvelope>, tonic::Status>,
            >,
    {
        let client = self.client().map_err(|e| RpcErr(e.0))?;
        match tokio::time::timeout(option.hard_ttl(), rpc(client)).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(s)) => {
                if s.code() == tonic::Code::Unavailable || s.code() == tonic::Code::Unknown {
                    self.channels.forget(&self.target_addr);
                }
                Err(RpcErr::from(s))
            }
            Err(_) => {
                self.channels.forget(&self.target_addr);
                Err(RpcErr(format!(
                    "no answer from {} within {:?}",
                    self.target_addr,
                    option.hard_ttl()
                )))
            }
        }
    }

    fn envelope(&self, payload: Vec<u8>) -> objectio_proto::raft::RaftEnvelope {
        objectio_proto::raft::RaftEnvelope {
            from: self.self_id,
            payload,
        }
    }
}

// Opaque error types that `RPCError::{Unreachable, Network}` accept. Both
// wrap a message string; we keep them distinct so debug logs can tell
// "couldn't dial" apart from "RPC returned garbage".
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct TransportErr(String);

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct RpcErr(String);

impl From<tonic::Status> for RpcErr {
    fn from(s: tonic::Status) -> Self {
        RpcErr(format!("{}: {}", s.code(), s.message()))
    }
}

impl From<serde_json::Error> for RpcErr {
    fn from(e: serde_json::Error) -> Self {
        RpcErr(format!("decode: {e}"))
    }
}

impl RaftNetwork<MetaTypeConfig> for MetaRaftNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<MetaTypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let payload = serde_json::to_vec(&rpc).expect("openraft payload must serialize");
        let envelope = self.envelope(payload);
        let resp = self
            .call(&option, |mut c| async move {
                c.append_entries(tonic::Request::new(envelope)).await
            })
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        serde_json::from_slice::<AppendEntriesResponse<NodeId>>(&resp.into_inner().payload)
            .map_err(|e| RPCError::Network(NetworkError::new(&RpcErr::from(e))))
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<MetaTypeConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        let payload = serde_json::to_vec(&rpc).expect("openraft payload must serialize");
        let envelope = self.envelope(payload);
        let resp = self
            .call(&option, |mut c| async move {
                c.install_snapshot(tonic::Request::new(envelope)).await
            })
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        serde_json::from_slice::<InstallSnapshotResponse<NodeId>>(&resp.into_inner().payload)
            .map_err(|e| RPCError::Network(NetworkError::new(&RpcErr::from(e))))
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        let payload = serde_json::to_vec(&rpc).expect("openraft payload must serialize");
        let envelope = self.envelope(payload);
        let resp = self
            .call(&option, |mut c| async move {
                c.vote(tonic::Request::new(envelope)).await
            })
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        serde_json::from_slice::<VoteResponse<NodeId>>(&resp.into_inner().payload)
            .map_err(|e| RPCError::Network(NetworkError::new(&RpcErr::from(e))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_uri_adds_http_prefix() {
        assert_eq!(normalize_uri("127.0.0.1:9100"), "http://127.0.0.1:9100");
        assert_eq!(normalize_uri("http://meta-0:9100"), "http://meta-0:9100");
        assert_eq!(
            normalize_uri("https://meta.example.com:9100"),
            "https://meta.example.com:9100"
        );
    }
}
