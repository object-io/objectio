//! Any meta node answers any client: a follower forwards each gRPC call to
//! the Raft leader and relays its answer.
//!
//! Without this, a gateway, OSD or block gateway talking to a follower had
//! its writes refused ("not the raft leader") and found no OSDs (they
//! register with the leader); and one whose meta went down was down with
//! it. Clients connect to a Service in front of every meta pod, or to a
//! list of meta addresses, and whichever one answers serves them.
//!
//! Forwarding happens at the transport, so every method is covered,
//! including ones added later, and reads are answered by the leader too,
//! never from a follower's possibly stale state. And the leader answers
//! only while a quorum confirms it still leads (`read_gate`): a leader cut
//! off from its followers believes it leads until it hears otherwise, and
//! would go on answering from its own state while the others elect a new
//! leader and move on. Raft's own calls between metas are neither
//! forwarded nor gated.
//!
//! A call forwarded once is not forwarded again: if the node it reached is
//! no longer the leader (an election in between), it answers UNAVAILABLE,
//! which clients retry. With no leader known (an election under way), the
//! same. And a forwarded call still waiting when this node learns of
//! another leader is given up at once, UNAVAILABLE too: the leader it went
//! to has stopped answering (frozen, cut off), and the client's retry
//! reaches the new one rather than waiting out the call's timeout.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use objectio_meta_store::MetaTypeConfig;
use parking_lot::Mutex;
use tonic::body::BoxBody;
use tonic::codegen::http;
use tonic::transport::Channel;
use tracing::debug;

use crate::read_gate::ReadGate;

/// Marks a call a follower forwarded, so it is forwarded only once.
const FORWARDED: &str = "x-objectio-forwarded";

/// Marks a liveness probe from a client's meta channel
/// (`objectio_proto::transport::meta_channel`): answered here at once,
/// never forwarded, so it says whether *this* node is up, and whether it
/// can serve.
const PROBE: &str = objectio_proto::transport::META_PROBE_HEADER;

/// The probe's answers: up, or up but unable to serve.
const ALIVE: &str = objectio_proto::transport::META_PROBE_ALIVE;
const NOT_SERVING: &str = objectio_proto::transport::META_PROBE_NOT_SERVING;

/// The gRPC path prefix of Raft's own service: never forwarded.
const RAFT_PREFIX: &str = "/objectio.raft.";

/// A client whose format level is below the cluster's active level would
/// misread what newer nodes write (objectio-docs core/upgrade-path.md):
/// refuse it, at the node it first reached. Raft's own calls, and calls a
/// follower already checked and forwarded, pass.
fn too_old(req: &http::Request<BoxBody>) -> Option<tonic::Status> {
    if req.uri().path().starts_with(RAFT_PREFIX) || req.headers().contains_key(FORWARDED) {
        return None;
    }
    let active = objectio_common::version::active_level();
    if active == 0 {
        return None;
    }
    let level = req
        .headers()
        .get(http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map_or(0, objectio_common::version::level_of_user_agent);
    (level < active).then(|| {
        tonic::Status::failed_precondition(format!(
            "this client is at format level {level} and the cluster at {active}: it is older \
             than the cluster's finalized release; upgrade it"
        ))
    })
}

#[derive(Clone)]
pub struct ForwardToLeaderLayer {
    raft: Arc<openraft::Raft<MetaTypeConfig>>,
    self_id: u64,
    channels: Arc<Mutex<HashMap<String, Channel>>>,
    gate: Arc<ReadGate>,
}

impl ForwardToLeaderLayer {
    /// `gate` is also the Raft service's (`raft_rpc`), which closes it
    /// when another node may lead.
    pub fn new(
        raft: Arc<openraft::Raft<MetaTypeConfig>>,
        self_id: u64,
        gate: Arc<ReadGate>,
    ) -> Self {
        Self {
            gate,
            raft,
            self_id,
            channels: Arc::default(),
        }
    }
}

impl<S> tower::Layer<S> for ForwardToLeaderLayer {
    type Service = ForwardToLeader<S>;
    fn layer(&self, inner: S) -> Self::Service {
        ForwardToLeader {
            inner,
            layer: self.clone(),
        }
    }
}

#[derive(Clone)]
pub struct ForwardToLeader<S> {
    inner: S,
    layer: ForwardToLeaderLayer,
}

/// Where a call goes.
enum Route {
    /// Raft's own call: answered here, as it is.
    Raft,
    /// This node leads in `term`: answered here once the gate lets it.
    Here {
        term: u64,
    },
    Leader(u64, String),
    Unavailable(&'static str),
}

impl ForwardToLeaderLayer {
    fn route(&self, req: &http::Request<BoxBody>) -> Route {
        if req.uri().path().starts_with(RAFT_PREFIX) {
            return Route::Raft;
        }
        let metrics = self.raft.metrics().borrow().clone();
        match metrics.current_leader {
            Some(leader) if leader == self.self_id => Route::Here {
                term: metrics.current_term,
            },
            Some(_) if req.headers().contains_key(FORWARDED) => Route::Unavailable(
                "the meta node this was forwarded to is no longer the leader; retry",
            ),
            Some(leader) => metrics
                .membership_config
                .membership()
                .get_node(&leader)
                .map_or(
                    Route::Unavailable("the raft leader's address is not known yet; retry"),
                    |n| Route::Leader(leader, n.addr.clone()),
                ),
            None => Route::Unavailable("no raft leader (an election is under way); retry"),
        }
    }

    #[allow(clippy::result_large_err)]
    fn channel(&self, addr: &str) -> Result<Channel, tonic::Status> {
        let mut channels = self.channels.lock();
        if let Some(c) = channels.get(addr) {
            return Ok(c.clone());
        }
        // A leader that stopped answering (frozen, cut off) must not hold
        // the call forever: the client retries elsewhere. Its answer is
        // passed on as it arrives, so one that stopped after its headers
        // is noticed by the pings (`meta_endpoint`), not the call timeout.
        let endpoint = objectio_proto::transport::meta_endpoint(addr)
            .map_err(|e| tonic::Status::internal(format!("leader address {addr}: {e}")))?
            .initial_stream_window_size(objectio_proto::transport::STREAM_WINDOW)
            .initial_connection_window_size(objectio_proto::transport::CONNECTION_WINDOW);
        let channel = objectio_proto::transport::connect_lazy(&endpoint);
        channels.insert(addr.to_string(), channel.clone());
        Ok(channel)
    }
}

impl<S> tower::Service<http::Request<BoxBody>> for ForwardToLeader<S>
where
    S: tower::Service<http::Request<BoxBody>, Response = http::Response<BoxBody>>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = http::Response<BoxBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<BoxBody>) -> Self::Future {
        if req.headers().contains_key(PROBE) {
            let answer = match self.layer.route(&req) {
                Route::Here { term } if !self.layer.gate.serving(term) => NOT_SERVING,
                _ => ALIVE,
            };
            return Box::pin(async move { Ok(tonic::Status::unavailable(answer).into_http()) });
        }
        if let Some(refusal) = too_old(&req) {
            return Box::pin(async move { Ok(refusal.into_http()) });
        }
        match self.layer.route(&req) {
            Route::Raft => Box::pin(self.inner.call(req)),
            Route::Here { term } => {
                let gate = self.layer.gate.clone();
                // The service polled ready is the one that takes the call.
                let fresh = self.inner.clone();
                let mut inner = std::mem::replace(&mut self.inner, fresh);
                Box::pin(async move {
                    if let Err(why) = gate.check(term).await {
                        return Ok(tonic::Status::unavailable(format!(
                            "this meta node can't confirm it is still the raft leader ({why}); \
                             retry"
                        ))
                        .into_http());
                    }
                    inner.call(req).await
                })
            }
            Route::Unavailable(why) => {
                Box::pin(async move { Ok(tonic::Status::unavailable(why).into_http()) })
            }
            Route::Leader(leader, addr) => {
                let channel = self.layer.channel(&addr);
                let mut metrics = self.layer.raft.metrics();
                Box::pin(async move {
                    let mut channel = match channel {
                        Ok(c) => c,
                        Err(status) => return Ok(status.into_http()),
                    };
                    debug!("forwarding {} to the leader at {addr}", req.uri().path());
                    req.headers_mut()
                        .insert(FORWARDED, http::HeaderValue::from_static("1"));
                    // The request's URI is for this node; the channel
                    // supplies the leader's authority.
                    let forwarded = async {
                        match tower::ServiceExt::ready(&mut channel).await {
                            Ok(ready) => match tower::Service::call(ready, req).await {
                                Ok(resp) => resp,
                                Err(e) => tonic::Status::unavailable(format!(
                                    "forwarding to the raft leader at {addr} failed: {e}; retry"
                                ))
                                .into_http(),
                            },
                            Err(e) => tonic::Status::unavailable(format!(
                                "the raft leader at {addr} can't be reached: {e}; retry"
                            ))
                            .into_http(),
                        }
                    };
                    let superseded = metrics.wait_for(|m| m.current_leader != Some(leader));
                    tokio::select! {
                        resp = forwarded => Ok(resp),
                        _ = superseded => Ok(tonic::Status::unavailable(format!(
                            "the raft leader at {addr} was replaced while this call waited \
                             for it; retry"
                        ))
                        .into_http()),
                    }
                })
            }
        }
    }
}
