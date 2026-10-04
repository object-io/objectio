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
//! including ones added later, and reads are answered by the leader too:
//! a client never sees a follower's possibly stale state. Raft's own calls
//! between metas are never forwarded.
//!
//! A call forwarded once is not forwarded again: if the node it reached is
//! no longer the leader (an election in between), it answers UNAVAILABLE,
//! which clients retry. With no leader known (an election under way), the
//! same.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use objectio_meta_store::MetaTypeConfig;
use parking_lot::Mutex;
use tonic::body::BoxBody;
use tonic::codegen::http;
use tonic::transport::{Channel, Endpoint};
use tracing::debug;

/// Marks a call a follower forwarded, so it is forwarded only once.
const FORWARDED: &str = "x-objectio-forwarded";

/// Marks a liveness probe from a client's meta channel
/// (`objectio_proto::transport::meta_channel`): answered here at once,
/// never forwarded, so it says whether *this* node is up.
const PROBE: &str = objectio_proto::transport::META_PROBE_HEADER;

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
}

impl ForwardToLeaderLayer {
    pub fn new(raft: Arc<openraft::Raft<MetaTypeConfig>>, self_id: u64) -> Self {
        Self {
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
    Here,
    Leader(String),
    Unavailable(&'static str),
}

impl ForwardToLeaderLayer {
    fn route(&self, req: &http::Request<BoxBody>) -> Route {
        if req.uri().path().starts_with(RAFT_PREFIX) {
            return Route::Here;
        }
        let metrics = self.raft.metrics().borrow().clone();
        match metrics.current_leader {
            Some(leader) if leader == self.self_id => Route::Here,
            Some(_) if req.headers().contains_key(FORWARDED) => Route::Unavailable(
                "the meta node this was forwarded to is no longer the leader; retry",
            ),
            Some(leader) => metrics
                .membership_config
                .membership()
                .get_node(&leader)
                .map_or(
                    Route::Unavailable("the raft leader's address is not known yet; retry"),
                    |n| Route::Leader(n.addr.clone()),
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
        let uri = if addr.starts_with("http://") || addr.starts_with("https://") {
            addr.to_string()
        } else {
            format!("http://{addr}")
        };
        let channel = Endpoint::from_shared(uri)
            .map_err(|e| tonic::Status::internal(format!("leader address {addr}: {e}")))?
            .connect_timeout(std::time::Duration::from_secs(3))
            // A leader that stopped answering (frozen, cut off) must not
            // hold the call forever: the client retries elsewhere.
            .timeout(objectio_proto::transport::META_CALL_TIMEOUT)
            .initial_stream_window_size(objectio_proto::transport::STREAM_WINDOW)
            .initial_connection_window_size(objectio_proto::transport::CONNECTION_WINDOW)
            .connect_lazy();
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
            return Box::pin(async { Ok(tonic::Status::unavailable("alive").into_http()) });
        }
        if let Some(refusal) = too_old(&req) {
            return Box::pin(async move { Ok(refusal.into_http()) });
        }
        match self.layer.route(&req) {
            Route::Here => Box::pin(self.inner.call(req)),
            Route::Unavailable(why) => {
                Box::pin(async move { Ok(tonic::Status::unavailable(why).into_http()) })
            }
            Route::Leader(addr) => {
                let channel = self.layer.channel(&addr);
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
                    match tower::ServiceExt::ready(&mut channel).await {
                        Ok(ready) => match tower::Service::call(ready, req).await {
                            Ok(resp) => Ok(resp),
                            Err(e) => Ok(tonic::Status::unavailable(format!(
                                "forwarding to the raft leader at {addr} failed: {e}; retry"
                            ))
                            .into_http()),
                        },
                        Err(e) => Ok(tonic::Status::unavailable(format!(
                            "the raft leader at {addr} can't be reached: {e}; retry"
                        ))
                        .into_http()),
                    }
                })
            }
        }
    }
}
