//! HTTP admin endpoints for Raft bootstrap + membership.
//!
//! These are meta-local — operators (or a helm post-install Job) call
//! them to turn a fresh pod into a single-voter cluster, then onboard
//! additional pods as learners, then promote them to voters. The gateway
//! doesn't proxy these: the cluster has to be up before the gateway has
//! someone to talk to.
//!
//! ## Endpoints (all on the meta admin port, default :9102)
//!
//! - `POST /init`
//!   Bootstrap a brand-new single-voter cluster with this node as the
//!   sole member. Idempotent — a second call fails with `NotAllowed`
//!   because a cluster already exists.
//! - `POST /add-learner  { "node_id": u64, "addr": "host:port" }`
//!   Register a peer as a learner (non-voting). It catches up on the
//!   log without holding up writes.
//! - `POST /change-membership  { "voters": [u64, ...] }`
//!   Promote the given set of node ids (which must already be learners)
//!   to voters. Writes go through quorum of this new voter set.
//! - `GET  /status`
//!   Current leader id, term, membership config, last_log_index; `fatal`
//!   when this node's Raft has stopped for good.
//! - `GET  /health`
//!   200 while this node's Raft runs; 503 once it has stopped (a fatal
//!   storage error, a panic, a shutdown). What a liveness probe asks:
//!   the process still answering HTTP is not enough.
//! - `GET  /ready`
//!   200 while Raft runs, this node is a member of the cluster and it
//!   knows a leader; 503 otherwise (before the cluster is initialized,
//!   before this node is added, during an election). What a readiness
//!   probe asks.
//!
//! ## Who may call them
//!
//! A learner is sent the whole log, so whoever may add one may read every
//! record in the cluster. With mTLS on, the port is HTTPS with the node's
//! certificate; a client certificate is optional at the handshake, and
//! checked per call. `GET /status`, `/health` and `/ready` only read this
//! node's state and take any client, with a certificate or none: kubelet's
//! probes present none. Every other call, the three that change membership
//! first, takes only a client presenting a certificate of role `admin`
//! (the Helm bootstrap Job's, `objectio-install cluster init`'s, an
//! operator's) and is refused 403 otherwise. With mTLS off it is plain HTTP and unauthenticated, like
//! the rest of the internal network: it binds the host meta listens on
//! (loopback in the all-in-one) and the node says at startup that the
//! network must be isolated.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{ConnectInfo, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use objectio_meta_store::MetaTypeConfig;
use objectio_proto::peer_auth::Roles;
use openraft::{BasicNode, Raft, RaftMetrics, ServerState};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tracing::{debug, info, warn};

pub struct RaftAdminState {
    pub raft: Arc<Raft<MetaTypeConfig>>,
    pub self_id: u64,
    pub self_addr: String,
}

impl RaftAdminState {
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/init", post(init))
            .route("/add-learner", post(add_learner))
            .route("/change-membership", post(change_membership))
            .route("/status", get(status))
            .route("/health", get(health))
            .route("/ready", get(ready))
            // Every route: a call added later needs role admin unless it
            // is made open below.
            .route_layer(middleware::from_fn(require_admin))
            .with_state(self)
    }
}

/// A client of the admin port, over TLS: its address and the roles its
/// certificate names (none without one).
#[derive(Clone, Debug)]
pub struct Peer {
    pub addr: SocketAddr,
    pub roles: Roles,
}

/// The calls any client may make under mTLS, with a certificate or none:
/// they only read this node's state, and kubelet's probes, which present
/// no certificate, ask the last two.
const OPEN_PATHS: [&str; 3] = ["/status", "/health", "/ready"];

/// Whether `method` `path` is one of [`OPEN_PATHS`], read (GET or HEAD).
fn open_to_anyone(method: &Method, path: &str) -> bool {
    (method == Method::GET || method == Method::HEAD) && OPEN_PATHS.contains(&path)
}

/// Under mTLS, every call but the open ones (those that change membership,
/// and any other) needs a client certificate of role `admin`.
async fn require_admin(req: Request, next: Next) -> Response {
    if !objectio_proto::transport::tls_enabled() || open_to_anyone(req.method(), req.uri().path()) {
        return next.run(req).await;
    }
    let peer = req.extensions().get::<ConnectInfo<Peer>>().map(|c| &c.0);
    match peer {
        Some(p) if p.roles.intersects(Roles::ADMIN) => next.run(req).await,
        _ => {
            let (who, roles) = peer.map_or_else(
                || ("an unknown peer".to_string(), Roles::NONE),
                |p| (p.addr.to_string(), p.roles),
            );
            warn!(
                "raft admin: refused {} from {who} (role {roles}): needs a certificate of role admin",
                req.uri().path()
            );
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "this call needs a client certificate of role admin"
                })),
            )
                .into_response()
        }
    }
}

/// Serve the admin API on `listener` until the process ends: over TLS with
/// this node's certificate when mTLS is on, plain HTTP otherwise. The
/// caller binds it, so a port that can't be had fails startup.
///
/// # Errors
/// The TLS configuration doesn't apply.
pub async fn serve(state: Arc<RaftAdminState>, listener: TcpListener) -> anyhow::Result<()> {
    let addr = listener.local_addr()?;
    let router = state.router();
    match objectio_proto::transport::https_server_config().map_err(anyhow::Error::msg)? {
        Some(config) => {
            info!("Raft admin API on https://{addr}/ (membership changes: role admin)");
            let tls = TlsListener::spawn(listener, tokio_rustls::TlsAcceptor::from(config));
            axum::serve(tls, router.into_make_service_with_connect_info::<Peer>()).await?;
        }
        None => {
            objectio_proto::transport::warn_unauthenticated();
            info!("Raft admin API on http://{addr}/ (unauthenticated: mTLS is off)");
            axum::serve(listener, router).await?;
        }
    }
    Ok(())
}

/// How long a client has to finish its TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Connections that completed their TLS handshake, each with its peer.
/// Handshakes run on tasks of their own, so a slow one holds up no other.
struct TlsListener {
    local: SocketAddr,
    ready: tokio::sync::mpsc::Receiver<(TlsStream<TcpStream>, Peer)>,
}

impl TlsListener {
    fn spawn(listener: TcpListener, acceptor: tokio_rustls::TlsAcceptor) -> Self {
        let local = listener
            .local_addr()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
        let (tx, ready) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                let (tcp, addr) = match listener.accept().await {
                    Ok(c) => c,
                    Err(e) => {
                        debug!("raft admin: accept: {e}");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let (acceptor, tx) = (acceptor.clone(), tx.clone());
                tokio::spawn(async move {
                    let tls =
                        match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
                            Ok(Ok(tls)) => tls,
                            Ok(Err(e)) => {
                                debug!("raft admin: TLS handshake from {addr}: {e}");
                                return;
                            }
                            Err(_) => return,
                        };
                    let roles =
                        objectio_proto::peer_auth::peer_roles(tls.get_ref().1.peer_certificates());
                    let _ = tx.send((tls, Peer { addr, roles })).await;
                });
            }
        });
        Self { local, ready }
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = Peer;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(conn) => conn,
            // The accepting task never ends while the listener lives.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Ok(Peer {
            addr: self.local,
            roles: Roles::NONE,
        })
    }
}

impl axum::extract::connect_info::Connected<axum::serve::IncomingStream<'_, TlsListener>> for Peer {
    fn connect_info(stream: axum::serve::IncomingStream<'_, TlsListener>) -> Self {
        stream.remote_addr().clone()
    }
}

/// POST /init — single-voter bootstrap. Use on the first meta pod only.
async fn init(State(s): State<Arc<RaftAdminState>>) -> impl IntoResponse {
    let mut members = std::collections::BTreeMap::new();
    members.insert(
        s.self_id,
        BasicNode {
            addr: s.self_addr.clone(),
        },
    );
    match s.raft.initialize(members).await {
        Ok(()) => {
            info!(
                "raft cluster initialized with self_id={} at {}",
                s.self_id, s.self_addr
            );
            Json(serde_json::json!({
                "ok": true,
                "node_id": s.self_id,
                "addr": s.self_addr,
            }))
            .into_response()
        }
        Err(e) => {
            let msg = e.to_string();
            // Idempotent restart: cluster is already initialized. Treat as 409 so
            // callers (notably objectio-aio) don't have to distinguish cold boot
            // from warm boot.
            let already =
                msg.contains("not allowed to initialize") || msg.contains("already initialized");
            if already {
                info!("raft init: already initialized — idempotent restart");
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "ok": true,
                        "already_initialized": true,
                    })),
                )
                    .into_response();
            }
            warn!("raft init failed: {}", msg);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": msg })),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct AddLearnerBody {
    node_id: u64,
    addr: String,
}

/// POST /add-learner — register a peer as a non-voting learner. Must be
/// called on the current leader. Blocks until the learner is caught up.
async fn add_learner(
    State(s): State<Arc<RaftAdminState>>,
    Json(body): Json<AddLearnerBody>,
) -> impl IntoResponse {
    match s
        .raft
        .add_learner(
            body.node_id,
            BasicNode {
                addr: body.addr.clone(),
            },
            true,
        )
        .await
    {
        Ok(resp) => {
            info!(
                "learner {} @ {} added at log_id={:?}",
                body.node_id, body.addr, resp.log_id
            );
            Json(serde_json::json!({
                "ok": true,
                "node_id": body.node_id,
                "addr": body.addr,
                "log_id": format!("{:?}", resp.log_id),
            }))
            .into_response()
        }
        Err(e) => {
            warn!("add_learner({}, {}) failed: {}", body.node_id, body.addr, e);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct ChangeMembershipBody {
    voters: Vec<u64>,
}

/// POST /change-membership — promote the given set to voters. Must be
/// called on the leader. Replaces the existing voter set outright, so
/// pass the full intended voter list, not a delta.
async fn change_membership(
    State(s): State<Arc<RaftAdminState>>,
    Json(body): Json<ChangeMembershipBody>,
) -> impl IntoResponse {
    let voters: std::collections::BTreeSet<u64> = body.voters.into_iter().collect();
    // `retain_learners = false` drops any existing learner that isn't in
    // the new voter set. If you want to keep them as learners, call
    // `change_membership(voters, true)` — we default to false because the
    // typical flow promotes every learner to voter.
    match s.raft.change_membership(voters.clone(), false).await {
        Ok(resp) => {
            info!(
                "membership changed to voters={:?} at log_id={:?}",
                voters, resp.log_id
            );
            Json(serde_json::json!({
                "ok": true,
                "voters": voters,
                "log_id": format!("{:?}", resp.log_id),
            }))
            .into_response()
        }
        Err(e) => {
            warn!("change_membership({:?}) failed: {}", voters, e);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

#[derive(Serialize)]
struct StatusResponse {
    self_id: u64,
    self_addr: String,
    leader_id: Option<u64>,
    current_term: u64,
    last_log_index: Option<u64>,
    last_applied: Option<u64>,
    /// Index the last snapshot covers: the log is compacted up to it.
    snapshot: Option<u64>,
    /// Index the log is purged up to.
    purged: Option<u64>,
    state: String,
    /// Why this node's Raft has stopped for good, if it has (it exits
    /// then); absent while it runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    fatal: Option<String>,
    voters: Vec<u64>,
    learners: Vec<u64>,
    /// Whether opening the database at start had to walk all of it (B25:
    /// never expected).
    open_repair: bool,
}

/// GET /status — current leader / term / log / membership.
async fn status(State(s): State<Arc<RaftAdminState>>) -> impl IntoResponse {
    let m = s.raft.metrics().borrow().clone();
    let cfg = m.membership_config.membership();
    let voters: Vec<u64> = cfg.voter_ids().collect();
    let learners: Vec<u64> = cfg.learner_ids().collect();
    let resp = StatusResponse {
        self_id: s.self_id,
        self_addr: s.self_addr.clone(),
        leader_id: m.current_leader,
        current_term: m.current_term,
        last_log_index: m.last_log_index,
        last_applied: m.last_applied.map(|l| l.index),
        snapshot: m.snapshot.map(|l| l.index),
        purged: m.purged.map(|l| l.index),
        state: format!("{:?}", m.state),
        fatal: m.running_state.as_ref().err().map(ToString::to_string),
        voters,
        learners,
        open_repair: objectio_meta_store::commit_metrics::open_repaired(),
    };
    Json(resp).into_response()
}

/// Why this node's Raft is not running, if it isn't.
fn not_running(m: &RaftMetrics<u64, BasicNode>) -> Option<String> {
    if let Err(fatal) = &m.running_state {
        return Some(format!("raft stopped: {fatal}"));
    }
    (m.state == ServerState::Shutdown).then(|| "raft is shutting down".to_owned())
}

/// Why this node can't serve, if it can't: Raft must run, the node must
/// be a member (voter or learner), and a leader must be known (a
/// follower forwards every call to it).
fn not_ready(m: &RaftMetrics<u64, BasicNode>, self_id: u64) -> Option<String> {
    if let Some(why) = not_running(m) {
        return Some(why);
    }
    let membership = m.membership_config.membership();
    if membership.get_node(&self_id).is_none() {
        return Some("not a member of a raft cluster (not initialized, or not added yet)".into());
    }
    m.current_leader
        .is_none()
        .then(|| "no raft leader known".to_owned())
}

fn answer(problem: Option<String>) -> axum::response::Response {
    match problem {
        None => (StatusCode::OK, "ok").into_response(),
        Some(why) => (StatusCode::SERVICE_UNAVAILABLE, why).into_response(),
    }
}

/// GET /health — 200 while Raft runs (a liveness probe).
async fn health(State(s): State<Arc<RaftAdminState>>) -> impl IntoResponse {
    answer(not_running(&s.raft.metrics().borrow()))
}

/// GET /ready — 200 while this node can serve (a readiness probe).
async fn ready(State(s): State<Arc<RaftAdminState>>) -> impl IntoResponse {
    answer(not_ready(&s.raft.metrics().borrow(), s.self_id))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    use openraft::error::Fatal;
    use openraft::{BasicNode, Membership, RaftMetrics, ServerState, StoredMembership};

    use axum::http::Method;

    use super::{not_ready, not_running, open_to_anyone};

    /// Under mTLS only reading the node's state takes a client without an
    /// admin certificate; anything else, a path added later included,
    /// needs one.
    #[test]
    fn only_reading_state_is_open_to_any_client() {
        for path in ["/status", "/health", "/ready"] {
            assert!(open_to_anyone(&Method::GET, path), "GET {path}");
            assert!(open_to_anyone(&Method::HEAD, path), "HEAD {path}");
            assert!(!open_to_anyone(&Method::POST, path), "POST {path}");
        }
        for path in [
            "/init",
            "/add-learner",
            "/change-membership",
            "/anything-else",
            "/status/",
        ] {
            assert!(!open_to_anyone(&Method::GET, path), "GET {path}");
            assert!(!open_to_anyone(&Method::POST, path), "POST {path}");
        }
    }

    fn member_of(voters: &[u64]) -> RaftMetrics<u64, BasicNode> {
        let mut m = RaftMetrics::new_initial(1);
        let nodes: BTreeMap<u64, BasicNode> = voters
            .iter()
            .map(|id| (*id, BasicNode::new(format!("meta-{id}:9100"))))
            .collect();
        let ids: BTreeSet<u64> = voters.iter().copied().collect();
        m.membership_config = Arc::new(StoredMembership::new(
            None,
            Membership::new(vec![ids], nodes),
        ));
        m
    }

    /// A node that was never initialized nor added runs, but can't serve.
    #[test]
    fn a_node_outside_any_cluster_is_alive_but_not_ready() {
        let m = RaftMetrics::<u64, BasicNode>::new_initial(1);
        assert_eq!(not_running(&m), None);
        assert!(not_ready(&m, 1).unwrap().contains("not a member"));
    }

    /// A member that knows its leader is ready; during an election it isn't.
    #[test]
    fn a_member_is_ready_while_it_knows_a_leader() {
        let mut m = member_of(&[1, 2, 3]);
        m.current_leader = Some(2);
        assert_eq!(not_ready(&m, 1), None);
        m.current_leader = None;
        assert_eq!(not_ready(&m, 1).as_deref(), Some("no raft leader known"));
    }

    /// Raft stopped: neither alive nor ready, whatever it last knew.
    #[test]
    fn a_stopped_raft_is_neither_alive_nor_ready() {
        let mut m = member_of(&[1]);
        m.current_leader = Some(1);
        m.running_state = Err(Fatal::Panicked);
        assert!(not_running(&m).unwrap().contains("raft stopped"));
        assert!(not_ready(&m, 1).is_some());
        m.running_state = Ok(());
        m.state = ServerState::Shutdown;
        assert!(not_running(&m).is_some());
    }
}
