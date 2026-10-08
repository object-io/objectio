//! ObjectIO Metadata Service — library form.
//!
//! The thin `src/main.rs` wraps `run()` with CLI parsing + tracing
//! subscriber setup. The same `run()` is re-used by
//! `bin/aio` to compose meta into a single-process monolith.

pub mod balancer;
mod campaign;
pub mod drain_observer;
pub mod forward;
pub mod liveness;
mod op_metrics;
pub mod raft_admin;
pub mod raft_rpc;
pub mod repair;
pub mod service;

use anyhow::Result;
use axum::{
    Router,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use clap::Parser;
use objectio_meta_store::MetaStore;
use objectio_proto::metadata::metadata_service_server::MetadataServiceServer;
use service::MetaService;
use std::fmt::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

#[derive(Parser, Debug)]
#[command(name = "objectio-meta")]
#[command(about = "ObjectIO Metadata Service")]
#[command(version)]
pub struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/objectio/meta.toml")]
    pub config: String,

    /// Node ID (for Raft)
    #[arg(long)]
    pub node_id: Option<u64>,

    /// Listen address for gRPC
    #[arg(short, long, default_value = "0.0.0.0:9001")]
    pub listen: String,

    /// Peer addresses for Raft cluster
    #[arg(long)]
    pub peers: Vec<String>,

    /// Erasure coding data shards (k)
    #[arg(long, default_value = "4")]
    pub ec_k: u8,

    /// Erasure coding parity shards (m)
    #[arg(long, default_value = "2")]
    pub ec_m: u8,

    /// Replication count (use instead of EC for simple replication)
    /// Set to 1 for single-disk mode (no redundancy)
    /// Set to 3 for 3-way replication
    /// When set, overrides ec_k and ec_m
    #[arg(long)]
    pub replication: Option<u8>,

    /// Data directory for persistent metadata (redb)
    #[arg(long, default_value = "/var/lib/objectio/meta")]
    pub data_dir: PathBuf,

    /// Admin user name (creates default admin on startup if no users exist)
    #[arg(long, default_value = "admin")]
    pub admin_user: String,

    /// Log level
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Prometheus `/metrics` port; 0 serves none (the gateway re-exports
    /// these metrics either way)
    #[arg(long, default_value = "9101")]
    pub metrics_port: u16,

    /// HTTP admin port for Raft bootstrap + membership endpoints
    /// (/_admin/raft/{init,add-learner,change-membership,status}).
    #[arg(long, default_value = "9102")]
    pub admin_port: u16,

    /// Seconds between repair passes. Each pass checks every object's
    /// shards and rebuilds any that are missing or corrupt from the rest
    /// of their stripe, and restores listing entries that are missing.
    /// Runs on the Raft leader. 0 turns it off.
    #[arg(long, default_value_t = 3600)]
    pub repair_interval_secs: u64,

    /// Seconds between drain sweeps (on the Raft leader).
    #[arg(long, default_value_t = 30)]
    pub drain_interval_secs: u64,

    /// Snapshot the state machine, and compact the Raft log into it, every
    /// this many log entries (B18). A snapshot is the whole metadata
    /// database (a listing entry per object), so not too often.
    #[arg(long, default_value_t = 500_000)]
    pub raft_snapshot_every: u64,

    /// How often the applied state is made durable, in ms (B25): entries
    /// are applied without a flush each, and a crash re-applies at most
    /// this much from the log. Each checkpoint holds applies while it
    /// flushes, so small and often: at 1000 ms, under ~700 small PUTs a
    /// second, a checkpoint took up to 1 s and held every PUT (B21); at 200
    /// the slowest 1% of PUTs halved.
    #[arg(long, default_value_t = 200)]
    pub raft_checkpoint_ms: u64,

    /// Log entries kept behind the last snapshot: a follower behind by
    /// fewer catches up from the log; one further behind gets a snapshot.
    #[arg(long, default_value_t = 10_000)]
    pub raft_keep_logs: u64,

    /// Raft heartbeat interval, in ms. It also bounds how long a leader
    /// waits for a follower to take entries before counting it lost.
    #[arg(long, default_value_t = 500)]
    pub raft_heartbeat_ms: u64,

    /// A follower that hears nothing from its leader for a random time in
    /// [this, 2 × this] ms stands for election. Under write load a follower
    /// fsyncing its log, or a busy VM, delays heartbeats: at 500 ms meta
    /// elected under the soak's load with no fault at all, and every
    /// election is seconds of 503s.
    #[arg(long, default_value_t = 2000)]
    pub raft_election_ms: u64,

    /// Shards a drain sweep moves off each draining OSD, at most.
    #[arg(long, default_value_t = 64)]
    pub drain_batch: usize,

    /// This node's addressable endpoint for Raft peers (host:port of the
    /// gRPC server). Peers dial this when adding us as a learner or
    /// sending AppendEntries. Defaults to `--listen` but must be
    /// pod-reachable, not `0.0.0.0`, in production.
    #[arg(long, default_value = "")]
    pub raft_advertise: String,

    /// mTLS between services (A8a).
    #[command(flatten)]
    pub tls: objectio_proto::transport::TlsArgs,
}

/// Largest Raft RPC message meta accepts.
const RAFT_MESSAGE_LIMIT: usize = 256 * 1024 * 1024;

/// Raft settings for the meta cluster.
///
/// The log is compacted (B18): every `snapshot_every` entries each node
/// snapshots its state machine (the whole database, streamed through a
/// file) and purges its log up to it, keeping `keep_logs` entries behind
/// it for followers that are only a little behind. A follower further
/// behind is sent the snapshot.
fn raft_config(
    snapshot_every: u64,
    keep_logs: u64,
    heartbeat_ms: u64,
    election_ms: u64,
) -> openraft::Config {
    openraft::Config {
        cluster_name: "objectio-meta".into(),
        heartbeat_interval: heartbeat_ms,
        election_timeout_min: election_ms,
        election_timeout_max: election_ms * 2,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(snapshot_every.max(1)),
        max_in_snapshot_log_to_keep: keep_logs,
        // Snapshots travel in chunks: small enough that one, JSON-encoded,
        // is far under the Raft RPC limit.
        snapshot_max_chunk_size: 512 * 1024,
        ..Default::default()
    }
}

/// Run the metadata service until `shutdown` resolves. The caller is
/// responsible for:
///   - building `args` (e.g. from `Args::parse()` in the bin, or
///     constructed in-process by the aio monolith)
///   - installing a tracing subscriber BEFORE calling this
///   - providing a shutdown future (Ctrl-C in the bin, a
///     broadcast-channel recv in aio)
pub async fn run(
    args: Args,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    objectio_proto::transport::configure_tls(&args.tls).map_err(anyhow::Error::msg)?;
    info!("Starting ObjectIO Metadata Service");

    // Initialize metadata service with EC config
    // Replication mode takes precedence over EC settings
    let ec_config = if let Some(replication_count) = args.replication {
        info!("Storage mode: Replication (count={})", replication_count);
        objectio_meta_store::EcConfig::Replication {
            count: replication_count,
        }
    } else {
        info!(
            "Storage mode: Erasure coding (k={}, m={})",
            args.ec_k, args.ec_m
        );
        objectio_meta_store::EcConfig::Mds {
            k: args.ec_k,
            m: args.ec_m,
        }
    };

    // Open persistent store
    let store_path = args.data_dir.join("meta.redb");
    info!("Opening metadata store at {}", store_path.display());
    let store = Arc::new(MetaStore::open(&store_path).unwrap_or_else(|e| {
        panic!(
            "Failed to open metadata store at {}: {}",
            store_path.display(),
            e
        )
    }));
    info!("Metadata store opened successfully");

    let meta_service = MetaService::with_store(ec_config, store.clone());

    // Parse listen address
    let addr = args
        .listen
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid listen address {}: {}", args.listen, e))?;

    // Wrap services in Arc for sharing
    let meta_service = Arc::new(meta_service);

    // Create metrics state
    let metrics_state = Arc::new(MetaMetricsState {
        meta_service: meta_service.clone(),
        start_time: std::time::Instant::now(),
    });

    {
        let weak = Arc::downgrade(&metrics_state);
        meta_service.set_metrics_renderer(Box::new(move || {
            weak.upgrade()
                .map(|s| render_metrics(&s))
                .unwrap_or_default()
        }));
    }

    // Start metrics server
    // Port 0 turns it off: the same text is served over gRPC GetMetrics,
    // which the gateway re-exports (aio runs it this way).
    let metrics_port = args.metrics_port;
    if metrics_port != 0 {
        let metrics_state_clone = metrics_state.clone();
        tokio::spawn(async move {
            if let Err(e) = start_metrics_server(metrics_port, metrics_state_clone).await {
                error!("Metrics server error: {}", e);
            }
        });
    }

    // ------------------------------------------------------------
    // Raft wiring (Phase R1)
    //
    // Meta always runs through Raft. A one-pod deployment boots a
    // single-voter cluster after /_admin/raft/init; multi-pod
    // deployments add peers as learners and promote them to voters.
    // ------------------------------------------------------------
    let node_id: u64 = args.node_id.unwrap_or(1);
    let self_addr = if args.raft_advertise.is_empty() {
        // For local dev we fall back to listen-as-advertise; it's fine
        // when all pods are on localhost or the k8s headless DNS is
        // resolvable and peers reach each other by hostname.
        args.listen.clone()
    } else {
        args.raft_advertise.clone()
    };

    let raft_db = meta_service
        .store()
        .map(|s| s.db())
        .expect("meta service must be backed by a persistent store for Raft");

    // Apply-event channel: state machine → meta service cache refresher.
    // On every follower too — so a just-promoted pod doesn't serve reads
    // off a pre-promote snapshot of buckets/users/iceberg-tables.
    let (apply_tx, apply_rx) =
        tokio::sync::mpsc::unbounded_channel::<objectio_meta_store::ApplyEvent>();
    meta_service.spawn_apply_listener(apply_rx);
    let raft_storage = objectio_meta_store::MetaRaftStorage::open(
        raft_db,
        args.data_dir.join("raft-snapshots"),
        &args.data_dir.join("raft-log"),
    )
    .unwrap_or_else(|e| {
        panic!(
            "Raft log in {}: {e}",
            args.data_dir.join("raft-log").display()
        )
    })
    .with_apply_listener(apply_tx);
    // The state machine is applied without a flush per batch; this makes
    // it durable every --raft-checkpoint-ms (B25).
    let checkpointer = raft_storage.clone();
    let checkpoint_every = std::time::Duration::from_millis(args.raft_checkpoint_ms.max(10));
    tokio::spawn({
        let storage = checkpointer.clone();
        async move {
            let mut tick = tokio::time::interval(checkpoint_every);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                let s = storage.clone();
                match tokio::task::spawn_blocking(move || s.checkpoint().map_err(|e| e.to_string()))
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => tracing::error!("raft checkpoint failed: {e}"),
                    Err(e) => tracing::error!("raft checkpoint task: {e}"),
                }
            }
        }
    });
    let (log_store, state_machine) = openraft::storage::Adaptor::new(raft_storage);
    let raft_config = Arc::new(
        raft_config(
            args.raft_snapshot_every,
            args.raft_keep_logs,
            args.raft_heartbeat_ms,
            args.raft_election_ms,
        )
        .validate()
        .expect("raft config valid"),
    );
    let network = objectio_meta_store::MetaRaftNetworkFactory::new(node_id);
    let raft = openraft::Raft::<objectio_meta_store::MetaTypeConfig>::new(
        node_id,
        raft_config,
        network,
        log_store,
        state_machine,
    )
    .await
    .map_err(|e| anyhow::anyhow!("raft init: {e}"))?;
    let raft = Arc::new(raft);
    // Hand the handle to MetaService so set_config / delete_config
    // route through Raft (R1.5).
    meta_service.set_raft(raft.clone());

    // Drain observer — every replica runs the task, only the leader
    // issues client_writes. Kick it off once the Raft handle is wired
    // so `is_raft_leader` returns a meaningful answer.
    drain_observer::spawn(
        meta_service.clone(),
        std::time::Duration::from_secs(args.drain_interval_secs.max(1)),
        args.drain_batch,
    );
    liveness::spawn(meta_service.clone());
    campaign::spawn(raft.clone(), node_id);
    spawn_admin_bootstrap(
        meta_service.clone(),
        args.admin_user.clone(),
        args.data_dir.clone(),
    );

    // Report this node's release and format level (rolling upgrades),
    // through its own address: a follower forwards it to the leader.
    objectio_proto::transport::spawn_version_reporter(
        self_addr.clone(),
        "meta",
        node_id.to_string(),
        self_addr.clone(),
    );
    // PG balancer — leader-only, evaluates placement-group load each
    // tick. Currently observational (Phase 4a); execution lands with
    // the Phase 5 migration path.
    balancer::spawn(meta_service.clone());
    // Placement groups (B31): the default pool, stand-ins committed for
    // acting members that can't take writes, and stand-ins filled.
    service::pgs::spawn(meta_service.clone());
    service::peering::spawn(meta_service.clone());
    service::recovery::spawn(meta_service.clone());
    service::scrub::spawn(meta_service.clone());
    repair::spawn(
        meta_service.clone(),
        std::time::Duration::from_secs(args.repair_interval_secs),
    );
    info!(
        "Raft node id={} advertise={} (call POST /init on :{} to bootstrap)",
        node_id, self_addr, args.admin_port
    );

    // Start HTTP admin server (init, add-learner, change-membership, status)
    let admin_state = Arc::new(raft_admin::RaftAdminState {
        raft: raft.clone(),
        self_id: node_id,
        self_addr: self_addr.clone(),
    });
    let admin_port = args.admin_port;
    tokio::spawn(async move {
        let router = admin_state.router();
        let addr: SocketAddr = format!("0.0.0.0:{admin_port}")
            .parse()
            .expect("admin port valid");
        info!("Raft admin API on http://0.0.0.0:{}/", admin_port);
        if let Ok(l) = TcpListener::bind(addr).await {
            let _ = axum::serve(l, router).await;
        } else {
            error!("Raft admin server failed to bind {admin_port}");
        }
    });

    info!("Starting gRPC server on {}", addr);
    if metrics_port != 0 {
        info!("Metrics available at http://0.0.0.0:{metrics_port}/metrics");
    }

    // Start gRPC server with metadata, block, and Raft RPC services.
    let raft_rpc_svc = raft_rpc::RaftRpcService::new(raft.clone(), node_id);
    objectio_proto::transport::server()
        .layer(objectio_proto::rpc_metrics::RpcMetricsLayer(
            &op_metrics::RPC_METRICS,
        ))
        // A follower forwards every client call to the leader, so any meta
        // node serves any client (see `forward`).
        .layer(forward::ForwardToLeaderLayer::new(raft.clone(), node_id))
        .add_service(MetadataServiceServer::from_arc(meta_service))
        // Raft messages are JSON, which bloats binary values 3-4x; at
        // tonic's default 4 MiB limit a batch of large entries, or a
        // snapshot chunk, would be refused and the follower never caught up.
        .add_service(
            objectio_proto::raft::raft_rpc_server::RaftRpcServer::new(raft_rpc_svc)
                .max_decoding_message_size(RAFT_MESSAGE_LIMIT)
                .max_encoding_message_size(RAFT_MESSAGE_LIMIT),
        )
        .serve_with_shutdown(addr, async move {
            shutdown.await;
            info!("Shutting down...");
        })
        .await?;

    // What was applied since the last checkpoint, made durable.
    if let Err(e) =
        tokio::task::spawn_blocking(move || checkpointer.checkpoint().map_err(|e| e.to_string()))
            .await?
    {
        tracing::error!("raft checkpoint at shutdown failed: {e}");
    }
    info!("Metadata Service shut down gracefully");

    Ok(())
}

/// The bootstrap admin: created once for the whole cluster, by the Raft
/// leader, through Raft — every meta node used to create its own admin at
/// startup, so a 3-node cluster had three, and the credentials in use
/// stopped working after a failover. Every node, once the admin exists
/// (created here or replicated to it), writes its credentials next to its
/// store for wrappers (aio) to show, and logs them once.
fn spawn_admin_bootstrap(
    svc: Arc<service::MetaService>,
    admin_name: String,
    data_dir: std::path::PathBuf,
) {
    tokio::spawn(async move {
        loop {
            if let Some((access_key_id, secret_access_key)) = svc.admin_credentials(&admin_name) {
                // The secret goes only to the file, readable by its owner:
                // logs are shipped and kept where anyone may read them.
                let creds_path = data_dir.join("admin-creds.env");
                let body = format!(
                    "# Created by objectio-meta on first boot. Safe to delete.\n\
                     export AWS_ACCESS_KEY_ID={access_key_id}\n\
                     export AWS_SECRET_ACCESS_KEY={secret_access_key}\n"
                );
                match write_private(&creds_path, body.as_bytes()) {
                    Ok(()) => info!(
                        "Admin access key {access_key_id}; its secret is in {} (only its owner can read it)",
                        creds_path.display()
                    ),
                    Err(e) => error!(
                        "Admin access key {access_key_id}; failed to write its credentials to {}: {e}",
                        creds_path.display()
                    ),
                }
                return;
            }
            if svc.is_raft_leader()
                && let Err(e) = svc.create_admin(&admin_name).await
            {
                tracing::warn!("creating the bootstrap admin: {e}; retrying");
            }
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
    });
}

/// Write `body` to `path`, readable and writable by its owner only.
fn write_private(path: &std::path::Path, body: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    // An existing file keeps its mode through `open`: set it.
    f.set_permissions(std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    f.write_all(body)?;
    f.sync_all()
}

/// Metrics state for the Meta service
struct MetaMetricsState {
    meta_service: Arc<MetaService>,
    start_time: std::time::Instant,
}

/// Metrics HTTP handler
async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<Arc<MetaMetricsState>>,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        render_metrics(&state),
    )
}

/// This node's Prometheus exposition. Served on meta's own metrics port
/// and, through `MetadataService.GetMetrics`, from the gateway's.
fn render_metrics(state: &MetaMetricsState) -> String {
    let mut output = String::with_capacity(8 * 1024);

    // Meta service uptime
    let uptime = state.start_time.elapsed().as_secs();
    writeln!(
        output,
        "# HELP objectio_meta_uptime_seconds Metadata service uptime"
    )
    .unwrap();
    writeln!(output, "# TYPE objectio_meta_uptime_seconds counter").unwrap();
    writeln!(output, "objectio_meta_uptime_seconds {}", uptime).unwrap();

    // Get stats from meta service
    let stats = state.meta_service.stats();

    // Bucket and object counts
    writeln!(
        output,
        "# HELP objectio_meta_buckets_total Total number of buckets"
    )
    .unwrap();
    writeln!(output, "# TYPE objectio_meta_buckets_total gauge").unwrap();
    writeln!(output, "objectio_meta_buckets_total {}", stats.bucket_count).unwrap();

    // Object counts live on the OSDs, not here: the gateway sums them and
    // exports `objectio_cluster_objects` / `objectio_bucket_objects`.

    // OSD counts
    writeln!(
        output,
        "# HELP objectio_meta_osds_total Total registered OSDs"
    )
    .unwrap();
    writeln!(output, "# TYPE objectio_meta_osds_total gauge").unwrap();
    writeln!(output, "objectio_meta_osds_total {}", stats.osd_count).unwrap();
    repair::render_metrics(&mut output);
    service::pgs::render_metrics(&mut output);
    service::peering::render_metrics(&mut output);
    service::recovery::render_metrics(&mut output);
    service::scrub::render_metrics(&mut output);

    // User counts
    writeln!(output, "# HELP objectio_meta_users_total Total users").unwrap();
    writeln!(output, "# TYPE objectio_meta_users_total gauge").unwrap();
    writeln!(output, "objectio_meta_users_total {}", stats.user_count).unwrap();

    // Block volumes and snapshots, and the shared-stripe registry, from
    // the Raft tables.
    state.meta_service.render_block_metrics(&mut output);
    op_metrics::render_raft(&state.meta_service, &mut output);
    objectio_erasure::metrics::render(&mut output);

    output.push_str(&op_metrics::render());
    output.push_str(&state.meta_service.render_multipart_metrics());
    output.push_str(&objectio_common::process_metrics::render(""));
    output
}

/// Health check handler
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Start the metrics HTTP server
async fn start_metrics_server(port: u16, state: Arc<MetaMetricsState>) -> Result<()> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .with_state(state);

    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse()?;
    info!("Starting metrics server on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod raft_config_tests {
    /// The log is compacted at the configured interval, keeping the
    /// configured tail.
    #[test]
    fn the_log_is_compacted_as_configured() {
        let c = super::raft_config(1000, 100, 500, 2000).validate().unwrap();
        assert!(matches!(
            c.snapshot_policy,
            openraft::SnapshotPolicy::LogsSinceLast(1000)
        ));
        assert_eq!(c.max_in_snapshot_log_to_keep, 100);
    }
}
