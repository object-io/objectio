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
pub mod raft_batch;
pub mod raft_rpc;
pub mod read_gate;
pub mod repair;
pub mod restore;
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
    /// Node ID (for Raft)
    #[arg(long)]
    pub node_id: Option<u64>,

    /// Listen address for gRPC
    #[arg(short, long, default_value = "0.0.0.0:9100")]
    pub listen: String,

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

    /// Admin port for Raft bootstrap and membership (/init, /add-learner,
    /// /change-membership) and this node's state (/status, /health,
    /// /ready). HTTPS under mTLS, where every call but reading the state
    /// takes a client certificate of role admin; plain and unauthenticated
    /// otherwise.
    #[arg(long, default_value = "9102")]
    pub admin_port: u16,

    /// Address the admin port binds. Default: the host of `--listen`
    /// (0.0.0.0 there: every interface, so `objectio-install cluster init`
    /// and probes reach it from elsewhere; loopback: this host only).
    #[arg(long)]
    pub admin_host: Option<String>,

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
    /// waits for a follower to take entries before counting it lost, so
    /// it isn't lowered to elect sooner: a follower fsyncing a batch under
    /// load would time out. openraft's timer ticks every 1.5 × this: an
    /// idle leader heartbeats, and a follower checks its election timer,
    /// once a tick.
    #[arg(long, default_value_t = 500)]
    pub raft_heartbeat_ms: u64,

    /// Election timeout, in ms (`E`); all meta nodes should use the same.
    ///
    /// Each node draws its timeout once, at start, from [E, 2E]. A follower
    /// stands for election after hearing nothing from its leader for the
    /// leader lease (2E) plus that timeout, checked on the next tick, and
    /// until the lease has passed it refuses to vote for anyone else. The
    /// default, 1000, makes that 3-4 s of silence (up to 4.75 s with the
    /// tick); a candidate that loses a vote to a peer in the same term
    /// tries again after its timeout, 1-2 s more.
    ///
    /// Lower costs spurious elections: under write load a follower
    /// fsyncing its log, or a busy VM, delays heartbeats, and at 500 ms
    /// (1.5-2 s of silence) meta elected under the soak's load with no
    /// fault at all; every election is seconds of 503s. Higher costs
    /// failover: at 2000 a lost leader was replaced 6-9 s after its last
    /// heartbeat, 12 s when the first candidate's log was behind.
    ///
    /// A leader's quorum confirmation serves reads for a quarter of its
    /// lease, E/2 (`read_gate`), which is safe while that is shorter than
    /// every voter's lease (2E): values less than 4× apart across the
    /// nodes, as in a rolling upgrade that changes this default, are still
    /// safe.
    #[arg(long, default_value_t = 1000)]
    pub raft_election_ms: u64,

    /// Free space, in MiB, meta keeps on the filesystem of --data-dir.
    /// Below it the leader refuses new writes (an S3 client gets 507
    /// StorageFull) while reads go on, and a follower takes its leader's
    /// entries down to half of it; writes resume by themselves once there
    /// is room. A snapshot is built only with room for it above it. What
    /// meta still writes below it (entries already proposed, their
    /// applies, checkpoints, votes) is a few MiB.
    #[arg(long, default_value_t = objectio_meta_store::disk_space::DEFAULT_RESERVE >> 20)]
    pub min_free_mib: u64,

    /// Tests only: the data directory's free space, in bytes, is read from
    /// this file (relative to --data-dir) while it exists, instead of from
    /// its filesystem, which a test can't fill without root.
    #[arg(long, hide = true)]
    pub test_free_bytes_file: Option<PathBuf>,

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

    /// An offline tool to run instead of the service.
    #[command(subcommand)]
    pub tool: Option<restore::Tool>,
}

/// Where the admin port binds: `host` when given, else the host meta's
/// gRPC `listen` address binds (so a node listening on loopback doesn't
/// open its admin port to the network).
fn admin_address(host: Option<&str>, listen: &str, port: u16) -> Result<SocketAddr> {
    let ip: std::net::IpAddr = match host {
        Some(h) => h
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse()
            .map_err(|e| anyhow::anyhow!("--admin-host {h}: {e}"))?,
        None => listen
            .parse::<SocketAddr>()
            .map_err(|e| anyhow::anyhow!("Invalid listen address {listen}: {e}"))?
            .ip(),
    };
    Ok(SocketAddr::new(ip, port))
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
///   - providing a shutdown future (SIGTERM or SIGINT in the bin, a
///     broadcast-channel recv in aio)
pub async fn run(
    args: Args,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    // From here to serving is what a node costs after a crash (B25).
    let process_started = std::time::Instant::now();
    restore::refuse_incomplete(&args.data_dir)?;
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
    // The default pool would be refused (`check_scheme`) at every try to
    // make it, and nothing written; say so once, at start.
    if let Err(e) = service::pgs::check_scheme(&service::pgs::pool_with_scheme(
        service::pgs::DEFAULT_POOL,
        &ec_config,
    )) {
        anyhow::bail!(
            "the default pool's protection (--ec-k/--ec-m, or --replication) is refused: {}",
            e.message()
        );
    }

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

    // Room on the filesystem under the data: what meta keeps free, and
    // what it may still write (`objectio_meta_store::disk_space`).
    let reserve = args.min_free_mib.saturating_mul(1 << 20);
    let space = Arc::new(match &args.test_free_bytes_file {
        Some(file) => {
            tracing::warn!(
                "--test-free-bytes-file: free space is read from {} while it exists",
                file.display()
            );
            objectio_meta_store::DiskSpace::with_free_bytes_file(
                &args.data_dir,
                reserve,
                &args.data_dir.join(file),
            )
        }
        None => objectio_meta_store::DiskSpace::new(&args.data_dir, reserve),
    });
    match space.free() {
        Some(free) if free < reserve => tracing::warn!(
            "{} has {free} bytes free, under the reserve of {reserve} (--min-free-mib): \
             this node takes no writes until there is room",
            args.data_dir.display()
        ),
        Some(free) => info!(
            "{} has {free} bytes free; meta keeps {reserve} free",
            args.data_dir.display()
        ),
        None => tracing::warn!(
            "the free space of {} can't be told: no reserve is kept",
            args.data_dir.display()
        ),
    }

    // Parse listen address
    let addr: std::net::SocketAddr = args
        .listen
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid listen address {}: {}", args.listen, e))?;

    // Wrap services in Arc for sharing
    let meta_service = Arc::new(meta_service);

    // Create metrics state
    let metrics_state = Arc::new(MetaMetricsState {
        meta_service: meta_service.clone(),
        start_time: std::time::Instant::now(),
        space: space.clone(),
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
    // Bound here, not in the task that serves it: a port that can't be bound
    // is a failed start, not a node running on without its health endpoint.
    let metrics_port = args.metrics_port;
    if metrics_port != 0 {
        let listener = bind_http(metrics_port, "metrics").await?;
        let metrics_state_clone = metrics_state.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_metrics(listener, metrics_state_clone).await {
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
    .with_apply_listener(apply_tx)
    .with_disk_space(space.clone());
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
                    // redb refuses every read and write after one that
                    // failed (a full filesystem among the causes) until it
                    // is opened again: this node can't apply or serve, so it
                    // stops, as one whose Raft stopped does, and is
                    // restarted on its data (the log brings back what the
                    // checkpoint didn't make durable).
                    Ok(Err(e)) => {
                        error!("raft checkpoint failed: {e}; exiting so this node is restarted");
                        std::process::exit(1);
                    }
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
    let peers_without_room = network.peers_without_room();
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
    tokio::spawn(exit_when_raft_stops(raft.metrics()));
    // Hand the handle to MetaService so set_config / delete_config
    // route through Raft (R1.5). As leader, it refuses writes it has no
    // room for.
    meta_service.set_raft(raft_batch::MetaRaft::with_room(
        raft.clone(),
        raft_batch::Room {
            space: space.clone(),
            peers: peers_without_room,
        },
    ));

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
        space: space.clone(),
    });
    // Bound here, so a port that can't be had fails startup.
    let admin_addr = admin_address(args.admin_host.as_deref(), &args.listen, args.admin_port)?;
    let admin_listener = TcpListener::bind(admin_addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind the admin port {admin_addr}: {e}"))?;
    tokio::spawn(async move {
        if let Err(e) = raft_admin::serve(admin_state, admin_listener).await {
            error!("Raft admin server: {e:#}");
        }
    });

    info!("Starting gRPC server on {}", addr);
    if metrics_port != 0 {
        info!("Metrics available at http://0.0.0.0:{metrics_port}/metrics");
    }

    // Start gRPC server with metadata, block, and Raft RPC services.
    let read_gate = read_gate::ReadGate::for_raft(raft.clone());
    let raft_rpc_svc = raft_rpc::RaftRpcService::new(raft.clone(), node_id, read_gate.clone())
        .with_disk_space(space.clone());
    objectio_meta_store::commit_metrics::ready(process_started.elapsed());
    info!(
        "Serving {:.2} s after start (the database opened {})",
        process_started.elapsed().as_secs_f64(),
        if objectio_meta_store::commit_metrics::open_repaired() {
            "after walking the whole file"
        } else {
            "without a walk"
        }
    );
    let grpc = objectio_proto::transport::server()
        .layer(objectio_proto::rpc_metrics::RpcMetricsLayer(
            &op_metrics::RPC_METRICS,
        ))
        // Who may call what (mTLS): checked here, on the node the caller
        // reached, before a follower forwards the call under its own
        // certificate.
        .layer(objectio_proto::peer_auth::PeerAuthLayer::new(&[
            objectio_proto::peer_auth::METADATA_SERVICE,
            objectio_proto::peer_auth::RAFT_SERVICE,
        ]))
        // A follower forwards every client call to the leader, so any meta
        // node serves any client (see `forward`).
        .layer(forward::ForwardToLeaderLayer::new(
            raft.clone(),
            node_id,
            read_gate,
        ))
        .add_service(MetadataServiceServer::from_arc(meta_service))
        // Raft messages are JSON, which bloats binary values 3-4x; at
        // tonic's default 4 MiB limit a batch of large entries, or a
        // snapshot chunk, would be refused and the follower never caught up.
        .add_service(
            objectio_proto::raft::raft_rpc_server::RaftRpcServer::new(raft_rpc_svc)
                .max_decoding_message_size(RAFT_MESSAGE_LIMIT)
                .max_encoding_message_size(RAFT_MESSAGE_LIMIT),
        );
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind gRPC on {addr}: {e}"))?;
    objectio_proto::transport::serve(grpc, listener, async move {
        shutdown.await;
        info!("Shutting down...");
    })
    .await?;

    // The calls in flight have been answered. Raft stops before the last
    // checkpoint, so that checkpoint holds everything it applied.
    match tokio::time::timeout(std::time::Duration::from_secs(5), raft.shutdown()).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!("raft shutdown: {e}"),
        Err(_) => tracing::warn!("raft did not stop within 5 s; checkpointing anyway"),
    }
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
    space: Arc<objectio_meta_store::DiskSpace>,
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
    state.meta_service.render_restore_metrics(&mut output);
    op_metrics::render_raft(&state.meta_service, &mut output);
    state.space.render_metrics(&mut output);
    objectio_erasure::metrics::render(&mut output);

    output.push_str(&op_metrics::render());
    output.push_str(&state.meta_service.render_multipart_metrics());
    output.push_str(&objectio_common::process_metrics::render(""));
    output
}

/// Why this node's Raft has stopped for good, if it has: a storage error or
/// a panic in its core. It answers nothing after that, while the process,
/// with its gRPC server and caches, would go on.
fn raft_fatal(m: &openraft::RaftMetrics<u64, openraft::BasicNode>) -> Option<String> {
    m.running_state.as_ref().err().map(ToString::to_string)
}

type RaftMetricsWatch =
    tokio::sync::watch::Receiver<openraft::RaftMetrics<u64, openraft::BasicNode>>;

/// Exit the process when this node's Raft stops for good, so whatever runs
/// it (Kubernetes, systemd, the aio wrapper) starts it again: a restart
/// reopens the store and applies the log from the last checkpoint, which a
/// stopped core never would. Not on a deliberate shutdown.
async fn exit_when_raft_stops(metrics: RaftMetricsWatch) {
    if let Some(why) = raft_stopped(metrics).await {
        error!("Raft stopped: {why}; exiting so this node is restarted");
        std::process::exit(1);
    }
}

/// Once this node's Raft has stopped for good: why. `None` when it was
/// shut down on purpose.
async fn raft_stopped(mut metrics: RaftMetricsWatch) -> Option<String> {
    loop {
        {
            let m = metrics.borrow_and_update();
            match &m.running_state {
                Err(openraft::error::Fatal::Stopped) => return None,
                Err(fatal) => return Some(fatal.to_string()),
                Ok(()) => {}
            }
        }
        metrics.changed().await.ok()?;
    }
}

/// Health check: 503 once this node's Raft has stopped for good (it is
/// about to exit, see [`exit_when_raft_stops`]); OK otherwise, including
/// while it starts.
async fn health_handler(
    axum::extract::State(state): axum::extract::State<Arc<MetaMetricsState>>,
) -> impl IntoResponse {
    let fatal = state
        .meta_service
        .raft_handle()
        .and_then(|r| raft_fatal(&r.metrics().borrow()));
    match fatal {
        Some(why) => (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("raft stopped: {why}"),
        ),
        None => (StatusCode::OK, "OK".to_string()),
    }
}

/// Bind an HTTP server's port on every address, or say which could not be.
async fn bind_http(port: u16, what: &str) -> Result<TcpListener> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind the {what} port {addr}: {e}"))
}

/// Serve the metrics HTTP server on `listener`.
async fn serve_metrics(listener: TcpListener, state: Arc<MetaMetricsState>) -> Result<()> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .with_state(state);
    info!("Starting metrics server on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod raft_stopped_tests {
    use super::raft_stopped;

    /// A Raft that stops for good is noticed, with why; one shut down on
    /// purpose is not, and the process goes on to exit as it chose.
    #[tokio::test]
    async fn a_raft_stopped_for_good_is_noticed_and_a_shutdown_is_not() {
        use openraft::error::Fatal;
        let (tx, rx) = tokio::sync::watch::channel(openraft::RaftMetrics::new_initial(1));
        let watching = tokio::spawn(raft_stopped(rx));
        tokio::task::yield_now().await;
        assert!(!watching.is_finished());
        tx.send_modify(|m| m.running_state = Err(Fatal::Panicked));
        let why = watching.await.unwrap();
        assert!(why.is_some_and(|w| w.contains("panicked")));

        let (tx, rx) = tokio::sync::watch::channel(openraft::RaftMetrics::new_initial(1));
        tx.send_modify(|m| m.running_state = Err(Fatal::Stopped));
        assert_eq!(raft_stopped(rx).await, None);
    }
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

    /// The default timing, as openraft 0.9 applies it: a follower whose
    /// leader is gone stands for election after the leader lease
    /// (`election_timeout_max`) plus its own timeout (drawn once from
    /// [min, max]), on the first tick (every 1.5 heartbeats) after that.
    /// It is replaced within ~5 s of its last heartbeat, ~8 s if the first
    /// candidate loses a vote in the same term; a follower tolerates 3 s
    /// of silence (2× what elected spuriously under load at 500 ms); and
    /// a read confirmation is reused for less than any voter's lease.
    #[test]
    fn the_default_timing_replaces_a_lost_leader_within_seconds() {
        use clap::Parser;
        let args = super::Args::try_parse_from(["objectio-meta"]).unwrap();
        let c = super::raft_config(1, 1, args.raft_heartbeat_ms, args.raft_election_ms)
            .validate()
            .unwrap();
        let (min, max) = (c.election_timeout_min, c.election_timeout_max);
        let lease = max;
        let tick = c.heartbeat_interval * 3 / 2;

        let tolerated = lease + min;
        let first = lease + max + tick;
        let after_a_lost_vote = first + max + tick;
        assert!(tolerated >= 3000, "elects after {tolerated} ms of silence");
        assert!(first <= 5000, "first election {first} ms after the leader");
        assert!(after_a_lost_vote <= 8000, "{after_a_lost_vote} ms");

        // Read confirmations (read_gate) are reused for a quarter of the
        // lease from when the round started; no voter that acked it votes
        // for another leader within its lease, so the reuse must end well
        // before.
        let window = lease / 4;
        assert_eq!(window, 500, "the window is E/2");
        // A node still on the previous default (2000) during a rolling
        // upgrade, as leader, reuses for 1 s; voters here lease for 2 s.
        assert!(4000 / 4 < lease);
    }
}
