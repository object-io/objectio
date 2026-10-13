//! ObjectIO OSD - Object Storage Daemon (library form).
//!
//! `src/main.rs` is a thin entrypoint. `run()` is also consumed
//! in-process by `bin/aio`.

pub mod discovery;
pub mod pg_epochs;
pub mod pg_index;
#[cfg(feature = "rdma")]
pub mod rdma;
pub mod service;
pub mod shard_store;
mod usage;

use anyhow::Result;
use axum::{
    Router,
    http::{StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use clap::Parser;
use objectio_proto::metadata::{
    FailureDomainInfo, RegisterOsdRequest, metadata_service_client::MetadataServiceClient,
};
use objectio_proto::storage::storage_service_server::StorageServiceServer;
use objectio_storage::SmartMonitor;
use serde::Deserialize;
use service::OsdService;
use std::fmt::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "objectio-osd")]
#[command(about = "ObjectIO Object Storage Daemon")]
#[command(version)]
pub struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/objectio/osd.toml")]
    pub config: String,

    /// Listen address for gRPC
    #[arg(short, long)]
    pub listen: Option<String>,

    /// Advertise address (how other services reach this OSD)
    /// If not set, derived from listen address
    #[arg(long)]
    pub advertise_addr: Option<String>,

    /// Disk paths to use for storage. Explicit — discovery skips most
    /// filters for these (still honors root-FS exclusion + mount check).
    #[arg(long)]
    pub disks: Vec<String>,

    /// Disk discovery glob(s), e.g. `/dev/disk/by-id/wwn-*` or
    /// `/data/disk*/disk.raw`. Each match is probed; previously-
    /// claimed ObjectIO disks attach automatically, blanks are
    /// reported but skipped unless `--init-blank-disks=true`.
    /// Operator-safe by default: foreign filesystems and the root
    /// FS's backing device are always excluded.
    #[arg(long = "disk-filter")]
    pub disk_filters: Vec<String>,

    /// Minimum disk size (bytes) considered by discovery. Guards
    /// against accidentally formatting a tiny EFI partition or an
    /// install image.
    #[arg(long, default_value_t = 1024u64 * 1024 * 1024)]
    pub disk_min_size: u64,

    /// Allow discovery to format blank disks. Off by default — an
    /// operator must explicitly opt in, matching the Rook /
    /// ceph-volume posture ("refuse to touch anything we don't
    /// already own").
    #[arg(long, default_value_t = false)]
    pub init_blank_disks: bool,

    /// Metadata service endpoint: one address, or every meta node's,
    /// comma-separated
    #[arg(long)]
    pub meta_endpoint: Option<String>,

    /// Data directory for OSD metadata
    #[arg(long)]
    pub data_dir: Option<String>,

    /// Log level
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Prometheus `/metrics` port; 0 serves none (the gateway re-exports
    /// these metrics either way)
    #[arg(long, default_value = "9201")]
    pub metrics_port: u16,

    /// Seconds between scrub passes, each of which reads every shard on this
    /// OSD and checks its checksums, so rot is found before a read needs the
    /// shard. A pass starts this long after the previous one ended. 0 turns
    /// scrubbing off.
    #[arg(long, default_value_t = 7 * 24 * 60 * 60)]
    pub scrub_interval_secs: u64,

    /// Read rate cap for scrubbing, in MiB/s, so it does not compete with
    /// client I/O. 0 means unthrottled.
    #[arg(long, default_value_t = 50)]
    pub scrub_rate_mib: u64,

    /// The share of each disk client writes may fill; past it they are
    /// refused (the gateway answers 507), and the rest is kept for repair,
    /// drain and backfill.
    #[arg(long, env = "OBJECTIO_OSD_FULL_RATIO", default_value_t = crate::service::DEFAULT_FULL_RATIO)]
    pub full_ratio: f64,

    /// The metadata index's page cache, in MiB: with the memtables, all
    /// the memory the OSD's metadata takes, whatever its object count.
    #[arg(long, env = "OBJECTIO_OSD_META_CACHE_MIB", default_value_t = 1024)]
    pub meta_cache_mib: usize,

    /// The engine of the metadata index (B27): `native`, or `rocksdb` (in a
    /// build with the `rocksdb` feature). A data directory is opened only
    /// by the engine that wrote it.
    #[arg(long, env = "OBJECTIO_OSD_META_ENGINE", default_value = "native")]
    pub meta_engine: objectio_storage::metadata::MetaEngine,

    /// Accept shard transfers over Mooncake Transfer Engine: `rdma`, or
    /// `tcp` to develop without RDMA hardware. Unset: gRPC bytes only.
    #[cfg(feature = "rdma")]
    #[arg(long)]
    pub rdma: Option<String>,

    /// Address Transfer Engine binds and advertises — one on the storage
    /// network, never a public one. Defaults to the host of
    /// --advertise-addr.
    #[cfg(feature = "rdma")]
    #[arg(long)]
    pub rdma_host: Option<String>,

    /// 4 MiB staging slots, which bound concurrent RDMA shard transfers.
    /// When they are all busy the gateway sends the shard over gRPC.
    #[cfg(feature = "rdma")]
    #[arg(long, default_value_t = 64)]
    pub rdma_staging_slots: usize,

    /// mTLS between services (A8a).
    #[command(flatten)]
    pub tls: objectio_proto::transport::TlsArgs,
}

/// Configuration file structure
#[derive(Debug, Deserialize, Default)]
struct Config {
    #[serde(default)]
    osd: OsdConfig,
    #[serde(default)]
    storage: StorageConfig,
    #[serde(default)]
    logging: LoggingConfig,
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
struct OsdConfig {
    #[serde(default)]
    node_id: Option<String>,
    #[serde(default)]
    node_name: Option<String>,
    #[serde(default = "default_listen")]
    listen: String,
    /// Address to advertise to metadata service (how other services reach this OSD)
    #[serde(default)]
    advertise_addr: Option<String>,
    #[serde(default = "default_meta_endpoint")]
    meta_endpoint: String,
    #[serde(default)]
    failure_domain: FailureDomainConfig,
    #[serde(default = "default_weight")]
    weight: f64,
}

/// Failure domain configuration — defines where this OSD sits in the
/// topology. `zone` and `host` are additive; empty string on either means
/// "inherit from the enclosing level" (still safe for the 3-level world).
#[derive(Debug, Deserialize, Clone)]
struct FailureDomainConfig {
    #[serde(default = "default_region")]
    region: String,
    #[serde(default = "default_datacenter")]
    datacenter: String,
    #[serde(default = "default_rack")]
    rack: String,
    #[serde(default)]
    zone: String,
    #[serde(default)]
    host: String,
}

impl Default for FailureDomainConfig {
    fn default() -> Self {
        Self {
            region: default_region(),
            datacenter: default_datacenter(),
            rack: default_rack(),
            zone: String::new(),
            host: String::new(),
        }
    }
}

fn default_region() -> String {
    "default".to_string()
}

fn default_datacenter() -> String {
    "default".to_string()
}

fn default_rack() -> String {
    "default".to_string()
}

fn default_weight() -> f64 {
    1.0
}

#[derive(Debug, Deserialize)]
struct StorageConfig {
    #[serde(default)]
    disks: Vec<String>,
    #[serde(default = "default_block_size")]
    block_size: usize,
    #[serde(default = "default_data_dir")]
    data_dir: String,
}

// Hand-roll Default so `Config::default()` (hit when the config file
// is absent) still honors default_block_size — the derive(Default)
// version would produce block_size: 0 and OSD init would panic on
// `disk_size / block_size` during superblock computation.
impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            disks: Vec::new(),
            block_size: default_block_size(),
            data_dir: default_data_dir(),
        }
    }
}

#[derive(Debug, Deserialize, Default)]
struct LoggingConfig {
    #[serde(default = "default_log_level")]
    level: String,
}

fn default_listen() -> String {
    "0.0.0.0:9002".to_string()
}

fn default_meta_endpoint() -> String {
    "http://localhost:9001".to_string()
}

/// Disk allocation granularity.
///
/// Derived from the storage layer's constant rather than restated, because it
/// was restated here as 4 MiB — the *stripe* size — and that is the value the
/// OSD actually used. `objectio_common::StorageConfig` said one thing,
/// `objectio-storage` said another, and this said a third; this one won.
///
/// The effect: every shard occupied a whole 4 MiB block however small it was,
/// so a 4 KB object and a 4 MB object both cost 24 MB across a 4+2 stripe.
fn default_block_size() -> usize {
    objectio_storage::DEFAULT_BLOCK_SIZE as usize
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_data_dir() -> String {
    "./osd-data".to_string()
}

/// Run the OSD until `shutdown` resolves. Caller installs tracing
/// subscriber and builds `args` (via CLI parse in the bin, or direct
/// construction in aio).
pub async fn run(
    args: Args,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    objectio_proto::transport::configure_tls(&args.tls).map_err(anyhow::Error::msg)?;
    // Load config file if it exists
    let config: Config = if std::path::Path::new(&args.config).exists() {
        let config_str = std::fs::read_to_string(&args.config)?;
        toml::from_str(&config_str).unwrap_or_else(|e| {
            eprintln!("Warning: Failed to parse config file: {}", e);
            Config::default()
        })
    } else {
        Config::default()
    };

    // Merge CLI args with config file (CLI takes precedence)
    let listen = args.listen.unwrap_or(config.osd.listen);
    let meta_endpoint = args.meta_endpoint.unwrap_or(config.osd.meta_endpoint);
    let explicit_disks = if args.disks.is_empty() {
        config.storage.disks
    } else {
        args.disks
    };
    let block_size = config.storage.block_size;
    let data_dir = args.data_dir.unwrap_or(config.storage.data_dir);
    let log_level = if args.log_level != "info" {
        args.log_level
    } else {
        config.logging.level
    };

    // Tracing subscriber is installed by the caller (bin/main.rs or
    // aio). We just consume log_level from config so the bin's CLI
    // override path still records what it wanted.
    let _ = log_level;

    info!("Starting ObjectIO OSD");

    // Resolve final disk list — explicit disks pass through; any
    // `--disk-filter` globs are expanded, root-FS device + mounted
    // partitions excluded, superblocks classified.
    let disks = {
        let discovered =
            discovery::discover(&explicit_disks, &args.disk_filters, args.disk_min_size)
                .map_err(|e| anyhow::anyhow!("disk discovery failed: {e}"))?;

        let mut claim = Vec::new();
        for d in &discovered {
            let path = d.path.display().to_string();
            let is_explicit = explicit_disks.iter().any(|p| p == &path);
            match &d.state {
                discovery::DiskState::Claimed {
                    cluster_uuid,
                    node_id,
                } => {
                    info!(
                        "discovery: claiming {path} ({} bytes, cluster={}, node_id={})",
                        d.size_bytes,
                        cluster_uuid,
                        hex::encode(node_id)
                    );
                    claim.push(path);
                }
                discovery::DiskState::Blank => {
                    // Explicit `--disk` paths bypass the --init-blank-disks
                    // gate — operator passed the path verbatim, so the
                    // intent is "use this". The gate only governs
                    // glob-discovered disks where auto-format could be
                    // destructive.
                    if is_explicit || args.init_blank_disks {
                        let reason = if is_explicit {
                            "explicit --disk"
                        } else {
                            "--init-blank-disks"
                        };
                        info!("discovery: initialising blank disk {path} ({reason})");
                        claim.push(path);
                    } else {
                        warn!(
                            "discovery: skipping blank disk {path} — pass --init-blank-disks=true to format"
                        );
                    }
                }
                discovery::DiskState::Foreign { reason } => {
                    warn!("discovery: refusing foreign disk {path}: {reason}");
                }
            }
        }
        if claim.is_empty() {
            anyhow::bail!(
                "no disks to claim after discovery; explicit={} filters={} foreign/blank/excluded={}",
                explicit_disks.len(),
                args.disk_filters.len(),
                discovered.len()
            );
        }
        claim
    };
    info!("Config file: {}", args.config);
    info!("Disks: {:?}", disks);
    info!("Block size: {block_size} bytes");

    if disks.is_empty() {
        error!(
            "No disks specified. Use --disks or configure in {}",
            args.config
        );
        std::process::exit(1);
    }

    // Initialize OSD service
    let data_path = PathBuf::from(&data_dir);
    info!("Data directory: {}", data_dir);
    let disk_paths = disks.clone();
    let (cache_bytes, engine) = (args.meta_cache_mib << 20, args.meta_engine);
    info!("Metadata index: {engine:?}");
    let osd_service =
        match OsdService::new_with_store(disk_paths, block_size as u32, data_path, |c| {
            c.cache_bytes = cache_bytes;
            c.engine = engine;
        }) {
            Ok(s) => s.with_full_ratio(args.full_ratio),
            Err(e) => {
                error!("Failed to initialize OSD: {}", e);
                std::process::exit(1);
            }
        };
    // Wrap in Arc early so the registration task (which needs to stamp
    // cluster_uuid into disk superblocks on the response) can share
    // it with the gRPC server and the metrics state.
    let osd_service = Arc::new(osd_service);

    if args.scrub_interval_secs > 0 {
        let svc = Arc::clone(&osd_service);
        let interval = Duration::from_secs(args.scrub_interval_secs);
        let rate = args.scrub_rate_mib * 1024 * 1024;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                svc.scrub_pass(rate).await;
            }
        });
        info!(
            "Scrubbing every {}s at up to {} MiB/s",
            args.scrub_interval_secs, args.scrub_rate_mib
        );
    }

    let node_id_bytes = *osd_service.node_id();
    let node_id = hex::encode(node_id_bytes);
    info!("OSD node ID: {}", node_id);

    // Get disk IDs for registration
    let disk_ids: Vec<Vec<u8>> = osd_service.disk_ids().iter().map(|d| d.to_vec()).collect();
    let disk_capacities = osd_service.disk_capacities();
    info!("OSD managing {} disks", disk_ids.len());

    // Parse listen address and bind now, before registering: the address
    // meta records must be one this process already holds. Port 0 lets the
    // OS choose; picking a "free" port and binding it later raced with every
    // other socket on the host, and an OSD that lost left meta pointing at
    // an address something else answered.
    let addr: SocketAddr = listen
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid listen address {}: {}", listen, e))?;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("OSD could not listen on {addr}: {e}"))?;
    let bound = listener.local_addr()?;
    info!("OSD listening on {bound}");

    // Determine the address to advertise to the metadata service
    // Priority: CLI --advertise-addr > config advertise_addr > derived from listen address
    let advertise_addr = if let Some(addr) = args.advertise_addr {
        // Use explicit CLI advertise address
        if addr.starts_with("http://") || addr.starts_with("https://") {
            addr
        } else {
            format!("http://{}", addr)
        }
    } else if let Some(addr) = &config.osd.advertise_addr {
        // Use config file advertise address
        if addr.starts_with("http://") || addr.starts_with("https://") {
            addr.clone()
        } else {
            format!("http://{}", addr)
        }
    } else if listen.starts_with("0.0.0.0") {
        // Fallback: use localhost when listening on all interfaces
        format!(
            "http://127.0.0.1:{}",
            listen.split(':').next_back().unwrap_or("9002")
        )
    } else {
        format!("http://{}", listen)
    };
    // An advertised port of 0 means "whatever we were given".
    let advertise_addr = match advertise_addr.strip_suffix(":0") {
        Some(host) => format!("{host}:{}", bound.port()),
        None => advertise_addr,
    };
    info!("Advertising at: {}", advertise_addr);

    // Before registering, so the segment goes to meta with the address.
    #[cfg(feature = "rdma")]
    if let Some(protocol) = args.rdma.as_deref() {
        let protocol = rdma::parse_protocol(protocol).map_err(|e| anyhow::anyhow!(e))?;
        let host = args
            .rdma_host
            .clone()
            .unwrap_or_else(|| host_of(&advertise_addr).to_string());
        let staging = rdma::RdmaStaging::start(protocol, &host, args.rdma_staging_slots)
            .map_err(|e| anyhow::anyhow!("rdma ({protocol:?} on {host}): {e}"))?;
        info!(
            "Transfer Engine ({protocol:?}) segment {}, {} staging slots",
            staging.segment(),
            args.rdma_staging_slots
        );
        osd_service.enable_rdma(staging);
    }
    // For a supervisor (aio) that let the OS pick the port.
    let addr_file = PathBuf::from(&data_dir).join("osd.addr");
    if let Err(e) = std::fs::write(&addr_file, &advertise_addr) {
        warn!("could not write {}: {e}", addr_file.display());
    }

    // The host defaults to this machine's name, as Ceph's does. Left
    // empty, every OSD of a cluster set up without a host in its config
    // was one failure domain: nothing spread across machines, and a pool
    // with placement groups could not be made ("have 1 failure domain").
    let mut failure_domain = config.osd.failure_domain.clone();
    if failure_domain.host.is_empty() {
        failure_domain.host = gethostname::gethostname().to_string_lossy().into_owned();
    }
    let node_name = config.osd.node_name.clone();
    let weight = config.osd.weight;
    info!(
        "Failure domain: region={}, datacenter={}, rack={}, host={}",
        failure_domain.region, failure_domain.datacenter, failure_domain.rack, failure_domain.host
    );

    // Register with metadata service
    let meta_endpoint_clone = meta_endpoint.clone();
    let node_id_for_reg = node_id_bytes;
    let disk_ids_for_reg = disk_ids.clone();
    let disk_capacities_for_reg = disk_capacities.clone();
    let advertise_addr_clone = advertise_addr.clone();
    let failure_domain_for_reg = failure_domain.clone();
    let node_name_for_reg = node_name.clone();
    let osd_service_for_reg = osd_service.clone();

    // Spawn registration task with retry. Meta may be coming up in
    // parallel (rolling restart, k8s StatefulSet) so a transport error on
    // first attempt shouldn't leave this OSD unregistered forever — back
    // off and retry until it sticks.
    let registration_handle = tokio::spawn(async move {
        let mut delay_secs: u64 = 2;
        loop {
            match register_with_meta(
                &meta_endpoint_clone,
                &node_id_for_reg,
                &advertise_addr_clone,
                &disk_ids_for_reg,
                &disk_capacities_for_reg,
                &failure_domain_for_reg,
                node_name_for_reg.as_deref(),
                weight,
                osd_service_for_reg.as_ref(),
            )
            .await
            {
                Ok(()) => return Ok::<(), String>(()),
                Err(e) => {
                    warn!(
                        "register_with_meta failed: {e}; retrying in {}s",
                        delay_secs
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                    // Cap the backoff at 30s so we keep trying during
                    // long meta outages without hammering it either.
                    delay_secs = (delay_secs * 2).min(30);
                }
            }
        }
    });

    // Create SMART monitor
    let smart_monitor = Arc::new(SmartMonitor::new(&node_id, Duration::from_secs(300)));
    let disk_devices = disks.clone();

    // Check if SMART monitoring is available
    if SmartMonitor::is_available() {
        info!("SMART monitoring available - disk health will be tracked");
    } else {
        warn!(
            "SMART monitoring unavailable (smartctl not found) - disk health metrics will be limited"
        );
    }

    // Create metrics state
    let metrics_state = Arc::new(OsdMetricsState {
        osd_service: osd_service.clone(),
        osd_id: node_id.clone(),
        node_name: node_name.clone().unwrap_or_else(|| "unknown".to_string()),
        failure_domain: failure_domain.clone(),
        start_time: std::time::Instant::now(),
        smart_monitor: smart_monitor.clone(),
        disk_devices: disk_devices.clone(),
    });

    // Let the gateway pull the same exposition over gRPC. Weak, because
    // the metrics state holds the service and this closure lives on it.
    {
        let weak = Arc::downgrade(&metrics_state);
        osd_service.set_metrics_renderer(Box::new(move || {
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

    info!("Starting gRPC server on {}", addr);
    if metrics_port != 0 {
        info!("Metrics available at http://0.0.0.0:{metrics_port}/metrics");
    }

    // Report this binary's release and format level (rolling upgrades).
    objectio_proto::transport::spawn_version_reporter(
        meta_endpoint.clone(),
        "osd",
        node_id.clone(),
        advertise_addr.clone(),
    );

    // Start heartbeat task
    let heartbeat_meta_endpoint = meta_endpoint.clone();
    let heartbeat_node_id = node_id_bytes;
    let heartbeat_disk_ids = disk_ids.clone();
    let heartbeat_handle = tokio::spawn(async move {
        heartbeat_loop(
            &heartbeat_meta_endpoint,
            &heartbeat_node_id,
            &heartbeat_disk_ids,
        )
        .await
    });

    // Start gRPC server with increased message size limit (100MB for large objects)
    let max_message_size = 100 * 1024 * 1024; // 100 MB
    let storage_service = StorageServiceServer::from_arc(osd_service)
        .max_decoding_message_size(max_message_size)
        .max_encoding_message_size(max_message_size);

    // tonic sets TCP_NODELAY only on listeners it binds itself; a listener
    // handed in is served as-is, with Nagle on. Nagle holding back the tail
    // of a response while the peer delays its ACK stalled idle requests by
    // ~40 ms on Linux.
    let incoming = tonic::transport::server::TcpIncoming::from_listener(listener, true, None)
        .map_err(|e| anyhow::anyhow!("OSD listener: {e}"))?;
    let server_future = objectio_proto::transport::server()
        .layer(objectio_proto::rpc_metrics::RpcMetricsLayer(&RPC_METRICS))
        .add_service(storage_service)
        .serve_with_incoming_shutdown(incoming, async move {
            shutdown.await;
            info!("Shutting down...");
        });

    // Wait for registration to complete (with timeout)
    tokio::select! {
        result = registration_handle => {
            match result {
                Ok(Ok(())) => info!("Registered with metadata service"),
                Ok(Err(e)) => warn!("Failed to register with metadata service: {} (continuing anyway)", e),
                Err(e) => warn!("Registration task error: {} (continuing anyway)", e),
            }
        }
        _ = tokio::time::sleep(Duration::from_secs(5)) => {
            warn!("Registration timed out (continuing anyway)");
        }
    }

    // Run server (heartbeat continues in background)
    server_future.await?;

    // Cancel heartbeat on shutdown
    heartbeat_handle.abort();

    info!("OSD shut down gracefully");

    Ok(())
}

/// Register this OSD with the metadata service. On success, stamps
/// the returned cluster_uuid into every disk's superblock so the
/// cross-cluster guard (`DiskManager::set_identity`) can reject
/// disks that try to join a different cluster later.
#[allow(clippy::result_large_err, clippy::too_many_arguments)]
async fn register_with_meta(
    meta_endpoint: &str,
    node_id: &[u8; 16],
    address: &str,
    disk_ids: &[Vec<u8>],
    disk_capacity_bytes: &[u64],
    failure_domain: &FailureDomainConfig,
    node_name: Option<&str>,
    weight: f64,
    osd_service: &OsdService,
) -> Result<(), String> {
    info!("Registering OSD with metadata service at {}", meta_endpoint);

    // Connect to metadata service
    let mut client = MetadataServiceClient::new(
        objectio_proto::transport::meta_channel(meta_endpoint)
            .await
            .map_err(|e| format!("Failed to connect to metadata service: {e}"))?,
    );

    // Call RegisterOsd RPC with failure domain + per-disk capacity (latter
    // feeds meta's cluster capacity accounting).
    let response = client
        .register_osd(RegisterOsdRequest {
            node_id: node_id.to_vec(),
            address: address.to_string(),
            disk_ids: disk_ids.to_vec(),
            failure_domain: Some(FailureDomainInfo {
                region: failure_domain.region.clone(),
                datacenter: failure_domain.datacenter.clone(),
                rack: failure_domain.rack.clone(),
                zone: failure_domain.zone.clone(),
                host: failure_domain.host.clone(),
            }),
            node_name: node_name.unwrap_or_default().to_string(),
            weight,
            disk_capacity_bytes: disk_capacity_bytes.to_vec(),
            te_segment: osd_service.te_segment(),
            shards_dropped: osd_service.shards_dropped_at_open(),
        })
        .await
        .map_err(|e| format!("Failed to register OSD: {}", e))?;

    let resp = response.into_inner();

    // Every placement group's epoch (B31): requests placed under an older
    // one are refused from now on.
    osd_service.pg_epochs().set_meta_endpoint(meta_endpoint);
    for e in &resp.pg_epochs {
        osd_service.pg_epochs().learn(&e.pool, e.pg_id, e.epoch);
    }

    // Stamp the cluster_uuid into each disk's superblock. Empty
    // response means meta is pre-3.1 or a follower that couldn't
    // write — leave superblocks alone in that case.
    if resp.cluster_uuid.len() == 16 {
        let mut cuid_bytes = [0u8; 16];
        cuid_bytes.copy_from_slice(&resp.cluster_uuid);
        let cluster_uuid = uuid::Uuid::from_bytes(cuid_bytes);
        if let Err(e) = osd_service.stamp_cluster_uuid(cluster_uuid) {
            warn!(
                "cluster_uuid stamping failed: {e} — \
                 cross-cluster guard won't trigger on this OSD until next register"
            );
        }
    }

    info!(
        "OSD {} with {} disks ready to serve at {} (topology v{})",
        hex::encode(&node_id[..4]),
        disk_ids.len(),
        address,
        resp.topology_version
    );

    Ok(())
}

/// Every gRPC call this OSD serves: counts by status and latency.
static RPC_METRICS: std::sync::LazyLock<objectio_proto::rpc_metrics::RpcMetrics> =
    std::sync::LazyLock::new(Default::default);

/// OSD metrics state for the HTTP server
struct OsdMetricsState {
    osd_service: Arc<OsdService>,
    osd_id: String,
    node_name: String,
    failure_domain: FailureDomainConfig,
    start_time: std::time::Instant,
    smart_monitor: Arc<SmartMonitor>,
    disk_devices: Vec<String>,
}

/// Metrics HTTP handler
async fn metrics_handler(
    axum::extract::State(state): axum::extract::State<Arc<OsdMetricsState>>,
) -> impl IntoResponse {
    // SMART polling may shell out to smartctl.
    let output = tokio::task::spawn_blocking(move || render_metrics(&state))
        .await
        .unwrap_or_default();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        output,
    )
}

/// This OSD's full Prometheus exposition. Served on the OSD's own metrics
/// port and, through `StorageService.GetMetrics`, from the gateway's.
fn render_metrics(state: &OsdMetricsState) -> String {
    let mut output = String::with_capacity(16 * 1024);

    // OSD info
    writeln!(output, "# HELP objectio_osd_info OSD information").unwrap();
    writeln!(output, "# TYPE objectio_osd_info gauge").unwrap();
    writeln!(
        output,
        "objectio_osd_info{{osd_id=\"{}\",node=\"{}\",rack=\"{}\",datacenter=\"{}\",region=\"{}\"}} 1",
        state.osd_id, state.node_name, state.failure_domain.rack,
        state.failure_domain.datacenter, state.failure_domain.region
    ).unwrap();

    // OSD uptime
    let uptime = state.start_time.elapsed().as_secs();
    writeln!(
        output,
        "# HELP objectio_osd_uptime_seconds OSD uptime in seconds"
    )
    .unwrap();
    writeln!(output, "# TYPE objectio_osd_uptime_seconds counter").unwrap();
    writeln!(
        output,
        "objectio_osd_uptime_seconds{{osd_id=\"{}\"}} {}",
        state.osd_id, uptime
    )
    .unwrap();

    // Get disk stats from OSD service
    let status = state.osd_service.status();

    // OSD capacity and usage are per disk below (`objectio_disk_*`), and
    // per OSD from the gateway's poll (`objectio_osd_capacity_bytes`,
    // `objectio_osd_used_bytes`). Exporting them here as well put two
    // series per OSD under one name once OSDs are scraped directly.

    // Shard count
    writeln!(
        output,
        "# HELP objectio_osd_shards_total Total shards stored"
    )
    .unwrap();
    writeln!(output, "# TYPE objectio_osd_shards_total gauge").unwrap();
    writeln!(
        output,
        "objectio_osd_shards_total{{osd_id=\"{}\"}} {}",
        state.osd_id, status.total_shards
    )
    .unwrap();

    // Per-disk metrics
    writeln!(output, "# HELP objectio_disk_capacity_bytes Disk capacity").unwrap();
    writeln!(output, "# TYPE objectio_disk_capacity_bytes gauge").unwrap();
    writeln!(output, "# HELP objectio_disk_used_bytes Disk used space").unwrap();
    writeln!(output, "# TYPE objectio_disk_used_bytes gauge").unwrap();
    writeln!(output, "# HELP objectio_disk_shards_total Shards on disk").unwrap();
    writeln!(output, "# TYPE objectio_disk_shards_total gauge").unwrap();
    writeln!(
        output,
        "# HELP objectio_disk_healthy Disk health status (1=healthy, 0=unhealthy)"
    )
    .unwrap();
    writeln!(output, "# TYPE objectio_disk_healthy gauge").unwrap();

    for disk in &status.disks {
        let healthy = if disk.status == "healthy" { 1 } else { 0 };
        writeln!(
            output,
            "objectio_disk_capacity_bytes{{osd_id=\"{}\",disk=\"{}\"}} {}",
            state.osd_id, disk.path, disk.capacity
        )
        .unwrap();
        writeln!(
            output,
            "objectio_disk_used_bytes{{osd_id=\"{}\",disk=\"{}\"}} {}",
            state.osd_id, disk.path, disk.used
        )
        .unwrap();
        writeln!(
            output,
            "objectio_disk_shards_total{{osd_id=\"{}\",disk=\"{}\"}} {}",
            state.osd_id, disk.path, disk.shard_count
        )
        .unwrap();
        writeln!(
            output,
            "objectio_disk_healthy{{osd_id=\"{}\",disk=\"{}\"}} {}",
            state.osd_id, disk.path, healthy
        )
        .unwrap();
    }

    // Disk IO since the OSD started, as counted by the storage engine.
    type DiskField = fn(&service::DiskStatusInfo) -> u64;
    let io_families: [(&str, &str, &str, DiskField); 5] = [
        (
            "objectio_disk_available_bytes",
            "gauge",
            "Free bytes on the disk",
            |d| d.capacity.saturating_sub(d.used),
        ),
        ("objectio_disk_reads_total", "counter", "Shard reads", |d| {
            d.reads
        }),
        (
            "objectio_disk_writes_total",
            "counter",
            "Shard writes",
            |d| d.writes,
        ),
        (
            "objectio_disk_read_bytes_total",
            "counter",
            "Bytes read",
            |d| d.bytes_read,
        ),
        (
            "objectio_disk_written_bytes_total",
            "counter",
            "Bytes written",
            |d| d.bytes_written,
        ),
    ];
    for (name, kind, help, f) in io_families {
        writeln!(output, "# HELP {name} {help}").unwrap();
        writeln!(output, "# TYPE {name} {kind}").unwrap();
        for disk in &status.disks {
            writeln!(
                output,
                "{name}{{osd_id=\"{}\",disk=\"{}\"}} {}",
                state.osd_id,
                disk.path,
                f(disk)
            )
            .unwrap();
        }
    }
    writeln!(
        output,
        "# HELP objectio_disk_errors_total IO errors and checksum mismatches"
    )
    .unwrap();
    writeln!(output, "# TYPE objectio_disk_errors_total counter").unwrap();
    for disk in &status.disks {
        for (kind, v) in [
            ("read", disk.read_errors),
            ("write", disk.write_errors),
            ("checksum", disk.checksum_errors),
        ] {
            writeln!(
                output,
                "objectio_disk_errors_total{{osd_id=\"{}\",disk=\"{}\",type=\"{kind}\"}} {v}",
                state.osd_id, disk.path
            )
            .unwrap();
        }
    }

    state
        .osd_service
        .render_wal_metrics(&mut output, &format!("osd_id=\"{}\"", state.osd_id));
    state
        .osd_service
        .render_scrub_metrics(&mut output, &format!("osd_id=\"{}\"", state.osd_id));
    shard_store::render_disk_metrics(&mut output, &format!("osd_id=\"{}\"", state.osd_id));

    // gRPC calls served, every method
    RPC_METRICS.render(
        &mut output,
        "objectio_osd_grpc",
        "this OSD",
        &format!("osd_id=\"{}\"", state.osd_id),
    );
    output.push_str(
        &state
            .osd_service
            .grpc_metrics()
            .export_prometheus(&state.osd_id),
    );

    // Check SMART metrics (will only poll if interval has elapsed)
    state.smart_monitor.check_if_needed(&state.disk_devices);
    output.push_str(&state.smart_monitor.export_prometheus());

    output.push_str(&objectio_common::process_metrics::render(&format!(
        "osd_id=\"{}\"",
        state.osd_id
    )));
    output
}

/// Health check handler
async fn health_handler(
    axum::extract::State(state): axum::extract::State<Arc<OsdMetricsState>>,
) -> impl IntoResponse {
    let status = state.osd_service.status();
    let healthy = status.disks.iter().all(|d| d.status == "healthy");

    if healthy {
        (StatusCode::OK, "OK")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "UNHEALTHY")
    }
}

/// Start the metrics HTTP server
async fn start_metrics_server(port: u16, state: Arc<OsdMetricsState>) -> Result<()> {
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

/// Send periodic heartbeats to the metadata service
async fn heartbeat_loop(meta_endpoint: &str, node_id: &[u8; 16], _disk_ids: &[Vec<u8>]) {
    let heartbeat_interval = Duration::from_secs(10);

    loop {
        tokio::time::sleep(heartbeat_interval).await;

        // In a full implementation, we would:
        // 1. Connect to metadata service
        // 2. Send HeartbeatRequest with node status and disk health
        // 3. Process HeartbeatResponse for cluster map updates
        //
        // For now, just log that we would send a heartbeat
        tracing::trace!(
            "Would send heartbeat for node {} to {}",
            hex::encode(&node_id[..4]),
            meta_endpoint
        );
    }
}

/// The host part of an `http://host:port` address.
#[cfg(feature = "rdma")]
fn host_of(addr: &str) -> &str {
    let rest = addr
        .strip_prefix("http://")
        .or_else(|| addr.strip_prefix("https://"))
        .unwrap_or(addr);
    rest.rsplit_once(':').map_or(rest, |(host, _)| host)
}
