#![allow(clippy::result_large_err)]
//! ObjectIO Block Gateway
//!
//! Accepts block I/O over gRPC (BlockService) and NBD, buffers writes in an
//! in-memory WriteCache, and flushes 4 MB chunks as EC objects to the OSDs.
//! A library so the all-in-one binary can run it in-process.

mod ec_io;
mod flush;
mod meta_blocks;
pub mod metrics;
mod nbd;
mod osd_pool;
mod resolve;
mod service;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use objectio_block::chunk::ChunkMapper;
use objectio_block::{CacheConfig, VolumeManager, WriteCache};
use objectio_proto::block::block_service_server::BlockServiceServer;
use tokio::sync::Mutex;
use tracing::info;

use crate::meta_blocks::MetaBlocks;
use crate::osd_pool::OsdPool;
use crate::service::BlockGatewayState;

/// Largest gRPC Read or Write the gateway takes: 16 chunks.
const MAX_MESSAGE: usize = 64 * 1024 * 1024;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(
    name = "objectio-block-gateway",
    about = "ObjectIO Block Storage Gateway"
)]
pub struct Args {
    /// gRPC listen address (BlockService)
    #[arg(long, default_value = "0.0.0.0:9300")]
    pub listen: String,

    /// NBD TCP listen address
    #[arg(long, default_value = "0.0.0.0:10809")]
    pub nbd_listen: String,

    /// Host advertised in NBD attachment URLs (defaults to listen host)
    #[arg(long, default_value = "")]
    pub advertise_host: String,

    /// Prometheus `/metrics` address; empty serves none. (aio leaves it
    /// empty and serves these on the gateway's `/metrics` instead.)
    #[arg(long, default_value = "0.0.0.0:9301")]
    pub metrics_listen: String,

    /// Meta service endpoint
    #[arg(long, default_value = "http://localhost:9100")]
    pub meta_endpoint: String,

    /// Data directory (the write journal). Volumes, snapshots and chunk
    /// maps are kept in meta.
    #[arg(long, default_value = "./block-gw-data")]
    pub data_dir: std::path::PathBuf,

    /// Write-cache size in bytes
    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    pub cache_bytes: usize,

    /// Background flush interval in seconds
    #[arg(long, default_value_t = 5)]
    pub flush_interval_s: u64,

    /// EC data shards (k)
    #[arg(long, default_value_t = 4)]
    pub ec_k: u32,

    /// EC parity shards (m)
    #[arg(long, default_value_t = 2)]
    pub ec_m: u32,

    /// Log level (trace / debug / info / warn / error)
    #[arg(long, default_value = "info")]
    pub log_level: String,
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run the block gateway until its gRPC server stops.
///
/// # Errors
/// If the data directory, store, meta connection or listeners cannot be
/// set up, or the gRPC server fails.
pub async fn run(args: Args) -> Result<()> {
    info!("Starting ObjectIO Block Gateway");

    // ── Data directory ────────────────────────────────────────────────────────
    std::fs::create_dir_all(&args.data_dir)
        .with_context(|| format!("create data_dir {:?}", args.data_dir))?;

    // ── Write cache ───────────────────────────────────────────────────────────
    let journal_path = args.data_dir.join("block.journal");
    let cache_config = CacheConfig {
        max_cache_bytes: args.cache_bytes as u64,
        journal_path: Some(journal_path.to_string_lossy().to_string()),
        ..CacheConfig::default()
    };
    let chunk_mapper = Arc::new(ChunkMapper::default());
    let cache = Arc::new(WriteCache::new(chunk_mapper, cache_config));
    metrics::register(Arc::clone(&cache));
    if !args.metrics_listen.is_empty() {
        let addr: SocketAddr = args
            .metrics_listen
            .parse()
            .context("parse metrics listen address")?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .with_context(|| format!("bind metrics on {addr}"))?;
        let app = axum::Router::new().route(
            "/metrics",
            axum::routing::get(|| async {
                // Erasure coding and process stats too: under aio the
                // gateway exports these for the whole process already.
                let mut out = objectio_common::metrics_registry::render_registered();
                objectio_erasure::metrics::render(&mut out);
                out.push_str(&objectio_common::process_metrics::render(""));
                out
            }),
        );
        info!("Block gateway metrics on {addr}/metrics");
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                tracing::error!("block gateway metrics server stopped: {e}");
            }
        });
    }

    // ── Meta gRPC client ──────────────────────────────────────────────────────
    let meta_channel = tonic::transport::Endpoint::new(args.meta_endpoint.clone())
        .context("parse meta endpoint")?
        .connect()
        .await
        .context("connect to meta service")?;

    let meta = Arc::new(MetaBlocks::new(Arc::new(Mutex::new(
        objectio_proto::metadata::metadata_service_client::MetadataServiceClient::new(meta_channel),
    ))));

    // ── Volumes, from meta ────────────────────────────────────────────────────
    let volume_manager = Arc::new(VolumeManager::new());
    let volumes = meta
        .client()
        .await
        .block_list_volumes(objectio_proto::metadata::BlockListVolumesRequest {})
        .await
        .context("list volumes from meta")?
        .into_inner()
        .volumes;
    for v in &volumes {
        volume_manager
            .restore_volume(service::from_proto(v))
            .with_context(|| format!("restore volume {}", v.volume_id))?;
        cache.init_volume_sized(&v.volume_id, service::chunk_size_of(v));
    }
    info!("{} volumes in meta", volumes.len());

    // ── OSD pool ──────────────────────────────────────────────────────────────
    let osd_pool = Arc::new(OsdPool::new());

    // ── NBD advertise host / port ─────────────────────────────────────────────
    let advertise_host = if args.advertise_host.is_empty() {
        args.listen
            .split(':')
            .next()
            .unwrap_or("localhost")
            .to_string()
    } else {
        args.advertise_host.clone()
    };
    let nbd_port: u16 = args
        .nbd_listen
        .split(':')
        .next_back()
        .unwrap_or("10809")
        .parse()
        .unwrap_or(10809);

    // ── NBD server ────────────────────────────────────────────────────────────
    let resolver = Arc::new(resolve::Resolver::new(
        Arc::clone(&cache),
        Arc::clone(&meta),
        Arc::clone(&osd_pool),
    ));
    let nbd_server = Arc::new(nbd::NbdServer::new(
        Arc::clone(&cache),
        Arc::clone(&resolver),
    ));

    // ── Gateway state ─────────────────────────────────────────────────────────
    let state = Arc::new(BlockGatewayState {
        meta,
        osd_pool,
        cache,
        volume_manager,
        nbd_server: Arc::clone(&nbd_server),
        resolver,
        advertise_host,
        nbd_port,
        ec_k: args.ec_k,
        ec_m: args.ec_m,
        flush_lock: tokio::sync::Mutex::new(()),
    });

    // ── Journal replay ────────────────────────────────────────────────────────
    // Writes acknowledged but not flushed before the last stop are in the
    // journal; put them back in the cache before serving anything. They
    // used to be discarded: a crash lost every write of the last ~30 s.
    replay_journal(&state).await?;

    // ── NBD exports ───────────────────────────────────────────────────────────
    // Every volume meta records as attached is exported again, the way it
    // was attached: the attachment outlives the gateway, so a client
    // reconnects to the same export name after a restart. They used to be
    // lost, and a volume left attached in meta could not be attached
    // again. Only now, after the journal replay, and before the NBD
    // listener starts: an export serves reads, which must see every write
    // acknowledged before the stop.
    let restored = restore_exports(&nbd_server, &volumes);
    if restored > 0 {
        info!("Restored {restored} NBD exports");
    }

    // ── Background flush loop ─────────────────────────────────────────────────
    {
        let flush_state = Arc::clone(&state);
        let interval = Duration::from_secs(args.flush_interval_s);
        tokio::spawn(flush::flush_loop(flush_state, interval));
    }

    // ── NBD TCP listener ──────────────────────────────────────────────────────
    let nbd_addr: SocketAddr = args
        .nbd_listen
        .parse()
        .context("parse NBD listen address")?;
    tokio::spawn(nbd::NbdServer::serve(Arc::clone(&nbd_server), nbd_addr));

    // ── gRPC server ───────────────────────────────────────────────────────────
    let grpc_addr: SocketAddr = args.listen.parse().context("parse gRPC listen address")?;
    info!("Block gateway gRPC on {grpc_addr}");
    info!("NBD server on {nbd_addr}");

    let svc = service::BlockGatewayService::new(Arc::clone(&state));
    objectio_proto::transport::server()
        // tonic's default 4 MiB limit refused any Write or Read of a
        // chunk or more.
        .add_service(
            BlockServiceServer::new(svc)
                .max_decoding_message_size(MAX_MESSAGE)
                .max_encoding_message_size(MAX_MESSAGE),
        )
        .serve(grpc_addr)
        .await
        .context("gRPC server error")?;

    Ok(())
}

/// Export every volume meta records as attached; the number exported.
fn restore_exports(
    nbd_server: &nbd::NbdServer,
    volumes: &[objectio_proto::block::Volume],
) -> usize {
    let mut restored = 0;
    for v in volumes {
        if v.state() == objectio_proto::block::VolumeState::Attached {
            nbd_server.register(&v.volume_id, v.size_bytes, v.attached_read_only);
            restored += 1;
        }
    }
    restored
}

/// Re-apply the journal's writes to the cache, each onto its chunk's
/// stored bytes, in the order they were acknowledged.
async fn replay_journal(state: &BlockGatewayState) -> Result<()> {
    let writes = state.cache.recover().context("read the block journal")?;
    let mut replayed = 0usize;
    for (volume_id, chunk_id, offset_in_chunk, data) in writes {
        if state.volume_manager.get_volume(&volume_id).is_err() {
            continue; // deleted since
        }
        // Entries are in the volume's own chunks; its size never changes.
        let Some(mapper) = state.cache.mapper_of(&volume_id) else {
            continue;
        };
        let offset = chunk_id * mapper.chunk_size() + offset_in_chunk;
        // A chunk not cached comes back pending; its stored bytes are
        // merged in before it is read whole or flushed.
        state
            .cache
            .replay(&volume_id, offset, &data)
            .with_context(|| format!("replay a write to {volume_id}"))?;
        replayed += 1;
    }
    if replayed > 0 {
        info!("Replayed {replayed} journaled writes");
    }
    Ok(())
}
