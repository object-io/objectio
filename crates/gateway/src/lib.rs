//! ObjectIO Gateway - S3 API Gateway
//!
//! This binary provides the S3-compatible HTTP API.
//! Credentials are managed by the metadata service for persistence.

pub mod admin;
pub mod audit;
pub mod audit_spool;
pub mod auth_middleware;
pub mod authz;
pub mod checksum;
pub mod chunked_decode;
pub mod clock_skew;
pub mod cluster_poll;
pub mod console_auth;
pub mod cors;
pub mod dedup;
pub mod digest;
pub mod gateway_metrics;
pub mod grep;
pub mod grep_engine;
pub mod heal;
pub mod host_provider;
pub mod iam_admin;
pub mod iam_api;
pub mod iceberg_auth;
pub mod kms;
pub mod lifecycle;
pub mod metrics_middleware;
pub mod origin;
pub mod osd_pool;
pub mod packer;
pub mod packs;
pub mod post_object;
pub mod prom;
pub mod public_access;
pub mod quota;
pub mod rdma;
pub mod replication;
pub mod s3;
pub mod s3_metrics;
pub mod scatter_gather;
pub mod sts_api;
pub mod test_hooks;
pub mod upgrade;

use crate::s3_metrics::{ProtectionConfig, s3_metrics};
use anyhow::Result;
use auth_middleware::{AuthState, auth_layer, optional_auth_layer};
use axum::serve::ListenerExt as _;
use axum::{
    Extension, Router,
    extract::DefaultBodyLimit,
    http::{StatusCode, header},
    middleware,
    response::{IntoResponse, Redirect},
    routing::{delete, get, head, post, put},
};
use clap::Parser;
use console_auth::ListenerKind;
use objectio_auth::policy::PolicyEvaluator;
use objectio_delta_sharing::{
    DeltaSharingConfig, admin_router as delta_admin_router, router as delta_router,
};
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use osd_pool::OsdPool;
use s3::AppState;
use scatter_gather::ScatterGatherEngine;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{debug, info, warn};

/// Prometheus metrics endpoint handler
/// Join the per-OSD usage with meta's buckets and tenants. `None` when meta
/// cannot be reached — the previous report is better than one in which
/// every bucket has vanished.
pub(crate) async fn build_usage_report(
    mut meta: objectio_proto::metadata::metadata_service_client::MetadataServiceClient<
        tonic::transport::Channel,
    >,
    nodes: &[crate::s3_metrics::metrics::NodeCapacity],
    usage: &HashMap<String, Vec<crate::s3_metrics::usage::OsdBucketUsage>>,
) -> Option<crate::s3_metrics::usage::UsageReport> {
    use crate::s3_metrics::usage::{BucketInfo, ClusterUsage, TenantInfo, build_report};
    use objectio_proto::metadata::{ListBucketsRequest, ListTenantsRequest};

    let buckets = meta
        .list_buckets(ListBucketsRequest::default())
        .await
        .ok()?
        .into_inner()
        .buckets
        .into_iter()
        .map(|b| BucketInfo {
            name: b.name,
            tenant: b.tenant,
            owner: b.owner,
            created_at: b.created_at,
            pool: b.pool,
            quota_bytes: b.quota_bytes,
            quota_objects: b.quota_objects,
        })
        .collect::<Vec<_>>();
    let tenants = meta
        .list_tenants(ListTenantsRequest {})
        .await
        .map(|r| r.into_inner().tenants)
        .unwrap_or_default()
        .into_iter()
        .map(|t| TenantInfo {
            name: t.name,
            quota_bytes: t.quota_bytes,
            quota_buckets: t.quota_buckets,
            quota_objects: t.quota_objects,
        })
        .collect::<Vec<_>>();

    let up: Vec<_> = nodes.iter().filter(|n| n.reachable).collect();
    let raw_capacity: u64 = up.iter().map(|n| n.total_bytes).sum();
    let raw_used: u64 = up.iter().map(|n| n.used_bytes).sum();
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let usable = s3_metrics()
        .protection_efficiency()
        .map_or(0, |e| (raw_capacity as f64 * e) as u64);
    let cluster = ClusterUsage {
        raw_capacity_bytes: raw_capacity,
        raw_used_bytes: raw_used,
        raw_available_bytes: raw_capacity.saturating_sub(raw_used),
        usable_capacity_bytes: usable,
        osds_total: nodes.len() as u64,
        osds_up: up.len() as u64,
        osds_stale: nodes
            .iter()
            .filter(|n| !n.reachable && usage.contains_key(&n.node_id))
            .count() as u64,
        ..Default::default()
    };
    let reports: Vec<_> = usage.values().cloned().collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    Some(build_report(&reports, &buckets, &tenants, cluster, now))
}

async fn metrics_handler() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        cluster_poll::render_metrics(),
    )
}

#[derive(Parser, Debug)]
#[command(name = "objectio-gateway")]
#[command(about = "ObjectIO S3 API Gateway")]
#[command(version)]
pub struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "/etc/objectio/gateway.toml")]
    pub config: String,

    /// Listen address for the data plane (S3 + Iceberg + Delta Sharing).
    /// In single-port mode (the default), also serves /_admin/* and /_console/*.
    #[arg(short, long, default_value = "0.0.0.0:9000")]
    pub listen: String,

    /// Optional dedicated listener for the admin API (`/_admin/*`) and
    /// `/metrics`. When set, the admin surface moves OFF `--listen`
    /// entirely and only this address serves it. Bind to a mgmt
    /// interface (e.g. `127.0.0.1:9001` or `10.0.5.10:9001`) so the
    /// public S3 endpoint stays the only Internet-facing port. Empty =
    /// single-port mode (admin stays on `--listen`).
    #[arg(long, default_value = "")]
    pub admin_listen: String,

    /// Optional dedicated listener for the **ops** console (full
    /// surface — pools, OSDs, balancer, tenants, billing). Mounts the
    /// SPA from `OBJECTIO_OPS_CONSOLE_DIR` plus the `/_admin/*` API
    /// (so the browser stays same-origin — no CORS). Bind to a mgmt
    /// interface in production. Empty = ops console is served on
    /// `--listen` (single-port) or omitted entirely if `--tenant-console-listen`
    /// is set without this one.
    #[arg(long, default_value = "")]
    pub ops_console_listen: String,

    /// Optional dedicated listener for the **tenant** console
    /// (self-service: my buckets, my keys, my catalogs). Mounts the
    /// SPA from `OBJECTIO_TENANT_CONSOLE_DIR` plus the same `/_admin/*`
    /// surface (server-side tenant-scoped). Safe to expose publicly so
    /// end users can self-serve. Empty = tenant console is not served
    /// separately (ops console covers both surfaces in single-port mode).
    #[arg(long, default_value = "")]
    pub tenant_console_listen: String,

    /// Metadata service endpoint: one address, or every meta node's,
    /// comma-separated (any of them serves; one that's down is skipped)
    #[arg(long, default_value = "http://localhost:9001")]
    pub meta_endpoint: String,

    /// OSD endpoint (initial OSD, more discovered via metadata service)
    #[arg(long, default_value = "http://localhost:9002")]
    pub osd_endpoint: String,

    /// Erasure coding data shards (k)
    #[arg(long, default_value = "4")]
    pub ec_k: u32,

    /// Erasure coding parity shards (m)
    #[arg(long, default_value = "2")]
    pub ec_m: u32,

    /// Protection scheme: ec (MDS erasure coding), lrc (locally repairable codes), replication
    #[arg(long, default_value = "ec")]
    pub protection: String,

    /// LRC local parity shards (only used when --protection=lrc)
    #[arg(long, default_value = "0")]
    pub lrc_local_parity: u32,

    /// LRC global parity shards (only used when --protection=lrc)
    #[arg(long, default_value = "0")]
    pub lrc_global_parity: u32,

    /// Number of replicas (only used when --protection=replication)
    #[arg(long, default_value = "3")]
    pub replicas: u32,

    /// Disable authentication (for development)
    #[arg(long, default_value_t = false)]
    pub no_auth: bool,

    /// Base URL of a Prometheus that scrapes this cluster, e.g.
    /// `http://prometheus:9090`. The console proxies range queries through the
    /// gateway to it.
    ///
    /// `/metrics` is a point-in-time scrape, so a browser polling it only knows
    /// what happened since the page opened — about five minutes. Ranges beyond
    /// that, and any series labelled per node or per gateway, come from
    /// Prometheus, which already scrapes the gateway, the meta nodes and the
    /// OSDs. Leave empty to run without it: the console falls back to the live
    /// scrape and says so.
    #[arg(long, env = "OBJECTIO_PROMETHEUS_URL", default_value = "")]
    pub prometheus_url: String,

    /// Objects of at most this many bytes are stored inside their metadata
    /// record, on every OSD in their placement, instead of erasure-coded
    /// into shards: a PUT makes one round to the OSDs instead of two, and a
    /// GET one instead of two. The record lives in each OSD's memory, so
    /// keep it small. 0 turns it off.
    #[arg(long, default_value_t = 4096)]
    pub inline_max_size: usize,

    /// Move shards over Mooncake Transfer Engine to OSDs that offer it:
    /// `rdma`, or `tcp` to develop without RDMA hardware. Unset: gRPC bytes
    /// only.
    #[cfg(feature = "rdma")]
    #[arg(long)]
    pub rdma: Option<String>,

    /// Address Transfer Engine binds and advertises — one on the storage
    /// network, never a public one. Defaults to the host of --listen, which
    /// must then not be a wildcard.
    #[cfg(feature = "rdma")]
    #[arg(long)]
    pub rdma_host: Option<String>,

    /// Registered slots of one encoded stripe each: bounds PUT stripes in
    /// flight over Transfer Engine. Beyond that a stripe goes over gRPC.
    #[cfg(feature = "rdma")]
    #[arg(long, default_value_t = 16)]
    pub rdma_stripe_slots: usize,

    /// Registered slots of one shard each: bounds GET shard reads in flight
    /// over Transfer Engine. Beyond that a shard is read over gRPC.
    #[cfg(feature = "rdma")]
    #[arg(long, default_value_t = 64)]
    pub rdma_read_slots: usize,

    /// Leave the per-bucket usage series (`objectio_bucket_*`) out of
    /// `/metrics`. They carry one series per bucket, which is fine into the
    /// tens of thousands; beyond that, tenant and cluster totals are still
    /// exported and `/_admin/usage` still has every bucket.
    #[arg(long, env = "OBJECTIO_NO_BUCKET_METRICS", default_value_t = false)]
    pub no_bucket_metrics: bool,

    /// Leave the OSDs' and meta's metrics out of `/metrics`. By default the
    /// gateway polls them every 30 s and re-exports them, so one scrape
    /// target covers the cluster (aio, one gateway). With several gateways,
    /// or Prometheus scraping each OSD (:9201) and meta node (:9101), set
    /// this: otherwise every gateway exports a copy and sums multiply.
    #[arg(long, env = "OBJECTIO_NO_REEXPORT_METRICS", default_value_t = false)]
    pub no_reexport_metrics: bool,

    /// Name of the `--listen` endpoint, for policies (`aws:SourceVpce`).
    /// Empty: unnamed, as a request over the internet is in AWS.
    #[arg(long, env = "OBJECTIO_ENDPOINT_NAME", default_value = "")]
    pub endpoint_name: String,

    /// A further data-plane listener (S3, Iceberg, Delta Sharing; no admin
    /// API or console), as `ADDR=NAME`: e.g. `0.0.0.0:9010=external` for the
    /// port the ingress reaches while `--listen` serves pods in the cluster.
    /// Repeatable.
    #[arg(long = "data-listen")]
    pub data_listen: Vec<String>,

    /// Proxies (CIDRs or addresses, comma-separated) whose
    /// `X-Forwarded-For` is believed for the client's address
    /// (`aws:SourceIp`). Empty: the connection's peer is the client.
    #[arg(long, env = "OBJECTIO_TRUSTED_PROXIES", default_value = "")]
    pub trusted_proxies: String,

    /// Append every request's audit event, as JSON lines, to this file
    /// (`-` for stdout). Further targets are configured at
    /// `/_admin/audit`.
    #[arg(long, env = "OBJECTIO_AUDIT_LOG")]
    pub audit_log: Option<String>,

    /// Keep audit events in this directory before they are delivered
    /// (A8c): a gateway killed or a receiver down loses none. A local
    /// directory that survives restarts.
    #[arg(long, env = "OBJECTIO_AUDIT_SPOOL")]
    pub audit_spool: Option<std::path::PathBuf>,

    /// The most the spool holds; past it, new events are dropped and
    /// counted (`objectio_audit_dropped_total{target="spool"}`).
    #[arg(long, env = "OBJECTIO_AUDIT_SPOOL_MAX_BYTES", default_value_t = 10 << 30)]
    pub audit_spool_max_bytes: u64,

    /// The system always audits: every event also goes to this bucket in
    /// the cluster (created if missing), as JSON-lines objects by hour.
    /// Needs `--audit-spool`.
    #[arg(long, env = "OBJECTIO_AUDIT_SYSTEM_BUCKET")]
    pub audit_system_bucket: Option<String>,

    /// On shutdown, how long to wait for the audit spool to be delivered.
    #[arg(long, env = "OBJECTIO_AUDIT_DRAIN_SECS", default_value_t = 20)]
    pub audit_drain_secs: u64,

    /// Days the system bucket keeps events (0: kept).
    #[arg(long, env = "OBJECTIO_AUDIT_RETENTION_DAYS", default_value_t = 365)]
    pub audit_retention_days: u32,

    /// How often the lifecycle worker scans buckets with lifecycle rules.
    #[arg(long, default_value_t = 3600)]
    pub lifecycle_interval_secs: u64,

    /// The length of a lifecycle "day" in seconds. For testing only: a
    /// rule's Days count in units of this.
    #[arg(long, default_value_t = 86_400, hide = true)]
    pub lifecycle_day_secs: u64,

    /// Mount `/_admin/test/*`, endpoints tests drive directly (packing
    /// named objects now). For testing only.
    #[arg(long, hide = true)]
    pub test_hooks: bool,

    /// Run this gateway's stamp clock this many milliseconds off the
    /// system's: a gateway whose clock is wrong. For testing only.
    #[arg(long, default_value_t = 0, hide = true, allow_negative_numbers = true)]
    pub test_clock_offset_ms: i64,

    /// How often the packer moves small objects into packs (seconds). 0,
    /// the default, leaves packing off.
    #[arg(long, default_value_t = 0)]
    pub pack_interval_secs: u64,

    /// Objects written more recently than this many seconds aren't packed.
    #[arg(long, default_value_t = 3600)]
    pub pack_min_age_secs: u64,

    /// How often this gateway works the heal queue: keys a write or delete
    /// left behind on some metadata copies (seconds; 0 turns it off).
    #[arg(long, default_value_t = 10)]
    pub heal_interval_secs: u64,

    /// How often the replication scanner looks for versions not yet sent
    /// to their targets (seconds).
    #[arg(long, default_value_t = 30)]
    pub replication_scan_secs: u64,

    /// Send replicated versions as soon as they're written (off only in
    /// tests, standing for a gateway that died before it could).
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set, hide = true)]
    pub replication_fast_path: bool,

    /// Seconds the packer waits between switching objects into a pack and
    /// releasing their old stripes, for reads already under way.
    #[arg(long, default_value_t = 30, hide = true)]
    pub pack_grace_secs: u64,

    /// Name of the env var holding the base64-encoded 32-byte SSE master key.
    /// If the env var is set, SSE-S3 is enabled — PUT to buckets with
    /// ServerSideEncryptionConfiguration will encrypt at rest. If missing,
    /// SSE-S3 requests on PUT will be rejected; plaintext writes/reads are
    /// unaffected. In `--no-auth` mode only, a random key is generated
    /// when the env var is missing (dev convenience, objects are lost on restart).
    #[arg(long, default_value = "OBJECTIO_MASTER_KEY")]
    pub master_key_env: String,

    /// KMS backend used for SSE-KMS operations: `local` (keys stored in meta,
    /// wrapped by the service master key) or `vault` (HashiCorp Vault Transit
    /// engine). Vault reads config from `VAULT_ADDR` / `VAULT_TOKEN` /
    /// `VAULT_TRANSIT_PATH` env vars. SSE-S3 works regardless of this flag
    /// and always uses the service master key.
    #[arg(long, default_value = "local")]
    pub kms_backend: String,

    /// AWS region for SigV4 verification
    #[arg(long, default_value = "us-east-1")]
    pub region: String,

    /// Public URL the gateway is reachable at (e.g. https://s3.example.com).
    /// Consumed by three features:
    ///   • Iceberg vended credentials — included as the `s3.endpoint` in
    ///     LoadTableResponse.credentials so Spark/Trino clients know where
    ///     to send subsequent S3 reads/writes.
    ///   • Delta Sharing — base URL used when generating presigned S3 URLs
    ///     for Parquet file downloads.
    ///   • Console OIDC callback — the authorize flow needs an absolute
    ///     redirect_uri; Entra/Okta reject bare paths.
    /// Defaults to http://<listen> if unset.
    #[arg(long, default_value = "")]
    pub external_endpoint: String,

    /// Admin access key ID for Delta Sharing presigned URL generation.
    /// Leave empty to disable Delta Sharing presigned URL support.
    #[arg(long, default_value = "")]
    pub delta_access_key_id: String,

    /// Admin secret access key for Delta Sharing presigned URL generation.
    #[arg(long, default_value = "")]
    pub delta_secret_key: String,

    /// Lifetime in seconds of presigned data-file URLs returned by the Delta
    /// Sharing /query endpoint. 0 falls back to the crate default (3600s).
    /// Tune higher when recipients run long Spark/Databricks jobs against
    /// large native Delta tables — past this window data-file URLs return 403.
    #[arg(long, default_value = "0")]
    pub delta_url_ttl_seconds: u64,

    /// OIDC issuer URL for Iceberg JWT authentication (e.g., https://keycloak.example.com/realms/myrealm)
    #[arg(long)]
    pub oidc_issuer_url: Option<String>,

    /// OIDC client ID (registered in the OIDC provider)
    #[arg(long)]
    pub oidc_client_id: Option<String>,

    /// OIDC client secret (for client_credentials grant at /iceberg/v1/oauth/tokens)
    #[arg(long)]
    pub oidc_client_secret: Option<String>,

    /// OIDC audience for JWT validation (defaults to client_id if not set)
    #[arg(long)]
    pub oidc_audience: Option<String>,

    /// OIDC claim name for user groups/roles (default: "groups";
    /// Keycloak uses "roles", Azure AD uses "roles", Okta uses "groups")
    #[arg(long, default_value = "groups")]
    pub oidc_groups_claim: String,

    /// OIDC claim name for user role (default: "role")
    #[arg(long, default_value = "role")]
    pub oidc_role_claim: String,

    /// OIDC scopes to request (default: "openid profile email")
    #[arg(long, default_value = "openid profile email")]
    pub oidc_scopes: String,

    /// OIDC groups/roles that grant Iceberg catalog admin access.
    /// Comma-separated. These are matched as ARNs: arn:obio:iam::oidc:group/<value>
    #[arg(long, value_delimiter = ',')]
    pub oidc_admin_roles: Vec<String>,

    /// Gateway's own topology position — used by locality-aware read routing
    /// to prefer shards on nearby OSDs (Phase 2). Empty string at any level
    /// means "inherit / unknown". Also configurable via
    /// OBJECTIO_TOPOLOGY_{REGION,ZONE,DATACENTER,RACK,HOST} env vars.
    #[arg(long, env = "OBJECTIO_TOPOLOGY_REGION", default_value = "")]
    pub topology_region: String,
    #[arg(long, env = "OBJECTIO_TOPOLOGY_ZONE", default_value = "")]
    pub topology_zone: String,
    #[arg(long, env = "OBJECTIO_TOPOLOGY_DATACENTER", default_value = "")]
    pub topology_datacenter: String,
    #[arg(long, env = "OBJECTIO_TOPOLOGY_RACK", default_value = "")]
    pub topology_rack: String,
    #[arg(long, env = "OBJECTIO_TOPOLOGY_HOST", default_value = "")]
    pub topology_host: String,

    /// Host lifecycle backend for /_admin/hosts and /_admin/osds/*/reboot.
    /// `noop` (default) refuses those actions; `k8s` talks to the
    /// in-cluster Kubernetes API (requires a ServiceAccount with
    /// patch-scale on the OSD StatefulSet + delete-pod). Future values:
    /// `linux-ssh`, `appliance`.
    #[arg(long, env = "OBJECTIO_HOST_PROVIDER", default_value = "noop")]
    pub host_provider: String,

    /// Namespace the OSD StatefulSet lives in. Only read when
    /// `--host-provider=k8s`. Defaults to POD_NAMESPACE (downward API
    /// set by the helm chart) or "default" if unset.
    #[arg(long, env = "POD_NAMESPACE", default_value = "default")]
    pub host_provider_namespace: String,

    /// Name of the OSD StatefulSet — the chart's `objectio.osd.fullname`
    /// helper renders this as `{release}-osd` (e.g. `objectio-osd`).
    /// Override if you've customised the release name.
    #[arg(
        long,
        env = "OBJECTIO_HOST_PROVIDER_OSD_STS",
        default_value = "objectio-osd"
    )]
    pub host_provider_osd_sts: String,

    /// Log level
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// mTLS between services (A8a).
    #[command(flatten)]
    pub tls: objectio_proto::transport::TlsArgs,
}

/// Run the gateway until `shutdown` resolves. Caller owns the tracing
/// subscriber and the Ctrl-C wiring; we trust args already parsed.
pub async fn run(
    args: Args,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    objectio_proto::transport::configure_tls(&args.tls).map_err(anyhow::Error::msg)?;
    if args.test_clock_offset_ms != 0 {
        objectio_common::stamp::set_test_offset_ms(args.test_clock_offset_ms);
    }
    info!("Starting ObjectIO Gateway");
    info!("Metadata endpoint: {}", args.meta_endpoint);
    info!("OSD endpoint: {}", args.osd_endpoint);

    // Register protection config for Prometheus metrics
    let protection_config = match args.protection.as_str() {
        "lrc" => {
            let total = args.ec_k + args.lrc_local_parity + args.lrc_global_parity;
            info!(
                "Protection: LRC k={} l={} g={} (total={}, efficiency={:.1}%)",
                args.ec_k,
                args.lrc_local_parity,
                args.lrc_global_parity,
                total,
                (f64::from(args.ec_k) / f64::from(total)) * 100.0
            );
            ProtectionConfig {
                scheme: "lrc".to_string(),
                data_shards: args.ec_k,
                parity_shards: args.lrc_local_parity + args.lrc_global_parity,
                total_shards: total,
                efficiency: f64::from(args.ec_k) / f64::from(total),
                lrc_local_parity: args.lrc_local_parity,
                lrc_global_parity: args.lrc_global_parity,
            }
        }
        "replication" => {
            info!(
                "Protection: Replication replicas={} (efficiency={:.1}%)",
                args.replicas,
                (1.0 / f64::from(args.replicas)) * 100.0
            );
            ProtectionConfig {
                scheme: "replication".to_string(),
                data_shards: 1,
                parity_shards: args.replicas - 1,
                total_shards: args.replicas,
                efficiency: 1.0 / f64::from(args.replicas),
                lrc_local_parity: 0,
                lrc_global_parity: 0,
            }
        }
        _ => {
            // Default: MDS erasure coding
            let total = args.ec_k + args.ec_m;
            info!(
                "Protection: EC (MDS) k={} m={} (total={}, efficiency={:.1}%)",
                args.ec_k,
                args.ec_m,
                total,
                (f64::from(args.ec_k) / f64::from(total)) * 100.0
            );
            ProtectionConfig {
                scheme: "ec".to_string(),
                data_shards: args.ec_k,
                parity_shards: args.ec_m,
                total_shards: total,
                efficiency: f64::from(args.ec_k) / f64::from(total),
                lrc_local_parity: 0,
                lrc_global_parity: 0,
            }
        }
    };
    s3_metrics().set_protection_config(protection_config);
    s3_metrics().set_per_bucket_usage(!args.no_bucket_metrics);
    cluster_poll::set_reexport(!args.no_reexport_metrics);

    // Connect to metadata service
    let meta_client = MetadataServiceClient::new(
        objectio_proto::transport::meta_channel(&args.meta_endpoint)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to metadata service: {e}"))?,
    );

    info!("Connected to metadata service");
    info!("Credentials are managed by the metadata service");

    // Report this binary's release and format level (rolling upgrades).
    // A gateway has no stable id; its host and listen address name it.
    objectio_proto::transport::spawn_version_reporter(
        args.meta_endpoint.clone(),
        "gateway",
        format!(
            "{}/{}",
            std::env::var("HOSTNAME").unwrap_or_else(|_| "gateway".into()),
            args.listen
        ),
        args.listen.clone(),
    );

    // Create OSD connection pool
    let osd_pool = Arc::new(OsdPool::new());
    osd_pool.set_heal_queue(meta_client.clone());

    // Connect to initial OSD (more will be discovered via placement)
    // Generate a temporary node ID for the initial OSD
    let initial_node_id = uuid::Uuid::new_v4();
    if let Err(e) = osd_pool
        .connect(
            osd_pool::NodeId::from(*initial_node_id.as_bytes()),
            &args.osd_endpoint,
        )
        .await
    {
        tracing::warn!(
            "Failed to connect to initial OSD: {}. Will connect on demand.",
            e
        );
    } else {
        info!("Connected to initial OSD at {}", args.osd_endpoint);
    }

    // STS provider for vended Iceberg credentials + S3 temporary auth.
    // Keyed by the cluster's secret from meta, shared by every gateway.
    let cluster_secret = load_cluster_secret(meta_client.clone()).await;
    console_auth::set_session_key(derive_key(&cluster_secret, "console-session"));
    let sts_provider =
        objectio_auth::sts::StsProvider::new(&derive_key(&cluster_secret, "sts-session"));

    // Create auth state using metadata service for credential lookup
    let auth_state =
        Arc::new(AuthState::new(meta_client.clone(), &args.region).with_sts(sts_provider.clone()));

    // Listing continuation tokens, signed under the cluster's secret too.
    let scatter_gather = ScatterGatherEngine::new(
        osd_pool.clone(),
        &derive_key(&cluster_secret, "scatter-gather"),
    );

    // Build admin principals list from OIDC admin roles config. Used by
    // the Iceberg catalog router.
    let admin_principals: Vec<String> = args
        .oidc_admin_roles
        .iter()
        .map(|role| format!("arn:obio:iam::oidc:group/{role}"))
        .collect();

    // S3 endpoint for vended Iceberg credentials.
    let s3_endpoint = if args.external_endpoint.is_empty() {
        format!(
            "http://{}:{}",
            args.listen.split(':').next().unwrap_or("localhost"),
            args.listen.split(':').nth(1).unwrap_or("9000")
        )
    } else {
        args.external_endpoint.clone()
    };

    // OIDC provider — used by both the Iceberg auth layer and the console
    // OIDC login flow.
    let oidc_provider = if let (Some(issuer_url), Some(client_id)) =
        (&args.oidc_issuer_url, &args.oidc_client_id)
    {
        let audience = args
            .oidc_audience
            .as_deref()
            .unwrap_or(client_id)
            .to_string();
        let oidc_config = objectio_auth::OidcConfig {
            issuer_url: issuer_url.clone(),
            client_id: client_id.clone(),
            client_secret: args.oidc_client_secret.clone().unwrap_or_default(),
            audience,
            jwks_uri: None,
            token_endpoint: None,
            groups_claim: args.oidc_groups_claim.clone(),
            role_claim: args.oidc_role_claim.clone(),
            scopes: args.oidc_scopes.clone(),
        };
        info!(
            "OIDC configured: issuer={} client={}",
            issuer_url, client_id
        );
        Some(std::sync::Arc::new(objectio_auth::OidcProvider::new(
            oidc_config,
        )))
    } else {
        None
    };

    // STS (AssumeRoleWithWebIdentity, unsigned) on the S3 endpoint.
    let sts_state = Arc::new(sts_api::StsState {
        meta_client: meta_client.clone(),
        system_oidc: oidc_provider.clone(),
        sts: sts_provider.clone(),
    });

    // Build Iceberg REST Catalog router and Delta Sharing router.
    //
    // The Unity Catalog router (mounted at /api/2.1/unity-catalog/*) shares
    // the same iceberg auth layer — Unity is just an alternate REST surface
    // over the same catalog metadata.
    let iceberg_router = {
        let router = objectio_iceberg::router(
            meta_client.clone(),
            PolicyEvaluator::new(),
            admin_principals.clone(),
            Some(sts_provider.clone()),
            s3_endpoint.clone(),
        );
        info!(
            "Iceberg REST Catalog at /iceberg/v1/* ({})",
            if oidc_provider.is_some() {
                "SigV4 + OIDC + session cookie"
            } else {
                "SigV4 + session cookie"
            }
        );
        let iceberg_auth_state = Arc::new(iceberg_auth::IcebergAuthState {
            sigv4_state: Arc::clone(&auth_state),
            oidc_provider: oidc_provider.clone(),
        });
        if let Some(ref oidc) = oidc_provider {
            let oauth_router = Router::new()
                .route(
                    "/v1/oauth/tokens",
                    axum::routing::post(iceberg_auth::oauth_tokens),
                )
                .with_state(Arc::clone(oidc));
            router
                .layer(middleware::from_fn_with_state(
                    iceberg_auth_state,
                    iceberg_auth::iceberg_unified_auth_layer,
                ))
                .merge(oauth_router)
        } else {
            router.layer(middleware::from_fn_with_state(
                iceberg_auth_state,
                iceberg_auth::iceberg_unified_auth_layer,
            ))
        }
    };

    // Unity Catalog REST router — same auth layer as Iceberg (SigV4 + OIDC
    // bearer + session cookie). Mounted
    // at the gateway root so its `/api/2.1/unity-catalog/*` paths land where
    // Databricks-style clients expect them.
    let unity_router = {
        let router = objectio_unity_catalog::router(
            meta_client.clone(),
            PolicyEvaluator::new(),
            admin_principals,
            Some(sts_provider),
            s3_endpoint,
        );
        info!(
            "Unity Catalog REST API at /api/2.1/unity-catalog/* ({})",
            if oidc_provider.is_some() {
                "SigV4 + OIDC + session cookie"
            } else {
                "SigV4 + session cookie"
            }
        );
        let unity_auth_state = Arc::new(iceberg_auth::IcebergAuthState {
            sigv4_state: Arc::clone(&auth_state),
            oidc_provider: oidc_provider.clone(),
        });
        router.layer(middleware::from_fn_with_state(
            unity_auth_state,
            iceberg_auth::iceberg_unified_auth_layer,
        ))
    };

    // Warehouse prefix rewrite layer.
    let warehouse_rewrite =
        tower::util::MapRequestLayer::new(|mut req: axum::http::Request<axum::body::Body>| {
            let path = req.uri().path().to_string();
            if let Some(rest) = path.strip_prefix("/iceberg/v1/ws/")
                && let Some(slash_pos) = rest.find('/')
            {
                let warehouse = &rest[..slash_pos];
                let remaining = &rest[slash_pos..];
                let new_path = format!("/iceberg/v1{remaining}");
                let existing_query = req.uri().query().unwrap_or("");
                let new_query = if existing_query.is_empty() {
                    format!("warehouse={warehouse}")
                } else {
                    format!("{existing_query}&warehouse={warehouse}")
                };
                if let Ok(uri) = format!("{new_path}?{new_query}").parse() {
                    *req.uri_mut() = uri;
                }
            }
            req
        });

    let (delta_sharing_router, delta_sharing_admin_router) = {
        let external_endpoint = if args.external_endpoint.is_empty() {
            format!("http://{}", args.listen)
        } else {
            args.external_endpoint.clone()
        };
        let url_ttl = if args.delta_url_ttl_seconds > 0 {
            Some(args.delta_url_ttl_seconds)
        } else {
            None
        };
        let delta_config = DeltaSharingConfig {
            endpoint: external_endpoint.clone(),
            region: args.region.clone(),
            access_key_id: args.delta_access_key_id.clone(),
            secret_access_key: args.delta_secret_key.clone(),
            default_url_ttl_seconds: url_ttl,
        };
        let delta_admin_config = DeltaSharingConfig {
            endpoint: external_endpoint,
            region: args.region.clone(),
            access_key_id: args.delta_access_key_id.clone(),
            secret_access_key: args.delta_secret_key.clone(),
            default_url_ttl_seconds: url_ttl,
        };
        info!("Delta Sharing protocol enabled at /delta-sharing/v1/*");
        info!("Delta Sharing admin API enabled at /_admin/delta-sharing/*");
        (
            delta_router(meta_client.clone(), delta_config),
            delta_admin_router(meta_client.clone(), delta_admin_config),
        )
    };

    // Clone meta_client for OIDC auto-provisioning before it's moved into AppState
    let meta_client_for_oidc = meta_client.clone();

    // Load the SSE master key. Order of preference: env var, dev fallback,
    // otherwise leave disabled. When a bucket has default encryption set
    // but `master_key` is None, PUT will fail — that's the intended gate.
    let master_key = match objectio_kms::MasterKey::from_env(&args.master_key_env) {
        Ok(k) => {
            info!(
                "SSE master key loaded from env var {} — SSE-S3 enabled",
                args.master_key_env
            );
            Some(k)
        }
        Err(e) if args.no_auth => {
            let k = objectio_kms::MasterKey::generate_random();
            warn!(
                "SSE master key env var not usable ({}); generated a random key for dev mode. \
                 Objects encrypted with this key will be UNREADABLE after gateway restart. \
                 Set {}=<base64 32 bytes> to persist across restarts.",
                e, args.master_key_env,
            );
            Some(k)
        }
        Err(e) => {
            warn!(
                "SSE master key not available ({}); SSE-S3 is disabled. Plaintext writes/reads \
                 are unaffected. To enable SSE, set {}=<base64 32 bytes>.",
                e, args.master_key_env,
            );
            None
        }
    };

    // Resolve the initial KMS backend. Meta's `kms/config` entry wins if
    // present (so the console can reconfigure without a gateway restart);
    // otherwise fall back to `--kms-backend` + env. Admin PUTs at runtime
    // replace the providers in-place via `AppState::set_kms`.
    let kms_config = match kms::load_backend_config_from_meta(meta_client.clone()).await {
        Some(cfg) => {
            info!("SSE-KMS backend from meta: {}", cfg.label());
            cfg
        }
        None => {
            let cfg = kms::KmsBackendConfig::from_cli(&args.kms_backend);
            info!("SSE-KMS backend from CLI/env: {}", cfg.label());
            cfg
        }
    };
    let (kms_local, kms) =
        kms::build_kms_provider(meta_client.clone(), master_key.as_ref(), &kms_config);

    // Build this gateway's self-topology from CLI flags / env so read
    // routing can prefer locally-adjacent OSDs.
    let self_topology = objectio_placement::FailureDomainInfo::new_full(
        &args.topology_region,
        &args.topology_zone,
        &args.topology_datacenter,
        &args.topology_rack,
        &args.topology_host,
    );
    if !self_topology.region.is_empty() {
        info!(
            "Gateway topology: region={} zone={} datacenter={} rack={} host={}",
            self_topology.region,
            self_topology.zone,
            self_topology.datacenter,
            self_topology.rack,
            self_topology.host
        );
    } else {
        info!("Gateway topology: unconfigured — locality-aware read routing disabled");
    }

    // Host provider selection. `noop` means /_admin/hosts and Reboot
    // return 501 — safe default for dev clusters with no platform to
    // talk to. `k8s` connects to the in-cluster API; startup fails
    // fast if the ServiceAccount isn't wired.
    let host_provider: Arc<dyn host_provider::HostProvider> = match args.host_provider.as_str() {
        "noop" => Arc::new(host_provider::NoopHostProvider),
        "k8s" => {
            info!(
                "Host provider: k8s (namespace={}, osd_sts={})",
                args.host_provider_namespace, args.host_provider_osd_sts
            );
            match host_provider::K8sHostProvider::try_new(
                args.host_provider_namespace.clone(),
                args.host_provider_osd_sts.clone(),
            )
            .await
            {
                Ok(p) => Arc::new(p),
                Err(e) => {
                    // Don't hard-fail boot — if the k8s API is
                    // briefly unreachable (CNI still starting, RBAC
                    // propagation) we'd rather serve S3 + return 503
                    // on host-action endpoints than refuse traffic
                    // entirely. Startup logs will flag the config
                    // for ops to check.
                    warn!("k8s host provider init failed, falling back to noop: {e}");
                    Arc::new(host_provider::NoopHostProvider)
                }
            }
        }
        other => {
            warn!(
                "unknown --host-provider={:?}; falling back to noop. Accepted: noop, k8s",
                other
            );
            Arc::new(host_provider::NoopHostProvider)
        }
    };

    #[cfg(feature = "rdma")]
    let rdma = match args.rdma.as_deref() {
        None => None,
        Some(protocol) => Some(Arc::new(start_rdma(&args, protocol)?)),
    };
    #[cfg(not(feature = "rdma"))]
    let rdma = None;

    let dedup_meta = meta_client.clone();
    let dedup_pool = Arc::clone(&osd_pool);
    // Create application state. KMS fields are held behind RwLocks so
    // `PUT /_admin/kms/config` can hot-swap the backend at runtime; we seed
    // them here with whatever the CLI flag + env / meta config resolved to.
    let trusted_proxies = origin::TrustedProxies::parse(&args.trusted_proxies)
        .map_err(|e| anyhow::anyhow!("--trusted-proxies: {e}"))?;
    let spool = match &args.audit_spool {
        Some(dir) => Some(
            audit_spool::Spool::open(dir, args.audit_spool_max_bytes)
                .map_err(|e| anyhow::anyhow!("--audit-spool {}: {e}", dir.display()))?,
        ),
        None => None,
    };
    let auditor = audit::Auditor::start(
        meta_client.clone(),
        args.audit_log.clone(),
        trusted_proxies.clone(),
        spool,
    );
    let state = Arc::new(AppState {
        meta_client,
        osd_pool,
        ec_k: args.ec_k,
        ec_m: args.ec_m,
        policy_evaluator: PolicyEvaluator::new(),
        policy_cache: authz::AuthzCache::default(),
        scatter_gather,
        master_key,
        kms: parking_lot::RwLock::new(kms),
        kms_local: parking_lot::RwLock::new(kms_local),
        self_topology,
        host_provider,
        prometheus_url: args.prometheus_url.clone(),
        rdma,
        inline_max_size: args.inline_max_size,
        dedup: dedup::DryRun::start(dedup_meta, Arc::clone(&dedup_pool)),
        trusted_proxies,
        auth_state: Arc::clone(&auth_state),
        auditor: Arc::clone(&auditor),
        pack_cache: crate::packs::PackCache::default(),
        replication: crate::replication::Replication::default(),
    });

    if let Some(bucket) = &args.audit_system_bucket {
        auditor.start_system_bucket(
            Arc::clone(&state),
            bucket.clone(),
            args.audit_retention_days,
        );
    }

    // Lifecycle: every gateway runs a worker; a lease in meta lets one scan
    // at a time.
    lifecycle::spawn_worker(
        Arc::clone(&state),
        lifecycle::Timing {
            interval: std::time::Duration::from_secs(args.lifecycle_interval_secs.max(1)),
            day: std::time::Duration::from_secs(args.lifecycle_day_secs.max(1)),
        },
    );

    // Bucket replication: the fast path and the scanner (a lease in meta
    // lets one gateway scan). Idle while no bucket has rules.
    replication::spawn(
        Arc::clone(&state),
        replication::Timing {
            scan_every: std::time::Duration::from_secs(args.replication_scan_secs.max(1)),
            fast_path: args.replication_fast_path,
        },
    );

    // Healing: every gateway works the heal queue; a claim in meta keeps two
    // off one key.
    heal::spawn(
        Arc::clone(&state),
        std::time::Duration::from_secs(args.heal_interval_secs),
    );

    // Packing: off unless asked for; a lease in meta lets one gateway pack.
    if args.pack_interval_secs > 0 {
        packer::spawn_worker(
            Arc::clone(&state),
            packer::Timing {
                interval: std::time::Duration::from_secs(args.pack_interval_secs),
                min_age: std::time::Duration::from_secs(args.pack_min_age_secs),
                grace: std::time::Duration::from_secs(args.pack_grace_secs),
            },
        );
    }

    // Build router
    // Allow up to 100MB for single-part uploads (larger objects need multipart)
    let body_limit = DefaultBodyLimit::max(100 * 1024 * 1024);
    info!("Max single-part upload size: 100 MB");

    // Bucket operations (including ?policy and ?uploads query params;
    // POST is ?delete, the batch delete)
    let bucket_routes = put(s3::create_bucket)
        .delete(s3::delete_bucket)
        .head(s3::head_bucket)
        .get(s3::list_objects)
        .post(s3::post_bucket);

    // Build S3 routes (behind SigV4 auth when enabled)
    let s3_routes = Router::new()
        // /health stays no-auth so a load balancer can probe the data
        // listener directly. /metrics now lives on the admin listener
        // (or the combined router) — splitting it off lets
        // operators firewall metrics/admin together on a mgmt VLAN.
        .route("/health", get(s3::health_check))
        .route("/_ready", get(cluster_poll::ready_handler))
        // Service endpoint (list buckets)
        .route("/", get(s3::list_buckets))
        // `/{bucket}/` is the same request: minio-go (warp, mc) and s3fs
        // send the slash, so every verb takes it.
        .route("/{bucket}", bucket_routes.clone())
        .route("/{bucket}/", bucket_routes)
        // Object operations (with multipart upload support via query params)
        .route("/{bucket}/{*key}", put(s3::put_object_with_params))
        .route("/{bucket}/{*key}", get(s3::get_object_with_params))
        .route("/{bucket}/{*key}", head(s3::head_object))
        .route("/{bucket}/{*key}", delete(s3::delete_object_with_params))
        .route("/{bucket}/{*key}", post(s3::post_object))
        .with_state(Arc::clone(&state));

    // Admin API routes — outside SigV4, protected by session cookie
    let admin_routes = Router::new()
        .route("/_admin/users", get(s3::admin_list_users))
        .route("/_admin/users", post(s3::admin_create_user))
        .route("/_admin/users/{user_id}", delete(s3::admin_delete_user))
        .route("/_admin/users/{user_id}", get(admin::admin_get_user))
        .route("/_admin/users/{user_id}", put(admin::admin_update_user))
        .route(
            "/_admin/access-keys/{access_key_id}",
            put(admin::admin_update_access_key),
        )
        .route(
            "/_admin/policies/{name}",
            get(iam_admin::get_policy_handler),
        )
        .route("/_admin/policies/{name}", put(iam_admin::update_policy))
        .route("/_admin/groups/{group_id}", get(iam_admin::get_group))
        .route(
            "/_admin/audit",
            get(audit::admin_get)
                .put(audit::admin_put)
                .delete(audit::admin_delete),
        )
        .route(
            "/_admin/public-access-block",
            get(public_access::admin_get)
                .put(public_access::admin_put)
                .delete(public_access::admin_delete),
        )
        .route(
            "/_admin/replication/targets",
            get(replication::admin_list_targets).post(replication::admin_put_target),
        )
        .route(
            "/_admin/replication/targets/{name}",
            delete(replication::admin_delete_target),
        )
        .route("/_admin/upgrade", get(upgrade::status))
        .route("/_admin/upgrade/finalize", post(upgrade::finalize))
        .route(
            "/_admin/replication/settings",
            get(replication::admin_get_settings).put(replication::admin_put_settings),
        )
        .route("/_admin/roles", get(iam_admin::list_roles))
        .route("/_admin/roles", post(iam_admin::create_role))
        .route("/_admin/roles/{name}", get(iam_admin::get_role))
        .route("/_admin/roles/{name}", put(iam_admin::update_role))
        .route("/_admin/roles/{name}", delete(iam_admin::delete_role))
        .route(
            "/_admin/users/{user_id}/access-keys",
            get(s3::admin_list_access_keys),
        )
        .route(
            "/_admin/users/{user_id}/access-keys",
            post(s3::admin_create_access_key),
        )
        .route(
            "/_admin/access-keys/{access_key_id}",
            delete(s3::admin_delete_access_key),
        )
        .route("/_admin/config", get(admin::admin_list_config))
        .route("/_admin/config/{*section}", get(admin::admin_get_config))
        .route("/_admin/config/{*section}", put(admin::admin_set_config))
        .route(
            "/_admin/config/{*section}",
            delete(admin::admin_delete_config),
        )
        .route("/_admin/pools", get(admin::admin_list_pools))
        .route("/_admin/pools", post(admin::admin_create_pool))
        .route("/_admin/pools/{name}", get(admin::admin_get_pool))
        .route("/_admin/pools/{name}", put(admin::admin_update_pool))
        .route("/_admin/pools/{name}", delete(admin::admin_delete_pool))
        .route(
            "/_admin/pools/{name}/placement-groups",
            get(admin::admin_list_pool_placement_groups),
        )
        .route("/_admin/tenants", get(admin::admin_list_tenants))
        .route("/_admin/tenants", post(admin::admin_create_tenant))
        .route("/_admin/tenants/{name}", get(admin::admin_get_tenant))
        .route("/_admin/tenants/{name}", put(admin::admin_update_tenant))
        .route("/_admin/tenants/{name}", delete(admin::admin_delete_tenant))
        .route(
            "/_admin/tenants/{name}/admins",
            post(admin::admin_add_tenant_admin),
        )
        .route(
            "/_admin/tenants/{name}/admins/{user}",
            delete(admin::admin_remove_tenant_admin),
        )
        .route("/_admin/nodes", get(admin::admin_list_nodes))
        .route("/_admin/usage", get(admin::admin_usage))
        .route(
            "/_admin/osds/{node_id}/admin-state",
            put(admin::admin_set_osd_state),
        )
        .route(
            "/_admin/osds/{node_id}/reboot",
            post(admin::admin_reboot_osd),
        )
        .route("/_admin/hosts", post(admin::admin_add_hosts))
        .route(
            "/_admin/host-provider",
            get(admin::admin_host_provider_info),
        )
        .route("/_admin/drain-status", get(admin::admin_drain_status))
        .route(
            "/_admin/rebalance-status",
            get(admin::admin_rebalance_status),
        )
        .route(
            "/_admin/rebalance/pause",
            post(admin::admin_rebalance_pause),
        )
        .route(
            "/_admin/rebalance/resume",
            post(admin::admin_rebalance_resume),
        )
        .route("/_admin/cluster-info", get(admin::admin_cluster_info))
        .route("/_admin/topology", get(admin::admin_get_topology))
        .route(
            "/_admin/placement/validate",
            get(admin::admin_validate_placement),
        )
        // IAM Policies
        .route("/_admin/policies", get(iam_admin::list_policies))
        .route("/_admin/policies", post(iam_admin::create_policy))
        .route("/_admin/policies/{name}", delete(iam_admin::delete_policy))
        .route(
            "/_admin/buckets/{bucket}/owner",
            put(admin::admin_set_bucket_owner),
        )
        .route(
            "/_admin/buckets/{bucket}/quota",
            put(admin::admin_set_bucket_quota),
        )
        .route("/_admin/policies/attach", post(iam_admin::attach_policy))
        .route("/_admin/policies/detach", post(iam_admin::detach_policy))
        .route("/_admin/policies/attached", get(iam_admin::list_attached))
        // IAM groups
        .route("/_admin/groups", get(iam_admin::list_groups))
        .route("/_admin/groups", post(iam_admin::create_group))
        .route("/_admin/groups/{group_id}", delete(iam_admin::delete_group))
        .route(
            "/_admin/groups/{group_id}/members",
            post(iam_admin::add_group_member),
        )
        .route(
            "/_admin/groups/{group_id}/members/{user_id}",
            delete(iam_admin::remove_group_member),
        )
        // Tenant-aware Table Sharing admin
        .route("/_admin/shares", get(admin::admin_list_shares_tenant))
        .route("/_admin/shares", post(admin::admin_create_share_tenant))
        .route(
            "/_admin/recipients",
            get(admin::admin_list_recipients_tenant),
        )
        .route("/_admin/warehouses", get(admin::admin_list_warehouses))
        .route("/_admin/warehouses", post(admin::admin_create_warehouse))
        .route(
            "/_admin/warehouses/{name}",
            delete(admin::admin_delete_warehouse),
        )
        .route(
            "/_admin/dedup",
            get(admin::admin_get_dedup).put(admin::admin_put_dedup),
        )
        .route(
            "/_admin/dedup/dry-run/reset",
            post(admin::admin_reset_dedup_dry_run),
        )
        .route(
            "/_admin/buckets/{name}/dedup",
            get(admin::admin_get_bucket_dedup)
                .put(admin::admin_put_bucket_dedup)
                .delete(admin::admin_delete_bucket_dedup),
        )
        .route("/_admin/buckets", get(admin::admin_list_buckets))
        .route("/_admin/buckets", post(admin::admin_create_bucket))
        .route("/_admin/buckets/{name}", delete(admin::admin_delete_bucket))
        .route(
            "/_admin/buckets/{name}/policy",
            get(admin::admin_get_bucket_policy),
        )
        .route(
            "/_admin/buckets/{name}/policy",
            put(admin::admin_put_bucket_policy),
        )
        .route(
            "/_admin/buckets/{name}/policy",
            delete(admin::admin_delete_bucket_policy),
        )
        .route(
            "/_admin/buckets/{name}/objects",
            get(admin::admin_list_objects),
        )
        // Object read/write for the console. The S3 path needs a SigV4
        // signature; the console has a session cookie, so these run the same
        // handlers behind the `/_admin/*` tenant-admin check rather than
        // handing the browser an access key.
        .route(
            "/_admin/buckets/{name}/objects/{*key}",
            get(admin::admin_get_object)
                .put(admin::admin_put_object)
                .delete(admin::admin_delete_object)
                // The admin router carries no body limit, so it would
                // otherwise inherit axum's 2 MB default and cap a console
                // upload well below what the S3 path accepts.
                .layer(DefaultBodyLimit::max(100 * 1024 * 1024)),
        )
        // KMS admin API
        .route("/_admin/kms/status", get(kms::admin_kms_status))
        .route("/_admin/kms/version", get(kms::admin_kms_version))
        .route("/_admin/kms/api", get(kms::admin_kms_api))
        .route("/_admin/kms/keys", get(kms::admin_list_kms_keys))
        .route("/_admin/kms/keys", post(kms::admin_create_kms_key))
        .route("/_admin/kms/keys/{key_id}", get(kms::admin_get_kms_key))
        .route(
            "/_admin/kms/keys/{key_id}",
            delete(kms::admin_delete_kms_key),
        )
        // Dynamic backend config: console-driven runtime reconfiguration
        .route("/_admin/kms/config", get(kms::admin_kms_get_config))
        .route("/_admin/kms/config", put(kms::admin_kms_put_config))
        .route("/_admin/kms/config", delete(kms::admin_kms_delete_config))
        .route("/_admin/kms/test", post(kms::admin_kms_test))
        // Prometheus proxy. Sits with the other admin APIs so it inherits the
        // same optional SigV4 layer — a console session and a signed request
        // are both recognised. Inert when --prometheus-url is unset.
        .route("/_admin/metrics/capabilities", get(prom::capabilities))
        .route("/_admin/metrics/query", get(prom::query))
        .route("/_admin/metrics/query_range", get(prom::query_range));
    // Hooks a test drives directly, never mounted otherwise.
    let admin_routes = if args.test_hooks {
        warn!("--test-hooks: /_admin/test/* is mounted");
        admin_routes
            .route("/_admin/test/pack", post(packs::admin_test_pack))
            .route(
                "/_admin/test/pack-reconcile",
                post(packs::admin_test_reconcile),
            )
            .route("/_admin/test/pack-compact", post(packs::admin_test_compact))
            .route("/_admin/test/packs", get(packs::admin_test_list))
            .route(
                "/_admin/test/rewrite-shard",
                post(test_hooks::rewrite_shard),
            )
    } else {
        admin_routes
    };
    let admin_routes = admin_routes
        .with_state(Arc::clone(&state))
        // Layer SigV4 verification that is optional — if a request carries
        // `Authorization: AWS4-HMAC-SHA256 ...`, verify it and inject
        // `Extension<AuthResult>`. Cookie-only console requests pass through
        // untouched. This lets handlers like `check_kms_policy` observe both
        // SigV4 callers (for IAM policy eval) and session users (admin).
        .layer(middleware::from_fn_with_state(
            Arc::clone(&auth_state),
            optional_auth_layer,
        ));

    // Console auth API routes (login/logout/session — no auth required)
    let console_oidc_state = Arc::new(console_auth::ConsoleOidcState {
        oidc_provider: oidc_provider.clone(),
        external_endpoint: args.external_endpoint.clone(),
        meta_client: meta_client_for_oidc,
    });

    let console_api_routes = Router::new()
        .route("/_console/api/login", post(console_auth::console_login))
        .route("/_console/api/session", get(console_auth::console_session))
        .route("/_console/api/logout", post(console_auth::console_logout))
        // Self-service key management (any authenticated user)
        .route("/_console/api/me/keys", get(console_auth::my_list_keys))
        .route("/_console/api/me/keys", post(console_auth::my_create_key))
        .route(
            "/_console/api/me/keys/{key_id}",
            delete(console_auth::my_delete_key),
        )
        .with_state(Arc::clone(&state));

    let console_oidc_routes = Router::new()
        .route(
            "/_console/api/oidc/enabled",
            get(console_auth::oidc_enabled),
        )
        .route(
            "/_console/api/oidc/authorize",
            get(console_auth::oidc_authorize),
        )
        .route(
            "/_console/api/oidc/callback",
            get(console_auth::oidc_callback),
        )
        // Public per-tenant SSO discovery — what the login page calls
        // when the URL carries ?tenant=NAME or the user types a tenant
        // in the account-name input. Matches AWS "account alias" UX.
        .route(
            "/_console/api/tenant/{name}/sso",
            get(console_auth::tenant_sso_info),
        )
        .with_state(console_oidc_state);

    // ============================================================
    // Multi-listener composition
    //
    // Layout:
    //   data    (--listen)                : S3 + Iceberg + Unity + Delta Sharing + /health
    //   admin   (--admin-listen)          : /_admin/* + /metrics + /health
    //   ops     (--ops-console-listen)    : /_console/* SPA + /_console/api/* + /_admin/* + /health
    //   tenant  (--tenant-console-listen) : same shape as ops, different SPA bundle
    //
    // Single-port mode (no split flag set, the default): everything is
    // merged onto --listen.
    // ============================================================
    if !args.no_auth {
        info!("Authentication is ENABLED (credentials from metadata service)");
        info!("Admin API is ENABLED (requires 'admin' user credentials)");
        info!("Iceberg REST Catalog: /iceberg/v1/* (no SigV4, use OAuth/bearer)");
    } else {
        info!("Authentication is DISABLED (development mode)");
        info!("Admin API is ENABLED (no auth required in dev mode)");
    }

    // SPA dirs.
    //   OBJECTIO_CONSOLE_DIR        — where both bundles live (ops/, tenant/)
    //   OBJECTIO_OPS_CONSOLE_DIR    — the ops bundle, if elsewhere
    //   OBJECTIO_TENANT_CONSOLE_DIR — the tenant bundle, if elsewhere
    let console_root = std::env::var("OBJECTIO_CONSOLE_DIR")
        .unwrap_or_else(|_| "/usr/share/objectio/console".to_string());
    let ops_console_dir =
        std::env::var("OBJECTIO_OPS_CONSOLE_DIR").unwrap_or_else(|_| format!("{console_root}/ops"));
    let tenant_console_dir = std::env::var("OBJECTIO_TENANT_CONSOLE_DIR")
        .unwrap_or_else(|_| format!("{console_root}/tenant"));

    let console_service = |dir: &str| {
        tower_http::services::ServeDir::new(dir).fallback(tower_http::services::ServeFile::new(
            format!("{dir}/index.html"),
        ))
    };

    // The IAM and STS query APIs (POST / with a form body) on the S3
    // endpoint.
    let query_api_state = Arc::new(iam_api::QueryApiState {
        app: Arc::clone(&state),
        sts: Arc::clone(&sts_state),
    });

    let post_object_state = Arc::new(post_object::PostObjectState {
        app: Arc::clone(&state),
        auth_enabled: !args.no_auth,
    });

    // S3-side layer stack (chunked-decode + body limit + optional SigV4 auth).
    let build_s3_protected = || {
        let r = Router::new()
            .merge(s3_routes.clone())
            // Innermost: after authentication and authorization.
            .layer(middleware::from_fn(s3::unsupported_subresource_layer))
            .layer(middleware::from_fn(chunked_decode::s3_chunked_decode_layer))
            .layer(body_limit);
        let r = if args.no_auth {
            r
        } else {
            // Layers wrap in reverse application order, so the authorization
            // layer is applied first and runs second: auth_layer puts the
            // caller's AuthResult on the request, authz_layer reads it.
            r.layer(middleware::from_fn_with_state(
                Arc::clone(&state),
                authz::authz_layer,
            ))
            .layer(middleware::from_fn_with_state(
                Arc::clone(&auth_state),
                auth_layer,
            ))
        };
        r.layer(middleware::from_fn_with_state(
            Arc::clone(&query_api_state),
            iam_api::query_api_layer,
        ))
        // Browser form uploads carry their credentials in the form, not an
        // Authorization header: taken ahead of SigV4, like STS.
        .layer(middleware::from_fn_with_state(
            Arc::clone(&post_object_state),
            post_object::post_object_layer,
        ))
        // CORS outermost: preflights are never signed, and a browser needs
        // the headers on every answer, refusals included.
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            cors::cors_layer,
        ))
    };

    // Parse the optional split-mode addrs.
    let parse_opt = |label: &str, val: &str| -> Result<Option<SocketAddr>> {
        if val.is_empty() {
            Ok(None)
        } else {
            val.parse::<SocketAddr>()
                .map(Some)
                .map_err(|e| anyhow::anyhow!("Invalid {label}={val}: {e}"))
        }
    };
    let admin_addr = parse_opt("--admin-listen", &args.admin_listen)?;
    let ops_console_addr = parse_opt("--ops-console-listen", &args.ops_console_listen)?;
    let tenant_console_addr = parse_opt("--tenant-console-listen", &args.tenant_console_listen)?;
    let split_mode =
        admin_addr.is_some() || ops_console_addr.is_some() || tenant_console_addr.is_some();

    let data_addr: SocketAddr = args
        .listen
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid --listen {}: {}", args.listen, e))?;

    // Each entry: (bind addr, router, label-for-logs, endpoint name).
    let mut listeners: Vec<(SocketAddr, Router, String, Option<String>)> = Vec::new();
    let main_endpoint = if args.endpoint_name.is_empty() {
        None
    } else if origin::valid_name(&args.endpoint_name) {
        Some(args.endpoint_name.clone())
    } else {
        anyhow::bail!("invalid --endpoint-name {:?}", args.endpoint_name);
    };
    let mut extra_data: Vec<(SocketAddr, String)> = Vec::new();
    for spec in &args.data_listen {
        let (addr, name) = spec
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--data-listen {spec}: expected ADDR=NAME"))?;
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| anyhow::anyhow!("--data-listen {spec}: {e}"))?;
        if !origin::valid_name(name)
            || main_endpoint.as_deref() == Some(name)
            || extra_data.iter().any(|(_, n)| n == name)
        {
            anyhow::bail!("--data-listen {spec}: invalid or duplicate endpoint name");
        }
        extra_data.push((addr, name.to_string()));
    }
    let data_only_router = || {
        Router::new()
            .merge(build_s3_protected())
            .nest("/iceberg", iceberg_router.clone())
            .merge(unity_router.clone())
            .nest("/delta-sharing", delta_sharing_router.clone())
            .layer(middleware::from_fn(metrics_middleware::metrics_layer))
            .layer(Extension(ListenerKind::Data))
            .layer(TraceLayer::new_for_http())
    };

    if !split_mode {
        // ---------- Single-port: everything on --listen ----------
        // ListenerKind::Combined = no audience gating on console_login /
        // oidc_callback (preserves pre-split behavior — any creds work
        // anywhere because there IS only one "anywhere").
        let combined = Router::new()
            .merge(build_s3_protected())
            .merge(admin_routes.clone())
            .merge(console_api_routes.clone())
            .merge(console_oidc_routes.clone())
            .nest("/iceberg", iceberg_router.clone())
            .merge(unity_router.clone())
            .nest("/delta-sharing", delta_sharing_router.clone())
            .nest("/_admin/delta-sharing", delta_sharing_admin_router.clone())
            // Path-mounted consoles. These are the addressable surfaces:
            // /_console/admin is the operator console, /_console/tenant the
            // self-service one. Each bundle is built with its own base, so the
            // same build serves correctly here and on a dedicated listener.
            // The bare /_console mount serves the single-port console.
            .nest_service("/_console/admin", console_service(&ops_console_dir))
            .nest_service("/_console/tenant", console_service(&tenant_console_dir))
            // Self-registration entry point. A short, shareable URL that lands
            // in the tenant bundle's signup route — the bundle is built with
            // its own base, so it has to be reached under that base rather
            // than mounted a second time somewhere else.
            .route(
                "/_console/signup",
                get(|| async { Redirect::temporary("/_console/tenant/signup") }),
            )
            // `/_console` itself has no bundle — the build produces the ops and
            // tenant bundles only — so it redirects to the operator console
            // rather than serving a directory with no index.html, which
            // renders as a blank page.
            .route(
                "/_console",
                get(|| async { Redirect::temporary("/_console/admin/") }),
            )
            .route(
                "/_console/",
                get(|| async { Redirect::temporary("/_console/admin/") }),
            )
            .route("/metrics", get(metrics_handler))
            .layer(middleware::from_fn(metrics_middleware::metrics_layer))
            .layer(Extension(ListenerKind::Combined))
            .layer(TraceLayer::new_for_http());
        listeners.push((
            data_addr,
            combined,
            "data (+ admin + console)".into(),
            main_endpoint.clone(),
        ));
    } else {
        // ---------- Split mode ----------
        // Data plane only.
        listeners.push((
            data_addr,
            data_only_router(),
            "data plane (S3 + Iceberg + Delta Sharing)".into(),
            main_endpoint.clone(),
        ));

        if let Some(addr) = admin_addr {
            if addr.ip().is_unspecified() {
                warn!(
                    "--admin-listen is bound to {} (all interfaces) — for production, \
                     pin it to a management interface so the admin API isn't internet-reachable.",
                    addr
                );
            }
            let admin_only = Router::new()
                .route("/health", get(s3::health_check))
                .route("/_ready", get(cluster_poll::ready_handler))
                .route("/metrics", get(metrics_handler))
                .merge(admin_routes.clone())
                .merge(console_api_routes.clone())
                .merge(console_oidc_routes.clone())
                .nest("/_admin/delta-sharing", delta_sharing_admin_router.clone())
                .layer(Extension(ListenerKind::AdminApi))
                .layer(TraceLayer::new_for_http());
            listeners.push((addr, admin_only, "admin API + metrics".into(), None));
        }

        if let Some(addr) = ops_console_addr {
            if addr.ip().is_unspecified() {
                warn!(
                    "--ops-console-listen is bound to {} — for production, pin to a \
                     management interface (the ops console is for system admins, not end users).",
                    addr
                );
            }
            info!("Ops console SPA: {}", ops_console_dir);
            let ops_router = Router::new()
                .route("/health", get(s3::health_check))
                .route("/_ready", get(cluster_poll::ready_handler))
                .merge(admin_routes.clone())
                .merge(console_api_routes.clone())
                .merge(console_oidc_routes.clone())
                .nest("/_admin/delta-sharing", delta_sharing_admin_router.clone())
                // Same canonical path as the single-port mount, so one
                // build serves both modes.
                .nest_service("/_console/admin", console_service(&ops_console_dir))
                .route(
                    "/",
                    get(|| async { Redirect::permanent("/_console/admin/") }),
                )
                .route(
                    "/_console",
                    get(|| async { Redirect::permanent("/_console/admin/") }),
                )
                .layer(Extension(ListenerKind::OpsConsole))
                .layer(TraceLayer::new_for_http());
            listeners.push((addr, ops_router, "ops console".into(), None));
        }

        if let Some(addr) = tenant_console_addr {
            info!("Tenant console SPA: {}", tenant_console_dir);
            let tenant_router = Router::new()
                .route("/health", get(s3::health_check))
                .route("/_ready", get(cluster_poll::ready_handler))
                // Tenant console mounts the same `/_admin/*` surface; the
                // handlers themselves enforce per-tenant scoping
                // (see `require_tenant_admin_access`). The bundle that
                // ships from `/_console/` only exposes tenant-relevant
                // pages so end users never see system-admin views, and
                // `console_login` refuses system-admin AK/SK here so the
                // public listener can't mint admin sessions.
                .merge(admin_routes.clone())
                .merge(console_api_routes.clone())
                .merge(console_oidc_routes.clone())
                .nest("/_admin/delta-sharing", delta_sharing_admin_router.clone())
                .nest_service("/_console/tenant", console_service(&tenant_console_dir))
                .route(
                    "/",
                    get(|| async { Redirect::permanent("/_console/tenant/") }),
                )
                .route(
                    "/_console",
                    get(|| async { Redirect::permanent("/_console/tenant/") }),
                )
                .layer(Extension(ListenerKind::TenantConsole))
                .layer(TraceLayer::new_for_http());
            listeners.push((addr, tenant_router, "tenant console".into(), None));
        }
    }

    for (addr, name) in extra_data {
        listeners.push((
            addr,
            data_only_router(),
            format!("data plane, endpoint {name:?}"),
            Some(name),
        ));
    }

    // Bind all listeners and serve concurrently. A shared broadcast channel
    // fans the user's shutdown future out to every axum::serve.
    // Keep capacity, usage, data-safety and the OSD / meta metrics fed.
    // Polled rather than gathered on scrape: /metrics has to stay fast and
    // must not fail because one node is slow to answer.
    cluster_poll::spawn(state.meta_client.clone());
    cluster_poll::spawn_readiness(state.meta_client.clone());
    clock_skew::spawn(state.meta_client.clone());

    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(listeners.len().max(1));
    let mut tasks = Vec::with_capacity(listeners.len());
    for (addr, router, label, endpoint) in listeners {
        // Audited outermost (inside only the endpoint's name), so every
        // refusal on the way in is recorded too.
        let router = router
            .layer(middleware::from_fn_with_state(
                Arc::clone(&auditor),
                audit::audit_layer,
            ))
            .layer(Extension(origin::Endpoint(endpoint)));
        // axum serves accepted sockets with Nagle on unless told otherwise;
        // Nagle holding back the tail of a response while the client delays
        // its ACK stalls a lone request by ~40 ms on Linux.
        let listener = TcpListener::bind(addr).await?.tap_io(|tcp| {
            if let Err(e) = tcp.set_nodelay(true) {
                debug!("TCP_NODELAY on accepted connection: {e}");
            }
        });
        info!("Listener: {label} on {addr}");
        // Iceberg path rewrite (`/iceberg/v1/ws/{wh}/...` →
        // `/iceberg/v1/...?warehouse={wh}`) is harmless on listeners
        // that don't serve Iceberg, but cheap to apply universally.
        let app = tower::ServiceBuilder::new()
            .layer(warehouse_rewrite.clone())
            .service(router);
        let mut rx = shutdown_tx.subscribe();
        tasks.push(tokio::spawn(async move {
            // Each connection's peer address rides on its requests.
            axum::serve(
                listener,
                tower::service_fn(move |stream: axum::serve::IncomingStream<'_, _>| {
                    let svc = origin::WithClientAddr {
                        inner: app.clone(),
                        addr: *stream.remote_addr(),
                    };
                    async move { Ok::<_, std::convert::Infallible>(svc) }
                }),
            )
            .with_graceful_shutdown(async move {
                let _ = rx.recv().await;
            })
            .await
        }));
    }

    // Wait for caller-provided shutdown future, then fan out to all listeners.
    shutdown.await;
    info!("Shutting down all listeners...");
    let _ = shutdown_tx.send(());

    for t in tasks {
        match t.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("Listener exited with error: {}", e),
            Err(e) => warn!("Listener task join error: {}", e),
        }
    }

    // What the audit spool holds goes out before the gateway does.
    auditor
        .drain(std::time::Duration::from_secs(args.audit_drain_secs))
        .await;

    info!("Gateway shut down gracefully");

    Ok(())
}

/// Start Transfer Engine and register the pools OSDs move shards through.
#[cfg(feature = "rdma")]
fn start_rdma(args: &Args, protocol: &str) -> Result<rdma::GatewayRdma> {
    use objectio_transport_te::Protocol;
    let protocol = match protocol {
        "rdma" => Protocol::Rdma,
        "tcp" => Protocol::Tcp,
        other => anyhow::bail!("--rdma {other}: expected rdma or tcp"),
    };
    let host = match &args.rdma_host {
        Some(host) => host.clone(),
        None => {
            let host = args
                .listen
                .rsplit_once(':')
                .map_or(args.listen.as_str(), |(host, _)| host);
            if host.is_empty() || host == "0.0.0.0" || host == "[::]" {
                anyhow::bail!(
                    "--rdma needs --rdma-host: --listen {} does not name one address",
                    args.listen
                );
            }
            host.to_string()
        }
    };
    // One slot holds a whole encoded stripe: every shard of the widest scheme
    // this gateway writes, and at least 4+2.
    let shards = usize::try_from(args.ec_k + args.ec_m).unwrap_or(6).max(6);
    let stripe_slot_size = shards * rdma::SHARD_SLOT_SIZE;
    let rdma = rdma::GatewayRdma::start(
        protocol,
        &host,
        stripe_slot_size,
        args.rdma_stripe_slots,
        args.rdma_read_slots,
    )
    .map_err(|e| anyhow::anyhow!("rdma ({protocol:?} on {host}): {e}"))?;
    info!(
        "Transfer Engine ({protocol:?}) segment {}: {} stripe slots of {} MiB, {} read slots",
        rdma.segment(),
        args.rdma_stripe_slots,
        stripe_slot_size >> 20,
        args.rdma_read_slots
    );
    Ok(rdma)
}

/// The cluster's secret signing key, from meta (created there on first
/// use). Both signing keys used to be derived from the region name alone,
/// which anyone can know. Without meta answering, a random key for this
/// gateway only: secure, though other gateways won't accept what it signs.
async fn load_cluster_secret(
    meta: objectio_proto::metadata::metadata_service_client::MetadataServiceClient<
        tonic::transport::Channel,
    >,
) -> Vec<u8> {
    for attempt in 0..30 {
        match meta
            .clone()
            .get_sts_signing_key(objectio_proto::metadata::GetStsSigningKeyRequest {})
            .await
        {
            Ok(r) => return r.into_inner().key,
            Err(e) if attempt == 29 => {
                tracing::error!(
                    "cannot load the cluster signing key from meta ({e}); using a key local to \
                     this gateway: its temporary credentials work only here"
                );
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_secs(1)).await,
        }
    }
    let mut key = vec![0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    key
}

/// A key for one purpose from the cluster secret: HMAC-SHA256(secret, label).
fn derive_key(secret: &[u8], label: &str) -> Vec<u8> {
    use hmac::Mac;
    let mut mac =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(secret).expect("HMAC takes a key of any length");
    mac.update(label.as_bytes());
    mac.finalize().into_bytes().to_vec()
}
