//! ObjectIO Gateway - S3 API Gateway
//!
//! This binary provides the S3-compatible HTTP API.
//! Credentials are managed by the metadata service for persistence.

pub mod admin;
pub mod auth_middleware;
pub mod authz;
pub mod chunked_decode;
pub mod console_auth;
pub mod grep;
pub mod grep_engine;
pub mod host_provider;
pub mod iceberg_auth;
pub mod kms;
pub mod license_gate;
pub mod lifecycle;
pub mod metrics_middleware;
pub mod osd_pool;
pub mod prom;
pub mod s3;
pub mod scatter_gather;

use anyhow::Result;
use auth_middleware::{AuthState, auth_layer, optional_auth_layer};
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
use objectio_s3::{ProtectionConfig, s3_metrics};
use osd_pool::OsdPool;
use s3::AppState;
use scatter_gather::ScatterGatherEngine;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

/// Resolve the initial license at startup.
///
/// Order of precedence:
/// 1. explicit `--license` flag path
/// 2. `OBJECTIO_LICENSE` env var — either a path or inline JSON
/// 3. meta config at `license/active` (what the console writes)
///
/// Any failure (missing file, bad signature, expired) logs a warning and
/// degrades to Community tier. Startup never hard-fails on the license.
async fn load_initial_license(
    cli_path: Option<&str>,
    meta_client: MetadataServiceClient<tonic::transport::Channel>,
) -> objectio_license::License {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // 0. Dev-mode escape hatch — `objectio-aio` and integration tests
    //    set this so all Enterprise features are usable without needing
    //    a signed license. Production deployments must NOT set this; it
    //    bypasses every license-gated check.
    if std::env::var("OBJECTIO_DEV_NO_LICENSE").is_ok_and(|v| !v.is_empty() && v != "0") {
        warn!(
            "OBJECTIO_DEV_NO_LICENSE is set — running with in-process Developer license. This is a development convenience and MUST NOT be used in production."
        );
        return objectio_license::License::developer_unsigned();
    }

    // 1. CLI flag
    if let Some(path) = cli_path {
        match std::fs::read(path) {
            Ok(bytes) => match objectio_license::License::load_from_bytes(&bytes, now) {
                Ok(l) => return l,
                Err(e) => warn!("--license {} rejected: {} — falling back", path, e),
            },
            Err(e) => warn!("--license {} unreadable: {} — falling back", path, e),
        }
    }

    // 2. Environment variable — path or inline JSON
    if let Ok(val) = std::env::var("OBJECTIO_LICENSE")
        && !val.is_empty()
    {
        let bytes = if val.trim_start().starts_with('{') {
            Some(val.into_bytes())
        } else {
            std::fs::read(&val).ok()
        };
        if let Some(bytes) = bytes {
            match objectio_license::License::load_from_bytes(&bytes, now) {
                Ok(l) => return l,
                Err(e) => warn!("OBJECTIO_LICENSE rejected: {} — falling back", e),
            }
        }
    }

    // 3. Meta config
    let mut client = meta_client;
    if let Ok(resp) = client
        .get_config(objectio_proto::metadata::GetConfigRequest {
            key: "license/active".to_string(),
        })
        .await
    {
        let inner = resp.into_inner();
        if inner.found
            && let Some(entry) = inner.entry
            && !entry.value.is_empty()
        {
            match objectio_license::License::load_from_bytes(&entry.value, now) {
                Ok(l) => return l,
                Err(e) => warn!("license in meta config rejected: {} — falling back", e),
            }
        }
    }

    objectio_license::License::community()
}

/// Prometheus metrics endpoint handler
/// How often the capacity gauges are refreshed. Capacity moves on the scale of
/// writes, not milliseconds, and each poll costs one `GetStatus` per OSD.
const CAPACITY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Ask every registered OSD how full it is.
///
/// Best effort in both directions: a node meta does not know about is not
/// reported, and a node that does not answer is reported with
/// `reachable: false` rather than omitted. Dropping it would make capacity
/// appear to shrink when a disk goes unreachable, which reads as data loss
/// rather than as a node being down.
async fn collect_capacity(
    mut meta: objectio_proto::metadata::metadata_service_client::MetadataServiceClient<
        tonic::transport::Channel,
    >,
) -> Vec<objectio_s3::metrics::NodeCapacity> {
    use objectio_proto::metadata::GetListingNodesRequest;
    use objectio_proto::storage::storage_service_client::StorageServiceClient;

    let Ok(resp) = meta
        .get_listing_nodes(GetListingNodesRequest {
            bucket: String::new(),
            include_all_states: true,
        })
        .await
    else {
        return Vec::new();
    };

    let mut seen = std::collections::HashSet::new();
    let targets: Vec<(String, Vec<u8>)> = resp
        .into_inner()
        .nodes
        .into_iter()
        .filter(|n| seen.insert(n.address.clone()))
        .map(|n| (n.address, n.node_id))
        .collect();

    let polls = targets.into_iter().map(|(addr, node_id)| async move {
        let endpoint = if addr.starts_with("http") {
            addr.clone()
        } else {
            format!("http://{addr}")
        };
        let status = async {
            let mut c = StorageServiceClient::connect(endpoint).await.ok()?;
            let s = c
                .get_status(objectio_proto::storage::GetStatusRequest {})
                .await
                .ok()?
                .into_inner();
            Some((s.total_capacity, s.used_capacity, s.shard_count))
        }
        .await;

        let (total, used, shards, reachable) =
            status.map_or((0, 0, 0, false), |(t, u, s)| (t, u, s, true));
        objectio_s3::metrics::NodeCapacity {
            node_id: hex::encode(&node_id),
            address: addr,
            total_bytes: total,
            used_bytes: used,
            shard_count: shards,
            reachable,
        }
    });

    futures::future::join_all(polls).await
}

async fn metrics_handler() -> impl IntoResponse {
    let metrics = s3_metrics().export_prometheus();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        metrics,
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
    /// In legacy single-port mode, also serves /_admin/* and /_console/*.
    #[arg(short, long, default_value = "0.0.0.0:9000")]
    pub listen: String,

    /// Optional dedicated listener for the admin API (`/_admin/*`) and
    /// `/metrics`. When set, the admin surface moves OFF `--listen`
    /// entirely and only this address serves it. Bind to a mgmt
    /// interface (e.g. `127.0.0.1:9001` or `10.0.5.10:9001`) so the
    /// public S3 endpoint stays the only Internet-facing port. Empty =
    /// legacy single-port (admin stays on `--listen`).
    #[arg(long, default_value = "")]
    pub admin_listen: String,

    /// Optional dedicated listener for the **ops** console (full
    /// surface — pools, OSDs, balancer, tenants, billing). Mounts the
    /// SPA from `OBJECTIO_OPS_CONSOLE_DIR` plus the `/_admin/*` API
    /// (so the browser stays same-origin — no CORS). Bind to a mgmt
    /// interface in production. Empty = ops console is served on
    /// `--listen` (legacy) or omitted entirely if `--tenant-console-listen`
    /// is set without this one.
    #[arg(long, default_value = "")]
    pub ops_console_listen: String,

    /// Optional dedicated listener for the **tenant** console
    /// (self-service: my buckets, my keys, my catalogs). Mounts the
    /// SPA from `OBJECTIO_TENANT_CONSOLE_DIR` plus the same `/_admin/*`
    /// surface (server-side tenant-scoped). Safe to expose publicly so
    /// end users can self-serve. Empty = tenant console is not served
    /// separately (ops console covers both surfaces in legacy mode).
    #[arg(long, default_value = "")]
    pub tenant_console_listen: String,

    /// Metadata service endpoint
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

    /// Keep buckets that have no recorded owner accessible to any
    /// authenticated caller. Buckets created before ownership was tracked
    /// carry no owner, so enforcing owner-only on them would lock an existing
    /// deployment out of everything it already has.
    ///
    /// Backfill with `PUT /_admin/buckets/{bucket}/owner`, then set this to
    /// false to close the gap. Buckets created from now on always record
    /// their creator and are unaffected either way.
    #[arg(
        long,
        env = "OBJECTIO_AUTHZ_LEGACY_OPEN_BUCKETS",
        default_value_t = true,
        action = clap::ArgAction::Set
    )]
    pub authz_legacy_open_buckets: bool,

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
    #[arg(long, default_value = "", alias = "external-url")]
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

    /// Path to an Enterprise license file. Falls back to `$OBJECTIO_LICENSE`,
    /// then to the `license/active` key in meta config, then to Community
    /// tier (no Enterprise features).
    #[arg(long)]
    pub license: Option<String>,

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
}

/// Run the gateway until `shutdown` resolves. Caller owns the tracing
/// subscriber and the Ctrl-C wiring; we trust args already parsed.
pub async fn run(
    args: Args,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
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

    // Connect to metadata service
    let meta_client = MetadataServiceClient::connect(args.meta_endpoint.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to metadata service: {}", e))?;

    info!("Connected to metadata service");
    info!("Credentials are managed by the metadata service");

    // Create OSD connection pool
    let osd_pool = Arc::new(OsdPool::new());

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

    // STS provider for vended Iceberg credentials + S3 temporary auth
    let sts_signing_key = format!("objectio-sts-{}", args.region);
    let sts_provider = objectio_auth::sts::StsProvider::new(sts_signing_key.as_bytes());

    // Create auth state using metadata service for credential lookup
    let auth_state =
        Arc::new(AuthState::new(meta_client.clone(), &args.region).with_sts(sts_provider.clone()));

    // Create scatter-gather engine with a signing key derived from region
    let signing_key = format!("objectio-scatter-gather-{}", args.region);
    let scatter_gather = ScatterGatherEngine::new(osd_pool.clone(), signing_key.as_bytes());

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

    // OIDC provider — used by both the Iceberg auth layer (Enterprise) and
    // the console OIDC login flow (all tiers). Defined here so it stays in
    // scope for the Community build even when the Iceberg block below is
    // compiled out.
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

    // Build Iceberg REST Catalog router and Delta Sharing router. Both are
    // Enterprise features, gated at runtime by `feature_gate` middleware —
    // without a valid Enterprise license the routers reject with 403.
    //
    // The Unity Catalog router (mounted at /api/2.1/unity-catalog/*) shares
    // the same iceberg auth layer and is gated by the same Iceberg feature
    // flag — there is no separate Feature::Unity, since Unity is just an
    // alternate REST surface over the same catalog metadata.
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
    // bearer + session cookie), same Feature::Iceberg license gate. Mounted
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

    // Warehouse prefix rewrite layer — harmless when the license gate
    // rejects Iceberg: rewritten requests simply short-circuit with 403.
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

    // Start lifecycle background worker
    lifecycle::spawn_lifecycle_worker(
        meta_client.clone(),
        Arc::clone(&osd_pool),
        lifecycle::LifecycleWorkerConfig::default(),
    );

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

    // Load license. Order of precedence: --license flag, OBJECTIO_LICENSE env,
    // meta config at `license/active`. No license → Community tier (all
    // Enterprise features remain gated). Parse/verify failures log a warning
    // and fall back to Community — never hard-fail startup on a broken license.
    let license = load_initial_license(args.license.as_deref(), meta_client.clone()).await;
    match license.tier {
        objectio_license::Tier::Enterprise => info!(
            "License: Enterprise — licensee='{}' expires_at={} max_nodes={}",
            license.licensee, license.expires_at, license.max_nodes
        ),
        objectio_license::Tier::Developer => info!(
            "License: Developer — licensee='{}' expires_at={} max_nodes={} (single-host)",
            license.licensee, license.expires_at, license.max_nodes
        ),
        objectio_license::Tier::Community => {
            info!("License: Community — Enterprise features gated")
        }
    }

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

    // Create application state. KMS fields are held behind RwLocks so
    // `PUT /_admin/kms/config` can hot-swap the backend at runtime; we seed
    // them here with whatever the CLI flag + env / meta config resolved to.
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
        license: parking_lot::RwLock::new(Arc::new(license)),
        self_topology,
        host_provider,
        legacy_open_buckets: args.authz_legacy_open_buckets,
        prometheus_url: args.prometheus_url.clone(),
    });

    // Build router
    // Allow up to 100MB for single-part uploads (larger objects need multipart)
    let body_limit = DefaultBodyLimit::max(100 * 1024 * 1024);
    info!("Max single-part upload size: 100 MB");

    // Build S3 routes (behind SigV4 auth when enabled)
    let s3_routes = Router::new()
        // /health stays no-auth so a load balancer can probe the data
        // listener directly. /metrics now lives on the admin listener
        // (or the legacy combined router) — splitting it off lets
        // operators firewall metrics/admin together on a mgmt VLAN.
        .route("/health", get(s3::health_check))
        // Service endpoint (list buckets)
        .route("/", get(s3::list_buckets))
        // Bucket operations (including ?policy and ?uploads query params)
        .route("/{bucket}", put(s3::create_bucket))
        .route("/{bucket}", delete(s3::delete_bucket))
        .route("/{bucket}", head(s3::head_bucket))
        .route("/{bucket}", get(s3::list_objects))
        // POST /{bucket}?delete - batch delete objects
        .route("/{bucket}", post(s3::post_bucket))
        // Bucket with trailing slash (s3fs compatibility)
        .route("/{bucket}/", head(s3::head_bucket_trailing))
        .route("/{bucket}/", get(s3::list_objects_trailing))
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
        .route("/_admin/policies", get(admin::admin_list_policies))
        .route("/_admin/policies", post(admin::admin_create_policy))
        .route(
            "/_admin/policies/{name}",
            delete(admin::admin_delete_policy),
        )
        .route(
            "/_admin/buckets/{bucket}/owner",
            put(admin::admin_set_bucket_owner),
        )
        .route("/_admin/policies/attach", post(admin::admin_attach_policy))
        .route("/_admin/policies/detach", post(admin::admin_detach_policy))
        .route(
            "/_admin/policies/attached",
            get(admin::admin_list_attached_policies),
        )
        // IAM groups
        .route("/_admin/groups", get(admin::admin_list_groups))
        .route("/_admin/groups", post(admin::admin_create_group))
        .route(
            "/_admin/groups/{group_id}",
            delete(admin::admin_delete_group),
        )
        .route(
            "/_admin/groups/{group_id}/members",
            post(admin::admin_add_group_member),
        )
        .route(
            "/_admin/groups/{group_id}/members/{user_id}",
            delete(admin::admin_remove_group_member),
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
        // License management
        .route("/_admin/license", get(admin::admin_get_license))
        .route("/_admin/license", put(admin::admin_put_license))
        .route("/_admin/license", delete(admin::admin_delete_license))
        // Prometheus proxy. Sits with the other admin APIs so it inherits the
        // same optional SigV4 layer — a console session and a signed request
        // are both recognised. Inert when --prometheus-url is unset.
        .route("/_admin/metrics/capabilities", get(prom::capabilities))
        .route("/_admin/metrics/query", get(prom::query))
        .route("/_admin/metrics/query_range", get(prom::query_range))
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
    // Legacy single-port mode (no split flag set): everything is merged
    // onto --listen, identical to pre-split deployments.
    // ============================================================
    if !args.no_auth {
        info!("Authentication is ENABLED (credentials from metadata service)");
        info!("Admin API is ENABLED (requires 'admin' user credentials)");
        info!("Iceberg REST Catalog: /iceberg/v1/* (no SigV4, use OAuth/bearer)");
    } else {
        info!("Authentication is DISABLED (development mode)");
        info!("Admin API is ENABLED (no auth required in dev mode)");
    }

    // License-gated wrappers — built once, cloned into each composite
    // router that exposes them.
    let iceberg_gated = iceberg_router.layer(middleware::from_fn_with_state(
        (Arc::clone(&state), objectio_license::Feature::Iceberg),
        license_gate::feature_gate,
    ));
    let unity_gated = unity_router.layer(middleware::from_fn_with_state(
        (Arc::clone(&state), objectio_license::Feature::Iceberg),
        license_gate::feature_gate,
    ));
    let delta_gated = delta_sharing_router.layer(middleware::from_fn_with_state(
        (Arc::clone(&state), objectio_license::Feature::DeltaSharing),
        license_gate::feature_gate,
    ));
    let delta_admin_gated = delta_sharing_admin_router.layer(middleware::from_fn_with_state(
        (Arc::clone(&state), objectio_license::Feature::DeltaSharing),
        license_gate::feature_gate,
    ));

    // SPA dirs.
    //   OBJECTIO_CONSOLE_DIR        — legacy single-bundle (default for legacy mode)
    //   OBJECTIO_OPS_CONSOLE_DIR    — ops bundle for --ops-console-listen
    //   OBJECTIO_TENANT_CONSOLE_DIR — tenant bundle for --tenant-console-listen
    let legacy_console_dir = std::env::var("OBJECTIO_CONSOLE_DIR")
        .unwrap_or_else(|_| "/usr/share/objectio/console".to_string());
    let ops_console_dir = std::env::var("OBJECTIO_OPS_CONSOLE_DIR")
        .unwrap_or_else(|_| format!("{legacy_console_dir}/ops"));
    let tenant_console_dir = std::env::var("OBJECTIO_TENANT_CONSOLE_DIR")
        .unwrap_or_else(|_| format!("{legacy_console_dir}/tenant"));

    let console_service = |dir: &str| {
        tower_http::services::ServeDir::new(dir).fallback(tower_http::services::ServeFile::new(
            format!("{dir}/index.html"),
        ))
    };

    // S3-side layer stack (chunked-decode + body limit + optional SigV4 auth).
    let build_s3_protected = || {
        let r = Router::new()
            .merge(s3_routes.clone())
            .layer(middleware::from_fn(chunked_decode::s3_chunked_decode_layer))
            .layer(body_limit);
        if args.no_auth {
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
        }
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

    // Each entry: (bind addr, router, label-for-logs).
    let mut listeners: Vec<(SocketAddr, Router, &'static str)> = Vec::new();

    if !split_mode {
        // ---------- Legacy single-port: everything on --listen ----------
        // ListenerKind::Legacy = no audience gating on console_login /
        // oidc_callback (preserves pre-split behavior — any creds work
        // anywhere because there IS only one "anywhere").
        let combined = Router::new()
            .merge(build_s3_protected())
            .merge(admin_routes.clone())
            .merge(console_api_routes.clone())
            .merge(console_oidc_routes.clone())
            .nest("/iceberg", iceberg_gated.clone())
            .merge(unity_gated.clone())
            .nest("/delta-sharing", delta_gated.clone())
            .nest("/_admin/delta-sharing", delta_admin_gated.clone())
            // Path-mounted consoles. These are the addressable surfaces:
            // /_console/admin is the operator console, /_console/tenant the
            // self-service one. Each bundle is built with its own base, so the
            // same build serves correctly here and on a dedicated listener.
            // The bare /_console mount stays for the legacy single bundle.
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
            .layer(Extension(ListenerKind::Legacy))
            .layer(TraceLayer::new_for_http());
        listeners.push((data_addr, combined, "data (legacy: + admin + console)"));
    } else {
        // ---------- Split mode ----------
        // Data plane only.
        let data_router = Router::new()
            .merge(build_s3_protected())
            .nest("/iceberg", iceberg_gated.clone())
            .merge(unity_gated.clone())
            .nest("/delta-sharing", delta_gated.clone())
            .layer(middleware::from_fn(metrics_middleware::metrics_layer))
            .layer(Extension(ListenerKind::Data))
            .layer(TraceLayer::new_for_http());
        listeners.push((
            data_addr,
            data_router,
            "data plane (S3 + Iceberg + Delta Sharing)",
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
                .route("/metrics", get(metrics_handler))
                .merge(admin_routes.clone())
                .merge(console_api_routes.clone())
                .merge(console_oidc_routes.clone())
                .nest("/_admin/delta-sharing", delta_admin_gated.clone())
                .layer(Extension(ListenerKind::AdminApi))
                .layer(TraceLayer::new_for_http());
            listeners.push((addr, admin_only, "admin API + metrics"));
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
                .merge(admin_routes.clone())
                .merge(console_api_routes.clone())
                .merge(console_oidc_routes.clone())
                .nest("/_admin/delta-sharing", delta_admin_gated.clone())
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
            listeners.push((addr, ops_router, "ops console"));
        }

        if let Some(addr) = tenant_console_addr {
            info!("Tenant console SPA: {}", tenant_console_dir);
            let tenant_router = Router::new()
                .route("/health", get(s3::health_check))
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
                .nest("/_admin/delta-sharing", delta_admin_gated.clone())
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
            listeners.push((addr, tenant_router, "tenant console"));
        }
    }

    // Bind all listeners and serve concurrently. A shared broadcast channel
    // fans the user's shutdown future out to every axum::serve.
    // Keep the capacity gauges fed. Polling here rather than computing on
    // scrape: a reading costs a GetStatus to every OSD, and /metrics has to
    // stay fast and must not fail because one disk is slow to answer.
    {
        let meta_client = state.meta_client.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(CAPACITY_POLL_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                ticker.tick().await;
                let nodes = collect_capacity(meta_client.clone()).await;
                s3_metrics().set_capacity(nodes);
            }
        });
    }

    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(listeners.len().max(1));
    let mut tasks = Vec::with_capacity(listeners.len());
    for (addr, router, label) in listeners {
        let listener = TcpListener::bind(addr).await?;
        info!("Listener: {label} on {addr}");
        // Iceberg path rewrite (`/iceberg/v1/ws/{wh}/...` →
        // `/iceberg/v1/...?warehouse={wh}`) is harmless on listeners
        // that don't serve Iceberg, but cheap to apply universally.
        let app = tower::ServiceBuilder::new()
            .layer(warehouse_rewrite.clone())
            .service(router);
        let mut rx = shutdown_tx.subscribe();
        tasks.push(tokio::spawn(async move {
            axum::serve(listener, tower::make::Shared::new(app))
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

    info!("Gateway shut down gracefully");

    Ok(())
}
