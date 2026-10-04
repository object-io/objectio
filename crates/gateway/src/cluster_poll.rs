//! The gateway's background poll of the cluster, and everything it feeds
//! into `/metrics`.
//!
//! Every [`POLL_INTERVAL`] the gateway asks meta for the OSDs, then asks
//! each OSD for its status (capacity, per-bucket usage, shard safety) and
//! its own metrics exposition, and asks meta for its exposition and for
//! drain / rebalance progress. `/metrics` serves the result without
//! touching the network: a scrape must stay fast and must not fail
//! because one node is slow.
//!
//! The gateway is the single scrape target. OSD and meta expositions are
//! merged into its own (see `crate::s3_metrics::metrics_merge`), so the
//! all-in-one binary — whose OSDs and meta have no metrics port — exposes
//! them too.

use crate::s3_metrics::metrics::NodeCapacity;
use crate::s3_metrics::metrics_merge::{self, Source};
use crate::s3_metrics::s3_metrics;
use crate::s3_metrics::usage::OsdBucketUsage;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::metadata::{
    DrainStatus, GetDrainStatusRequest, GetListingNodesRequest, GetMetricsRequest,
    GetMetricsResponse, GetRebalanceStatusRequest, GetRebalanceStatusResponse,
};
use objectio_proto::storage::storage_service_client::StorageServiceClient;
use objectio_proto::storage::{GetStatusRequest, GetStatusResponse, ObjectSafety};
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::sync::{LazyLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tonic::transport::Channel;

/// How often the cluster is polled. Capacity and usage move on the scale
/// of writes, and each poll costs a few RPCs per OSD.
pub const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// The poll interval while any bucket or tenant has a quota.
pub const QUOTA_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Budget for one OSD or meta call. A node slower than this is reported
/// as down for the poll rather than holding up every other node.
const CALL_TIMEOUT: Duration = Duration::from_secs(10);

type MetaClient = MetadataServiceClient<Channel>;

/// What the last poll learned, for `/metrics`.
#[derive(Default)]
struct Snapshot {
    /// (osd node id hex, exposition) for OSDs that answered.
    osd_metrics: Vec<(String, GetMetricsResponse)>,
    meta_metrics: Option<GetMetricsResponse>,
    /// Summed over OSDs that answered, when any computed it.
    safety: Option<ObjectSafety>,
    /// OSDs that did not answer, whose owned objects are only covered
    /// through the fallback in the OSD's safety check.
    safety_osds_missing: u64,
    drains: Vec<DrainStatus>,
    rebalance: Option<GetRebalanceStatusResponse>,
    // Poll bookkeeping (section "staleness"): a frozen number looks
    // healthy, so say when it was last refreshed and how long that took.
    polls_total: u64,
    poll_failures_total: u64,
    last_success: Option<u64>,
    last_duration: Option<Duration>,
}

static SNAPSHOT: LazyLock<RwLock<Snapshot>> = LazyLock::new(|| RwLock::new(Snapshot::default()));

/// Start the poll loop.
pub fn spawn(meta: MetaClient) {
    tokio::spawn(async move {
        // Last usage each OSD reported. An OSD that misses a poll keeps its
        // previous numbers: its objects are counted by nobody else, so
        // dropping them would make every bucket it serves look like it lost
        // data until it came back.
        let mut last_usage: HashMap<String, Vec<OsdBucketUsage>> = HashMap::new();
        // Nodes that answered the previous poll; sent to OSDs as the "up"
        // set for the safety check.
        let mut up: Vec<Vec<u8>> = Vec::new();
        let mut first = true;
        loop {
            // While any quota is set, usage is gathered more often: it is
            // what writes are admitted against (crate::quota).
            if !first {
                tokio::time::sleep(if crate::quota::any_quota() {
                    QUOTA_POLL_INTERVAL
                } else {
                    POLL_INTERVAL
                })
                .await;
            }
            first = false;
            let started = Instant::now();
            let ok = poll_once(meta.clone(), &mut last_usage, &mut up).await;
            let elapsed = started.elapsed();
            if let Ok(mut s) = SNAPSHOT.write() {
                s.polls_total += 1;
                s.last_duration = Some(elapsed);
                if ok {
                    s.last_success = Some(now_secs());
                } else {
                    s.poll_failures_total += 1;
                }
            }
        }
    });
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn timed<T, E>(f: impl std::future::Future<Output = Result<T, E>>) -> Option<T> {
    tokio::time::timeout(CALL_TIMEOUT, f).await.ok()?.ok()
}

struct OsdPoll {
    node_id: Vec<u8>,
    capacity: NodeCapacity,
    status: Option<GetStatusResponse>,
    metrics: Option<GetMetricsResponse>,
}

async fn poll_osd(addr: String, node_id: Vec<u8>, up: Vec<Vec<u8>>) -> OsdPoll {
    let endpoint = if addr.starts_with("http") {
        addr.clone()
    } else {
        format!("http://{addr}")
    };
    let (status, metrics) = match timed(StorageServiceClient::connect(endpoint)).await {
        Some(mut c) => {
            let status = timed(c.get_status(GetStatusRequest { up_nodes: up }))
                .await
                .map(tonic::Response::into_inner);
            let metrics = timed(c.get_metrics(GetMetricsRequest {}))
                .await
                .map(tonic::Response::into_inner);
            (status, metrics)
        }
        None => (None, None),
    };
    let capacity = NodeCapacity {
        node_id: hex::encode(&node_id),
        address: addr,
        total_bytes: status.as_ref().map_or(0, |s| s.total_capacity),
        used_bytes: status.as_ref().map_or(0, |s| s.used_capacity),
        shard_count: status.as_ref().map_or(0, |s| s.shard_count),
        reachable: status.is_some(),
    };
    OsdPoll {
        node_id,
        capacity,
        status,
        metrics,
    }
}

/// One poll. Returns whether meta answered — without it nothing else is
/// known, and the numbers served are the previous poll's.
async fn poll_once(
    mut meta: MetaClient,
    last_usage: &mut HashMap<String, Vec<OsdBucketUsage>>,
    up: &mut Vec<Vec<u8>>,
) -> bool {
    // Usage gathered from here on: writes admitted before it are in it.
    let gathered_at = Instant::now();
    let Some(resp) = timed(meta.get_listing_nodes(GetListingNodesRequest {
        bucket: String::new(),
        include_all_states: true,
    }))
    .await
    else {
        return false;
    };

    let mut seen = HashSet::new();
    let targets: Vec<(String, Vec<u8>)> = resp
        .into_inner()
        .nodes
        .into_iter()
        .filter(|n| seen.insert(n.address.clone()))
        .map(|n| (n.address, n.node_id))
        .collect();

    let prev_up = up.clone();
    let polls = futures::future::join_all(
        targets
            .into_iter()
            .map(|(addr, id)| poll_osd(addr, id, prev_up.clone())),
    );
    let (mut m1, mut m2, mut m3) = (meta.clone(), meta.clone(), meta.clone());
    let meta_metrics = timed(m1.get_metrics(GetMetricsRequest {}));
    let drains = timed(m2.get_drain_status(GetDrainStatusRequest {}));
    let rebalance = timed(m3.get_rebalance_status(GetRebalanceStatusRequest {}));
    let (polls, meta_metrics, drains, rebalance) =
        tokio::join!(polls, meta_metrics, drains, rebalance);

    *up = polls
        .iter()
        .filter(|p| p.status.is_some())
        .map(|p| p.node_id.clone())
        .collect();

    let mut safety: Option<ObjectSafety> = None;
    let mut safety_missing = 0;
    let mut osd_metrics = Vec::new();
    let mut nodes = Vec::with_capacity(polls.len());
    for p in polls {
        if let Some(st) = &p.status {
            last_usage.insert(p.capacity.node_id.clone(), usage_of(st));
            if let Some(s) = &st.safety {
                let t = safety.get_or_insert_with(ObjectSafety::default);
                t.objects_checked += s.objects_checked;
                t.objects_degraded += s.objects_degraded;
                t.objects_at_risk += s.objects_at_risk;
                t.objects_unreadable += s.objects_unreadable;
                t.bytes_degraded += s.bytes_degraded;
                t.bytes_at_risk += s.bytes_at_risk;
                t.bytes_unreadable += s.bytes_unreadable;
            }
        } else {
            safety_missing += 1;
        }
        if let Some(m) = p.metrics {
            osd_metrics.push((p.capacity.node_id.clone(), m));
        }
        nodes.push(p.capacity);
    }
    last_usage.retain(|id, _| nodes.iter().any(|n| &n.node_id == id));

    if let Some(report) = crate::build_usage_report(meta.clone(), &nodes, last_usage).await {
        crate::quota::on_report(&report, gathered_at);
        s3_metrics().set_usage(report);
    }
    s3_metrics().set_capacity(nodes);

    if let Ok(mut s) = SNAPSHOT.write() {
        s.osd_metrics = osd_metrics;
        s.meta_metrics = meta_metrics.map(tonic::Response::into_inner);
        s.safety = safety;
        s.safety_osds_missing = safety_missing;
        s.drains = drains.map(|r| r.into_inner().drains).unwrap_or_default();
        s.rebalance = rebalance.map(tonic::Response::into_inner);
    }
    true
}

fn usage_of(st: &GetStatusResponse) -> Vec<OsdBucketUsage> {
    st.bucket_usage
        .iter()
        .map(|u| OsdBucketUsage {
            bucket: u.bucket.clone(),
            objects: u.objects,
            logical_bytes: u.logical_bytes,
            stored_bytes: u.stored_bytes,
            noncurrent_versions: u.noncurrent_versions,
            noncurrent_bytes: u.noncurrent_bytes,
            last_modified: u.last_modified,
        })
        .collect()
}

fn gauge(out: &mut String, name: &str, kind: &str, help: &str, samples: &[(String, u64)]) {
    writeln!(out, "# HELP {name} {help}").unwrap();
    writeln!(out, "# TYPE {name} {kind}").unwrap();
    for (labels, v) in samples {
        if labels.is_empty() {
            writeln!(out, "{name} {v}").unwrap();
        } else {
            writeln!(out, "{name}{{{labels}}} {v}").unwrap();
        }
    }
}

/// Families the poll itself produces: staleness, data safety, drain and
/// rebalance progress.
fn render_local(s: &Snapshot) -> String {
    let mut out = String::new();
    let one = |v: u64| vec![(String::new(), v)];

    if let Some(t) = s.last_success {
        gauge(
            &mut out,
            "objectio_capacity_poll_last_success_timestamp_seconds",
            "gauge",
            "When the gateway last refreshed capacity, usage and cluster metrics",
            &one(t),
        );
    }
    if let Some(d) = s.last_duration {
        writeln!(
            out,
            "# HELP objectio_capacity_poll_duration_seconds How long the last poll took\n\
             # TYPE objectio_capacity_poll_duration_seconds gauge\n\
             objectio_capacity_poll_duration_seconds {}",
            d.as_secs_f64()
        )
        .unwrap();
    }
    gauge(
        &mut out,
        "objectio_capacity_polls_total",
        "counter",
        "Polls attempted",
        &one(s.polls_total),
    );
    gauge(
        &mut out,
        "objectio_capacity_poll_failures_total",
        "counter",
        "Polls in which meta did not answer",
        &one(s.poll_failures_total),
    );

    if let Some(t) = &s.safety {
        for (name, help, v) in [
            (
                "objectio_objects_checked",
                "Objects and versions whose shard availability was checked",
                t.objects_checked,
            ),
            (
                "objectio_objects_degraded",
                "Objects with a shard on an OSD that is down (still readable)",
                t.objects_degraded,
            ),
            (
                "objectio_objects_at_risk",
                "Objects with fewer than k+1 reachable shards: one more loss makes them unreadable",
                t.objects_at_risk,
            ),
            (
                "objectio_objects_unreadable",
                "Objects with fewer than k reachable shards",
                t.objects_unreadable,
            ),
            (
                "objectio_degraded_bytes",
                "Logical bytes of degraded objects",
                t.bytes_degraded,
            ),
            (
                "objectio_at_risk_bytes",
                "Logical bytes of at-risk objects",
                t.bytes_at_risk,
            ),
            (
                "objectio_unreadable_bytes",
                "Logical bytes of unreadable objects",
                t.bytes_unreadable,
            ),
        ] {
            gauge(&mut out, name, "gauge", help, &one(v));
        }
        gauge(
            &mut out,
            "objectio_safety_osds_unreported",
            "gauge",
            "OSDs that did not answer, so objects only they hold metadata for were not checked",
            &one(s.safety_osds_missing),
        );
    }

    if !s.drains.is_empty() {
        let by = |f: fn(&DrainStatus) -> u64| -> Vec<(String, u64)> {
            s.drains
                .iter()
                .map(|d| (format!("node_id=\"{}\"", hex::encode(&d.node_id)), f(d)))
                .collect()
        };
        gauge(
            &mut out,
            "objectio_drain_shards_remaining",
            "gauge",
            "Shards still on a draining OSD",
            &by(|d| d.shards_remaining),
        );
        gauge(
            &mut out,
            "objectio_drain_shards_initial",
            "gauge",
            "Shards on the OSD when its drain started",
            &by(|d| d.initial_shards),
        );
        gauge(
            &mut out,
            "objectio_drain_shards_migrated_total",
            "counter",
            "Shards moved off the draining OSD",
            &by(|d| d.shards_migrated),
        );
        gauge(
            &mut out,
            "objectio_drain_errored",
            "gauge",
            "1 if the last drain sweep reported an error",
            &by(|d| u64::from(!d.last_error.is_empty())),
        );
    }

    if let Some(r) = &s.rebalance {
        for (name, kind, help, v) in [
            (
                "objectio_rebalance_running",
                "gauge",
                "1 if the balancer is started and not paused",
                u64::from(r.started && !r.paused),
            ),
            (
                "objectio_rebalance_pgs_moved_total",
                "counter",
                "Placement groups the balancer has moved",
                r.pgs_moved_total,
            ),
            (
                "objectio_rebalance_pg_candidates",
                "gauge",
                "Placement groups the balancer wanted to move on its last tick",
                r.pg_candidates_last_tick,
            ),
            (
                "objectio_rebalance_last_sweep_timestamp_seconds",
                "gauge",
                "When the balancer last ran",
                r.last_sweep_at,
            ),
        ] {
            gauge(&mut out, name, kind, help, &one(v));
        }
    }
    out
}

/// Whether `/metrics` carries the OSDs' and meta's metrics too.
static REEXPORT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Stop re-exporting OSD and meta metrics (`--no-reexport-metrics`): for
/// deployments that scrape every OSD and meta node directly, and with
/// several gateways, where each would otherwise export a copy of them all.
pub fn set_reexport(on: bool) {
    REEXPORT.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// The full `/metrics` body: the gateway's own families, the poll's, and
/// (unless turned off) the merged OSD and meta expositions.
#[must_use]
pub fn render_metrics() -> String {
    let mut base = s3_metrics().export_prometheus();
    base.push_str(&objectio_common::process_metrics::render(""));
    base.push_str(&crate::gateway_metrics::render());
    // Components running in this process (aio's block gateway).
    base.push_str(&objectio_common::metrics_registry::render_registered());

    let Ok(s) = SNAPSHOT.read() else {
        return base;
    };
    base.push_str(&render_local(&s));
    if !REEXPORT.load(std::sync::atomic::Ordering::Relaxed) {
        return base;
    }

    let own = objectio_common::process_metrics::instance_id();
    let mut sources: Vec<Source<'_>> = s
        .osd_metrics
        .iter()
        .map(|(id, m)| Source {
            text: &m.text,
            inject: Some(("osd_id", id.as_str())),
            drop_process: m.process_instance == own,
        })
        .collect();
    if let Some(m) = &s.meta_metrics {
        sources.push(Source {
            text: &m.text,
            inject: Some(("component", "meta")),
            // Every service renders build info; the gateway's describes
            // the same binary when they share a process.
            drop_process: m.process_instance == own,
        });
    }
    metrics_merge::merge(&base, &sources, &|name| {
        // The block exporter's cluster-wide gauges are one OSD's view of
        // the cluster; next to the gateway's real totals they mislead.
        name.starts_with("objectio_cluster_")
    })
}

// ---------------------------------------------------------------------------
// Readiness
// ---------------------------------------------------------------------------

/// How often readiness is re-checked while the gateway is starting.
const READY_POLL: Duration = Duration::from_secs(1);

#[derive(Default, Clone, Copy)]
struct Readiness {
    ready: bool,
    osds_reachable: usize,
    osds_registered: usize,
    /// Write quorum: the default scheme's data shards.
    osds_required: usize,
    meta_reachable: bool,
    /// Ready without every registered OSD, after [`DEGRADED_GRACE`].
    degraded: bool,
}

/// How long to wait for the last OSDs once a write quorum is reachable.
/// A write fails if *any* OSD in its placement is down (its metadata goes
/// to all of them), so startup waits for all of them — but not forever: a
/// disk that is simply dead must not keep the gateway out of service.
const DEGRADED_GRACE: Duration = Duration::from_secs(30);

static READINESS: LazyLock<RwLock<Readiness>> = LazyLock::new(|| RwLock::new(Readiness::default()));

/// OSDs a write needs to reach: the default scheme's data shards (k), the
/// write quorum. 1 for replication or before the scheme is known.
fn osds_required() -> usize {
    s3_metrics()
        .protection_config()
        .map_or(1, |p| p.data_shards.max(1) as usize)
}

/// (reachable, registered) OSDs: those meta lists and that answer a status
/// call now *as the
/// node meta says lives there*, out of all it lists. An address can be answered by some other
/// OSD — a reused pod IP, or on one host an OSD port another process took
/// first — and writes sent to it fail, so an answer from the wrong node
/// does not count.
async fn reachable_osds(mut meta: MetaClient) -> Option<(usize, usize)> {
    let nodes = timed(meta.get_listing_nodes(GetListingNodesRequest {
        bucket: String::new(),
        include_all_states: false,
    }))
    .await?
    .into_inner()
    .nodes;
    let mut seen = HashSet::new();
    let nodes: Vec<_> = nodes
        .into_iter()
        .filter(|n| seen.insert(n.address.clone()))
        .collect();
    let registered = nodes.len();
    let probes = nodes.into_iter().map(|n| async move {
        let endpoint = if n.address.starts_with("http") {
            n.address
        } else {
            format!("http://{}", n.address)
        };
        let expected = n.node_id;
        let probe = async {
            let mut c = StorageServiceClient::connect(endpoint).await.ok()?;
            c.get_status(GetStatusRequest::default()).await.ok()
        };
        tokio::time::timeout(Duration::from_secs(3), probe)
            .await
            .ok()
            .flatten()
            .is_some_and(|r| r.into_inner().node_id == expected)
    });
    let reachable = futures::future::join_all(probes)
        .await
        .into_iter()
        .filter(|up| *up)
        .count();
    Some((reachable, registered))
}

/// Check once a second until meta answers and every registered OSD is
/// reachable — or, after [`DEGRADED_GRACE`] with a write quorum reachable,
/// the ones that are — then latch ready.
///
/// Latched on purpose: this is a startup gate. Were `/_ready` to drop when
/// OSDs go away later, every gateway would leave the load balancer at
/// once and reads that degraded EC could still serve would fail too.
/// Losing OSDs after start is what `objectio_cluster_osds_up` and
/// `objectio_objects_degraded` are for.
pub fn spawn_readiness(meta: MetaClient) {
    tokio::spawn(async move {
        let mut quorum_since: Option<Instant> = None;
        loop {
            let required = osds_required();
            let probe = reachable_osds(meta.clone()).await;
            let (reachable, registered) = probe.unwrap_or((0, 0));
            let quorum = reachable >= required;
            if !quorum {
                quorum_since = None;
            } else if quorum_since.is_none() {
                quorum_since = Some(Instant::now());
            }
            let all = quorum && reachable >= registered;
            let degraded = !all && quorum_since.is_some_and(|t| t.elapsed() >= DEGRADED_GRACE);
            let state = Readiness {
                ready: all || degraded,
                osds_reachable: reachable,
                osds_registered: registered,
                osds_required: required,
                meta_reachable: probe.is_some(),
                degraded,
            };
            if let Ok(mut r) = READINESS.write() {
                *r = state;
            }
            if state.ready {
                if degraded {
                    tracing::warn!(
                        "gateway ready without every OSD: {reachable} of {registered} reachable \
                         after {}s; writes placed on the others will fail until they return",
                        DEGRADED_GRACE.as_secs()
                    );
                } else {
                    tracing::info!("gateway ready: all {registered} OSDs reachable");
                }
                return;
            }
            tokio::time::sleep(READY_POLL).await;
        }
    });
}

/// Whether the gateway can serve writes yet.
#[must_use]
pub fn is_ready() -> bool {
    READINESS.read().is_ok_and(|r| r.ready)
}

/// `GET /_ready`: 200 once the gateway can serve writes, 503 with the
/// reason until then. Unauthenticated, like `/health`, and named so it
/// cannot shadow a bucket (bucket names cannot contain `_`).
pub async fn ready_handler() -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let r = READINESS.read().map(|r| *r).unwrap_or_default();
    let body = serde_json::json!({
        "status": match (r.ready, r.degraded) {
            (true, false) => "ready",
            (true, true) => "ready_degraded",
            _ => "starting",
        },
        "meta_reachable": r.meta_reachable,
        "osds_reachable": r.osds_reachable,
        "osds_registered": r.osds_registered,
        "osds_required": r.osds_required,
    });
    let code = if r.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, axum::Json(body)).into_response()
}
