//! The audit stream: one event per request — who, from where, what, and
//! how it ended — delivered to the operator's targets and to each tenant's.
//!
//! ## What an event records
//!
//! The request ID (also sent back as `x-amz-request-id` and in error
//! bodies), the time, the listener's endpoint name and the client's
//! address; the principal (user, ARN, access key, tenant, how it
//! authenticated); the action as policies name it (`s3:GetObject`), the
//! bucket, key and version; the HTTP status and S3 error code; bytes in and
//! out; the duration to the last byte; and whether the response body was
//! sent in full (a client that hangs up mid-download shows as incomplete).
//! Secrets never appear: no `Authorization` header, and the signature and
//! credential parameters of a presigned URL are removed from the query.
//!
//! ## Where events go
//!
//! - `--audit-log <path>` (or `-` for stdout): a JSON-lines file every event
//!   is appended to. A file is a host path, so it is set only on the command
//!   line — never through the API, where it would let an API admin write
//!   files on the gateway's host.
//! - The operator's targets (`/_admin/audit`, system admin): `stdout` and
//!   `webhook`. Every event.
//! - A tenant's targets (`/_admin/audit?tenant=`, its admin): `webhook`
//!   only, `https` only, and only to hosts the operator lists in
//!   `allowed_tenant_hosts` — otherwise a tenant could point the gateway at
//!   addresses inside the cluster. A tenant gets the events on its buckets
//!   and by its principals.
//!
//! ## Delivery
//!
//! Events are queued in memory and delivered at least once: a webhook batch
//! is retried with backoff until it is taken, so a receiver may see an event
//! twice (dedupe on `id`). Each target has a bounded queue; when it is full
//! — the receiver has been down a long time — new events for it are dropped
//! and counted (`objectio_audit_dropped_total`), never silently, and the
//! request itself is never held up or refused.

use std::collections::HashMap;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{Extension, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use http_body::{Body as HttpBody, Frame, SizeHint};
use objectio_auth::AuthResult;
use objectio_common::histogram::CounterVec;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::metadata::{
    DeleteConfigRequest, GetConfigRequest, ListConfigRequest, SetConfigRequest,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, watch};
use tonic::transport::Channel;
use tracing::{debug, warn};

use crate::s3::AppState;

const CLUSTER_KEY: &str = "audit/cluster";
const TENANT_PREFIX: &str = "audit/tenant/";
const REDACTED: &str = "********";
/// Events waiting for the dispatcher. Past this, events are dropped and
/// counted rather than holding up requests.
const INGEST_QUEUE: usize = 65_536;
const DEFAULT_TARGET_QUEUE: usize = 10_000;
const DEFAULT_BATCH: usize = 500;
const DEFAULT_FLUSH_MS: u64 = 2_000;
const RELOAD_EVERY: Duration = Duration::from_secs(10);

static EVENTS: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static DROPPED: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static FAILURES: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);

/// The audit metrics, for `/metrics`.
pub fn render_metrics(out: &mut String) {
    EVENTS.render(
        out,
        "objectio_audit_events_total",
        "Audit events delivered, by target",
    );
    DROPPED.render(
        out,
        "objectio_audit_dropped_total",
        "Audit events dropped because a queue was full, by target",
    );
    FAILURES.render(
        out,
        "objectio_audit_delivery_failures_total",
        "Failed attempts to deliver a batch of audit events, by target",
    );
}

fn label(target: &str) -> String {
    format!(
        "target=\"{}\"",
        objectio_common::histogram::label_value(target)
    )
}

// ── The event ───────────────────────────────────────────────────────────

/// One request, as the audit stream records it.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    pub version: u32,
    pub id: String,
    /// RFC 3339, UTC, milliseconds.
    pub time: String,
    /// `s3`, `admin`, `console`, `sts`, `iceberg`, `unity`, `delta-sharing`,
    /// or `internal` for what the gateway does on its own (lifecycle).
    pub api: &'static str,
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub query: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// The bucket's tenant, when the request touched a bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket_tenant: Option<String>,
    pub principal: Principal,
    pub source: Source,
    pub status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub duration_ms: u64,
    /// Whether the whole response body went out. False when the client
    /// hung up first.
    pub complete: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Principal {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub arn: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub access_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub tenant: String,
    /// `Permanent`, `Sts`, `AssumedRole`, `Anonymous`, `Console`, or empty
    /// when the request was refused before an identity was established.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub auth: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Source {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user_agent: String,
}

impl AuditEvent {
    const fn is_read(&self) -> bool {
        matches!(self.method.as_bytes(), b"GET" | b"HEAD")
    }

    /// The tenants this event belongs to: the bucket's and the caller's.
    fn tenants(&self) -> Vec<&str> {
        let mut out = Vec::with_capacity(2);
        if let Some(t) = self.bucket_tenant.as_deref().filter(|t| !t.is_empty()) {
            out.push(t);
        }
        let own = self.principal.tenant.as_str();
        if !own.is_empty() && !out.contains(&own) {
            out.push(own);
        }
        out
    }
}

// ── What inner layers note about the request ────────────────────────────

#[derive(Default)]
struct Noted {
    principal: Principal,
    action: Option<String>,
    bucket: Option<String>,
    key: Option<String>,
    bucket_tenant: Option<String>,
}

struct Current {
    id: String,
    noted: Mutex<Noted>,
}

tokio::task_local! {
    static CURRENT: Arc<Current>;
}

/// The ID of the request being served, if it is being audited.
#[must_use]
pub fn request_id() -> Option<String> {
    CURRENT.try_with(|c| c.id.clone()).ok()
}

fn note(f: impl FnOnce(&mut Noted)) {
    let _ = CURRENT.try_with(|c| f(&mut c.noted.lock()));
}

/// Attach an identity to the request, and record it for the audit event.
/// Every auth layer puts its result on the request through here.
pub fn attach(request: &mut Request, auth: AuthResult) {
    note_identity(&auth);
    request.extensions_mut().insert(auth);
}

/// Record the request's identity.
pub fn note_identity(auth: &AuthResult) {
    note(|n| {
        n.principal = Principal {
            user_id: auth.user_id.clone(),
            arn: auth.user_arn.clone(),
            access_key: auth.access_key_id.clone(),
            tenant: auth.tenant.clone(),
            auth: auth.auth_mode.as_str().to_string(),
        };
    });
}

/// Record what the request acts on, as authorization classifies it.
pub fn note_target(action: &str, bucket: &str, key: Option<&str>) {
    note(|n| {
        n.action = Some(action.to_string());
        if !bucket.is_empty() {
            n.bucket = Some(bucket.to_string());
        }
        n.key = key.map(str::to_string);
    });
}

/// Record the tenant of the request's own bucket (not of another bucket a
/// handler checks, such as a copy's source).
pub fn note_bucket_tenant(bucket: &str, tenant: &str) {
    note(|n| {
        if n.bucket.as_deref() == Some(bucket) && n.bucket_tenant.is_none() {
            n.bucket_tenant = Some(tenant.to_string());
        }
    });
}

/// Record just the action (STS, which has no bucket).
pub fn note_action(action: &str) {
    note(|n| n.action = Some(action.to_string()));
}

// ── Configuration ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Target {
    Stdout {
        #[serde(default = "stdout_name")]
        name: String,
    },
    Webhook(Webhook),
}

fn stdout_name() -> String {
    "stdout".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Webhook {
    pub name: String,
    pub url: String,
    /// Sent as `Authorization: Bearer <token>`. Read back as `********`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub auth_token: String,
    #[serde(default)]
    pub batch_size: usize,
    #[serde(default)]
    pub flush_ms: u64,
    #[serde(default)]
    pub queue_size: usize,
}

impl Target {
    fn name(&self) -> &str {
        match self {
            Self::Stdout { name } => name,
            Self::Webhook(w) => &w.name,
        }
    }
}

const fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterAudit {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "yes")]
    pub include_reads: bool,
    #[serde(default)]
    pub targets: Vec<Target>,
    /// Hosts tenants may send their events to (`host`, `host:port`, or
    /// `*.domain`). Empty: tenants can't configure targets.
    #[serde(default)]
    pub allowed_tenant_hosts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantAudit {
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "yes")]
    pub include_reads: bool,
    #[serde(default)]
    pub targets: Vec<Webhook>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Config {
    cluster: Option<ClusterAudit>,
    tenants: HashMap<String, TenantAudit>,
}

/// Whether `url` is an https URL to a host the operator allows tenants.
fn tenant_url_allowed(url: &str, allowed: &[String]) -> Result<(), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or("a tenant's webhook must be https")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err("credentials in the URL are not allowed; use auth_token".into());
    }
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
    let ok = allowed.iter().any(|pattern| {
        let pattern = pattern.trim().to_ascii_lowercase();
        let (authority, host) = (authority.to_ascii_lowercase(), host.to_ascii_lowercase());
        if let Some(domain) = pattern.strip_prefix("*.") {
            host.ends_with(&format!(".{domain}"))
        } else {
            pattern == authority || pattern == host
        }
    });
    if ok {
        Ok(())
    } else {
        Err(format!(
            "{host} is not among the hosts the operator allows for tenant audit targets"
        ))
    }
}

// ── The auditor ─────────────────────────────────────────────────────────

/// Collects events from requests and hands them to the dispatcher.
pub struct Auditor {
    tx: mpsc::Sender<AuditEvent>,
    /// Whether any target is listening. When none is, requests still get
    /// an ID but no event is built.
    active: Arc<AtomicBool>,
    reload: tokio::sync::Notify,
    trusted_proxies: crate::origin::TrustedProxies,
}

impl Auditor {
    /// Start the dispatcher, the config reloader and, with `log`, the
    /// command-line file target.
    #[must_use]
    pub fn start(
        meta: MetadataServiceClient<Channel>,
        log: Option<String>,
        trusted_proxies: crate::origin::TrustedProxies,
    ) -> Arc<Self> {
        let (tx, rx) = mpsc::channel(INGEST_QUEUE);
        let active = Arc::new(AtomicBool::new(log.is_some()));
        let auditor = Arc::new(Self {
            tx,
            active: Arc::clone(&active),
            reload: tokio::sync::Notify::new(),
            trusted_proxies,
        });
        let (cfg_tx, cfg_rx) = watch::channel(Config::default());
        tokio::spawn(reload_loop(Arc::clone(&auditor), meta, cfg_tx));
        tokio::spawn(dispatch(rx, cfg_rx, log, active));
        auditor
    }

    fn submit(&self, event: AuditEvent) {
        if self.tx.try_send(event).is_err() {
            DROPPED.inc(&label("ingest"));
        }
    }

    /// Record something the gateway did on its own (lifecycle), as the
    /// request it stands for.
    pub fn record_internal(&self, a: InternalAction<'_>) {
        if !self.active.load(Ordering::Relaxed) {
            return;
        }
        self.submit(AuditEvent {
            version: 1,
            id: uuid::Uuid::new_v4().simple().to_string().to_uppercase(),
            time: now_rfc3339(),
            api: "internal",
            method: a.method.to_string(),
            path: format!("/{}/{}", a.bucket, a.key.unwrap_or_default()),
            query: a
                .version_id
                .map(|v| format!("versionId={v}"))
                .unwrap_or_default(),
            action: Some(a.action.to_string()),
            bucket: Some(a.bucket.to_string()),
            key: a.key.map(str::to_string),
            bucket_tenant: Some(a.bucket_tenant.to_string()),
            principal: Principal {
                arn: a.principal,
                auth: a.auth.to_string(),
                ..Principal::default()
            },
            source: Source::default(),
            status: a.status,
            error_code: None,
            request_bytes: 0,
            response_bytes: 0,
            duration_ms: 0,
            complete: true,
        });
    }

    /// Re-read the configuration now (after this gateway changed it).
    pub fn reload_now(&self) {
        self.reload.notify_one();
    }
}

async fn load_config(meta: &mut MetadataServiceClient<Channel>) -> Option<Config> {
    let cluster = match meta
        .get_config(GetConfigRequest {
            key: CLUSTER_KEY.to_string(),
        })
        .await
    {
        Ok(r) => r
            .into_inner()
            .entry
            .and_then(|e| serde_json::from_slice::<ClusterAudit>(&e.value).ok()),
        Err(e) => {
            debug!("audit: config unreadable: {e}");
            return None;
        }
    };
    let tenants = meta
        .list_config(ListConfigRequest {
            prefix: TENANT_PREFIX.to_string(),
        })
        .await
        .ok()?
        .into_inner()
        .entries
        .into_iter()
        .filter_map(|e| {
            let tenant = e.key.strip_prefix(TENANT_PREFIX)?.to_string();
            Some((
                tenant,
                serde_json::from_slice::<TenantAudit>(&e.value).ok()?,
            ))
        })
        .collect();
    Some(Config { cluster, tenants })
}

async fn reload_loop(
    auditor: Arc<Auditor>,
    mut meta: MetadataServiceClient<Channel>,
    cfg_tx: watch::Sender<Config>,
) {
    loop {
        if let Some(cfg) = load_config(&mut meta).await {
            cfg_tx.send_if_modified(|current| {
                let changed = *current != cfg;
                *current = cfg;
                changed
            });
        }
        tokio::select! {
            () = tokio::time::sleep(RELOAD_EVERY) => {}
            () = auditor.reload.notified() => {}
        }
        if cfg_tx.is_closed() {
            return;
        }
    }
}

/// A running target: its queue, and the config it was started with.
struct Running {
    tx: mpsc::Sender<AuditEvent>,
    spec: Target,
}

async fn dispatch(
    mut rx: mpsc::Receiver<AuditEvent>,
    mut cfg_rx: watch::Receiver<Config>,
    log: Option<String>,
    active: Arc<AtomicBool>,
) {
    let log_tx = log.map(|path| {
        let (tx, rx) = mpsc::channel(INGEST_QUEUE);
        tokio::spawn(run_file(path, rx));
        tx
    });
    // Keyed "c/<name>" (the operator's) and "t/<tenant>/<name>".
    let mut running: HashMap<String, Running> = HashMap::new();
    let mut cfg = cfg_rx.borrow().clone();
    loop {
        tokio::select! {
            changed = cfg_rx.changed() => {
                if changed.is_err() { return; }
                cfg = cfg_rx.borrow_and_update().clone();
                reconcile(&mut running, &cfg);
                active.store(log_tx.is_some() || !running.is_empty(), Ordering::Relaxed);
            }
            event = rx.recv() => {
                let Some(event) = event else { return; };
                route(&event, &cfg, &running, log_tx.as_ref());
            }
        }
    }
}

/// Start, restart and stop targets so they match `cfg`.
fn reconcile(running: &mut HashMap<String, Running>, cfg: &Config) {
    let mut wanted: HashMap<String, Target> = HashMap::new();
    if let Some(c) = cfg.cluster.as_ref().filter(|c| c.enabled) {
        for t in &c.targets {
            wanted.insert(format!("c/{}", t.name()), t.clone());
        }
        for (tenant, ta) in &cfg.tenants {
            if !ta.enabled {
                continue;
            }
            for w in &ta.targets {
                // Checked again here: the operator may have narrowed the
                // allowed hosts since the tenant saved it.
                if let Err(e) = tenant_url_allowed(&w.url, &c.allowed_tenant_hosts) {
                    debug!("audit: tenant {tenant} target {}: {e}", w.name);
                    continue;
                }
                wanted.insert(format!("t/{tenant}/{}", w.name), Target::Webhook(w.clone()));
            }
        }
    }
    running.retain(|key, r| wanted.get(key) == Some(&r.spec));
    for (key, spec) in wanted {
        if running.contains_key(&key) {
            continue;
        }
        let (tx, rx) = mpsc::channel(match &spec {
            Target::Webhook(w) if w.queue_size > 0 => w.queue_size,
            _ => DEFAULT_TARGET_QUEUE,
        });
        match &spec {
            Target::Stdout { .. } => {
                tokio::spawn(run_stdout(key.clone(), rx));
            }
            Target::Webhook(w) => {
                tokio::spawn(run_webhook(key.clone(), w.clone(), rx));
            }
        }
        running.insert(key, Running { tx, spec });
    }
}

fn route(
    event: &AuditEvent,
    cfg: &Config,
    running: &HashMap<String, Running>,
    log: Option<&mpsc::Sender<AuditEvent>>,
) {
    let send = |name: &str, tx: &mpsc::Sender<AuditEvent>| {
        if tx.try_send(event.clone()).is_err() {
            DROPPED.inc(&label(name));
        }
    };
    if let Some(tx) = log {
        send("file", tx);
    }
    let Some(cluster) = cfg.cluster.as_ref().filter(|c| c.enabled) else {
        return;
    };
    if cluster.include_reads || !event.is_read() {
        for t in &cluster.targets {
            let key = format!("c/{}", t.name());
            if let Some(r) = running.get(&key) {
                send(&key, &r.tx);
            }
        }
    }
    for tenant in event.tenants() {
        let Some(ta) = cfg.tenants.get(tenant).filter(|t| t.enabled) else {
            continue;
        };
        if !ta.include_reads && event.is_read() {
            continue;
        }
        for w in &ta.targets {
            let key = format!("t/{tenant}/{}", w.name);
            if let Some(r) = running.get(&key) {
                send(&key, &r.tx);
            }
        }
    }
}

/// Up to `max` events: waits for the first, then takes what arrives within
/// `wait`. `None` when the target was stopped.
async fn next_batch(
    rx: &mut mpsc::Receiver<AuditEvent>,
    max: usize,
    wait: Duration,
) -> Option<Vec<AuditEvent>> {
    let first = rx.recv().await?;
    let mut batch = vec![first];
    let deadline = tokio::time::Instant::now() + wait;
    while batch.len() < max {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(e)) => batch.push(e),
            Ok(None) | Err(_) => break,
        }
    }
    Some(batch)
}

fn ndjson(batch: &[AuditEvent]) -> Vec<u8> {
    let mut out = Vec::with_capacity(batch.len() * 512);
    for e in batch {
        if serde_json::to_writer(&mut out, e).is_ok() {
            out.push(b'\n');
        }
    }
    out
}

async fn run_stdout(name: String, mut rx: mpsc::Receiver<AuditEvent>) {
    let mut out = tokio::io::stdout();
    while let Some(batch) = next_batch(&mut rx, DEFAULT_BATCH, Duration::from_millis(200)).await {
        if out.write_all(&ndjson(&batch)).await.is_ok() && out.flush().await.is_ok() {
            EVENTS.add(&label(&name), batch.len() as u64);
        } else {
            FAILURES.inc(&label(&name));
        }
    }
}

/// The command-line target: appended to `path` (`-` for stdout). The file
/// is reopened when it is moved away (log rotation) or a write fails.
async fn run_file(path: String, mut rx: mpsc::Receiver<AuditEvent>) {
    if path == "-" {
        return run_stdout("file".into(), rx).await;
    }
    let open = || async {
        tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
    };
    let mut file = None;
    while let Some(batch) = next_batch(&mut rx, DEFAULT_BATCH, Duration::from_millis(200)).await {
        let data = ndjson(&batch);
        for attempt in 0..2 {
            if file.is_none() || (attempt == 0 && rotated(&path, file.as_ref()).await) {
                file = open()
                    .await
                    .map_err(|e| warn!("audit log {path}: {e}"))
                    .ok();
            }
            let Some(f) = file.as_mut() else { break };
            if f.write_all(&data).await.is_ok() && f.flush().await.is_ok() {
                EVENTS.add(&label("file"), batch.len() as u64);
                break;
            }
            file = None;
            FAILURES.inc(&label("file"));
        }
    }
}

/// Whether the file at `path` is no longer the one open.
async fn rotated(path: &str, open: Option<&tokio::fs::File>) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Some(open) = open else { return true };
        let (Ok(on_disk), Ok(held)) = (tokio::fs::metadata(path).await, open.metadata().await)
        else {
            return true;
        };
        on_disk.ino() != held.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (path, open);
        false
    }
}

async fn run_webhook(name: String, w: Webhook, mut rx: mpsc::Receiver<AuditEvent>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        // Never follow a redirect: a tenant's allowed host could otherwise
        // bounce events anywhere.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default();
    let max = if w.batch_size == 0 {
        DEFAULT_BATCH
    } else {
        w.batch_size
    };
    let wait = Duration::from_millis(if w.flush_ms == 0 {
        DEFAULT_FLUSH_MS
    } else {
        w.flush_ms
    });
    while let Some(batch) = next_batch(&mut rx, max, wait).await {
        let body = ndjson(&batch);
        let mut backoff = Duration::from_secs(1);
        loop {
            let mut req = client
                .post(&w.url)
                .header("Content-Type", "application/x-ndjson")
                .body(body.clone());
            if !w.auth_token.is_empty() {
                req = req.bearer_auth(&w.auth_token);
            }
            match req.send().await {
                Ok(r) if r.status().is_success() => {
                    EVENTS.add(&label(&name), batch.len() as u64);
                    break;
                }
                Ok(r) => warn!("audit target {name}: {} from {}", r.status(), w.url),
                Err(e) => warn!("audit target {name}: {e}"),
            }
            FAILURES.inc(&label(&name));
            if rx.is_closed() {
                // Stopped (reconfigured or removed): don't retry forever.
                return;
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }
}

/// An action the gateway took on its own, for [`Auditor::record_internal`].
pub struct InternalAction<'a> {
    /// Who, e.g. `lifecycle:<rule id>`.
    pub principal: String,
    pub auth: &'static str,
    pub method: &'static str,
    pub action: &'static str,
    pub bucket: &'a str,
    pub bucket_tenant: &'a str,
    pub key: Option<&'a str>,
    pub version_id: Option<&'a str>,
    pub status: u16,
}

// ── The middleware ──────────────────────────────────────────────────────

fn api_of(method: &axum::http::Method, path: &str, headers: &HeaderMap) -> &'static str {
    if path.starts_with("/_admin") {
        "admin"
    } else if path.starts_with("/_console") {
        "console"
    } else if path.starts_with("/iceberg") {
        "iceberg"
    } else if path.starts_with("/api/2.1/unity-catalog") {
        "unity"
    } else if path.starts_with("/delta-sharing") {
        "delta-sharing"
    } else if method == axum::http::Method::POST
        && path == "/"
        && !headers.contains_key(axum::http::header::AUTHORIZATION)
    {
        "sts"
    } else {
        "s3"
    }
}

/// Whether a request is worth an event: not probes, metrics scrapes, or the
/// console's static files.
fn audited(path: &str) -> bool {
    !(path == "/health"
        || path == "/_ready"
        || path == "/_status"
        || path == "/metrics"
        || (path.starts_with("/_console") && !path.starts_with("/_console/api/")))
}

/// The query without credentials: a presigned URL's signature, credential
/// and session token.
fn redact_query(query: &str) -> String {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let name = pair.split('=').next().unwrap_or_default();
            if matches!(
                name.to_ascii_lowercase().as_str(),
                "x-amz-signature"
                    | "x-amz-credential"
                    | "x-amz-security-token"
                    | "signature"
                    | "awsaccesskeyid"
                    | "webidentitytoken"
            ) {
                format!("{name}={REDACTED}")
            } else {
                pair.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn now_rfc3339() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    chrono::DateTime::from_timestamp_millis(i64::try_from(now.as_millis()).unwrap_or(0))
        .map(|t| t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string())
        .unwrap_or_default()
}

/// Audit every request through this layer. Outermost on each listener.
pub async fn audit_layer(
    State(auditor): State<Arc<Auditor>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    if !audited(&path) {
        return next.run(request).await;
    }
    let started = Instant::now();
    let id = uuid::Uuid::new_v4().simple().to_string().to_uppercase();
    let method = request.method().clone();
    let headers = request.headers();
    let api = api_of(&method, &path, headers);
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    };
    let user_agent = header("user-agent");
    let request_bytes = header("content-length").parse().unwrap_or(0);
    let session = crate::console_auth::validate_session_from_headers(headers);
    let source = Source {
        ip: request
            .extensions()
            .get::<crate::origin::ClientAddr>()
            .map(|c| auditor.trusted_proxies.client_ip(c.0.ip(), headers)),
        endpoint: request
            .extensions()
            .get::<crate::origin::Endpoint>()
            .and_then(|e| e.0.clone()),
        user_agent,
    };
    let query = redact_query(request.uri().query().unwrap_or_default());

    let current = Arc::new(Current {
        id: id.clone(),
        noted: Mutex::new(Noted::default()),
    });
    let mut response = CURRENT.scope(Arc::clone(&current), next.run(request)).await;

    if let Ok(v) = HeaderValue::from_str(&id) {
        response
            .headers_mut()
            .entry("x-amz-request-id")
            .or_insert(v);
    }
    if !auditor.active.load(Ordering::Relaxed) {
        return response;
    }
    let status = response.status().as_u16();
    let error_code = response
        .extensions()
        .get::<crate::gateway_metrics::S3ErrorCode>()
        .map(|c| c.0.clone());

    let noted = std::mem::take(&mut *current.noted.lock());
    let mut principal = noted.principal;
    if principal.auth.is_empty()
        && let Some(s) = session
    {
        principal = Principal {
            user_id: s.user,
            arn: String::new(),
            access_key: s.access_key,
            tenant: s.tenant,
            auth: "Console".to_string(),
        };
    }
    let event = AuditEvent {
        version: 1,
        id,
        time: now_rfc3339(),
        api,
        method: method.to_string(),
        path,
        query,
        action: noted.action,
        bucket: noted.bucket,
        key: noted.key,
        bucket_tenant: noted.bucket_tenant,
        principal,
        source,
        status,
        error_code,
        request_bytes,
        response_bytes: 0,
        duration_ms: 0,
        complete: false,
    };
    let (parts, body) = response.into_parts();
    Response::from_parts(
        parts,
        Body::new(Counted {
            inner: body,
            bytes: AtomicU64::new(0),
            done: AtomicBool::new(false),
            pending: Some((event, auditor, started)),
        }),
    )
}

/// A response body that counts what it sends and submits the event when
/// it ends — or is dropped unfinished, when the client hangs up.
struct Counted {
    inner: Body,
    bytes: AtomicU64,
    done: AtomicBool,
    pending: Option<(AuditEvent, Arc<Auditor>, Instant)>,
}

impl Counted {
    fn finish(&mut self, complete: bool) {
        if let Some((mut event, auditor, started)) = self.pending.take() {
            event.response_bytes = self.bytes.load(Ordering::Relaxed);
            event.duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            event.complete = complete;
            auditor.submit(event);
        }
    }
}

impl HttpBody for Counted {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                if self.inner.is_end_stream() {
                    self.done.store(true, Ordering::Relaxed);
                    self.finish(true);
                }
            }
            Poll::Ready(None) => {
                self.done.store(true, Ordering::Relaxed);
                self.finish(true);
            }
            Poll::Ready(Some(Err(_))) => self.finish(false),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for Counted {
    fn drop(&mut self) {
        // An empty body may never be polled; it is complete all the same.
        let complete = self.done.load(Ordering::Relaxed) || self.inner.is_end_stream();
        self.finish(complete);
    }
}

// ── Admin API ───────────────────────────────────────────────────────────

fn admin_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn config_key(tenant: &str) -> String {
    if tenant.is_empty() {
        CLUSTER_KEY.to_string()
    } else {
        format!("{TENANT_PREFIX}{tenant}")
    }
}

async fn stored(state: &AppState, key: &str) -> Option<serde_json::Value> {
    state
        .meta_client
        .clone()
        .get_config(GetConfigRequest {
            key: key.to_string(),
        })
        .await
        .ok()?
        .into_inner()
        .entry
        .and_then(|e| serde_json::from_slice(&e.value).ok())
}

/// Every webhook's token read back as `********`.
fn redact_tokens(mut doc: serde_json::Value) -> serde_json::Value {
    if let Some(targets) = doc.get_mut("targets").and_then(|t| t.as_array_mut()) {
        for t in targets {
            if t.get("auth_token")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.is_empty())
            {
                t["auth_token"] = json!(REDACTED);
            }
        }
    }
    doc
}

/// Tokens written back as read (`********`) keep the stored ones, matched
/// by target name.
fn keep_stored_tokens(new: &mut serde_json::Value, stored: Option<&serde_json::Value>) {
    let stored_tokens: HashMap<String, String> = stored
        .and_then(|s| s.get("targets"))
        .and_then(|t| t.as_array())
        .map(|ts| {
            ts.iter()
                .filter_map(|t| {
                    Some((
                        t.get("name")?.as_str()?.to_string(),
                        t.get("auth_token")?.as_str()?.to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(targets) = new.get_mut("targets").and_then(|t| t.as_array_mut()) {
        for t in targets {
            if t.get("auth_token").and_then(|v| v.as_str()) == Some(REDACTED) {
                let name = t.get("name").and_then(|n| n.as_str()).unwrap_or_default();
                t["auth_token"] = json!(stored_tokens.get(name).cloned().unwrap_or_default());
            }
        }
    }
}

/// `GET /_admin/audit[?tenant=]`: the cluster's audit configuration
/// (system admin) or a tenant's (its admin, or the system admin naming it).
pub async fn admin_get(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let admin = match crate::iam_admin::admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    let key = config_key(&admin.tenant);
    match stored(&state, &key).await {
        Some(doc) => {
            let mut doc = redact_tokens(doc);
            doc["tenant"] = json!(admin.tenant);
            Json(doc).into_response()
        }
        None => admin_error(StatusCode::NOT_FOUND, "no audit configuration"),
    }
}

/// `PUT /_admin/audit[?tenant=]`: replace the cluster's (system admin) or a
/// tenant's audit configuration.
pub async fn admin_put(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
    body: Bytes,
) -> Response {
    let admin = match crate::iam_admin::admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    let Ok(mut doc) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return admin_error(StatusCode::BAD_REQUEST, "invalid JSON");
    };
    if let Some(obj) = doc.as_object_mut() {
        obj.remove("tenant");
    }
    let key = config_key(&admin.tenant);
    keep_stored_tokens(&mut doc, stored(&state, &key).await.as_ref());

    let names: Vec<String>;
    if admin.tenant.is_empty() {
        let cfg: ClusterAudit = match serde_json::from_value(doc.clone()) {
            Ok(c) => c,
            Err(e) => {
                return admin_error(
                    StatusCode::BAD_REQUEST,
                    &format!("invalid configuration: {e}"),
                );
            }
        };
        names = cfg.targets.iter().map(|t| t.name().to_string()).collect();
        for t in &cfg.targets {
            if let Target::Webhook(w) = t
                && !(w.url.starts_with("https://") || w.url.starts_with("http://"))
            {
                return admin_error(StatusCode::BAD_REQUEST, "a webhook url must be http(s)");
            }
        }
    } else {
        let cfg: TenantAudit = match serde_json::from_value(doc.clone()) {
            Ok(c) => c,
            Err(e) => {
                return admin_error(
                    StatusCode::BAD_REQUEST,
                    &format!("invalid configuration: {e}"),
                );
            }
        };
        let allowed = stored(&state, CLUSTER_KEY)
            .await
            .and_then(|d| serde_json::from_value::<ClusterAudit>(d).ok())
            .map(|c| c.allowed_tenant_hosts)
            .unwrap_or_default();
        for w in &cfg.targets {
            if let Err(e) = tenant_url_allowed(&w.url, &allowed) {
                return admin_error(StatusCode::BAD_REQUEST, &e);
            }
        }
        names = cfg.targets.iter().map(|w| w.name.clone()).collect();
    }
    let mut seen = std::collections::HashSet::new();
    if names
        .iter()
        .any(|n| n.is_empty() || n.contains('/') || !seen.insert(n))
    {
        return admin_error(
            StatusCode::BAD_REQUEST,
            "target names must be unique, non-empty, without '/'",
        );
    }

    let updated_by = auth
        .as_ref()
        .map(|Extension(a)| a.user_id.clone())
        .unwrap_or_default();
    match state
        .meta_client
        .clone()
        .set_config(SetConfigRequest {
            key,
            value: doc.to_string().into_bytes(),
            updated_by,
        })
        .await
    {
        Ok(_) => {
            state.auditor.reload_now();
            let mut out = redact_tokens(doc);
            out["tenant"] = json!(admin.tenant);
            Json(out).into_response()
        }
        Err(e) => admin_error(StatusCode::INTERNAL_SERVER_ERROR, e.message()),
    }
}

/// `DELETE /_admin/audit[?tenant=]`
pub async fn admin_delete(
    State(state): State<Arc<AppState>>,
    auth: Option<Extension<AuthResult>>,
    headers: HeaderMap,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let admin = match crate::iam_admin::admin_in(
        &state,
        &auth,
        &headers,
        params.get("tenant").map(String::as_str),
    )
    .await
    {
        Ok(a) => a,
        Err(r) => return r,
    };
    match state
        .meta_client
        .clone()
        .delete_config(DeleteConfigRequest {
            key: config_key(&admin.tenant),
        })
        .await
    {
        Ok(_) => {
            state.auditor.reload_now();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => admin_error(StatusCode::INTERNAL_SERVER_ERROR, e.message()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tenant_target_must_be_https_to_an_allowed_host() {
        let allowed = vec![
            "siem.acme.example".to_string(),
            "*.logs.example".to_string(),
        ];
        assert!(tenant_url_allowed("https://siem.acme.example/ingest", &allowed).is_ok());
        assert!(tenant_url_allowed("https://siem.acme.example:8443/x", &allowed).is_ok());
        assert!(tenant_url_allowed("https://a.logs.example/x", &allowed).is_ok());
        // Not https, not allowed, a lookalike, a userinfo trick.
        assert!(tenant_url_allowed("http://siem.acme.example/x", &allowed).is_err());
        assert!(tenant_url_allowed("https://10.0.0.1/x", &allowed).is_err());
        assert!(tenant_url_allowed("https://logs.example/x", &allowed).is_err());
        assert!(tenant_url_allowed("https://evilsiem.acme.example/x", &allowed).is_err());
        assert!(tenant_url_allowed("https://siem.acme.example@10.0.0.1/x", &allowed).is_err());
        assert!(tenant_url_allowed("https://siem.acme.example/x", &[]).is_err());
    }

    #[test]
    fn credentials_never_reach_the_query_log() {
        let q = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA%2F2026&X-Amz-Signature=abc\
                 &X-Amz-Security-Token=tok&versionId=v1";
        let r = redact_query(q);
        assert!(
            !r.contains("AKIA") && !r.contains("abc") && !r.contains("tok"),
            "{r}"
        );
        assert!(r.contains("versionId=v1") && r.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
    }

    #[test]
    fn tokens_read_back_redacted_keep_the_stored_ones() {
        let stored = json!({"targets": [{"type": "webhook", "name": "siem", "url": "https://x", "auth_token": "s3cret"}]});
        let read = redact_tokens(stored.clone());
        assert_eq!(read["targets"][0]["auth_token"], REDACTED);
        let mut back = read;
        keep_stored_tokens(&mut back, Some(&stored));
        assert_eq!(back["targets"][0]["auth_token"], "s3cret");
    }

    #[test]
    fn an_event_belongs_to_the_buckets_tenant_and_the_callers() {
        let mut e = AuditEvent {
            version: 1,
            id: String::new(),
            time: String::new(),
            api: "s3",
            method: "GET".into(),
            path: "/b/k".into(),
            query: String::new(),
            action: None,
            bucket: Some("b".into()),
            key: None,
            bucket_tenant: Some("acme".into()),
            principal: Principal {
                tenant: "acme".into(),
                ..Principal::default()
            },
            source: Source::default(),
            status: 200,
            error_code: None,
            request_bytes: 0,
            response_bytes: 0,
            duration_ms: 0,
            complete: true,
        };
        assert_eq!(e.tenants(), vec!["acme"]);
        e.principal.tenant = String::new();
        e.bucket_tenant = Some("globex".into());
        assert_eq!(e.tenants(), vec!["globex"]);
        assert!(e.is_read());
    }

    fn event(method: &str, bucket_tenant: &str, caller_tenant: &str) -> AuditEvent {
        AuditEvent {
            version: 1,
            id: String::new(),
            time: String::new(),
            api: "s3",
            method: method.into(),
            path: String::new(),
            query: String::new(),
            action: None,
            bucket: None,
            key: None,
            bucket_tenant: Some(bucket_tenant.into()),
            principal: Principal {
                tenant: caller_tenant.into(),
                ..Principal::default()
            },
            source: Source::default(),
            status: 200,
            error_code: None,
            request_bytes: 0,
            response_bytes: 0,
            duration_ms: 0,
            complete: true,
        }
    }

    #[tokio::test]
    async fn events_go_to_the_operator_and_to_their_tenants_only() {
        let hook = |name: &str| Webhook {
            name: name.into(),
            url: "https://siem.example/x".into(),
            auth_token: String::new(),
            batch_size: 0,
            flush_ms: 0,
            queue_size: 0,
        };
        let cfg = Config {
            cluster: Some(ClusterAudit {
                enabled: true,
                include_reads: false,
                targets: vec![Target::Webhook(hook("ops"))],
                allowed_tenant_hosts: vec!["siem.example".into()],
            }),
            tenants: HashMap::from([
                (
                    "acme".to_string(),
                    TenantAudit {
                        enabled: true,
                        include_reads: true,
                        targets: vec![hook("a")],
                    },
                ),
                (
                    "globex".to_string(),
                    TenantAudit {
                        enabled: true,
                        include_reads: true,
                        targets: vec![hook("g")],
                    },
                ),
            ]),
        };
        let mut running = HashMap::new();
        let mut rxs = HashMap::new();
        for key in ["c/ops", "t/acme/a", "t/globex/g"] {
            let (tx, rx) = mpsc::channel(10);
            let spec = Target::Webhook(hook(key.rsplit('/').next().unwrap()));
            running.insert(key.to_string(), Running { tx, spec });
            rxs.insert(key, rx);
        }
        route(&event("PUT", "acme", "acme"), &cfg, &running, None);
        route(&event("GET", "acme", ""), &cfg, &running, None);
        let count = |rx: &mut mpsc::Receiver<AuditEvent>| {
            let mut n = 0;
            while rx.try_recv().is_ok() {
                n += 1;
            }
            n
        };
        // The operator: the write only (include_reads is off).
        assert_eq!(count(rxs.get_mut("c/ops").unwrap()), 1);
        // acme: both. globex: nothing of acme's.
        assert_eq!(count(rxs.get_mut("t/acme/a").unwrap()), 2);
        assert_eq!(count(rxs.get_mut("t/globex/g").unwrap()), 0);
        // Disabled at the cluster: no tenant gets anything either.
        let off = Config {
            cluster: cfg.cluster.clone().map(|c| ClusterAudit {
                enabled: false,
                ..c
            }),
            ..cfg.clone()
        };
        route(&event("PUT", "acme", "acme"), &off, &running, None);
        assert_eq!(count(rxs.get_mut("t/acme/a").unwrap()), 0);
    }
}
