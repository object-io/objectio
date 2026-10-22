//! What the gateway lets in, so that its memory stays bounded under any load.
//!
//! Two limits, both answering `503 SlowDown` (with `Retry-After`) when they
//! are reached, rather than queueing without end or running out of memory:
//!
//! - **Requests in flight** (`--max-requests`): a request holds a slot from
//!   the moment it is admitted until its response body has been sent.
//! - **A memory budget** (`--memory-budget`), in bytes: what the gateway
//!   holds of request bodies, and of GET data read ahead of the client. A
//!   request body is reserved in full, from its declared length, before a
//!   byte of it is read — except a large upload's (a PUT or an UploadPart
//!   over [`STREAM_ABOVE`]), which is never held whole: it is streamed to
//!   the shards, and reserves only the stripes it has in hand at once. A
//!   GET reserves each stripe before reading it, and gives it back once the
//!   client has been sent it. A new request that does not fit is refused;
//!   a GET already streaming waits for room for its next stripe (released
//!   bytes go to waiters first).
//!
//! Health, readiness and metrics are never limited: a load balancer has to
//! be able to see an overloaded gateway.
//!
//! The budget counts the bytes requests bring in and take out, not every
//! buffer that handles them (erasure coding's shards, the TCP buffers), so
//! the process uses more than the budget: about half its memory limit is
//! the default.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::middleware::Next;
use axum::response::Response;
use http_body::{Body as HttpBody, Frame, SizeHint};
use objectio_common::histogram::{CounterVec, label_value};
use std::sync::LazyLock;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};

/// The largest request body the S3 API takes other than an upload's (an
/// XML document, a form, a sub-resource's body), all read whole.
pub const MAX_BODY: usize = 100 * 1024 * 1024;

/// The largest body of a single PUT or an UploadPart: S3's 5 GiB. An
/// object of more is uploaded in parts (up to 10,000 of them).
pub const MAX_UPLOAD: u64 = 5 * 1024 * 1024 * 1024;

/// An upload body larger than this, or of a length not known up front, is
/// not read whole: its handler streams it to the shards stripe by stripe.
/// One up to it is read here, as other bodies are: about a stripe of the
/// usual 4+2 code, which an upload holds whole on its way to the shards
/// either way.
pub const STREAM_ABOVE: u64 = 16 * 1024 * 1024;

/// The budget's default when no `--memory-budget` is given and the process
/// has no memory limit of its own.
pub const DEFAULT_MEMORY_BUDGET: u64 = 512 * 1024 * 1024;

/// The smallest budget the gateway runs with.
const MIN_MEMORY_BUDGET: u64 = 16 * 1024 * 1024;

/// Seconds a refused client is asked to wait (`Retry-After`). S3 SDKs back
/// off on `SlowDown` on their own; this is for the others.
const RETRY_AFTER_SECS: u32 = 1;

/// The budget is counted in units of this many bytes, so a semaphore's
/// `u32` permit count can hold budgets of terabytes.
const UNIT: u64 = 1024;

static REJECTED: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static TIMEOUTS: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
static GET_ABORTS: LazyLock<CounterVec> = LazyLock::new(CounterVec::new);
/// The admission of the gateway running in this process, for `/metrics`.
static CURRENT: std::sync::OnceLock<Arc<Admission>> = std::sync::OnceLock::new();

/// A request refused for want of `reason` (`requests` or `memory`).
fn record_rejected(reason: &str) {
    REJECTED.inc(&format!("reason=\"{reason}\""));
}

/// A connection or a request cut off by a timeout: `body` (a request body
/// that stopped arriving) or `send` (a client that stopped reading).
pub fn record_timeout(kind: &str) {
    TIMEOUTS.inc(&format!("kind=\"{kind}\""));
}

/// A GET that had sent its headers and stopped before the end of its body,
/// by why: `read` (a stripe could not be read), `length` (a stripe read
/// back other than its recorded size), `memory` (no room in the budget for
/// the next stripe in time).
pub fn record_get_abort(reason: &str) {
    GET_ABORTS.inc(&format!("reason=\"{}\"", label_value(reason)));
}

/// The admission families, for the gateway's `/metrics`.
pub fn render(out: &mut String) {
    use std::fmt::Write as _;
    if let Some(a) = CURRENT.get() {
        let gauge = |out: &mut String, name: &str, help: &str, v: u64| {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} gauge");
            let _ = writeln!(out, "{name} {v}");
        };
        gauge(
            out,
            "objectio_gateway_memory_budget_bytes",
            "The memory budget for request bodies and GET read-ahead (--memory-budget)",
            a.budget.capacity(),
        );
        gauge(
            out,
            "objectio_gateway_memory_budget_in_use_bytes",
            "Bytes of the memory budget held by requests now",
            a.budget.in_use(),
        );
        gauge(
            out,
            "objectio_gateway_requests_limit",
            "Requests the gateway serves at once (--max-requests)",
            a.max_requests as u64,
        );
        gauge(
            out,
            "objectio_gateway_requests_admitted",
            "Requests admitted and not yet finished, response bodies included",
            a.in_flight(),
        );
    }
    REJECTED.render(
        out,
        "objectio_gateway_requests_rejected_total",
        "Requests refused with 503 SlowDown, by the limit they hit (requests or memory)",
    );
    TIMEOUTS.render(
        out,
        "objectio_gateway_timeouts_total",
        "Requests or connections cut off by a timeout, by kind (body, send)",
    );
    GET_ABORTS.render(
        out,
        "objectio_gateway_get_aborted_total",
        "GETs cut off after their headers were sent, by reason",
    );
}

/// A size such as `512MiB`, `1GiB`, `64M` or `1048576` (bytes).
///
/// # Errors
///
/// When it is not a number with an optional unit.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("{s:?}: expected a size such as 512MiB or 1GiB"))?;
    let mult: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        "t" | "tb" | "tib" => 1 << 40,
        other => return Err(format!("{s:?}: unknown unit {other:?}")),
    };
    n.checked_mul(mult)
        .ok_or_else(|| format!("{s:?}: too large"))
}

/// The memory limit the kernel holds this process to (its cgroup's), if
/// any: what a container's memory limit becomes.
fn cgroup_memory_limit() -> Option<u64> {
    let read = |path: &str| {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
    };
    // cgroup v2: the tightest `memory.max` from the process's own group up
    // ("max" is no limit). In a container the group is the namespace's
    // root, /sys/fs/cgroup itself.
    let own = std::fs::read_to_string("/proc/self/cgroup")
        .ok()
        .and_then(|c| {
            c.lines()
                .find_map(|l| l.strip_prefix("0::").map(str::to_string))
        })
        .unwrap_or_default();
    let mut dir = std::path::PathBuf::from("/sys/fs/cgroup").join(own.trim_start_matches('/'));
    let mut limit: Option<u64> = None;
    loop {
        if let Some(v) = read(&dir.join("memory.max").to_string_lossy()) {
            limit = Some(limit.map_or(v, |l| l.min(v)));
        }
        if dir.as_os_str() == "/sys/fs/cgroup" || !dir.pop() {
            break;
        }
    }
    // cgroup v1, which says "no limit" with a page-rounded i64::MAX.
    let limit = limit.or_else(|| read("/sys/fs/cgroup/memory/memory.limit_in_bytes"))?;
    (limit < 1 << 60).then_some(limit)
}

/// The budget to run with: `--memory-budget` when given, otherwise half the
/// process's memory limit when it has one, otherwise 512 MiB.
#[must_use]
pub fn budget_bytes(flag: Option<u64>) -> u64 {
    let (bytes, from) = match (flag, cgroup_memory_limit()) {
        (Some(b), _) => (b, "--memory-budget"),
        (None, Some(limit)) => (limit / 2, "half the memory limit"),
        (None, None) => (DEFAULT_MEMORY_BUDGET, "the default"),
    };
    let bytes = bytes.max(MIN_MEMORY_BUDGET);
    info!("Memory budget: {} MiB ({from})", bytes >> 20);
    bytes
}

/// A pool of bytes requests reserve from before they hold them.
#[derive(Clone)]
pub struct MemoryBudget {
    sem: Arc<Semaphore>,
    units: u32,
}

impl MemoryBudget {
    #[must_use]
    pub fn new(bytes: u64) -> Self {
        let units = u32::try_from(bytes.div_ceil(UNIT))
            .unwrap_or(u32::MAX)
            .max(1);
        Self {
            sem: Arc::new(Semaphore::new(units as usize)),
            units,
        }
    }

    /// The whole budget, in bytes.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        u64::from(self.units) * UNIT
    }

    /// Bytes reserved now.
    #[must_use]
    pub fn in_use(&self) -> u64 {
        let free = u64::try_from(self.sem.available_permits()).unwrap_or(u64::MAX);
        (u64::from(self.units).saturating_sub(free)) * UNIT
    }

    /// Units for `bytes`: rounded up, and never more than the whole budget,
    /// so that one request larger than the budget still runs (alone).
    fn units_for(&self, bytes: u64) -> u32 {
        u32::try_from(bytes.div_ceil(UNIT))
            .unwrap_or(u32::MAX)
            .min(self.units)
    }

    /// Reserve `bytes` now, or `None` if they are not free.
    #[must_use]
    pub fn try_reserve(&self, bytes: u64) -> Option<Reservation> {
        let units = self.units_for(bytes);
        if units == 0 {
            return Some(Reservation::default());
        }
        let permit = Arc::clone(&self.sem).try_acquire_many_owned(units).ok()?;
        Some(Reservation {
            permit: Some(permit),
        })
    }

    /// Reserve `bytes`, waiting for them to be freed, at most `within`.
    pub async fn reserve(&self, bytes: u64, within: Duration) -> Option<Reservation> {
        let units = self.units_for(bytes);
        if units == 0 {
            return Some(Reservation::default());
        }
        let permit = tokio::time::timeout(within, Arc::clone(&self.sem).acquire_many_owned(units))
            .await
            .ok()?
            .ok()?;
        Some(Reservation {
            permit: Some(permit),
        })
    }
}

/// Bytes of a [`MemoryBudget`], given back when dropped.
#[derive(Default)]
pub struct Reservation {
    permit: Option<OwnedSemaphorePermit>,
}

impl Reservation {
    /// Bytes held.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.permit
            .as_ref()
            .map_or(0, |p| p.num_permits() as u64 * UNIT)
    }

    /// `bytes` of this reservation (rounded up to the budget's unit, and at
    /// most what it holds) as a reservation of their own.
    #[must_use]
    pub fn split(&mut self, bytes: u64) -> Self {
        let want = usize::try_from(bytes.div_ceil(UNIT)).unwrap_or(usize::MAX);
        let Some(p) = self.permit.as_mut() else {
            return Self::default();
        };
        let take = want.min(p.num_permits());
        if take == p.num_permits() {
            return Self {
                permit: self.permit.take(),
            };
        }
        Self {
            permit: p.split(take),
        }
    }

    /// Take `other`, split from this one, back into it.
    pub fn merge(&mut self, other: Self) {
        match (self.permit.as_mut(), other.permit) {
            (Some(p), Some(o)) => p.merge(o),
            (None, o) => self.permit = o,
            (Some(_), None) => {}
        }
    }

    /// Give back all but `bytes` of it (rounded up to the budget's unit).
    pub fn shrink_to(&mut self, bytes: u64) {
        let keep = usize::try_from(bytes.div_ceil(UNIT)).unwrap_or(usize::MAX);
        if let Some(p) = self.permit.as_mut() {
            let held = p.num_permits();
            if keep < held {
                drop(p.split(held - keep));
            }
        }
        if keep == 0 {
            self.permit = None;
        }
    }
}

/// `data`, holding its reservation until the last copy of the bytes is
/// dropped (by the connection, once it has written them).
#[must_use]
pub fn reserved_bytes(data: Vec<u8>, reservation: Reservation) -> Bytes {
    struct Owned(Vec<u8>, #[allow(dead_code)] Reservation);
    impl AsRef<[u8]> for Owned {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }
    if reservation.permit.is_none() {
        return Bytes::from(data);
    }
    Bytes::from_owner(Owned(data, reservation))
}

/// The gateway's limits, and what they have let in.
pub struct Admission {
    pub budget: MemoryBudget,
    requests: Arc<Semaphore>,
    max_requests: usize,
    /// How long a request body may go without sending a byte; also how long
    /// a streaming GET waits for room in the budget for its next stripe.
    pub body_timeout: Duration,
}

impl Admission {
    #[must_use]
    pub fn new(budget_bytes: u64, max_requests: usize, body_timeout: Duration) -> Arc<Self> {
        let max_requests = max_requests.clamp(1, Semaphore::MAX_PERMITS);
        Arc::new(Self {
            budget: MemoryBudget::new(budget_bytes),
            requests: Arc::new(Semaphore::new(max_requests)),
            max_requests,
            body_timeout,
        })
    }

    /// Make this the admission `/metrics` reports (the first one wins).
    pub fn register(self: &Arc<Self>) {
        let _ = CURRENT.set(Arc::clone(self));
    }

    fn in_flight(&self) -> u64 {
        (self
            .max_requests
            .saturating_sub(self.requests.available_permits())) as u64
    }
}

/// `503 SlowDown`, as S3 answers a client to back off, with `Retry-After`.
#[must_use]
pub fn slow_down(reason: &str) -> Response {
    record_rejected(reason);
    let mut resp = crate::s3::S3Error::xml_response(
        "SlowDown",
        "Please reduce your request rate.",
        StatusCode::SERVICE_UNAVAILABLE,
    );
    resp.headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from(RETRY_AFTER_SECS));
    resp
}

/// Paths outside every limit: a probe or a scrape has to get through to an
/// overloaded gateway.
fn exempt(path: &str) -> bool {
    matches!(path, "/health" | "/_ready" | "/metrics")
}

/// A response body that holds `guard` until it has been sent, or dropped.
struct Held<G> {
    inner: Body,
    guard: Option<G>,
}

impl<G: Send + Unpin + 'static> HttpBody for Held<G> {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(polled, Poll::Ready(None | Some(Err(_)))) {
            self.guard = None;
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

fn hold<G: Send + Unpin + 'static>(resp: Response, guard: G) -> Response {
    resp.map(|inner| {
        Body::new(Held {
            inner,
            guard: Some(guard),
        })
    })
}

/// The in-flight limit, outermost on a data listener: a request gets a slot
/// or `503 SlowDown`, and keeps it until its response body is sent.
pub async fn request_layer(
    State(admission): State<Arc<Admission>>,
    request: Request,
    next: Next,
) -> Response {
    if exempt(request.uri().path()) {
        return next.run(request).await;
    }
    let Ok(slot) = Arc::clone(&admission.requests).try_acquire_owned() else {
        debug!(
            "refused {}: {} requests in flight",
            request.uri().path(),
            admission.max_requests
        );
        return slow_down("requests");
    };
    let resp = next.run(request).await;
    hold(resp, slot)
}

/// Whether the request's body is in AWS-chunked framing, which carries more
/// bytes on the wire than the payload it decodes to.
fn aws_chunked(headers: &HeaderMap) -> bool {
    headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("STREAMING-"))
        || headers
            .get(header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("aws-chunked"))
}

/// Whether the path names an object (`/bucket/key`), not a bucket.
fn on_object(path: &str) -> bool {
    path.trim_start_matches('/')
        .split_once('/')
        .is_some_and(|(bucket, key)| !bucket.is_empty() && !key.is_empty())
}

/// Whether the request is an upload, a PutObject or an UploadPart: a PUT
/// to an object that copies nothing and names none of its sub-resources
/// (an ACL, tags, a retention, a legal hold), whose bodies are small
/// documents.
pub(crate) fn is_upload(method: &Method, uri: &Uri, headers: &HeaderMap) -> bool {
    method == Method::PUT
        && on_object(uri.path())
        && !headers.contains_key("x-amz-copy-source")
        && !uri.query().is_some_and(|q| {
            q.split('&').any(|pair| {
                matches!(
                    pair.split('=').next().unwrap_or_default(),
                    "acl" | "tagging" | "retention" | "legal-hold"
                )
            })
        })
}

/// The largest payload the request may carry: [`MAX_UPLOAD`] for an
/// upload, [`MAX_BODY`] for anything else.
pub(crate) fn payload_limit(upload: bool) -> u64 {
    if upload { MAX_UPLOAD } else { MAX_BODY as u64 }
}

/// A request body the handler streams rather than one read whole here: a
/// large upload's (see [`STREAM_ABOVE`]). Its handler reserves from the
/// budget what it holds of it.
#[derive(Clone, Copy, Debug)]
pub struct Streamed;

/// The most wire bytes a body of a payload of at most `max` may have: the
/// payload, and for an AWS-chunked body room for its framing too (SDKs
/// send 64 KiB chunks, about 90 bytes of framing each; AWS's smallest
/// chunk is 8 KiB), and the trailers.
pub(crate) fn wire_limit(chunked: bool, max: u64) -> u64 {
    if chunked {
        max + max / 8 + 64 * 1024
    } else {
        max
    }
}

/// S3's answer to a payload over `max` bytes.
pub(crate) fn entity_too_large(max: u64) -> Response {
    crate::s3::S3Error::xml_response(
        "EntityTooLarge",
        &format!("Your proposed upload exceeds the maximum allowed size of {max} bytes"),
        StatusCode::BAD_REQUEST,
    )
}

fn incomplete_body() -> Response {
    crate::s3::S3Error::xml_response(
        "IncompleteBody",
        "You did not provide the number of bytes specified by the Content-Length HTTP header.",
        StatusCode::BAD_REQUEST,
    )
}

fn request_timeout() -> Response {
    crate::s3::S3Error::xml_response(
        "RequestTimeout",
        "Your socket connection to the server was not read from or written to within the timeout period.",
        StatusCode::BAD_REQUEST,
    )
}

/// Why a body could not be read in full.
#[derive(Debug)]
pub enum BodyError {
    /// More bytes than the limit, which is this many bytes of payload.
    TooLarge(u64),
    /// No bytes for longer than the body timeout.
    Timeout,
    /// The connection failed, or the client ended the body early.
    Read(String),
    /// What the body is read from (an object being copied) failed.
    Source(String),
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge(max) => write!(f, "the body is over {max} bytes"),
            Self::Timeout => f.write_str("no body bytes within the body timeout"),
            Self::Read(e) => write!(f, "the body could not be read: {e}"),
            Self::Source(e) => write!(f, "the body's source could not be read: {e}"),
        }
    }
}

impl std::error::Error for BodyError {}

/// How S3 answers a request whose body failed as it was read: an error a
/// streamed body ended in (this layer's limit or timeout, a broken
/// `aws-chunked` framing or chunk signature, a payload that is not the one
/// signed), whichever it is under `error`'s causes. Anything else is the
/// client's connection failing, `IncompleteBody`.
pub(crate) fn body_refused(error: &(dyn std::error::Error + 'static)) -> Response {
    let mut cause = Some(error);
    while let Some(e) = cause {
        if let Some(b) = e.downcast_ref::<BodyError>() {
            return match b {
                BodyError::TooLarge(max) => entity_too_large(*max),
                BodyError::Timeout => {
                    record_timeout("body");
                    warn!("an upload's body stopped arriving; cut off");
                    request_timeout()
                }
                BodyError::Read(_) => incomplete_body(),
                BodyError::Source(e) => {
                    warn!("a copy's source failed as it was read: {e}");
                    crate::s3::S3Error::xml_response(
                        "InternalError",
                        "Failed to read the source object",
                        StatusCode::INTERNAL_SERVER_ERROR,
                    )
                }
            };
        }
        if let Some(d) = e.downcast_ref::<crate::chunked_decode::DecodeError>() {
            return d.response();
        }
        if e.is::<crate::payload_hash::Mismatch>() {
            return crate::payload_hash::mismatch_response();
        }
        cause = e.source();
    }
    debug!("an upload's body failed: {error}");
    incomplete_body()
}

/// A streamed request body held to the limits a body read whole is: at
/// most `limit` bytes on the wire, and never `idle` without a byte while
/// it is being read. Errors of the body it wraps pass through as they are.
struct LimitedBody {
    inner: Body,
    /// The payload limit, for the refusal.
    max: u64,
    limit: u64,
    read: u64,
    idle: Duration,
    /// Runs only while the reader waits on the client: between reads (the
    /// handler busy with what it has) the client is not late.
    timer: Pin<Box<tokio::time::Sleep>>,
    waiting: bool,
    failed: bool,
}

impl LimitedBody {
    fn new(inner: Body, max: u64, limit: u64, idle: Duration) -> Self {
        Self {
            inner,
            max,
            limit,
            read: 0,
            idle,
            timer: Box::pin(tokio::time::sleep(idle)),
            waiting: false,
            failed: false,
        }
    }
}

impl HttpBody for LimitedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        if this.failed {
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => {
                if !this.waiting {
                    this.waiting = true;
                    let deadline = tokio::time::Instant::now() + this.idle;
                    this.timer.as_mut().reset(deadline);
                }
                if this.timer.as_mut().poll(cx).is_ready() {
                    this.failed = true;
                    return Poll::Ready(Some(Err(axum::Error::new(BodyError::Timeout))));
                }
                Poll::Pending
            }
            Poll::Ready(Some(Ok(frame))) => {
                this.waiting = false;
                if let Some(data) = frame.data_ref() {
                    this.read += data.len() as u64;
                    if this.read > this.limit {
                        this.failed = true;
                        return Poll::Ready(Some(Err(axum::Error::new(BodyError::TooLarge(
                            this.max,
                        )))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.failed || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// Read `body` into one buffer, at most `limit` bytes, each frame within
/// `idle` of the one before. `expected` sizes the buffer up front.
///
/// A body that already is one buffer (a body this layer has read) comes
/// back without a copy.
///
/// # Errors
///
/// [`BodyError`]: too large, too slow, or cut off.
pub async fn body_into_vec(
    body: Body,
    expected: u64,
    limit: u64,
    idle: Option<Duration>,
) -> Result<Vec<u8>, BodyError> {
    let mut body = body;
    let mut out: Option<Vec<u8>> = None;
    loop {
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx));
        let frame = match idle {
            Some(t) => tokio::time::timeout(t, frame)
                .await
                .map_err(|_| BodyError::Timeout)?,
            None => frame.await,
        };
        let Some(frame) = frame else { break };
        let frame = frame.map_err(|e| BodyError::Read(e.to_string()))?;
        let Ok(data) = frame.into_data() else {
            // Trailers: no S3 request carries HTTP trailers (an SDK sends
            // its checksum trailers inside the AWS-chunked body).
            continue;
        };
        let held = out.as_ref().map_or(0, Vec::len) as u64;
        if held + data.len() as u64 > limit {
            return Err(BodyError::TooLarge(limit));
        }
        match out.as_mut() {
            // The first frame: taken over without a copy when it is the
            // only owner of its buffer (the whole body, from this layer).
            None if data.len() as u64 >= expected => out = Some(Vec::from(data)),
            None => {
                let cap = usize::try_from(expected.min(limit)).unwrap_or(0);
                let mut v = Vec::with_capacity(cap.max(data.len()));
                v.extend_from_slice(&data);
                out = Some(v);
            }
            Some(v) => v.extend_from_slice(&data),
        }
    }
    Ok(out.unwrap_or_default())
}

/// Request bodies on the S3 API, after authentication: refused over the
/// limit (`400 EntityTooLarge`, as S3 answers) before a byte is read, then
/// either
///
/// - read in full here into one buffer, its declared length reserved from
///   the memory budget first (or `503 SlowDown`), each part within the body
///   timeout of the last (`400 RequestTimeout`); handlers then take it
///   without another copy; or
/// - for an upload over [`STREAM_ABOVE`] (or of unknown length), handed on
///   unread, marked [`Streamed`], held to the same limit and timeout as it
///   is read: its handler streams it to the shards.
pub async fn body_layer(
    State(admission): State<Arc<Admission>>,
    mut request: Request,
    next: Next,
) -> Response {
    let hint = request.body().size_hint();
    if request.body().is_end_stream() || hint.exact() == Some(0) {
        return next.run(request).await;
    }
    let upload = is_upload(request.method(), request.uri(), request.headers());
    let max = payload_limit(upload);
    let chunked = aws_chunked(request.headers());
    let limit = wire_limit(chunked, max);
    let decoded = request
        .headers()
        .get("x-amz-decoded-content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if hint.exact().is_some_and(|n| n > limit) || decoded.is_some_and(|n| n > max) {
        return entity_too_large(max);
    }
    // The most the payload can be, when that is known: its decoded length,
    // else what is on the wire.
    let payload = decoded.or(hint.exact());
    if upload && payload.is_none_or(|n| n > STREAM_ABOVE) {
        request.extensions_mut().insert(Streamed);
        let idle = admission.body_timeout;
        let request = request.map(|body| Body::new(LimitedBody::new(body, max, limit, idle)));
        return next.run(request).await;
    }
    // Without a length (chunked transfer encoding), the most it may be.
    let declared = hint.exact().unwrap_or(limit);
    let Some(reservation) = admission.budget.try_reserve(declared) else {
        debug!(
            "refused a {declared}-byte body: {} of {} budget bytes in use",
            admission.budget.in_use(),
            admission.budget.capacity()
        );
        return slow_down("memory");
    };
    let (parts, body) = request.into_parts();
    let data = match body_into_vec(body, declared, limit, Some(admission.body_timeout)).await {
        Ok(d) => d,
        Err(BodyError::TooLarge(_)) => return entity_too_large(max),
        Err(BodyError::Timeout) => {
            record_timeout("body");
            warn!(
                "{} {}: no request body bytes for {:?}; cut off",
                parts.method,
                parts.uri.path(),
                admission.body_timeout
            );
            return request_timeout();
        }
        Err(BodyError::Read(e) | BodyError::Source(e)) => {
            debug!("request body could not be read: {e}");
            return incomplete_body();
        }
    };
    let request = Request::from_parts(parts, Body::from(data));
    let resp = next.run(request).await;
    hold(resp, reservation)
}

/// What the connection-level timeouts are (see [`crate::serve`]).
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// A request's headers must arrive within this; also how long an idle
    /// keep-alive connection waits for its next request.
    pub header: Duration,
    /// How long a write to the client may wait for it to read.
    pub send: Duration,
}

/// A counter's value, for tests.
#[cfg(test)]
fn counted(c: &CounterVec, labels: &str) -> u64 {
    let mut out = String::new();
    c.render(&mut out, "x", "x");
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("x{{{labels}}} ")))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    #[test]
    fn sizes_parse_with_and_without_units() {
        assert_eq!(parse_size("512MiB"), Ok(512 * MIB));
        assert_eq!(parse_size("1GiB"), Ok(1 << 30));
        assert_eq!(parse_size("64M"), Ok(64 * MIB));
        assert_eq!(parse_size("4096"), Ok(4096));
        assert_eq!(parse_size(" 2 gb "), Ok(2 << 30));
        assert!(parse_size("lots").is_err());
        assert!(parse_size("12XB").is_err());
    }

    #[test]
    fn a_reservation_is_given_back_when_dropped() {
        let b = MemoryBudget::new(64 * MIB);
        assert_eq!(b.capacity(), 64 * MIB);
        let r = b.try_reserve(40 * MIB).expect("fits");
        assert_eq!(r.bytes(), 40 * MIB);
        assert_eq!(b.in_use(), 40 * MIB);
        assert!(b.try_reserve(30 * MIB).is_none(), "only 24 MiB are free");
        let r2 = b.try_reserve(24 * MIB).expect("the rest fits");
        assert_eq!(b.in_use(), 64 * MIB);
        drop(r);
        assert_eq!(b.in_use(), 24 * MIB);
        drop(r2);
        assert_eq!(b.in_use(), 0);
    }

    #[test]
    fn bytes_round_up_to_the_unit_and_zero_reserves_nothing() {
        let b = MemoryBudget::new(MIB);
        let r = b.try_reserve(1).expect("fits");
        assert_eq!(r.bytes(), UNIT);
        let none = b.try_reserve(0).expect("nothing to reserve");
        assert_eq!(none.bytes(), 0);
        assert_eq!(b.in_use(), UNIT);
    }

    #[test]
    fn a_request_larger_than_the_whole_budget_takes_all_of_it() {
        let b = MemoryBudget::new(16 * MIB);
        let r = b.try_reserve(100 * MIB).expect("runs alone");
        assert_eq!(r.bytes(), 16 * MIB);
        assert!(b.try_reserve(1).is_none());
        drop(r);
        assert!(b.try_reserve(100 * MIB).is_some());
    }

    #[test]
    fn shrinking_a_reservation_frees_the_difference() {
        let b = MemoryBudget::new(64 * MIB);
        let mut r = b.try_reserve(32 * MIB).expect("fits");
        r.shrink_to(10 * MIB);
        assert_eq!(r.bytes(), 10 * MIB);
        assert_eq!(b.in_use(), 10 * MIB);
        // Growing is not what shrink does.
        r.shrink_to(20 * MIB);
        assert_eq!(b.in_use(), 10 * MIB);
        r.shrink_to(0);
        assert_eq!(r.bytes(), 0);
        assert_eq!(b.in_use(), 0);
    }

    #[test]
    fn reserved_bytes_hold_the_budget_until_the_last_copy_is_dropped() {
        let b = MemoryBudget::new(64 * MIB);
        let r = b.try_reserve(8 * MIB).expect("fits");
        let bytes = reserved_bytes(vec![7u8; 8 << 20], r);
        let copy = bytes.slice(0..10);
        drop(bytes);
        assert_eq!(b.in_use(), 8 * MIB, "a slice still holds it");
        assert_eq!(&copy[..], &[7u8; 10]);
        drop(copy);
        assert_eq!(b.in_use(), 0);
    }

    #[tokio::test]
    async fn a_waiter_gets_released_bytes_before_a_newcomer() {
        let b = MemoryBudget::new(16 * MIB);
        let held = b.try_reserve(16 * MIB).expect("fits");
        let b2 = b.clone();
        let waiter = tokio::spawn(async move {
            b2.reserve(8 * MIB, Duration::from_secs(10))
                .await
                .map(|r| r.bytes())
        });
        // Let the waiter queue, then free the room: it goes to the waiter,
        // not to a newcomer asking at the same moment.
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(held);
        let newcomer = b.try_reserve(12 * MIB);
        assert_eq!(waiter.await.unwrap(), Some(8 * MIB));
        assert!(newcomer.is_none(), "the waiter's 8 MiB left only 8 free");
    }

    #[tokio::test(start_paused = true)]
    async fn a_wait_for_room_gives_up_after_its_deadline() {
        let b = MemoryBudget::new(16 * MIB);
        let _held = b.try_reserve(16 * MIB).expect("fits");
        assert!(b.reserve(MIB, Duration::from_secs(5)).await.is_none());
    }

    #[test]
    fn a_refusal_is_slow_down_with_retry_after() {
        let resp = slow_down("memory");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            resp.headers().get(header::RETRY_AFTER).unwrap(),
            &HeaderValue::from(RETRY_AFTER_SECS)
        );
        assert!(counted(&REJECTED, "reason=\"memory\"") >= 1);
    }

    #[tokio::test]
    async fn a_body_is_read_whole_up_to_its_limit() {
        let body = Body::from(vec![1u8; 1000]);
        let v = body_into_vec(body, 1000, 1000, None).await.expect("fits");
        assert_eq!(v.len(), 1000);
        let body = Body::from(vec![1u8; 1001]);
        assert!(matches!(
            body_into_vec(body, 1001, 1000, None).await,
            Err(BodyError::TooLarge(1000))
        ));
    }

    #[tokio::test]
    async fn a_body_from_many_frames_comes_back_whole() {
        let frames = futures::stream::iter(
            (0..10u8).map(|i| Ok::<_, std::io::Error>(Bytes::from(vec![i; 100]))),
        );
        let v = body_into_vec(Body::from_stream(frames), 1000, 4096, None)
            .await
            .expect("fits");
        assert_eq!(v.len(), 1000);
        assert_eq!(v[999], 9);
        assert_eq!(v[0], 0);
    }

    #[tokio::test(start_paused = true)]
    async fn a_body_that_stops_arriving_times_out() {
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(1);
        tx.send(Ok(Bytes::from_static(b"abc"))).await.unwrap();
        let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
        let got = body_into_vec(body, 10, 100, Some(Duration::from_secs(30))).await;
        assert!(matches!(got, Err(BodyError::Timeout)), "{got:?}");
        drop(tx);
    }

    #[test]
    fn an_aws_chunked_body_may_carry_its_framing_over_the_limit() {
        let mut h = HeaderMap::new();
        assert!(!aws_chunked(&h));
        assert_eq!(wire_limit(false, MAX_UPLOAD), MAX_UPLOAD);
        h.insert(
            "x-amz-content-sha256",
            HeaderValue::from_static("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
        );
        assert!(aws_chunked(&h));
        assert!(wire_limit(true, MAX_UPLOAD) > MAX_UPLOAD);
    }

    #[test]
    fn only_an_object_put_without_a_sub_resource_is_an_upload() {
        let put = Method::PUT;
        let uri = |u: &str| u.parse::<Uri>().unwrap();
        let none = HeaderMap::new();
        assert!(is_upload(&put, &uri("/b/k"), &none));
        assert!(is_upload(&put, &uri("/b/dir/k"), &none));
        assert!(is_upload(&put, &uri("/b/k?partNumber=2&uploadId=x"), &none));
        assert!(!is_upload(&Method::POST, &uri("/b/k"), &none));
        assert!(!is_upload(&put, &uri("/b"), &none));
        assert!(!is_upload(&put, &uri("/b/"), &none));
        for sub in ["acl", "tagging", "retention", "legal-hold"] {
            assert!(
                !is_upload(&put, &uri(&format!("/b/k?{sub}")), &none),
                "{sub}"
            );
        }
        let mut copy = HeaderMap::new();
        copy.insert("x-amz-copy-source", HeaderValue::from_static("/a/b"));
        assert!(!is_upload(&put, &uri("/b/k"), &copy));
        assert_eq!(payload_limit(true), MAX_UPLOAD);
        assert_eq!(payload_limit(false), MAX_BODY as u64);
    }

    #[test]
    fn a_reservation_splits_and_merges_back() {
        let b = MemoryBudget::new(64 * MIB);
        let mut r = b.try_reserve(48 * MIB).expect("fits");
        let part = r.split(16 * MIB);
        assert_eq!((r.bytes(), part.bytes()), (32 * MIB, 16 * MIB));
        assert_eq!(b.in_use(), 48 * MIB);
        drop(part);
        assert_eq!(b.in_use(), 32 * MIB, "a part dropped is given back");
        let part = r.split(16 * MIB);
        r.merge(part);
        assert_eq!(r.bytes(), 32 * MIB);
        // Asked for more than it holds: all of it.
        let all = r.split(100 * MIB);
        assert_eq!((r.bytes(), all.bytes()), (0, 32 * MIB));
        r.merge(all);
        assert_eq!(r.bytes(), 32 * MIB);
        drop(r);
        assert_eq!(b.in_use(), 0);
    }

    #[tokio::test]
    async fn a_streamed_body_is_held_to_its_limit() {
        use http_body_util::BodyExt;
        let frames = futures::stream::iter(
            (0..4u8).map(|i| Ok::<_, std::io::Error>(Bytes::from(vec![i; 100]))),
        );
        let body = LimitedBody::new(Body::from_stream(frames), 300, 300, Duration::from_secs(5));
        let err = body.collect().await.expect_err("over the limit");
        let resp = body_refused(&err);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let text = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&text).contains("EntityTooLarge"));

        let frames = futures::stream::iter(
            (0..3u8).map(|i| Ok::<_, std::io::Error>(Bytes::from(vec![i; 100]))),
        );
        let body = LimitedBody::new(Body::from_stream(frames), 300, 300, Duration::from_secs(5));
        assert_eq!(body.collect().await.unwrap().to_bytes().len(), 300);
    }

    /// The idle timer runs only while the body is awaited: a reader that
    /// takes long between reads does not make the client late.
    #[tokio::test(start_paused = true)]
    async fn a_streamed_body_times_out_only_while_waited_on() {
        use http_body_util::BodyExt;
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
        let mut body = LimitedBody::new(
            Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx)),
            1000,
            1000,
            Duration::from_secs(30),
        );
        tx.send(Ok(Bytes::from_static(b"abc"))).await.unwrap();
        assert!(body.frame().await.unwrap().is_ok());
        // The reader busy for longer than the timeout; the client has sent
        // its next bytes meanwhile.
        tokio::time::sleep(Duration::from_secs(60)).await;
        tx.send(Ok(Bytes::from_static(b"def"))).await.unwrap();
        assert!(body.frame().await.unwrap().is_ok());
        // Now the client stops.
        let err = body.frame().await.unwrap().expect_err("timed out");
        let resp = body_refused(&err);
        let text = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&text).contains("RequestTimeout"));
        drop(tx);
    }

    #[test]
    fn probes_and_scrapes_are_never_limited() {
        assert!(exempt("/health"));
        assert!(exempt("/_ready"));
        assert!(exempt("/metrics"));
        assert!(!exempt("/bucket/health"));
    }
}
