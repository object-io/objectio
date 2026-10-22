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
//!   byte of it is read; a GET reserves each stripe before reading it, and
//!   gives it back once the client has been sent it. A new request that
//!   does not fit is refused; a GET already streaming waits for room for
//!   its next stripe (released bytes go to waiters first).
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
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::Response;
use http_body::{Body as HttpBody, Frame, SizeHint};
use objectio_common::histogram::{CounterVec, label_value};
use std::sync::LazyLock;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, info, warn};

/// The largest request body the S3 API takes (a PUT or an upload part).
pub const MAX_BODY: usize = 100 * 1024 * 1024;

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

/// The most wire bytes a body may have: the payload limit, and for an
/// AWS-chunked body room for its framing too (SDKs send 64 KiB chunks,
/// about 90 bytes of framing each; AWS's smallest chunk is 8 KiB), and the
/// trailers.
pub(crate) fn wire_limit(chunked: bool) -> u64 {
    let max = MAX_BODY as u64;
    if chunked {
        max + max / 8 + 64 * 1024
    } else {
        max
    }
}

pub(crate) fn entity_too_large() -> Response {
    crate::s3::S3Error::xml_response(
        "EntityTooLarge",
        &format!("Your proposed upload exceeds the maximum allowed size of {MAX_BODY} bytes"),
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
    /// More bytes than the limit.
    TooLarge,
    /// No bytes for longer than the body timeout.
    Timeout,
    /// The connection failed, or the client ended the body early.
    Read(String),
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
            return Err(BodyError::TooLarge);
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

/// Request bodies on the S3 API, after authentication: the declared length
/// is reserved from the memory budget (or `503 SlowDown`), refused over the
/// limit (`400 EntityTooLarge`, as S3 answers), and read in full here into one buffer,
/// each part within the body timeout of the last (`400 RequestTimeout`).
/// Handlers then take it without another copy.
pub async fn body_layer(
    State(admission): State<Arc<Admission>>,
    request: Request,
    next: Next,
) -> Response {
    let hint = request.body().size_hint();
    if request.body().is_end_stream() || hint.exact() == Some(0) {
        return next.run(request).await;
    }
    let chunked = aws_chunked(request.headers());
    let limit = wire_limit(chunked);
    let decoded_too_large = request
        .headers()
        .get("x-amz-decoded-content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|n| n > MAX_BODY as u64);
    // Without a length (chunked transfer encoding), the most it may be.
    let declared = hint.exact().unwrap_or(limit);
    if declared > limit || decoded_too_large {
        return entity_too_large();
    }
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
        Err(BodyError::TooLarge) => return entity_too_large(),
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
        Err(BodyError::Read(e)) => {
            debug!("request body could not be read: {e}");
            return crate::s3::S3Error::xml_response(
                "IncompleteBody",
                "You did not provide the number of bytes specified by the Content-Length HTTP header.",
                StatusCode::BAD_REQUEST,
            );
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
            Err(BodyError::TooLarge)
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
        assert_eq!(wire_limit(false), MAX_BODY as u64);
        h.insert(
            "x-amz-content-sha256",
            HeaderValue::from_static("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
        );
        assert!(aws_chunked(&h));
        assert!(wire_limit(true) > MAX_BODY as u64);
    }

    #[test]
    fn probes_and_scrapes_are_never_limited() {
        assert!(exempt("/health"));
        assert!(exempt("/_ready"));
        assert!(exempt("/metrics"));
        assert!(!exempt("/bucket/health"));
    }
}
