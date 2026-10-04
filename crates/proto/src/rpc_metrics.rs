//! Request counts and latency for every gRPC method a server serves.
//!
//! Measured at the transport, so every method is covered, including ones
//! added later, without touching its handler. A service keeps one
//! [`RpcMetrics`] in a static and adds its layer to the server:
//!
//! ```ignore
//! static RPC: LazyLock<RpcMetrics> = LazyLock::new(RpcMetrics::default);
//! transport::server().layer(RpcMetricsLayer(&RPC))
//! ```
//!
//! `method` is the last part of the request path
//! (`/objectio.storage.StorageService/WriteShard` → `WriteShard`), which
//! the service definitions bound. `code` is the gRPC status name.
//!
//! A unary call that fails sends its status in the response headers, where
//! it is seen. A streaming call that fails part-way sends it in trailers
//! after the body, which the layer does not wait for, so such a call counts
//! as `OK`. Latency is time to the response headers: for a unary call the
//! whole call, for a streaming one the time to its first message.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Instant;

use objectio_common::histogram::{CounterVec, HistogramVec, LATENCY_BUCKETS, label_value};
use tonic::codegen::http;

/// One server's request counts and latencies, by method.
pub struct RpcMetrics {
    seconds: HistogramVec,
    requests: CounterVec,
}

impl Default for RpcMetrics {
    fn default() -> Self {
        Self {
            seconds: HistogramVec::new(LATENCY_BUCKETS),
            requests: CounterVec::new(),
        }
    }
}

impl RpcMetrics {
    /// Record one finished call.
    pub fn record(&self, method: &str, code: tonic::Code, elapsed: std::time::Duration) {
        let method = label_value(method);
        self.seconds
            .observe_duration(&format!("method=\"{method}\""), elapsed);
        self.requests
            .inc(&format!("method=\"{method}\",code=\"{}\"", code_name(code)));
    }

    /// Render `{prefix}_requests_total{method,code}` and
    /// `{prefix}_latency_seconds{method}`. `extra` (e.g. `osd_id="…"`) is
    /// added to every series.
    pub fn render(&self, out: &mut String, prefix: &str, what: &str, extra: &str) {
        self.requests.render_with(
            out,
            &format!("{prefix}_requests_total"),
            &format!("gRPC calls {what} served, by method and status code"),
            extra,
        );
        self.seconds.render(
            out,
            &format!("{prefix}_latency_seconds"),
            &format!("Time {what} took to answer a gRPC call, by method"),
            extra,
        );
    }
}

/// The status name gRPC uses, e.g. `NOT_FOUND`.
#[must_use]
pub const fn code_name(code: tonic::Code) -> &'static str {
    use tonic::Code;
    match code {
        Code::Ok => "OK",
        Code::Cancelled => "CANCELLED",
        Code::Unknown => "UNKNOWN",
        Code::InvalidArgument => "INVALID_ARGUMENT",
        Code::DeadlineExceeded => "DEADLINE_EXCEEDED",
        Code::NotFound => "NOT_FOUND",
        Code::AlreadyExists => "ALREADY_EXISTS",
        Code::PermissionDenied => "PERMISSION_DENIED",
        Code::ResourceExhausted => "RESOURCE_EXHAUSTED",
        Code::FailedPrecondition => "FAILED_PRECONDITION",
        Code::Aborted => "ABORTED",
        Code::OutOfRange => "OUT_OF_RANGE",
        Code::Unimplemented => "UNIMPLEMENTED",
        Code::Internal => "INTERNAL",
        Code::Unavailable => "UNAVAILABLE",
        Code::DataLoss => "DATA_LOSS",
        Code::Unauthenticated => "UNAUTHENTICATED",
    }
}

/// The status a response's headers carry: `OK` when they carry none (it
/// follows in trailers).
fn status_of(headers: &http::HeaderMap) -> tonic::Code {
    headers
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<i32>().ok())
        .map_or(tonic::Code::Ok, tonic::Code::from_i32)
}

/// Tower layer that records every call into an [`RpcMetrics`].
#[derive(Clone, Copy)]
pub struct RpcMetricsLayer(pub &'static RpcMetrics);

impl<S> tower::Layer<S> for RpcMetricsLayer {
    type Service = RpcMetricsService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        RpcMetricsService {
            inner,
            metrics: self.0,
        }
    }
}

#[derive(Clone)]
pub struct RpcMetricsService<S> {
    inner: S,
    metrics: &'static RpcMetrics,
}

impl<S, B, RB> tower::Service<http::Request<B>> for RpcMetricsService<S>
where
    S: tower::Service<http::Request<B>, Response = http::Response<RB>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let method = req
            .uri()
            .path()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        let metrics = self.metrics;
        let started = Instant::now();
        let fut = self.inner.call(req);
        Box::pin(async move {
            let res = fut.await;
            let code = res
                .as_ref()
                .map_or(tonic::Code::Unknown, |r| status_of(r.headers()));
            metrics.record(&method, code, started.elapsed());
            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_call_is_counted_by_its_code() {
        let m = RpcMetrics::default();
        m.record(
            "WriteShard",
            tonic::Code::Ok,
            std::time::Duration::from_millis(2),
        );
        m.record(
            "WriteShard",
            tonic::Code::NotFound,
            std::time::Duration::from_millis(1),
        );
        let mut out = String::new();
        m.render(&mut out, "objectio_osd_grpc", "this OSD", "osd_id=\"a\"");
        assert!(out.contains(
            "objectio_osd_grpc_requests_total{osd_id=\"a\",method=\"WriteShard\",code=\"NOT_FOUND\"} 1"
        ), "{out}");
        assert!(
            out.contains(
                "objectio_osd_grpc_latency_seconds_count{osd_id=\"a\",method=\"WriteShard\"} 2"
            ),
            "{out}"
        );
    }

    #[test]
    fn the_status_comes_from_the_headers() {
        let mut h = http::HeaderMap::new();
        assert_eq!(status_of(&h), tonic::Code::Ok);
        h.insert("grpc-status", http::HeaderValue::from_static("5"));
        assert_eq!(status_of(&h), tonic::Code::NotFound);
    }
}
