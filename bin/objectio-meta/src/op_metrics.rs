//! Latency of every gRPC call meta serves, and of its redb commits.
//!
//! Timed at the transport, so a new RPC is covered without touching its
//! handler. The label is the method name from the request path
//! (`/objectio.metadata.MetadataService/CreateBucket` → `CreateBucket`),
//! which is bounded by the service definitions.

use objectio_common::histogram::{HistogramVec, LATENCY_BUCKETS, label_value};
use std::future::Future;
use std::pin::Pin;
use std::sync::LazyLock;
use std::task::{Context, Poll};
use std::time::Instant;
use tonic::codegen::http;

static OP_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| HistogramVec::new(LATENCY_BUCKETS));

/// Everything meta's metrics endpoint adds for operations and storage.
pub fn render() -> String {
    let mut out = String::new();
    OP_SECONDS.render(
        &mut out,
        "objectio_meta_op_seconds",
        "Time to serve one meta gRPC call, by method",
        "",
    );
    objectio_meta_store::commit_metrics::render(&mut out);
    out
}

#[derive(Clone, Copy)]
pub struct OpTimerLayer;

impl<S> tower::Layer<S> for OpTimerLayer {
    type Service = OpTimer<S>;
    fn layer(&self, inner: S) -> Self::Service {
        OpTimer { inner }
    }
}

#[derive(Clone)]
pub struct OpTimer<S> {
    inner: S,
}

impl<S, B> tower::Service<http::Request<B>> for OpTimer<S>
where
    S: tower::Service<http::Request<B>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<S::Response, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let op = req
            .uri()
            .path()
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_string();
        let started = Instant::now();
        let fut = self.inner.call(req);
        Box::pin(async move {
            let res = fut.await;
            OP_SECONDS.observe_duration(&format!("op=\"{}\"", label_value(&op)), started.elapsed());
            res
        })
    }
}
