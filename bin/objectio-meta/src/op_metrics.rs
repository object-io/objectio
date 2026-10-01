//! Meta's gRPC calls (counts by status, and latency, every method, via
//! the transport layer in `objectio_proto::rpc_metrics`) and its redb
//! commits.

use std::sync::LazyLock;

use objectio_proto::rpc_metrics::RpcMetrics;

/// Every gRPC call meta serves, Raft's included.
pub static RPC_METRICS: LazyLock<RpcMetrics> = LazyLock::new(RpcMetrics::default);

/// Everything meta's metrics endpoint adds for operations and storage.
pub fn render() -> String {
    let mut out = String::new();
    RPC_METRICS.render(&mut out, "objectio_meta_grpc", "meta", "");
    objectio_meta_store::commit_metrics::render(&mut out);
    out
}
