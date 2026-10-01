//! HTTP/2 settings for gRPC servers that receive shards.
//!
//! hyper's server defaults give each connection a 1 MiB receive window, for
//! each stream and for the connection as a whole. A shard is up to 4 MiB, so
//! a lone PUT's shard stalls on window updates several times on its way to
//! the OSD. On datacore (NVMe, loopback), opening the windows took a single
//! 4 MiB PUT from ~80 to ~175 MiB/s — its shard writes' transport time from
//! ~9 ms to ~2 ms — and left 16-way concurrent PUT and GET unchanged.
//!
//! Only servers are tuned. Enlarging the gateway's client windows as well
//! (hyper's client defaults are already 2 MiB per stream, 5 MiB per
//! connection) cost a single GET ~30% of its throughput in the same test.
//!
//! The windows are credit the receiver extends, not memory it allocates up
//! front: a connection only buffers what is actually in flight.

use tonic::transport::Server;

/// Per-stream window: one whole shard (at most 4 MiB) arrives without the
/// sender waiting for a window update.
pub const STREAM_WINDOW: u32 = 8 * 1024 * 1024;

/// Per-connection window: room for many shards in flight from one gateway.
pub const CONNECTION_WINDOW: u32 = 64 * 1024 * 1024;

/// A server builder whose connections accept shards at full window.
#[must_use]
pub fn server() -> Server {
    Server::builder()
        .initial_stream_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONNECTION_WINDOW)
}
