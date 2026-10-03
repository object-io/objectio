//! OSD Connection Pool
//!
//! Manages connections to multiple OSD nodes for distributed storage operations.

use bytes::Bytes;
use objectio_proto::metadata::NodePlacement;
use objectio_proto::storage::storage_service_client::StorageServiceClient;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tonic::transport::Channel;
use tracing::{error, info, warn};

/// Error type for OSD pool operations
#[derive(Debug, thiserror::Error)]
pub enum OsdPoolError {
    #[error("node not found: {0}")]
    NodeNotFound(String),

    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("no nodes available")]
    #[allow(dead_code)]
    NoNodesAvailable,

    #[error("shard checksum mismatch: {0}")]
    ChecksumMismatch(String),

    /// The object needs a newer release to read correctly.
    #[error("{0}")]
    TooOld(String),
}

/// Node identifier (16-byte UUID)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeId([u8; 16]);

impl NodeId {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 16 {
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            Some(Self(arr))
        } else {
            None
        }
    }

    #[allow(dead_code)]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl From<[u8; 16]> for NodeId {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

/// Information about a connected OSD node
#[derive(Clone)]
#[allow(dead_code)]
pub struct OsdNode {
    pub node_id: NodeId,
    pub address: String,
    pub client: StorageServiceClient<Channel>,
}

/// How long an OSD address that just failed at the transport level (no
/// connection, or a connection that dropped) is failed fast, without
/// trying it. A slow answer does not count: a busy OSD is not a dead one. A host that vanished without resetting its connections would
/// otherwise cost every request a timeout; meanwhile writes go on with the
/// other shards (the write quorum) and repair rebuilds the missing one.
const FAIL_FAST: std::time::Duration = std::time::Duration::from_secs(5);

/// Pool of OSD connections for multi-node operations
pub struct OsdPool {
    /// Connected nodes: node_id -> OsdNode
    nodes: RwLock<HashMap<NodeId, OsdNode>>,
    /// Address to node_id mapping for deduplication
    address_map: RwLock<HashMap<String, NodeId>>,
    /// Addresses that failed at the transport level, and when.
    unreachable: std::sync::Mutex<HashMap<String, std::time::Instant>>,
    /// Meta, for keys a write or delete left behind on some copies.
    heal: std::sync::OnceLock<
        objectio_proto::metadata::metadata_service_client::MetadataServiceClient<Channel>,
    >,
}

impl OsdPool {
    /// Create a new empty OSD pool
    pub fn new() -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            address_map: RwLock::new(HashMap::new()),
            unreachable: std::sync::Mutex::new(HashMap::new()),
            heal: std::sync::OnceLock::new(),
        }
    }

    /// Where keys go whose copies a write or delete left behind.
    pub fn set_heal_queue(
        &self,
        meta: objectio_proto::metadata::metadata_service_client::MetadataServiceClient<Channel>,
    ) {
        let _ = self.heal.set(meta);
    }

    /// A write or delete of `bucket/key` reached the quorum but not every
    /// copy: queue the key for healing (core/object-metadata-quorum.md).
    /// Before the caller acknowledges; if meta can't take it, the data is
    /// still durable at quorum and only waits longer to converge.
    pub async fn queue_heal(&self, bucket: &str, key: &str, version_id: &str) {
        let Some(meta) = self.heal.get() else {
            return;
        };
        let r = meta
            .clone()
            .heal_enqueue(objectio_proto::metadata::HealEnqueueRequest {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: version_id.to_string(),
            })
            .await;
        crate::gateway_metrics::record_heal_queued(r.is_ok());
        if let Err(e) = r {
            warn!("{bucket}/{key}: could not queue for healing: {e}");
        }
    }

    /// `address` failed at the transport level: fail it fast for a while.
    pub fn mark_unreachable(&self, address: &str) {
        self.unreachable
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(address.to_string(), std::time::Instant::now());
    }

    /// Whether `address` failed at the transport level within `FAIL_FAST`.
    fn is_unreachable(&self, address: &str) -> bool {
        let mut m = self
            .unreachable
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match m.get(address) {
            Some(at) if at.elapsed() < FAIL_FAST => true,
            Some(_) => {
                m.remove(address);
                false
            }
            None => false,
        }
    }

    /// Connect to an OSD node and add it to the pool
    pub async fn connect(&self, node_id: NodeId, address: &str) -> Result<(), OsdPoolError> {
        // Take the write lock immediately to avoid race conditions
        let mut nodes = self.nodes.write().await;

        // Double-check if already connected (another task may have inserted while we waited)
        if nodes.contains_key(&node_id) {
            return Ok(());
        }

        // Check if address already has a connection with a different node_id
        let address_map = self.address_map.read().await;
        if let Some(existing_node_id) = address_map.get(address).cloned() {
            drop(address_map); // Release read lock before taking nodes read

            if let Some(existing_node) = nodes.get(&existing_node_id).cloned() {
                let aliased_node = OsdNode {
                    node_id: node_id.clone(),
                    address: address.to_string(),
                    client: existing_node.client,
                };
                nodes.insert(node_id, aliased_node);
                return Ok(());
            }
        } else {
            drop(address_map);
        }

        // Need to create a new connection - release the lock during the network call
        drop(nodes);

        // Connect with increased message size limit (100MB for large objects)
        let max_message_size = 100 * 1024 * 1024; // 100 MB
        // A dead host is noticed in seconds: connecting gives up after 3 s,
        // and an open connection that stops answering keepalives is closed
        // after about 10 s, failing what is in flight on it.
        let channel = tonic::transport::Endpoint::new(address.to_string())
            .map_err(|e| OsdPoolError::ConnectionFailed(e.to_string()))?
            .connect_timeout(std::time::Duration::from_secs(3))
            .tcp_keepalive(Some(std::time::Duration::from_secs(10)))
            .http2_keep_alive_interval(std::time::Duration::from_secs(5))
            .keep_alive_timeout(std::time::Duration::from_secs(5))
            .keep_alive_while_idle(true)
            .connect()
            .await
            .map_err(|e| {
                self.mark_unreachable(address);
                OsdPoolError::ConnectionFailed(e.to_string())
            })?;

        let client = StorageServiceClient::new(channel)
            .max_decoding_message_size(max_message_size)
            .max_encoding_message_size(max_message_size);

        // Re-acquire the lock and check again (another task may have connected)
        let mut nodes = self.nodes.write().await;
        if nodes.contains_key(&node_id) {
            return Ok(()); // Another task connected while we were making the network call
        }

        let node = OsdNode {
            node_id: node_id.clone(),
            address: address.to_string(),
            client,
        };

        nodes.insert(node_id.clone(), node);
        drop(nodes);

        self.address_map
            .write()
            .await
            .insert(address.to_string(), node_id);

        info!("Connected to OSD at {}", address);
        Ok(())
    }

    /// Get a client for a specific node
    #[allow(dead_code)]
    pub async fn get_client(
        &self,
        node_id: &[u8],
    ) -> Result<StorageServiceClient<Channel>, OsdPoolError> {
        let id = NodeId::from_bytes(node_id)
            .ok_or_else(|| OsdPoolError::NodeNotFound("invalid node ID".to_string()))?;

        self.nodes
            .read()
            .await
            .get(&id)
            .map(|n| n.client.clone())
            .ok_or_else(|| OsdPoolError::NodeNotFound(id.to_hex()))
    }

    /// Get a client for a node by address, connecting if necessary
    pub async fn get_or_connect(
        &self,
        node_id: &[u8],
        address: &str,
    ) -> Result<StorageServiceClient<Channel>, OsdPoolError> {
        let id = NodeId::from_bytes(node_id)
            .ok_or_else(|| OsdPoolError::NodeNotFound("invalid node ID".to_string()))?;
        if self.is_unreachable(address) {
            return Err(OsdPoolError::ConnectionFailed(format!(
                "{address} failed in the last {} s; not tried",
                FAIL_FAST.as_secs()
            )));
        }

        // Try to get existing client first (fast path)
        if let Some(node) = self.nodes.read().await.get(&id) {
            return Ok(node.client.clone());
        }

        // Connect (handles races internally)
        self.connect(id.clone(), address).await?;

        self.nodes
            .read()
            .await
            .get(&id)
            .map(|n| n.client.clone())
            .ok_or_else(|| OsdPoolError::NodeNotFound(id.to_hex()))
    }

    /// Remove a node from the pool
    #[allow(dead_code)]
    pub async fn disconnect(&self, node_id: &NodeId) {
        if let Some(node) = self.nodes.write().await.remove(node_id) {
            self.address_map.write().await.remove(&node.address);
            info!("Disconnected from OSD node {}", node_id.to_hex());
        }
    }

    /// Get all connected node IDs
    #[allow(dead_code)]
    pub async fn connected_nodes(&self) -> Vec<NodeId> {
        self.nodes.read().await.keys().cloned().collect()
    }

    /// Get the number of connected nodes
    #[allow(dead_code)]
    pub async fn node_count(&self) -> usize {
        self.nodes.read().await.len()
    }

    /// Get a client for a node placement
    pub async fn get_client_for_placement(
        &self,
        placement: &NodePlacement,
    ) -> Result<StorageServiceClient<Channel>, OsdPoolError> {
        self.get_or_connect(&placement.node_id, &placement.node_address)
            .await
    }
}

impl Default for OsdPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Client for a shard call, counting a failure to connect as `refused`.
async fn connect_for_shard(
    pool: &OsdPool,
    placement: &NodePlacement,
) -> Result<StorageServiceClient<Channel>, OsdPoolError> {
    pool.get_client_for_placement(placement)
        .await
        .inspect_err(|_| {
            crate::gateway_metrics::record_osd_error(&placement.node_address, "refused");
        })
}

/// A PUT shard's place in the gateway's registered memory, so an OSD can
/// read it over Transfer Engine instead of receiving it as bytes.
#[derive(Clone, Copy)]
pub struct RdmaSource<'a> {
    pub rdma: &'a crate::rdma::GatewayRdma,
    /// Address of the shard's first byte in this process.
    pub addr: u64,
}

/// Whether `e` says the OSD could not be reached (as opposed to an answer
/// from it): unavailable, or a connection that dropped, which tonic reports
/// as Unknown "transport error".
fn is_transport_failure(e: &tonic::Status) -> bool {
    e.code() == tonic::Code::Unavailable
        || (e.code() == tonic::Code::Unknown && e.message() == "transport error")
}

/// A shard call that did not succeed.
enum ShardCallError {
    Connect(OsdPoolError),
    Timeout,
    Status(tonic::Status),
}

impl From<ShardCallError> for OsdPoolError {
    fn from(e: ShardCallError) -> Self {
        match e {
            ShardCallError::Connect(e) => e,
            ShardCallError::Timeout => Self::ConnectionFailed("timeout".to_string()),
            ShardCallError::Status(s) => Self::ConnectionFailed(s.to_string()),
        }
    }
}

/// Why a Transfer Engine attempt failed, and what to do about the OSD. A
/// busy OSD refused before touching the gateway's memory; anything else
/// means the path is suspect, so the OSD cools down.
fn rdma_failure(
    rdma: &crate::rdma::GatewayRdma,
    te_segment: &str,
    e: &ShardCallError,
) -> crate::rdma::Fallback {
    use crate::rdma::Fallback;
    let reason = match e {
        ShardCallError::Status(s) if s.code() == tonic::Code::ResourceExhausted => {
            return Fallback::OsdBusy;
        }
        ShardCallError::Status(s) if s.code() == tonic::Code::DataLoss => Fallback::Checksum,
        _ => Fallback::Error,
    };
    rdma.cool_down(te_segment);
    reason
}

/// Whether `data` is the shard the OSD described. A response without a
/// checksum is taken as is: the field is optional on the wire.
fn matches_checksum(checksum: Option<&objectio_proto::storage::Checksum>, data: &[u8]) -> bool {
    checksum.is_none_or(|c| c.crc32c == crc32c::crc32c(data))
}

/// One WriteShard call, with the gateway's timeout and error accounting.
async fn call_write_shard(
    pool: &OsdPool,
    placement: &NodePlacement,
    request: objectio_proto::storage::WriteShardRequest,
) -> Result<objectio_proto::storage::BlockLocation, ShardCallError> {
    let mut client = connect_for_shard(pool, placement)
        .await
        .map_err(ShardCallError::Connect)?;
    let position = request.shard_id.as_ref().map_or(0, |s| s.position);
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.write_shard(request),
    )
    .await;
    crate::gateway_metrics::record_shard_io(&placement.node_address, "write", started.elapsed());
    let response = result
        .map_err(|_| {
            crate::gateway_metrics::record_osd_error(&placement.node_address, "timeout");
            error!(
                "Timeout writing shard {} to OSD {}",
                position, placement.node_address
            );
            ShardCallError::Timeout
        })?
        .map_err(|e| {
            crate::gateway_metrics::record_osd_error(&placement.node_address, "error");
            if is_transport_failure(&e) {
                pool.mark_unreachable(&placement.node_address);
            }
            error!(
                "Failed to write shard to OSD {}: {}",
                placement.node_address, e
            );
            ShardCallError::Status(e)
        })?;
    response.into_inner().location.ok_or_else(|| {
        ShardCallError::Connect(OsdPoolError::ConnectionFailed(
            "no location returned".to_string(),
        ))
    })
}

/// One ReadShard call, with the gateway's timeout and error accounting.
async fn call_read_shard(
    pool: &OsdPool,
    placement: &NodePlacement,
    request: objectio_proto::storage::ReadShardRequest,
) -> Result<objectio_proto::storage::ReadShardResponse, ShardCallError> {
    let mut client = connect_for_shard(pool, placement)
        .await
        .map_err(ShardCallError::Connect)?;
    let position = request.shard_id.as_ref().map_or(0, |s| s.position);
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client.read_shard(request),
    )
    .await;
    crate::gateway_metrics::record_shard_io(&placement.node_address, "read", started.elapsed());
    let response = result
        .map_err(|_| {
            crate::gateway_metrics::record_osd_error(&placement.node_address, "timeout");
            error!(
                "Timeout reading shard {} from OSD {}",
                position, placement.node_address
            );
            ShardCallError::Timeout
        })?
        .map_err(|e| {
            crate::gateway_metrics::record_osd_error(&placement.node_address, "error");
            if is_transport_failure(&e) {
                pool.mark_unreachable(&placement.node_address);
            }
            warn!(
                "Failed to read shard from OSD {}: {}",
                placement.node_address, e
            );
            ShardCallError::Status(e)
        })?;
    Ok(response.into_inner())
}

/// Write a shard to the OSD in `placement`.
///
/// With `rdma`, and an OSD that offers Transfer Engine, the OSD reads the
/// shard out of the gateway's memory; if that fails for any reason the same
/// shard is sent again as bytes. `data` is the shard either way — for the
/// checksum, and for the fallback.
#[allow(clippy::too_many_arguments)]
pub async fn write_shard_to_osd(
    pool: &OsdPool,
    placement: &NodePlacement,
    object_id: &[u8],
    stripe_id: u64,
    position: u32,
    data: Bytes,
    ec_k: u32,
    ec_m: u32,
    rdma: Option<RdmaSource<'_>>,
) -> Result<objectio_proto::storage::BlockLocation, OsdPoolError> {
    use objectio_proto::storage::{Checksum, RdmaBuffer, ShardId, WriteShardRequest};

    let shard_id = ShardId {
        object_id: object_id.to_vec(),
        stripe_id,
        position,
    };
    let checksum = Checksum {
        crc32c: crc32c::crc32c(&data),
        xxhash64: 0,
        sha256: vec![],
    };

    if let Some(src) = rdma {
        match src.rdma.check(&placement.te_segment) {
            Ok(()) => {
                let request = WriteShardRequest {
                    shard_id: Some(shard_id.clone()),
                    data: Bytes::new(),
                    ec_k,
                    ec_m,
                    checksum: Some(checksum.clone()),
                    rdma: Some(RdmaBuffer {
                        segment: src.rdma.segment().to_string(),
                        addr: src.addr,
                        len: data.len() as u64,
                    }),
                };
                match call_write_shard(pool, placement, request).await {
                    Ok(location) => {
                        crate::gateway_metrics::record_shard_transfer("write", "rdma");
                        return Ok(location);
                    }
                    Err(e) => {
                        let reason = rdma_failure(src.rdma, &placement.te_segment, &e);
                        crate::gateway_metrics::record_rdma_fallback("write", reason);
                        // The OSD may still be reading this memory.
                        if reason != crate::rdma::Fallback::OsdBusy {
                            src.rdma.quarantine(data.clone());
                        }
                        warn!(
                            "shard {position} to {} over rdma: {}; sending it over gRPC",
                            placement.node_address,
                            reason.label()
                        );
                    }
                }
            }
            Err(Some(reason)) => crate::gateway_metrics::record_rdma_fallback("write", reason),
            Err(None) => {}
        }
    }

    let request = WriteShardRequest {
        shard_id: Some(shard_id),
        ec_k,
        ec_m,
        checksum: Some(checksum),
        data,
        rdma: None,
    };
    let location = call_write_shard(pool, placement, request)
        .await
        .inspect_err(|e| {
            // The OSD refuses bytes that do not match the checksum sent
            // with them: the shard was damaged between here and there.
            if matches!(e, ShardCallError::Status(s) if s.code() == tonic::Code::DataLoss) {
                crate::gateway_metrics::record_shard_checksum_mismatch("write");
            }
        })?;
    crate::gateway_metrics::record_shard_transfer("write", "grpc");
    Ok(location)
}

/// Read a shard from the OSD in `placement`.
///
/// With `rdma`, and an OSD that offers Transfer Engine, the OSD writes the
/// shard into one of the gateway's read slots and the returned `Bytes` is a
/// view of that slot — checked against the OSD's checksum. Any failure reads
/// the shard again as bytes.
pub async fn read_shard_from_osd(
    pool: &OsdPool,
    placement: &NodePlacement,
    object_id: &[u8],
    stripe_id: u64,
    position: u32,
    rdma: Option<&crate::rdma::GatewayRdma>,
) -> Result<Bytes, OsdPoolError> {
    use crate::rdma::Fallback;
    use objectio_proto::storage::{RdmaBuffer, ReadShardRequest, ShardId};

    let shard_id = ShardId {
        object_id: object_id.to_vec(),
        stripe_id,
        position,
    };

    if let Some(r) = rdma {
        match r.check(&placement.te_segment) {
            Ok(()) => match r.read_slot() {
                None => crate::gateway_metrics::record_rdma_fallback("read", Fallback::NoSlot),
                Some(slot) => {
                    let request = ReadShardRequest {
                        shard_id: Some(shard_id.clone()),
                        offset: 0,
                        length: 0,
                        rdma_dest: Some(RdmaBuffer {
                            segment: r.segment().to_string(),
                            addr: slot.addr(),
                            len: slot.capacity() as u64,
                        }),
                    };
                    let reason = match call_read_shard(pool, placement, request).await {
                        Ok(resp) => {
                            let len = usize::try_from(resp.rdma_len).unwrap_or(usize::MAX);
                            if len > slot.capacity() {
                                r.quarantine(slot.into_bytes(0));
                                r.cool_down(&placement.te_segment);
                                Fallback::Error
                            } else {
                                let bytes = slot.into_bytes(len);
                                if matches_checksum(resp.checksum.as_ref(), &bytes) {
                                    crate::gateway_metrics::record_shard_transfer("read", "rdma");
                                    return Ok(bytes);
                                }
                                r.quarantine(bytes);
                                r.cool_down(&placement.te_segment);
                                Fallback::Checksum
                            }
                        }
                        Err(e) => {
                            let reason = rdma_failure(r, &placement.te_segment, &e);
                            // The OSD may still be writing into this slot.
                            if reason != Fallback::OsdBusy {
                                r.quarantine(slot.into_bytes(0));
                            }
                            reason
                        }
                    };
                    crate::gateway_metrics::record_rdma_fallback("read", reason);
                    warn!(
                        "shard {position} from {} over rdma: {}; reading it over gRPC",
                        placement.node_address,
                        reason.label()
                    );
                }
            },
            Err(Some(reason)) => crate::gateway_metrics::record_rdma_fallback("read", reason),
            Err(None) => {}
        }
    }

    let request = ReadShardRequest {
        rdma_dest: None,
        shard_id: Some(shard_id),
        offset: 0,
        length: 0, // 0 means read all
    };
    let response = call_read_shard(pool, placement, request).await?;
    // The same check the rdma path makes. A shard damaged on the way is a
    // failed read, so the caller moves on to another shard or replica
    // instead of decoding the damage into the object.
    if !matches_checksum(response.checksum.as_ref(), &response.data) {
        crate::gateway_metrics::record_shard_checksum_mismatch("read");
        warn!(
            "shard {position} from {} does not match its checksum; not using it",
            placement.node_address
        );
        return Err(OsdPoolError::ChecksumMismatch(format!(
            "shard {position} from {}",
            placement.node_address
        )));
    }
    crate::gateway_metrics::record_shard_transfer("read", "grpc");
    Ok(response.data)
}

/// `length` bytes at `offset` of a shard, over gRPC: a packed object's
/// slice, without moving the whole shard. The OSD checks the whole shard
/// against its stored checksum before slicing, and the slice comes back
/// with a checksum of its own, checked here.
pub async fn read_shard_range_from_osd(
    pool: &OsdPool,
    placement: &NodePlacement,
    object_id: &[u8],
    stripe_id: u64,
    position: u32,
    offset: u64,
    length: u32,
) -> Result<Bytes, OsdPoolError> {
    use objectio_proto::storage::{ReadShardRequest, ShardId};
    let request = ReadShardRequest {
        rdma_dest: None,
        shard_id: Some(ShardId {
            object_id: object_id.to_vec(),
            stripe_id,
            position,
        }),
        offset,
        length,
    };
    let response = call_read_shard(pool, placement, request).await?;
    if !matches_checksum(response.checksum.as_ref(), &response.data) {
        crate::gateway_metrics::record_shard_checksum_mismatch("read");
        warn!(
            "shard {position} range from {} does not match its checksum; not using it",
            placement.node_address
        );
        return Err(OsdPoolError::ChecksumMismatch(format!(
            "shard {position} range from {}",
            placement.node_address
        )));
    }
    if response.data.len() > length as usize {
        return Err(OsdPoolError::ChecksumMismatch(format!(
            "shard {position} range from {}: {} bytes for a {length}-byte range",
            placement.node_address,
            response.data.len()
        )));
    }
    crate::gateway_metrics::record_shard_transfer("read", "grpc");
    Ok(response.data)
}

// ============================================================================
// Object Metadata Operations
//
// ObjectMeta is replicated on every shard-carrying OSD (MinIO xl.meta / Ceph
// OMAP style). Writes fan out to all k+m placements and require every replica
// to succeed. Reads try each placement in CRUSH order and return the first
// success. Deletes are best-effort across all replicas — a surviving stale
// copy is harmless because ObjectListingEntry is the source of truth for
// existence, and the next drain/rebalance sweep will GC it.
// ============================================================================

/// Deduplicate placements by node_id — `NodePlacement` carries a `position`
/// alongside the node, so the same OSD appears once per shard it owns. For
/// ObjectMeta fan-out we want one write per physical OSD.
fn unique_node_placements(placements: &[NodePlacement]) -> Vec<NodePlacement> {
    let mut seen: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(placements.len());
    for p in placements {
        if seen.insert(p.node_id.clone()) {
            out.push(p.clone());
        }
    }
    out
}

/// A failed [`put_object_meta_to_all`].
#[derive(Debug)]
pub struct MetaWriteError {
    pub error: OsdPoolError,
    /// No replica can have applied the write: each one was unreachable or
    /// refused it outright. Only then may the caller free the shards the
    /// write would have referenced — after a timeout, or an error from
    /// inside the OSD, a replica may hold the new ObjectMeta, and reads
    /// served from it would find its shards gone.
    pub unapplied: bool,
}

impl std::fmt::Display for MetaWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

/// Write ObjectMeta to every shard-carrying OSD in parallel. Requires all
/// replicas to accept — any failure fails the PUT and the caller surfaces a
/// retryable error to the S3 client.
///
/// `expected_object_id`, when not empty, makes each replica refuse the
/// write unless its current ObjectMeta for the key is that object: a
/// read-modify-write must not put back an object that a PUT replaced, or a
/// DELETE removed, and freed, after the read.
///
/// Returns what each replica displaced, for the caller to free.
pub async fn put_object_meta_to_all(
    pool: &OsdPool,
    placements: &[NodePlacement],
    bucket: &str,
    key: &str,
    object_meta: objectio_proto::metadata::ObjectMeta,
    versioning_enabled: bool,
    expected_object_id: &[u8],
) -> Result<Vec<Displaced>, MetaWriteError> {
    put_object_meta_with(
        pool,
        placements,
        bucket,
        key,
        object_meta,
        MetaWrite {
            versioning_enabled,
            expected_object_id,
            ..MetaWrite::default()
        },
    )
    .await
}

/// How [`put_object_meta_with`] writes.
#[derive(Default, Clone, Copy)]
pub struct MetaWrite<'a> {
    pub versioning_enabled: bool,
    /// Only over this object (an update), which must still exist.
    pub expected_object_id: &'a [u8],
    /// Only the version entry `object.version_id` (an update of a version
    /// that may not be current).
    pub version_only: bool,
    /// A replica: made current only if no newer version is.
    pub keep_newer_current: bool,
}

/// As [`put_object_meta_to_all`], with every option the OSD takes.
pub async fn put_object_meta_with(
    pool: &OsdPool,
    placements: &[NodePlacement],
    bucket: &str,
    key: &str,
    object_meta: objectio_proto::metadata::ObjectMeta,
    write: MetaWrite<'_>,
) -> Result<Vec<Displaced>, MetaWriteError> {
    use objectio_proto::storage::PutObjectMetaRequest;
    let MetaWrite {
        versioning_enabled,
        expected_object_id,
        version_only,
        keep_newer_current,
    } = write;

    let targets = unique_node_placements(placements);
    if targets.is_empty() {
        return Err(MetaWriteError {
            error: OsdPoolError::NoNodesAvailable,
            unapplied: true,
        });
    }

    // Exactly one replica counts the object in usage. Chosen from the
    // key's placement rather than the stripes: a multipart object's
    // stripes live wherever its parts were placed, which need not be any
    // of the OSDs holding this ObjectMeta.
    let mut object_meta = object_meta;
    object_meta.usage_owner.clone_from(&targets[0].node_id);
    // Every copy gets the same stamp, above any this one was read at: the
    // order the copies keep (core/object-metadata-quorum.md).
    object_meta.stamp = objectio_common::stamp::CLOCK.next_after(object_meta.stamp);

    let mut futs = Vec::with_capacity(targets.len());
    for placement in &targets {
        let req = PutObjectMetaRequest {
            // A write over an object read (an expected id) is an update of
            // it: one deleted since must not come back. Without this, a
            // DELETE between a tagging, retention, legal-hold or packing
            // update's read and its write brought the object back, naming
            // shards the DELETE had freed.
            require_existing: !expected_object_id.is_empty(),
            version_only,
            keep_newer_current,
            replication_update: false,
            replication_set: std::collections::HashMap::new(),
            bucket: bucket.to_string(),
            key: key.to_string(),
            object: Some(object_meta.clone()),
            versioning_enabled,
            expected_object_id: expected_object_id.to_vec(),
        };
        let p = placement.clone();
        // The bool on an error: this replica certainly did not apply it.
        futs.push(async move {
            let mut client = pool
                .get_client_for_placement(&p)
                .await
                .map_err(|e| (e, true))?;
            let fut = client.put_object_meta(req);
            let resp = tokio::time::timeout(std::time::Duration::from_secs(10), fut)
                .await
                .map_err(|_| {
                    error!("Timeout putting object metadata to OSD {}", p.node_address);
                    (
                        OsdPoolError::ConnectionFailed("put_object_meta timeout".to_string()),
                        false,
                    )
                })?
                .map_err(|e| {
                    error!(
                        "Failed to put object metadata to OSD {}: {}",
                        p.node_address, e
                    );
                    let refused = matches!(
                        e.code(),
                        tonic::Code::FailedPrecondition | tonic::Code::InvalidArgument
                    );
                    (OsdPoolError::ConnectionFailed(e.to_string()), refused)
                })?
                .into_inner();
            Ok::<_, (OsdPoolError, bool)>(Displaced {
                replaced: resp.replaced,
                version_kept: resp.replaced_version_kept,
                superseded: resp.superseded,
                missed: false,
            })
        });
    }

    let quorum = meta_write_quorum(targets.len());
    let results = futures::future::join_all(futs).await;
    let mut displaced = Vec::with_capacity(results.len());
    let mut failure: Option<OsdPoolError> = None;
    let mut unapplied = true;
    let mut applied = 0;
    for r in results {
        match r {
            Ok(d) => {
                unapplied = false;
                applied += 1;
                displaced.push(d);
            }
            Err((e, refused)) => {
                unapplied &= refused;
                failure.get_or_insert(e);
                // A copy that may hold what this write replaced: nothing
                // it could still name is freed (repair heals it).
                displaced.push(Displaced {
                    replaced: None,
                    version_kept: false,
                    superseded: false,
                    missed: true,
                });
            }
        }
    }
    match failure {
        Some(error) if applied < quorum => Err(MetaWriteError { error, unapplied }),
        Some(error) => {
            warn!(
                "{bucket}/{key}: metadata on {applied} of {} copies (quorum {quorum}); \
                 the rest are healed: {error}",
                targets.len()
            );
            pool.queue_heal(bucket, key, &object_meta.version_id).await;
            Ok(displaced)
        }
        None => Ok(displaced),
    }
}

/// How many copies of a key's ObjectMeta a write (or delete) needs
/// (core/object-metadata-quorum.md): a majority. Every copy until the
/// cluster is finalized at the level that allows it: a reader from the
/// release before takes the first copy that answers.
fn meta_write_quorum(copies: usize) -> usize {
    if objectio_common::version::allows(2) {
        copies / 2 + 1
    } else {
        copies
    }
}

/// How many copies a read must hear from: enough to include one that took
/// the last acknowledged write.
fn meta_read_quorum(copies: usize) -> usize {
    copies - meta_write_quorum(copies) + 1
}

/// Read ObjectMeta from the shard-carrying OSDs: every copy at once, and the
/// newest (highest stamp) that has it. Returns `Ok(None)` only when every
/// reachable copy reports not-found — a mixed outcome (some down, some report
/// Some) returns the Some. Returns `Err` only if every copy errored (no
/// authoritative answer).
pub async fn get_object_meta_from_any(
    pool: &OsdPool,
    placements: &[NodePlacement],
    bucket: &str,
    key: &str,
) -> Result<Option<objectio_proto::metadata::ObjectMeta>, OsdPoolError> {
    get_object_version_meta_from_any(pool, placements, bucket, key, "").await
}

/// As [`get_object_meta_from_any`], for one version of the key; an empty
/// `version_id` is the current object.
pub async fn get_object_version_meta_from_any(
    pool: &OsdPool,
    placements: &[NodePlacement],
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<Option<objectio_proto::metadata::ObjectMeta>, OsdPoolError> {
    use objectio_proto::storage::GetObjectMetaRequest;

    let targets = unique_node_placements(placements);
    if targets.is_empty() {
        return Err(OsdPoolError::NoNodesAvailable);
    }

    // Every copy at once; the newest that has it wins
    // (core/object-metadata-quorum.md). A copy that lacks it may just not
    // have it yet (a new OSD during a drain), so "not found" is the answer
    // only when no copy has it.
    let asks = targets.iter().map(|placement| async move {
        let req = GetObjectMetaRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            version_id: version_id.to_string(),
        };
        let mut client = pool
            .get_client_for_placement(placement)
            .await
            .map_err(|e| {
                warn!(
                    "get_object_meta: connect failed to {}: {}",
                    placement.node_address, e
                );
                e
            })?;
        match tokio::time::timeout(
            std::time::Duration::from_secs(10),
            client.get_object_meta(req),
        )
        .await
        {
            Ok(Ok(resp)) => {
                let inner = resp.into_inner();
                Ok((
                    if inner.found { inner.object } else { None },
                    inner.tombstone_stamp,
                ))
            }
            Ok(Err(e)) => {
                warn!(
                    "get_object_meta from {} failed: {}",
                    placement.node_address, e
                );
                if is_transport_failure(&e) {
                    pool.mark_unreachable(&placement.node_address);
                }
                Err(OsdPoolError::ConnectionFailed(e.to_string()))
            }
            Err(_) => {
                warn!("get_object_meta timeout from {}", placement.node_address);
                Err(OsdPoolError::ConnectionFailed(
                    "get_object_meta timeout".to_string(),
                ))
            }
        }
    });
    let answers = futures::future::join_all(asks).await;

    let mut newest: Option<objectio_proto::metadata::ObjectMeta> = None;
    let mut deleted_at = 0u64;
    let mut answered = 0;
    let mut last_err: Option<OsdPoolError> = None;
    for answer in answers {
        match answer {
            Ok((found, tombstone)) => {
                answered += 1;
                deleted_at = deleted_at.max(tombstone);
                if let Some(o) = found
                    && newest
                        .as_ref()
                        .is_none_or(|n| (o.stamp, &o.object_id) > (n.stamp, &n.object_id))
                {
                    newest = Some(o);
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    // Fewer answers than a read quorum could all be copies that missed the
    // last write: no answer rather than a stale one.
    if answered < meta_read_quorum(targets.len()) {
        return Err(last_err.unwrap_or(OsdPoolError::NoNodesAvailable));
    }
    // A delete newer than every copy's object: gone, whatever a copy that
    // missed the delete still holds.
    if let Some(o) = newest.take_if(|o| deleted_at < o.stamp || deleted_at == 0) {
        if o.required_level > objectio_common::version::FORMAT_LEVEL {
            return Err(OsdPoolError::TooOld(format!(
                "{bucket}/{key} needs format level {}; this gateway is at {}",
                o.required_level,
                objectio_common::version::FORMAT_LEVEL
            )));
        }
        return Ok(Some(o));
    }
    Ok(None)
}

/// One OSD's copy of one version of `key` (`""`: the current one). An
/// error says this copy couldn't be read, not that there is none.
pub async fn get_object_version_meta_from_osd(
    pool: &OsdPool,
    primary_placement: &NodePlacement,
    bucket: &str,
    key: &str,
    version_id: &str,
) -> Result<Option<objectio_proto::metadata::ObjectMeta>, OsdPoolError> {
    use objectio_proto::storage::GetObjectMetaRequest;

    let mut client = pool.get_client_for_placement(primary_placement).await?;

    let request = GetObjectMetaRequest {
        bucket: bucket.to_string(),
        key: key.to_string(),
        version_id: version_id.to_string(),
    };

    let get_future = client.get_object_meta(request);
    let response = tokio::time::timeout(std::time::Duration::from_secs(10), get_future)
        .await
        .map_err(|_| {
            error!(
                "Timeout getting object metadata from OSD {}",
                primary_placement.node_address
            );
            OsdPoolError::ConnectionFailed("get_object_meta timeout".to_string())
        })?
        .map_err(|e| {
            warn!(
                "Failed to get object metadata from OSD {}: {}",
                primary_placement.node_address, e
            );
            OsdPoolError::ConnectionFailed(e.to_string())
        })?;

    let inner = response.into_inner();
    if inner.found {
        Ok(inner.object)
    } else {
        Ok(None)
    }
}

/// What a delete of `bucket/key` (or one version of it) did on its
/// replicas.
#[derive(Debug, Default)]
pub struct MetaDeleted {
    /// Replicas that carried it out (or already held something newer), of
    /// how many, and how many the delete needs.
    pub ok: usize,
    pub of: usize,
    pub quorum: usize,
    /// What those replicas removed, as each had it. Replicas can disagree
    /// (a write racing the delete): each is what that copy named.
    pub removed: Vec<objectio_proto::metadata::ObjectMeta>,
}

/// Delete the current object (`version_id` empty) or one version of
/// `bucket/key` from every replica. For a version, each OSD makes the
/// newest remaining one current if it was, under the key's lock.
pub async fn delete_meta_from_all(
    pool: &OsdPool,
    placements: &[NodePlacement],
    bucket: &str,
    key: &str,
    version_id: &str,
) -> MetaDeleted {
    use objectio_proto::storage::DeleteObjectMetaRequest;

    let targets = unique_node_placements(placements);
    // Every copy records the same stamp as its tombstone.
    let stamp = objectio_common::stamp::CLOCK.now();
    let futs = targets.iter().map(|p| async move {
        let mut client = pool.get_client_for_placement(p).await?;
        let fut = client.delete_object_meta(DeleteObjectMetaRequest {
            bucket: bucket.to_string(),
            key: key.to_string(),
            version_id: version_id.to_string(),
            stamp,
        });
        let resp = tokio::time::timeout(std::time::Duration::from_secs(10), fut)
            .await
            .map_err(|_| OsdPoolError::ConnectionFailed("delete_object_meta timeout".into()))?
            .map_err(|e| OsdPoolError::ConnectionFailed(e.to_string()))?;
        Ok::<_, OsdPoolError>(resp.into_inner().removed)
    });
    let mut out = MetaDeleted {
        of: targets.len(),
        quorum: meta_write_quorum(targets.len()),
        ..MetaDeleted::default()
    };
    for r in futures::future::join_all(futs).await {
        match r {
            Ok(removed) => {
                out.ok += 1;
                out.removed.extend(removed);
            }
            Err(e) => warn!("delete {bucket}/{key} (version {version_id:?}): {e}"),
        }
    }
    if out.ok >= out.quorum && out.ok < out.of {
        pool.queue_heal(bucket, key, version_id).await;
    }
    out
}

/// Of the objects a delete removed, those no replica still has as its
/// current object: what may be freed. A write racing the delete can leave
/// an object current on some replicas (they saw the write after the
/// delete); freeing it would leave them naming shards that are gone. Any
/// replica that can't be read keeps everything: a leak, never a loss. An
/// object gone from every replica can't come back: an update of one
/// requires it to exist, and a PUT always writes a new one.
pub async fn unreferenced(
    pool: &OsdPool,
    placements: &[NodePlacement],
    bucket: &str,
    key: &str,
    removed: Vec<objectio_proto::metadata::ObjectMeta>,
) -> Vec<objectio_proto::metadata::ObjectMeta> {
    let mut distinct: Vec<objectio_proto::metadata::ObjectMeta> = Vec::new();
    for o in removed {
        if !o.object_id.is_empty() && !distinct.contains(&o) {
            distinct.push(o);
        }
    }
    if distinct.is_empty() {
        return distinct;
    }
    // Every replica's current object, and the version entry of each removed
    // object that has one (an object kept as a version too stays).
    let versions: std::collections::BTreeSet<String> = distinct
        .iter()
        .map(|o| o.version_id.clone())
        .filter(|v| !v.is_empty())
        .collect();
    let mut held = std::collections::HashSet::new();
    for p in &unique_node_placements(placements) {
        for v in std::iter::once(String::new()).chain(versions.iter().cloned()) {
            match get_object_version_meta_from_osd(pool, p, bucket, key, &v).await {
                Ok(Some(o)) => {
                    held.insert(o.object_id);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(
                        "{bucket}/{key}: a replica can't be read after the delete ({e}); \
                         its blocks stay allocated"
                    );
                    return Vec::new();
                }
            }
        }
    }
    distinct
        .into_iter()
        .filter(|o| !held.contains(&o.object_id))
        .collect()
}

// ============================================================================
// Shard reclamation
//
// A shard is referenced by the ObjectMeta that lists it, or by a multipart
// upload's part, and by nothing else. Whatever stops referencing a shard —
// a delete, an overwrite, a re-uploaded or abandoned part, a write that
// failed half way — has to delete it, or its block stays allocated forever
// with nothing left that knows where it is.
// ============================================================================

/// Why shards are being freed: the `reason` label on the reclaim metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reclaim {
    /// The object was deleted.
    Delete,
    /// A write to the key replaced the object.
    Overwrite,
    /// The write that sent them failed before its object was committed.
    FailedWrite,
    /// The same part number was uploaded again.
    ReplacedPart,
    /// The part was uploaded but left out of the completed object.
    UnusedPart,
    /// The multipart upload was aborted.
    Abort,
    /// The object moved into a pack: its own stripe goes.
    Packed,
}

impl Reclaim {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::Overwrite => "overwrite",
            Self::FailedWrite => "failed_write",
            Self::Packed => "packed",
            Self::ReplacedPart => "replaced_part",
            Self::UnusedPart => "unused_part",
            Self::Abort => "abort",
        }
    }
}

/// One shard to delete, and the OSD holding it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ShardTarget {
    pub node_id: Vec<u8>,
    /// The OSD's address when the caller knows it; empty to look it up.
    pub address: String,
    pub object_id: Vec<u8>,
    pub stripe_id: u64,
    pub position: u32,
    /// The object letting the shard go. A stripe shared with other objects
    /// (a zero-copy copy) is freed only when its last referrer lets go;
    /// see meta's `ReleaseStripes`.
    pub owner: Vec<u8>,
}

/// Every shard of `object`'s stripes, released on the object's behalf.
#[must_use]
pub fn stripe_targets_of(object: &objectio_proto::metadata::ObjectMeta) -> Vec<ShardTarget> {
    let mut targets = stripe_targets(&object.stripes);
    if !object.object_id.is_empty() {
        for t in &mut targets {
            t.owner.clone_from(&object.object_id);
        }
    }
    targets
}

/// Every shard `stripes` records, at the node its location names.
///
/// Routed by `ShardLocation::node_id` because that is where the shard is:
/// a multipart object's parts are placed by their own keys, and a drained
/// shard has moved, so the key's current placement can miss both.
#[must_use]
pub fn stripe_targets(stripes: &[objectio_proto::metadata::StripeMeta]) -> Vec<ShardTarget> {
    let mut seen = std::collections::HashSet::new();
    stripes
        .iter()
        .filter(|stripe| !stripe.object_id.is_empty() || !stripe.pack_id.is_empty())
        .flat_map(|stripe| {
            // A slice of a pack holds no shards of its own: one marker
            // stands for its reference to the pack, which reclaim releases
            // and, if it was the pack's last, expands into the pack's shards.
            let marker = (!stripe.pack_id.is_empty()).then(|| ShardTarget {
                node_id: Vec::new(),
                address: String::new(),
                object_id: stripe.pack_id.clone(),
                stripe_id: stripe.stripe_id,
                position: PACK_MARKER,
                owner: stripe.pack_id.clone(),
            });
            let shards = stripe
                .shards
                .iter()
                .filter(|_| stripe.pack_id.is_empty())
                .map(move |shard| ShardTarget {
                    node_id: shard.node_id.clone(),
                    address: String::new(),
                    object_id: stripe.object_id.clone(),
                    stripe_id: stripe.stripe_id,
                    position: shard.position,
                    // Unless the caller knows better: the stripe's own writer.
                    owner: stripe.object_id.clone(),
                });
            marker.into_iter().chain(shards)
        })
        .filter(|t| (t.is_pack_marker() || !t.node_id.is_empty()) && seen.insert(t.clone()))
        .collect()
}

/// [`ShardTarget::position`] of a pack marker.
const PACK_MARKER: u32 = u32::MAX;

impl ShardTarget {
    /// A packed object's reference to its pack, not a shard.
    #[must_use]
    pub const fn is_pack_marker(&self) -> bool {
        self.position == PACK_MARKER && self.node_id.is_empty()
    }
}

/// The object ids whose shards `object` refers to: its own, and each
/// stripe's (a multipart object's stripes carry their parts' ids).
#[must_use]
pub fn referenced_object_ids(
    object: &objectio_proto::metadata::ObjectMeta,
) -> std::collections::HashSet<Vec<u8>> {
    std::iter::once(object.object_id.clone())
        .chain(object.stripes.iter().map(|s| s.object_id.clone()))
        .filter(|id| !id.is_empty())
        .collect()
}

/// What one replica's `PutObjectMeta` displaced.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Displaced {
    pub replaced: Option<objectio_proto::metadata::ObjectMeta>,
    /// The replaced object is still held there as a version.
    pub version_kept: bool,
    /// That copy already held a newer write; this one was not applied.
    pub superseded: bool,
    /// That copy did not answer: it may still hold what this write replaced.
    pub missed: bool,
}

/// Shards of the object an overwrite displaced, if it is safe to free them.
///
/// Only when every replica displaced the same object, and none still keeps
/// it as a version. Each OSD applies writes to a key one at a time, but two
/// concurrent PUTs can reach the replicas in different orders: then one
/// replica reports the other PUT's object as replaced while another still
/// holds it as current. Agreement across every replica rules that out — if
/// all of them replaced X with this write, none of them holds X any more —
/// and costs only a leaked object in the rare split case.
///
/// `keep` is what the new object refers to; nothing in it is freed, which
/// covers a metadata-only rewrite of the same object.
#[must_use]
pub fn reclaimable_after_overwrite(
    replies: &[Displaced],
    keep: &std::collections::HashSet<Vec<u8>>,
) -> Vec<ShardTarget> {
    let Some(first) = replies.first().and_then(|d| d.replaced.as_ref()) else {
        return Vec::new();
    };
    let unanimous = replies.iter().all(|d| {
        !d.version_kept
            && d.replaced
                .as_ref()
                .is_some_and(|r| r.object_id == first.object_id)
    });
    if !unanimous || first.object_id.is_empty() || keep.contains(&first.object_id) {
        return Vec::new();
    }
    // Replicas can disagree on where a shard is while a migration is
    // refreshing them; deleting at every location any of them names is
    // harmless where the shard is not.
    let mut seen = std::collections::HashSet::new();
    replies
        .iter()
        .filter_map(|d| d.replaced.as_ref())
        .flat_map(stripe_targets_of)
        .filter(|t| !keep.contains(&t.object_id) && seen.insert(t.clone()))
        .collect()
}

/// Release each target's stripe on its owner's behalf, and return the
/// `(owner, stripe)` pairs whose stripes no object references any more.
/// What releasing `targets` freed: `(owner, stripe id)` pairs whose shards
/// may go, and the packs whose last object let go.
async fn freeable(
    meta: &mut objectio_proto::metadata::metadata_service_client::MetadataServiceClient<Channel>,
    targets: &[ShardTarget],
) -> Result<
    (
        std::collections::HashSet<(Vec<u8>, Vec<u8>)>,
        Vec<objectio_proto::metadata::StripeMeta>,
    ),
    tonic::Status,
> {
    let mut by_owner: HashMap<Vec<u8>, std::collections::BTreeSet<Vec<u8>>> = HashMap::new();
    for t in targets {
        by_owner
            .entry(t.owner.clone())
            .or_default()
            .insert(t.object_id.clone());
    }
    let mut free = std::collections::HashSet::new();
    let mut packs = Vec::new();
    for (owner, ids) in by_owner {
        let req = objectio_proto::metadata::ReleaseStripesRequest {
            stripe_ids: ids.into_iter().collect(),
            referrer: owner.clone(),
        };
        // Meta answers Aborted when the entry kept changing under it (many
        // releases of one pack at once): try again, a little later.
        let mut attempt = 0u32;
        let resp = loop {
            match meta.release_stripes(req.clone()).await {
                Err(e) if e.code() == tonic::Code::Aborted && attempt < 4 => {
                    attempt += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(50 << attempt)).await;
                }
                other => break other?.into_inner(),
            }
        };
        free.extend(resp.freeable.into_iter().map(|id| (owner.clone(), id)));
        packs.extend(resp.freed_packs);
    }
    Ok((free, packs))
}

/// Drop `owner`'s reference to `stripe_ids` without deleting anything: an
/// object replaced by one that still uses these stripes (a copy onto
/// itself) stops referencing them, but they are not free.
pub async fn release_only(
    meta: &mut objectio_proto::metadata::metadata_service_client::MetadataServiceClient<Channel>,
    owner: &[u8],
    stripe_ids: Vec<Vec<u8>>,
) {
    if owner.is_empty() || stripe_ids.is_empty() {
        return;
    }
    if let Err(e) = meta
        .release_stripes(objectio_proto::metadata::ReleaseStripesRequest {
            stripe_ids,
            referrer: owner.to_vec(),
        })
        .await
    {
        warn!("could not release a replaced object's shared stripes: {e}");
    }
}

/// Shards a write has sent to OSDs, freed again if the write is abandoned —
/// an error return, or the request future being dropped mid-write.
///
/// Every shard is recorded when it is sent, not when it is acknowledged: a
/// write that timed out may still have landed. [`Self::disarm`] hands the
/// list over once the write's metadata commit begins, because from then on
/// a replica may reference these shards and only the commit's outcome says
/// whether they can go.
pub struct PendingShards {
    targets: Vec<ShardTarget>,
    on_abandon: Option<Box<dyn FnOnce(Vec<ShardTarget>) + Send>>,
}

impl PendingShards {
    pub fn new(on_abandon: impl FnOnce(Vec<ShardTarget>) + Send + 'static) -> Self {
        Self {
            targets: Vec::new(),
            on_abandon: Some(Box::new(on_abandon)),
        }
    }

    /// Record a shard about to be written to `placement`.
    pub fn sent(
        &mut self,
        placement: &NodePlacement,
        object_id: &[u8],
        stripe_id: u64,
        position: u32,
    ) {
        self.targets.push(ShardTarget {
            node_id: placement.node_id.clone(),
            address: placement.node_address.clone(),
            object_id: object_id.to_vec(),
            stripe_id,
            position,
            owner: object_id.to_vec(),
        });
    }

    /// Stop freeing on drop; returns what was sent.
    #[must_use]
    pub fn disarm(mut self) -> Vec<ShardTarget> {
        self.on_abandon = None;
        std::mem::take(&mut self.targets)
    }
}

impl Drop for PendingShards {
    fn drop(&mut self) {
        if let Some(f) = self.on_abandon.take()
            && !self.targets.is_empty()
        {
            f(std::mem::take(&mut self.targets));
        }
    }
}

/// How many shards [`reclaim_shards`] deletes at once.
const RECLAIM_CONCURRENCY: usize = 64;

/// Delete `targets` from the OSDs holding them, and count the outcome.
///
/// Best-effort by design: a shard that cannot be deleted now is a leaked
/// block, not a correctness problem, so this never fails the caller. An OSD
/// that does not hold a shard answers `success: false`, which is not a
/// failure — deleting is idempotent under retry. Returns how many deletes
/// failed.
pub async fn reclaim_shards(
    pool: &OsdPool,
    meta: &mut objectio_proto::metadata::metadata_service_client::MetadataServiceClient<Channel>,
    targets: Vec<ShardTarget>,
    reason: Reclaim,
) -> usize {
    use futures::StreamExt;
    use objectio_proto::storage::{DeleteShardRequest, ShardId};

    if targets.is_empty() {
        return 0;
    }

    // Only stripes no other object still references may go. Asked of meta
    // once per releasing object; if meta cannot answer, nothing is deleted
    // — a leak can be reclaimed later, deleted shared data cannot.
    let total = targets.len();
    let targets = match freeable(meta, &targets).await {
        Ok((free, packs)) => {
            let mut freed: Vec<ShardTarget> = targets
                .into_iter()
                .filter(|t| {
                    !t.is_pack_marker() && free.contains(&(t.owner.clone(), t.object_id.clone()))
                })
                .collect();
            // A pack its last object let go: meta dropped its record in
            // the same commit, so its shards are nobody's.
            for mut pack in packs {
                pack.pack_id.clear();
                freed.extend(stripe_targets(std::slice::from_ref(&pack)));
            }
            freed
        }
        Err(e) => {
            warn!("reclaim: cannot ask meta which stripes are still shared, keeping them: {e}");
            crate::gateway_metrics::record_reclaim(reason.label(), 0, total as u64);
            return total;
        }
    };
    if targets.is_empty() {
        return 0;
    }

    // One client per OSD: connected already, at an address the caller gave,
    // or — after a restart, or for a node outside this request's placement —
    // at the address meta has registered for it, asked once.
    let mut clients: HashMap<Vec<u8>, StorageServiceClient<Channel>> = HashMap::new();
    let mut addresses: HashMap<Vec<u8>, String> = targets
        .iter()
        .filter(|t| !t.address.is_empty())
        .map(|t| (t.node_id.clone(), t.address.clone()))
        .collect();
    let mut asked_meta = false;
    let node_ids: std::collections::HashSet<Vec<u8>> =
        targets.iter().map(|t| t.node_id.clone()).collect();
    for node_id in node_ids {
        if let Ok(client) = pool.get_client(&node_id).await {
            clients.insert(node_id, client);
            continue;
        }
        if !addresses.contains_key(&node_id) && !asked_meta {
            asked_meta = true;
            match meta
                .get_listing_nodes(objectio_proto::metadata::GetListingNodesRequest {
                    bucket: String::new(),
                    include_all_states: true,
                })
                .await
            {
                Ok(resp) => {
                    for n in resp.into_inner().nodes {
                        addresses.entry(n.node_id).or_insert(n.address);
                    }
                }
                Err(e) => warn!("reclaim: could not list OSD addresses: {e}"),
            }
        }
        match addresses.get(&node_id) {
            Some(addr) => match pool.get_or_connect(&node_id, addr).await {
                Ok(client) => {
                    clients.insert(node_id, client);
                }
                Err(e) => warn!("reclaim: cannot reach OSD {addr}: {e}"),
            },
            None => warn!("reclaim: no address for OSD {}", hex::encode(&node_id)),
        }
    }

    let results: Vec<Result<bool, OsdPoolError>> = futures::stream::iter(targets)
        .map(|t| {
            let client = clients.get(&t.node_id).cloned();
            async move {
                let mut client =
                    client.ok_or_else(|| OsdPoolError::NodeNotFound(hex::encode(&t.node_id)))?;
                let req = DeleteShardRequest {
                    shard_id: Some(ShardId {
                        object_id: t.object_id,
                        stripe_id: t.stripe_id,
                        position: t.position,
                    }),
                };
                let resp = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    client.delete_shard(req),
                )
                .await
                .map_err(|_| OsdPoolError::ConnectionFailed("delete_shard timeout".into()))?
                .map_err(|e| OsdPoolError::ConnectionFailed(e.to_string()))?;
                Ok(resp.into_inner().success)
            }
        })
        .buffer_unordered(RECLAIM_CONCURRENCY)
        .collect()
        .await;

    let mut reclaimed = 0u64;
    let mut failed = 0usize;
    for r in results {
        match r {
            Ok(true) => reclaimed += 1,
            Ok(false) => {}
            Err(e) => {
                failed += 1;
                warn!("reclaim ({}): delete_shard failed: {e}", reason.label());
            }
        }
    }
    crate::gateway_metrics::record_reclaim(reason.label(), reclaimed, failed as u64);
    failed
}

#[cfg(test)]
mod reclaim_tests {
    use super::*;
    use objectio_proto::metadata::{ObjectMeta, ShardLocation, StripeMeta};
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    /// A stripe of object `id`, its shard at each position on node `n`+pos.
    fn stripe(id: u8, stripe_id: u64, n: u8, shards: u32) -> StripeMeta {
        StripeMeta {
            stripe_id,
            object_id: vec![id; 16],
            shards: (0..shards)
                .map(|position| ShardLocation {
                    position,
                    node_id: vec![n + u8::try_from(position).unwrap(); 16],
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    fn object(id: u8, stripes: Vec<StripeMeta>) -> ObjectMeta {
        ObjectMeta {
            object_id: vec![id; 16],
            stripes,
            ..Default::default()
        }
    }

    fn replaced(o: &ObjectMeta) -> Displaced {
        Displaced {
            replaced: Some(o.clone()),
            version_kept: false,
            superseded: false,
            missed: false,
        }
    }

    fn keep(o: &ObjectMeta) -> HashSet<Vec<u8>> {
        referenced_object_ids(o)
    }

    #[test]
    fn shards_are_addressed_to_the_node_holding_them() {
        let t = stripe_targets(&[stripe(1, 0, 10, 3), stripe(1, 1, 20, 3)]);
        assert_eq!(t.len(), 6);
        assert!(t.iter().all(|t| t.object_id == vec![1; 16]));
        let s1: Vec<u8> = t
            .iter()
            .filter(|t| t.stripe_id == 1)
            .map(|t| t.node_id[0])
            .collect();
        assert_eq!(s1, [20, 21, 22]);
    }

    /// Each part of a multipart object is its own object id, on its own
    /// placement.
    #[test]
    fn a_multipart_objects_stripes_keep_their_parts_ids() {
        let o = object(9, vec![stripe(1, 0, 10, 2), stripe(2, 0, 30, 2)]);
        let ids: HashSet<Vec<u8>> = stripe_targets(&o.stripes)
            .into_iter()
            .map(|t| t.object_id)
            .collect();
        assert_eq!(ids, HashSet::from([vec![1; 16], vec![2; 16]]));
        assert_eq!(keep(&o).len(), 3);
    }

    #[test]
    fn an_agreed_overwrite_frees_the_old_object() {
        let old = object(1, vec![stripe(1, 0, 10, 6)]);
        let new = object(2, vec![stripe(2, 0, 10, 6)]);
        let got = reclaimable_after_overwrite(&[replaced(&old), replaced(&old)], &keep(&new));
        assert_eq!(got, stripe_targets(&old.stripes));
    }

    #[test]
    fn a_new_key_frees_nothing() {
        let new = object(2, vec![]);
        assert!(reclaimable_after_overwrite(&[Displaced::default()], &keep(&new)).is_empty());
        assert!(reclaimable_after_overwrite(&[], &keep(&new)).is_empty());
    }

    /// Two PUTs that reached the replicas in different orders: each sees the
    /// other's object as replaced on some replica, while another replica
    /// still holds it. Neither may free anything.
    #[test]
    fn replicas_that_disagree_free_nothing() {
        let a = object(1, vec![stripe(1, 0, 10, 2)]);
        let b = object(2, vec![stripe(2, 0, 10, 2)]);
        let x = object(3, vec![stripe(3, 0, 10, 2)]);
        assert!(reclaimable_after_overwrite(&[replaced(&x), replaced(&b)], &keep(&a)).is_empty());
        assert!(
            reclaimable_after_overwrite(&[Displaced::default(), replaced(&b)], &keep(&a))
                .is_empty()
        );
    }

    #[test]
    fn an_object_kept_as_a_version_is_not_freed() {
        let old = object(1, vec![stripe(1, 0, 10, 2)]);
        let new = object(2, vec![]);
        let kept = Displaced {
            replaced: Some(old.clone()),
            version_kept: true,
            superseded: false,
            missed: false,
        };
        assert!(reclaimable_after_overwrite(&[replaced(&old), kept], &keep(&new)).is_empty());
    }

    /// Retention, legal hold and shard migration rewrite the same object.
    #[test]
    fn rewriting_the_same_object_frees_nothing() {
        let o = object(1, vec![stripe(1, 0, 10, 2)]);
        assert!(reclaimable_after_overwrite(&[replaced(&o)], &keep(&o)).is_empty());
    }

    /// Nothing the new object still refers to is freed, whatever the old
    /// one was called.
    #[test]
    fn stripes_the_new_object_shares_are_kept() {
        let old = object(1, vec![stripe(7, 0, 10, 2), stripe(8, 0, 20, 2)]);
        let new = object(2, vec![stripe(8, 0, 20, 2)]);
        let got = reclaimable_after_overwrite(&[replaced(&old)], &keep(&new));
        assert!(got.iter().all(|t| t.object_id == vec![7; 16]));
        assert_eq!(got.len(), 2);
    }

    /// While a migration refreshes the replicas they can name different
    /// nodes for a shard; it is deleted wherever any of them says it is.
    #[test]
    fn locations_from_every_replica_are_freed() {
        let here = object(1, vec![stripe(1, 0, 10, 2)]);
        let moved = object(1, vec![stripe(1, 0, 40, 2)]);
        let got = reclaimable_after_overwrite(
            &[replaced(&here), replaced(&moved)],
            &keep(&object(2, vec![])),
        );
        let nodes: HashSet<u8> = got.iter().map(|t| t.node_id[0]).collect();
        assert_eq!(nodes, HashSet::from([10, 11, 40, 41]));
    }

    fn recorder() -> (Arc<Mutex<Vec<ShardTarget>>>, PendingShards) {
        let freed = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&freed);
        let pending = PendingShards::new(move |t| sink.lock().unwrap().extend(t));
        (freed, pending)
    }

    fn node(n: u8) -> NodePlacement {
        NodePlacement {
            node_id: vec![n; 16],
            node_address: format!("http://osd{n}:9200"),
            ..Default::default()
        }
    }

    /// An error return, or the request being dropped mid-write, frees every
    /// shard sent — acknowledged or not, since a timed-out write may land.
    #[test]
    fn an_abandoned_write_frees_every_shard_it_sent() {
        let (freed, mut pending) = recorder();
        pending.sent(&node(1), &[5; 16], 0, 0);
        pending.sent(&node(2), &[5; 16], 0, 1);
        drop(pending);
        let freed = freed.lock().unwrap();
        assert_eq!(freed.len(), 2);
        assert_eq!(freed[1].address, "http://osd2:9200");
        assert_eq!(freed[1].position, 1);
    }

    #[test]
    fn a_write_that_reached_its_commit_frees_nothing_by_itself() {
        let (freed, mut pending) = recorder();
        pending.sent(&node(1), &[5; 16], 0, 0);
        let sent = pending.disarm();
        assert_eq!(sent.len(), 1);
        assert!(freed.lock().unwrap().is_empty());
    }

    /// Reclaim against an OSD that cannot be reached counts a failure and
    /// returns, rather than failing whatever triggered it.
    #[tokio::test]
    async fn an_unreachable_osd_is_counted_not_fatal() {
        let pool = OsdPool::new();
        let meta = tonic::transport::Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
        let mut meta =
            objectio_proto::metadata::metadata_service_client::MetadataServiceClient::new(meta);
        let target = ShardTarget {
            node_id: vec![1; 16],
            address: "http://127.0.0.1:1".into(),
            object_id: vec![5; 16],
            stripe_id: 0,
            position: 0,
            owner: vec![5; 16],
        };
        let failed = reclaim_shards(&pool, &mut meta, vec![target], Reclaim::FailedWrite).await;
        assert_eq!(failed, 1);
        assert!(
            crate::gateway_metrics::render()
                .contains("objectio_gateway_shard_reclaim_failures_total{reason=\"failed_write\"}")
        );
    }
}

#[cfg(test)]
mod quorum_tests {
    use super::*;

    /// A majority writes, and reads hear from enough copies to overlap it.
    #[test]
    fn the_metadata_quorums() {
        objectio_common::version::set_active_level(2);
        for (copies, write, read) in [(6, 4, 3), (12, 7, 6), (3, 2, 2), (1, 1, 1)] {
            assert_eq!(meta_write_quorum(copies), write, "{copies} copies");
            assert_eq!(meta_read_quorum(copies), read, "{copies} copies");
            assert!(write + read > copies);
        }
    }
}

#[cfg(test)]
mod fail_fast_tests {
    use super::*;

    /// An address that just failed is not tried for FAIL_FAST, then is.
    #[tokio::test]
    async fn an_unreachable_osd_fails_fast_for_a_while() {
        let pool = OsdPool::new();
        let addr = "http://10.0.0.1:9200";
        pool.mark_unreachable(addr);
        let r = pool.get_or_connect(&[1u8; 16], addr).await;
        assert!(matches!(r, Err(OsdPoolError::ConnectionFailed(m)) if m.contains("not tried")));

        // Once the window has passed, it is tried again.
        pool.unreachable.lock().unwrap().insert(
            addr.to_string(),
            std::time::Instant::now().checked_sub(FAIL_FAST).unwrap(),
        );
        assert!(!pool.is_unreachable(addr));
    }
}

#[cfg(test)]
mod tests {
    use super::matches_checksum;
    use objectio_proto::storage::Checksum;

    fn checksum(crc32c: u32) -> Checksum {
        Checksum {
            crc32c,
            ..Default::default()
        }
    }

    #[test]
    fn a_shard_matches_the_checksum_of_its_own_bytes() {
        let data = b"a shard as the osd stored it";
        assert!(matches_checksum(
            Some(&checksum(crc32c::crc32c(data))),
            data
        ));
    }

    /// Without this a shard damaged between OSD and gateway is decoded into
    /// the object and handed to the client as good.
    #[test]
    fn a_damaged_shard_does_not_match() {
        let data = b"a shard as the osd stored it".to_vec();
        let sent = checksum(crc32c::crc32c(&data));
        let mut damaged = data;
        damaged[3] ^= 0x10;
        assert!(!matches_checksum(Some(&sent), &damaged));
        assert!(!matches_checksum(
            Some(&sent),
            &damaged[..damaged.len() - 1]
        ));
    }

    #[test]
    fn a_response_without_a_checksum_is_taken_as_is() {
        assert!(matches_checksum(None, b"anything"));
    }
}

/// Record `status` for replication `target` on every copy of `version`
/// (its version entry, and the current entry if it is that version),
/// changing nothing else: each OSD merges just the status under the key's
/// lock, so a tag or retention change made since `version` was read stays.
/// Succeeds if any copy took it.
pub async fn set_replication_status(
    pool: &OsdPool,
    placements: &[NodePlacement],
    version: &objectio_proto::metadata::ObjectMeta,
    target: &str,
    status: &str,
) -> Result<(), OsdPoolError> {
    use objectio_proto::storage::PutObjectMetaRequest;
    let only_ids = objectio_proto::metadata::ObjectMeta {
        object_id: version.object_id.clone(),
        version_id: version.version_id.clone(),
        ..Default::default()
    };
    let targets = unique_node_placements(placements);
    let futs = targets.iter().map(|p| {
        let req = PutObjectMetaRequest {
            bucket: version.bucket.clone(),
            key: version.key.clone(),
            object: Some(only_ids.clone()),
            replication_update: true,
            replication_set: std::iter::once((target.to_string(), status.to_string())).collect(),
            ..Default::default()
        };
        async move {
            let mut client = pool.get_client_for_placement(p).await?;
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                client.put_object_meta(req),
            )
            .await
            .map_err(|_| OsdPoolError::ConnectionFailed("put_object_meta timeout".into()))?
            .map_err(|e| OsdPoolError::ConnectionFailed(e.to_string()))?;
            Ok::<_, OsdPoolError>(())
        }
    });
    let results = futures::future::join_all(futs).await;
    if results.iter().any(Result::is_ok) {
        Ok(())
    } else {
        Err(results
            .into_iter()
            .find_map(Result::err)
            .unwrap_or(OsdPoolError::NoNodesAvailable))
    }
}
