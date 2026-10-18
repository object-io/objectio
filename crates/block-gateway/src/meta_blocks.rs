//! Block metadata, kept in meta.
//!
//! Volumes, snapshots and each volume's chunk map — which erasure-coded
//! stripe holds each 4 MiB chunk, and where its shards are — live in meta's
//! Raft-replicated block tables. The gateway used to keep them in a local
//! database: one disk whose loss lost every volume while the data sat safe
//! on the OSDs. Now the gateway holds nothing but its write journal.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::metadata::{
    BlockChunkUpdate, BlockCommitChunksRequest, BlockGetChunksRequest, GetListingNodesRequest,
    StripeMeta,
};
use parking_lot::RwLock;
use tokio::sync::Mutex;
use tonic::transport::Channel;

/// Outcome of committing one chunk.
#[derive(Debug)]
pub enum Commit {
    /// Recorded. These stripes are no longer used by anything: delete
    /// their shards.
    Done(Vec<StripeMeta>),
    /// The chunk no longer holds the stripe the commit expected; nothing
    /// changed.
    Conflict,
}

pub struct MetaBlocks {
    client: Arc<Mutex<MetadataServiceClient<Channel>>>,
    /// OSD addresses by node id, refreshed from meta when one is missing.
    addresses: RwLock<HashMap<Vec<u8>, String>>,
}

impl MetaBlocks {
    pub fn new(client: Arc<Mutex<MetadataServiceClient<Channel>>>) -> Self {
        Self {
            client,
            addresses: RwLock::new(HashMap::new()),
        }
    }

    /// A client of its own for one call, so calls do not queue behind each
    /// other on the shared one.
    pub async fn client(&self) -> MetadataServiceClient<Channel> {
        self.client.lock().await.clone()
    }

    /// The stripe holding `chunk_id` of `volume_id`; `None` if the chunk
    /// was never written (it reads as zeros).
    pub async fn chunk(&self, volume_id: &str, chunk_id: u64) -> Result<Option<StripeMeta>> {
        let chunks = self
            .client()
            .await
            .block_get_chunks(BlockGetChunksRequest {
                volume_id: volume_id.to_string(),
                start_chunk: chunk_id,
                count: 1,
            })
            .await
            .map_err(|e| anyhow!("BlockGetChunks {volume_id}/{chunk_id}: {e}"))?
            .into_inner()
            .chunks;
        Ok(chunks
            .into_iter()
            .find(|c| c.chunk_id == chunk_id)
            .and_then(|c| c.stripe))
    }

    /// Point `chunk_id` at `stripe` (`None` trims it), provided it still
    /// holds the stripe `expected` (empty: no stripe).
    pub async fn commit(
        &self,
        volume_id: &str,
        chunk_id: u64,
        expected: Vec<u8>,
        stripe: Option<StripeMeta>,
    ) -> Result<Commit> {
        let resp = self
            .client()
            .await
            .block_commit_chunks(BlockCommitChunksRequest {
                volume_id: volume_id.to_string(),
                updates: vec![BlockChunkUpdate {
                    chunk_id,
                    expected_object_id: expected,
                    stripe,
                }],
            })
            .await;
        match resp {
            Ok(r) => Ok(Commit::Done(r.into_inner().freeable)),
            Err(s) if s.code() == tonic::Code::Aborted => Ok(Commit::Conflict),
            Err(s) => Err(anyhow!("BlockCommitChunks {volume_id}/{chunk_id}: {s}")),
        }
    }

    /// The address of OSD `node_id`.
    pub async fn address(&self, node_id: &[u8]) -> Result<String> {
        if let Some(a) = self.addresses.read().get(node_id) {
            return Ok(a.clone());
        }
        let nodes = self
            .client()
            .await
            .get_listing_nodes(GetListingNodesRequest {
                bucket: String::new(),
                include_all_states: true,
            })
            .await
            .map_err(|e| anyhow!("GetListingNodes: {e}"))?
            .into_inner()
            .nodes;
        let mut map = self.addresses.write();
        *map = nodes.into_iter().map(|n| (n.node_id, n.address)).collect();
        map.get(node_id)
            .cloned()
            .ok_or_else(|| anyhow!("OSD {} is not registered", hex::encode(node_id)))
    }
}
