//! Erasure-coded chunk I/O
//!
//! A chunk is written as one erasure-coded stripe under a fresh object id:
//! GetPlacement → WriteShard per shard. Meta records the stripe in the
//! volume's chunk map (see `meta_blocks`); reads take the stripe from
//! there and fetch the shards from the nodes it names.

use std::sync::Arc;

use anyhow::{Result, anyhow};
use futures::future::join_all;
use objectio_common::ErasureConfig;
use objectio_erasure::ErasureCodec;
use objectio_proto::metadata::{GetPlacementRequest, NodePlacement, ShardLocation, StripeMeta};
use objectio_proto::stripe::{self, Scheme};
use tracing::warn;
use uuid::Uuid;

use crate::meta_blocks::MetaBlocks;
use crate::osd_pool::{OsdPool, OsdPoolError, read_shard_from_osd, write_shard_to_osd};

/// Bucket name block chunks are placed under.
pub const BLOCK_BUCKET: &str = "__block__";

/// Derive the placement key for a volume chunk.
pub fn chunk_object_key(volume_id: &str, chunk_id: u64) -> String {
    format!("vol_{volume_id}/chunk_{chunk_id:08x}")
}

/// Write `data` as a new erasure-coded stripe and return it, for meta to
/// record. Fails unless a write quorum of shards was stored.
pub async fn write_chunk(
    meta: &MetaBlocks,
    osd_pool: &Arc<OsdPool>,
    volume_id: &str,
    chunk_id: u64,
    data: &[u8],
    ec_k: u32,
    ec_m: u32,
) -> Result<StripeMeta> {
    let placement = meta
        .client()
        .await
        .get_placement(GetPlacementRequest {
            bucket: BLOCK_BUCKET.to_string(),
            key: chunk_object_key(volume_id, chunk_id),
            size: data.len() as u64,
            storage_class: String::new(),
        })
        .await
        .map_err(|e| anyhow!("GetPlacement failed: {e}"))?
        .into_inner();

    // Coded with the volume's profile, not the pool's; placed, fenced by
    // the placement group's epoch and held to its quorum as every stripe
    // is. Short of it, the chunk stays dirty (and journaled) for the next
    // flush to place and write again.
    let scheme = Scheme::Mds { k: ec_k, m: ec_m };
    let config = scheme
        .erasure()
        .ok_or_else(|| anyhow!("no code for {scheme:?}"))?;
    let codec = ErasureCodec::new(config).map_err(|e| anyhow!("erasure codec init: {e}"))?;
    let shards = codec
        .encode_bytes(data)
        .map_err(|e| anyhow!("erasure encode: {e}"))?;

    // Every write is a new stripe under its own id: the one it replaces
    // stays intact until meta has recorded this one, and is freed only
    // once nothing (a snapshot, a clone) uses it.
    let object_id = Uuid::new_v4().as_bytes().to_vec();
    let pg = stripe::fence(&placement);
    let written = stripe::write(scheme, &placement.nodes, shards, |position, node, shard| {
        write_shard_to_osd(
            osd_pool,
            node,
            &object_id,
            0,
            position,
            shard,
            ec_k,
            ec_m,
            pg.as_ref(),
        )
    })
    .await;
    match written {
        Ok(shards) => Ok(scheme.stripe(0, data.len() as u64, object_id, shards)),
        Err(short) => {
            let partial = scheme.stripe(0, data.len() as u64, object_id, short.written.clone());
            free_stripes(meta, osd_pool, std::slice::from_ref(&partial)).await;
            Err(anyhow!("chunk {chunk_id}: {short}"))
        }
    }
}

/// Where a shard is: enough to reach its OSD.
async fn shard_target(meta: &MetaBlocks, loc: &ShardLocation) -> Result<NodePlacement> {
    Ok(NodePlacement {
        position: loc.position,
        node_id: loc.node_id.clone(),
        node_address: meta.address(&loc.node_id).await?,
        disk_id: loc.disk_id.clone(),
        shard_type: loc.shard_type,
        local_group: loc.local_group,
        // The block gateway moves shards over gRPC only (for now).
        te_segment: String::new(),
    })
}

/// A chunk's bytes: zeros if it was never written.
pub async fn read_chunk(
    meta: &MetaBlocks,
    osd_pool: &Arc<OsdPool>,
    volume_id: &str,
    chunk_id: u64,
    chunk_size: usize,
) -> Result<Vec<u8>> {
    match meta.chunk(volume_id, chunk_id).await? {
        Some(stripe) => {
            crate::metrics::chunk_read("stored");
            read_stripe(meta, osd_pool, &stripe).await
        }
        None => {
            crate::metrics::chunk_read("unwritten");
            Ok(vec![0u8; chunk_size])
        }
    }
}

/// Read and decode a stripe from the shards it names.
pub async fn read_stripe(
    meta: &MetaBlocks,
    osd_pool: &Arc<OsdPool>,
    stripe: &StripeMeta,
) -> Result<Vec<u8>> {
    let (k, m) = (stripe.ec_k as usize, stripe.ec_m as usize);
    let id = hex::encode(&stripe.object_id);
    let total = k + m;
    let mut shards: Vec<Option<Vec<u8>>> = vec![None; total];
    let mut read_count = 0usize;
    // What each shard was written as, by position (B23).
    let mut recorded: Vec<Option<u32>> = vec![None; total];
    for loc in &stripe.shards {
        if let Some(slot) = recorded.get_mut(loc.position as usize) {
            *slot = loc.crc32c;
        }
    }
    let codec = ErasureCodec::new(ErasureConfig::new(k as u8, m as u8))
        .map_err(|e| anyhow!("erasure codec init: {e}"))?;

    // Data shards first; a parity shard only for one that fails.
    let mut locations: Vec<&ShardLocation> = stripe.shards.iter().collect();
    locations.sort_by_key(|l| l.position);
    let mut locations = locations.into_iter();
    let mut want = k;
    loop {
        while read_count < want {
            let Some(loc) = locations.next() else { break };
            let pos = loc.position as usize;
            if pos >= total || shards[pos].is_some() {
                continue;
            }
            let result = async {
                let target = shard_target(meta, loc).await?;
                read_shard_from_osd(
                    osd_pool,
                    &target,
                    &stripe.object_id,
                    stripe.stripe_id,
                    loc.position,
                    loc.crc32c,
                )
                .await
                .map_err(anyhow::Error::from)
            }
            .await;
            match result {
                Ok(data) => {
                    shards[pos] = Some(data);
                    read_count += 1;
                }
                Err(e) => warn!("Failed to read shard {pos} of stripe {id}: {e}"),
            }
        }

        if read_count < k {
            return Err(anyhow!(
                "insufficient shards for stripe {id}: have {read_count}, need {k}"
            ));
        }

        // A rebuilt data shard is returned only once it checks out against
        // what the stripe records; one that does not may from other shards,
        // so read one more while there are any.
        match codec.decode_verified(&shards, stripe.data_size as usize, &recorded) {
            Ok(data) => return Ok(data),
            Err(e) if read_count == want && read_count < total => {
                warn!("stripe {id}: {e}; reading one more shard");
                want += 1;
            }
            Err(e) => return Err(anyhow!("erasure decode of stripe {id}: {e}")),
        }
    }
}

/// Delete the shards of stripes nothing uses any more, each on the node
/// that holds it.
///
/// Best effort: a shard that will not delete is leaked space, not lost
/// data. Returns how many deletes failed.
pub async fn free_stripes(meta: &MetaBlocks, pool: &OsdPool, stripes: &[StripeMeta]) -> usize {
    use objectio_proto::storage::{DeleteShardRequest, ShardId};

    let futs = stripes.iter().flat_map(|stripe| {
        stripe.shards.iter().map(move |loc| async move {
            let target = shard_target(meta, loc).await?;
            let mut client = pool.get_client_for_placement(&target).await?;
            let req = DeleteShardRequest {
                shard_id: Some(ShardId {
                    object_id: stripe.object_id.clone(),
                    stripe_id: stripe.stripe_id,
                    position: loc.position,
                }),
            };
            tokio::time::timeout(std::time::Duration::from_secs(10), client.delete_shard(req))
                .await
                .map_err(|_| OsdPoolError::ConnectionFailed("delete_shard timeout".into()))?
                .map_err(|e| OsdPoolError::ConnectionFailed(e.to_string()))?;
            Ok::<_, anyhow::Error>(())
        })
    });
    let mut failed = 0;
    for r in join_all(futs).await {
        if let Err(e) = r {
            failed += 1;
            warn!("delete_shard failed: {e}");
        }
    }
    failed
}
