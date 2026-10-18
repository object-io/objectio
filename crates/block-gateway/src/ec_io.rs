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
use tracing::{error, warn};
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

    if placement.nodes.is_empty() {
        return Err(anyhow!("no placement nodes returned for chunk {chunk_id}"));
    }

    let codec = ErasureCodec::new(ErasureConfig::new(ec_k as u8, ec_m as u8))
        .map_err(|e| anyhow!("erasure codec init: {e}"))?;
    let shards = codec
        .encode_bytes(data)
        .map_err(|e| anyhow!("erasure encode: {e}"))?;

    // Every write is a new stripe under its own id: the one it replaces
    // stays intact until meta has recorded this one, and is freed only
    // once nothing (a snapshot, a clone) uses it.
    let object_id = Uuid::new_v4().as_bytes().to_vec();
    let total_shards = (ec_k + ec_m) as usize;

    let results = join_all(shards.iter().enumerate().map(|(i, shard_data)| {
        let node = placement.nodes[i % placement.nodes.len()].clone();
        let oid = object_id.clone();
        let sdata = shard_data.clone();
        let pool = Arc::clone(osd_pool);
        async move {
            let result =
                write_shard_to_osd(&pool, &node, &oid, 0, i as u32, sdata, ec_k, ec_m).await;
            (i as u32, node, result)
        }
    }))
    .await;

    // Only shards actually written are recorded, each where it went.
    let mut stripe_shards: Vec<ShardLocation> = Vec::with_capacity(total_shards);
    for (position, node, result) in results {
        match result {
            Ok((location, crc32c)) => stripe_shards.push(ShardLocation {
                position,
                node_id: node.node_id.clone(),
                disk_id: location.disk_id,
                offset: location.offset,
                shard_type: node.shard_type,
                local_group: node.local_group,
                crc32c: Some(crc32c),
            }),
            Err(e) => error!("Failed to write shard {position} for chunk {chunk_id}: {e}"),
        }
    }

    let stripe = StripeMeta {
        stripe_id: 0,
        ec_k,
        ec_m,
        shards: stripe_shards,
        ec_type: 0, // ErasureMds
        data_size: data.len() as u64,
        object_id,
        ..Default::default()
    };

    // A spare shard beyond k before the chunk counts as stored: with only k
    // it would have no redundancy left. Failing here leaves the chunk dirty
    // (and journaled) for the next flush to retry.
    let quorum = write_quorum(ec_k, ec_m);
    if stripe.shards.len() < quorum {
        let written = stripe.shards.len();
        free_stripes(meta, osd_pool, std::slice::from_ref(&stripe)).await;
        return Err(anyhow!(
            "only {written}/{total_shards} shards written for chunk {chunk_id}, need {quorum}"
        ));
    }
    Ok(stripe)
}

/// Shards of a k+m chunk that must be written for it to count as stored:
/// k+1, so it still has redundancy (k when there is no parity).
const fn write_quorum(ec_k: u32, ec_m: u32) -> usize {
    let k = ec_k as usize;
    if ec_m == 0 { k } else { k + 1 }
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

    // Data shards first; a parity shard only for one that fails.
    let mut locations: Vec<&ShardLocation> = stripe.shards.iter().collect();
    locations.sort_by_key(|l| l.position);
    for loc in locations {
        if read_count >= k {
            break;
        }
        let pos = loc.position as usize;
        if pos >= total {
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

    let codec = ErasureCodec::new(ErasureConfig::new(k as u8, m as u8))
        .map_err(|e| anyhow!("erasure codec init: {e}"))?;
    codec
        .decode(&mut shards, stripe.data_size as usize)
        .map_err(|e| anyhow!("erasure decode: {e}"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_chunk_keeps_a_spare_shard() {
        assert_eq!(write_quorum(4, 2), 5);
        assert_eq!(write_quorum(2, 1), 3);
        assert_eq!(write_quorum(1, 0), 1);
    }
}
