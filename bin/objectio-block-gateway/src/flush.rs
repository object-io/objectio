//! Background flush loop: periodically writes dirty chunks from the
//! WriteCache as EC objects to the OSD cluster.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use objectio_block::chunk::ChunkId;
use tracing::{error, info, warn};

use crate::ec_io::write_chunk;
use crate::service::BlockGatewayState;

/// Write `chunks` of `vol_id` out and mark each flushed at the version
/// written. A chunk written again meanwhile, or whose write failed, stays
/// dirty for the next flush. Returns how many were flushed.
async fn flush_chunks(
    vol_id: &str,
    state: &BlockGatewayState,
    chunks: &[(ChunkId, Bytes, u64)],
) -> usize {
    if chunks.is_empty() {
        return 0;
    }
    // One flush at a time. A chunk write replaces the chunk's previous
    // generation and deletes it; two flushes of the same chunk interleaved
    // could each delete the generation the other had just recorded.
    let _flushing = state.flush_lock.lock().await;

    let mut flushed = Vec::with_capacity(chunks.len());
    for (chunk_id, data, version) in chunks {
        match write_chunk(
            Arc::clone(&state.meta_client),
            &state.osd_pool,
            vol_id,
            *chunk_id,
            data,
            state.ec_k,
            state.ec_m,
        )
        .await
        {
            Ok(object_key) => {
                if let Err(e) = state.store.put_chunk(vol_id, *chunk_id, &object_key) {
                    error!("Failed to persist chunk ref vol={vol_id} chunk={chunk_id}: {e}");
                } else {
                    flushed.push((*chunk_id, *version));
                }
            }
            Err(e) => warn!("Failed to flush chunk {chunk_id} for vol {vol_id}: {e}"),
        }
    }
    state.cache.mark_flushed(vol_id, &flushed);
    flushed.len()
}

/// Flush the chunks of one volume that are due (old enough, or under cache
/// pressure).
pub async fn flush_volume(vol_id: &str, state: &BlockGatewayState) {
    let chunks = state.cache.get_chunks_to_flush(vol_id);
    let n = flush_chunks(vol_id, state, &chunks).await;
    if n > 0 {
        info!("Flushed {n}/{} chunks for vol {vol_id}", chunks.len());
    }
}

/// Flush every dirty chunk of a volume now (Flush RPC, detach).
pub async fn flush_volume_all(vol_id: &str, state: &BlockGatewayState) {
    let chunks = state.cache.dirty_chunks(vol_id);
    let n = flush_chunks(vol_id, state, &chunks).await;
    if !chunks.is_empty() {
        info!("Force-flushed {n}/{} chunks for vol {vol_id}", chunks.len());
    }
    reset_journal(state);
}

/// Empty the journal once nothing is left dirty.
fn reset_journal(state: &BlockGatewayState) {
    if let Err(e) = state.cache.reset_journal_if_clean() {
        warn!("Could not reset the block journal: {e}");
    }
}

/// Long-running background task: flush dirty chunks every `interval`.
pub async fn flush_loop(state: Arc<BlockGatewayState>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        let volume_ids: Vec<String> = state
            .volume_manager
            .list_volumes()
            .into_iter()
            .map(|v| v.volume_id)
            .collect();

        for vol_id in &volume_ids {
            flush_volume(vol_id, &state).await;
        }
        reset_journal(&state);
    }
}
