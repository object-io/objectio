//! Background flush loop: periodically writes dirty chunks from the
//! WriteCache as EC stripes to the OSDs and records them in meta.

use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use bytes::Bytes;
use objectio_block::chunk::ChunkId;
use tracing::{info, warn};

use crate::ec_io::{free_stripes, write_chunk};
use crate::meta_blocks::Commit;
use crate::service::BlockGatewayState;

/// Store one chunk: write it as a new stripe, then point the chunk at it
/// in meta, naming the stripe it replaces.
///
/// The replaced stripe is freed only if meta says nothing else (a
/// snapshot, a clone) still uses it.
async fn flush_one(
    state: &BlockGatewayState,
    vol_id: &str,
    chunk_id: ChunkId,
    data: &[u8],
) -> anyhow::Result<()> {
    let started = std::time::Instant::now();
    let result = store_chunk(state, vol_id, chunk_id, data).await;
    let outcome = match &result {
        Ok(()) => "stored",
        Err(e) if e.to_string() == CHANGED => "conflict",
        Err(_) => "failed",
    };
    crate::metrics::flushed(outcome, started.elapsed());
    result
}

/// The error a flush ends with when the chunk changed meanwhile.
const CHANGED: &str = "the chunk changed meanwhile";

async fn store_chunk(
    state: &BlockGatewayState,
    vol_id: &str,
    chunk_id: ChunkId,
    data: &[u8],
) -> anyhow::Result<()> {
    let current = state.meta.chunk(vol_id, chunk_id).await?;
    let expected = current.map(|s| s.object_id).unwrap_or_default();
    let stripe = write_chunk(
        &state.meta,
        &state.osd_pool,
        vol_id,
        chunk_id,
        data,
        state.ec_k,
        state.ec_m,
    )
    .await?;
    match state
        .meta
        .commit(vol_id, chunk_id, expected, Some(stripe.clone()))
        .await
    {
        Ok(Commit::Done(freeable)) => {
            let failed = free_stripes(&state.meta, &state.osd_pool, &freeable).await;
            crate::metrics::stripes_freed("overwrite", freeable.len(), failed);
            if failed > 0 {
                warn!("chunk {chunk_id} of {vol_id}: {failed} shard deletes failed");
            }
            Ok(())
        }
        Ok(Commit::Conflict) => {
            // Certainly not recorded: nothing refers to the new stripe.
            free_stripes(&state.meta, &state.osd_pool, &[stripe]).await;
            Err(anyhow!(CHANGED))
        }
        // It may have been recorded (a lost reply), so the new stripe is
        // kept: at worst a leak, never a chunk pointing at deleted shards.
        // The retry reads what is recorded and replaces that.
        Err(e) => Err(e),
    }
}

/// Write `chunks` of `vol_id` out and mark each flushed at the version
/// written. A chunk written again meanwhile, or whose write failed, stays
/// dirty for the next flush. Returns how many were flushed. The caller
/// holds `state.flush_lock`.
async fn flush_chunks_locked(
    vol_id: &str,
    state: &BlockGatewayState,
    chunks: &[(ChunkId, Bytes, u64)],
) -> usize {
    let mut flushed = Vec::with_capacity(chunks.len());
    for (chunk_id, data, version) in chunks {
        match flush_one(state, vol_id, *chunk_id, data).await {
            Ok(()) => flushed.push((*chunk_id, *version)),
            Err(e) => warn!("Failed to flush chunk {chunk_id} for vol {vol_id}: {e}"),
        }
    }
    state.cache.mark_flushed(vol_id, &flushed);
    flushed.len()
}

/// Flush the chunks of one volume that are due (old enough, or under cache
/// pressure).
pub async fn flush_volume(vol_id: &str, state: &BlockGatewayState) {
    // Chunks with writes waiting for their stored bytes are made whole
    // first; one that cannot be stays pending and journaled, and is
    // retried next time.
    state.resolver.resolve_volume(vol_id).await;
    let chunks = state.cache.get_chunks_to_flush(vol_id);
    if chunks.is_empty() {
        return;
    }
    // One flush at a time: two flushes of one chunk would each name the
    // same stripe as the one they replace, and one would fail.
    let _flushing = state.flush_lock.lock().await;
    let n = flush_chunks_locked(vol_id, state, &chunks).await;
    if n > 0 {
        info!("Flushed {n}/{} chunks for vol {vol_id}", chunks.len());
    }
}

/// Flush every dirty chunk of a volume now, the caller holding
/// `state.flush_lock`. How many chunks are still dirty.
pub async fn flush_volume_all_locked(vol_id: &str, state: &BlockGatewayState) -> usize {
    // Pending chunks are dirty too: made whole first, and counted as still
    // dirty if they cannot be (a snapshot must not be taken without them).
    let unresolved = state.resolver.resolve_volume(vol_id).await;
    let chunks = state.cache.dirty_chunks(vol_id);
    let n = flush_chunks_locked(vol_id, state, &chunks).await;
    if !chunks.is_empty() {
        info!("Force-flushed {n}/{} chunks for vol {vol_id}", chunks.len());
    }
    reset_journal(state);
    chunks.len() - n + unresolved
}

/// Flush every dirty chunk of a volume now (Flush RPC, detach). How many
/// chunks are still dirty.
pub async fn flush_volume_all(vol_id: &str, state: &BlockGatewayState) -> usize {
    let _flushing = state.flush_lock.lock().await;
    flush_volume_all_locked(vol_id, state).await
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
