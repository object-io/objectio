//! Chunks with writes waiting for their stored bytes, and reads that see
//! them.
//!
//! A partial write to a chunk the cache does not hold is acknowledged once
//! journaled; the cache keeps it as a pending chunk (see
//! `objectio_block::cache::DirtyChunk::pending`). This module loads such
//! chunks' stored bytes and merges them in: in the background after the
//! write, on demand when a read or a flush needs the chunk whole. The load
//! used to happen before the write was acknowledged, ~17 ms of a random
//! 4 KiB write.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use objectio_block::WriteCache;
use objectio_block::chunk::ChunkId;
use parking_lot::Mutex;
use tracing::warn;

use crate::ec_io::read_chunk;
use crate::meta_blocks::MetaBlocks;
use crate::osd_pool::OsdPool;

/// Held while a chunk's stored bytes load, so only one load runs.
type LoadLock = Arc<tokio::sync::Mutex<()>>;

/// Chunk loads running at once in the background.
const BACKGROUND_LOADS: usize = 16;

pub struct Resolver {
    cache: Arc<WriteCache>,
    meta: Arc<MetaBlocks>,
    pool: Arc<OsdPool>,
    /// One load per chunk at a time: a read and the background both
    /// wanting a chunk share one load.
    loading: Mutex<HashMap<(String, ChunkId), LoadLock>>,
    background: Arc<tokio::sync::Semaphore>,
}

impl Resolver {
    pub fn new(cache: Arc<WriteCache>, meta: Arc<MetaBlocks>, pool: Arc<OsdPool>) -> Self {
        Self {
            cache,
            meta,
            pool,
            loading: Mutex::new(HashMap::new()),
            background: Arc::new(tokio::sync::Semaphore::new(BACKGROUND_LOADS)),
        }
    }

    /// `volume_id`'s chunk size (each volume has its own).
    fn chunk_size(&self, volume_id: &str) -> u64 {
        self.cache
            .mapper_of(volume_id)
            .unwrap_or_else(|| self.cache.chunk_mapper().as_ref().clone())
            .chunk_size()
    }

    /// Make `chunk_id` whole if it is pending: load its stored bytes
    /// (zeros if it was never stored) and merge them under its writes.
    pub async fn resolve(&self, volume_id: &str, chunk_id: ChunkId) -> Result<()> {
        if !self.cache.is_pending(volume_id, chunk_id) {
            return Ok(());
        }
        let key = (volume_id.to_string(), chunk_id);
        let lock = Arc::clone(self.loading.lock().entry(key.clone()).or_default());
        let result = async {
            let _one = lock.lock().await;
            // Resolved by whoever held the lock before us.
            if !self.cache.is_pending(volume_id, chunk_id) {
                return Ok(());
            }
            let base = read_chunk(
                &self.meta,
                &self.pool,
                volume_id,
                chunk_id,
                self.chunk_size(volume_id) as usize,
            )
            .await?;
            self.cache.resolve(volume_id, chunk_id, &base);
            Ok(())
        }
        .await;
        let mut loading = self.loading.lock();
        if Arc::strong_count(&lock) <= 2 {
            loading.remove(&key);
        }
        result
    }

    /// Resolve every pending chunk of `volume_id`. How many could not be.
    pub async fn resolve_volume(&self, volume_id: &str) -> usize {
        let mut failed = 0;
        for chunk_id in self.cache.pending_chunks(volume_id) {
            if let Err(e) = self.resolve(volume_id, chunk_id).await {
                warn!("chunk {chunk_id} of {volume_id}: cannot load its stored bytes: {e}");
                failed += 1;
            }
        }
        failed
    }

    /// After a write: start loading the stored bytes of any chunk it left
    /// pending, in the background, so a later read or flush finds it whole.
    pub fn kick(self: &Arc<Self>, volume_id: &str, offset: u64, len: u64) {
        let Some(mapper) = self.cache.mapper_of(volume_id) else {
            return;
        };
        for range in mapper.byte_range_to_chunks(offset, len) {
            if !self.cache.is_pending(volume_id, range.chunk_id) {
                continue;
            }
            let this = Arc::clone(self);
            let vol = volume_id.to_string();
            tokio::spawn(async move {
                let Ok(_slot) = Arc::clone(&this.background).acquire_owned().await else {
                    return;
                };
                // A failure is retried by the next read or flush.
                if let Err(e) = this.resolve(&vol, range.chunk_id).await {
                    warn!(
                        "chunk {} of {vol}: background load failed: {e}",
                        range.chunk_id
                    );
                }
            });
        }
    }

    /// `length` bytes at `offset`, each chunk from the cache if it holds
    /// it whole, made whole first if it is pending, from its stripe
    /// otherwise.
    ///
    /// Chunk by chunk: a read spanning a cached chunk and an uncached one
    /// used to fetch both from the OSDs, returning stale bytes for the
    /// cached one when it had writes not yet flushed.
    pub async fn read(&self, volume_id: &str, offset: u64, length: u64) -> Result<Vec<u8>> {
        if length == 0 {
            return Ok(Vec::new());
        }
        if let Some(data) = self.cache.read(volume_id, offset, length) {
            return Ok(data);
        }
        let Some(mapper) = self.cache.mapper_of(volume_id) else {
            anyhow::bail!("volume {volume_id} is not open on this gateway");
        };
        let chunk_size = mapper.chunk_size();
        let mut out = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
        for range in mapper.byte_range_to_chunks(offset, length) {
            let chunk = self
                .whole_chunk(volume_id, range.chunk_id, chunk_size)
                .await?;
            let start = (range.offset_in_chunk as usize).min(chunk.len());
            let end = (start + range.length as usize).min(chunk.len());
            out.extend_from_slice(&chunk[start..end]);
            // Past the end of what the chunk holds reads as zeros.
            out.resize(out.len() + (range.length as usize - (end - start)), 0);
        }
        Ok(out)
    }

    async fn whole_chunk(
        &self,
        volume_id: &str,
        chunk_id: ChunkId,
        chunk_size: u64,
    ) -> Result<bytes::Bytes> {
        // A few rounds: a write can make a chunk pending between looking
        // and loading.
        for _ in 0..4 {
            if let Some(c) = self.cache.chunk(volume_id, chunk_id) {
                return Ok(c);
            }
            if self.cache.is_pending(volume_id, chunk_id) {
                self.resolve(volume_id, chunk_id).await?;
                continue;
            }
            let stored = bytes::Bytes::from(
                read_chunk(
                    &self.meta,
                    &self.pool,
                    volume_id,
                    chunk_id,
                    chunk_size as usize,
                )
                .await?,
            );
            self.cache.add_clean(volume_id, chunk_id, stored.clone());
            // A write may have landed meanwhile: the cache's copy wins.
            return Ok(self.cache.chunk(volume_id, chunk_id).unwrap_or(stored));
        }
        anyhow::bail!("chunk {chunk_id} of {volume_id} kept changing while being read")
    }
}
