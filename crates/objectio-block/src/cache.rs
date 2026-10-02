//! Write cache for block storage
//!
//! Provides a write-back cache with journaling for durability and low latency.

use crate::chunk::{ChunkId, ChunkMapper};
use crate::error::{BlockError, BlockResult};
use crate::journal::WriteJournal;

use bytes::{Bytes, BytesMut};
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Largest piece [`WriteCache::write_zeroes`] writes at once.
pub const ZERO_PIECE: u64 = 4 * 1024 * 1024;

/// Run journal I/O (appends, fsyncs, rotation) on the blocking pool: an
/// fsync on an async worker stalls every task scheduled on it.
async fn blocking<T, F>(f: F) -> BlockResult<T>
where
    F: FnOnce() -> BlockResult<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| BlockError::Internal(format!("journal task: {e}")))?
}

/// A dirty chunk that needs to be flushed to storage
#[derive(Debug, Clone)]
pub struct DirtyChunk {
    /// Full chunk data
    pub data: Bytes,
    /// When the chunk was first dirtied
    pub dirty_since: Instant,
    /// When the chunk was last modified
    pub last_modified: Instant,
    /// Bumped by every write to the chunk, so a flush can tell whether the
    /// bytes it wrote out are still the latest.
    pub version: u64,
    /// The byte ranges written, `(offset, length)`, while the chunk's stored
    /// bytes are not merged in yet: a partial write to a chunk the cache did
    /// not hold is acknowledged once journaled, without waiting to load the
    /// rest of the chunk (that load cost a random 4 KiB write ~17 ms).
    /// `None` once the chunk is whole. A pending chunk is not flushed or
    /// read whole until [`WriteCache::resolve`] merges the stored bytes in.
    pub pending: Option<Vec<(u32, u32)>>,
}

/// Write cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum cache size in bytes
    pub max_cache_bytes: u64,
    /// Flush interval for background flushing
    pub flush_interval: Duration,
    /// Maximum age before a dirty chunk must be flushed
    pub max_dirty_age: Duration,
    /// Journal directory path
    pub journal_path: Option<String>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_cache_bytes: 256 * 1024 * 1024, // 256MB
            flush_interval: Duration::from_secs(5),
            max_dirty_age: Duration::from_secs(30),
            journal_path: None,
        }
    }
}

/// Cached data for a volume
struct VolumeCache {
    /// Dirty chunks (not yet flushed to storage)
    dirty_chunks: BTreeMap<ChunkId, DirtyChunk>,
    /// Clean chunks (read cache)
    clean_chunks: BTreeMap<ChunkId, Bytes>,
    /// Total dirty bytes
    dirty_bytes: u64,
    /// Total clean bytes
    clean_bytes: u64,
    /// Source of `DirtyChunk::version`.
    next_version: u64,
    /// This volume's chunk size; fixed for its lifetime.
    mapper: ChunkMapper,
}

impl VolumeCache {
    fn new(mapper: ChunkMapper) -> Self {
        Self {
            mapper,
            dirty_chunks: BTreeMap::new(),
            clean_chunks: BTreeMap::new(),
            dirty_bytes: 0,
            clean_bytes: 0,
            next_version: 0,
        }
    }
}

/// Write-back cache for block storage
///
/// Provides low-latency writes by caching data in memory and flushing
/// to storage in the background. A write-ahead journal ensures durability.
pub struct WriteCache {
    /// Per-volume caches
    caches: RwLock<BTreeMap<String, VolumeCache>>,
    /// Chunk mapper
    chunk_mapper: Arc<ChunkMapper>,
    /// Configuration
    config: CacheConfig,
    /// Total dirty bytes across all volumes
    total_dirty_bytes: RwLock<u64>,
    /// Write-ahead journal for durability (optional)
    journal: Option<Arc<WriteJournal>>,
    /// Shutdown signal sender
    _shutdown_tx: Option<mpsc::Sender<()>>,
}

/// Default maximum journal size: 256MB
const DEFAULT_MAX_JOURNAL_SIZE: u64 = 256 * 1024 * 1024;

impl WriteCache {
    /// Create a new write cache
    pub fn new(chunk_mapper: Arc<ChunkMapper>, config: CacheConfig) -> Self {
        let journal = config.journal_path.as_ref().map(|path| {
            Arc::new(
                WriteJournal::open(path, DEFAULT_MAX_JOURNAL_SIZE).expect("failed to open journal"),
            )
        });

        if journal.is_some() {
            info!(
                "Write cache initialized with journal at {:?}",
                config.journal_path
            );
        } else {
            warn!("Write cache initialized WITHOUT journal - data may be lost on crash");
        }

        Self {
            caches: RwLock::new(BTreeMap::new()),
            chunk_mapper,
            config,
            total_dirty_bytes: RwLock::new(0),
            journal,
            _shutdown_tx: None,
        }
    }

    /// Create a new write cache with default configuration
    pub fn with_defaults(chunk_mapper: Arc<ChunkMapper>) -> Self {
        Self::new(chunk_mapper, CacheConfig::default())
    }

    /// Create a new write cache with journaling enabled
    pub fn with_journal<P: AsRef<Path>>(chunk_mapper: Arc<ChunkMapper>, journal_path: P) -> Self {
        let config = CacheConfig {
            journal_path: Some(journal_path.as_ref().to_string_lossy().to_string()),
            ..CacheConfig::default()
        };
        Self::new(chunk_mapper, config)
    }

    /// Get the chunk mapper
    pub fn chunk_mapper(&self) -> Arc<ChunkMapper> {
        self.chunk_mapper.clone()
    }

    /// Initialize cache for a volume, with the cache's default chunk size.
    pub fn init_volume(&self, volume_id: &str) {
        self.init_volume_sized(volume_id, self.chunk_mapper.chunk_size());
    }

    /// Initialize cache for a volume whose chunks are `chunk_size` bytes.
    pub fn init_volume_sized(&self, volume_id: &str, chunk_size: u64) {
        let mut caches = self.caches.write();
        if !caches.contains_key(volume_id) {
            caches.insert(
                volume_id.to_string(),
                VolumeCache::new(ChunkMapper::new(chunk_size)),
            );
        }
    }

    /// The chunk mapping of `volume_id`, if the cache knows the volume.
    pub fn mapper_of(&self, volume_id: &str) -> Option<ChunkMapper> {
        self.caches.read().get(volume_id).map(|c| c.mapper.clone())
    }

    /// Remove cache for a volume
    pub fn remove_volume(&self, volume_id: &str) {
        let mut caches = self.caches.write();
        if let Some(cache) = caches.remove(volume_id) {
            let mut total = self.total_dirty_bytes.write();
            *total = total.saturating_sub(cache.dirty_bytes);
        }
    }

    /// Write data to the cache
    ///
    /// This updates the in-memory cache and marks chunks as dirty. With a
    /// journal, the write is logged and the journal fsynced before this
    /// returns, so it is durable when acknowledged. Erasure-coding it out to
    /// the OSDs happens later.
    pub fn write(&self, volume_id: &str, offset: u64, data: &[u8]) -> BlockResult<()> {
        if data.is_empty() {
            return Ok(());
        }

        let mut caches = self.caches.write();
        let mapper = caches
            .get(volume_id)
            .map(|c| c.mapper.clone())
            .ok_or_else(|| BlockError::VolumeNotFound(volume_id.to_string()))?;
        // Log to the journal before acknowledging (write-ahead), under the
        // cache lock: the journal's order is then the order writes are
        // applied, and it cannot be reset between a write being logged and
        // that write becoming dirty.
        let logged = match self.journal {
            Some(ref journal) => Some(journal.log_write(
                volume_id,
                mapper.byte_offset_to_chunk_id(offset),
                offset % mapper.chunk_size(),
                Bytes::copy_from_slice(data),
            )?),
            None => None,
        };
        self.apply(&mut caches, volume_id, offset, data)?;
        drop(caches);
        // Acknowledged means on stable storage: the journal is fsynced
        // before the write returns, not only on an explicit flush, so a
        // power cut cannot lose a write the client was told succeeded.
        // Outside the cache lock, so other writes proceed meanwhile, and
        // concurrent writes share one fsync (group commit).
        if let (Some(journal), Some(seq)) = (&self.journal, logged) {
            journal.sync_to(seq + 1)?;
        }
        Ok(())
    }

    /// Re-apply a write recovered from the journal: as [`Self::write`],
    /// without logging it again (it is still in the journal).
    pub fn replay(&self, volume_id: &str, offset: u64, data: &[u8]) -> BlockResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut caches = self.caches.write();
        self.apply(&mut caches, volume_id, offset, data)
    }

    fn apply(
        &self,
        caches: &mut BTreeMap<String, VolumeCache>,
        volume_id: &str,
        offset: u64,
        data: &[u8],
    ) -> BlockResult<()> {
        let cache = caches
            .get_mut(volume_id)
            .ok_or_else(|| BlockError::VolumeNotFound(volume_id.to_string()))?;
        let chunk_ranges = cache.mapper.byte_range_to_chunks(offset, data.len() as u64);
        let chunk_size = cache.mapper.chunk_size() as usize;

        let mut data_offset = 0usize;
        let now = Instant::now();

        for range in chunk_ranges {
            let range_len = range.length as usize;

            // The chunk's current bytes: dirty, clean (promoted to dirty), or
            // zeros for a chunk never cached.
            let (existing, dirty_since, pending_of) =
                if let Some(dirty) = cache.dirty_chunks.remove(&range.chunk_id) {
                    (Some(dirty.data), Some(dirty.dirty_since), dirty.pending)
                } else if let Some(clean) = cache.clean_chunks.remove(&range.chunk_id) {
                    cache.clean_bytes = cache.clean_bytes.saturating_sub(clean.len() as u64);
                    (Some(clean), None, None)
                } else {
                    (None, None, None)
                };
            let was_dirty = dirty_since.is_some();
            let offset_in_chunk = range.offset_in_chunk as usize;
            let whole = offset_in_chunk == 0 && range_len == chunk_size;
            // A chunk held whole stays whole. One not held becomes pending
            // unless this write covers all of it.
            let pending = match (&existing, pending_of) {
                (Some(_), Some(mut ranges)) => {
                    ranges.push((offset_in_chunk as u32, range_len as u32));
                    (!covers(&mut ranges, chunk_size)).then_some(ranges)
                }
                (Some(_), None) => None,
                (None, _) if whole => None,
                (None, _) => Some(vec![(offset_in_chunk as u32, range_len as u32)]),
            };

            // Written in place when the cache holds the only reference;
            // copied only while a flush or a read holds one too (they keep
            // the bytes they took). This used to copy the whole 4 MiB chunk
            // on every write, under the cache lock: ~3k writes/s for the
            // whole gateway, whatever the disk could do.
            let mut chunk_data: BytesMut = match existing {
                Some(b) => b
                    .try_into_mut()
                    .unwrap_or_else(|shared| BytesMut::from(&shared[..])),
                None => BytesMut::zeroed(chunk_size),
            };
            if chunk_data.len() < chunk_size {
                chunk_data.resize(chunk_size, 0);
            }

            chunk_data[offset_in_chunk..offset_in_chunk + range_len]
                .copy_from_slice(&data[data_offset..data_offset + range_len]);

            // Store as dirty
            cache.next_version += 1;
            let dirty_chunk = DirtyChunk {
                version: cache.next_version,
                data: chunk_data.freeze(),
                dirty_since: dirty_since.unwrap_or(now),
                last_modified: now,
                pending,
            };

            if !was_dirty {
                cache.dirty_bytes += chunk_size as u64;
                *self.total_dirty_bytes.write() += chunk_size as u64;
            }

            cache.dirty_chunks.insert(range.chunk_id, dirty_chunk);
            data_offset += range_len;
        }

        // Check if we need to trigger a flush
        if self.should_flush() {
            debug!("Cache pressure high, should trigger flush");
            // In a real implementation, this would signal the background flusher
        }

        // Check if journal needs rotation
        if let Some(ref journal) = self.journal
            && journal.needs_rotation()
        {
            debug!("Journal needs rotation");
        }

        Ok(())
    }

    /// Read data from the cache (or return None if not cached)
    ///
    /// Returns the data if found in cache (dirty or clean), None otherwise.
    /// The caller should read from storage if None is returned.
    pub fn read(&self, volume_id: &str, offset: u64, length: u64) -> Option<Vec<u8>> {
        if length == 0 {
            return Some(Vec::new());
        }

        let caches = self.caches.read();
        let cache = caches.get(volume_id)?;
        let chunk_ranges = cache.mapper.byte_range_to_chunks(offset, length);

        let mut result = Vec::with_capacity(length as usize);

        for range in &chunk_ranges {
            // Check dirty cache first (a pending chunk is not whole yet)
            if let Some(dirty) = cache
                .dirty_chunks
                .get(&range.chunk_id)
                .filter(|d| d.pending.is_none())
            {
                let offset_in_chunk = range.offset_in_chunk as usize;
                let range_len = range.length as usize;
                result.extend_from_slice(&dirty.data[offset_in_chunk..offset_in_chunk + range_len]);
            }
            // Check clean cache
            else if let Some(clean) = cache
                .clean_chunks
                .get(&range.chunk_id)
                .filter(|_| !cache.dirty_chunks.contains_key(&range.chunk_id))
            {
                let offset_in_chunk = range.offset_in_chunk as usize;
                let range_len = range.length as usize;
                result.extend_from_slice(&clean[offset_in_chunk..offset_in_chunk + range_len]);
            } else {
                // Cache miss - caller needs to read from storage
                return None;
            }
        }

        Some(result)
    }

    /// Whether the cache holds all of `chunk_id` of `volume_id`, dirty or
    /// clean.
    pub fn holds_chunk(&self, volume_id: &str, chunk_id: ChunkId) -> bool {
        self.chunk(volume_id, chunk_id).is_some()
    }

    /// The whole chunk, if the cache holds all of it: dirty, or clean.
    pub fn chunk(&self, volume_id: &str, chunk_id: ChunkId) -> Option<Bytes> {
        let caches = self.caches.read();
        let c = caches.get(volume_id)?;
        match c.dirty_chunks.get(&chunk_id) {
            Some(d) if d.pending.is_none() => Some(d.data.clone()),
            Some(_) => None,
            None => c.clean_chunks.get(&chunk_id).cloned(),
        }
    }

    /// Whether `chunk_id` has writes waiting for its stored bytes.
    pub fn is_pending(&self, volume_id: &str, chunk_id: ChunkId) -> bool {
        self.caches.read().get(volume_id).is_some_and(|c| {
            c.dirty_chunks
                .get(&chunk_id)
                .is_some_and(|d| d.pending.is_some())
        })
    }

    /// Chunks of `volume_id` with writes waiting for their stored bytes.
    pub fn pending_chunks(&self, volume_id: &str) -> Vec<ChunkId> {
        self.caches
            .read()
            .get(volume_id)
            .map(|c| {
                c.dirty_chunks
                    .iter()
                    .filter(|(_, d)| d.pending.is_some())
                    .map(|(id, _)| *id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Merge a pending chunk's stored bytes (`base`; zeros for a chunk
    /// never stored) under the writes made to it: the chunk is whole
    /// again, with every written range kept. A no-op for a chunk not
    /// pending (resolved already, or gone).
    pub fn resolve(&self, volume_id: &str, chunk_id: ChunkId, base: &[u8]) {
        let mut caches = self.caches.write();
        let Some(cache) = caches.get_mut(volume_id) else {
            return;
        };
        let chunk_size = cache.mapper.chunk_size() as usize;
        let next = cache.next_version + 1;
        let Some(dirty) = cache.dirty_chunks.get_mut(&chunk_id) else {
            return;
        };
        let Some(ranges) = dirty.pending.take() else {
            return;
        };
        let mut whole = BytesMut::from(&base[..base.len().min(chunk_size)]);
        whole.resize(chunk_size, 0);
        for (off, len) in ranges {
            let (off, len) = (off as usize, len as usize);
            whole[off..off + len].copy_from_slice(&dirty.data[off..off + len]);
        }
        dirty.data = whole.freeze();
        dirty.version = next;
        cache.next_version = next;
    }

    /// Add a clean chunk to the read cache
    pub fn add_clean(&self, volume_id: &str, chunk_id: ChunkId, data: Bytes) {
        let mut caches = self.caches.write();
        if let Some(cache) = caches.get_mut(volume_id) {
            // Never replace what the cache holds, dirty or clean: it is at
            // least as new as anything loaded from the OSDs. A load that
            // started before a write was applied, flushed and marked clean
            // would otherwise put the older bytes back over it — and with
            // requests served concurrently, two loads of one chunk can race.
            if !cache.dirty_chunks.contains_key(&chunk_id)
                && !cache.clean_chunks.contains_key(&chunk_id)
            {
                cache.clean_bytes += data.len() as u64;
                cache.clean_chunks.insert(chunk_id, data);
            }
        }
    }

    /// Get dirty chunks that should be flushed
    ///
    /// Returns chunks that are either:
    /// - Older than max_dirty_age
    /// - Need to be flushed due to cache pressure
    pub fn get_chunks_to_flush(&self, volume_id: &str) -> Vec<(ChunkId, Bytes, u64)> {
        let caches = self.caches.read();
        let cache = match caches.get(volume_id) {
            Some(c) => c,
            None => return Vec::new(),
        };

        let now = Instant::now();
        let mut to_flush = Vec::new();

        for (chunk_id, dirty) in cache
            .dirty_chunks
            .iter()
            .filter(|(_, d)| d.pending.is_none())
        {
            let age = now.duration_since(dirty.dirty_since);
            if age >= self.config.max_dirty_age || self.should_flush() {
                to_flush.push((*chunk_id, dirty.data.clone(), dirty.version));
            }
        }

        to_flush
    }

    /// Mark chunks as flushed: each `(chunk, version)` stops being dirty if
    /// it is still the version that was written out. A chunk written again
    /// while its flush was in flight stays dirty — marking it clean dropped
    /// that newer write.
    pub fn mark_flushed(&self, volume_id: &str, flushed: &[(ChunkId, u64)]) {
        let mut caches = self.caches.write();
        if let Some(cache) = caches.get_mut(volume_id) {
            for (chunk_id, version) in flushed {
                if cache
                    .dirty_chunks
                    .get(chunk_id)
                    .is_some_and(|d| d.version == *version)
                    && let Some(dirty) = cache.dirty_chunks.remove(chunk_id)
                {
                    let chunk_size = dirty.data.len() as u64;
                    cache.dirty_bytes = cache.dirty_bytes.saturating_sub(chunk_size);
                    *self.total_dirty_bytes.write() -= chunk_size;
                    cache.clean_bytes += chunk_size;
                    cache.clean_chunks.insert(*chunk_id, dirty.data);
                }
            }
        }
    }

    /// Empty the journal if nothing in the cache is dirty: everything it
    /// recorded is then on the OSDs. Without this it grew forever, and a
    /// restart would have replayed all of it. Returns whether it did.
    pub fn reset_journal_if_clean(&self) -> BlockResult<bool> {
        let Some(ref journal) = self.journal else {
            return Ok(false);
        };
        // Held across the rotation, so no write is logged in between.
        let caches = self.caches.write();
        if caches.values().any(|c| !c.dirty_chunks.is_empty()) {
            return Ok(false);
        }
        journal.rotate()?;
        drop(caches);
        Ok(true)
    }

    /// Create a checkpoint in the journal
    ///
    /// Entries before the checkpoint can be discarded on recovery.
    pub fn checkpoint(&self) -> BlockResult<()> {
        if let Some(ref journal) = self.journal {
            journal.checkpoint()?;
        }
        Ok(())
    }

    /// Recover unflushed writes from the journal
    ///
    /// Returns the writes that need to be replayed to restore cache state.
    pub fn recover(&self) -> BlockResult<Vec<(String, ChunkId, u64, Bytes)>> {
        let Some(ref journal) = self.journal else {
            return Ok(Vec::new());
        };

        let entries = journal.recover()?;
        let mut writes = Vec::new();

        for entry in entries {
            if let Some(data) = entry.data {
                writes.push((entry.volume_id, entry.chunk_id, entry.offset, data));
            }
        }

        info!("Recovered {} unflushed writes from journal", writes.len());
        Ok(writes)
    }

    /// Sync journal to disk
    pub fn sync(&self) -> BlockResult<()> {
        if let Some(ref journal) = self.journal {
            journal.sync()?;
        }
        Ok(())
    }

    /// [`Self::write`] from async code: run on the blocking pool, since it
    /// appends to the journal and fsyncs it. Returns once the write is
    /// durable, as `write` does; dropping the future does not undo it.
    ///
    /// # Errors
    /// As [`Self::write`], or if the blocking task cannot run.
    pub async fn write_durable(
        self: &Arc<Self>,
        volume_id: &str,
        offset: u64,
        data: Bytes,
    ) -> BlockResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        let cache = Arc::clone(self);
        let volume_id = volume_id.to_string();
        blocking(move || cache.write(&volume_id, offset, &data)).await
    }

    /// Write `length` zero bytes at `offset` (a trim), a piece of at most
    /// [`ZERO_PIECE`] at a time, so a large range is never one allocation
    /// of its whole length. Each piece is durable as [`Self::write_durable`].
    ///
    /// # Errors
    /// As [`Self::write`]; the pieces before a failed one stay written.
    pub async fn write_zeroes(
        self: &Arc<Self>,
        volume_id: &str,
        offset: u64,
        length: u64,
    ) -> BlockResult<()> {
        let end = offset
            .checked_add(length)
            .ok_or_else(|| BlockError::InvalidSize(format!("{length} bytes at {offset}")))?;
        let zeros = Bytes::from(vec![0u8; length.min(ZERO_PIECE) as usize]);
        let mut at = offset;
        while at < end {
            let piece = (end - at).min(ZERO_PIECE);
            self.write_durable(volume_id, at, zeros.slice(..piece as usize))
                .await?;
            at += piece;
        }
        Ok(())
    }

    /// [`Self::sync`] from async code, on the blocking pool.
    ///
    /// # Errors
    /// As [`Self::sync`], or if the blocking task cannot run.
    pub async fn sync_durable(self: &Arc<Self>) -> BlockResult<()> {
        let cache = Arc::clone(self);
        blocking(move || cache.sync()).await
    }

    /// [`Self::reset_journal_if_clean`] from async code, on the blocking
    /// pool.
    ///
    /// # Errors
    /// As [`Self::reset_journal_if_clean`], or if the blocking task cannot
    /// run.
    pub async fn reset_journal_if_clean_async(self: &Arc<Self>) -> BlockResult<bool> {
        let cache = Arc::clone(self);
        blocking(move || cache.reset_journal_if_clean()).await
    }

    /// Every dirty chunk of a volume with its version, to flush now. They
    /// stay dirty until [`Self::mark_flushed`], so a chunk whose flush fails
    /// is retried rather than dropped.
    pub fn dirty_chunks(&self, volume_id: &str) -> Vec<(ChunkId, Bytes, u64)> {
        self.caches
            .read()
            .get(volume_id)
            .map(|c| {
                c.dirty_chunks
                    .iter()
                    .filter(|(_, d)| d.pending.is_none())
                    .map(|(id, d)| (*id, d.data.clone(), d.version))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if we should trigger a flush due to cache pressure
    fn should_flush(&self) -> bool {
        *self.total_dirty_bytes.read() >= self.config.max_cache_bytes * 80 / 100
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let caches = self.caches.read();
        let mut stats = CacheStats::default();

        for cache in caches.values() {
            stats.dirty_bytes += cache.dirty_bytes;
            stats.clean_bytes += cache.clean_bytes;
            stats.dirty_chunks += cache.dirty_chunks.len();
            stats.clean_chunks += cache.clean_chunks.len();
        }

        stats.volume_count = caches.len();
        stats
    }
}

/// Cache statistics
#[derive(Debug, Default)]
pub struct CacheStats {
    /// Number of volumes with cached data
    pub volume_count: usize,
    /// Total dirty bytes
    pub dirty_bytes: u64,
    /// Total clean bytes
    pub clean_bytes: u64,
    /// Number of dirty chunks
    pub dirty_chunks: usize,
    /// Number of clean chunks
    pub clean_chunks: usize,
}

/// Whether `ranges` cover `0..len` (merged in place as a side effect).
fn covers(ranges: &mut Vec<(u32, u32)>, len: usize) -> bool {
    ranges.sort_unstable();
    let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
    for &(off, l) in ranges.iter() {
        match merged.last_mut() {
            Some(last) if off <= last.0 + last.1 => {
                last.1 = last.1.max(off + l - last.0);
            }
            _ => merged.push((off, l)),
        }
    }
    *ranges = merged;
    ranges.len() == 1 && ranges[0] == (0, len as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resolve every pending chunk as never stored (zeros), as the gateway
    /// does for a chunk with no stripe.
    fn settle(cache: &WriteCache, vol: &str) {
        for c in cache.pending_chunks(vol) {
            cache.resolve(vol, c, &[]);
        }
    }

    fn test_cache() -> WriteCache {
        let mapper = Arc::new(ChunkMapper::new(1024 * 1024)); // 1MB chunks for testing
        WriteCache::with_defaults(mapper)
    }

    #[test]
    fn test_write_single_chunk() {
        let cache = test_cache();
        cache.init_volume("vol1");

        let data = vec![0xABu8; 4096]; // 4KB
        cache.write("vol1", 0, &data).unwrap();
        settle(&cache, "vol1");

        // Should be able to read it back
        let read = cache.read("vol1", 0, 4096).unwrap();
        assert_eq!(read, data);

        // Stats should show dirty data
        let stats = cache.stats();
        assert_eq!(stats.dirty_chunks, 1);
        assert!(stats.dirty_bytes > 0);
    }

    #[test]
    fn test_write_spanning_chunks() {
        let cache = test_cache();
        cache.init_volume("vol1");

        // Write 2MB starting at 512KB (spans chunks 0 and 1)
        let data = vec![0xCDu8; 2 * 1024 * 1024];
        cache.write("vol1", 512 * 1024, &data).unwrap();
        settle(&cache, "vol1");

        // Should have 3 dirty chunks (512KB in chunk 0, 1MB in chunk 1, 512KB in chunk 2)
        let stats = cache.stats();
        assert_eq!(stats.dirty_chunks, 3);

        // Read back should work
        let read = cache.read("vol1", 512 * 1024, 2 * 1024 * 1024).unwrap();
        assert_eq!(read, data);
    }

    #[test]
    fn test_flush() {
        let cache = test_cache();
        cache.init_volume("vol1");

        let data = vec![0xEFu8; 4096];
        cache.write("vol1", 0, &data).unwrap();
        settle(&cache, "vol1");

        // The dirty chunk is offered for flushing, and clean once flushed
        let dirty = cache.dirty_chunks("vol1");
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].0, 0); // Chunk ID 0
        cache.mark_flushed("vol1", &[(dirty[0].0, dirty[0].2)]);

        // After flush, stats should show no dirty data
        let stats = cache.stats();
        assert_eq!(stats.dirty_chunks, 0);
        assert_eq!(stats.dirty_bytes, 0);
    }

    #[test]
    fn test_read_cache_miss() {
        let cache = test_cache();
        cache.init_volume("vol1");

        // Reading without writing should return None (cache miss)
        let read = cache.read("vol1", 0, 4096);
        assert!(read.is_none());
    }

    /// A write that lands while its chunk is being flushed must not be
    /// marked clean with the older bytes the flush wrote out.
    #[test]
    fn a_write_during_a_flush_stays_dirty() {
        let cache = test_cache();
        cache.init_volume("vol1");
        cache.write("vol1", 0, &[1u8; 4096]).unwrap();
        settle(&cache, "vol1");
        let in_flight = cache.dirty_chunks("vol1");

        cache.write("vol1", 4096, &[2u8; 4096]).unwrap(); // during the flush
        cache.mark_flushed("vol1", &[(in_flight[0].0, in_flight[0].2)]);

        let still = cache.dirty_chunks("vol1");
        assert_eq!(still.len(), 1, "the newer write was dropped");
        assert_eq!(&still[0].1[4096..8192], &[2u8; 4096]);
    }

    /// A partial write to a chunk the cache does not hold is taken at once
    /// and waits for the chunk's stored bytes: never flushed or served
    /// whole until they are merged in, and then every written byte wins.
    #[test]
    fn a_partial_write_waits_for_its_chunk_and_wins_over_it() {
        let cache = test_cache();
        cache.init_volume("vol1");
        cache.write("vol1", 4096, &[7u8; 4096]).unwrap();
        assert!(cache.is_pending("vol1", 0));
        assert!(cache.chunk("vol1", 0).is_none());
        assert!(cache.read("vol1", 0, 8192).is_none(), "served half a chunk");
        assert!(
            cache.dirty_chunks("vol1").is_empty(),
            "flushable while pending"
        );
        assert_eq!(cache.pending_chunks("vol1"), vec![0]);

        // Another write lands before the stored bytes do.
        cache.write("vol1", 0, &[8u8; 100]).unwrap();
        let stored = vec![1u8; 1024 * 1024];
        cache.resolve("vol1", 0, &stored);
        let whole = cache.chunk("vol1", 0).expect("whole after resolve");
        assert_eq!(&whole[..100], &[8u8; 100]);
        assert_eq!(&whole[100..4096], &[1u8; 3996][..]);
        assert_eq!(&whole[4096..8192], &[7u8; 4096]);
        assert_eq!(&whole[8192..8200], &[1u8; 8]);
        assert_eq!(cache.dirty_chunks("vol1").len(), 1);
        // Resolving again changes nothing.
        cache.resolve("vol1", 0, &vec![9u8; 1024 * 1024]);
        assert_eq!(cache.chunk("vol1", 0).unwrap(), whole);
    }

    /// Writes that between them cover the chunk need nothing stored.
    #[test]
    fn writes_covering_a_chunk_need_none_of_its_stored_bytes() {
        let cache = test_cache();
        cache.init_volume("vol1");
        let half = 512 * 1024;
        cache
            .write("vol1", half, &vec![2u8; half as usize])
            .unwrap();
        assert!(cache.is_pending("vol1", 0));
        cache.write("vol1", 0, &vec![3u8; half as usize]).unwrap();
        assert!(!cache.is_pending("vol1", 0));
        assert_eq!(cache.dirty_chunks("vol1").len(), 1);
    }

    /// A chunk is written in place, but never under a flush: the bytes a
    /// flush took stay what they were when it took them.
    #[test]
    fn a_write_does_not_change_the_bytes_a_flush_is_storing() {
        let cache = test_cache();
        cache.init_volume("vol1");
        cache.write("vol1", 0, &[1u8; 4096]).unwrap();
        settle(&cache, "vol1");
        let taken = cache.dirty_chunks("vol1");
        cache.write("vol1", 0, &[2u8; 4096]).unwrap();
        assert_eq!(
            &taken[0].1[..4096],
            &[1u8; 4096],
            "the flush's bytes changed"
        );
        let now = cache.dirty_chunks("vol1");
        assert_eq!(&now[0].1[..4096], &[2u8; 4096]);
        assert!(
            now[0].2 > taken[0].2,
            "the newer write must be flushed again"
        );
    }

    /// Writes logged since the journal was reopened are recovered, and
    /// resetting it once clean leaves nothing to replay.
    #[test]
    fn the_journal_recovers_writes_across_a_reopen_and_empties_when_clean() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("block.journal");
        let mapper = Arc::new(ChunkMapper::default());
        {
            let cache = WriteCache::with_journal(Arc::clone(&mapper), &path);
            cache.init_volume("vol1");
            cache.write("vol1", 0, b"first").unwrap();
        }
        let cache = WriteCache::with_journal(Arc::clone(&mapper), &path);
        cache.init_volume("vol1");
        cache.write("vol1", 4096, b"after a reopen").unwrap();
        settle(&cache, "vol1");
        let recovered: Vec<_> = cache.recover().unwrap().into_iter().map(|w| w.3).collect();
        assert_eq!(recovered, vec![&b"first"[..], &b"after a reopen"[..]]);

        let dirty = cache.dirty_chunks("vol1");
        assert!(
            !cache.reset_journal_if_clean().unwrap(),
            "reset with dirty data"
        );
        cache.mark_flushed("vol1", &[(dirty[0].0, dirty[0].2)]);
        assert!(cache.reset_journal_if_clean().unwrap());
        assert!(cache.recover().unwrap().is_empty());
    }

    /// A write from async code is journaled before it returns: a cache
    /// opened on the same journal recovers it.
    #[tokio::test]
    async fn write_durable_is_journaled_when_it_returns() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("block.journal");
        let mapper = Arc::new(ChunkMapper::default());
        let cache = Arc::new(WriteCache::with_journal(Arc::clone(&mapper), &path));
        cache.init_volume("vol1");
        cache
            .write_durable("vol1", 8192, Bytes::from_static(b"durable"))
            .await
            .unwrap();
        cache.sync_durable().await.unwrap();
        settle(&cache, "vol1");
        assert_eq!(cache.read("vol1", 8192, 7).unwrap(), b"durable");

        let reopened = WriteCache::with_journal(mapper, &path);
        let recovered: Vec<_> = reopened
            .recover()
            .unwrap()
            .into_iter()
            .map(|w| w.3)
            .collect();
        assert_eq!(recovered, vec![&b"durable"[..]]);
        assert!(
            !cache.reset_journal_if_clean_async().await.unwrap(),
            "reset with dirty data"
        );
    }

    /// Zeroes go in a piece at a time across chunks, and only the range
    /// given is zeroed.
    #[tokio::test]
    async fn write_zeroes_zeroes_just_the_range_in_pieces() {
        let cache = Arc::new(test_cache()); // 1 MiB chunks
        cache.init_volume("vol1");
        let len = 3 * ZERO_PIECE;
        cache.write("vol1", 0, &vec![0xab; len as usize]).unwrap();
        // Unaligned, longer than one piece, across many chunks.
        let (off, n) = (4097, ZERO_PIECE + 12_345);
        cache.write_zeroes("vol1", off, n).await.unwrap();
        settle(&cache, "vol1");
        let got = cache.read("vol1", 0, len).unwrap();
        for (i, b) in got.iter().enumerate() {
            let zeroed = (off..off + n).contains(&(i as u64));
            assert_eq!(*b, if zeroed { 0 } else { 0xab }, "byte {i}");
        }
        assert!(cache.write_zeroes("vol1", u64::MAX, 2).await.is_err());
    }
}
