//! Deduplication: chunking, fingerprints, and the phase-1 dry-run.
//!
//! Design: objectio-docs `architecture/design/core/dedup.md`. Dry-run measures
//! what dedup would save without changing how anything is stored: after a
//! PUT or UploadPart has answered, its body is cut into content-defined
//! chunks, each chunk fingerprinted within the bucket's dedup domain, and
//! every fingerprint noted on the OSD that would own it, which says whether
//! it had seen it before.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use objectio_proto::metadata::LocateChunksRequest;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::storage::NoteChunksRequest;
use tokio::sync::mpsc;
use tonic::transport::Channel;
use tracing::debug;

use crate::osd_pool::OsdPool;

/// A content-defined chunking: boundaries come from the bytes, so the same
/// data chunks the same way wherever it sits.
#[derive(Debug, Clone, Copy)]
pub struct Chunking {
    /// Metric label, and part of every fingerprint, so chunks cut one way
    /// never match chunks cut another.
    pub name: &'static str,
    pub min: u32,
    pub avg: u32,
    pub max: u32,
}

/// What dry-run measures. Content-defined chunking resynchronises only
/// when a multipart part spans several chunks, so the average size decides
/// how much of a file uploaded in parts matches the same file uploaded
/// whole. On 512 MiB of random bytes, the share that matched:
///
/// | average | 5 MiB parts | 8 MiB | 16 MiB | 64 MiB |
/// |---|---|---|---|---|
/// | 1 MiB | 55% | 71% | 86% | 96% |
/// | 4 MiB | 3% | 13% | 40% | 82% |
///
/// Smaller chunks find more but mean smaller stripes. Measuring both on
/// real data is what decides phase 2.
pub const CHUNKINGS: [Chunking; 2] = [
    Chunking {
        name: "1MiB",
        min: 256 * 1024,
        avg: 1024 * 1024,
        max: 4 * 1024 * 1024,
    },
    Chunking {
        name: "4MiB",
        min: 1024 * 1024,
        avg: 4 * 1024 * 1024,
        max: 8 * 1024 * 1024,
    },
];

/// Bodies queued for dry-run at once. Beyond it a body is dropped and
/// counted: dry-run must never hold up, or run the gateway out of memory
/// under, real traffic.
const MAX_QUEUED_BYTES: u64 = 512 * 1024 * 1024;

/// Bodies processed at once. Each one hashes on a blocking thread.
const WORKERS: usize = 2;

/// `(offset, length)` of each chunk of `body`.
#[must_use]
pub fn chunks(body: &[u8], c: &Chunking) -> Vec<(usize, usize)> {
    fastcdc::v2020::FastCDC::new(body, c.min, c.avg, c.max)
        .map(|c| (c.offset, c.length))
        .collect()
}

/// A chunk's fingerprint within `domain`: equal only for equal bytes in
/// the same domain. The domain is length-prefixed so no domain/bytes split
/// can collide with another.
#[must_use]
pub fn fingerprint(domain: &str, chunk: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&(domain.len() as u64).to_le_bytes());
    h.update(domain.as_bytes());
    h.update(chunk);
    *h.finalize().as_bytes()
}

struct Job {
    bucket: String,
    domain: String,
    body: Bytes,
}

/// The dry-run queue and its workers.
pub struct DryRun {
    tx: mpsc::Sender<Job>,
    queued_bytes: Arc<AtomicU64>,
}

impl DryRun {
    /// Start the workers. Needs a tokio runtime.
    #[must_use]
    pub fn start(meta: MetadataServiceClient<Channel>, osd_pool: Arc<OsdPool>) -> Self {
        let (tx, rx) = mpsc::channel::<Job>(1024);
        let rx = Arc::new(tokio::sync::Mutex::new(rx));
        let queued_bytes = Arc::new(AtomicU64::new(0));
        for _ in 0..WORKERS {
            let rx = Arc::clone(&rx);
            let meta = meta.clone();
            let pool = Arc::clone(&osd_pool);
            let queued = Arc::clone(&queued_bytes);
            tokio::spawn(async move {
                loop {
                    let Some(job) = rx.lock().await.recv().await else {
                        return;
                    };
                    let len = job.body.len() as u64;
                    note(&mut meta.clone(), &pool, job).await;
                    queued.fetch_sub(len, Ordering::Relaxed);
                }
            });
        }
        Self { tx, queued_bytes }
    }

    /// Queue `body`, just written to `bucket`, for dry-run accounting —
    /// or drop it and count the drop if too much is already queued.
    pub fn submit(&self, bucket: &str, domain: &str, body: Bytes) {
        let len = body.len() as u64;
        if self.queued_bytes.fetch_add(len, Ordering::Relaxed) + len > MAX_QUEUED_BYTES {
            self.queued_bytes.fetch_sub(len, Ordering::Relaxed);
            crate::gateway_metrics::record_dedup_dropped("queue_full");
            return;
        }
        let job = Job {
            bucket: bucket.to_string(),
            domain: domain.to_string(),
            body,
        };
        if self.tx.try_send(job).is_err() {
            self.queued_bytes.fetch_sub(len, Ordering::Relaxed);
            crate::gateway_metrics::record_dedup_dropped("queue_full");
        }
    }
}

/// Chunk, fingerprint, locate and note one body, and count the result.
async fn note(meta: &mut MetadataServiceClient<Channel>, pool: &OsdPool, job: Job) {
    let Job {
        bucket,
        domain,
        body,
    } = job;
    // (fingerprint, length, chunking) for every chunk under every chunking.
    let hashed = tokio::task::spawn_blocking(move || {
        CHUNKINGS
            .iter()
            .flat_map(|c| {
                let domain = format!("{domain}|{}", c.name);
                chunks(&body, c)
                    .into_iter()
                    .map(|(off, len)| (fingerprint(&domain, &body[off..off + len]), len, c.name))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    })
    .await;
    let Ok(chunks) = hashed else {
        crate::gateway_metrics::record_dedup_dropped("hash_failed");
        return;
    };
    if chunks.is_empty() {
        return;
    }

    let located = meta
        .locate_chunks(LocateChunksRequest {
            bucket: bucket.clone(),
            fingerprints: chunks.iter().map(|(fp, _, _)| fp.to_vec()).collect(),
        })
        .await;
    let located = match located {
        Ok(r) => r.into_inner(),
        Err(e) => {
            debug!("dedup dry-run: locate failed for {bucket}: {e}");
            crate::gateway_metrics::record_dedup_dropped("locate_failed");
            return;
        }
    };

    // One NoteChunks per owning OSD.
    let mut by_osd: HashMap<(Vec<u8>, String), Vec<usize>> = HashMap::new();
    for (i, (id, addr)) in located.node_ids.iter().zip(&located.addresses).enumerate() {
        if !addr.is_empty() && i < chunks.len() {
            by_osd
                .entry((id.clone(), addr.clone()))
                .or_default()
                .push(i);
        }
    }
    for ((node_id, addr), idx) in by_osd {
        let seen = async {
            let mut client = pool.get_or_connect(&node_id, &addr).await.ok()?;
            let resp = client
                .note_chunks(NoteChunksRequest {
                    fingerprints: idx.iter().map(|&i| chunks[i].0.to_vec()).collect(),
                })
                .await
                .ok()?;
            Some(resp.into_inner().seen)
        }
        .await;
        let Some(seen) = seen.filter(|s| s.len() == idx.len()) else {
            crate::gateway_metrics::record_dedup_dropped("note_failed");
            continue;
        };
        for (&i, dup) in idx.iter().zip(seen) {
            let (_, len, chunking) = chunks[i];
            crate::gateway_metrics::record_dedup_chunk(&bucket, chunking, dup, len as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes that do not repeat, so chunk boundaries are content-defined
    /// rather than an artefact of a pattern.
    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ seed;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x.to_le_bytes()[0]
            })
            .collect()
    }

    const SMALL: Chunking = CHUNKINGS[0];
    const LARGE: Chunking = CHUNKINGS[1];

    fn fingerprints(body: &[u8], c: &Chunking) -> Vec<[u8; 32]> {
        chunks(body, c)
            .into_iter()
            .map(|(o, l)| fingerprint("", &body[o..o + l]))
            .collect()
    }

    /// Share of `body`'s chunks (cut whole) that reappear when it is cut
    /// in `part`-sized pieces first, as a multipart upload is.
    fn shared_across_parts(body: &[u8], part: usize, c: &Chunking) -> f64 {
        let whole: std::collections::HashSet<_> = fingerprints(body, c).into_iter().collect();
        let parts: Vec<[u8; 32]> = body.chunks(part).flat_map(|p| fingerprints(p, c)).collect();
        parts.iter().filter(|f| whole.contains(*f)).count() as f64 / whole.len() as f64
    }

    #[test]
    fn chunks_cover_the_body_within_their_bounds() {
        let body = noise(24 << 20, 1);
        for c in &CHUNKINGS {
            let cs = chunks(&body, c);
            assert_eq!(cs.iter().map(|c| c.1).sum::<usize>(), body.len());
            let (last, rest) = cs.split_last().unwrap();
            assert!(
                rest.iter()
                    .all(|x| x.1 >= c.min as usize && x.1 <= c.max as usize)
            );
            assert!(last.1 <= c.max as usize);
        }
    }

    /// Why content-defined chunks: a file uploaded in parts still mostly
    /// chunks as it does whole — when parts span several chunks. The
    /// measured table on `CHUNKINGS` is the same effect at scale.
    #[test]
    fn a_file_uploaded_in_parts_mostly_matches_it_uploaded_whole() {
        let body = noise(64 << 20, 2);
        let small = shared_across_parts(&body, 16 << 20, &SMALL);
        assert!(small > 0.7, "1 MiB chunks, 16 MiB parts: {small:.2}");
        let large = shared_across_parts(&body, 32 << 20, &LARGE);
        assert!(large > 0.4, "4 MiB chunks, 32 MiB parts: {large:.2}");
    }

    /// An insertion moves only the chunks around it — backups.
    #[test]
    fn an_insertion_disturbs_only_nearby_chunks() {
        let body = noise(24 << 20, 3);
        let mut edited = body[..10 << 20].to_vec();
        edited.extend_from_slice(b"a few inserted bytes");
        edited.extend_from_slice(&body[10 << 20..]);
        for c in &CHUNKINGS {
            let before: std::collections::HashSet<_> = fingerprints(&body, c).into_iter().collect();
            let changed = fingerprints(&edited, c)
                .iter()
                .filter(|f| !before.contains(*f))
                .count();
            assert!(
                changed <= 3,
                "{}: {changed} chunks changed for one insertion",
                c.name
            );
        }
    }

    #[test]
    fn the_domain_separates_identical_bytes() {
        let chunk = noise(1 << 20, 4);
        assert_eq!(fingerprint("b:t/x", &chunk), fingerprint("b:t/x", &chunk));
        assert_ne!(fingerprint("b:t/x", &chunk), fingerprint("b:t/y", &chunk));
        assert_ne!(fingerprint("", &chunk), fingerprint("t:t", &chunk));
    }
}
