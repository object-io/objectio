//! Meta's placement answers, per key, for a short while (B21): a GET of a
//! key read or written lately skips the `GetPlacement` call. Placement is
//! meta's to decide (pools, placement groups, the key's home), so this
//! only remembers what meta said; it is never computed here.
//!
//! An entry can be stale: the key's home may have moved since (repair's
//! backfill, a lost OSD's evacuation). A read through a cached placement
//! that finds nothing, or fails, forgets the entry and asks meta again
//! (`get_object_version`), so staleness costs a retry, never a wrong
//! answer: reads take the newest copy of a quorum of the copies they ask.

use objectio_proto::metadata::GetPlacementResponse;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// How long an answer is used.
pub const TTL: Duration = Duration::from_secs(30);

/// Keys remembered at most; beyond it, expired entries go, then half.
const CAPACITY: usize = 65_536;

static CACHE: LazyLock<Mutex<HashMap<String, (Instant, GetPlacementResponse)>>> =
    LazyLock::new(Default::default);

fn cache_key(bucket: &str, key: &str) -> String {
    format!("{bucket}/{key}")
}

fn lock() -> std::sync::MutexGuard<'static, HashMap<String, (Instant, GetPlacementResponse)>> {
    CACHE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What meta last said about `bucket/key`'s placement, if lately.
#[must_use]
pub fn get(bucket: &str, key: &str) -> Option<GetPlacementResponse> {
    let cache = lock();
    cache
        .get(&cache_key(bucket, key))
        .filter(|(at, _)| at.elapsed() < TTL)
        .map(|(_, p)| p.clone())
}

/// Remember meta's answer for `bucket/key`.
pub fn put(bucket: &str, key: &str, placement: &GetPlacementResponse) {
    let mut cache = lock();
    if cache.len() >= CAPACITY {
        cache.retain(|_, (at, _)| at.elapsed() < TTL);
        if cache.len() >= CAPACITY {
            let drop: Vec<String> = cache.keys().take(CAPACITY / 2).cloned().collect();
            for k in drop {
                cache.remove(&k);
            }
        }
    }
    cache.insert(cache_key(bucket, key), (Instant::now(), placement.clone()));
}

/// Forget `bucket/key`: a read through the cached answer failed.
pub fn forget(bucket: &str, key: &str) {
    lock().remove(&cache_key(bucket, key));
}

/// Forget every answer naming placement group `pool/pg_id` (B31): an OSD
/// refused a request placed under one of its epochs as old.
pub fn forget_pg(pool: &str, pg_id: u32) {
    lock().retain(|_, (_, p)| !(p.pool == pool && p.pg_id == pg_id));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembered_then_forgotten() {
        let p = GetPlacementResponse {
            pg_id: 7,
            ..Default::default()
        };
        assert!(get("b-cache-test", "k").is_none());
        put("b-cache-test", "k", &p);
        assert_eq!(get("b-cache-test", "k").map(|p| p.pg_id), Some(7));
        forget("b-cache-test", "k");
        assert!(get("b-cache-test", "k").is_none());
    }
}
