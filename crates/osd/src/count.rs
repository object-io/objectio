//! Counting what an OSD holds while it serves (objectio-docs
//! `core/osd-start.md`): its PG summaries and bucket usage, after a start.
//!
//! A count walks its prefixes a chunk at a time. Each chunk is read from a
//! snapshot of its own, taken with every write that changes the count held
//! off, and at that moment the count's fence moves to the chunk's end: a
//! write to a key below the fence changes the count (it is kept aside, and
//! folded in at the end); a write above it does not, since a later chunk's
//! snapshot will see it. Each write is counted once: in a snapshot, or as a
//! change, never both and never neither.
//!
//! A snapshot is kept only while its chunk is read. One held for the whole
//! count kept the index file from reusing any page a checkpoint rewrote
//! meanwhile: under a million and a half writes during a nine-minute
//! count, the index of an OSD of ten million shards grew from 22 GB to
//! 46 GB.

use objectio_storage::metadata::{MetaIndex, MetaSnapshot, MetadataKey};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Entries per chunk: about 60 MB of object metadata, read in a second or
/// two from a cold drive.
pub(crate) const CHUNK: usize = 65_536;

/// What keeps a count in step with the writes that change it.
pub(crate) trait Fence {
    /// With every write that changes the count held off, take `snapshot`
    /// and move the fence to `below`: from then on a write to a key below
    /// it changes the count.
    fn advance(
        &self,
        below: &[u8],
        snapshot: &mut dyn FnMut() -> Option<Arc<dyn MetaSnapshot>>,
    ) -> Option<Arc<dyn MetaSnapshot>>;
}

/// The smallest key past every key under `prefix`.
fn past(prefix: &[u8]) -> Vec<u8> {
    let mut end = prefix.to_vec();
    while let Some(last) = end.pop() {
        if last < u8::MAX {
            end.push(last + 1);
            return end;
        }
    }
    vec![u8::MAX; prefix.len() + 1]
}

/// The smallest key past `key`.
fn after(key: &[u8]) -> Vec<u8> {
    let mut next = key.to_vec();
    next.push(0);
    next
}

/// Call `f` on every entry under `prefixes` (in key order) of `index`, a
/// chunk of `chunk` entries at a time, each from a snapshot taken through
/// `fence`. False if `stop` was set first. An engine that keeps no
/// snapshots is read as it is: only while nothing writes.
pub(crate) fn walk(
    index: &dyn MetaIndex,
    prefixes: &[MetadataKey],
    chunk: usize,
    fence: &dyn Fence,
    stop: &AtomicBool,
    f: &mut dyn FnMut(&[u8], &[u8]),
) -> bool {
    for prefix in prefixes {
        let end = past(prefix.as_bytes());
        let mut last: Option<MetadataKey> = None;
        loop {
            if stop.load(Ordering::Relaxed) {
                return false;
            }
            // Where this chunk ends: the index as it is, only for a bound.
            let mut n = 0;
            let mut upto = None;
            index.for_each_prefix(prefix, last.as_ref(), &mut |k, _| {
                n += 1;
                if n < chunk {
                    return true;
                }
                upto = Some(k.to_vec());
                false
            });
            let from = last
                .as_ref()
                .map_or_else(|| prefix.as_bytes().to_vec(), |l| after(l.as_bytes()));
            let below = upto.as_deref().map_or_else(|| end.clone(), after);
            let mut go = |k: &[u8], v: &[u8]| {
                f(k, v);
                !stop.load(Ordering::Relaxed)
            };
            match fence.advance(&below, &mut || index.snapshot(&from, &below)) {
                Some(snapshot) => snapshot.scan(&mut go),
                None => index.for_each_prefix(prefix, last.as_ref(), &mut |k, v| {
                    k < below.as_slice() && go(k, v)
                }),
            }
            match upto {
                Some(u) => last = Some(MetadataKey::from_bytes(u)),
                None => break,
            }
        }
    }
    !stop.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn past_a_prefix() {
        assert_eq!(past(b"m"), b"n");
        assert_eq!(past(b"pg/\xff"), b"pg0");
        assert_eq!(after(b"k1"), b"k1\0");
        assert!(after(b"k1").as_slice() < b"k10".as_slice());
    }
}
