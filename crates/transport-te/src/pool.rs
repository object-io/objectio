//! Fixed-size slots carved from one aligned allocation.
//!
//! Registering memory with a NIC pins its pages and programs the card, which
//! is far too slow to do per request. So each process allocates one region at
//! startup, registers it once, and hands out slots from it.
//!
//! Slots are 4 KiB-aligned and a multiple of 4 KiB long, so an OSD's staging
//! slot is directly usable as an `O_DIRECT` buffer.
//!
//! A slot is returned to its pool when the [`Slot`] — or, after
//! [`Slot::into_bytes`], the last `Bytes` view of it — is dropped. The region
//! itself lives until the pool and every slot from it are gone.

// The pool hands out raw memory. The invariants that make it sound are stated
// on `Region`; every `unsafe` block below relies on them.
#![allow(unsafe_code)]

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ptr::NonNull;
use std::sync::{Arc, Mutex, PoisonError};

use bytes::Bytes;

use crate::Error;

/// Alignment and size granularity of every slot: `O_DIRECT` needs 4 KiB.
pub const ALIGN: usize = 4096;

/// One allocation, split into `slots` slots of `slot_size` bytes.
///
/// Invariants:
/// - `base` points to `slots * slot_size` bytes allocated with `layout`,
///   valid until `Region` is dropped.
/// - A slot index is either in `free` or held by exactly one [`Slot`], never
///   both, so no two `Slot`s alias the same memory.
struct Region {
    base: NonNull<u8>,
    layout: Layout,
    slot_size: usize,
    slots: usize,
    free: Mutex<Vec<usize>>,
}

// SAFETY: `Region` owns its allocation outright, and its memory is only
// reached through a `Slot`, which holds its index exclusively (see the
// invariants above). The free list is behind a mutex.
unsafe impl Send for Region {}
// SAFETY: as above; shared access only reads `base`, `slot_size` and `slots`,
// or goes through the mutex.
unsafe impl Sync for Region {}

impl Drop for Region {
    fn drop(&mut self) {
        // SAFETY: `base` was allocated with `layout` in `SlotPool::new` and is
        // freed exactly once, here. No `Slot` outlives the region: each holds
        // an `Arc<Region>`.
        unsafe { dealloc(self.base.as_ptr(), self.layout) }
    }
}

impl Region {
    fn release(&self, index: usize) {
        self.free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(index);
    }
}

/// A pool of fixed-size, 4 KiB-aligned slots from one allocation.
///
/// Cloning is cheap and shares the pool.
#[derive(Clone)]
pub struct SlotPool {
    region: Arc<Region>,
}

impl SlotPool {
    /// A pool of `slots` slots, each at least `slot_size` bytes (rounded up to
    /// a multiple of [`ALIGN`]). The memory starts zeroed.
    ///
    /// # Errors
    /// [`Error::InvalidPool`] for a zero size or count, or a total that
    /// overflows; [`Error::OutOfMemory`] if the allocation fails.
    pub fn new(slot_size: usize, slots: usize) -> Result<Self, Error> {
        if slot_size == 0 || slots == 0 {
            return Err(Error::InvalidPool(
                "slot size and slot count must be non-zero",
            ));
        }
        let slot_size = slot_size
            .checked_next_multiple_of(ALIGN)
            .ok_or(Error::InvalidPool("slot size overflows"))?;
        let len = slot_size
            .checked_mul(slots)
            .ok_or(Error::InvalidPool("pool size overflows"))?;
        let layout = Layout::from_size_align(len, ALIGN)
            .map_err(|_| Error::InvalidPool("pool too large"))?;
        // SAFETY: `layout` has a non-zero size (both factors are non-zero).
        let base = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or(Error::OutOfMemory(len))?;
        Ok(Self {
            region: Arc::new(Region {
                base,
                layout,
                slot_size,
                slots,
                // Reversed so slots are handed out from the start of the region.
                free: Mutex::new((0..slots).rev().collect()),
            }),
        })
    }

    /// Take a free slot, or `None` if every slot is in use. Never waits: a
    /// caller with no slot falls back to another path.
    #[must_use]
    pub fn acquire(&self) -> Option<Slot> {
        let index = self
            .region
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()?;
        Some(Slot {
            region: Arc::clone(&self.region),
            index,
        })
    }

    /// Start of the region, for registering it with a NIC.
    #[must_use]
    pub fn base_ptr(&self) -> *mut u8 {
        self.region.base.as_ptr()
    }

    /// Length of the region in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.region.layout.size()
    }

    /// Always false: a pool has at least one slot.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Size of each slot, after rounding up to [`ALIGN`].
    #[must_use]
    pub fn slot_size(&self) -> usize {
        self.region.slot_size
    }

    /// Number of slots in the pool.
    #[must_use]
    pub fn slots(&self) -> usize {
        self.region.slots
    }

    /// Slots free right now.
    #[must_use]
    pub fn available(&self) -> usize {
        self.region
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether `[addr, addr + len)` lies entirely inside this pool.
    #[must_use]
    pub fn contains(&self, addr: u64, len: u64) -> bool {
        let base = self.base_ptr() as u64;
        addr >= base
            && addr
                .checked_add(len)
                .is_some_and(|end| end <= base + self.len() as u64)
    }
}

/// One slot of a [`SlotPool`], held exclusively until dropped.
pub struct Slot {
    region: Arc<Region>,
    index: usize,
}

impl Slot {
    /// The slot's size in bytes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.region.slot_size
    }

    /// Start of the slot's memory.
    #[must_use]
    pub fn as_ptr(&self) -> *mut u8 {
        // SAFETY: `index < slots`, so the offset stays inside the allocation.
        unsafe {
            self.region
                .base
                .as_ptr()
                .add(self.index * self.region.slot_size)
        }
    }

    /// The slot's address as a peer sees it in a transfer request.
    #[must_use]
    pub fn addr(&self) -> u64 {
        self.as_ptr() as u64
    }

    /// The whole slot.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        // SAFETY: the slot's bytes are inside the live allocation, initialised
        // (the region is zeroed at allocation), and not aliased by any other
        // `Slot` (region invariant).
        unsafe { std::slice::from_raw_parts(self.as_ptr(), self.capacity()) }
    }

    /// The whole slot, mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: as for `as_slice`, and `&mut self` makes this the only
        // reference to the slot's bytes.
        unsafe { std::slice::from_raw_parts_mut(self.as_ptr(), self.capacity()) }
    }

    /// Freeze the first `len` bytes as `Bytes` without copying. The slot goes
    /// back to the pool when the last clone or slice of it is dropped.
    ///
    /// # Panics
    /// If `len` exceeds the slot's capacity.
    #[must_use]
    pub fn into_bytes(self, len: usize) -> Bytes {
        assert!(
            len <= self.capacity(),
            "{len} bytes do not fit a {}-byte slot",
            self.capacity()
        );
        Bytes::from_owner(Frozen { slot: self, len })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.region.release(self.index);
    }
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Slot")
            .field("index", &self.index)
            .field("addr", &format_args!("{:#x}", self.addr()))
            .field("capacity", &self.capacity())
            .finish_non_exhaustive()
    }
}

/// A slot frozen into `Bytes`: read-only from here on.
struct Frozen {
    slot: Slot,
    len: usize,
}

impl AsRef<[u8]> for Frozen {
    fn as_ref(&self) -> &[u8] {
        &self.slot.as_slice()[..self.len]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_aligned_distinct_and_rounded_up() {
        let pool = SlotPool::new(5000, 4).unwrap();
        assert_eq!(pool.slot_size(), 8192);
        assert_eq!(pool.len(), 4 * 8192);
        let slots: Vec<Slot> = (0..4).map(|_| pool.acquire().unwrap()).collect();
        let mut addrs: Vec<u64> = slots.iter().map(Slot::addr).collect();
        assert!(addrs.iter().all(|a| a % ALIGN as u64 == 0));
        addrs.sort_unstable();
        addrs.dedup();
        assert_eq!(addrs.len(), 4, "two slots share an address");
        assert!(slots.iter().all(|s| pool.contains(s.addr(), 8192)));
    }

    #[test]
    fn exhausts_and_refills() {
        let pool = SlotPool::new(ALIGN, 2).unwrap();
        let a = pool.acquire().unwrap();
        let b = pool.acquire().unwrap();
        assert!(pool.acquire().is_none());
        assert_eq!(pool.available(), 0);
        drop(a);
        assert_eq!(pool.available(), 1);
        let c = pool.acquire().unwrap();
        drop((b, c));
        assert_eq!(pool.available(), 2);
    }

    #[test]
    fn bytes_hold_the_slot_until_the_last_view_drops() {
        let pool = SlotPool::new(ALIGN, 1).unwrap();
        let mut slot = pool.acquire().unwrap();
        slot.as_mut_slice()[..5].copy_from_slice(b"hello");
        let bytes = slot.into_bytes(5);
        let tail = bytes.slice(1..);
        drop(bytes);
        assert_eq!(pool.available(), 0, "slot freed while a view is alive");
        assert_eq!(&tail[..], b"ello");
        drop(tail);
        assert_eq!(pool.available(), 1);
    }

    #[test]
    fn rejects_zero_and_overflowing_pools() {
        assert!(matches!(SlotPool::new(0, 1), Err(Error::InvalidPool(_))));
        assert!(matches!(
            SlotPool::new(ALIGN, 0),
            Err(Error::InvalidPool(_))
        ));
        assert!(matches!(
            SlotPool::new(usize::MAX / 2, 4),
            Err(Error::InvalidPool(_))
        ));
    }

    #[test]
    fn contains_rejects_ranges_that_leave_the_pool() {
        let pool = SlotPool::new(ALIGN, 2).unwrap();
        let base = pool.base_ptr() as u64;
        assert!(pool.contains(base, 2 * ALIGN as u64));
        assert!(!pool.contains(base, 2 * ALIGN as u64 + 1));
        assert!(!pool.contains(base - 1, 1));
        assert!(!pool.contains(u64::MAX, 2));
    }

    #[test]
    fn concurrent_acquire_never_hands_out_a_slot_twice() {
        let pool = SlotPool::new(ALIGN, 8).unwrap();
        std::thread::scope(|s| {
            for t in 0..8u8 {
                let pool = pool.clone();
                s.spawn(move || {
                    for _ in 0..1000 {
                        if let Some(mut slot) = pool.acquire() {
                            slot.as_mut_slice().fill(t);
                            std::thread::yield_now();
                            assert!(
                                slot.as_slice().iter().all(|&b| b == t),
                                "another thread wrote into this slot"
                            );
                        }
                    }
                });
            }
        });
        assert_eq!(pool.available(), 8);
    }
}
