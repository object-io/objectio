//! Stamps: the order of writes to one object's metadata copies
//! (objectio-docs `core/object-metadata-quorum.md`).
//!
//! A stamp is a hybrid logical clock value: the wall-clock milliseconds in
//! the high 48 bits and a counter in the low 16. Every process that writes
//! ObjectMeta stamps it from its own [`Clock`]; an OSD keeps the copy with
//! the highest stamp, and a read takes the newest copy a read quorum
//! returns. Stamp 0 means unstamped.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const COUNTER_BITS: u32 = 16;
const COUNTER_MASK: u64 = (1 << COUNTER_BITS) - 1;

/// A stamp's wall-clock milliseconds.
#[must_use]
pub const fn millis(stamp: u64) -> u64 {
    stamp >> COUNTER_BITS
}

/// A hybrid logical clock: stamps that only increase, follow wall time,
/// and stay above every stamp this process has seen.
#[derive(Debug, Default)]
pub struct Clock {
    last: Mutex<u64>,
}

impl Clock {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: Mutex::new(0),
        }
    }

    /// A stamp higher than any this clock has issued or observed.
    pub fn now(&self) -> u64 {
        self.next_after(0)
    }

    /// A stamp higher than `seen` and than any this clock has issued: what
    /// an update of something read at `seen` writes, so it orders after
    /// what it read whatever the clocks say.
    pub fn next_after(&self, seen: u64) -> u64 {
        let wall = wall_millis() << COUNTER_BITS;
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let floor = (*last).max(seen);
        let stamp = if wall > floor {
            wall
        } else if floor & COUNTER_MASK < COUNTER_MASK {
            floor + 1
        } else {
            // Counter full within this millisecond: borrow the next one.
            (millis(floor) + 1) << COUNTER_BITS
        };
        *last = stamp;
        stamp
    }

    /// Note a stamp seen elsewhere, so later ones from this clock exceed it.
    pub fn observe(&self, seen: u64) {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *last = (*last).max(seen);
    }
}

fn wall_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX >> COUNTER_BITS)
    })
}

/// This process's clock.
pub static CLOCK: Clock = Clock::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_only_increase() {
        let c = Clock::new();
        let mut prev = 0;
        for _ in 0..100_000 {
            let s = c.now();
            assert!(s > prev);
            prev = s;
        }
    }

    #[test]
    fn a_stamp_follows_what_it_saw() {
        let c = Clock::new();
        let far = (wall_millis() + 60_000) << COUNTER_BITS; // a clock a minute ahead
        assert!(c.next_after(far) > far);
        assert!(c.now() > far, "and so does every later stamp");
        c.observe(far + 10);
        assert!(c.now() > far + 10);
    }

    #[test]
    fn stamps_carry_wall_time() {
        let c = Clock::new();
        let before = wall_millis();
        let s = c.now();
        assert!(millis(s) >= before && millis(s) <= wall_millis());
    }

    #[test]
    fn a_full_counter_moves_to_the_next_millisecond() {
        let c = Clock::new();
        let at = ((wall_millis() + 60_000) << COUNTER_BITS) | COUNTER_MASK;
        let s = c.next_after(at);
        assert_eq!(millis(s), millis(at) + 1);
    }
}
