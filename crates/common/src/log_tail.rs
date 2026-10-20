//! Telling a log's torn tail from damage inside it.
//!
//! The OSD's metadata log, the block gateway's write journal and meta's
//! Raft log are each one file of records that is appended to and synced.
//! Opening one reads its records in order until one fails its checks. Two
//! things leave such a record:
//!
//! - **A torn append**: a crash before the append's sync returned. What
//!   reached the disk of that append, and of anything written after it, is
//!   arbitrary, but none of it was acknowledged: a sync covers the whole
//!   file, so a record after the torn one was never synced either. The log
//!   ends there; the bytes after are cut off.
//! - **Damage** to a record that was synced (a bad sector, a misdirected or
//!   lost write). The records after it may well have been acknowledged.
//!   Cutting the log there would drop them silently.
//!
//! A whole record after the bad one is what tells them apart: an
//! acknowledged record after the bad one means the bad one was synced, so it
//! is damage. The log can't tell an acknowledged record from one that only
//! happened to reach the disk before the crash, so any whole record after
//! the bad one stops the open: the node is rebuilt from its peers rather
//! than lose an acknowledged write. [`whole_record_after`] looks for one.

use std::io;

/// Where a log's bytes are read from: its file, or a copy in memory.
pub trait ReadAt {
    /// Fill `buf` from `offset`.
    ///
    /// # Errors
    /// I/O, or `offset + buf.len()` past the end.
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()>;
}

impl ReadAt for std::fs::File {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        std::os::unix::fs::FileExt::read_exact_at(self, buf, offset)
    }
}

impl ReadAt for [u8] {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::ErrorKind::UnexpectedEof)?;
        let src = start
            .checked_add(buf.len())
            .and_then(|end| self.get(start..end))
            .ok_or(io::ErrorKind::UnexpectedEof)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

/// How much is read at a time while looking.
const WINDOW: usize = 1 << 20;

/// The offset of the first whole record that starts after `bad` (where a
/// record failed its checks) and ends by `len`, if any: when there is one,
/// the bad record is damage and the log must not be cut there.
///
/// Every offset after `bad` is a candidate. `probe` is given a candidate's
/// offset and up to `probe_len` bytes from it, and answers the length of
/// the record that would start there if its header is plausible (a magic,
/// a sequence number in the range the log could hold, lengths it allows);
/// it is called at every offset, so it must be cheap and strict. Only a
/// candidate that passes is read whole and given to `whole`, which checks
/// it as the log's reader does (its checksum).
///
/// # Errors
/// I/O.
pub fn whole_record_after<R: ReadAt + ?Sized>(
    src: &R,
    bad: u64,
    len: u64,
    probe_len: usize,
    mut probe: impl FnMut(u64, &[u8]) -> Option<u64>,
    mut whole: impl FnMut(u64, &[u8]) -> bool,
) -> io::Result<Option<u64>> {
    let mut window = Vec::new();
    let mut start = bad.saturating_add(1);
    while start < len {
        let have = usize::try_from(len - start).unwrap_or(usize::MAX);
        window.resize(have.min(WINDOW + probe_len), 0);
        src.read_exact_at(&mut window, start)?;
        let candidates = have.min(WINDOW);
        for i in 0..candidates {
            let at = start + i as u64;
            let head = &window[i..window.len().min(i + probe_len)];
            let Some(record_len) = probe(at, head) else {
                continue;
            };
            if record_len == 0 || record_len > len - at {
                continue;
            }
            let ok = match usize::try_from(record_len) {
                Ok(n) if i + n <= window.len() => whole(at, &window[i..i + n]),
                Ok(n) => {
                    let mut record = vec![0u8; n];
                    src.read_exact_at(&mut record, at)?;
                    whole(at, &record)
                }
                Err(_) => false,
            };
            if ok {
                return Ok(Some(at));
            }
        }
        start += candidates as u64;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A record: `b'R'`, a length byte, that many bytes, their sum.
    fn record(body: &[u8]) -> Vec<u8> {
        let mut r = vec![b'R', u8::try_from(body.len()).unwrap()];
        r.extend_from_slice(body);
        r.push(body.iter().fold(0u8, |a, b| a.wrapping_add(*b)));
        r
    }

    fn probe(_: u64, head: &[u8]) -> Option<u64> {
        (head.len() >= 2 && head[0] == b'R').then(|| 3 + u64::from(head[1]))
    }

    fn whole(_: u64, r: &[u8]) -> bool {
        let body = &r[2..r.len() - 1];
        body.iter().fold(0u8, |a, b| a.wrapping_add(*b)) == r[r.len() - 1]
    }

    fn find(log: &[u8], bad: u64) -> Option<u64> {
        whole_record_after(log, bad, log.len() as u64, 2, probe, whole).unwrap()
    }

    #[test]
    fn a_whole_record_after_the_bad_one_is_found() {
        let mut log = record(b"one");
        let bad = log.len() as u64;
        log.extend_from_slice(b"\x00\xffjunk");
        let at = log.len() as u64;
        log.extend_from_slice(&record(b"three"));
        assert_eq!(find(&log, bad), Some(at));
    }

    #[test]
    fn a_torn_tail_has_none() {
        let mut log = record(b"one");
        let bad = log.len() as u64;
        let mut torn = record(b"two");
        torn.truncate(3);
        log.extend_from_slice(&torn);
        log.extend_from_slice(&[0u8; 100]);
        assert_eq!(find(&log, bad), None);
    }

    /// A candidate whose length runs past the end is not read.
    #[test]
    fn a_length_past_the_end_is_not_a_record() {
        let log = [b'R', 200, 1, 2, 3];
        assert_eq!(find(&log, 0), None);
    }

    /// Candidates are found across the window's edge, and records longer
    /// than the bytes already read are read whole.
    #[test]
    fn records_across_windows_are_found() {
        for at in [WINDOW - 2, WINDOW + 3] {
            let mut log = vec![0u8; at];
            log.extend_from_slice(&record(&[7u8; 200]));
            log.extend_from_slice(&[0u8; 10]);
            assert_eq!(find(&log, 0), Some(at as u64));
        }
    }
}
