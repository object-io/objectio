//! The container of a meta backup (objectio-docs `core/meta.md`, "Backup,
//! restore and losing a majority").
//!
//! ```text
//! "OBIO-META-BACKUP-1\n"
//! u64 header length, header
//! frames: u32 length (1..), bytes      the body
//! u32 0                                end of the body
//! 32 bytes: SHA-256 of everything before them
//! ```
//!
//! The body is written as it is read from meta's database, so its length
//! isn't known up front: frames carry it, and the terminator and digest
//! tell a whole file from one cut short. What the header and the body
//! mean is meta's business; this only frames and checks them, so the CLI
//! checks a download with the same code a restore checks a file with.

use std::io::{self, Read, Write};

use sha2::{Digest, Sha256};

/// The first bytes of every backup.
pub const MAGIC: &[u8] = b"OBIO-META-BACKUP-1\n";

/// Body bytes per frame written.
const FRAME: usize = 1 << 20;

/// A header or frame longer than these is damage, not data.
const HEADER_LIMIT: u64 = 16 << 20;
const FRAME_LIMIT: u32 = 64 << 20;

fn damaged(what: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("not a whole meta backup: {what}"),
    )
}

/// `read_exact`, a short read reported as a file cut short.
fn read_exact(src: &mut impl Read, buf: &mut [u8], what: &str) -> io::Result<()> {
    src.read_exact(buf).map_err(|e| {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            damaged(format!("it ends inside {what} (truncated)"))
        } else {
            e
        }
    })
}

/// Writes a backup: the header at once, then the body as it is written to
/// it, in frames; [`Writer::finish`] ends it.
pub struct Writer<W: Write> {
    out: W,
    hash: Sha256,
    frame: Vec<u8>,
}

impl<W: Write> Writer<W> {
    /// Start a backup on `out` with `header`.
    ///
    /// # Errors
    /// Writing to `out` fails.
    pub fn new(out: W, header: &[u8]) -> io::Result<Self> {
        let mut w = Self {
            out,
            hash: Sha256::new(),
            frame: Vec::with_capacity(FRAME),
        };
        w.emit(MAGIC)?;
        w.emit(&(header.len() as u64).to_le_bytes())?;
        w.emit(header)?;
        Ok(w)
    }

    fn emit(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.hash.update(bytes);
        self.out.write_all(bytes)
    }

    fn write_frame(&mut self) -> io::Result<()> {
        if self.frame.is_empty() {
            return Ok(());
        }
        let frame = std::mem::take(&mut self.frame);
        let len = u32::try_from(frame.len()).map_err(io::Error::other)?;
        self.emit(&len.to_le_bytes())?;
        self.emit(&frame)?;
        self.frame = frame;
        self.frame.clear();
        Ok(())
    }

    /// End the body: the last frame, the terminator and the digest. Returns
    /// `out`, flushed.
    ///
    /// # Errors
    /// Writing to `out` fails.
    pub fn finish(mut self) -> io::Result<W> {
        self.write_frame()?;
        self.emit(&0u32.to_le_bytes())?;
        let digest = self.hash.finalize_reset();
        self.out.write_all(&digest)?;
        self.out.flush()?;
        Ok(self.out)
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len().min(FRAME - self.frame.len());
        self.frame.extend_from_slice(&buf[..n]);
        if self.frame.len() == FRAME {
            self.write_frame()?;
        }
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_frame()?;
        self.out.flush()
    }
}

/// Reads a backup: the header when opened, then the body. The body reads
/// to its end only if the file is whole: the terminator, a digest that
/// matches, and nothing after it; otherwise the read that reaches the end
/// fails `InvalidData`. Read the body to its end before trusting any of it.
pub struct Reader<R: Read> {
    src: R,
    hash: Sha256,
    header: Vec<u8>,
    /// Body bytes left in the current frame.
    left: usize,
    done: bool,
}

impl<R: Read> Reader<R> {
    /// Open a backup on `src`, reading its header.
    ///
    /// # Errors
    /// I/O, or `src` doesn't start as a backup does.
    pub fn open(mut src: R) -> io::Result<Self> {
        let mut hash = Sha256::new();
        let mut magic = vec![0u8; MAGIC.len()];
        read_exact(&mut src, &mut magic, "its first bytes")?;
        if magic != MAGIC {
            return Err(damaged("it doesn't start as a meta backup does"));
        }
        hash.update(&magic);
        let mut len = [0u8; 8];
        read_exact(&mut src, &mut len, "the header")?;
        hash.update(len);
        let len = u64::from_le_bytes(len);
        if len > HEADER_LIMIT {
            return Err(damaged(format!("a header of {len} bytes")));
        }
        let mut header = vec![0u8; usize::try_from(len).map_err(io::Error::other)?];
        read_exact(&mut src, &mut header, "the header")?;
        hash.update(&header);
        Ok(Self {
            src,
            hash,
            header,
            left: 0,
            done: false,
        })
    }

    /// The header, as written.
    #[must_use]
    pub fn header(&self) -> &[u8] {
        &self.header
    }

    /// The end of the body: the digest, then nothing.
    fn finish(&mut self) -> io::Result<()> {
        let mut digest = [0u8; 32];
        read_exact(&mut self.src, &mut digest, "the digest")?;
        if self.hash.finalize_reset().as_slice() != digest {
            return Err(damaged("its SHA-256 doesn't match: the file is damaged"));
        }
        let mut more = [0u8; 1];
        loop {
            match self.src.read(&mut more) {
                Ok(0) => break,
                Ok(_) => return Err(damaged("there are bytes after its digest")),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        self.done = true;
        Ok(())
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.done || buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut len = [0u8; 4];
            read_exact(&mut self.src, &mut len, "a frame's length")?;
            self.hash.update(len);
            let len = u32::from_le_bytes(len);
            if len == 0 {
                self.finish()?;
                return Ok(0);
            }
            if len > FRAME_LIMIT {
                return Err(damaged(format!("a frame of {len} bytes")));
            }
            self.left = len as usize;
        }
        let want = buf.len().min(self.left);
        let n = self.src.read(&mut buf[..want])?;
        if n == 0 {
            return Err(damaged("it ends inside a frame (truncated)"));
        }
        self.hash.update(&buf[..n]);
        self.left -= n;
        Ok(n)
    }
}

/// Check a whole backup on `src`; its header if it is whole.
///
/// # Errors
/// I/O, or the file isn't a whole backup.
pub fn verify(src: impl Read) -> io::Result<Vec<u8>> {
    let mut r = Reader::open(src)?;
    io::copy(&mut r, &mut io::sink())?;
    Ok(r.header)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backup(header: &[u8], body: &[u8]) -> Vec<u8> {
        let mut w = Writer::new(Vec::new(), header).unwrap();
        // In odd pieces, across frame boundaries.
        for piece in body.chunks(FRAME / 3 + 7) {
            w.write_all(piece).unwrap();
        }
        w.finish().unwrap()
    }

    fn body(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn read(file: &[u8]) -> io::Result<(Vec<u8>, Vec<u8>)> {
        let mut r = Reader::open(file)?;
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok((r.header().to_vec(), out))
    }

    #[test]
    fn a_backup_reads_back_as_written() {
        for len in [0, 1, FRAME - 1, FRAME, FRAME + 1, 3 * FRAME + 5] {
            let b = body(len);
            let file = backup(b"{\"a\":1}", &b);
            let (header, out) = read(&file).unwrap();
            assert_eq!(header, b"{\"a\":1}");
            assert_eq!(out, b, "body of {len} bytes");
            assert_eq!(verify(file.as_slice()).unwrap(), b"{\"a\":1}");
        }
    }

    #[test]
    fn a_changed_byte_anywhere_is_refused() {
        let file = backup(b"header", &body(FRAME + 100));
        // The magic, the header, a frame's length, the body, the digest.
        for at in [0, MAGIC.len() + 9, MAGIC.len() + 14, 1000, file.len() - 1] {
            let mut bad = file.clone();
            bad[at] ^= 0x01;
            assert!(verify(bad.as_slice()).is_err(), "byte {at} changed");
        }
    }

    #[test]
    fn a_truncated_backup_is_refused() {
        let file = backup(b"header", &body(2 * FRAME));
        for cut in [
            5,
            MAGIC.len() + 4,
            100,
            FRAME,
            file.len() - 33,
            file.len() - 1,
        ] {
            let e = verify(&file[..cut]).unwrap_err();
            assert_eq!(e.kind(), io::ErrorKind::InvalidData, "cut at {cut}: {e}");
        }
    }

    #[test]
    fn bytes_after_the_digest_are_refused() {
        let mut file = backup(b"header", b"body");
        file.push(0);
        let e = verify(file.as_slice()).unwrap_err();
        assert!(e.to_string().contains("after its digest"), "{e}");
    }

    #[test]
    fn the_body_is_not_whole_until_its_end_is_read() {
        let file = backup(b"h", &body(10));
        let mut bad = file.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let mut r = Reader::open(bad.as_slice()).unwrap();
        let mut ten = [0u8; 10];
        r.read_exact(&mut ten).unwrap();
        assert_eq!(ten.to_vec(), body(10));
        assert!(r.read(&mut [0u8; 1]).is_err(), "the end checks the digest");
    }
}
