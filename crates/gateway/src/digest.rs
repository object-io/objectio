//! MD5, for S3 ETags and the SSE-C key check.
//!
//! RustCrypto's `md-5`, with its assembly implementation on x86_64 (the
//! `asm` feature; other targets use the portable one). On a 4 MiB PUT the
//! ETag was the single largest CPU cost in the gateway after erasure coding,
//! and it is on every PUT.

use md5::{Digest, Md5};

/// The MD5 digest of `data`.
#[must_use]
pub fn md5(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

/// The MD5 digest of `data` as lowercase hex, the form an S3 ETag carries.
#[must_use]
pub fn md5_hex(data: &[u8]) -> String {
    hex::encode(md5(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 1321's test vectors: the digest must not change with the crate.
    #[test]
    fn matches_the_rfc_1321_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }
}
