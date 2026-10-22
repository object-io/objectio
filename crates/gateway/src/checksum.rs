//! Integrity checksums a client sends with an upload: `Content-MD5` and the
//! flexible `x-amz-checksum-<algorithm>` headers.
//!
//! S3 refuses a PUT or UploadPart whose body does not match what the client
//! says it sent, and stores nothing. Without the check a body corrupted on
//! the way in is stored and served as if it were good. Modern SDKs send a
//! flexible checksum on every upload by default, so this is the common path,
//! not an edge case.
//!
//! An `aws-chunked` body carries its checksum as a trailer instead of a
//! header. A body read whole has it lifted into the request headers by
//! `chunked_decode`, so both arrive the same way; a streamed body brings it
//! with its end, and [`StreamingChecksums`] checks it then.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use http::HeaderMap;
use md5::{Digest as _, Md5};

/// A flexible checksum algorithm S3 accepts on upload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlgorithm {
    Crc32,
    Crc32c,
    Crc64Nvme,
    Sha1,
    Sha256,
}

/// CRC-64/NVME, the checksum S3 computes for every object by default.
static CRC64_NVME: crc::Crc<u64, crc::Table<16>> =
    crc::Crc::<u64, crc::Table<16>>::new(&crc::CRC_64_NVME);

impl ChecksumAlgorithm {
    const ALL: [Self; 5] = [
        Self::Crc32,
        Self::Crc32c,
        Self::Crc64Nvme,
        Self::Sha1,
        Self::Sha256,
    ];

    /// Every algorithm S3 has.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        Self::ALL
    }

    /// The name S3 uses for it: `x-amz-sdk-checksum-algorithm` values and
    /// error messages.
    #[must_use]
    pub const fn aws_name(self) -> &'static str {
        match self {
            Self::Crc32 => "CRC32",
            Self::Crc32c => "CRC32C",
            Self::Crc64Nvme => "CRC64NVME",
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
        }
    }

    /// The header that carries the checksum, on requests and responses.
    #[must_use]
    pub const fn header_name(self) -> &'static str {
        match self {
            Self::Crc32 => "x-amz-checksum-crc32",
            Self::Crc32c => "x-amz-checksum-crc32c",
            Self::Crc64Nvme => "x-amz-checksum-crc64nvme",
            Self::Sha1 => "x-amz-checksum-sha1",
            Self::Sha256 => "x-amz-checksum-sha256",
        }
    }

    /// Bytes in the decoded checksum.
    const fn len(self) -> usize {
        match self {
            Self::Crc32 | Self::Crc32c => 4,
            Self::Crc64Nvme => 8,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    #[must_use]
    pub fn from_aws_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.aws_name().eq_ignore_ascii_case(name))
    }

    fn from_header_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.header_name().eq_ignore_ascii_case(name))
    }

    /// For a CRC, its reflected polynomial: what combining two CRCs needs.
    const fn crc_poly(self) -> Option<u64> {
        match self {
            Self::Crc32 => Some(0xEDB8_8320),
            Self::Crc32c => Some(0x82F6_3B78),
            Self::Crc64Nvme => Some(0x9A6C_9329_AC4B_C9B5),
            Self::Sha1 | Self::Sha256 => None,
        }
    }

    /// Whether S3 can give a multipart object of this algorithm a checksum
    /// of the whole object (`FULL_OBJECT`), made from its parts' checksums.
    #[must_use]
    pub const fn can_combine(self) -> bool {
        self.crc_poly().is_some()
    }

    /// The CRC of a whole object from its parts' CRCs (big-endian bytes)
    /// and lengths, without the data: zlib's `crc32_combine`, in GF(2), for
    /// any of the three reflected CRCs. None for a hash, or bad input.
    #[must_use]
    pub fn combine(self, parts: &[(Vec<u8>, u64)]) -> Option<Vec<u8>> {
        let poly = self.crc_poly()?;
        let width = self.len() * 8;
        let value = |b: &[u8]| -> Option<u64> {
            (b.len() == self.len()).then(|| b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
        };
        let times = |mat: &[u64], mut vec: u64| {
            let mut sum = 0u64;
            let mut i = 0;
            while vec != 0 {
                if vec & 1 == 1 {
                    sum ^= mat[i];
                }
                vec >>= 1;
                i += 1;
            }
            sum
        };
        let square = |out: &mut [u64], mat: &[u64]| {
            for n in 0..width {
                out[n] = times(mat, mat[n]);
            }
        };
        let combine2 = |mut crc1: u64, crc2: u64, mut len2: u64| {
            if len2 == 0 {
                return crc1;
            }
            let mut even = vec![0u64; width];
            let mut odd = vec![0u64; width];
            odd[0] = poly;
            let mut row = 1u64;
            for slot in odd.iter_mut().skip(1) {
                *slot = row;
                row <<= 1;
            }
            square(&mut even, &odd); // two zero bits
            square(&mut odd, &even); // four
            loop {
                square(&mut even, &odd); // one zero byte, then doubling
                if len2 & 1 == 1 {
                    crc1 = times(&even, crc1);
                }
                len2 >>= 1;
                if len2 == 0 {
                    break;
                }
                square(&mut odd, &even);
                if len2 & 1 == 1 {
                    crc1 = times(&odd, crc1);
                }
                len2 >>= 1;
                if len2 == 0 {
                    break;
                }
            }
            crc1 ^ crc2
        };
        let mut iter = parts.iter();
        let (first, _) = iter.next()?;
        let mut acc = value(first)?;
        for (crc, len) in iter {
            acc = combine2(acc, value(crc)?, *len);
        }
        Some(acc.to_be_bytes()[8 - self.len()..].to_vec())
    }

    /// The checksum of `data`, big-endian for the CRCs — the bytes whose
    /// base64 the header carries.
    #[must_use]
    pub fn compute(self, data: &[u8]) -> Vec<u8> {
        let mut h = self.hasher();
        h.update(data);
        h.finish()
    }

    /// A checksum of this algorithm over data given a piece at a time.
    #[must_use]
    pub fn hasher(self) -> ChecksumHasher {
        use sha2::Digest as _;
        match self {
            Self::Crc32 => ChecksumHasher::Crc32(crc32fast::Hasher::new()),
            Self::Crc32c => ChecksumHasher::Crc32c(0),
            Self::Crc64Nvme => ChecksumHasher::Crc64Nvme(CRC64_NVME.digest()),
            Self::Sha1 => ChecksumHasher::Sha1(sha1::Sha1::new()),
            Self::Sha256 => ChecksumHasher::Sha256(sha2::Sha256::new()),
        }
    }
}

/// A checksum being computed over data as it arrives.
pub enum ChecksumHasher {
    Crc32(crc32fast::Hasher),
    Crc32c(u32),
    Crc64Nvme(crc::Digest<'static, u64, crc::Table<16>>),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
}

impl ChecksumHasher {
    pub fn update(&mut self, data: &[u8]) {
        use sha2::Digest as _;
        match self {
            Self::Crc32(h) => h.update(data),
            Self::Crc32c(crc) => *crc = crc32c::crc32c_append(*crc, data),
            Self::Crc64Nvme(d) => d.update(data),
            Self::Sha1(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
        }
    }

    /// The checksum, as [`ChecksumAlgorithm::compute`] gives it.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Self::Crc32(h) => h.finalize().to_be_bytes().to_vec(),
            Self::Crc32c(crc) => crc.to_be_bytes().to_vec(),
            Self::Crc64Nvme(d) => d.finalize().to_be_bytes().to_vec(),
            Self::Sha1(h) => h.finalize().to_vec(),
            Self::Sha256(h) => h.finalize().to_vec(),
        }
    }
}

/// A flexible checksum the client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlexibleChecksum {
    pub algorithm: ChecksumAlgorithm,
    /// Decoded value, already checked to be the algorithm's length.
    expected: Vec<u8>,
}

impl FlexibleChecksum {
    /// The value as the header carries it.
    #[must_use]
    pub fn value_b64(&self) -> String {
        B64.encode(&self.expected)
    }
}

/// Why an upload's checksum was refused. Every one is a 400.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChecksumError {
    /// `Content-MD5` is not base64 of 16 bytes.
    InvalidDigest,
    /// `Content-MD5` does not match the body.
    BadDigest,
    /// A flexible checksum header is malformed, or the headers contradict
    /// each other.
    InvalidRequest(String),
    /// A flexible checksum does not match the body.
    BadChecksum(ChecksumAlgorithm),
}

impl ChecksumError {
    /// The S3 error code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidDigest => "InvalidDigest",
            Self::BadDigest | Self::BadChecksum(_) => "BadDigest",
            Self::InvalidRequest(_) => "InvalidRequest",
        }
    }

    /// The message S3 sends with it.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::InvalidDigest => "The Content-MD5 you specified was invalid.".to_string(),
            Self::BadDigest => {
                "The Content-MD5 you specified did not match what we received.".to_string()
            }
            Self::InvalidRequest(m) => m.clone(),
            Self::BadChecksum(a) => format!(
                "The {} you specified did not match the calculated checksum.",
                a.aws_name()
            ),
        }
    }
}

/// The checksums an upload request carries.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestChecksums {
    content_md5: Option<[u8; 16]>,
    pub flexible: Option<FlexibleChecksum>,
    /// A flexible checksum `x-amz-trailer` names, when no header carries
    /// one: its value comes after the body, as a trailer.
    pub trailer: Option<ChecksumAlgorithm>,
}

/// A flexible checksum's value as a header or trailer carries it: base64
/// of the algorithm's length.
fn decode_value(algorithm: ChecksumAlgorithm, value: &str) -> Result<Vec<u8>, ChecksumError> {
    B64.decode(value.trim())
        .ok()
        .filter(|d| d.len() == algorithm.len())
        // AWS's answer (Ceph RGW says BadDigest instead).
        .ok_or_else(|| {
            ChecksumError::InvalidRequest(format!(
                "Value for {} header is invalid.",
                algorithm.header_name()
            ))
        })
}

impl RequestChecksums {
    /// Read and check the form of the request's checksum headers. Nothing is
    /// computed over the body yet.
    ///
    /// # Errors
    /// The header S3 would refuse, as S3 refuses it.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, ChecksumError> {
        let content_md5 = match headers.get("content-md5") {
            None => None,
            Some(v) => {
                let decoded = v
                    .to_str()
                    .ok()
                    .and_then(|s| B64.decode(s.trim()).ok())
                    .ok_or(ChecksumError::InvalidDigest)?;
                Some(
                    <[u8; 16]>::try_from(decoded.as_slice())
                        .map_err(|_| ChecksumError::InvalidDigest)?,
                )
            }
        };

        let mut flexible: Option<FlexibleChecksum> = None;
        for (name, value) in headers {
            let Some(algorithm) = ChecksumAlgorithm::from_header_name(name.as_str()) else {
                continue;
            };
            if flexible.is_some() {
                return Err(ChecksumError::InvalidRequest(
                    "Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed."
                        .to_string(),
                ));
            }
            let expected = decode_value(algorithm, value.to_str().unwrap_or_default())?;
            flexible = Some(FlexibleChecksum {
                algorithm,
                expected,
            });
        }

        // A checksum sent after the body: named up front in x-amz-trailer.
        let mut trailer: Option<ChecksumAlgorithm> = None;
        for name in headers
            .get_all("x-amz-trailer")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
        {
            let Some(algorithm) = ChecksumAlgorithm::from_header_name(name.trim()) else {
                continue;
            };
            if trailer.is_some_and(|t| t != algorithm) {
                return Err(ChecksumError::InvalidRequest(
                    "Expecting a single x-amz-checksum- header. Multiple checksum Types are not allowed."
                        .to_string(),
                ));
            }
            trailer = Some(algorithm);
        }
        // A header that carries it already (a trailer lifted into one, for
        // a body read whole) is the checksum.
        if flexible.is_some() {
            trailer = None;
        }

        // The SDK names the algorithm it used; it must be one we know and
        // agree with the checksum that came with it.
        if let Some(v) = headers.get("x-amz-sdk-checksum-algorithm") {
            let named = v
                .to_str()
                .ok()
                .and_then(|s| ChecksumAlgorithm::from_aws_name(s.trim()))
                .ok_or_else(|| {
                    ChecksumError::InvalidRequest(
                        "Value for x-amz-sdk-checksum-algorithm header is invalid.".to_string(),
                    )
                })?;
            match flexible.as_ref().map(|f| f.algorithm).or(trailer) {
                None => {
                    return Err(ChecksumError::InvalidRequest(
                        "x-amz-sdk-checksum-algorithm specified, but no corresponding \
                         x-amz-checksum-* or x-amz-trailer headers were found."
                            .to_string(),
                    ));
                }
                Some(a) if a != named => {
                    return Err(ChecksumError::InvalidRequest(
                        "Value for x-amz-sdk-checksum-algorithm header is invalid.".to_string(),
                    ));
                }
                Some(_) => {}
            }
        }

        Ok(Self {
            content_md5,
            flexible,
            trailer,
        })
    }

    /// Whether the request carries anything to check.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.content_md5.is_none() && self.flexible.is_none()
    }

    /// Check `body` against every checksum the request carries.
    ///
    /// Returns the body's MD5 when it had to be computed for `Content-MD5`,
    /// so the caller can make the ETag from it instead of hashing again.
    ///
    /// # Errors
    /// The first checksum that does not match.
    pub fn verify(&self, body: &[u8]) -> Result<Option<[u8; 16]>, ChecksumError> {
        let md5 = match self.content_md5 {
            Some(expected) => {
                let actual: [u8; 16] = Md5::digest(body).into();
                if actual != expected {
                    return Err(ChecksumError::BadDigest);
                }
                Some(actual)
            }
            None => None,
        };
        if let Some(f) = &self.flexible
            && f.algorithm.compute(body) != f.expected
        {
            return Err(ChecksumError::BadChecksum(f.algorithm));
        }
        Ok(md5)
    }
}

/// An upload's body checked as it streams: its MD5 (the ETag, and what
/// `Content-MD5` is held to) and the flexible checksum it carries, in a
/// header or a trailer, or that its upload declared.
pub struct StreamingChecksums {
    request: RequestChecksums,
    md5: Md5,
    flexible: Option<(ChecksumAlgorithm, ChecksumHasher)>,
}

/// What a streamed body turned out to be, once every checksum it carried
/// matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamedChecksums {
    pub md5: [u8; 16],
    /// The flexible checksum computed, and whether the client sent it (or
    /// only its upload declared the algorithm).
    pub flexible: Option<(ChecksumAlgorithm, Vec<u8>, bool)>,
}

impl StreamedChecksums {
    /// The flexible checksum the client sent, as stored and answered.
    #[must_use]
    pub fn sent(&self) -> Option<(ChecksumAlgorithm, String)> {
        self.flexible
            .as_ref()
            .filter(|(_, _, sent)| *sent)
            .map(|(a, v, _)| (*a, B64.encode(v)))
    }

    /// The flexible checksum computed, sent or not.
    #[must_use]
    pub fn computed(&self) -> Option<(ChecksumAlgorithm, String)> {
        self.flexible.as_ref().map(|(a, v, _)| (*a, B64.encode(v)))
    }
}

impl StreamingChecksums {
    /// Check against what `request` carries; `declared` is the algorithm
    /// computed when the request sends none (a part of an upload that
    /// declared one).
    #[must_use]
    pub fn new(request: RequestChecksums, declared: Option<ChecksumAlgorithm>) -> Self {
        let algorithm = request
            .flexible
            .as_ref()
            .map(|f| f.algorithm)
            .or(request.trailer)
            .or(declared);
        Self {
            request,
            md5: Md5::new(),
            flexible: algorithm.map(|a| (a, a.hasher())),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.md5.update(data);
        if let Some((_, h)) = self.flexible.as_mut() {
            h.update(data);
        }
    }

    /// The body has ended, with `trailers` (an `aws-chunked` body's
    /// checksum): check every checksum the request carried.
    ///
    /// # Errors
    /// The first checksum that does not match, or a trailer whose value is
    /// malformed.
    pub fn finish(self, trailers: Option<&HeaderMap>) -> Result<StreamedChecksums, ChecksumError> {
        let md5: [u8; 16] = self.md5.finalize().into();
        if self.request.content_md5.is_some_and(|want| want != md5) {
            return Err(ChecksumError::BadDigest);
        }
        let Some((algorithm, hasher)) = self.flexible else {
            return Ok(StreamedChecksums {
                md5,
                flexible: None,
            });
        };
        let computed = hasher.finish();
        let expected = match (&self.request.flexible, self.request.trailer) {
            (Some(f), _) => Some(f.expected.clone()),
            (None, Some(a)) => trailers
                .and_then(|t| t.get(a.header_name()))
                .map(|v| decode_value(a, v.to_str().unwrap_or_default()))
                .transpose()?,
            (None, None) => None,
        };
        if expected.as_ref().is_some_and(|e| *e != computed) {
            return Err(ChecksumError::BadChecksum(algorithm));
        }
        Ok(StreamedChecksums {
            md5,
            flexible: Some((algorithm, computed, expected.is_some())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    /// "hello world" under each algorithm, computed independently with
    /// Python reference implementations.
    #[test]
    fn each_algorithm_matches_its_known_vector() {
        let cases = [
            (ChecksumAlgorithm::Crc32, "DUoRhQ=="),
            (ChecksumAlgorithm::Crc32c, "yZRlqg=="),
            (ChecksumAlgorithm::Crc64Nvme, "jSnVw/bqjr4="),
            (ChecksumAlgorithm::Sha1, "Kq5sNclPz7QV2+lfQIuc6R7oRu0="),
            (
                ChecksumAlgorithm::Sha256,
                "uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=",
            ),
        ];
        for (alg, b64) in cases {
            assert_eq!(B64.encode(alg.compute(b"hello world")), b64, "{alg:?}");
            let c = RequestChecksums::from_headers(&headers(&[(alg.header_name(), b64)])).unwrap();
            assert_eq!(c.verify(b"hello world"), Ok(None), "{alg:?}");
            assert_eq!(
                c.verify(b"hello world!"),
                Err(ChecksumError::BadChecksum(alg)),
                "{alg:?}"
            );
        }
    }

    /// The catalogue check value: CRC-64/NVME of "123456789".
    #[test]
    fn crc64_nvme_matches_the_catalogue_check_value() {
        assert_eq!(
            ChecksumAlgorithm::Crc64Nvme.compute(b"123456789"),
            0xae8b_1486_0a79_9888_u64.to_be_bytes()
        );
    }

    #[test]
    fn content_md5_good_bad_and_malformed() {
        // base64(md5("hello world"))
        let good = "XrY7u+Ae7tCTyyK7j1rNww==";
        let c = RequestChecksums::from_headers(&headers(&[("content-md5", good)])).unwrap();
        let md5 = c.verify(b"hello world").unwrap().unwrap();
        assert_eq!(hex::encode(md5), "5eb63bbbe01eeed093cb22bb8f5acdc3");
        assert_eq!(c.verify(b"hello"), Err(ChecksumError::BadDigest));

        for bad in ["not base64!", "aGVsbG8=", ""] {
            assert_eq!(
                RequestChecksums::from_headers(&headers(&[("content-md5", bad)])),
                Err(ChecksumError::InvalidDigest),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_malformed_or_wrong_length_flexible_checksum_is_invalid_request() {
        // Not base64, and base64 of the wrong number of bytes.
        for bad in ["***", "AAAAAAAA"] {
            let e = RequestChecksums::from_headers(&headers(&[("x-amz-checksum-crc32", bad)]))
                .unwrap_err();
            assert_eq!(e.code(), "InvalidRequest");
            assert_eq!(
                e.message(),
                "Value for x-amz-checksum-crc32 header is invalid."
            );
        }
    }

    #[test]
    fn two_flexible_checksums_are_refused() {
        let e = RequestChecksums::from_headers(&headers(&[
            ("x-amz-checksum-crc32", "DUoRhQ=="),
            ("x-amz-checksum-crc32c", "yZRlqg=="),
        ]))
        .unwrap_err();
        assert_eq!(e.code(), "InvalidRequest");
    }

    #[test]
    fn the_sdk_algorithm_must_agree_with_the_checksum() {
        let ok = RequestChecksums::from_headers(&headers(&[
            ("x-amz-sdk-checksum-algorithm", "crc32"),
            ("x-amz-checksum-crc32", "DUoRhQ=="),
        ]))
        .unwrap();
        assert_eq!(ok.flexible.unwrap().algorithm, ChecksumAlgorithm::Crc32);

        for pairs in [
            vec![("x-amz-sdk-checksum-algorithm", "CRC32")],
            vec![
                ("x-amz-sdk-checksum-algorithm", "SHA256"),
                ("x-amz-checksum-crc32", "DUoRhQ=="),
            ],
            vec![
                ("x-amz-sdk-checksum-algorithm", "MD5"),
                ("x-amz-checksum-crc32", "DUoRhQ=="),
            ],
        ] {
            let e = RequestChecksums::from_headers(&headers(&pairs)).unwrap_err();
            assert_eq!(e.code(), "InvalidRequest", "{pairs:?}");
        }
    }

    #[test]
    fn other_checksum_headers_are_not_checksums() {
        let c = RequestChecksums::from_headers(&headers(&[
            ("x-amz-checksum-mode", "ENABLED"),
            ("x-amz-checksum-type", "FULL_OBJECT"),
            ("x-amz-checksum-algorithm", "CRC32"),
        ]))
        .unwrap();
        assert!(c.is_empty());
    }

    #[test]
    fn both_kinds_are_checked() {
        let c = RequestChecksums::from_headers(&headers(&[
            ("content-md5", "XrY7u+Ae7tCTyyK7j1rNww=="),
            ("x-amz-checksum-crc32c", "AAAAAA=="),
        ]))
        .unwrap();
        assert_eq!(
            c.verify(b"hello world"),
            Err(ChecksumError::BadChecksum(ChecksumAlgorithm::Crc32c))
        );
    }

    /// A whole object's CRC from its parts' CRCs is the CRC of the whole.
    #[test]
    fn combined_crcs_are_the_crc_of_the_whole() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let (a, rest) = data.split_at(70_001);
        let (b, c) = rest.split_at(100_000);
        for algo in [
            ChecksumAlgorithm::Crc32,
            ChecksumAlgorithm::Crc32c,
            ChecksumAlgorithm::Crc64Nvme,
        ] {
            let parts: Vec<(Vec<u8>, u64)> = [a, b, c]
                .iter()
                .map(|p| (algo.compute(p), p.len() as u64))
                .collect();
            assert_eq!(algo.combine(&parts), Some(algo.compute(&data)), "{algo:?}");
        }
        assert_eq!(ChecksumAlgorithm::Sha256.combine(&[(vec![0; 32], 1)]), None);
    }

    /// Fed in pieces, a hasher gives what one pass over the whole gives.
    #[test]
    fn a_checksum_in_pieces_is_the_checksum_of_the_whole() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i * 13 % 251) as u8).collect();
        for algo in ChecksumAlgorithm::all() {
            let mut h = algo.hasher();
            for piece in data.chunks(7_777) {
                h.update(piece);
            }
            assert_eq!(h.finish(), algo.compute(&data), "{algo:?}");
        }
    }

    #[test]
    fn a_streamed_body_is_held_to_its_headers() {
        let c = RequestChecksums::from_headers(&headers(&[
            ("content-md5", "XrY7u+Ae7tCTyyK7j1rNww=="),
            ("x-amz-checksum-crc32c", "yZRlqg=="),
        ]))
        .unwrap();
        let mut s = StreamingChecksums::new(c.clone(), None);
        s.update(b"hello ");
        s.update(b"world");
        let done = s.finish(None).unwrap();
        assert_eq!(hex::encode(done.md5), "5eb63bbbe01eeed093cb22bb8f5acdc3");
        assert_eq!(
            done.sent(),
            Some((ChecksumAlgorithm::Crc32c, "yZRlqg==".to_string()))
        );

        let mut s = StreamingChecksums::new(c, None);
        s.update(b"hello world!");
        assert_eq!(s.finish(None), Err(ChecksumError::BadDigest));
    }

    /// A checksum named in x-amz-trailer is computed as the body streams and
    /// checked against the trailer at its end.
    #[test]
    fn a_trailer_checksum_is_checked_at_the_end() {
        let c = RequestChecksums::from_headers(&headers(&[
            ("x-amz-trailer", "x-amz-checksum-crc32c"),
            ("x-amz-sdk-checksum-algorithm", "CRC32C"),
        ]))
        .unwrap();
        assert_eq!(c.trailer, Some(ChecksumAlgorithm::Crc32c));
        let trailers = headers(&[("x-amz-checksum-crc32c", "yZRlqg==")]);
        let mut s = StreamingChecksums::new(c.clone(), None);
        s.update(b"hello world");
        assert_eq!(
            s.finish(Some(&trailers)).unwrap().sent(),
            Some((ChecksumAlgorithm::Crc32c, "yZRlqg==".to_string()))
        );

        let mut s = StreamingChecksums::new(c.clone(), None);
        s.update(b"hello there");
        assert_eq!(
            s.finish(Some(&trailers)),
            Err(ChecksumError::BadChecksum(ChecksumAlgorithm::Crc32c))
        );

        let bad = headers(&[("x-amz-checksum-crc32c", "AAAAAAAA")]);
        let mut s = StreamingChecksums::new(c, None);
        s.update(b"hello world");
        assert_eq!(s.finish(Some(&bad)).unwrap_err().code(), "InvalidRequest");
    }

    /// An upload part sent without a checksum gets the one its upload
    /// declared, computed, and not reported as sent.
    #[test]
    fn a_declared_algorithm_is_computed_when_none_is_sent() {
        let mut s =
            StreamingChecksums::new(RequestChecksums::default(), Some(ChecksumAlgorithm::Crc32));
        s.update(b"hello world");
        let done = s.finish(None).unwrap();
        assert_eq!(done.sent(), None);
        assert_eq!(
            done.computed(),
            Some((ChecksumAlgorithm::Crc32, "DUoRhQ==".to_string()))
        );
    }
}
