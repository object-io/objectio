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
//! header; `chunked_decode` lifts that trailer into the request headers, so
//! both arrive here the same way.

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
const CRC64_NVME: crc::Crc<u64, crc::Table<16>> =
    crc::Crc::<u64, crc::Table<16>>::new(&crc::CRC_64_NVME);

impl ChecksumAlgorithm {
    const ALL: [Self; 5] = [
        Self::Crc32,
        Self::Crc32c,
        Self::Crc64Nvme,
        Self::Sha1,
        Self::Sha256,
    ];

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

    /// The checksum of `data`, big-endian for the CRCs — the bytes whose
    /// base64 the header carries.
    #[must_use]
    pub fn compute(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest as _;
        match self {
            Self::Crc32 => crc32fast::hash(data).to_be_bytes().to_vec(),
            Self::Crc32c => crc32c::crc32c(data).to_be_bytes().to_vec(),
            Self::Crc64Nvme => CRC64_NVME.checksum(data).to_be_bytes().to_vec(),
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
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
            let expected = value
                .to_str()
                .ok()
                .and_then(|s| B64.decode(s.trim()).ok())
                .filter(|d| d.len() == algorithm.len())
                .ok_or_else(|| {
                    ChecksumError::InvalidRequest(format!(
                        "Value for {} header is invalid.",
                        algorithm.header_name()
                    ))
                })?;
            flexible = Some(FlexibleChecksum {
                algorithm,
                expected,
            });
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
            match &flexible {
                None => {
                    return Err(ChecksumError::InvalidRequest(
                        "x-amz-sdk-checksum-algorithm specified, but no corresponding \
                         x-amz-checksum-* or x-amz-trailer headers were found."
                            .to_string(),
                    ));
                }
                Some(f) if f.algorithm != named => {
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
}
