//! Error types for ObjectIO
//!
//! This module defines the common error types used throughout the system.

use crate::types::BucketNameError;
use thiserror::Error;

/// Common result type for ObjectIO operations
pub type Result<T> = std::result::Result<T, Error>;

/// Common error type for ObjectIO
#[derive(Debug, Error)]
pub enum Error {
    // Storage errors
    #[error("disk I/O error: {0}")]
    DiskIo(#[from] std::io::Error),

    #[error("block not found: {block_id}")]
    BlockNotFound { block_id: String },

    #[error("insufficient disk space: required {required} bytes, available {available} bytes")]
    InsufficientSpace { required: u64, available: u64 },

    #[error("disk is full")]
    DiskFull,

    #[error("checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    #[error("data corruption detected")]
    DataCorruption,

    #[error("storage error: {0}")]
    Storage(String),

    // Erasure coding errors
    #[error("insufficient shards for reconstruction: have {available}, need {required}")]
    InsufficientShards { available: usize, required: usize },

    #[error("erasure coding error: {0}")]
    ErasureCoding(String),

    // Metadata errors
    #[error("bucket not found: {0}")]
    BucketNotFound(String),

    #[error("bucket already exists: {0}")]
    BucketAlreadyExists(String),

    #[error("object not found: {bucket}/{key}")]
    ObjectNotFound { bucket: String, key: String },

    #[error("object already exists: {bucket}/{key}")]
    ObjectAlreadyExists { bucket: String, key: String },

    #[error("invalid bucket name: {0}")]
    InvalidBucketName(#[from] BucketNameError),

    // Placement errors
    #[error("insufficient nodes for placement: have {available}, need {required}")]
    InsufficientNodes { available: usize, required: usize },

    #[error("insufficient racks for placement: have {available}, need {required}")]
    InsufficientRacks { available: usize, required: usize },

    #[error("insufficient datacenters for placement: have {available}, need {required}")]
    InsufficientDatacenters { available: usize, required: usize },

    #[error("node not found: {0}")]
    NodeNotFound(String),

    #[error("disk not found: {0}")]
    DiskNotFound(String),

    // S3 API errors
    #[error("access denied")]
    AccessDenied,

    #[error("invalid access key")]
    InvalidAccessKey,

    #[error("signature mismatch")]
    SignatureDoesNotMatch,

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("method not allowed: {0}")]
    MethodNotAllowed(String),

    #[error("precondition failed: {0}")]
    PreconditionFailed(String),

    #[error("entity too large: max {max_size} bytes")]
    EntityTooLarge { max_size: u64 },

    // Multipart upload errors
    #[error("no such upload: {upload_id}")]
    NoSuchUpload { upload_id: String },

    #[error("invalid part: {part_number}")]
    InvalidPart { part_number: u32 },

    #[error("invalid part order")]
    InvalidPartOrder,

    // Network/RPC errors
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("request timeout")]
    Timeout,

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    // Internal errors
    #[error("internal error: {0}")]
    Internal(String),

    #[error("not implemented: {0}")]
    NotImplemented(String),

    #[error("configuration error: {0}")]
    Configuration(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("deserialization error: {0}")]
    Deserialization(String),
}

/// Whether `e` is the filesystem out of room: ENOSPC, or EDQUOT (a quota).
/// Not a failing disk: the write can succeed once space is freed.
#[must_use]
pub fn is_out_of_space(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded
    )
}

impl Error {
    /// An I/O failure while doing `what`. One for lack of room
    /// ([`is_out_of_space`]) keeps its kind, so a caller can answer "full"
    /// rather than "failed"; any other is a storage error.
    pub fn io(what: impl std::fmt::Display, e: &std::io::Error) -> Self {
        if is_out_of_space(e) {
            Self::DiskIo(std::io::Error::new(e.kind(), format!("{what}: {e}")))
        } else {
            Self::Storage(format!("{what}: {e}"))
        }
    }

    /// Whether this is storage out of room: a disk with no free block, or
    /// a filesystem that refused a write with ENOSPC or EDQUOT.
    #[must_use]
    pub fn is_out_of_space(&self) -> bool {
        match self {
            Self::DiskFull | Self::InsufficientSpace { .. } => true,
            Self::DiskIo(e) => is_out_of_space(e),
            _ => false,
        }
    }

    /// Create a new internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }

    /// Create an invalid argument error
    pub fn invalid_argument(msg: impl Into<String>) -> Self {
        Self::InvalidArgument(msg.into())
    }

    /// Create a storage error
    pub fn storage(msg: impl Into<String>) -> Self {
        Self::Storage(msg.into())
    }

    /// Check if this is a retryable error
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::ServiceUnavailable(_) | Self::ConnectionFailed(_)
        )
    }

    /// Check if this is a not found error
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            Self::BucketNotFound(_)
                | Self::ObjectNotFound { .. }
                | Self::BlockNotFound { .. }
                | Self::NodeNotFound(_)
                | Self::DiskNotFound(_)
                | Self::NoSuchUpload { .. }
        )
    }

    /// Get HTTP status code for S3 API compatibility
    #[must_use]
    pub fn http_status_code(&self) -> u16 {
        if self.is_out_of_space() {
            return 507;
        }
        match self {
            // 400 Bad Request
            Self::InvalidRequest(_)
            | Self::InvalidArgument(_)
            | Self::InvalidBucketName(_)
            | Self::InvalidPart { .. }
            | Self::InvalidPartOrder => 400,

            // 403 Forbidden
            Self::AccessDenied | Self::InvalidAccessKey | Self::SignatureDoesNotMatch => 403,

            // 404 Not Found
            Self::BucketNotFound(_)
            | Self::ObjectNotFound { .. }
            | Self::NoSuchUpload { .. }
            | Self::BlockNotFound { .. } => 404,

            // 405 Method Not Allowed
            Self::MethodNotAllowed(_) => 405,

            // 409 Conflict
            Self::BucketAlreadyExists(_) | Self::ObjectAlreadyExists { .. } => 409,

            // 412 Precondition Failed
            Self::PreconditionFailed(_) => 412,

            // 413 Payload Too Large
            Self::EntityTooLarge { .. } => 413,

            // 500 Internal Server Error
            Self::Internal(_)
            | Self::DiskIo(_)
            | Self::DataCorruption
            | Self::ChecksumMismatch { .. }
            | Self::ErasureCoding(_)
            | Self::Storage(_)
            | Self::Serialization(_)
            | Self::Deserialization(_) => 500,

            // 501 Not Implemented
            Self::NotImplemented(_) => 501,

            // 503 Service Unavailable
            Self::ServiceUnavailable(_)
            | Self::Timeout
            | Self::ConnectionFailed(_)
            | Self::InsufficientNodes { .. }
            | Self::InsufficientRacks { .. }
            | Self::InsufficientDatacenters { .. }
            | Self::InsufficientShards { .. }
            | Self::InsufficientSpace { .. }
            | Self::DiskFull
            | Self::Configuration(_)
            | Self::NodeNotFound(_)
            | Self::DiskNotFound(_) => 503,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_retryable() {
        assert!(Error::Timeout.is_retryable());
        assert!(Error::ServiceUnavailable("test".into()).is_retryable());
        assert!(!Error::AccessDenied.is_retryable());
    }

    #[test]
    fn test_error_not_found() {
        assert!(Error::BucketNotFound("test".into()).is_not_found());
        assert!(
            Error::ObjectNotFound {
                bucket: "b".into(),
                key: "k".into()
            }
            .is_not_found()
        );
        assert!(!Error::AccessDenied.is_not_found());
    }

    #[test]
    fn test_error_http_status() {
        assert_eq!(Error::AccessDenied.http_status_code(), 403);
        assert_eq!(Error::BucketNotFound("test".into()).http_status_code(), 404);
        assert_eq!(Error::Internal("test".into()).http_status_code(), 500);
    }

    /// ENOSPC and EDQUOT are the filesystem out of room, whatever wraps
    /// them; EIO is a failing disk.
    #[test]
    fn a_full_filesystem_is_out_of_space_not_a_failure() {
        let os = std::io::Error::from_raw_os_error;
        for errno in [libc::ENOSPC, libc::EDQUOT] {
            let e = Error::io("write disk.raw @ 4096", &os(errno));
            assert!(e.is_out_of_space(), "{e}");
            assert_eq!(e.http_status_code(), 507);
            assert!(e.to_string().contains("disk.raw"), "{e}");
        }
        let eio = Error::io("write disk.raw @ 4096", &os(libc::EIO));
        assert!(!eio.is_out_of_space(), "{eio}");
        assert!(matches!(eio, Error::Storage(_)), "{eio}");
        assert!(Error::DiskFull.is_out_of_space());
        assert!(!Error::Storage("No space left on device".into()).is_out_of_space());
    }

    /// What the kernel answers a write with no room for, as std reports it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_write_to_a_full_device_is_out_of_space() {
        use std::io::Write as _;
        let e = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .and_then(|mut f| f.write_all(b"x"))
            .unwrap_err();
        assert!(is_out_of_space(&e), "{e:?}");
    }
}
