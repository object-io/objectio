//! ObjectIO Common - Shared types and utilities
//!
//! This crate provides common types, error definitions, and utilities
//! used across all ObjectIO components.

pub mod checksum;
pub mod error;
pub mod exposition;
pub mod histogram;
pub mod location;
pub mod log_tail;
pub mod metrics_registry;
pub mod process_metrics;
pub mod shutdown;
pub mod stamp;
pub mod types;
pub mod version;

pub use checksum::{Checksum, ChecksumCalculator};
pub use error::{Error, Result};
pub use shutdown::shutdown_signal;
pub use types::*;

/// The most compare-and-set operations one meta write carries. Meta refuses
/// a larger one before proposing it, and its state machine answers one that
/// reaches the log anyway as rejected, without writing anything. Callers
/// with more split them: copies share and release stripes in batches of at
/// most this many. Every release since 0.1 applies up to this many, and a
/// node of an older release stops at more, so the number never grows.
pub const META_MAX_OPS: usize = 256;
