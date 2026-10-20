//! ObjectIO erasure coding
//!
//! # Code Types
//!
//! - **MDS**: Reed-Solomon on ISA-L's Vandermonde matrix, on every build;
//!   any k shards rebuild the data for the profiles [`is_mds`] allows
//! - **LRC**: local XOR parity per group, global parity on
//!   reed-solomon-simd; a lost shard is rebuilt from its group
//!
//! # Example
//!
//! ```
//! use objectio_erasure::{ErasureCodec, backend::{BackendConfig, BackendFactory}};
//! use objectio_common::ErasureConfig;
//!
//! // High-level API
//! let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
//! let data = b"Hello, World!";
//! let shards = codec.encode(data).unwrap();
//!
//! // Low-level backend API for more control
//! let config = BackendConfig::mds(4, 2);
//! let backend = BackendFactory::create_mds(&config).unwrap();
//! ```

pub mod backend;
pub mod codec;
pub mod metrics;
pub mod shard;

// Re-exports from codec
pub use codec::{ErasureCodec, ErasureError};
pub use shard::Shard;

// Re-exports from backend for convenience
pub use backend::isal::is_mds;
pub use backend::{
    BackendCapabilities, BackendConfig, BackendFactory, ErasureBackend, IsalBackend, LocalGroup,
    LrcBackend, LrcConfig, LrcEncodedData, RustSimdLrcBackend,
};

/// Prelude for common imports
pub mod prelude {
    pub use super::{
        BackendConfig, BackendFactory, ErasureBackend, ErasureCodec, ErasureError, LrcBackend,
        LrcConfig,
    };
}
