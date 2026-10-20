//! Backend factory: the one code each kind of stripe is written with
//!
//! An MDS stripe is coded with ISA-L and an LRC stripe with
//! reed-solomon-simd, on every build. A stripe decodes only with the code
//! that wrote its parity, so there is no choosing.

use super::{ErasureBackend, IsalBackend, LrcBackend, LrcConfig, RustSimdLrcBackend};
use crate::ErasureError;
use std::sync::Arc;

/// Configuration for creating a backend
#[derive(Clone, Debug)]
pub struct BackendConfig {
    /// Data shards (k)
    pub data_shards: u8,
    /// Parity shards (m) for MDS, or (l + g) for LRC
    pub parity_shards: u8,
    /// LRC configuration (if using LRC mode)
    pub lrc_config: Option<LrcConfig>,
}

impl BackendConfig {
    /// Create a new MDS backend configuration
    pub fn mds(data_shards: u8, parity_shards: u8) -> Self {
        Self {
            data_shards,
            parity_shards,
            lrc_config: None,
        }
    }

    /// Create a new LRC backend configuration
    pub fn lrc(config: LrcConfig) -> Self {
        Self {
            data_shards: config.data_shards,
            parity_shards: config.total_parity(),
            lrc_config: Some(config),
        }
    }
}

/// Factory for creating erasure coding backends
pub struct BackendFactory;

impl BackendFactory {
    /// The MDS backend: ISA-L.
    pub fn create_mds(config: &BackendConfig) -> Result<Arc<dyn ErasureBackend>, ErasureError> {
        Ok(Arc::new(IsalBackend::new(
            config.data_shards,
            config.parity_shards,
        )?))
    }

    /// The LRC backend: reed-solomon-simd global parity, as the PUT path
    /// and meta's recovery code it.
    pub fn create_lrc(config: &BackendConfig) -> Result<Arc<dyn LrcBackend>, ErasureError> {
        let lrc_config = config.lrc_config.ok_or_else(|| {
            ErasureError::InvalidConfig("LRC config required for LRC backend".into())
        })?;
        Ok(Arc::new(RustSimdLrcBackend::new(lrc_config)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_mds_backend() {
        let config = BackendConfig::mds(4, 2);
        let backend = BackendFactory::create_mds(&config).unwrap();

        assert_eq!(backend.capabilities().name, "isal");
        assert_eq!(backend.data_shards(), 4);
        assert_eq!(backend.parity_shards(), 2);
        assert_eq!(backend.total_shards(), 6);
    }

    #[test]
    fn test_create_lrc_backend() {
        let lrc_config = LrcConfig::new(6, 2, 2);
        let config = BackendConfig::lrc(lrc_config);
        let backend = BackendFactory::create_lrc(&config).unwrap();

        assert_eq!(backend.data_shards(), 6);
        assert_eq!(backend.parity_shards(), 4); // 2 local + 2 global
        assert_eq!(backend.total_shards(), 10);
    }
}
