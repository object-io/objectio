//! ISA-L backend implementation
//!
//! Uses the `erasure-isa-l` crate for hardware-accelerated erasure coding.
//! The crate bundles ISA-L source and compiles it during build, so no system
//! library installation is required (but nasm, autoconf, automake, libtool are needed).

use crate::ErasureError;
use crate::backend::{BackendCapabilities, BackendResult, ErasureBackend};
use erasure_isa_l::erasure::ErasureCode;
use std::num::NonZeroUsize;

/// ISA-L MDS Reed-Solomon backend
///
/// Uses Intel ISA-L for hardware-accelerated erasure coding on x86/x86_64.
/// Works on both Intel and AMD processors (uses standard AVX/AVX2/AVX-512).
pub struct IsalBackend {
    k: usize,
    m: usize,
    encoder: ErasureCode,
}

impl IsalBackend {
    /// Create a new ISA-L backend
    ///
    /// # Arguments
    /// * `data_shards` - Number of data shards (k)
    /// * `parity_shards` - Number of parity shards (m)
    pub fn new(data_shards: u8, parity_shards: u8) -> Result<Self, ErasureError> {
        if data_shards == 0 {
            return Err(ErasureError::InvalidConfig(
                "data_shards must be > 0".into(),
            ));
        }
        if parity_shards == 0 {
            return Err(ErasureError::InvalidConfig(
                "parity_shards must be > 0".into(),
            ));
        }

        let k = data_shards as usize;
        let m = parity_shards as usize;

        if k + m > 255 {
            return Err(ErasureError::InvalidConfig("k + m must be <= 255".into()));
        }

        // Use Reed-Solomon (Vandermonde) matrix - more reliable than Cauchy
        // in some ISA-L versions
        let k_nz = NonZeroUsize::new(k).unwrap(); // Safe: we checked k > 0 above
        let m_nz = NonZeroUsize::new(m).unwrap(); // Safe: we checked m > 0 above
        let encoder = ErasureCode::with_reed_solomon(k_nz, m_nz).map_err(|e| {
            ErasureError::InvalidConfig(format!("failed to create ISA-L encoder: {}", e))
        })?;

        Ok(Self { k, m, encoder })
    }
}

impl ErasureBackend for IsalBackend {
    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            name: "isal",
            supports_lrc: false,
            supports_simd: true,
            max_data_shards: 255,
            max_parity_shards: 255,
        }
    }

    fn data_shards(&self) -> usize {
        self.k
    }

    fn parity_shards(&self) -> usize {
        self.m
    }

    fn encode(&self, data_shards: &[&[u8]], shard_size: usize) -> BackendResult<Vec<Vec<u8>>> {
        if data_shards.len() != self.k {
            return Err(ErasureError::InvalidConfig(format!(
                "expected {} data shards, got {}",
                self.k,
                data_shards.len()
            )));
        }

        // Verify all shards are same size
        for (i, shard) in data_shards.iter().enumerate() {
            if shard.len() != shard_size {
                return Err(ErasureError::InvalidConfig(format!(
                    "shard {} has size {}, expected {}",
                    i,
                    shard.len(),
                    shard_size
                )));
            }
        }

        // Prepare mutable parity buffers
        let mut parity: Vec<Vec<u8>> = (0..self.m).map(|_| vec![0u8; shard_size]).collect();

        // Encode: data is read-only, parity is written
        self.encoder
            .encode(data_shards, &mut parity)
            .map_err(|e| ErasureError::EncodingFailed(format!("ISA-L encode failed: {}", e)))?;

        // Build result: data shards + parity shards
        let mut result = Vec::with_capacity(self.k + self.m);
        for shard in data_shards {
            result.push(shard.to_vec());
        }
        result.extend(parity);

        Ok(result)
    }

    fn encode_parity_into(
        &self,
        data_shards: &[&[u8]],
        parity: &mut [&mut [u8]],
        shard_size: usize,
    ) -> BackendResult<()> {
        crate::backend::check_parity_buffers(parity, self.m, shard_size)?;
        if data_shards.len() != self.k || data_shards.iter().any(|s| s.len() != shard_size) {
            return Err(ErasureError::ShardSizeMismatch);
        }
        // ISA-L writes parity straight into the caller's buffers.
        self.encoder
            .encode(data_shards, parity)
            .map_err(|e| ErasureError::EncodingFailed(format!("ISA-L encode failed: {e}")))
    }

    fn decode(
        &self,
        shards: &[Option<&[u8]>],
        shard_size: usize,
        missing_indices: &[usize],
    ) -> BackendResult<Vec<Vec<u8>>> {
        if shards.len() != self.k + self.m {
            return Err(ErasureError::InvalidConfig(format!(
                "expected {} shards, got {}",
                self.k + self.m,
                shards.len()
            )));
        }

        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < self.k {
            return Err(ErasureError::InsufficientShards {
                available,
                required: self.k,
            });
        }

        // If all data shards are present, just copy them and re-encode parity
        let data_all_present = (0..self.k).all(|i| shards[i].is_some());
        if data_all_present {
            let mut result = Vec::with_capacity(self.k + self.m);
            for shard in shards.iter().take(self.k) {
                result.push(shard.unwrap().to_vec());
            }
            // Re-encode parity
            let data_refs: Vec<&[u8]> = result.iter().map(|s| s.as_slice()).collect();
            let encoded = self.encode(&data_refs, shard_size)?;
            for item in encoded.iter().skip(self.k).take(self.m) {
                result.push(item.clone());
            }
            return Ok(result);
        }

        // Need to reconstruct missing data shards
        // Prepare data and parity arrays
        let mut data: Vec<Vec<u8>> = Vec::with_capacity(self.k);
        let mut parity: Vec<Vec<u8>> = Vec::with_capacity(self.m);

        for shard in shards.iter().take(self.k) {
            if let Some(s) = shard {
                data.push(s.to_vec());
            } else {
                data.push(vec![0u8; shard_size]);
            }
        }

        for shard in shards.iter().skip(self.k).take(self.m) {
            if let Some(s) = shard {
                parity.push(s.to_vec());
            } else {
                parity.push(vec![0u8; shard_size]);
            }
        }

        // Every shard that is absent is an erasure, whether or not the
        // caller listed it: ISA-L decodes from the first k positions not
        // erased, and an absent one among them is the zeros put in its place
        // above. Repair listed only the positions it lost, not a source read
        // that failed, and stored shards rebuilt from zeros (the B2 soak).
        let erasures: Vec<usize> = (0..shards.len())
            .filter(|&i| shards[i].is_none() || missing_indices.contains(&i))
            .collect();

        // Decode
        self.encoder
            .decode(&mut data, &mut parity, erasures)
            .map_err(|e| ErasureError::DecodingFailed(format!("ISA-L decode failed: {}", e)))?;

        // Build result
        let mut result = Vec::with_capacity(self.k + self.m);
        result.extend(data);
        result.extend(parity);

        Ok(result)
    }

    fn verify(&self, shards: &[&[u8]]) -> BackendResult<bool> {
        if shards.len() != self.k + self.m {
            return Ok(false);
        }

        // Check all shards have same size
        if let Some(first_len) = shards.first().map(|s| s.len()) {
            if !shards.iter().all(|s| s.len() == first_len) {
                return Ok(false);
            }

            // Re-encode and compare parity
            let data_shards: Vec<&[u8]> = shards[..self.k].to_vec();
            let encoded = self.encode(&data_shards, first_len)?;

            for i in 0..self.m {
                if encoded[self.k + i] != shards[self.k + i] {
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }
}

// Safety: IsalBackend contains owned data and ErasureCode which is Send+Sync
unsafe impl Send for IsalBackend {}
unsafe impl Sync for IsalBackend {}
