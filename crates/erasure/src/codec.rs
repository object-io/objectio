//! Reed-Solomon encoder/decoder
//!
//! This module provides both a high-level `ErasureCodec` API and low-level
//! backend access via the `backend` module.
//!
//! # High-Level API
//!
//! ```
//! use objectio_erasure::ErasureCodec;
//! use objectio_common::ErasureConfig;
//!
//! let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
//! let data = b"Hello, World!";
//! let shards = codec.encode(data).unwrap();
//! ```
//!
//! # Backend API
//!
//! For more control, use the backend directly:
//!
//! ```
//! use objectio_erasure::backend::{BackendConfig, BackendFactory};
//!
//! let config = BackendConfig::mds(4, 2);
//! let backend = BackendFactory::create_mds(&config).unwrap();
//! ```

use crate::backend::{BackendConfig, BackendFactory, ErasureBackend, LrcBackend, LrcConfig};
use bytes::Bytes;
use objectio_common::{ErasureConfig, ErasureType, Error as CommonError, Result};
use std::sync::Arc;
use thiserror::Error;

/// Errors specific to erasure coding operations
#[derive(Debug, Error)]
pub enum ErasureError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("encoding failed: {0}")]
    EncodingFailed(String),

    #[error("decoding failed: {0}")]
    DecodingFailed(String),

    #[error("insufficient shards: have {available}, need {required}")]
    InsufficientShards { available: usize, required: usize },

    #[error("shard size mismatch")]
    ShardSizeMismatch,

    #[error("LRC configuration required")]
    LrcConfigRequired,

    /// A decode rebuilt data shards that are not shown to be the ones
    /// written (see [`ErasureCodec::decode_verified`]).
    #[error("rebuilt data not verified: {0}")]
    Unverified(String),
}

/// Most decodes [`ErasureCodec::decode_verified`] tries before giving up.
const MAX_DECODE_ATTEMPTS: usize = 256;

/// What checking a decode's rebuilt data shards found.
enum Check {
    Verified,
    Mismatch,
    /// Nothing to check them against.
    Unchecked,
}

/// The data shards, in order, cut to `original_size`.
fn join_data<'a>(data: impl IntoIterator<Item = &'a [u8]>, original_size: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(original_size);
    for shard in data {
        output.extend_from_slice(shard);
    }
    output.truncate(original_size);
    output
}

/// Every choice of `r` of `0..n`, in lexicographic order.
struct Combinations {
    n: usize,
    next: Option<Vec<usize>>,
}

impl Combinations {
    fn new(n: usize, r: usize) -> Self {
        Self {
            n,
            next: (r <= n).then(|| (0..r).collect()),
        }
    }
}

impl Iterator for Combinations {
    type Item = Vec<usize>;

    fn next(&mut self) -> Option<Vec<usize>> {
        let current = self.next.take()?;
        let r = current.len();
        // The rightmost index that can still move right, and those after
        // it packed in behind.
        if let Some(i) = (0..r).rev().find(|&i| current[i] < self.n - r + i) {
            let mut following = current.clone();
            following[i] += 1;
            for j in i + 1..r {
                following[j] = following[j - 1] + 1;
            }
            self.next = Some(following);
        }
        Some(current)
    }
}

impl From<ErasureError> for CommonError {
    fn from(e: ErasureError) -> Self {
        CommonError::ErasureCoding(e.to_string())
    }
}

/// Backend wrapper for unified handling of MDS and LRC
enum CodecBackend {
    Mds(Arc<dyn ErasureBackend>),
    Lrc(Arc<dyn LrcBackend>),
}

/// Erasure codec supporting both MDS Reed-Solomon and LRC
///
/// This is the high-level API for erasure coding. Every build codes a
/// stripe alike: MDS with ISA-L, LRC's global parity with reed-solomon-simd.
///
/// # MDS Mode (default)
///
/// Reed-Solomon on ISA-L's Vandermonde matrix: any k shards rebuild the
/// data, for the profiles [`crate::is_mds`] allows.
///
/// # LRC Mode
///
/// Locally Repairable Codes with local parity groups for faster single-shard
/// recovery with reduced bandwidth.
pub struct ErasureCodec {
    config: ErasureConfig,
    backend: CodecBackend,
}

impl ErasureCodec {
    /// Create a new erasure codec with the given configuration
    pub fn new(config: ErasureConfig) -> Result<Self> {
        if config.data_shards == 0 {
            return Err(ErasureError::InvalidConfig("data_shards must be > 0".into()).into());
        }
        if config.parity_shards == 0 {
            return Err(ErasureError::InvalidConfig("parity_shards must be > 0".into()).into());
        }

        let backend = match config.ec_type {
            ErasureType::Mds => {
                let backend_config = BackendConfig::mds(config.data_shards, config.parity_shards);
                let mds_backend = BackendFactory::create_mds(&backend_config)?;
                CodecBackend::Mds(mds_backend)
            }
            ErasureType::Lrc {
                local_parity,
                global_parity,
            } => {
                let lrc_config = LrcConfig::new(config.data_shards, local_parity, global_parity);
                let backend_config = BackendConfig::lrc(lrc_config);
                let lrc_backend = BackendFactory::create_lrc(&backend_config)?;
                CodecBackend::Lrc(lrc_backend)
            }
        };

        Ok(Self { config, backend })
    }

    /// Get the configuration
    #[must_use]
    pub const fn config(&self) -> ErasureConfig {
        self.config
    }

    /// Get the number of data shards
    #[must_use]
    pub fn data_shards(&self) -> usize {
        match &self.backend {
            CodecBackend::Mds(b) => b.data_shards(),
            CodecBackend::Lrc(b) => b.data_shards(),
        }
    }

    /// Get the number of parity shards
    #[must_use]
    pub fn parity_shards(&self) -> usize {
        match &self.backend {
            CodecBackend::Mds(b) => b.parity_shards(),
            CodecBackend::Lrc(b) => b.parity_shards(),
        }
    }

    /// Get the total number of shards (data + parity)
    #[must_use]
    pub fn total_shards(&self) -> usize {
        self.data_shards() + self.parity_shards()
    }

    /// Check if this codec uses LRC
    #[must_use]
    pub fn is_lrc(&self) -> bool {
        matches!(self.backend, CodecBackend::Lrc(_))
    }

    /// Encode data into k data shards and m parity shards
    ///
    /// The input data is split into k equal-sized chunks, then m parity
    /// shards are computed. Returns a vector of k+m shards.
    ///
    /// For LRC mode, this includes both local and global parity shards.
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let started = std::time::Instant::now();
        let res = self.encode_inner(data);
        crate::metrics::ENCODE_SECONDS.observe_duration(started.elapsed());
        res
    }

    /// Shard size for `len` bytes over `k` data shards.
    ///
    /// A multiple of 64, and at least 64: ISA-L codes vectors of 32 bytes
    /// or more, reed-solomon-simd (LRC) needs an even size, and 64 keeps
    /// every SIMD width aligned. A stripe's layout depends on it.
    /// Bytes per shard when `len` bytes are split over `k` data shards:
    /// data byte `p` is in shard `p / shard` at offset `p % shard`.
    #[must_use]
    pub fn shard_size_for(len: usize, k: usize) -> usize {
        len.div_ceil(k).next_multiple_of(64).max(64)
    }

    /// As [`encode`](Self::encode), with every shard a slice of one buffer.
    ///
    /// The data is copied once into a buffer laid out as k data shards then
    /// m parity shards, parity is computed in place, and each returned shard
    /// is a zero-copy view of it — so fanning shards out to OSDs, or handing
    /// them to gRPC, never copies them again.
    pub fn encode_bytes(&self, data: &[u8]) -> Result<Vec<Bytes>> {
        let started = std::time::Instant::now();
        let res = self.encode_bytes_inner(data);
        crate::metrics::ENCODE_SECONDS.observe_duration(started.elapsed());
        res
    }

    fn encode_bytes_inner(&self, data: &[u8]) -> Result<Vec<Bytes>> {
        // LRC shards come back from the backend already owned; wrapping a
        // Vec in Bytes takes it over without copying.
        if self.is_lrc() {
            return Ok(self
                .encode_inner(data)?
                .into_iter()
                .map(Bytes::from)
                .collect());
        }
        let mut stripe = vec![0u8; self.stripe_len(data.len())];
        let shard_size = self.encode_into_inner(data, &mut stripe)?;
        let stripe = Bytes::from(stripe);
        Ok((0..self.total_shards())
            .map(|i| stripe.slice(i * shard_size..(i + 1) * shard_size))
            .collect())
    }

    /// Bytes a stripe of `data_len` bytes takes once encoded: k + m shards
    /// of equal size, laid out one after another.
    #[must_use]
    pub fn stripe_len(&self, data_len: usize) -> usize {
        Self::shard_size_for(data_len, self.data_shards()) * self.total_shards()
    }

    /// Encode `data` into `stripe` — k data shards then m parity shards,
    /// contiguous — and return the shard size. Lets a caller encode straight
    /// into memory it owns, such as a slot registered with a NIC. Only the
    /// first [`stripe_len`](Self::stripe_len) bytes of `stripe` are written;
    /// the padding after `data` is zeroed, so a reused buffer is safe.
    ///
    /// MDS only: LRC stripes are not laid out this way.
    ///
    /// # Errors
    /// For an LRC codec, or a `stripe` shorter than `stripe_len(data.len())`.
    pub fn encode_into(&self, data: &[u8], stripe: &mut [u8]) -> Result<usize> {
        let started = std::time::Instant::now();
        let res = self.encode_into_inner(data, stripe);
        crate::metrics::ENCODE_SECONDS.observe_duration(started.elapsed());
        res
    }

    fn encode_into_inner(&self, data: &[u8], stripe: &mut [u8]) -> Result<usize> {
        let CodecBackend::Mds(backend) = &self.backend else {
            return Err(
                ErasureError::InvalidConfig("encode_into needs an MDS codec".into()).into(),
            );
        };
        let k = self.data_shards();
        let shard_size = Self::shard_size_for(data.len(), k);
        let len = shard_size * self.total_shards();
        let stripe = stripe
            .get_mut(..len)
            .ok_or(ErasureError::ShardSizeMismatch)?;

        stripe[..data.len()].copy_from_slice(data);
        stripe[data.len()..shard_size * k].fill(0);
        let (data_part, parity_part) = stripe.split_at_mut(shard_size * k);
        let data_shards: Vec<&[u8]> = data_part.chunks_exact(shard_size).collect();
        let mut parity: Vec<&mut [u8]> = parity_part.chunks_exact_mut(shard_size).collect();
        backend
            .encode_parity_into(&data_shards, &mut parity, shard_size)
            .map_err(|e| ErasureError::EncodingFailed(e.to_string()))?;
        Ok(shard_size)
    }

    fn encode_inner(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let k = self.data_shards();
        let shard_size = Self::shard_size_for(data.len(), k);
        let padded_size = shard_size * k;

        // Create padded data
        let mut padded = vec![0u8; padded_size];
        padded[..data.len()].copy_from_slice(data);

        // Split into data shards
        let data_shards: Vec<&[u8]> = (0..k)
            .map(|i| &padded[i * shard_size..(i + 1) * shard_size])
            .collect();

        // Encode using backend
        let shards = match &self.backend {
            CodecBackend::Mds(backend) => backend
                .encode(&data_shards, shard_size)
                .map_err(|e| ErasureError::EncodingFailed(e.to_string()))?,
            CodecBackend::Lrc(backend) => {
                let encoded = backend
                    .encode_lrc(&data_shards, shard_size)
                    .map_err(|e| ErasureError::EncodingFailed(e.to_string()))?;
                encoded.all_shards()
            }
        };

        Ok(shards)
    }

    /// Decode shards back to original data
    ///
    /// Takes one slot per shard, `None` for a missing one; a shard can be
    /// any byte container (`Vec<u8>`, `Bytes`). At least k shards must be
    /// present to reconstruct the data.
    ///
    /// For LRC mode, this will attempt local recovery first (using only the
    /// local parity group) before falling back to global recovery.
    ///
    /// A data shard rebuilt here is not checked: what is served to a
    /// client goes through [`decode_verified`](Self::decode_verified).
    pub fn decode<S: AsRef<[u8]>>(
        &self,
        shards: &mut [Option<S>],
        original_size: usize,
    ) -> Result<Vec<u8>> {
        let refs: Vec<Option<&[u8]>> = shards
            .iter()
            .map(|s| s.as_ref().map(AsRef::as_ref))
            .collect();
        let path = self.decode_path(&refs);
        let started = std::time::Instant::now();
        let k = self.data_shards();
        let res = if self.data_present(&refs) {
            Ok(join_data(
                refs[..k].iter().flatten().copied(),
                original_size,
            ))
        } else {
            self.rebuild_data(&refs)
                .map(|data| join_data(data.iter().map(Vec::as_slice), original_size))
                .map_err(Into::into)
        };
        crate::metrics::DECODE_SECONDS.observe_duration(path, started.elapsed());
        res
    }

    /// Decode, serving a data shard it had to rebuild only once that shard
    /// is shown to be the one written.
    ///
    /// `recorded[i]` is the crc32c the stripe records for shard `i` (`None`
    /// where it records none, as for a position never written). The shards
    /// given are the caller's to have checked against it when it read
    /// them. A decode is only as right as its codec: one with parity from
    /// another codec, or a parity shard stored wrong under a checksum of its
    /// own, rebuilds other bytes, and nothing else would notice.
    ///
    /// Each rebuilt data shard must match its recorded checksum. One with
    /// none recorded must instead be borne out by a parity shard the decode
    /// did not use: re-encoded, the stripe gives that shard's bytes. A
    /// decode that fails either check is tried again from another choice
    /// of the shards given, when there are more than k; with none
    /// verifying, the result is [`ErasureError::Unverified`], and the
    /// caller reads more shards or fails the read.
    ///
    /// # Errors
    /// [`ErasureError::InsufficientShards`] with fewer than k shards;
    /// [`ErasureError::Unverified`] when no choice of them rebuilds data
    /// that checks out.
    pub fn decode_verified<S: AsRef<[u8]>>(
        &self,
        shards: &[Option<S>],
        original_size: usize,
        recorded: &[Option<u32>],
    ) -> std::result::Result<Vec<u8>, ErasureError> {
        let refs: Vec<Option<&[u8]>> = shards
            .iter()
            .map(|s| s.as_ref().map(AsRef::as_ref))
            .collect();
        let path = self.decode_path(&refs);
        let started = std::time::Instant::now();
        let res = self.decode_verified_inner(&refs, original_size, recorded);
        crate::metrics::DECODE_SECONDS.observe_duration(path, started.elapsed());
        if matches!(res, Err(ErasureError::Unverified(_))) {
            crate::metrics::REBUILDS_REJECTED.inc("");
        }
        res
    }

    fn decode_verified_inner(
        &self,
        shards: &[Option<&[u8]>],
        original_size: usize,
        recorded: &[Option<u32>],
    ) -> std::result::Result<Vec<u8>, ErasureError> {
        let k = self.data_shards();
        let n = self.total_shards();
        if shards.len() != n {
            return Err(ErasureError::InvalidConfig(format!(
                "expected {n} shard slots, got {}",
                shards.len()
            )));
        }
        // Nothing to rebuild: every data shard is one the caller checked.
        if self.data_present(shards) {
            return Ok(join_data(
                shards[..k].iter().flatten().copied(),
                original_size,
            ));
        }
        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < k {
            return Err(ErasureError::InsufficientShards {
                available,
                required: k,
            });
        }

        let rebuilt: Vec<usize> = (0..k).filter(|&i| shards[i].is_none()).collect();
        let parity: Vec<usize> = (k..n).filter(|&i| shards[i].is_some()).collect();
        let mut tried = 0usize;
        let mut mismatched = 0usize;
        // The fewest parity shards first: what the decode leaves out is
        // what can bear out a shard with no checksum recorded.
        for used in rebuilt.len()..=parity.len() {
            for choice in Combinations::new(parity.len(), used) {
                if tried == MAX_DECODE_ATTEMPTS {
                    break;
                }
                tried += 1;
                let chosen: Vec<usize> = choice.iter().map(|&c| parity[c]).collect();
                let subset: Vec<Option<&[u8]>> = (0..n)
                    .map(|i| {
                        if i < k || chosen.contains(&i) {
                            shards[i]
                        } else {
                            None
                        }
                    })
                    .collect();
                // Not every choice determines an LRC stripe's data.
                let Ok(data) = self.rebuild_data(&subset) else {
                    continue;
                };
                match self.check_rebuilt(shards, &data, &rebuilt, &chosen, recorded) {
                    Check::Verified => {
                        return Ok(join_data(data.iter().map(Vec::as_slice), original_size));
                    }
                    Check::Mismatch => mismatched += 1,
                    Check::Unchecked => {}
                }
            }
        }
        Err(ErasureError::Unverified(if mismatched > 0 {
            format!(
                "data shards {rebuilt:?} rebuilt from {available} shards do not match \
                 the checksums their stripe records ({mismatched} of {tried} decodes)"
            )
        } else {
            format!(
                "data shards {rebuilt:?} rebuilt from {available} shards: no checksum \
                 recorded and no unused parity shard to check them against"
            )
        }))
    }

    /// Whether data shards `rebuilt` of `data`, decoded using the parity
    /// shards `chosen`, are the ones written.
    fn check_rebuilt(
        &self,
        shards: &[Option<&[u8]>],
        data: &[Vec<u8>],
        rebuilt: &[usize],
        chosen: &[usize],
        recorded: &[Option<u32>],
    ) -> Check {
        let mut unrecorded = false;
        for &i in rebuilt {
            match recorded.get(i).copied().flatten() {
                Some(crc) if crc32c::crc32c(&data[i]) == crc => {}
                Some(_) => return Check::Mismatch,
                None => unrecorded = true,
            }
        }
        if !unrecorded {
            return Check::Verified;
        }
        let unused: Vec<usize> = (self.data_shards()..self.total_shards())
            .filter(|i| shards[*i].is_some() && !chosen.contains(i))
            .collect();
        if unused.is_empty() {
            return Check::Unchecked;
        }
        let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
        let Ok(stripe) = self.encode_shards(&refs) else {
            return Check::Unchecked;
        };
        if unused
            .iter()
            .any(|&p| shards[p].is_some_and(|s| s == stripe[p].as_slice()))
        {
            Check::Verified
        } else {
            Check::Mismatch
        }
    }

    /// The decode-time label: "reconstruct" when a data shard is missing
    /// and parity has to be used — the slow path, and a sign of a degraded
    /// read.
    fn decode_path(&self, shards: &[Option<&[u8]>]) -> &'static str {
        if self.data_present(shards) {
            "path=\"fast\""
        } else {
            "path=\"reconstruct\""
        }
    }

    /// Whether every data shard is present.
    fn data_present(&self, shards: &[Option<&[u8]>]) -> bool {
        shards.len() >= self.data_shards()
            && shards[..self.data_shards()].iter().all(Option::is_some)
    }

    /// Every shard of the stripe whose data shards are `data`.
    fn encode_shards(&self, data: &[&[u8]]) -> std::result::Result<Vec<Vec<u8>>, ErasureError> {
        let shard_size = data.first().map_or(0, |s| s.len());
        match &self.backend {
            CodecBackend::Mds(backend) => backend.encode(data, shard_size),
            CodecBackend::Lrc(backend) => {
                backend.encode_lrc(data, shard_size).map(|e| e.all_shards())
            }
        }
    }

    /// The k data shards, rebuilding those missing from the shards given.
    fn rebuild_data(
        &self,
        shards: &[Option<&[u8]>],
    ) -> std::result::Result<Vec<Vec<u8>>, ErasureError> {
        let k = self.data_shards();
        if shards.len() != self.total_shards() {
            return Err(ErasureError::InvalidConfig(format!(
                "expected {} shard slots, got {}",
                self.total_shards(),
                shards.len()
            )));
        }

        // Count available shards
        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < k {
            return Err(ErasureError::InsufficientShards {
                available,
                required: k,
            });
        }

        // Get shard size from first available shard
        let shard_size = shards.iter().find_map(|s| s.map(<[u8]>::len)).ok_or(
            ErasureError::InsufficientShards {
                available: 0,
                required: k,
            },
        )?;

        if self.data_present(shards) {
            return Ok(shards[..k].iter().flatten().map(|s| s.to_vec()).collect());
        }

        // Find missing indices
        let missing_indices: Vec<usize> = shards
            .iter()
            .enumerate()
            .filter_map(|(i, s)| if s.is_none() { Some(i) } else { None })
            .collect();

        match &self.backend {
            CodecBackend::Mds(backend) => {
                let mut decoded = backend
                    .decode(shards, shard_size, &missing_indices)
                    .map_err(|e| ErasureError::DecodingFailed(e.to_string()))?;
                if decoded.len() < k {
                    return Err(ErasureError::DecodingFailed(format!(
                        "decode returned {} shards, need the {k} data shards",
                        decoded.len()
                    )));
                }
                decoded.truncate(k);
                Ok(decoded)
            }
            CodecBackend::Lrc(backend) => {
                // Data shards first from their own group (a member and the
                // local parity), then the rest from the global code. Only
                // data shards are recovered: the output needs no parity,
                // and a missing local parity can't come from the global
                // code (it asked for one and failed the whole decode).
                let mut recovered: Vec<Option<Vec<u8>>> = vec![None; self.total_shards()];
                for &idx in missing_indices.iter().filter(|&&i| i < k) {
                    let refs: Vec<Option<&[u8]>> = (0..self.total_shards())
                        .map(|i| recovered[i].as_deref().or(shards[i]))
                        .collect();
                    if let Ok(Some(shard)) = backend.decode_local(&refs, shard_size, idx) {
                        recovered[idx] = Some(shard);
                    }
                }
                let still: Vec<usize> = (0..k)
                    .filter(|&i| shards[i].is_none() && recovered[i].is_none())
                    .collect();
                if !still.is_empty() {
                    let refs: Vec<Option<&[u8]>> = (0..self.total_shards())
                        .map(|i| recovered[i].as_deref().or(shards[i]))
                        .collect();
                    // The backend's shards come back in the order asked.
                    let global = backend
                        .decode(&refs, shard_size, &still)
                        .map_err(|e| ErasureError::DecodingFailed(e.to_string()))?;
                    for (idx, shard) in still.into_iter().zip(global) {
                        recovered[idx] = Some(shard);
                    }
                }
                (0..k)
                    .map(|i| {
                        recovered[i]
                            .take()
                            .or_else(|| shards[i].map(<[u8]>::to_vec))
                            .ok_or_else(|| {
                                ErasureError::DecodingFailed(format!("data shard {i} not rebuilt"))
                            })
                    })
                    .collect()
            }
        }
    }

    /// Verify that shards are consistent
    ///
    /// Re-encodes the data shards and compares parity to verify integrity.
    /// Reconstruct specific missing shards without decoding the full
    /// original data.
    ///
    /// Used by the meta's repair path (Phase 4c): when an ObjectMeta
    /// has a ShardLocation pointing at an unregistered OSD, we read
    /// the surviving shards and regenerate the missing one instead of
    /// re-uploading the object. Returns reconstructed bytes in the
    /// same order as `missing_indices`.
    ///
    /// Requires at least k shards to be `Some`; returns
    /// `InsufficientShards` otherwise.
    ///
    /// # Errors
    /// Returns `InsufficientShards` if fewer than k shards are
    /// available, and propagates any backend-level decoding error.
    pub fn reconstruct_shards(
        &self,
        shards: &[Option<Vec<u8>>],
        missing_indices: &[usize],
    ) -> Result<Vec<Vec<u8>>> {
        let k = self.data_shards();
        let available = shards.iter().filter(|s| s.is_some()).count();
        if available < k {
            return Err(ErasureError::InsufficientShards {
                available,
                required: k,
            }
            .into());
        }
        let shard_size = shards
            .iter()
            .find_map(|s| s.as_ref().map(|v| v.len()))
            .ok_or(ErasureError::InsufficientShards {
                available: 0,
                required: k,
            })?;

        match &self.backend {
            CodecBackend::Mds(backend) => {
                let shard_refs: Vec<Option<&[u8]>> = shards
                    .iter()
                    .map(|s| s.as_ref().map(|v| v.as_slice()))
                    .collect();
                // The backend does not return what `decode` documents: it
                // hands back every shard, data first. Taking that output as
                // "the missing shards, in order" rebuilt the wrong bytes.
                // Take the data shards and re-encode the stripe for the
                // parity.
                let decoded = backend
                    .decode(&shard_refs, shard_size, missing_indices)
                    .map_err(|e| ErasureError::DecodingFailed(e.to_string()))?;
                if decoded.len() < k {
                    return Err(ErasureError::DecodingFailed(format!(
                        "decode returned {} shards, need the {k} data shards",
                        decoded.len()
                    ))
                    .into());
                }
                let data: Vec<&[u8]> = decoded[..k].iter().map(Vec::as_slice).collect();
                let mut stripe = backend
                    .encode(&data, shard_size)
                    .map_err(|e| ErasureError::EncodingFailed(e.to_string()))?;
                missing_indices
                    .iter()
                    .map(|&i| {
                        stripe.get_mut(i).map(std::mem::take).ok_or_else(|| {
                            ErasureError::InvalidConfig(format!("no shard {i} in the stripe"))
                                .into()
                        })
                    })
                    .collect()
            }
            CodecBackend::Lrc(backend) => {
                let shard_refs: Vec<Option<&[u8]>> = shards
                    .iter()
                    .map(|s| s.as_ref().map(|v| v.as_slice()))
                    .collect();
                backend
                    .decode(&shard_refs, shard_size, missing_indices)
                    .map_err(|e| ErasureError::DecodingFailed(e.to_string()).into())
            }
        }
    }

    pub fn verify(&self, shards: &[Vec<u8>]) -> Result<bool> {
        let total = self.total_shards();

        if shards.len() != total {
            return Ok(false);
        }

        // Check all shards have same size
        if let Some(first_len) = shards.first().map(Vec::len)
            && !shards.iter().all(|s| s.len() == first_len)
        {
            return Ok(false);
        }

        // Convert to slice references
        let shard_refs: Vec<&[u8]> = shards.iter().map(|s| s.as_slice()).collect();

        // Verify using backend
        match &self.backend {
            CodecBackend::Mds(backend) => backend
                .verify(&shard_refs)
                .map_err(|e| ErasureError::EncodingFailed(e.to_string()).into()),
            CodecBackend::Lrc(backend) => backend
                .verify(&shard_refs)
                .map_err(|e| ErasureError::EncodingFailed(e.to_string()).into()),
        }
    }

    /// Try to recover a single missing shard using local parity (LRC only)
    ///
    /// Returns `None` if local recovery is not possible (e.g., MDS mode or
    /// multiple failures in the local group).
    pub fn try_local_recovery(
        &self,
        shards: &[Option<&[u8]>],
        shard_size: usize,
        missing_index: usize,
    ) -> Result<Option<Vec<u8>>> {
        match &self.backend {
            CodecBackend::Mds(_) => Ok(None),
            CodecBackend::Lrc(backend) => backend
                .decode_local(shards, shard_size, missing_index)
                .map_err(|e| ErasureError::DecodingFailed(e.to_string()).into()),
        }
    }

    /// Check if a missing shard can be recovered using local parity only
    ///
    /// This is useful for repair scheduling to prioritize local repairs.
    pub fn can_recover_locally(&self, available: &[bool], missing_index: usize) -> bool {
        match &self.backend {
            CodecBackend::Mds(_) => false,
            CodecBackend::Lrc(backend) => backend.can_recover_locally(available, missing_index),
        }
    }
}

impl Default for ErasureCodec {
    fn default() -> Self {
        Self::new(ErasureConfig::default()).expect("default config is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    fn checksums(stripe: &[Vec<u8>]) -> Vec<Option<u32>> {
        stripe.iter().map(|s| Some(crc32c::crc32c(s))).collect()
    }

    fn without(stripe: &[Vec<u8>], lost: &[usize]) -> Vec<Option<Vec<u8>>> {
        (0..stripe.len())
            .map(|i| (!lost.contains(&i)).then(|| stripe[i].clone()))
            .collect()
    }

    #[test]
    fn combinations_are_every_choice_once() {
        let all: Vec<Vec<usize>> = Combinations::new(4, 2).collect();
        assert_eq!(
            all,
            vec![
                vec![0, 1],
                vec![0, 2],
                vec![0, 3],
                vec![1, 2],
                vec![1, 3],
                vec![2, 3]
            ]
        );
        assert_eq!(Combinations::new(3, 0).count(), 1);
        assert_eq!(Combinations::new(3, 3).count(), 1);
        assert_eq!(Combinations::new(2, 3).count(), 0);
    }

    /// A parity shard stored wrong under a checksum of its own wrong bytes
    /// (what a writer with another codec leaves, to this one) passes every
    /// read check; a decode through it rebuilds other bytes. The rebuilt
    /// shard's recorded checksum catches it, and the decode goes around it
    /// when there is a way.
    #[test]
    fn a_parity_shard_stored_wrong_is_never_decoded_into_the_data() {
        let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
        let data = body(70_001);
        let mut stripe = codec.encode(&data).unwrap();
        for b in &mut stripe[4] {
            *b = !*b;
        }
        let recorded = checksums(&stripe);

        // Data shard 1 lost, decoded through parity 4: other bytes.
        let mut through_bad = without(&stripe, &[1, 5]);
        assert_ne!(codec.decode(&mut through_bad, data.len()).unwrap(), data);
        assert!(matches!(
            codec.decode_verified(&through_bad, data.len(), &recorded),
            Err(ErasureError::Unverified(_))
        ));
        // With parity 5 read too, the decode goes through it instead.
        let both = without(&stripe, &[1]);
        assert_eq!(
            codec.decode_verified(&both, data.len(), &recorded).unwrap(),
            data
        );
    }

    /// A data shard never written (the write met its quorum without it) has
    /// no checksum recorded: rebuilt, it is borne out by a parity shard the
    /// decode did not use, and with none it is not returned.
    #[test]
    fn a_rebuilt_shard_with_no_checksum_needs_a_spare_shard() {
        let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
        let data = body(50_051);
        let stripe = codec.encode(&data).unwrap();
        let mut recorded = checksums(&stripe);
        recorded[2] = None;

        let exactly_k = without(&stripe, &[2, 4]);
        assert!(matches!(
            codec.decode_verified(&exactly_k, data.len(), &recorded),
            Err(ErasureError::Unverified(_))
        ));
        let spare = without(&stripe, &[2]);
        assert_eq!(
            codec
                .decode_verified(&spare, data.len(), &recorded)
                .unwrap(),
            data
        );
        // All data present: nothing rebuilt, nothing to check.
        let healthy = without(&stripe, &[4, 5]);
        assert_eq!(
            codec
                .decode_verified(&healthy, data.len(), &recorded)
                .unwrap(),
            data
        );
        assert!(matches!(
            codec.decode_verified(&without(&stripe, &[0, 1, 2]), data.len(), &recorded),
            Err(ErasureError::InsufficientShards { .. })
        ));
    }

    #[test]
    fn lrc_decodes_verified() {
        let codec = ErasureCodec::new(ErasureConfig::lrc(6, 2, 2)).unwrap();
        let data = body(60_000);
        let stripe = codec.encode(&data).unwrap();
        let recorded = checksums(&stripe);
        // One from its group; two of group 0 and its local parity, and
        // one of each group with one global parity, from the global code.
        for lost in [vec![1], vec![0, 1, 6], vec![0, 4, 8]] {
            let shards = without(&stripe, &lost);
            assert_eq!(
                codec
                    .decode_verified(&shards, data.len(), &recorded)
                    .unwrap(),
                data,
                "lost {lost:?}"
            );
        }
    }

    /// An LRC stripe is coded as the PUT path codes it
    /// (`RustSimdLrcBackend`), on every build: an ISA-L LRC backend wrote
    /// its global parity with ISA-L, which other nodes decoded as
    /// reed-solomon-simd's.
    #[test]
    fn lrc_is_coded_alike_on_every_build() {
        let codec = ErasureCodec::new(ErasureConfig::lrc(6, 2, 2)).unwrap();
        let data = body(60_000);
        let stripe = codec.encode(&data).unwrap();
        let size = ErasureCodec::shard_size_for(data.len(), 6);
        let mut padded = data.clone();
        padded.resize(size * 6, 0);
        let refs: Vec<&[u8]> = padded.chunks(size).collect();
        let put = crate::RustSimdLrcBackend::new(LrcConfig::new(6, 2, 2))
            .unwrap()
            .encode_lrc(&refs, size)
            .unwrap()
            .all_shards();
        assert!(
            stripe == put,
            "LRC coded otherwise than the PUT path codes it"
        );
    }

    #[test]
    fn encode_bytes_matches_encode() {
        // Sizes that pad (not a multiple of k * 64) and ones that do not.
        let data: Vec<u8> = (0..1_000_003u32).map(|i| (i * 7 + 3) as u8).collect();
        for config in [
            ErasureConfig::new(4, 2),
            ErasureConfig::new(8, 3),
            ErasureConfig::lrc(6, 2, 2),
        ] {
            let codec = ErasureCodec::new(config).unwrap();
            for len in [1, 63, 4096, 1_000_003] {
                let owned = codec.encode(&data[..len]).unwrap();
                let bytes = codec.encode_bytes(&data[..len]).unwrap();
                assert_eq!(owned.len(), bytes.len());
                for (a, b) in owned.iter().zip(&bytes) {
                    assert_eq!(a.as_slice(), b.as_ref(), "{config:?} len={len}");
                }
            }
        }
    }

    #[test]
    fn encode_into_a_dirty_buffer_matches_a_fresh_encode() {
        let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
        let data: Vec<u8> = (0..70_003u32).map(|i| (i % 253) as u8).collect();
        // A reused slot still holds the last stripe's bytes.
        let mut slot = vec![0xAAu8; codec.stripe_len(data.len()) + 4096];
        let shard_size = codec.encode_into(&data, &mut slot).unwrap();
        for (i, want) in codec.encode(&data).unwrap().iter().enumerate() {
            assert_eq!(
                &slot[i * shard_size..(i + 1) * shard_size],
                want.as_slice(),
                "shard {i}"
            );
        }
        assert!(
            slot[codec.stripe_len(data.len())..]
                .iter()
                .all(|&b| b == 0xAA)
        );
    }

    #[test]
    fn encode_into_refuses_short_buffers_and_lrc() {
        let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
        let mut short = vec![0u8; codec.stripe_len(1000) - 1];
        assert!(codec.encode_into(&[1; 1000], &mut short).is_err());
        let lrc = ErasureCodec::new(ErasureConfig::lrc(6, 2, 2)).unwrap();
        let mut buf = vec![0u8; 1 << 20];
        assert!(lrc.encode_into(&[1; 1000], &mut buf).is_err());
    }

    /// Every shard, data or parity, comes back as it was encoded, for every
    /// way of losing up to m of them — what repair and drain write back.
    #[test]
    fn reconstruct_shards_rebuilds_exactly_the_positions_asked_for() {
        let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
        let data: Vec<u8> = (0..70_001u32).map(|i| (i * 7 % 253) as u8).collect();
        let stripe = codec.encode(&data).unwrap();
        let mut losses: Vec<Vec<usize>> = (0..6).map(|a| vec![a]).collect();
        for a in 0..6 {
            for b in a + 1..6 {
                losses.push(vec![a, b]);
            }
        }
        for lost in losses {
            let survivors: Vec<Option<Vec<u8>>> = (0..6)
                .map(|i| (!lost.contains(&i)).then(|| stripe[i].clone()))
                .collect();
            let rebuilt = codec.reconstruct_shards(&survivors, &lost).unwrap();
            assert_eq!(rebuilt.len(), lost.len(), "lost {lost:?}");
            for (i, shard) in lost.iter().zip(&rebuilt) {
                assert_eq!(shard, &stripe[*i], "shard {i} wrong after losing {lost:?}");
            }
        }
    }

    /// A source that couldn't be read is not a shard of zeros. Repair asks
    /// for the positions it lost, and its survivors can hold more gaps than
    /// that: a source read that failed. Taken as zeros, the rebuilt shard
    /// was wrong and stored with a checksum of its own wrong bytes; the B2
    /// soak read objects back with a shard of zeros, HTTP 200.
    #[test]
    fn an_unread_source_is_not_taken_as_zeros() {
        let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
        let data: Vec<u8> = (0..50_051u32).map(|i| (i * 13 % 251) as u8).collect();
        let stripe = codec.encode(&data).unwrap();
        for lost in 0..6 {
            for unread in (0..6).filter(|&u| u != lost) {
                let survivors: Vec<Option<Vec<u8>>> = (0..6)
                    .map(|i| (i != lost && i != unread).then(|| stripe[i].clone()))
                    .collect();
                let rebuilt = codec.reconstruct_shards(&survivors, &[lost]).unwrap();
                assert_eq!(
                    rebuilt[0], stripe[lost],
                    "shard {lost} rebuilt wrong with shard {unread} unread"
                );
            }
        }
    }

    #[test]
    fn decode_accepts_bytes_and_recovers_from_parity() {
        let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
        let data: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let mut shards: Vec<Option<Bytes>> = codec
            .encode_bytes(&data)
            .unwrap()
            .into_iter()
            .map(Some)
            .collect();
        shards[0] = None;
        shards[3] = None;
        assert_eq!(codec.decode(&mut shards, data.len()).unwrap(), data);
    }

    #[test]
    fn test_encode_decode_mds() {
        let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
        let data = b"Hello, World! This is a test of erasure coding.";

        let shards = codec.encode(data).unwrap();
        assert_eq!(shards.len(), 6); // 4 data + 2 parity

        // All shards should be same size
        let shard_size = shards[0].len();
        assert!(shards.iter().all(|s| s.len() == shard_size));

        // Decode with all shards present
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let decoded = codec.decode(&mut shard_opts, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_decode_with_missing_mds() {
        let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
        let data = b"Hello, World! This is a test of erasure coding with recovery.";

        let shards = codec.encode(data).unwrap();
        assert_eq!(shards.len(), 6);

        // Remove 2 shards (within parity tolerance)
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shard_opts[1] = None; // Remove one data shard
        shard_opts[4] = None; // Remove one parity shard

        let decoded = codec.decode(&mut shard_opts, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_insufficient_shards() {
        let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();

        // Only 3 shards when we need 4
        let mut shards: Vec<Option<Vec<u8>>> = vec![
            Some(vec![0u8; 64]),
            Some(vec![0u8; 64]),
            Some(vec![0u8; 64]),
            None,
            None,
            None,
        ];

        let result = codec.decode(&mut shards, 64);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_decode_lrc() {
        // LRC with 6 data shards, 2 local parity (groups of 3), 2 global parity
        let config = ErasureConfig::lrc(6, 2, 2);
        let codec = ErasureCodec::new(config).unwrap();

        assert!(codec.is_lrc());
        assert_eq!(codec.data_shards(), 6);
        assert_eq!(codec.parity_shards(), 4); // 2 local + 2 global

        let data = b"Testing LRC erasure coding with local and global parity shards.";

        let shards = codec.encode(data).unwrap();
        assert_eq!(shards.len(), 10); // 6 data + 2 local + 2 global

        // Decode with all shards present
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        let decoded = codec.decode(&mut shard_opts, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    /// Every subset of an LRC(4,2,1) stripe's shards: a decode gives the
    /// original data or an error, never other bytes; and it succeeds
    /// whenever its two steps can: a group's one missing data shard from
    /// the group, then k of the data and global parity for the rest. (Two
    /// data shards of one group, from its local parity and the global one
    /// together, are not solved.)
    #[test]
    fn lrc_decodes_every_subset_that_determines_the_data() {
        let codec = ErasureCodec::new(ErasureConfig::lrc(4, 2, 1)).unwrap();
        let data: Vec<u8> = (0..4000u32).map(|i| (i * 7 + 3) as u8).collect();
        let shards = codec.encode(&data).unwrap();
        let n = shards.len();
        for mask in 0u32..(1 << n) {
            let have = |i: usize| mask & (1 << i) != 0;
            let mut slots: Vec<Option<Vec<u8>>> =
                (0..n).map(|i| have(i).then(|| shards[i].clone())).collect();
            // Groups (d0, d1, lp0 at 4) and (d2, d3, lp1 at 5); g at 6.
            let group = |a: usize, b: usize, lp: usize| {
                usize::from(have(a))
                    + usize::from(have(b))
                    + usize::from(have(lp) && have(a) != have(b))
            };
            let usable = group(0, 1, 4) + group(2, 3, 5) + usize::from(have(6));
            match codec.decode(&mut slots, data.len()) {
                Ok(got) => assert_eq!(got, data, "shards {mask:07b}: wrong data"),
                Err(e) => assert!(
                    usable < 4,
                    "shards {mask:07b} decode in two steps, yet: {e}"
                ),
            }
        }
    }

    #[test]
    fn test_lrc_local_recovery() {
        // LRC with 6 data shards, 2 local parity (groups of 3), 2 global parity
        let config = ErasureConfig::lrc(6, 2, 2);
        let codec = ErasureCodec::new(config).unwrap();

        let data = b"Testing LRC local recovery - should only need local group shards.";

        let shards = codec.encode(data).unwrap();

        // Remove one shard from first group (indices 0-2 are group 0)
        let mut shard_opts: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        shard_opts[1] = None; // Remove data shard 1

        // Should be able to recover using local parity
        let decoded = codec.decode(&mut shard_opts, data.len()).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_verify_mds() {
        let codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
        let data = b"Data to verify with erasure coding.";

        let shards = codec.encode(data).unwrap();
        assert!(codec.verify(&shards).unwrap());

        // Corrupt a shard and verify should fail
        let mut corrupted = shards.clone();
        corrupted[0][0] ^= 0xFF;
        assert!(!codec.verify(&corrupted).unwrap());
    }

    #[test]
    fn test_codec_helper_methods() {
        let mds_codec = ErasureCodec::new(ErasureConfig::new(4, 2)).unwrap();
        assert!(!mds_codec.is_lrc());
        assert_eq!(mds_codec.data_shards(), 4);
        assert_eq!(mds_codec.parity_shards(), 2);
        assert_eq!(mds_codec.total_shards(), 6);

        let lrc_codec = ErasureCodec::new(ErasureConfig::lrc(6, 2, 2)).unwrap();
        assert!(lrc_codec.is_lrc());
        assert_eq!(lrc_codec.data_shards(), 6);
        assert_eq!(lrc_codec.parity_shards(), 4);
        assert_eq!(lrc_codec.total_shards(), 10);
    }

    #[test]
    fn test_ec_roundtrip_large_sizes() {
        let codec = ErasureCodec::new(ErasureConfig::new(3, 2)).unwrap();
        for size in [6_291_456, 6_656_000, 7_340_032, 8_388_608, 10_485_760] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let shards = codec.encode(&data).unwrap();
            let mut decode_shards: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
            let decoded = codec.decode(&mut decode_shards, size).unwrap();
            assert_eq!(decoded.len(), size, "size mismatch for {size}");
            assert_eq!(data, decoded, "data mismatch for {size}");
        }
    }
}
