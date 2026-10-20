//! MDS Reed-Solomon on ISA-L, on every build
//!
//! Every MDS stripe is coded with ISA-L's Vandermonde matrix
//! (`gf_gen_rs_matrix`, GF(2^8), polynomial 0x11d), on x86_64 and on
//! aarch64 alike: a stripe decodes only with the code that wrote its
//! parity, so there is one. The `erasure-isa-l` crate bundles ISA-L's
//! source and builds it with autotools (autoconf, automake, libtool; NASM
//! too on x86_64; libclang for its bindings).
//!
//! The Vandermonde matrix is not MDS for every (k, m): [`is_mds`] says
//! which profiles can rebuild the data from every k of their shards, and
//! meta refuses a pool with any other.

mod backend;

pub use backend::IsalBackend;

/// Most shards a stripe can have: GF(2^8) has 255 distinct nonzero
/// elements to build the rows from.
pub const MAX_SHARDS: usize = 255;

/// Whether every k of a k+m stripe's shards rebuild its data, with the
/// matrix ISA-L's `gf_gen_rs_matrix` makes: a k x k submatrix of it,
/// chosen by the shards left, is invertible for every choice.
///
/// Its parity rows are `(2^r)^j` (r the parity, j the data shard), which
/// is symmetric in r and j, so the set is too. Found exhaustively for
/// every k + m <= 255 (the tests below repeat it up to 26 shards; ISA-L's
/// `erasure_code.h` lists the same bounds): any m with k <= 3, any k with
/// m <= 3, k <= 21 with m = 4 (and m <= 21 with k = 4), and 5 + 5. Every
/// other profile has some loss of m or fewer shards it cannot decode:
/// 6 + 5, 5 + 6 and 22 + 4 are the smallest.
#[must_use]
pub const fn is_mds(data_shards: usize, parity_shards: usize) -> bool {
    if data_shards == 0 || parity_shards == 0 || data_shards + parity_shards > MAX_SHARDS {
        return false;
    }
    let (fewer, more) = if data_shards < parity_shards {
        (data_shards, parity_shards)
    } else {
        (parity_shards, data_shards)
    };
    fewer <= 3 || (fewer == 4 && more <= 21) || (fewer == 5 && more == 5)
}

#[cfg(test)]
mod tests {
    use super::*;
    use erasure_isa_l::gf;

    /// Every choice of `r` of `0..n`, in order, until `f` says stop.
    fn every_choice(n: usize, r: usize, f: &mut dyn FnMut(&[usize]) -> bool) {
        let mut c: Vec<usize> = (0..r).collect();
        while f(&c) {
            let Some(i) = (0..r).rev().find(|&i| c[i] < n - r + i) else {
                return;
            };
            c[i] += 1;
            for j in i + 1..r {
                c[j] = c[j - 1] + 1;
            }
        }
    }

    /// Whether ISA-L's own encode matrix for k + m inverts for every k of
    /// its rows: what a decode after losing any m shards needs.
    fn decodes_every_loss(k: usize, m: usize) -> bool {
        let n = k + m;
        let mut matrix = vec![0u8; n * k];
        gf::gen_rs_matrix(&mut matrix, n as i32, k as i32);
        let mut all = true;
        every_choice(n, k, &mut |rows| {
            let mut sub: Vec<u8> = rows
                .iter()
                .flat_map(|&r| matrix[r * k..(r + 1) * k].iter().copied())
                .collect();
            let mut inverse = vec![0u8; k * k];
            all = gf::invert_matrix(&mut sub, &mut inverse, k as i32);
            all
        });
        all
    }

    /// [`is_mds`] is what an exhaustive check of ISA-L's matrix finds, for
    /// every stripe of up to 26 shards, the edges at m = 4 and k = 4
    /// included: 6 + 5, 5 + 6, 22 + 4 ... are not.
    #[test]
    fn is_mds_is_what_the_matrix_inverts() {
        for n in 2..=26 {
            for k in 1..n {
                let m = n - k;
                assert_eq!(
                    is_mds(k, m),
                    decodes_every_loss(k, m),
                    "{k} + {m}: is_mds disagrees with the matrix"
                );
            }
        }
    }

    /// GF(2^8) product, polynomial 0x11d, one bit at a time.
    fn gf_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0;
        while b != 0 {
            if b & 1 != 0 {
                p ^= a;
            }
            a = (a << 1) ^ if a & 0x80 != 0 { 0x1d } else { 0 };
            b >>= 1;
        }
        p
    }

    /// The stripes on disk are this code, on every CPU: parity shard r is
    /// the sum over data shards j of `(2^r)^j` times shard j, in GF(2^8)
    /// with polynomial 0x11d: the code amd64 releases have always written.
    /// A change of matrix, library or CPU path that writes other parity
    /// fails here (it runs on x86_64 and aarch64 alike). Sizes with tails
    /// past every SIMD width.
    #[test]
    fn parity_is_the_vandermonde_code_on_every_cpu() {
        use crate::backend::ErasureBackend;
        for (k, m) in [(2, 1), (4, 2), (6, 3), (8, 3), (12, 4), (5, 5)] {
            let backend = IsalBackend::new(k as u8, m as u8).unwrap();
            for size in [64, 4160, 65_600] {
                let data: Vec<Vec<u8>> = (0..k)
                    .map(|j| {
                        (0..size)
                            .map(|b| ((b * 131 + j * 29 + (b >> 7)) % 251) as u8)
                            .collect()
                    })
                    .collect();
                let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();
                let stripe = backend.encode(&refs, size).unwrap();
                let mut generator = 1u8;
                for r in 0..m {
                    let mut want = vec![0u8; size];
                    let mut coefficient = 1u8;
                    for shard in &data {
                        for (w, &d) in want.iter_mut().zip(shard) {
                            *w ^= gf_mul(coefficient, d);
                        }
                        coefficient = gf_mul(coefficient, generator);
                    }
                    assert!(
                        stripe[k + r] == want,
                        "{k} + {m}, {size} bytes: parity {r} is not the Vandermonde code's"
                    );
                    generator = gf_mul(generator, 2);
                }
            }
        }
    }

    /// Past 26 shards, where checking every loss takes too long: up to 3
    /// parity (or 3 data) shards is MDS to the last shard GF(2^8) has.
    #[test]
    fn is_mds_far_edges() {
        assert!(is_mds(252, 3) && is_mds(3, 252) && is_mds(254, 1));
        assert!(!is_mds(253, 3) && !is_mds(30, 4) && !is_mds(0, 2) && !is_mds(4, 0));
    }
}
