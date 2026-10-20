//! The protection schemes the codecs can code, said once for every place
//! one is chosen: meta's pools (made, changed, its default pool) and the
//! block gateway's volumes. A scheme refused here is one whose stripes
//! some write or some loss it claims to survive would fail.

use crate::backend::isal::{MAX_SHARDS, is_mds};

/// Why a `k`+`m` MDS stripe can't be coded, or can't rebuild its data
/// after every loss of m shards. MDS stripes are ISA-L's, whose matrix is
/// MDS only for some profiles ([`is_mds`]); a stripe with no parity
/// (m = 0) is refused too: one lost shard loses it, and one unprotected
/// copy is what a replication pool of 1 is.
///
/// # Errors
/// What is wrong with the profile, naming it as `k+m`.
pub fn check_mds(k: usize, m: usize) -> Result<(), String> {
    if k == 0 || k + m > MAX_SHARDS {
        return Err(format!(
            "{k}+{m} is not an erasure code: k is at least 1 and k+m at most {MAX_SHARDS}"
        ));
    }
    if m == 0 {
        return Err(format!(
            "{k}+0 has no parity: one lost shard loses the object. One unprotected copy \
             of each object is replication with 1 copy (meta: --replication 1); erasure \
             coding has m at least 1"
        ));
    }
    if !is_mds(k, m) {
        return Err(format!(
            "{k}+{m} can't rebuild its data after every loss of {m} shards. MDS profiles: \
             up to 3 parity shards with any k, 4 with k up to 21, and 5+5 (or, the other \
             way round, k up to 3 with any m, k = 4 with m up to 21)"
        ));
    }
    Ok(())
}

/// Why an LRC stripe of `k` data shards in `l` local groups, with `g`
/// global parity shards, can't be coded: its groups are all one size (k a
/// multiple of l), each has its local parity, and the global parity
/// (reed-solomon-simd, which needs at least one recovery shard) is what
/// rebuilds a group that lost more than one. As implemented, every loss
/// of g shards decodes; more depend on where they fall.
///
/// # Errors
/// What is wrong with the profile, naming it as `k+l+g`.
pub fn check_lrc(k: usize, l: usize, g: usize) -> Result<(), String> {
    if k == 0 || l == 0 || g == 0 {
        return Err(format!(
            "LRC {k}+{l}+{g}: data shards (k), local groups (l) and global parity (g) are \
             each at least 1"
        ));
    }
    if !k.is_multiple_of(l) {
        return Err(format!(
            "LRC {k}+{l}+{g}: {k} data shards don't split into {l} local groups of one size \
             (k is a multiple of l)"
        ));
    }
    if k + l + g > MAX_SHARDS {
        return Err(format!(
            "LRC {k}+{l}+{g}: {} shards, at most {MAX_SHARDS}",
            k + l + g
        ));
    }
    Ok(())
}

/// Why `n` copies can't be a replicated stripe: at least one, and no more
/// positions than a stripe has.
///
/// # Errors
/// What is wrong with the count.
pub fn check_replicas(n: usize) -> Result<(), String> {
    if n == 0 || n > MAX_SHARDS {
        return Err(format!(
            "{n} copies: replication keeps from 1 to {MAX_SHARDS} copies of each object"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErasureCodec;
    use objectio_common::ErasureConfig;

    #[test]
    fn mds_profiles_with_parity_pass() {
        for (k, m) in [(1, 1), (4, 2), (8, 3), (21, 4), (5, 5), (3, 20), (252, 3)] {
            assert!(check_mds(k, m).is_ok(), "{k}+{m}");
        }
        for (k, m) in [
            (1, 0),
            (4, 0),
            (0, 2),
            (6, 5),
            (5, 6),
            (22, 4),
            (250, 6),
            (300, 1),
        ] {
            let e = check_mds(k, m).unwrap_err();
            assert!(e.contains(&format!("{k}+{m}")), "{k}+{m}: {e}");
        }
        assert!(check_mds(1, 0).unwrap_err().contains("replication"));
    }

    #[test]
    fn lrc_profiles_are_checked() {
        for (k, l, g) in [
            (6, 2, 2),
            (4, 2, 1),
            (12, 2, 2),
            (1, 1, 1),
            (8, 8, 1),
            (200, 50, 5),
        ] {
            assert!(check_lrc(k, l, g).is_ok(), "{k}+{l}+{g}");
        }
        for (k, l, g) in [
            (0, 1, 1),
            (6, 0, 2),
            (6, 2, 0),
            (6, 4, 2),
            (5, 2, 1),
            (2, 4, 1),
            (200, 50, 6),
            (250, 5, 5),
        ] {
            let e = check_lrc(k, l, g).unwrap_err();
            assert!(e.contains(&format!("{k}+{l}+{g}")), "{k}+{l}+{g}: {e}");
        }
    }

    #[test]
    fn replica_counts_are_checked() {
        assert!(check_replicas(1).is_ok());
        assert!(check_replicas(3).is_ok());
        assert!(check_replicas(0).is_err());
        assert!(check_replicas(256).is_err());
    }

    /// Bytes that differ along their length.
    fn bytes(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed) ^ (i >> 8) as u8)
            .collect()
    }

    /// Every LRC profile the check passes codes data of any length, odd
    /// ones too (reed-solomon-simd refuses odd shard sizes: the codec
    /// rounds them), and decodes it again after every loss of g shards.
    #[test]
    fn every_lrc_profile_passed_codes_any_length_and_survives_g_losses() {
        for k in 1..=8usize {
            for l in (1..=k).filter(|l| k.is_multiple_of(*l)) {
                for g in 1..=2usize {
                    check_lrc(k, l, g).unwrap();
                    let codec =
                        ErasureCodec::new(ErasureConfig::lrc(k as u8, l as u8, g as u8)).unwrap();
                    let n = k + l + g;
                    for len in [1usize, 63, 65, 1001] {
                        let data = bytes(len, (k * 7 + l * 3 + g) as u8);
                        let shards = codec.encode(&data).unwrap();
                        assert_eq!(shards.len(), n);
                        // Every choice of g positions lost.
                        let mut lost: Vec<usize> = (0..g).collect();
                        loop {
                            let mut slots: Vec<Option<&[u8]>> =
                                shards.iter().map(|s| Some(s.as_slice())).collect();
                            for &p in &lost {
                                slots[p] = None;
                            }
                            let got = codec.decode(&mut slots, len).unwrap_or_else(|e| {
                                panic!("LRC {k}+{l}+{g}, {len} bytes, lost {lost:?}: {e}")
                            });
                            assert_eq!(got, data, "LRC {k}+{l}+{g}, {len} bytes, lost {lost:?}");
                            let Some(i) = (0..g).rev().find(|&i| lost[i] < n - g + i) else {
                                break;
                            };
                            lost[i] += 1;
                            for j in i + 1..g {
                                lost[j] = lost[j - 1] + 1;
                            }
                        }
                    }
                }
            }
        }
    }

    /// LRC 6+2+2 as implemented: every two losses decode, 88% of three.
    /// (What the data-protection design says it guarantees.)
    #[test]
    fn lrc_6_2_2_decodes_every_two_losses_and_most_threes() {
        let codec = ErasureCodec::new(ErasureConfig::lrc(6, 2, 2)).unwrap();
        let data = bytes(6000, 9);
        let shards = codec.encode(&data).unwrap();
        let decodes = |lost: &[usize]| {
            let mut slots: Vec<Option<&[u8]>> = shards.iter().map(|s| Some(s.as_slice())).collect();
            for &p in lost {
                slots[p] = None;
            }
            codec
                .decode(&mut slots, data.len())
                .is_ok_and(|d| d == data)
        };
        for a in 0..10 {
            for b in a + 1..10 {
                assert!(decodes(&[a, b]), "lost {a}, {b}");
            }
        }
        let (mut ok, mut all) = (0, 0);
        for a in 0..10 {
            for b in a + 1..10 {
                for c in b + 1..10 {
                    all += 1;
                    ok += usize::from(decodes(&[a, b, c]));
                }
            }
        }
        assert_eq!(all, 120);
        assert_eq!(
            ok * 100 / all,
            88,
            "{ok} of {all} three-shard losses decode"
        );
    }
}
