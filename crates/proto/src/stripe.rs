//! Writing a stripe: which OSD each of its shards goes to, how many must be
//! on disk before the write is acknowledged, and what the stripe records.
//!
//! Every writer goes through here — the gateway's PUTs, multipart parts and
//! packs, and the block gateway's chunks — so each is held to the same
//! rules; what differs between them is only how a shard reaches its OSD
//! and how a write short of its quorum is answered.

use std::collections::HashSet;
use std::fmt;
use std::future::Future;

use objectio_common::ErasureConfig;

use crate::metadata::{
    ErasureType, GetPlacementResponse, NodePlacement, ShardLocation, StripeMeta,
};
use crate::storage::{BlockLocation, PgRef};

/// How a stripe is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// Whole copies, one per position.
    Replicas(u32),
    /// Reed-Solomon: `k` data shards, `m` parity; any `k` decode.
    Mds { k: u32, m: u32 },
    /// `k` data shards in `l` groups, each with a local parity, and `g`
    /// global parity over all of them.
    Lrc { k: u32, l: u32, g: u32 },
}

impl Scheme {
    /// The scheme a placement is for: its pool's.
    #[must_use]
    pub fn of(placement: &GetPlacementResponse) -> Self {
        match ErasureType::try_from(placement.ec_type) {
            Ok(ErasureType::ErasureReplication) => {
                Self::Replicas(placement.replication_count.max(1))
            }
            Ok(ErasureType::ErasureLrc) => Self::Lrc {
                k: placement.ec_k,
                l: placement.ec_local_parity,
                g: placement.ec_global_parity,
            },
            _ => Self::Mds {
                k: placement.ec_k,
                m: placement.ec_m,
            },
        }
    }

    /// Positions in a stripe: its shards, or its copies.
    #[must_use]
    pub const fn width(self) -> usize {
        (match self {
            Self::Replicas(n) => n,
            Self::Mds { k, m } => k + m,
            Self::Lrc { k, l, g } => k + l + g,
        }) as usize
    }

    /// Data shards: what a stripe's bytes are split over (1 for copies).
    #[must_use]
    pub const fn data_shards(self) -> usize {
        (match self {
            Self::Replicas(_) => 1,
            Self::Mds { k, .. } | Self::Lrc { k, .. } => k,
        }) as usize
    }

    /// Shards (on distinct OSDs) that must be on disk before a write is
    /// acknowledged: enough to read the stripe back after one more loss.
    ///
    /// - MDS: k + 1 (k without parity). Any k decode, but a stripe
    ///   acknowledged with exactly k has no redundancy left.
    /// - Replicas: two, the copy and a spare (one in a pool of one).
    /// - LRC: all but g − 1. Only a loss of g is sure to decode (more
    ///   decode or not by where they fall), so a stripe short of g − 1
    ///   still survives one more. k + 1 would acknowledge stripes some of
    ///   whose missing shards no decode can rebuild.
    #[must_use]
    pub const fn quorum(self) -> usize {
        match self {
            Self::Replicas(n) => {
                if n < 2 {
                    n as usize
                } else {
                    2
                }
            }
            Self::Mds { k, m } => {
                if m == 0 {
                    k as usize
                } else {
                    k as usize + 1
                }
            }
            Self::Lrc { k, l, .. } => (k + l + 1) as usize,
        }
    }

    /// The (k, m) a shard of the stripe is written with: (1, 0) for a copy.
    #[must_use]
    pub const fn shard_code(self) -> (u32, u32) {
        match self {
            Self::Replicas(_) => (1, 0),
            Self::Mds { k, m } => (k, m),
            Self::Lrc { k, l, g } => (k, l + g),
        }
    }

    /// The code the stripe's shards are made with; none for copies.
    #[must_use]
    pub fn erasure(self) -> Option<ErasureConfig> {
        let byte = |n: u32| u8::try_from(n).unwrap_or(u8::MAX);
        match self {
            Self::Replicas(_) => None,
            Self::Mds { k, m } => Some(ErasureConfig::new(byte(k), byte(m))),
            Self::Lrc { k, l, g } => Some(ErasureConfig::lrc(byte(k), byte(l), byte(g))),
        }
    }

    /// The record of a stripe written with this scheme. A copy per
    /// position is recorded as k = 1 and m = the copies but one, so
    /// recovery and the placement group index see a stripe short of a copy
    /// as they see one short of a shard.
    #[must_use]
    pub fn stripe(
        self,
        stripe_id: u64,
        data_size: u64,
        object_id: Vec<u8>,
        shards: Vec<ShardLocation>,
    ) -> StripeMeta {
        let (ec_type, ec_k, ec_m, local, global, group) = match self {
            Self::Replicas(n) => (
                ErasureType::ErasureReplication,
                1,
                n.saturating_sub(1),
                0,
                0,
                0,
            ),
            Self::Mds { k, m } => (ErasureType::ErasureMds, k, m, 0, m, 0),
            Self::Lrc { k, l, g } => (
                ErasureType::ErasureLrc,
                k,
                l + g,
                l,
                g,
                k.checked_div(l).unwrap_or(0),
            ),
        };
        StripeMeta {
            stripe_id,
            ec_k,
            ec_m,
            shards,
            ec_type: ec_type.into(),
            ec_local_parity: local,
            ec_global_parity: global,
            local_group_size: group,
            data_size,
            object_id,
            ..Default::default()
        }
    }
}

/// The placement group and epoch a placement was made under.
///
/// Every shard written by it carries them: an OSD that knows a newer epoch
/// refuses the write (B31), and the writer places it again. None for a
/// placement made without one.
#[must_use]
pub fn fence(placement: &GetPlacementResponse) -> Option<PgRef> {
    (placement.pg_epoch > 0).then(|| PgRef {
        pool: placement.pool.clone(),
        pg_id: placement.pg_id,
        epoch: placement.pg_epoch,
    })
}

/// Where each of a stripe's `width` shards goes.
///
/// Position i goes to the OSD the placement names for it, and nowhere when
/// the placement names none, one with no address (a member set out that
/// nothing stood in for), or one an earlier position already went to: two
/// shards on one OSD are lost together, so a stripe is never written as if
/// they weren't.
#[must_use]
pub fn targets(nodes: &[NodePlacement], width: usize) -> Vec<Option<&NodePlacement>> {
    let mut used: HashSet<&[u8]> = HashSet::with_capacity(width);
    (0..width)
        .map(|i| {
            nodes
                .get(i)
                .filter(|n| !n.node_address.is_empty() && used.insert(n.node_id.as_slice()))
        })
        .collect()
}

/// A stripe write that did not reach its quorum.
#[derive(Debug)]
pub struct Short<E> {
    /// The shards that were stored, for the writer to free.
    pub written: Vec<ShardLocation>,
    /// The distinct OSDs those are on.
    pub stored: usize,
    pub quorum: usize,
    pub width: usize,
    /// Each failed shard's position and error.
    pub failed: Vec<(u32, E)>,
}

impl<E> Short<E> {
    /// Whether any shard failed as `pred` says.
    pub fn any(&self, pred: impl Fn(&E) -> bool) -> bool {
        self.failed.iter().any(|(_, e)| pred(e))
    }
}

impl<E: fmt::Display> fmt::Display for Short<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} of {} shards stored on distinct OSDs, {} needed",
            self.stored, self.width, self.quorum
        )?;
        if let Some((position, e)) = self.failed.first() {
            write!(f, " (shard {position}: {e})")?;
        }
        Ok(())
    }
}

/// Write a stripe's `shards`, one per position, all at once.
///
/// Each goes with `write` to the OSD [`targets`] gives it. Returns where
/// they went (by position) once `scheme`'s quorum of distinct OSDs have
/// them on disk.
///
/// `write` is how a shard reaches its OSD; it answers where the shard is
/// and its crc32c. What counts is the OSD that answered, not the one
/// asked: two shards stored by one OSD count once.
///
/// # Errors
/// [`Short`] when fewer than the quorum of distinct OSDs stored a shard.
pub async fn write<'n, S, E, F, Fut>(
    scheme: Scheme,
    nodes: &'n [NodePlacement],
    shards: Vec<S>,
    mut write: F,
) -> Result<Vec<ShardLocation>, Short<E>>
where
    F: FnMut(u32, &'n NodePlacement, S) -> Fut,
    Fut: Future<Output = Result<(BlockLocation, u32), E>>,
    E: fmt::Display,
{
    let width = scheme.width();
    let quorum = scheme.quorum();
    let sends = targets(nodes, width)
        .into_iter()
        .zip(shards)
        .enumerate()
        .filter_map(|(i, (node, shard))| {
            let node = node?;
            let position = u32::try_from(i).unwrap_or(u32::MAX);
            let sent = write(position, node, shard);
            Some(async move { (position, node, sent.await) })
        });
    let results = futures::future::join_all(sends).await;

    let mut written = Vec::with_capacity(width);
    let mut failed = Vec::new();
    for (position, node, result) in results {
        match result {
            Ok((location, crc32c)) => written.push(ShardLocation {
                position,
                node_id: location.node_id,
                disk_id: location.disk_id,
                offset: location.offset,
                shard_type: node.shard_type,
                local_group: node.local_group,
                crc32c: Some(crc32c),
            }),
            Err(e) => {
                tracing::warn!("shard {position} to {}: {e}", node.node_address);
                failed.push((position, e));
            }
        }
    }
    written.sort_by_key(|l| l.position);
    let stored = written
        .iter()
        .map(|l| l.node_id.as_slice())
        .collect::<HashSet<_>>()
        .len();
    if stored < quorum {
        return Err(Short {
            written,
            stored,
            quorum,
            width,
            failed,
        });
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u8) -> NodePlacement {
        NodePlacement {
            node_id: vec![id; 16],
            node_address: format!("osd-{id}"),
            ..Default::default()
        }
    }

    fn at(node: &NodePlacement) -> BlockLocation {
        BlockLocation {
            node_id: node.node_id.clone(),
            ..Default::default()
        }
    }

    #[test]
    fn a_write_keeps_one_more_loss_than_it_can_read_through() {
        assert_eq!(Scheme::Mds { k: 4, m: 2 }.quorum(), 5);
        assert_eq!(Scheme::Mds { k: 8, m: 3 }.quorum(), 9);
        assert_eq!(Scheme::Mds { k: 2, m: 1 }.quorum(), 3, "every shard");
        assert_eq!(Scheme::Mds { k: 4, m: 0 }.quorum(), 4);
        assert_eq!(Scheme::Replicas(3).quorum(), 2);
        assert_eq!(Scheme::Replicas(2).quorum(), 2);
        assert_eq!(Scheme::Replicas(1).quorum(), 1);
        // Every loss of g decodes, so a write may be g − 1 short.
        assert_eq!(Scheme::Lrc { k: 6, l: 2, g: 2 }.quorum(), 9);
        assert_eq!(Scheme::Lrc { k: 4, l: 2, g: 1 }.quorum(), 7, "every shard");
        assert_eq!(Scheme::Lrc { k: 12, l: 2, g: 2 }.width(), 16);
    }

    #[test]
    fn the_scheme_is_the_placements() {
        let p = |ec_type: ErasureType| GetPlacementResponse {
            ec_type: ec_type.into(),
            ec_k: 6,
            ec_m: 4,
            ec_local_parity: 2,
            ec_global_parity: 2,
            replication_count: 3,
            ..Default::default()
        };
        assert_eq!(
            Scheme::of(&p(ErasureType::ErasureMds)),
            Scheme::Mds { k: 6, m: 4 }
        );
        assert_eq!(
            Scheme::of(&p(ErasureType::ErasureLrc)),
            Scheme::Lrc { k: 6, l: 2, g: 2 }
        );
        assert_eq!(
            Scheme::of(&p(ErasureType::ErasureReplication)),
            Scheme::Replicas(3)
        );
        let lrc = Scheme::Lrc { k: 6, l: 2, g: 2 }.stripe(0, 1, vec![], vec![]);
        assert_eq!(
            (
                lrc.ec_k,
                lrc.ec_m,
                lrc.ec_local_parity,
                lrc.ec_global_parity,
                lrc.local_group_size
            ),
            (6, 4, 2, 2, 3)
        );
        let copies = Scheme::Replicas(3).stripe(0, 1, vec![], vec![]);
        assert_eq!((copies.ec_k, copies.ec_m), (1, 2));
    }

    #[test]
    fn two_positions_never_go_to_one_osd() {
        let nodes = [node(1), node(2), node(1)];
        let t = targets(&nodes, 3);
        assert_eq!(t[0].map(|n| n.node_id[0]), Some(1));
        assert_eq!(t[1].map(|n| n.node_id[0]), Some(2));
        assert!(t[2].is_none(), "position 2's OSD has position 0");
    }

    #[test]
    fn a_placement_short_of_positions_is_not_wrapped_around() {
        let nodes = [node(1), node(2), node(3)];
        let t = targets(&nodes, 6);
        assert_eq!(t.iter().flatten().count(), 3);
        assert!(t[3..].iter().all(Option::is_none));
    }

    #[test]
    fn a_member_with_no_address_gets_nothing() {
        let mut out = node(2);
        out.node_address.clear();
        let nodes = [node(1), out, node(3)];
        assert!(targets(&nodes, 3)[1].is_none());
    }

    fn block_on<F: Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn a_stripe_on_fewer_osds_than_its_quorum_is_short() {
        // Six positions placed over three OSDs, every write answered: three
        // distinct OSDs hold it, short of 4+2's five.
        let nodes = [node(1), node(2), node(3)];
        let r = block_on(write(
            Scheme::Mds { k: 4, m: 2 },
            &nodes,
            vec![(); 6],
            |_, n, ()| async move { Ok::<_, String>((at(n), 0)) },
        ));
        let short = r.unwrap_err();
        assert_eq!((short.stored, short.quorum, short.written.len()), (3, 5, 3));
    }

    #[test]
    fn two_shards_one_osd_stored_count_once() {
        // Every OSD asked answers as OSD 1.
        let nodes = [node(1), node(2), node(3)];
        let r = block_on(write(
            Scheme::Replicas(3),
            &nodes,
            vec![(); 3],
            |_, _, ()| async { Ok::<_, String>((at(&node(1)), 0)) },
        ));
        assert_eq!(r.unwrap_err().stored, 1);
    }

    #[test]
    fn a_write_at_its_quorum_is_stored_and_says_where() {
        let nodes = [node(1), node(2), node(3)];
        let r = block_on(write(
            Scheme::Replicas(3),
            &nodes,
            vec![(); 3],
            |pos, n, ()| {
                let n = n.clone();
                async move {
                    if pos == 1 {
                        Err("down".to_string())
                    } else {
                        Ok((at(&n), 7))
                    }
                }
            },
        ));
        let written = r.unwrap();
        assert_eq!(
            written.iter().map(|l| l.position).collect::<Vec<_>>(),
            [0, 2]
        );
        assert!(written.iter().all(|l| l.crc32c == Some(7)));

        let r = block_on(write(
            Scheme::Replicas(3),
            &nodes,
            vec![(); 3],
            |pos, n, ()| {
                let n = n.clone();
                async move {
                    if pos == 0 {
                        Ok((at(&n), 0))
                    } else {
                        Err(format!("osd {pos} down"))
                    }
                }
            },
        ));
        let short = r.unwrap_err();
        assert_eq!(short.failed.len(), 2);
        assert_eq!(
            short.to_string(),
            "1 of 3 shards stored on distinct OSDs, 2 needed (shard 1: osd 1 down)"
        );
    }
}
