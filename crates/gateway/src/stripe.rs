//! A stripe written from the gateway: a PUT's, a multipart part's, a
//! pack's.
//!
//! Which OSD each shard goes to and when the write counts as stored are
//! [`objectio_proto::stripe`]'s rules, which the block gateway keeps too.
//! This adds how the gateway codes a stripe and sends its shards (each
//! fenced by the placement group's epoch, over Transfer Engine where it
//! can), what it records as sent, and how a write short of its quorum is
//! answered — and placed again, when the placement was stale.

use std::future::Future;

use axum::http::StatusCode;
use axum::response::Response;
use bytes::Bytes;
use objectio_erasure::ErasureCodec;
use objectio_proto::metadata::{GetPlacementResponse, NodePlacement, ShardLocation};
use objectio_proto::storage::PgRef;
pub use objectio_proto::stripe::{Scheme, Short};

use crate::osd_pool::{OsdPool, OsdPoolError, PendingShards, RdmaSource, StalePlacement};
use crate::s3::S3Error;

/// A placement, as its stripes are written: where, how, and under which
/// epoch of its placement group.
pub struct Placed<'a> {
    pub nodes: &'a [NodePlacement],
    pub scheme: Scheme,
    /// Carried by every shard written (B31).
    pub fence: Option<PgRef>,
}

impl<'a> Placed<'a> {
    #[must_use]
    pub fn new(placement: &'a GetPlacementResponse) -> Self {
        Self {
            nodes: &placement.nodes,
            scheme: Scheme::of(placement),
            fence: objectio_proto::stripe::fence(placement),
        }
    }
}

/// Makes a stripe's shards from its bytes as its scheme does: the copies,
/// or the code's shards (an LRC pool's with its LRC code).
pub struct Coder {
    scheme: Scheme,
    codec: Option<ErasureCodec>,
}

impl Coder {
    /// # Errors
    /// A scheme the codec can't keep.
    pub fn new(scheme: Scheme) -> objectio_common::Result<Self> {
        Ok(Self {
            scheme,
            codec: scheme.erasure().map(ErasureCodec::new).transpose()?,
        })
    }

    /// The code, for a stripe encoded elsewhere (into Transfer Engine
    /// memory); none for copies.
    #[must_use]
    pub const fn codec(&self) -> Option<&ErasureCodec> {
        self.codec.as_ref()
    }

    /// # Errors
    /// The codec refusing the data.
    pub fn shards(&self, data: Bytes) -> objectio_common::Result<Vec<Bytes>> {
        match &self.codec {
            None => Ok(vec![data; self.scheme.width()]),
            Some(codec) => codec.encode_bytes(&data),
        }
    }
}

/// A stripe encoded into the gateway's Transfer Engine memory, for OSDs to
/// read their shards out of.
pub struct RdmaStripe<'a> {
    pub rdma: &'a crate::rdma::GatewayRdma,
    /// The stripe's first byte; none when no stripe slot was free and the
    /// shards go over gRPC.
    pub base: Option<u64>,
}

/// Write stripe `stripe_id` of `object_id`, `shards` one per position,
/// where `placed` puts them. Each shard sent is recorded in `pending`
/// first: one that timed out may still have landed.
///
/// # Errors
/// [`Short`] when fewer than the scheme's quorum of distinct OSDs stored a
/// shard; [`refused`] says how S3 hears of it.
pub async fn write_stripe(
    pool: &OsdPool,
    placed: &Placed<'_>,
    object_id: &[u8],
    stripe_id: u64,
    shards: Vec<Bytes>,
    rdma: Option<RdmaStripe<'_>>,
    mut pending: Option<&mut PendingShards>,
) -> Result<Vec<ShardLocation>, Short<OsdPoolError>> {
    let (k, m) = placed.scheme.shard_code();
    let pg = placed.fence.as_ref();
    let rdma = rdma.as_ref();
    objectio_proto::stripe::write(
        placed.scheme,
        placed.nodes,
        shards,
        |position, node, shard| {
            if let Some(pending) = pending.as_deref_mut() {
                pending.sent(node, object_id, stripe_id, position);
            }
            let source = rdma.and_then(|r| {
                let addr = r
                    .base
                    .map(|base| base + u64::from(position) * shard.len() as u64);
                // Transfer Engine was on offer, but no stripe slot was free.
                if addr.is_none() && !node.te_segment.is_empty() {
                    crate::gateway_metrics::record_rdma_fallback(
                        "write",
                        crate::rdma::Fallback::NoSlot,
                    );
                }
                addr.map(|addr| RdmaSource { rdma: r.rdma, addr })
            });
            crate::osd_pool::write_shard_to_osd(
                pool, node, object_id, stripe_id, position, shard, k, m, source, pg,
            )
        },
    )
    .await
}

/// How S3 hears of stripe `stripe_id` short of its quorum: 507 when OSDs
/// refused it for lack of room; 503 marked to be placed again when they
/// knew a newer epoch of its placement group (nothing was stored under the
/// one it was placed by); otherwise 503.
#[must_use]
pub fn refused(short: &Short<OsdPoolError>, stripe_id: u64) -> Response {
    if short.any(OsdPoolError::is_full) {
        return S3Error::storage_full();
    }
    if short.any(OsdPoolError::is_stale_epoch) {
        let mut resp = S3Error::xml_response(
            "ServiceUnavailable",
            &format!(
                "stripe {stripe_id}: the placement group's acting set changed while it was \
                 written; retry"
            ),
            StatusCode::SERVICE_UNAVAILABLE,
        );
        resp.extensions_mut().insert(StalePlacement);
        return resp;
    }
    S3Error::xml_response(
        "ServiceUnavailable",
        &format!("Write quorum not met for stripe {stripe_id}: {short}"),
        StatusCode::SERVICE_UNAVAILABLE,
    )
}

/// A write of `bucket/key`, placed once more when it was refused as placed
/// under an older epoch of its placement group than an OSD knew (B31): the
/// acting set changed between placing and writing, and nothing was
/// stored. The client never sees that. PUT and UploadPart alike, and a
/// DELETE that no copy carried out.
pub async fn placed_again<F, Fut>(bucket: &str, key: &str, attempt: F) -> Response
where
    F: Fn() -> Fut,
    Fut: Future<Output = Response>,
{
    let first = attempt().await;
    if first.extensions().get::<StalePlacement>().is_none() {
        return first;
    }
    crate::gateway_metrics::record_stale_placement();
    crate::placement_cache::forget(bucket, key);
    tracing::info!("{bucket}/{key}: placed under an old epoch; placed again");
    attempt().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn short(errors: Vec<OsdPoolError>) -> Short<OsdPoolError> {
        Short {
            written: Vec::new(),
            stored: 1,
            quorum: 2,
            width: 3,
            failed: (0..).zip(errors).collect(),
        }
    }

    #[test]
    fn a_short_write_is_answered_by_why() {
        let down = || OsdPoolError::ConnectionFailed("down".into());
        let full = refused(
            &short(vec![down(), OsdPoolError::Full("no room".into())]),
            0,
        );
        assert_eq!(full.status(), StatusCode::INSUFFICIENT_STORAGE);

        let stale = refused(
            &short(vec![OsdPoolError::StaleEpoch("5".into()), down()]),
            0,
        );
        assert_eq!(stale.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(stale.extensions().get::<StalePlacement>().is_some());

        let unavailable = refused(&short(vec![down(), down()]), 0);
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(unavailable.extensions().get::<StalePlacement>().is_none());
    }

    #[tokio::test]
    async fn a_stale_placement_is_placed_once_more() {
        let tries = std::sync::atomic::AtomicUsize::new(0);
        let resp = placed_again("b", "k", || async {
            tries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            refused(&short(vec![OsdPoolError::StaleEpoch("5".into())]), 0)
        })
        .await;
        assert_eq!(tries.into_inner(), 2, "once more, not until it succeeds");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn copies_are_the_stripe_itself() {
        let coder = Coder::new(Scheme::Replicas(3)).unwrap();
        let shards = coder.shards(Bytes::from_static(b"abc")).unwrap();
        assert_eq!(shards, vec![Bytes::from_static(b"abc"); 3]);
        assert!(coder.codec().is_none());
        let lrc = Coder::new(Scheme::Lrc { k: 4, l: 2, g: 1 }).unwrap();
        assert_eq!(lrc.shards(Bytes::from(vec![7u8; 1001])).unwrap().len(), 7);
    }
}
