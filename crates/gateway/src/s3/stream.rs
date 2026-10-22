//! A large upload's body, streamed to the shards stripe by stripe.
//!
//! A PUT or an UploadPart over [`crate::admission::STREAM_ABOVE`] is never
//! held whole (they go up to 5 GiB). Its body is read a stripe at a time;
//! each stripe is hashed (the ETag's MD5, the checksum the client sent),
//! encrypted where it lies, erasure-coded and written at write quorum while
//! the next one is read, and at most [`IN_FLIGHT`] stripes are being
//! written at once. What the request holds of its body is reserved from
//! the memory budget up front: a stripe being read and those in flight.
//!
//! Nothing is committed until the whole body has arrived and every check
//! has passed: its signed payload hash or chunk signatures (the body ends
//! in an error otherwise, from the layer that checks them), its
//! `Content-MD5` and its flexible checksum. A body that fails, or a client
//! that goes away, leaves only shards no metadata names, and they are freed
//! at once (best effort, as every failed write's are); a gateway that dies
//! mid-upload leaves them until a scan finds what nothing references.

use super::*;
use crate::admission::Reservation;
use crate::checksum::{StreamedChecksums, StreamingChecksums};
use crate::s3::sse::StripeCipher;
use crate::stripe::{Coder, Scheme};
use bytes::BytesMut;
use http_body_util::BodyExt;
use std::collections::VecDeque;

/// Stripes being written at once while the next is read: the reader stays
/// ahead of the OSDs without holding more of the body than this.
pub(crate) const IN_FLIGHT: usize = 2;

/// The data bytes of one stripe of `scheme`: its shards each fit an OSD
/// block.
pub(crate) const fn stripe_size(scheme: Scheme) -> usize {
    MAX_SHARD_SIZE * scheme.data_shards()
}

/// What a streaming upload of `scheme` reserves from the memory budget:
/// the stripe being read and those being written, or the body's length,
/// when it is known and less.
pub(crate) fn window(scheme: Scheme, declared: Option<u64>) -> u64 {
    let stripes = ((IN_FLIGHT + 1) * stripe_size(scheme)) as u64;
    declared.map_or(stripes, |n| n.min(stripes))
}

/// A request body read a stripe at a time.
pub(crate) struct BodyReader {
    body: Body,
    /// What has been read and not yet taken.
    carry: VecDeque<Bytes>,
    /// The body's trailers (an `aws-chunked` body's checksum), once it has
    /// ended.
    pub(crate) trailers: Option<HeaderMap>,
    ended: bool,
}

impl BodyReader {
    pub(crate) fn new(body: Body) -> Self {
        Self {
            body,
            carry: VecDeque::new(),
            trailers: None,
            ended: false,
        }
    }

    /// Read the next frame into `carry`: false once the body has ended.
    /// Only its end proves the body: the checks of its payload hash and
    /// framing run then, and fail it rather than end it.
    async fn fill(&mut self) -> Result<bool, axum::Error> {
        while !self.ended {
            match self.body.frame().await {
                None => self.ended = true,
                Some(Err(e)) => {
                    self.ended = true;
                    return Err(e);
                }
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(data) if data.is_empty() => {}
                    Ok(data) => {
                        self.carry.push_back(data);
                        return Ok(true);
                    }
                    Err(frame) => {
                        if let Ok(t) = frame.into_trailers() {
                            self.trailers = Some(t);
                        }
                    }
                },
            }
        }
        Ok(false)
    }

    /// The next `size` bytes of the body, fewer at its end; none once it
    /// has ended (and passed its checks).
    pub(crate) async fn next(&mut self, size: usize) -> Result<Option<BytesMut>, axum::Error> {
        let mut buf = BytesMut::with_capacity(size);
        while buf.len() < size {
            let Some(front) = self.carry.front_mut() else {
                if self.fill().await? {
                    continue;
                }
                break;
            };
            let n = front.len().min(size - buf.len());
            buf.extend_from_slice(&front.split_to(n));
            if front.is_empty() {
                self.carry.pop_front();
            }
        }
        Ok((!buf.is_empty()).then_some(buf))
    }

    /// Whether the body has ended (and passed its checks), with nothing
    /// left to take.
    pub(crate) async fn at_end(&mut self) -> Result<bool, axum::Error> {
        Ok(self.carry.is_empty() && !self.fill().await?)
    }

    /// Put `data` back, to be taken first.
    pub(crate) fn unread(&mut self, data: Bytes) {
        if !data.is_empty() {
            self.carry.push_front(data);
        }
    }
}

/// A stripe on its way to the OSDs: its shards, and its own IV if its
/// cipher gives it one.
struct Encoded {
    shards: Vec<Bytes>,
    rdma_base: Option<u64>,
    iv: Vec<u8>,
    len: u64,
}

/// A stripe written (or not), with what it holds that goes back to the
/// upload: the shards it sent, its share of the reservation.
struct StripeDone {
    stripe: u64,
    written: Result<StripeMeta, Response>,
    sent: PendingShards,
    share: Reservation,
}

/// Where a streamed upload's stripes go and how they are made.
pub(crate) struct StreamTo<'a> {
    pub(crate) state: &'a Arc<AppState>,
    pub(crate) placement: &'a objectio_proto::metadata::GetPlacementResponse,
    pub(crate) object_id: [u8; 16],
    pub(crate) cipher: StripeCipher,
    /// Over Transfer Engine where it can (a PUT's MDS stripes), or gRPC.
    pub(crate) rdma: bool,
    /// The bucket and dedup domain each stripe is noted in, for a bucket
    /// whose dedup dry-run is on (and a body that is not encrypted).
    pub(crate) dedup: Option<(&'a str, &'a str)>,
    /// The object or part, for the log.
    pub(crate) what: String,
}

/// A body streamed to the shards, every check passed: not yet committed.
pub(crate) struct StreamedBody {
    pub(crate) stripes: Vec<StripeMeta>,
    pub(crate) size: u64,
    pub(crate) checksums: StreamedChecksums,
    /// Every shard sent, freed if the upload goes no further.
    pub(crate) sent: PendingShards,
}

fn internal(what: &str) -> Response {
    S3Error::xml_response("InternalError", what, StatusCode::INTERNAL_SERVER_ERROR)
}

/// Stream `reader`'s body to the shards of `to.placement`, stripe by
/// stripe, checked by `checks`, holding at most `window` of the memory
/// budget. The body's stripes are all on stable storage at write quorum
/// when this returns `Ok`; nothing is committed.
///
/// # Errors
/// The response for the client: the body failed (cut off, too large, not
/// what was signed or framed), a checksum did not match, or a stripe fell
/// short of its write quorum. The shards already sent are freed.
pub(crate) async fn stream_stripes(
    to: StreamTo<'_>,
    reader: &mut BodyReader,
    mut checks: StreamingChecksums,
    mut window: Reservation,
) -> Result<StreamedBody, Response> {
    let placement = Arc::new(to.placement.clone());
    let scheme = Scheme::of(&placement);
    let size = stripe_size(scheme);
    let coder = Arc::new(Coder::new(scheme).map_err(|e| {
        error!("Failed to create erasure codec: {e}");
        internal(&format!("Erasure coding error: {e}"))
    })?);
    let rdma = to
        .state
        .rdma
        .clone()
        .filter(|_| to.rdma && matches!(scheme, Scheme::Mds { .. }));
    let mut sent = pending_shards(to.state, to.what.clone());
    let mut in_flight: VecDeque<tokio::task::JoinHandle<StripeDone>> = VecDeque::new();
    let mut stripes: Vec<StripeMeta> = Vec::new();
    let mut offset = 0u64;
    let mut stripe = 0u64;

    // A stripe written: what it sent and its share of the budget come
    // back whatever happened to it.
    #[allow(clippy::result_large_err)] // the client's answer, as every handler returns
    let mut settle = |done: Result<StripeDone, tokio::task::JoinError>,
                      sent: &mut PendingShards,
                      window: &mut Reservation|
     -> Result<(), Response> {
        let done = done.map_err(|e| {
            error!("{}: a stripe write failed: {e}", to.what);
            internal("A stripe write failed")
        })?;
        sent.absorb(done.sent);
        window.merge(done.share);
        let meta = done.written?;
        debug_assert_eq!(meta.stripe_id, done.stripe);
        stripes.push(meta);
        Ok(())
    };

    loop {
        let share = window.split(size as u64);
        let data = match reader.next(size).await {
            Ok(Some(d)) => d,
            Ok(None) => break,
            Err(e) => return Err(crate::admission::body_refused(&e)),
        };
        // Hashed, encrypted where it lies, and coded off the async workers.
        let job = {
            let (coder, rdma, cipher) = (Arc::clone(&coder), rdma.clone(), to.cipher);
            let dedup = to.dedup.is_some() && !cipher.encrypts();
            move || {
                let mut data = data;
                checks.update(&data);
                let iv = cipher.apply(offset, &mut data);
                let len = data.len() as u64;
                let data = data.freeze();
                let plaintext = dedup.then(|| data.clone());
                let encoded = crate::stripe::encode(&coder, rdma.as_deref(), data);
                (
                    checks,
                    encoded.map(|(shards, rdma_base)| Encoded {
                        shards,
                        rdma_base,
                        iv,
                        len,
                    }),
                    plaintext,
                )
            }
        };
        let (returned, encoded, plaintext) =
            tokio::task::spawn_blocking(job).await.map_err(|e| {
                error!("{}: stripe {stripe} could not be coded: {e}", to.what);
                internal("Erasure encoding failed")
            })?;
        checks = returned;
        let encoded = encoded.map_err(|e| {
            error!("Failed to encode stripe {stripe}: {e}");
            internal(&format!("Erasure encoding failed for stripe {stripe}: {e}"))
        })?;
        if let (Some((bucket, domain)), Some(p)) = (to.dedup, plaintext) {
            to.state.dedup.submit(bucket, domain, p);
        }
        while in_flight.len() >= IN_FLIGHT {
            let Some(oldest) = in_flight.pop_front() else {
                break;
            };
            settle(oldest.await, &mut sent, &mut window)?;
        }
        offset += encoded.len;
        in_flight.push_back(tokio::spawn(write_stripe(
            Arc::clone(to.state),
            Arc::clone(&placement),
            rdma.clone(),
            (to.object_id, stripe),
            encoded,
            share,
            to.what.clone(),
        )));
        stripe += 1;
    }
    while let Some(next) = in_flight.pop_front() {
        settle(next.await, &mut sent, &mut window)?;
    }
    let checksums = checks
        .finish(reader.trailers.as_ref())
        .map_err(|e| S3Error::xml_response(e.code(), &e.message(), StatusCode::BAD_REQUEST))?;
    Ok(StreamedBody {
        stripes,
        size: offset,
        checksums,
        sent,
    })
}

/// Write one stripe at write quorum, on a task of its own so that it goes
/// on while the next is read.
async fn write_stripe(
    state: Arc<AppState>,
    placement: Arc<objectio_proto::metadata::GetPlacementResponse>,
    rdma: Option<Arc<crate::rdma::GatewayRdma>>,
    (object_id, stripe): ([u8; 16], u64),
    encoded: Encoded,
    share: Reservation,
    what: String,
) -> StripeDone {
    let placed = crate::stripe::Placed::new(&placement);
    // Recorded on its own, handed to the upload when done: a task whose
    // upload has gone frees what it sent itself.
    let mut sent = pending_shards(&state, what.clone());
    let written = crate::stripe::write_stripe(
        &state.osd_pool,
        &placed,
        &object_id,
        stripe,
        encoded.shards,
        rdma.as_deref().map(|rdma| crate::stripe::RdmaStripe {
            rdma,
            base: encoded.rdma_base,
        }),
        Some(&mut sent),
    )
    .await
    .map(|locs| StripeMeta {
        encryption_iv: encoded.iv,
        ..placed
            .scheme
            .stripe(stripe, encoded.len, object_id.to_vec(), locs)
    })
    .map_err(|short| {
        error!("{what}: stripe {stripe}: {short}");
        crate::stripe::refused(&short, stripe)
    });
    StripeDone {
        stripe,
        written,
        sent,
        share,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body_of(frames: Vec<&'static [u8]>) -> Body {
        Body::from_stream(futures::stream::iter(
            frames
                .into_iter()
                .map(|f| Ok::<_, std::io::Error>(Bytes::from_static(f))),
        ))
    }

    /// Stripes are cut at their size whatever the frames the body came in.
    #[tokio::test]
    async fn a_body_is_read_in_stripes_across_its_frames() {
        let mut r = BodyReader::new(body_of(vec![b"abc", b"", b"defgh", b"ij"]));
        assert_eq!(&r.next(4).await.unwrap().unwrap()[..], b"abcd");
        assert!(!r.at_end().await.unwrap());
        assert_eq!(&r.next(4).await.unwrap().unwrap()[..], b"efgh");
        r.unread(Bytes::from_static(b"XY"));
        assert_eq!(&r.next(4).await.unwrap().unwrap()[..], b"XYij");
        assert!(r.at_end().await.unwrap());
        assert!(r.next(4).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_body_that_fails_fails_its_reader() {
        let frames = futures::stream::iter(vec![
            Ok(Bytes::from_static(b"abcd")),
            Err(std::io::Error::other("cut")),
        ]);
        let mut r = BodyReader::new(Body::from_stream(frames));
        assert_eq!(&r.next(4).await.unwrap().unwrap()[..], b"abcd");
        assert!(r.next(4).await.is_err());
    }

    #[test]
    fn the_window_is_the_stripes_in_hand_or_the_body() {
        let scheme = Scheme::Mds { k: 4, m: 2 };
        let stripes = ((IN_FLIGHT + 1) * stripe_size(scheme)) as u64;
        assert_eq!(window(scheme, None), stripes);
        assert_eq!(window(scheme, Some(5 << 30)), stripes);
        assert_eq!(window(scheme, Some(20 << 20)), 20 << 20);
    }
}
