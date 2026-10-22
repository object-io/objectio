//! The body checked against the SHA-256 it was signed with.
//!
//! A SigV4 request signs its payload's hash in `x-amz-content-sha256`; the
//! signature only proves the body if the body is checked against that hash.
//! Without the check, a signed request captured in flight could be replayed
//! (inside the clock-skew window) with any other body.
//!
//! The body is hashed as it is read, so the check costs no extra pass over
//! it, and a mismatch turns the end of the body into an error: whatever was
//! reading it (an extractor, the chunked decoder) fails rather than sees a
//! complete body, so nothing built from it is stored. The response is then
//! S3's `XAmzContentSHA256Mismatch`.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use axum::{body::Body, http::Request, middleware::Next, response::Response};
use bytes::Bytes;
use http::StatusCode;
use http_body::{Frame, SizeHint};
use sha2::{Digest, Sha256};

/// The SHA-256 a request says its body has: `x-amz-content-sha256` when it
/// is a hex digest. `UNSIGNED-PAYLOAD` and the `STREAMING-*` values are not
/// (a streaming body is checked chunk by chunk, in `chunked_decode`).
pub(crate) fn declared_sha256(headers: &http::HeaderMap) -> Option<[u8; 32]> {
    let value = headers.get("x-amz-content-sha256")?.to_str().ok()?.trim();
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(value, &mut out).ok()?;
    Some(out)
}

/// S3's answer to a body that is not the one signed.
pub(crate) fn mismatch_response() -> Response {
    crate::s3::S3Error::xml_response(
        "XAmzContentSHA256Mismatch",
        "The provided 'x-amz-content-sha256' header does not match what was computed.",
        StatusCode::BAD_REQUEST,
    )
}

/// Run the rest of the request with its body checked against its declared
/// SHA-256, if it declares one.
pub(crate) async fn run_checked(request: Request<Body>, next: Next) -> Response {
    let Some(expected) = declared_sha256(request.headers()) else {
        return next.run(request).await;
    };
    let mismatched = Arc::new(AtomicBool::new(false));
    let request = request.map(|body| {
        Body::new(HashingBody {
            inner: body,
            hasher: Some(Sha256::new()),
            expected,
            mismatched: Arc::clone(&mismatched),
        })
    });
    let response = next.run(request).await;
    if mismatched.load(Ordering::Acquire) {
        return mismatch_response();
    }
    response
}

/// [`run_checked`] as a layer, for routes that no authentication layer
/// wraps (`--no-auth`): the hash is checked whether or not it was signed.
pub async fn payload_hash_layer(request: Request<Body>, next: Next) -> Response {
    run_checked(request, next).await
}

/// A body that hashes what passes through it and, at its end, fails instead
/// of ending when the hash is not the expected one.
struct HashingBody {
    inner: Body,
    /// `None` once the end has been checked.
    hasher: Option<Sha256>,
    expected: [u8; 32],
    mismatched: Arc<AtomicBool>,
}

#[derive(Debug)]
pub(crate) struct Mismatch;

impl std::fmt::Display for Mismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the body does not match x-amz-content-sha256")
    }
}

impl std::error::Error for Mismatch {}

impl HashingBody {
    /// Check the hash once the whole body has passed: `true` if it matched.
    fn finish(&mut self) -> bool {
        let Some(hasher) = self.hasher.take() else {
            return true;
        };
        let actual: [u8; 32] = hasher.finalize().into();
        let ok = actual == self.expected;
        if !ok {
            self.mismatched.store(true, Ordering::Release);
        }
        ok
    }
}

impl http_body::Body for HashingBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = &mut *self;
        if this.hasher.is_none() {
            return Pin::new(&mut this.inner).poll_frame(cx);
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(data), Some(hasher)) = (frame.data_ref(), this.hasher.as_mut()) {
                    hasher.update(data);
                }
                // Checked with the last frame, not after it: a reader that
                // stops at `is_end_stream` never polls again.
                if this.inner.is_end_stream() && !this.finish() {
                    return Poll::Ready(Some(Err(axum::Error::new(Mismatch))));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => {
                if this.finish() {
                    Poll::Ready(None)
                } else {
                    Poll::Ready(Some(Err(axum::Error::new(Mismatch))))
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        // Not before the hash is checked, or an empty body would never be.
        self.hasher.is_none() && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, middleware, routing::put};

    async fn store(body: Bytes) -> String {
        format!("stored {}", body.len())
    }

    fn app() -> Router {
        Router::new()
            .route("/", put(store))
            .layer(middleware::from_fn(payload_hash_layer))
    }

    async fn send(body: &'static [u8], sha: &str) -> (StatusCode, String) {
        let req = Request::builder()
            .method("PUT")
            .uri("/")
            .header("x-amz-content-sha256", sha)
            .body(Body::from(body))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app(), req).await.unwrap();
        let status = resp.status();
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        (status, String::from_utf8_lossy(&body).into_owned())
    }

    fn sha(data: &[u8]) -> String {
        hex::encode(Sha256::digest(data))
    }

    #[tokio::test]
    async fn the_body_signed_is_taken() {
        let (status, body) = send(b"hello", &sha(b"hello")).await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "stored 5"));
        let (status, _) = send(b"", &sha(b"")).await;
        assert_eq!(status, StatusCode::OK);
        // Uppercase hex is the same digest.
        let (status, _) = send(b"hello", &sha(b"hello").to_uppercase()).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn another_body_is_refused_before_the_handler_has_it() {
        let (status, body) = send(b"hellp", &sha(b"hello")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("XAmzContentSHA256Mismatch"), "{body}");
        // An empty body is checked too: a signed PUT replayed without its
        // body must not store an empty object.
        let (status, body) = send(b"", &sha(b"hello")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body.contains("XAmzContentSHA256Mismatch"), "{body}");
    }

    #[tokio::test]
    async fn an_unsigned_or_streaming_body_is_not_hashed() {
        for value in [
            "UNSIGNED-PAYLOAD",
            "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
            "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
        ] {
            let (status, _) = send(b"anything", value).await;
            assert_eq!(status, StatusCode::OK, "{value}");
        }
    }
}
