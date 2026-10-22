//! S3 chunked transfer encoding decoder middleware
//!
//! When S3 clients send requests with `Content-Encoding: aws-chunked`, the body
//! uses a custom chunked format that includes per-chunk signatures and optional
//! trailing checksums. This middleware decodes that format so handlers receive
//! the raw payload bytes.
//!
//! Chunked format:
//! ```text
//! <hex-size>;chunk-signature=<sig>\r\n
//! <data>\r\n
//! 0;chunk-signature=<sig>\r\n
//! x-amz-checksum-crc32:<base64>\r\n
//! \r\n
//! ```
//!
//! With `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` the request's signature covers
//! no body at all: each chunk carries its own signature, chained from the
//! request's, and that chain is what proves the body. It is checked here,
//! chunk by chunk, with the signing key the auth layer derived; `-TRAILER`
//! adds a signature over the trailing headers. A body whose chain breaks is
//! refused before the handler sees any of it.

use axum::{
    body::Body,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::Bytes;
use tracing::{debug, warn};

use crate::auth_middleware::{
    AuthError, ChunkSigningSeed, STREAMING_SIGNED, calculate_signature_v4, constant_time_eq,
    hex_sha256,
};

/// The SHA-256 of nothing, which the chunk string-to-sign carries where a
/// request's would carry its headers.
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The trailer that signs the other trailers.
const TRAILER_SIGNATURE: &str = "x-amz-trailer-signature";

/// A framed body this large is decoded off the async workers: decoding a
/// signed one hashes every byte.
const DECODE_INLINE_BYTES: usize = 256 * 1024;

/// Whether the request says its body is in AWS-chunked framing: a
/// streaming payload hash (`STREAMING-*`), or `aws-chunked` together with
/// the decoded length an SDK sends with it. `aws-chunked` in
/// Content-Encoding alone is weaker: clients name it over plain bodies too,
/// so such a body is decoded only if it parses as complete framing.
fn is_s3_chunked(request: &Request<Body>) -> bool {
    let headers = request.headers();
    let streaming = headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("STREAMING-"));
    streaming
        || (names_aws_chunked(headers) && headers.contains_key("x-amz-decoded-content-length"))
}

fn names_aws_chunked(headers: &http::HeaderMap) -> bool {
    headers
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|c| c.trim().eq_ignore_ascii_case("aws-chunked"))
        })
}

/// Content-Encoding with `aws-chunked` taken out (and removed if that was
/// all), so the object keeps only its own codings.
fn strip_aws_chunked(headers: &mut http::HeaderMap) {
    let remaining = headers
        .get("content-encoding")
        .map(|v| without_aws_chunked(&crate::auth_middleware::header_text(v)));
    match remaining.and_then(|r| http::HeaderValue::from_str(&r).ok()) {
        Some(v) if !v.is_empty() => {
            headers.insert("content-encoding", v);
        }
        _ => {
            headers.remove("content-encoding");
        }
    }
}

/// An AWS-chunked body, decoded.
#[derive(Debug, Default, PartialEq, Eq)]
struct Decoded {
    payload: Vec<u8>,
    /// Trailing headers after the terminal chunk, `(name, value)` with the
    /// name lowercased. This is where an SDK puts `x-amz-checksum-*` when it
    /// streams the body.
    trailers: Vec<(String, String)>,
}

/// Why a framed body was refused.
#[derive(Debug, PartialEq, Eq)]
enum DecodeError {
    /// The framing is broken: cut short, a wrong size, no CRLF.
    Malformed(String),
    /// A chunk or the trailers are not signed as the chain says.
    BadSignature(String),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) | Self::BadSignature(m) => f.write_str(m),
        }
    }
}

fn malformed(message: impl Into<String>) -> DecodeError {
    DecodeError::Malformed(message.into())
}

/// The chain of chunk signatures: each chunk's signature signs its data
/// and the signature before it, the first the request's own.
struct ChunkVerifier {
    seed: ChunkSigningSeed,
    previous: String,
    /// `-TRAILER`: the trailing headers are signed too.
    trailer: bool,
}

impl ChunkVerifier {
    fn new(seed: ChunkSigningSeed, trailer: bool) -> Self {
        let previous = seed.signature.clone();
        Self {
            seed,
            previous,
            trailer,
        }
    }

    /// Check one chunk's signature and move the chain on to it.
    fn chunk(&mut self, data: &[u8], provided: Option<&str>) -> Result<(), DecodeError> {
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{EMPTY_SHA256}\n{}",
            self.seed.date,
            self.seed.scope,
            self.previous,
            hex_sha256(data)
        );
        self.advance(&string_to_sign, provided, "chunk")
    }

    /// Check the trailing headers' signature. It signs each trailer line
    /// as sent (SDKs send `name:value`), ended by `\n`, the signature's own
    /// line left out.
    fn trailers(&mut self, raw: &[u8], provided: Option<&str>) -> Result<(), DecodeError> {
        let canonical = signed_trailer_text(raw);
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{}\n{}",
            self.seed.date,
            self.seed.scope,
            self.previous,
            hex_sha256(canonical.as_bytes())
        );
        self.advance(&string_to_sign, provided, "trailer")
    }

    fn advance(
        &mut self,
        string_to_sign: &str,
        provided: Option<&str>,
        what: &str,
    ) -> Result<(), DecodeError> {
        let provided = provided
            .ok_or_else(|| DecodeError::BadSignature(format!("a {what} has no signature")))?;
        let expected = calculate_signature_v4(&self.seed.signing_key, string_to_sign);
        if !constant_time_eq(&expected, provided) {
            return Err(DecodeError::BadSignature(format!(
                "a {what} signature does not match"
            )));
        }
        self.previous = expected;
        Ok(())
    }
}

/// The trailer section's lines, without their line ends. SDKs end them
/// differently (the Java SDK `\r\n`, minio-go `\n` and then a blank
/// `\r\n` before the signature), so any of `\r\n` and `\n` ends a line and
/// blank lines are skipped: the section runs to the end of the body.
fn trailer_lines(raw: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(raw)
        .split('\n')
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// What the trailer signature signs: each trailer line as sent, ended by
/// `\n`, without the signature's own line.
fn signed_trailer_text(raw: &[u8]) -> String {
    trailer_lines(raw)
        .iter()
        .filter(|line| {
            !line
                .split_once(':')
                .is_some_and(|(name, _)| name.trim().eq_ignore_ascii_case(TRAILER_SIGNATURE))
        })
        .map(|line| format!("{line}\n"))
        .collect()
}

/// The `chunk-signature` extension of a chunk-size line's extensions
/// (`;chunk-signature=<hex>`).
fn chunk_signature(extensions: &str) -> Option<&str> {
    extensions.split(';').find_map(|ext| {
        let (name, value) = ext.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("chunk-signature")
            .then(|| value.trim())
    })
}

/// Decode an AWS-chunked body into raw payload bytes and its trailers.
#[cfg(test)]
fn decode_s3_chunked(
    raw: &[u8],
    verifier: Option<&mut ChunkVerifier>,
) -> Result<Decoded, DecodeError> {
    decode_in_place(raw.to_vec(), verifier)
}

/// Decode the AWS-chunked body in `raw` where it is: each chunk's data is
/// moved down over the framing before it, and the buffer cut to the
/// payload, so a body of any size is decoded without a second copy of it.
///
/// Parses the `<hex-size>[;extensions]\r\n<data>\r\n` framing. With a
/// verifier, every chunk's signature is checked (before its data is
/// moved), and the trailers' when the verifier says they are signed;
/// without one, chunk signatures are not read.
fn decode_in_place(
    mut raw: Vec<u8>,
    mut verifier: Option<&mut ChunkVerifier>,
) -> Result<Decoded, DecodeError> {
    // Where the payload decoded so far ends; never past `pos`, since every
    // chunk's data follows a size line of at least three bytes.
    let mut written = 0;
    let mut pos = 0;

    loop {
        // A body that stops before the terminal chunk is a cut-off upload,
        // not a short object.
        if pos >= raw.len() {
            return Err(malformed("body ended before the terminal chunk"));
        }

        // Find the end of the chunk-size line (\r\n)
        let line_end = find_crlf(&raw, pos)
            .ok_or_else(|| malformed(format!("missing CRLF after chunk size at offset {pos}")))?;

        let line = &raw[pos..line_end];
        // The chunk size line may contain extensions after a semicolon
        // e.g. "ab;chunk-signature=..."
        let size_str = std::str::from_utf8(line)
            .map_err(|e| malformed(format!("invalid UTF-8 in chunk header: {e}")))?;
        let (hex_part, extensions) = size_str.split_once(';').unwrap_or((size_str, ""));
        let hex_part = hex_part.trim();

        let chunk_size = usize::from_str_radix(hex_part, 16)
            .map_err(|e| malformed(format!("invalid hex chunk size '{hex_part}': {e}")))?;
        let signature = chunk_signature(extensions);

        // Move past the size line + \r\n
        pos = line_end + 2;

        if chunk_size == 0 {
            // Terminal chunk — remaining bytes are trailing headers, one
            // `name:value` per line, ended by an empty line.
            let trailer_bytes = &raw[pos.min(raw.len())..];
            let trailers = parse_trailers(trailer_bytes);
            if let Some(v) = verifier.as_deref_mut() {
                v.chunk(&[], signature)?;
                if v.trailer {
                    let provided = trailers
                        .iter()
                        .find(|(name, _)| name == TRAILER_SIGNATURE)
                        .map(|(_, value)| value.as_str());
                    v.trailers(trailer_bytes, provided)?;
                }
            }
            raw.truncate(written);
            return Ok(Decoded {
                payload: raw,
                trailers,
            });
        }

        // Read chunk_size bytes of data
        let Some(chunk_end) = pos.checked_add(chunk_size).filter(|&e| e <= raw.len()) else {
            return Err(malformed(format!(
                "chunk data truncated: need {} bytes at offset {}, have {}",
                chunk_size,
                pos,
                raw.len() - pos
            )));
        };
        if let Some(v) = verifier.as_deref_mut() {
            v.chunk(&raw[pos..chunk_end], signature)?;
        }
        raw.copy_within(pos..chunk_end, written);
        written += chunk_size;
        pos = chunk_end;

        // The chunk's data is followed by CRLF; anything else means the
        // declared size was wrong.
        if raw.get(pos..pos + 2) != Some(b"\r\n".as_slice()) {
            return Err(malformed(format!(
                "missing CRLF after chunk data at offset {pos}"
            )));
        }
        pos += 2;
    }
}

/// Trailing headers after the terminal chunk. Lines that are not
/// `name:value` are skipped rather than failing the request: the payload is
/// already complete, and a checksum that cannot be read is not checked.
fn parse_trailers(raw: &[u8]) -> Vec<(String, String)> {
    trailer_lines(raw)
        .iter()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
        })
        .collect()
}

/// Find the position of the next \r\n starting from `start`.
fn find_crlf(data: &[u8], start: usize) -> Option<usize> {
    data.windows(2)
        .enumerate()
        .skip(start)
        .find(|(_, w)| w == b"\r\n")
        .map(|(i, _)| i)
}

/// `Content-Encoding` with the `aws-chunked` coding taken out.
fn without_aws_chunked(value: &str) -> String {
    value
        .split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty() && !c.eq_ignore_ascii_case("aws-chunked"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn incomplete_body(message: &str) -> Response {
    crate::s3::S3Error::xml_response("IncompleteBody", message, http::StatusCode::BAD_REQUEST)
}

/// The trailers the request names in `x-amz-trailer` that the body does not
/// carry. A checksum sent as a trailer is checked only if it arrives, so
/// one that was announced and left off is refused, not skipped.
fn missing_trailers(headers: &http::HeaderMap, trailers: &[(String, String)]) -> Vec<String> {
    headers
        .get_all("x-amz-trailer")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty() && !trailers.iter().any(|(n, _)| n == name))
        .collect()
}

/// Middleware that decodes S3 chunked transfer encoding before handlers see the body.
pub async fn s3_chunked_decode_layer(request: Request<Body>, next: Next) -> Response {
    let signalled = is_s3_chunked(&request);
    if !signalled && !names_aws_chunked(request.headers()) {
        return next.run(request).await;
    }

    let (mut parts, body) = request.into_parts();

    if parts
        .headers
        .get("x-amz-decoded-content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .is_some_and(|n| n > crate::admission::MAX_BODY as u64)
    {
        return crate::admission::entity_too_large();
    }

    // Read the full body, no more of it than a handler could take with its
    // framing (the admission layer has already read it, into one buffer
    // this takes without a copy). A body that can't be read, or decoded,
    // fails the request: handing the handler an empty or still-framed body
    // would store the wrong bytes under the key.
    let raw =
        match crate::admission::body_into_vec(body, 0, crate::admission::wire_limit(true), None)
            .await
        {
            Ok(raw) => raw,
            Err(crate::admission::BodyError::TooLarge) => {
                return crate::admission::entity_too_large();
            }
            Err(e) => {
                warn!("Failed to read s3-chunked body: {e:?}");
                return incomplete_body("The request body could not be read in full");
            }
        };
    let raw_len = raw.len();

    debug!("Decoding s3-chunked body ({raw_len} raw bytes)");

    // Signed chunks are checked against the chain the auth layer seeded. A
    // request it did not seed was not signed (anonymous, `--no-auth`), and
    // its chunk signatures prove nothing.
    let payload_hash = parts
        .headers
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .unwrap_or_default();
    let signed_chunks = payload_hash.starts_with(STREAMING_SIGNED);
    let signed_trailer = signed_chunks && payload_hash.ends_with("-TRAILER");
    let verifier = parts
        .extensions
        .remove::<ChunkSigningSeed>()
        .filter(|_| signed_chunks)
        .map(|seed| ChunkVerifier::new(seed, signed_trailer));

    // Decoded where it lies when the request says it is framed (a failure
    // refuses it); otherwise a copy, since a body that doesn't parse is
    // stored as sent.
    let (raw, as_sent) = if signalled {
        (raw, None)
    } else {
        (raw.clone(), Some(raw))
    };
    let decode = move |raw: Vec<u8>| {
        let mut verifier = verifier;
        decode_in_place(raw, verifier.as_mut())
    };
    let result = if raw_len <= DECODE_INLINE_BYTES {
        decode(raw)
    } else {
        match tokio::task::spawn_blocking(move || decode(raw)).await {
            Ok(r) => r,
            Err(e) => {
                warn!("s3-chunked decode task failed: {e}");
                return crate::s3::S3Error::xml_response(
                    "InternalError",
                    "We encountered an internal error. Please try again.",
                    http::StatusCode::INTERNAL_SERVER_ERROR,
                );
            }
        }
    };

    let decoded = match result {
        Ok(Decoded { payload, trailers }) => {
            debug!("Decoded s3-chunked: {raw_len} -> {} bytes", payload.len());
            let missing = missing_trailers(&parts.headers, &trailers);
            if !missing.is_empty() {
                return crate::s3::S3Error::xml_response(
                    "MalformedTrailerError",
                    &format!(
                        "The request names trailing headers it does not carry: {}",
                        missing.join(", ")
                    ),
                    http::StatusCode::BAD_REQUEST,
                );
            }
            // A checksum sent as a trailer becomes a header, so the handler
            // checks it the same way as one sent up front. Only checksums:
            // other trailers (the trailer signature) are not request headers.
            // When the chunks are signed and the trailers are not, the
            // trailers are not the client's and are left out.
            let trailers_trusted = !signed_chunks || signed_trailer;
            for (name, value) in trailers {
                if !trailers_trusted || !name.starts_with("x-amz-checksum-") {
                    continue;
                }
                if let (Ok(name), Ok(value)) = (
                    http::HeaderName::from_bytes(name.as_bytes()),
                    http::HeaderValue::from_str(&value),
                ) {
                    parts.headers.insert(name, value);
                }
            }
            payload
        }
        Err(DecodeError::BadSignature(e)) => {
            debug!("s3-chunked body refused: {e}");
            return AuthError::SignatureDoesNotMatch.into_response();
        }
        // Framing the request says it has (a streaming hash, a decoded
        // length), broken: refused.
        Err(e) if signalled => {
            warn!("Failed to decode s3-chunked body: {}", e);
            return incomplete_body(&format!("Malformed aws-chunked body: {e}"));
        }
        // Only named in Content-Encoding, and not complete framing: a
        // plain body, stored as sent. (A body that does parse as complete
        // framing, terminal chunk and all, is framed.)
        Err(_) => {
            strip_aws_chunked(&mut parts.headers);
            let raw = as_sent.unwrap_or_default();
            return next.run(Request::from_parts(parts, Body::from(raw))).await;
        }
    };

    if decoded.len() > crate::admission::MAX_BODY {
        return crate::admission::entity_too_large();
    }
    if let Some(expected) = parts
        .headers
        .get("x-amz-decoded-content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<usize>().ok())
        && expected != decoded.len()
    {
        return incomplete_body(&format!(
            "x-amz-decoded-content-length is {expected}, the body decoded to {} bytes",
            decoded.len()
        ));
    }

    // Update Content-Length to the decoded size. `aws-chunked` is only the
    // transfer framing: any other coding (`gzip, aws-chunked`) belongs to
    // the object and is kept.
    parts.headers.insert("content-length", decoded.len().into());
    strip_aws_chunked(&mut parts.headers);
    // The body is decoded (and its chunks checked): downstream sees a plain
    // body, whose hash was not signed.
    if payload_hash.starts_with("STREAMING-") {
        parts.headers.insert(
            "x-amz-content-sha256",
            http::HeaderValue::from_static("UNSIGNED-PAYLOAD"),
        );
    }

    let rebuilt = Request::from_parts(parts, Body::from(Bytes::from(decoded)));
    next.run(rebuilt).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    #[test]
    fn a_body_without_its_terminal_chunk_is_refused() {
        assert!(decode_s3_chunked(b"5;chunk-signature=aaa\r\nhello\r\n", None).is_err());
        assert!(decode_s3_chunked(b"", None).is_err());
        // Declared longer than sent.
        assert!(decode_s3_chunked(b"9\r\nhello\r\n0\r\n\r\n", None).is_err());
        // Declared shorter than sent.
        assert!(decode_s3_chunked(b"3\r\nhello\r\n0\r\n\r\n", None).is_err());
    }

    #[test]
    fn only_the_aws_chunked_coding_is_dropped() {
        assert_eq!(without_aws_chunked("gzip, aws-chunked"), "gzip");
        assert_eq!(without_aws_chunked("aws-chunked"), "");
        assert_eq!(without_aws_chunked("aws-chunked,br"), "br");
    }

    #[test]
    fn test_decode_simple_s3_chunked() {
        // Single chunk: "ab" (hex) = 171 bytes, then terminal 0
        let body = b"b;chunk-signature=abc123\r\nhello world\r\n0;chunk-signature=def456\r\n\r\n";
        let decoded = decode_s3_chunked(body, None).unwrap().payload;
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn test_decode_multiple_chunks() {
        let body = b"5;chunk-signature=aaa\r\nhello\r\n6;chunk-signature=bbb\r\n world\r\n0;chunk-signature=ccc\r\n\r\n";
        let decoded = decode_s3_chunked(body, None).unwrap().payload;
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn test_decode_with_trailing_checksum() {
        let body = b"5;chunk-signature=aaa\r\nhello\r\n0;chunk-signature=bbb\r\nx-amz-checksum-crc32:1b4gJg==\r\n\r\n";
        let decoded = decode_s3_chunked(body, None).unwrap();
        assert_eq!(decoded.payload, b"hello");
        assert_eq!(
            decoded.trailers,
            vec![("x-amz-checksum-crc32".to_string(), "1b4gJg==".to_string())]
        );
    }

    #[test]
    fn test_decode_trailers_with_signature_and_mixed_case() {
        let body = b"5\r\nhello\r\n0\r\nX-Amz-Checksum-CRC32C: yZRlqg==\r\nx-amz-trailer-signature:abc\r\n\r\n";
        let decoded = decode_s3_chunked(body, None).unwrap();
        assert_eq!(
            decoded.trailers,
            vec![
                ("x-amz-checksum-crc32c".to_string(), "yZRlqg==".to_string()),
                ("x-amz-trailer-signature".to_string(), "abc".to_string()),
            ]
        );
    }

    /// The middleware turns a checksum trailer into a request header, and
    /// leaves other trailers out.
    #[tokio::test]
    async fn trailer_checksum_reaches_the_handler_as_a_header() {
        use axum::{Router, middleware, routing::put};

        async fn echo(headers: http::HeaderMap, body: Bytes) -> String {
            format!(
                "{}|{}|{}",
                headers
                    .get("x-amz-checksum-crc32c")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("-"),
                headers.contains_key("x-amz-trailer-signature"),
                String::from_utf8_lossy(&body)
            )
        }
        let app = Router::new()
            .route("/", put(echo))
            .layer(middleware::from_fn(s3_chunked_decode_layer));
        let req = Request::builder()
            .method("PUT")
            .uri("/")
            .header("content-encoding", "aws-chunked")
            .body(Body::from(
                &b"5\r\nhello\r\n0\r\nx-amz-checksum-crc32c:yZRlqg==\r\nx-amz-trailer-signature:abc\r\n\r\n"[..],
            ))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"yZRlqg==|false|hello");
    }

    #[test]
    fn test_decode_no_extensions() {
        // Some clients send without chunk-signature
        let body = b"5\r\nhello\r\n0\r\n\r\n";
        let decoded = decode_s3_chunked(body, None).unwrap();
        assert_eq!(decoded.payload, b"hello");
        assert!(decoded.trailers.is_empty());
    }

    // The streaming PUT worked through in AWS's SigV4 documentation
    // ("Signature calculations for the Authorization header: Transferring
    // payload in multiple chunks"): 66560 bytes of 'a' in 64 KiB chunks,
    // PUT to examplebucket/chunkObject.txt on 2013-05-24.
    const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    const AWS_DATE: &str = "20130524T000000Z";
    const AWS_SCOPE: &str = "20130524/us-east-1/s3/aws4_request";
    const AWS_SEED: &str = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
    const AWS_CHUNK_SIGS: [&str; 3] = [
        "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648",
        "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497",
        "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9",
    ];

    fn aws_seed() -> ChunkSigningSeed {
        ChunkSigningSeed {
            signing_key: crate::auth_middleware::derive_signing_key(
                AWS_SECRET,
                "20130524",
                "us-east-1",
                "s3",
            ),
            date: AWS_DATE.to_string(),
            scope: AWS_SCOPE.to_string(),
            signature: AWS_SEED.to_string(),
        }
    }

    /// `data` framed in `chunk`-byte chunks, each with the signature
    /// `sigs` gives it, then the terminal chunk and `trailer`.
    fn framed(data: &[u8], chunk: usize, sigs: &[String], trailer: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut sigs = sigs.iter();
        for c in data.chunks(chunk) {
            let sig = sigs.next().expect("a signature per chunk");
            out.extend_from_slice(format!("{:x};chunk-signature={sig}\r\n", c.len()).as_bytes());
            out.extend_from_slice(c);
            out.extend_from_slice(b"\r\n");
        }
        let last = sigs.next().expect("a signature for the terminal chunk");
        out.extend_from_slice(format!("0;chunk-signature={last}\r\n{trailer}\r\n").as_bytes());
        out
    }

    fn aws_body() -> (Vec<u8>, Vec<u8>) {
        let data = vec![b'a'; 66_560];
        let sigs: Vec<String> = AWS_CHUNK_SIGS.iter().map(|s| (*s).to_string()).collect();
        let body = framed(&data, 65_536, &sigs, "");
        (data, body)
    }

    /// An independent signer for the tests: what a client computes.
    fn client_sign(key: &[u8], string_to_sign: &str) -> String {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
        mac.update(string_to_sign.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    fn client_chain(seed: &ChunkSigningSeed, data: &[u8], chunk: usize) -> Vec<String> {
        use sha2::Digest;
        let mut prev = seed.signature.clone();
        let mut out = Vec::new();
        let mut chunks: Vec<&[u8]> = data.chunks(chunk).collect();
        chunks.push(&[]);
        for c in chunks {
            let sts = format!(
                "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{prev}\n{EMPTY_SHA256}\n{}",
                seed.date,
                seed.scope,
                hex::encode(sha2::Sha256::digest(c))
            );
            prev = client_sign(&seed.signing_key, &sts);
            out.push(prev.clone());
        }
        out
    }

    fn client_trailer_sig(seed: &ChunkSigningSeed, prev: &str, trailer_text: &str) -> String {
        use sha2::Digest;
        let sts = format!(
            "AWS4-HMAC-SHA256-TRAILER\n{}\n{}\n{prev}\n{}",
            seed.date,
            seed.scope,
            hex::encode(sha2::Sha256::digest(trailer_text.as_bytes()))
        );
        client_sign(&seed.signing_key, &sts)
    }

    #[test]
    fn awss_published_streaming_example_verifies() {
        let (data, body) = aws_body();
        // The example's Content-Length, so the framing is the example's.
        assert_eq!(body.len(), 66_824);
        let mut v = ChunkVerifier::new(aws_seed(), false);
        let decoded = decode_s3_chunked(&body, Some(&mut v)).unwrap();
        assert_eq!(decoded.payload, data);
        // And an independent client computes the same chain.
        assert_eq!(client_chain(&aws_seed(), &data, 65_536), AWS_CHUNK_SIGS);
    }

    #[test]
    fn a_tampered_chunk_breaks_the_chain() {
        let (_, body) = aws_body();
        // One byte of the second chunk's data changed.
        let mut tampered = body.clone();
        let at = tampered.len() - 120;
        assert_eq!(tampered[at], b'a');
        tampered[at] = b'b';
        let mut v = ChunkVerifier::new(aws_seed(), false);
        assert!(matches!(
            decode_s3_chunked(&tampered, Some(&mut v)),
            Err(DecodeError::BadSignature(_))
        ));

        // A different seed: the chain is another request's.
        let mut seed = aws_seed();
        seed.signature = "0".repeat(64);
        let mut v = ChunkVerifier::new(seed, false);
        assert!(matches!(
            decode_s3_chunked(&body, Some(&mut v)),
            Err(DecodeError::BadSignature(_))
        ));

        // A chunk dropped, the rest of the chain kept.
        let data = vec![b'a'; 66_560];
        let sigs: Vec<String> = AWS_CHUNK_SIGS[1..]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let short = framed(&data[65_536..], 65_536, &sigs, "");
        let mut v = ChunkVerifier::new(aws_seed(), false);
        assert!(matches!(
            decode_s3_chunked(&short, Some(&mut v)),
            Err(DecodeError::BadSignature(_))
        ));

        // A chunk without a signature.
        let unsigned = b"5\r\nhello\r\n0\r\n\r\n";
        let mut v = ChunkVerifier::new(aws_seed(), false);
        assert!(matches!(
            decode_s3_chunked(unsigned, Some(&mut v)),
            Err(DecodeError::BadSignature(_))
        ));
    }

    /// The trailer example of AWS's documentation ("SigV4 streaming with
    /// trailers"): the trailer signature signs `x-amz-checksum-crc32c:wdBDMA==\n`,
    /// whose SHA-256 the documented string-to-sign ends with.
    #[test]
    fn the_trailer_text_signed_is_awss() {
        let raw = b"x-amz-checksum-crc32c:wdBDMA==\r\nx-amz-trailer-signature:abc\r\n\r\n";
        let text = signed_trailer_text(raw);
        assert_eq!(text, "x-amz-checksum-crc32c:wdBDMA==\n");
        assert_eq!(
            hex_sha256(text.as_bytes()),
            "2e4ab969aa65b1ad6def2db10e4d3a8260683d194dbaf757f90e8a37960a4b3c"
        );
    }

    #[test]
    fn signed_trailers_are_checked() {
        let seed = aws_seed();
        let data = b"hello world".repeat(1000);
        let sigs = client_chain(&seed, &data, 8192);
        let trailer = "x-amz-checksum-crc32c:sOO8/Q==";
        let tsig = client_trailer_sig(&seed, sigs.last().unwrap(), &format!("{trailer}\n"));
        let good = framed(
            &data,
            8192,
            &sigs,
            &format!("{trailer}\r\nx-amz-trailer-signature:{tsig}\r\n"),
        );
        let mut v = ChunkVerifier::new(seed.clone(), true);
        let decoded = decode_s3_chunked(&good, Some(&mut v)).unwrap();
        assert_eq!(decoded.payload, data);
        assert_eq!(decoded.trailers[0].1, "sOO8/Q==");

        // As minio-go frames it: the trailer line ended by `\n`, then a
        // blank `\r\n` before the signature.
        let minio_go = framed(
            &data,
            8192,
            &sigs,
            &format!("{trailer}\n\r\nx-amz-trailer-signature:{tsig}\r\n"),
        );
        let mut v = ChunkVerifier::new(seed.clone(), true);
        let decoded = decode_s3_chunked(&minio_go, Some(&mut v)).unwrap();
        assert_eq!(decoded.trailers[0].1, "sOO8/Q==");

        // Two trailers, signed in the order sent.
        let two = "x-amz-checksum-crc32c:sOO8/Q==\nx-amz-meta-x:1\n";
        let tsig2 = client_trailer_sig(&seed, sigs.last().unwrap(), two);
        let both = framed(
            &data,
            8192,
            &sigs,
            &format!(
                "x-amz-checksum-crc32c:sOO8/Q==\r\nx-amz-meta-x:1\r\nx-amz-trailer-signature:{tsig2}\r\n"
            ),
        );
        let mut v = ChunkVerifier::new(seed.clone(), true);
        assert!(decode_s3_chunked(&both, Some(&mut v)).is_ok());

        // The checksum changed after signing.
        let bad = framed(
            &data,
            8192,
            &sigs,
            &format!("x-amz-checksum-crc32c:AAAAAA==\r\nx-amz-trailer-signature:{tsig}\r\n"),
        );
        let mut v = ChunkVerifier::new(seed.clone(), true);
        assert!(matches!(
            decode_s3_chunked(&bad, Some(&mut v)),
            Err(DecodeError::BadSignature(_))
        ));

        // The trailer signature left off.
        let unsigned = framed(&data, 8192, &sigs, &format!("{trailer}\r\n"));
        let mut v = ChunkVerifier::new(seed, true);
        assert!(matches!(
            decode_s3_chunked(&unsigned, Some(&mut v)),
            Err(DecodeError::BadSignature(_))
        ));
    }

    /// Through the middleware: a seeded request whose chain breaks is
    /// refused with 403 and never reaches the handler; one that holds
    /// does; an unseeded one (no signature to chain from) is not checked.
    #[tokio::test]
    async fn the_layer_refuses_a_broken_chain_before_the_handler() {
        use axum::{Router, middleware, routing::put};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let reached = Arc::new(AtomicUsize::new(0));
        let app = {
            let reached = Arc::clone(&reached);
            Router::new()
                .route(
                    "/",
                    put(move |body: Bytes| {
                        let reached = Arc::clone(&reached);
                        async move {
                            reached.fetch_add(1, Ordering::SeqCst);
                            format!("{}", body.len())
                        }
                    }),
                )
                .layer(middleware::from_fn(s3_chunked_decode_layer))
        };
        let send = |body: Vec<u8>, seeded: bool| {
            let app = app.clone();
            async move {
                let mut req = Request::builder()
                    .method("PUT")
                    .uri("/")
                    .header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
                    .header("content-encoding", "aws-chunked")
                    .header("x-amz-decoded-content-length", "66560")
                    .body(Body::from(body))
                    .unwrap();
                if seeded {
                    req.extensions_mut().insert(aws_seed());
                }
                let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
                let status = resp.status();
                let text = resp.into_body().collect().await.unwrap().to_bytes();
                (status, String::from_utf8_lossy(&text).into_owned())
            }
        };

        let (_, body) = aws_body();
        let (status, text) = send(body.clone(), true).await;
        assert_eq!((status.as_u16(), text.as_str()), (200, "66560"));
        assert_eq!(reached.load(Ordering::SeqCst), 1);

        let mut tampered = body.clone();
        let at = tampered.len() - 120;
        tampered[at] = b'b';
        let (status, text) = send(tampered.clone(), true).await;
        assert_eq!(status.as_u16(), 403, "{text}");
        assert!(text.contains("SignatureDoesNotMatch"), "{text}");
        assert_eq!(reached.load(Ordering::SeqCst), 1, "the handler never ran");

        // Unseeded: no request signature to chain from (--no-auth).
        let (status, _) = send(tampered, false).await;
        assert_eq!(status.as_u16(), 200);
    }

    /// A trailer the request announces in `x-amz-trailer` and then leaves
    /// off is refused: its checksum would otherwise go unchecked.
    #[tokio::test]
    async fn an_announced_trailer_that_never_comes_is_refused() {
        use axum::{Router, middleware, routing::put};
        let app = Router::new()
            .route(
                "/",
                put(|body: Bytes| async move { format!("{}", body.len()) }),
            )
            .layer(middleware::from_fn(s3_chunked_decode_layer));
        let req = Request::builder()
            .method("PUT")
            .uri("/")
            .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
            .header("content-encoding", "aws-chunked")
            .header("x-amz-decoded-content-length", "5")
            .header("x-amz-trailer", "x-amz-checksum-crc32c")
            .body(Body::from(&b"5\r\nhello\r\n0\r\n\r\n"[..]))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 400);
        let text = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(
            String::from_utf8_lossy(&text).contains("MalformedTrailerError"),
            "{text:?}"
        );
    }

    /// With signed chunks and unsigned trailers, a checksum appended after
    /// the last chunk is not the client's and does not become a header.
    #[tokio::test]
    async fn trailers_are_not_taken_from_a_body_that_does_not_sign_them() {
        use axum::{Router, middleware, routing::put};
        async fn echo(headers: http::HeaderMap) -> String {
            headers.contains_key("x-amz-checksum-crc32c").to_string()
        }
        let app = Router::new()
            .route("/", put(echo))
            .layer(middleware::from_fn(s3_chunked_decode_layer));
        let data = vec![b'a'; 66_560];
        let sigs: Vec<String> = AWS_CHUNK_SIGS.iter().map(|s| (*s).to_string()).collect();
        let body = framed(&data, 65_536, &sigs, "x-amz-checksum-crc32c:AAAAAA==\r\n");
        let mut req = Request::builder()
            .method("PUT")
            .uri("/")
            .header("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
            .header("content-encoding", "aws-chunked")
            .body(Body::from(body))
            .unwrap();
        req.extensions_mut().insert(aws_seed());
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        let text = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&text[..], b"false");
    }

    #[tokio::test]
    async fn a_body_larger_than_a_handler_takes_is_refused_unread() {
        use axum::{Router, middleware, routing::put};
        let app = Router::new()
            .route("/", put(|| async { "stored" }))
            .layer(middleware::from_fn(s3_chunked_decode_layer));
        let req = Request::builder()
            .method("PUT")
            .uri("/")
            .header("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
            .header("content-encoding", "aws-chunked")
            .header(
                "x-amz-decoded-content-length",
                (crate::admission::MAX_BODY + 1).to_string(),
            )
            .body(Body::from(&b"5\r\nhello\r\n0\r\n\r\n"[..]))
            .unwrap();
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 400);
        let text = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&text).contains("EntityTooLarge"));
    }
}
