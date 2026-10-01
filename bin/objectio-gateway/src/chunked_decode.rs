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

use axum::{body::Body, http::Request, middleware::Next, response::Response};
use bytes::Bytes;
use http_body_util::BodyExt;
use tracing::{debug, warn};

/// Returns true if the request uses S3 chunked transfer encoding.
fn is_s3_chunked(request: &Request<Body>) -> bool {
    // Check Content-Encoding header
    if request
        .headers()
        .get("content-encoding")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("aws-chunked"))
    {
        return true;
    }

    // Check x-amz-content-sha256 for streaming signature variants
    request
        .headers()
        .get("x-amz-content-sha256")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("STREAMING-"))
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

/// Decode an AWS-chunked body into raw payload bytes and its trailers.
///
/// Parses the `<hex-size>[;extensions]\r\n<data>\r\n` framing, discarding
/// chunk-signature extensions.
fn decode_s3_chunked(raw: &[u8]) -> Result<Decoded, String> {
    let mut output = Vec::with_capacity(raw.len());
    let mut trailers = Vec::new();
    let mut pos = 0;

    loop {
        if pos >= raw.len() {
            break;
        }

        // Find the end of the chunk-size line (\r\n)
        let line_end = find_crlf(raw, pos)
            .ok_or_else(|| format!("missing CRLF after chunk size at offset {pos}"))?;

        let line = &raw[pos..line_end];
        // The chunk size line may contain extensions after a semicolon
        // e.g. "ab;chunk-signature=..."
        let size_str =
            std::str::from_utf8(line).map_err(|e| format!("invalid UTF-8 in chunk header: {e}"))?;
        let hex_part = size_str.split(';').next().unwrap_or(size_str).trim();

        let chunk_size = usize::from_str_radix(hex_part, 16)
            .map_err(|e| format!("invalid hex chunk size '{hex_part}': {e}"))?;

        // Move past the size line + \r\n
        pos = line_end + 2;

        if chunk_size == 0 {
            // Terminal chunk — remaining bytes are trailing headers, one
            // `name:value` per line, ended by an empty line.
            trailers = parse_trailers(&raw[pos.min(raw.len())..]);
            break;
        }

        // Read chunk_size bytes of data
        if pos + chunk_size > raw.len() {
            return Err(format!(
                "chunk data truncated: need {} bytes at offset {}, have {}",
                chunk_size,
                pos,
                raw.len() - pos
            ));
        }
        output.extend_from_slice(&raw[pos..pos + chunk_size]);
        pos += chunk_size;

        // Skip the trailing \r\n after chunk data
        if pos + 2 <= raw.len() && raw[pos] == b'\r' && raw[pos + 1] == b'\n' {
            pos += 2;
        }
    }

    Ok(Decoded {
        payload: output,
        trailers,
    })
}

/// Trailing headers after the terminal chunk. Lines that are not
/// `name:value` are skipped rather than failing the request: the payload is
/// already complete, and a checksum that cannot be read is not checked.
fn parse_trailers(raw: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(raw)
        .split("\r\n")
        .take_while(|line| !line.is_empty())
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

/// Middleware that decodes S3 chunked transfer encoding before handlers see the body.
pub async fn s3_chunked_decode_layer(request: Request<Body>, next: Next) -> Response {
    if !is_s3_chunked(&request) {
        return next.run(request).await;
    }

    let (mut parts, body) = request.into_parts();

    // Read the full body
    let raw = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!("Failed to read s3-chunked body: {}", e);
            let rebuilt = Request::from_parts(parts, Body::empty());
            return next.run(rebuilt).await;
        }
    };

    debug!("Decoding s3-chunked body ({} raw bytes)", raw.len());

    let decoded = match decode_s3_chunked(&raw) {
        Ok(Decoded { payload, trailers }) => {
            debug!(
                "Decoded s3-chunked: {} -> {} bytes",
                raw.len(),
                payload.len()
            );
            // A checksum sent as a trailer becomes a header, so the handler
            // checks it the same way as one sent up front. Only checksums:
            // other trailers (the trailer signature) are not request headers.
            for (name, value) in trailers {
                if !name.starts_with("x-amz-checksum-") {
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
        Err(e) => {
            warn!("Failed to decode s3-chunked body: {}; passing raw body", e);
            raw.to_vec()
        }
    };

    // Update Content-Length to the decoded size and remove s3-chunked encoding
    parts.headers.insert("content-length", decoded.len().into());
    parts.headers.remove("content-encoding");
    // Remove the streaming hash header so downstream doesn't expect chunked format
    if parts
        .headers
        .get("x-amz-content-sha256")
        .and_then(|sha| sha.to_str().ok())
        .is_some_and(|v| v.starts_with("STREAMING-"))
    {
        parts
            .headers
            .insert("x-amz-content-sha256", "UNSIGNED-PAYLOAD".parse().unwrap());
    }

    let rebuilt = Request::from_parts(parts, Body::from(Bytes::from(decoded)));
    next.run(rebuilt).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_simple_s3_chunked() {
        // Single chunk: "ab" (hex) = 171 bytes, then terminal 0
        let body = b"b;chunk-signature=abc123\r\nhello world\r\n0;chunk-signature=def456\r\n\r\n";
        let decoded = decode_s3_chunked(body).unwrap().payload;
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn test_decode_multiple_chunks() {
        let body = b"5;chunk-signature=aaa\r\nhello\r\n6;chunk-signature=bbb\r\n world\r\n0;chunk-signature=ccc\r\n\r\n";
        let decoded = decode_s3_chunked(body).unwrap().payload;
        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn test_decode_with_trailing_checksum() {
        let body = b"5;chunk-signature=aaa\r\nhello\r\n0;chunk-signature=bbb\r\nx-amz-checksum-crc32:1b4gJg==\r\n\r\n";
        let decoded = decode_s3_chunked(body).unwrap();
        assert_eq!(decoded.payload, b"hello");
        assert_eq!(
            decoded.trailers,
            vec![("x-amz-checksum-crc32".to_string(), "1b4gJg==".to_string())]
        );
    }

    #[test]
    fn test_decode_trailers_with_signature_and_mixed_case() {
        let body = b"5\r\nhello\r\n0\r\nX-Amz-Checksum-CRC32C: yZRlqg==\r\nx-amz-trailer-signature:abc\r\n\r\n";
        let decoded = decode_s3_chunked(body).unwrap();
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
        let decoded = decode_s3_chunked(body).unwrap();
        assert_eq!(decoded.payload, b"hello");
        assert!(decoded.trailers.is_empty());
    }
}
