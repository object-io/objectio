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
//! adds a signature over the trailing headers.
//!
//! A body read whole (most) is decoded here before the handler runs: one
//! whose chain breaks is refused before the handler sees any of it, and a
//! checksum trailer becomes a request header. A large upload's body, which
//! is never held whole ([`crate::admission::Streamed`]), is decoded as the
//! handler reads it: each chunk's data passes on as it arrives and its
//! signature is checked at its end, and the body ends in an error rather
//! than its end if anything is wrong, so the handler commits nothing built
//! from it. Its checksum trailers come as the body's HTTP trailers.

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::{
    body::Body,
    http::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use bytes::{Buf, Bytes};
use http_body::{Body as HttpBody, Frame, SizeHint};
use sha2::{Digest, Sha256};
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

/// The longest chunk-size line taken (its size and a signature are about
/// 90 bytes): a line that never ends is not buffered without end.
const MAX_LINE: usize = 4096;

/// The most trailer bytes taken after the terminal chunk.
const MAX_TRAILERS: usize = 64 * 1024;

/// Whether the request says its body is in AWS-chunked framing: a
/// streaming payload hash (`STREAMING-*`), or `aws-chunked` together with
/// the decoded length an SDK sends with it. `aws-chunked` in
/// Content-Encoding alone is weaker: clients name it over plain bodies too,
/// so such a body is decoded only if it parses as complete framing.
fn is_s3_chunked(headers: &http::HeaderMap) -> bool {
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

/// Why a framed body was refused.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// The framing is broken: cut short, a wrong size, no CRLF.
    Malformed(String),
    /// A chunk or the trailers are not signed as the chain says.
    BadSignature(String),
    /// Trailers the request names in `x-amz-trailer` and the body left off.
    MissingTrailers(Vec<String>),
    /// The payload is not `x-amz-decoded-content-length` long.
    Length { expected: u64, got: u64 },
    /// The payload is over this many bytes, the request's limit.
    TooLarge(u64),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(m) | Self::BadSignature(m) => f.write_str(m),
            Self::MissingTrailers(names) => {
                write!(f, "announced trailers missing: {}", names.join(", "))
            }
            Self::Length { expected, got } => write!(
                f,
                "x-amz-decoded-content-length is {expected}, the body decoded to {got} bytes"
            ),
            Self::TooLarge(max) => write!(f, "the payload is over {max} bytes"),
        }
    }
}

impl std::error::Error for DecodeError {}

impl DecodeError {
    /// How S3 answers it.
    pub(crate) fn response(&self) -> Response {
        match self {
            Self::Malformed(m) => incomplete_body(&format!("Malformed aws-chunked body: {m}")),
            Self::BadSignature(m) => {
                debug!("s3-chunked body refused: {m}");
                AuthError::SignatureDoesNotMatch.into_response()
            }
            Self::MissingTrailers(names) => crate::s3::S3Error::xml_response(
                "MalformedTrailerError",
                &format!(
                    "The request names trailing headers it does not carry: {}",
                    names.join(", ")
                ),
                http::StatusCode::BAD_REQUEST,
            ),
            Self::Length { .. } => incomplete_body(&self.to_string()),
            Self::TooLarge(max) => crate::admission::entity_too_large(*max),
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

    /// Check the signature of one chunk, whose data's SHA-256 is
    /// `data_sha256` (hex), and move the chain on to it.
    fn chunk(&mut self, data_sha256: &str, provided: Option<&str>) -> Result<(), DecodeError> {
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256-PAYLOAD\n{}\n{}\n{}\n{EMPTY_SHA256}\n{data_sha256}",
            self.seed.date, self.seed.scope, self.previous,
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

/// Where a [`Decoder`] is in the framing.
#[derive(Debug, Clone, Copy)]
enum State {
    /// In a chunk-size line.
    Size,
    /// In a chunk's data, this many bytes of it to come.
    Data(u64),
    /// After a chunk's data: its CR, then its LF.
    DataCr,
    DataLf,
    /// After the terminal chunk: the trailers, to the end of the body.
    Trailers,
}

/// An AWS-chunked body decoded as it arrives, whatever pieces it comes
/// in: `<hex-size>[;extensions]\r\n<data>\r\n`, up to the terminal chunk
/// and its trailers. With a verifier, every chunk's signature is checked
/// at its end (its data is hashed as it passes), and the trailers' when the
/// verifier says they are signed; without one, chunk signatures are not
/// read. Data passes on as it arrives, before its chunk is checked: what a
/// body decodes to counts only once [`Self::finish`] has accepted it.
pub(crate) struct Decoder {
    state: State,
    line: Vec<u8>,
    trailer: Vec<u8>,
    verifier: Option<ChunkVerifier>,
    /// The chunk being read: its data's hash so far, and its signature.
    chunk: Option<(Sha256, Option<String>)>,
    decoded: u64,
}

impl Decoder {
    fn new(verifier: Option<ChunkVerifier>) -> Self {
        Self {
            state: State::Size,
            line: Vec::new(),
            trailer: Vec::new(),
            verifier,
            chunk: None,
            decoded: 0,
        }
    }

    /// Decode `input`, the next bytes of the body, handing each piece of
    /// payload in it to `out` (slices of `input`, not copies).
    fn push(&mut self, mut input: Bytes, out: &mut impl FnMut(Bytes)) -> Result<(), DecodeError> {
        while !input.is_empty() {
            match self.state {
                State::Size => {
                    let end = memchr::memchr(b'\n', &input);
                    let take = end.map_or(input.len(), |i| i + 1);
                    if self.line.len() + take > MAX_LINE {
                        return Err(malformed(format!(
                            "a chunk-size line over {MAX_LINE} bytes"
                        )));
                    }
                    self.line.extend_from_slice(&input[..take]);
                    input.advance(take);
                    if end.is_some() {
                        self.chunk_header()?;
                    }
                }
                State::Data(left) => {
                    let n = usize::try_from(left).map_or(input.len(), |l| l.min(input.len()));
                    let piece = input.split_to(n);
                    if let Some((hasher, _)) = self.chunk.as_mut() {
                        hasher.update(&piece);
                    }
                    self.decoded += n as u64;
                    out(piece);
                    let left = left - n as u64;
                    if left == 0 {
                        self.end_chunk()?;
                        self.state = State::DataCr;
                    } else {
                        self.state = State::Data(left);
                    }
                }
                State::DataCr | State::DataLf => {
                    let cr = matches!(self.state, State::DataCr);
                    // The chunk's data is followed by CRLF; anything else
                    // means the declared size was wrong.
                    if input[0] != if cr { b'\r' } else { b'\n' } {
                        return Err(malformed(format!(
                            "missing CRLF after chunk data at payload offset {}",
                            self.decoded
                        )));
                    }
                    input.advance(1);
                    self.state = if cr { State::DataLf } else { State::Size };
                }
                State::Trailers => {
                    if self.trailer.len() + input.len() > MAX_TRAILERS {
                        return Err(malformed(format!("trailers over {MAX_TRAILERS} bytes")));
                    }
                    self.trailer.extend_from_slice(&input);
                    input.clear();
                }
            }
        }
        Ok(())
    }

    /// A chunk-size line has ended: start its chunk, or the trailers.
    fn chunk_header(&mut self) -> Result<(), DecodeError> {
        let line = std::mem::take(&mut self.line);
        let line = line
            .strip_suffix(b"\r\n")
            .ok_or_else(|| malformed("missing CRLF after chunk size"))?;
        let text = std::str::from_utf8(line)
            .map_err(|e| malformed(format!("invalid UTF-8 in chunk header: {e}")))?;
        // The chunk size line may contain extensions after a semicolon
        // e.g. "ab;chunk-signature=..."
        let (hex_part, extensions) = text.split_once(';').unwrap_or((text, ""));
        let hex_part = hex_part.trim();
        let size = u64::from_str_radix(hex_part, 16)
            .map_err(|e| malformed(format!("invalid hex chunk size '{hex_part}': {e}")))?;
        let signature = chunk_signature(extensions).map(str::to_string);
        if size == 0 {
            if let Some(v) = self.verifier.as_mut() {
                v.chunk(EMPTY_SHA256, signature.as_deref())?;
            }
            self.state = State::Trailers;
        } else {
            self.chunk = self.verifier.is_some().then(|| (Sha256::new(), signature));
            self.state = State::Data(size);
        }
        Ok(())
    }

    /// A chunk's data has all passed: check its signature.
    fn end_chunk(&mut self) -> Result<(), DecodeError> {
        if let (Some(v), Some((hasher, signature))) = (self.verifier.as_mut(), self.chunk.take()) {
            v.chunk(&hex::encode(hasher.finalize()), signature.as_deref())?;
        }
        Ok(())
    }

    /// The body has ended: it must have ended in its terminal chunk and
    /// trailers (signed, when they are to be). Returns the trailers,
    /// `(name, value)`, the name lowercased: where an SDK puts
    /// `x-amz-checksum-*` when it streams the body.
    fn finish(mut self) -> Result<Vec<(String, String)>, DecodeError> {
        // A body that stops before the terminal chunk is a cut-off upload,
        // not a short object.
        if !matches!(self.state, State::Trailers) {
            return Err(malformed("body ended before the terminal chunk"));
        }
        let trailers = parse_trailers(&self.trailer);
        if let Some(v) = self.verifier.as_mut()
            && v.trailer
        {
            let provided = trailers
                .iter()
                .find(|(name, _)| name == TRAILER_SIGNATURE)
                .map(|(_, value)| value.as_str());
            v.trailers(&self.trailer, provided)?;
        }
        Ok(trailers)
    }
}

/// An AWS-chunked body, decoded.
#[cfg(test)]
#[derive(Debug, Default, PartialEq, Eq)]
struct Decoded {
    payload: Vec<u8>,
    trailers: Vec<(String, String)>,
}

/// Decode a whole AWS-chunked body, fed to the decoder in pieces of every
/// size from one byte up, and once whole: each must decode the same.
#[cfg(test)]
fn decode_s3_chunked(raw: &[u8], verifier: Option<ChunkVerifier>) -> Result<Decoded, DecodeError> {
    let decode = |piece: usize, verifier: Option<ChunkVerifier>| {
        let mut d = Decoder::new(verifier);
        let mut payload = Vec::new();
        for p in raw.chunks(piece.max(1)) {
            d.push(Bytes::copy_from_slice(p), &mut |b| {
                payload.extend_from_slice(&b);
            })?;
        }
        Ok(Decoded {
            payload,
            trailers: d.finish()?,
        })
    };
    let whole = decode(raw.len(), verifier.as_ref().map(clone_verifier));
    for piece in [1, 2, 3, 7, 64, 1000] {
        let pieces = decode(piece, verifier.as_ref().map(clone_verifier));
        assert_eq!(pieces, whole, "fed in pieces of {piece} bytes");
    }
    whole
}

#[cfg(test)]
fn clone_verifier(v: &ChunkVerifier) -> ChunkVerifier {
    ChunkVerifier::new(v.seed.clone(), v.trailer)
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

/// The trailers the request names in `x-amz-trailer`, lowercased.
fn announced_trailers(headers: &http::HeaderMap) -> Vec<String> {
    headers
        .get_all("x-amz-trailer")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|name| name.trim().to_ascii_lowercase())
        .filter(|name| !name.is_empty())
        .collect()
}

/// The decoded body checked against what its request says of it: its
/// `x-amz-decoded-content-length`, and the trailers it named in
/// `x-amz-trailer` (a checksum sent as a trailer is checked only if it
/// arrives, so one that was announced and left off is refused, not
/// skipped). Returns the trailers that become the request's checksum:
/// only checksums, and only when they are the client's (with signed
/// chunks, only signed trailers are).
fn accepted_trailers(
    trailers: Vec<(String, String)>,
    decoded: u64,
    expected: Option<u64>,
    announced: &[String],
    trusted: bool,
) -> Result<http::HeaderMap, DecodeError> {
    let missing: Vec<String> = announced
        .iter()
        .filter(|name| !trailers.iter().any(|(n, _)| n == *name))
        .cloned()
        .collect();
    if !missing.is_empty() {
        return Err(DecodeError::MissingTrailers(missing));
    }
    if let Some(expected) = expected
        && expected != decoded
    {
        return Err(DecodeError::Length {
            expected,
            got: decoded,
        });
    }
    let mut out = http::HeaderMap::new();
    for (name, value) in trailers {
        if !trusted || !name.starts_with("x-amz-checksum-") {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(&value),
        ) {
            out.insert(name, value);
        }
    }
    Ok(out)
}

/// What a request's framing says of its body.
struct Framing {
    /// `x-amz-decoded-content-length`.
    decoded: Option<u64>,
    announced: Vec<String>,
    /// Whether its trailers are the client's (see [`accepted_trailers`]).
    trusted: bool,
    /// The payload limit.
    max: u64,
}

/// A streamed AWS-chunked body, decoded as it is read: payload frames, then
/// the accepted checksum trailers as an HTTP trailers frame. Anything wrong
/// with it ends it in an error ([`DecodeError`]), never its end.
struct DecodingBody {
    inner: Body,
    decoder: Option<Decoder>,
    framing: Framing,
    out: VecDeque<Bytes>,
    trailers: Option<http::HeaderMap>,
}

impl DecodingBody {
    fn fail(&mut self, e: DecodeError) -> Poll<Option<Result<Frame<Bytes>, axum::Error>>> {
        self.decoder = None;
        self.out.clear();
        Poll::Ready(Some(Err(axum::Error::new(e))))
    }
}

impl HttpBody for DecodingBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        loop {
            if let Some(piece) = this.out.pop_front() {
                return Poll::Ready(Some(Ok(Frame::data(piece))));
            }
            let Some(decoder) = this.decoder.as_mut() else {
                return Poll::Ready(this.trailers.take().map(|t| Ok(Frame::trailers(t))));
            };
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => {
                    this.decoder = None;
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(Some(Ok(frame))) => {
                    let Ok(data) = frame.into_data() else {
                        continue;
                    };
                    let out = &mut this.out;
                    if let Err(e) = decoder.push(data, &mut |piece| out.push_back(piece)) {
                        return this.fail(e);
                    }
                    if decoder.decoded > this.framing.max {
                        return this.fail(DecodeError::TooLarge(this.framing.max));
                    }
                }
                Poll::Ready(None) => {
                    let Some(decoder) = this.decoder.take() else {
                        continue;
                    };
                    let decoded = decoder.decoded;
                    let f = &this.framing;
                    match decoder.finish().and_then(|t| {
                        accepted_trailers(t, decoded, f.decoded, &f.announced, f.trusted)
                    }) {
                        Ok(t) => this.trailers = (!t.is_empty()).then_some(t),
                        Err(e) => return this.fail(e),
                    }
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.decoder.is_none() && self.out.is_empty() && self.trailers.is_none()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// Middleware that decodes S3 chunked transfer encoding before handlers see the body.
pub async fn s3_chunked_decode_layer(request: Request<Body>, next: Next) -> Response {
    let signalled = is_s3_chunked(request.headers());
    if !signalled && !names_aws_chunked(request.headers()) {
        return next.run(request).await;
    }
    let max = crate::admission::payload_limit(crate::admission::is_upload(
        request.method(),
        request.uri(),
        request.headers(),
    ));

    let (mut parts, body) = request.into_parts();
    let decoded_len = parts
        .headers
        .get("x-amz-decoded-content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if decoded_len.is_some_and(|n| n > max) {
        return crate::admission::entity_too_large(max);
    }

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
    let framing = Framing {
        decoded: decoded_len,
        announced: announced_trailers(&parts.headers),
        // When the chunks are signed and the trailers are not, the
        // trailers are not the client's and are left out.
        trusted: !signed_chunks || signed_trailer,
        max,
    };

    if parts
        .extensions
        .get::<crate::admission::Streamed>()
        .is_some()
    {
        strip_aws_chunked(&mut parts.headers);
        // Only named in Content-Encoding: a streamed body can't be tried as
        // framing and then stored as sent if it isn't, so it is taken as
        // sent. SDKs that frame a body say so (a streaming hash, a decoded
        // length).
        if !signalled {
            return next.run(Request::from_parts(parts, body)).await;
        }
        match decoded_len {
            Some(n) => parts.headers.insert("content-length", n.into()),
            None => parts.headers.remove("content-length"),
        };
        mark_unsigned(&mut parts.headers, &payload_hash);
        let body = Body::new(DecodingBody {
            inner: body,
            decoder: Some(Decoder::new(verifier)),
            framing,
            out: VecDeque::new(),
            trailers: None,
        });
        return next.run(Request::from_parts(parts, body)).await;
    }

    // Read the full body, no more of it than a handler could take with its
    // framing (the admission layer has already read it, into one buffer
    // this takes without a copy). A body that can't be read, or decoded,
    // fails the request: handing the handler an empty or still-framed body
    // would store the wrong bytes under the key.
    let raw = match crate::admission::body_into_vec(
        body,
        0,
        crate::admission::wire_limit(true, max),
        None,
    )
    .await
    {
        Ok(raw) => Bytes::from(raw),
        Err(crate::admission::BodyError::TooLarge(_)) => {
            return crate::admission::entity_too_large(max);
        }
        Err(e) => {
            warn!("Failed to read s3-chunked body: {e:?}");
            return incomplete_body("The request body could not be read in full");
        }
    };
    let raw_len = raw.len();
    debug!("Decoding s3-chunked body ({raw_len} raw bytes)");

    let decode = {
        let raw = raw.clone();
        move || {
            let mut decoder = Decoder::new(verifier);
            let mut payload = Vec::with_capacity(raw.len());
            decoder.push(raw, &mut |piece| payload.extend_from_slice(&piece))?;
            let decoded = decoder.decoded;
            let trailers = decoder.finish()?;
            if decoded > framing.max {
                return Err(DecodeError::TooLarge(framing.max));
            }
            let trailers = accepted_trailers(
                trailers,
                decoded,
                framing.decoded,
                &framing.announced,
                framing.trusted,
            )?;
            Ok((payload, trailers))
        }
    };
    let result = if raw_len <= DECODE_INLINE_BYTES {
        decode()
    } else {
        match tokio::task::spawn_blocking(decode).await {
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
        Ok((payload, trailers)) => {
            debug!("Decoded s3-chunked: {raw_len} -> {} bytes", payload.len());
            // A checksum sent as a trailer becomes a header, so the handler
            // checks it the same way as one sent up front.
            parts.headers.extend(trailers);
            payload
        }
        // Only named in Content-Encoding, and not complete framing: a
        // plain body, stored as sent. (A body that does parse as complete
        // framing, terminal chunk and all, is framed.)
        Err(DecodeError::Malformed(_)) if !signalled => {
            strip_aws_chunked(&mut parts.headers);
            return next.run(Request::from_parts(parts, Body::from(raw))).await;
        }
        Err(e) => {
            if matches!(e, DecodeError::Malformed(_)) {
                warn!("Failed to decode s3-chunked body: {e}");
            }
            return e.response();
        }
    };

    // Update Content-Length to the decoded size. `aws-chunked` is only the
    // transfer framing: any other coding (`gzip, aws-chunked`) belongs to
    // the object and is kept.
    parts.headers.insert("content-length", decoded.len().into());
    strip_aws_chunked(&mut parts.headers);
    mark_unsigned(&mut parts.headers, &payload_hash);

    let rebuilt = Request::from_parts(parts, Body::from(Bytes::from(decoded)));
    next.run(rebuilt).await
}

/// The body is decoded (and its chunks checked, or being checked):
/// downstream sees a plain body, whose hash was not signed.
fn mark_unsigned(headers: &mut http::HeaderMap, payload_hash: &str) {
    if payload_hash.starts_with("STREAMING-") {
        headers.insert(
            "x-amz-content-sha256",
            http::HeaderValue::from_static("UNSIGNED-PAYLOAD"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
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
        let v = ChunkVerifier::new(aws_seed(), false);
        let decoded = decode_s3_chunked(&body, Some(v)).unwrap();
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
        let v = ChunkVerifier::new(aws_seed(), false);
        assert!(matches!(
            decode_s3_chunked(&tampered, Some(v)),
            Err(DecodeError::BadSignature(_))
        ));

        // A different seed: the chain is another request's.
        let mut seed = aws_seed();
        seed.signature = "0".repeat(64);
        let v = ChunkVerifier::new(seed, false);
        assert!(matches!(
            decode_s3_chunked(&body, Some(v)),
            Err(DecodeError::BadSignature(_))
        ));

        // A chunk dropped, the rest of the chain kept.
        let data = vec![b'a'; 66_560];
        let sigs: Vec<String> = AWS_CHUNK_SIGS[1..]
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        let short = framed(&data[65_536..], 65_536, &sigs, "");
        let v = ChunkVerifier::new(aws_seed(), false);
        assert!(matches!(
            decode_s3_chunked(&short, Some(v)),
            Err(DecodeError::BadSignature(_))
        ));

        // A chunk without a signature.
        let unsigned = b"5\r\nhello\r\n0\r\n\r\n";
        let v = ChunkVerifier::new(aws_seed(), false);
        assert!(matches!(
            decode_s3_chunked(unsigned, Some(v)),
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
        let v = ChunkVerifier::new(seed.clone(), true);
        let decoded = decode_s3_chunked(&good, Some(v)).unwrap();
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
        let v = ChunkVerifier::new(seed.clone(), true);
        let decoded = decode_s3_chunked(&minio_go, Some(v)).unwrap();
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
        let v = ChunkVerifier::new(seed.clone(), true);
        assert!(decode_s3_chunked(&both, Some(v)).is_ok());

        // The checksum changed after signing.
        let bad = framed(
            &data,
            8192,
            &sigs,
            &format!("x-amz-checksum-crc32c:AAAAAA==\r\nx-amz-trailer-signature:{tsig}\r\n"),
        );
        let v = ChunkVerifier::new(seed.clone(), true);
        assert!(matches!(
            decode_s3_chunked(&bad, Some(v)),
            Err(DecodeError::BadSignature(_))
        ));

        // The trailer signature left off.
        let unsigned = framed(&data, 8192, &sigs, &format!("{trailer}\r\n"));
        let v = ChunkVerifier::new(seed, true);
        assert!(matches!(
            decode_s3_chunked(&unsigned, Some(v)),
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

    /// What a handler of a streamed body sees: its payload, its trailers,
    /// or the error it ended in, as S3 answers it.
    async fn stream_through(
        body: Vec<u8>,
        headers: &[(&str, &str)],
        seed: Option<ChunkSigningSeed>,
    ) -> Result<(Vec<u8>, Option<http::HeaderMap>), String> {
        use axum::{Router, middleware, routing::put};
        type Seen = std::sync::Arc<
            std::sync::Mutex<Option<Result<(Vec<u8>, Option<http::HeaderMap>), String>>>,
        >;
        let seen: Seen = std::sync::Arc::default();
        let app = {
            let seen = std::sync::Arc::clone(&seen);
            Router::new()
                .route(
                    "/b/k",
                    put(move |body: Body| {
                        let seen = std::sync::Arc::clone(&seen);
                        async move {
                            let got = match body.collect().await {
                                Ok(c) => {
                                    let trailers = c.trailers().cloned();
                                    Ok((c.to_bytes().to_vec(), trailers))
                                }
                                Err(e) => {
                                    let resp = crate::admission::body_refused(&e);
                                    let text = resp.into_body().collect().await.unwrap().to_bytes();
                                    Err(String::from_utf8_lossy(&text).into_owned())
                                }
                            };
                            *seen.lock().unwrap() = Some(got);
                            "done"
                        }
                    }),
                )
                .layer(middleware::from_fn(s3_chunked_decode_layer))
        };
        // In small frames, as a connection delivers a large body.
        let frames: Vec<Result<Bytes, std::io::Error>> = body
            .chunks(1000)
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        let mut req = Request::builder().method("PUT").uri("/b/k");
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let mut req = req
            .body(Body::from_stream(futures::stream::iter(frames)))
            .unwrap();
        req.extensions_mut().insert(crate::admission::Streamed);
        if let Some(seed) = seed {
            req.extensions_mut().insert(seed);
        }
        let resp = tower::ServiceExt::oneshot(app, req).await.unwrap();
        assert_eq!(resp.status().as_u16(), 200, "the handler ran");
        let got = seen.lock().unwrap().take();
        got.expect("the handler saw the body")
    }

    /// A streamed upload's chunks are checked as they pass, and its
    /// checksum trailer comes as the body's trailers.
    #[tokio::test]
    async fn a_streamed_body_is_decoded_and_checked_as_it_is_read() {
        let seed = aws_seed();
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let sigs = client_chain(&seed, &data, 65_536);
        let trailer = format!(
            "x-amz-checksum-crc32c:{}",
            base64::engine::general_purpose::STANDARD.encode(crc32c::crc32c(&data).to_be_bytes())
        );
        let tsig = client_trailer_sig(&seed, sigs.last().unwrap(), &format!("{trailer}\n"));
        let body = framed(
            &data,
            65_536,
            &sigs,
            &format!("{trailer}\r\nx-amz-trailer-signature:{tsig}\r\n"),
        );
        let len = data.len().to_string();
        let headers = [
            (
                "x-amz-content-sha256",
                "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
            ),
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", len.as_str()),
            ("x-amz-trailer", "x-amz-checksum-crc32c"),
        ];
        let (payload, trailers) = stream_through(body.clone(), &headers, Some(seed.clone()))
            .await
            .expect("decodes");
        assert!(payload == data);
        let trailers = trailers.expect("the checksum trailer");
        assert_eq!(
            trailers.get("x-amz-checksum-crc32c").unwrap(),
            trailer.split_once(':').unwrap().1
        );
        assert!(!trailers.contains_key(TRAILER_SIGNATURE));

        // One byte of the middle chunk changed: the body ends in an error.
        let mut tampered = body.clone();
        let at = tampered.len() / 2;
        tampered[at] ^= 1;
        let err = stream_through(tampered, &headers, Some(seed.clone()))
            .await
            .expect_err("a broken chain");
        assert!(err.contains("SignatureDoesNotMatch"), "{err}");

        // Cut off before its terminal chunk.
        let err = stream_through(
            body[..body.len() / 2].to_vec(),
            &headers,
            Some(seed.clone()),
        )
        .await
        .expect_err("cut short");
        assert!(err.contains("IncompleteBody"), "{err}");

        // Longer than it said.
        let short = (data.len() - 1).to_string();
        let mut lying = headers;
        lying[2] = ("x-amz-decoded-content-length", short.as_str());
        let err = stream_through(body, &lying, Some(seed))
            .await
            .expect_err("the wrong length");
        assert!(err.contains("IncompleteBody"), "{err}");
    }

    #[tokio::test]
    async fn a_streamed_body_without_its_announced_trailer_is_refused() {
        let body = b"5\r\nhello\r\n0\r\n\r\n".to_vec();
        let err = stream_through(
            body,
            &[
                ("x-amz-content-sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER"),
                ("content-encoding", "aws-chunked"),
                ("x-amz-decoded-content-length", "5"),
                ("x-amz-trailer", "x-amz-checksum-crc32c"),
            ],
            None,
        )
        .await
        .expect_err("refused");
        assert!(err.contains("MalformedTrailerError"), "{err}");
    }

    #[test]
    fn a_line_that_never_ends_is_not_buffered() {
        let mut d = Decoder::new(None);
        let long = Bytes::from(vec![b'a'; MAX_LINE + 1]);
        assert!(matches!(
            d.push(long, &mut |_| {}),
            Err(DecodeError::Malformed(_))
        ));
    }
}
