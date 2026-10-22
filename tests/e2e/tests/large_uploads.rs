//! A single PUT and an upload part up to S3's 5 GiB. Their bodies are
//! streamed to the shards stripe by stripe, never held whole in the
//! gateway, so its memory stays bounded however large the upload; a larger
//! body is refused with S3's `EntityTooLarge` before any of it is read.
//!
//! The gateway used to read every body whole and refuse one over 100 MiB:
//! no single PUT could reach S3's 5 GiB, and no object 5 TiB (its 10,000
//! parts were 100 MiB at most).
//!
//! Nothing is stored before the body has arrived whole and passed every
//! check it carries: its signed payload hash, its chunk signatures, its
//! Content-MD5 and its checksum. A body that fails one, or a client that
//! goes away mid-upload, leaves nothing: no object, and its shards freed.
//!
//! Bodies here are generated as they are sent, never held by the test
//! either. The 5 GiB uploads take minutes on a debug build, so they are
//! `#[ignore]`d; the others stream a few hundred MiB.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use md5::Md5;
use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;
/// S3's largest single PUT or part.
const MAX_UPLOAD: u64 = 5 * GIB;

/// Long enough for a 5 GiB upload on a debug build.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(1800);

const BLOCK: usize = 1 << 20;

/// `n`, which is known to fit, as an index.
fn index(n: u64) -> usize {
    usize::try_from(n).expect("fits")
}

/// `len` deterministic bytes from `start` on, generated as they are read.
/// Every 4 KiB starts with its offset, so a stripe stored out of place reads
/// back wrong.
struct Gen {
    end: u64,
    pos: u64,
    seed: u64,
    block: Vec<u8>,
}

impl Gen {
    fn new(seed: u64, len: u64) -> Self {
        Self::at(seed, 0, len)
    }

    fn at(seed: u64, start: u64, len: u64) -> Self {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
        let mut block = vec![0u8; BLOCK];
        for c in block.chunks_mut(8) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            c.copy_from_slice(&x.to_le_bytes()[..c.len()]);
        }
        Self {
            end: start + len,
            pos: start,
            seed,
            block,
        }
    }

    fn bytes(seed: u64, start: u64, len: u64) -> Vec<u8> {
        let mut out = Vec::new();
        Self::at(seed, start, len).read_to_end(&mut out).unwrap();
        out
    }
}

impl Read for Gen {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.end - self.pos;
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let at = index(self.pos % BLOCK as u64);
        let n = (BLOCK - at)
            .min(buf.len())
            .min(usize::try_from(left).unwrap_or(usize::MAX));
        buf[..n].copy_from_slice(&self.block[at..at + n]);
        let end = self.pos + n as u64;
        let mut o = self.pos - self.pos % 4096;
        while o < end {
            for (j, b) in (o ^ self.seed).to_le_bytes().iter().enumerate() {
                let p = o + j as u64;
                if p >= self.pos && p < end {
                    buf[index(p - self.pos)] = *b;
                }
            }
            o += 4096;
        }
        self.pos = end;
        Ok(n)
    }
}

/// MD5 and SHA-256 of whatever `r` reads, and how many bytes.
fn digests(mut r: impl Read) -> ([u8; 16], [u8; 32], u64) {
    let (mut md5, mut sha) = (Md5::new(), Sha256::new());
    let mut buf = vec![0u8; BLOCK];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf).expect("read");
        if n == 0 {
            break;
        }
        md5.update(&buf[..n]);
        sha.update(&buf[..n]);
        total += n as u64;
    }
    (md5.finalize().into(), sha.finalize().into(), total)
}

/// What a GET of `path` reads back: its MD5 and length, streamed.
fn get_digest(c: &Cluster, path: &str, extra: &[(&str, &str)]) -> ([u8; 16], u64) {
    let client = reqwest::blocking::Client::builder()
        .timeout(UPLOAD_TIMEOUT)
        .build()
        .unwrap();
    let mut req = client.get(c.presign("GET", path, 3600));
    for (k, v) in extra {
        req = req.header(*k, *v);
    }
    let resp = req.send().expect("GET");
    assert_eq!(resp.status().as_u16(), 200, "GET {path}");
    let (md5, _, n) = digests(resp);
    (md5, n)
}

fn etag_of(r: &objectio_e2e::Response) -> String {
    r.header("etag")
        .expect("an ETag")
        .trim_matches('"')
        .to_string()
}

/// The gateway's peak memory since it was last reset, and now (`VmHWM`,
/// `VmRSS`), in bytes.
fn memory(pid: u32) -> (u64, u64) {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("proc status");
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            .map_or_else(|| panic!("no {name} in /proc/{pid}/status"), |kb| kb * 1024)
    };
    (field("VmHWM:"), field("VmRSS:"))
}

/// Peak memory from here on (Linux: writing 5 resets `VmHWM` to `VmRSS`); the
/// memory now.
fn reset_peak(pid: u32) -> u64 {
    std::fs::write(format!("/proc/{pid}/clear_refs"), "5").expect("reset VmHWM");
    memory(pid).1
}

/// A PUT of `len` generated bytes, its payload hash signed.
fn signed_put(c: &Cluster, path: &str, seed: u64, len: u64) -> objectio_e2e::Response {
    let (_, sha, _) = digests(Gen::new(seed, len));
    let req = c.sign("PUT", path, &hex::encode(sha), &[]);
    req.send_streamed(
        reqwest::blocking::Body::sized(Gen::new(seed, len), len),
        &[],
        UPLOAD_TIMEOUT,
    )
    .expect("PUT")
}

/// A body in `aws-chunked` framing, built as it is read: `data` in
/// `chunk`-byte chunks, signed in a chain from the request's signature
/// when `signer` is given, then a CRC32 trailer (signed too, with a
/// signer).
struct Framed<R> {
    data: R,
    chunk: usize,
    signer: Option<Arc<objectio_e2e::SignedRequest>>,
    previous: String,
    crc: crc32fast::Hasher,
    out: Vec<u8>,
    at: usize,
    done: bool,
}

impl<R: Read> Framed<R> {
    fn new(data: R, chunk: usize, signer: Option<Arc<objectio_e2e::SignedRequest>>) -> Self {
        Self {
            data,
            chunk,
            previous: signer
                .as_ref()
                .map(|s| s.signature.clone())
                .unwrap_or_default(),
            signer,
            crc: crc32fast::Hasher::new(),
            out: Vec::new(),
            at: 0,
            done: false,
        }
    }

    /// The framed length of `len` payload bytes in `chunk`-byte chunks.
    fn length(len: u64, chunk: u64, signed: bool) -> u64 {
        let sig = if signed { 17 + 64 } else { 0 };
        let line = |n: u64| format!("{n:x}").len() as u64 + sig + 2;
        let (full, rest) = (len / chunk, len % chunk);
        let mut total = full * (line(chunk) + chunk + 2);
        if rest > 0 {
            total += line(rest) + rest + 2;
        }
        let trailer = "x-amz-checksum-crc32:AAAAAA==\r\n".len() as u64;
        let trailer_sig = if signed {
            "x-amz-trailer-signature:".len() as u64 + 64 + 2
        } else {
            0
        };
        total + line(0) + trailer + trailer_sig + 2
    }

    fn sign_chunk(&mut self, data: &[u8]) -> String {
        match &self.signer {
            Some(s) => {
                self.previous = s.chunk_signature(&self.previous, data);
                format!(";chunk-signature={}", self.previous)
            }
            None => String::new(),
        }
    }

    fn refill(&mut self) {
        self.out.clear();
        self.at = 0;
        let mut data = vec![0u8; self.chunk];
        let mut n = 0;
        while n < self.chunk {
            let got = self.data.read(&mut data[n..]).expect("generate");
            if got == 0 {
                break;
            }
            n += got;
        }
        data.truncate(n);
        let sig = self.sign_chunk(&data);
        self.out
            .extend_from_slice(format!("{:x}{sig}\r\n", data.len()).as_bytes());
        if data.is_empty() {
            let trailer = format!(
                "x-amz-checksum-crc32:{}",
                B64.encode(self.crc.clone().finalize().to_be_bytes())
            );
            self.out.extend_from_slice(trailer.as_bytes());
            self.out.extend_from_slice(b"\r\n");
            if let Some(s) = &self.signer {
                let tsig = s.trailer_signature(&self.previous, &format!("{trailer}\n"));
                self.out
                    .extend_from_slice(format!("x-amz-trailer-signature:{tsig}\r\n").as_bytes());
            }
            self.out.extend_from_slice(b"\r\n");
            self.done = true;
            return;
        }
        self.crc.update(&data);
        self.out.extend_from_slice(&data);
        self.out.extend_from_slice(b"\r\n");
    }
}

impl<R: Read> Read for Framed<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.at == self.out.len() {
            if self.done {
                return Ok(0);
            }
            self.refill();
        }
        let n = buf.len().min(self.out.len() - self.at);
        buf[..n].copy_from_slice(&self.out[self.at..self.at + n]);
        self.at += n;
        Ok(n)
    }
}

/// `UploadPart` `part` of `upload` as an SDK streams one: `aws-chunked`, a
/// CRC32 trailer, the chunks signed or not.
fn chunked_part(
    c: &Cluster,
    path: &str,
    upload: &str,
    part: u32,
    (seed, len): (u64, u64),
    signed: bool,
) -> objectio_e2e::Response {
    const CHUNK: u64 = 64 * 1024;
    let hash = if signed {
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
    } else {
        "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
    };
    let decoded = len.to_string();
    let req = Arc::new(c.sign(
        "PUT",
        &format!("{path}?partNumber={part}&uploadId={upload}"),
        hash,
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", &decoded),
            ("x-amz-trailer", "x-amz-checksum-crc32"),
        ],
    ));
    let framed = Framed::new(
        Gen::new(seed, len),
        index(CHUNK),
        signed.then(|| Arc::clone(&req)),
    );
    let wire = Framed::<Gen>::length(len, CHUNK, signed);
    req.send_streamed(
        reqwest::blocking::Body::sized(framed, wire),
        &[],
        UPLOAD_TIMEOUT,
    )
    .expect("UploadPart")
}

fn create_upload(c: &Cluster, path: &str) -> String {
    let r = c.request("POST", &format!("{path}?uploads"), &[]);
    r.expect_ok();
    let text = r.text();
    text.split("<UploadId>")
        .nth(1)
        .and_then(|t| t.split("</UploadId>").next())
        .expect("an upload id")
        .to_string()
}

fn complete_upload(c: &Cluster, path: &str, upload: &str, etags: &[String]) {
    use std::fmt::Write as _;
    let mut xml = String::from("<CompleteMultipartUpload>");
    for (i, etag) in etags.iter().enumerate() {
        let _ = write!(
            xml,
            "<Part><PartNumber>{}</PartNumber><ETag>\"{etag}\"</ETag></Part>",
            i + 1
        );
    }
    xml.push_str("</CompleteMultipartUpload>");
    c.request("POST", &format!("{path}?uploadId={upload}"), xml.as_bytes())
        .expect_ok();
}

/// A presigned URL split into the address to connect to and the request
/// target to send.
fn target(c: &Cluster, method: &str, path: &str) -> (String, String) {
    let url = c.presign(method, path, 3600);
    let rest = url.trim_start_matches("http://");
    let slash = rest.find('/').expect("a path");
    (rest[..slash].to_string(), rest[slash..].to_string())
}

/// A response's status line and body, read off a raw connection.
fn read_answer(s: TcpStream) -> (u16, String) {
    let mut r = BufReader::new(s);
    let mut line = String::new();
    r.read_line(&mut line).expect("a status line");
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut len = 0usize;
    loop {
        line.clear();
        r.read_line(&mut line).expect("a header");
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':')
            && k.eq_ignore_ascii_case("content-length")
        {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0; len];
    r.read_exact(&mut body).expect("the body");
    (status, String::from_utf8_lossy(&body).into_owned())
}

/// The answer to a PUT of `path` that declares `headers` and sends none of
/// its body: a refusal comes before the body is read.
fn put_headers_only(c: &Cluster, path: &str, headers: &str) -> (u16, String) {
    let (host, target) = target(c, "PUT", path);
    let mut s = TcpStream::connect(&host).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    write!(s, "PUT {target} HTTP/1.1\r\nHost: {host}\r\n{headers}\r\n").unwrap();
    read_answer(s)
}

/// A PUT and an `UploadPart` several times the size a body was ever read
/// whole at, through a gateway with a 64 MiB memory budget: both stream,
/// the gateway's memory grows by a fraction of what passed through it, and
/// what is read back is what was sent.
#[test]
fn a_large_put_and_part_stream_through_bounded_memory() {
    const LEN: u64 = 320 * MIB;
    let mut ha = HaCluster::start(1, 6, 1);
    ha.restart_gateway_with_args(0, &["--memory-budget", "64MiB"]);
    let c = &ha.clients[0];
    c.json("POST", "/_admin/buckets", json!({"name": "big"}))
        .expect_ok();
    let pid = ha.gateway_pid(0).expect("the gateway runs");

    // A single PUT, its payload hash signed.
    let before = reset_peak(pid);
    let started = Instant::now();
    let r = signed_put(c, "/big/put", 1, LEN);
    r.expect(200);
    let (peak, _) = memory(pid);
    let grew = peak.saturating_sub(before);
    eprintln!(
        "PUT of {} MiB in {:?}: gateway memory {} MiB before, peak +{} MiB",
        LEN >> 20,
        started.elapsed(),
        before >> 20,
        grew >> 20
    );
    let (md5, _, _) = digests(Gen::new(1, LEN));
    assert_eq!(etag_of(&r), hex::encode(md5), "the ETag is the body's MD5");
    // Read whole, the body alone would be 320 MiB.
    assert!(
        grew < LEN / 2,
        "the gateway's peak memory grew by {} MiB for a {} MiB PUT",
        grew >> 20,
        LEN >> 20
    );
    assert_eq!(get_digest(c, "/big/put", &[]), (md5, LEN));
    // A range across a stripe boundary is the body's.
    let (from, to) = (16 * MIB - 1000, 33 * MIB + 77);
    let range = c.request_with_headers(
        "GET",
        "/big/put",
        &[],
        &[("range", &format!("bytes={from}-{to}"))],
    );
    assert_eq!(range.status, 206);
    assert!(range.bytes == Gen::bytes(1, from, to - from + 1));

    // An UploadPart in aws-chunked framing, its chunks and checksum
    // trailer signed, then a small last part.
    let upload = create_upload(c, "/big/mpu");
    let before = reset_peak(pid);
    let started = Instant::now();
    let r = chunked_part(c, "/big/mpu", &upload, 1, (2, LEN), true);
    r.expect(200);
    let grew = memory(pid).0.saturating_sub(before);
    eprintln!(
        "UploadPart of {} MiB in {:?}: gateway peak +{} MiB",
        LEN >> 20,
        started.elapsed(),
        grew >> 20
    );
    assert!(
        grew < LEN / 2,
        "the gateway's peak memory grew by {} MiB for a {} MiB part",
        grew >> 20,
        LEN >> 20
    );
    let (part1, _, _) = digests(Gen::new(2, LEN));
    assert_eq!(etag_of(&r), hex::encode(part1));
    let crc = {
        let mut hasher = crc32fast::Hasher::new();
        let mut generated = Gen::new(2, LEN);
        let mut buf = vec![0u8; BLOCK];
        loop {
            let n = generated.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        B64.encode(hasher.finalize().to_be_bytes())
    };
    assert_eq!(
        r.header("x-amz-checksum-crc32").as_deref(),
        Some(crc.as_str()),
        "the part's checksum, from its trailer"
    );
    let tail = Gen::bytes(3, 0, MIB);
    let r2 = c.request(
        "PUT",
        &format!("/big/mpu?partNumber=2&uploadId={upload}"),
        &tail,
    );
    r2.expect(200);
    complete_upload(c, "/big/mpu", &upload, &[etag_of(&r), etag_of(&r2)]);
    let whole = digests(Gen::new(2, LEN).chain(Gen::new(3, MIB)));
    assert_eq!(get_digest(c, "/big/mpu", &[]), (whole.0, LEN + MIB));
}

/// A large body that fails a check it carries is refused once it has all
/// arrived, and leaves nothing: no object, and every shard it wrote freed.
/// So does a client that goes away mid-body.
#[test]
fn a_large_body_that_fails_its_checks_stores_nothing() {
    const LEN: u64 = 80 * MIB;
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "chk"}))
        .expect_ok();
    let baseline = c.total_used_bytes();
    let gone = |c: &Cluster, what: &str| {
        assert_eq!(c.request("GET", "/chk/obj", &[]).status, 404, "{what}");
        assert_eq!(
            c.await_total_used_bytes(baseline),
            baseline,
            "{what}: the shards it wrote are still allocated"
        );
    };

    // Not the body whose hash was signed.
    let (_, other, _) = digests(Gen::new(9, LEN));
    let r = c
        .sign("PUT", "/chk/obj", &hex::encode(other), &[])
        .send_streamed(
            reqwest::blocking::Body::sized(Gen::new(1, LEN), LEN),
            &[],
            UPLOAD_TIMEOUT,
        )
        .expect("PUT");
    assert_eq!(r.status, 400, "{}", r.text());
    assert!(
        r.text().contains("XAmzContentSHA256Mismatch"),
        "{}",
        r.text()
    );
    gone(&c, "a payload hash mismatch");

    // A Content-MD5, and a checksum, it does not match.
    let wrong_md5 = B64.encode([0u8; 16]);
    for (name, value) in [
        ("content-md5", wrong_md5.as_str()),
        ("x-amz-checksum-crc32", "AAAAAA=="),
    ] {
        let r = c
            .sign("PUT", "/chk/obj", "UNSIGNED-PAYLOAD", &[])
            .send_streamed(
                reqwest::blocking::Body::sized(Gen::new(1, LEN), LEN),
                &[(name, value)],
                UPLOAD_TIMEOUT,
            )
            .expect("PUT");
        assert_eq!(r.status, 400, "{name}: {}", r.text());
        assert!(r.text().contains("BadDigest"), "{name}: {}", r.text());
        gone(&c, name);
    }

    // A chunk signature broken in the middle of an aws-chunked body.
    let upload = create_upload(&c, "/chk/obj");
    let req = Arc::new(c.sign(
        "PUT",
        &format!("/chk/obj?partNumber=1&uploadId={upload}"),
        "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
        &[
            ("content-encoding", "aws-chunked"),
            ("x-amz-decoded-content-length", &LEN.to_string()),
            ("x-amz-trailer", "x-amz-checksum-crc32"),
        ],
    ));
    let mut framed = Vec::new();
    Framed::new(Gen::new(1, LEN), 64 * 1024, Some(Arc::clone(&req)))
        .read_to_end(&mut framed)
        .unwrap();
    let at = framed.len() / 2;
    framed[at] ^= 1;
    let r = req
        .send_streamed(framed.into(), &[], UPLOAD_TIMEOUT)
        .expect("UploadPart");
    assert_eq!(r.status, 403, "{}", r.text());
    assert!(r.text().contains("SignatureDoesNotMatch"), "{}", r.text());
    let parts = c.request("GET", &format!("/chk/obj?uploadId={upload}"), &[]);
    assert!(!parts.text().contains("<Part>"), "{}", parts.text());
    gone(&c, "a broken chunk signature");

    // The client goes away after half its body.
    let (host, target) = target(&c, "PUT", "/chk/obj");
    let mut s = TcpStream::connect(&host).expect("connect");
    write!(
        s,
        "PUT {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {LEN}\r\n\r\n"
    )
    .unwrap();
    let mut half = Gen::new(1, LEN / 2);
    std::io::copy(&mut half, &mut s).expect("send half");
    drop(s);
    gone(&c, "a client gone mid-body");
}

/// Bodies over S3's 5 GiB are refused with `EntityTooLarge` before any of
/// them is read: a PUT, an `UploadPart`, and an aws-chunked body by its
/// decoded length. 5 GiB itself is let in.
#[test]
fn a_body_over_five_gib_is_refused_with_entity_too_large() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "max"}))
        .expect_ok();
    let upload = create_upload(&c, "/max/mpu");
    let over = MAX_UPLOAD + 1;
    for (path, headers) in [
        (
            "/max/obj".to_string(),
            format!("Content-Length: {over}\r\n"),
        ),
        (
            format!("/max/mpu?partNumber=1&uploadId={upload}"),
            format!("Content-Length: {over}\r\n"),
        ),
        (
            "/max/obj".to_string(),
            format!(
                "Content-Length: 1000\r\nContent-Encoding: aws-chunked\r\n\
                 x-amz-decoded-content-length: {over}\r\n"
            ),
        ),
    ] {
        let (status, body) = put_headers_only(&c, &path, &headers);
        assert_eq!(status, 400, "{path} {headers}: {body}");
        assert!(body.contains("<Code>EntityTooLarge</Code>"), "{body}");
        assert!(body.contains(&MAX_UPLOAD.to_string()), "{body}");
    }
    // 5 GiB is admitted: the gateway asks for the body.
    let (status, _) = put_headers_only(
        &c,
        "/max/obj",
        &format!("Content-Length: {MAX_UPLOAD}\r\nExpect: 100-continue\r\n"),
    );
    assert_eq!(status, 100, "a 5 GiB PUT is let in");
    // Other bodies keep their small limit.
    let (status, body) = put_headers_only(
        &c,
        "/max/obj?tagging",
        &format!("Content-Length: {}\r\n", 200 * MIB),
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("EntityTooLarge"), "{body}");
}

/// A large PUT encrypted as it streams (SSE-S3, SSE-C) reads back as it was
/// sent, whole and by ranges across its stripes: each stripe is encrypted
/// where it lies in the object. A copy out of it, which must rewrite the
/// bytes, streams too, as does a part copied from a range of it.
#[test]
fn a_large_encrypted_put_streams_and_reads_back() {
    const LEN: u64 = 70 * MIB;
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "enc"}))
        .expect_ok();
    let key = [7u8; 32];
    let sse_c = [
        (
            "x-amz-server-side-encryption-customer-algorithm",
            "AES256".to_string(),
        ),
        ("x-amz-server-side-encryption-customer-key", B64.encode(key)),
        (
            "x-amz-server-side-encryption-customer-key-md5",
            B64.encode(Md5::digest(key)),
        ),
    ];
    let sse_c: Vec<(&str, &str)> = sse_c.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let (md5, _, _) = digests(Gen::new(5, LEN));
    for (path, headers) in [
        ("/enc/s3", vec![("x-amz-server-side-encryption", "AES256")]),
        ("/enc/c", sse_c.clone()),
    ] {
        let r = c
            .sign("PUT", path, "UNSIGNED-PAYLOAD", &[])
            .send_streamed(
                reqwest::blocking::Body::sized(Gen::new(5, LEN), LEN),
                &headers,
                UPLOAD_TIMEOUT,
            )
            .expect("PUT");
        r.expect(200);
        assert_eq!(etag_of(&r), hex::encode(md5), "{path}: the plaintext's MD5");
        let read: Vec<(&str, &str)> = if path == "/enc/c" {
            sse_c.clone()
        } else {
            Vec::new()
        };
        assert_eq!(get_digest(&c, path, &read), (md5, LEN), "{path}");
        let (from, to) = (32 * MIB - 5, 48 * MIB + 5);
        let mut ranged = read.clone();
        let range = format!("bytes={from}-{to}");
        ranged.push(("range", &range));
        let r = c.request_with_headers("GET", path, &[], &ranged);
        assert_eq!(r.status, 206, "{path}");
        assert!(
            r.bytes == Gen::bytes(5, from, to - from + 1),
            "{path} range"
        );
    }
    // Without its key, the SSE-C object is not served.
    assert_eq!(c.request("GET", "/enc/c", &[]).status, 400);

    // A copy out of an encrypted object rewrites its bytes (its stripes
    // can't be shared): streamed from the source's stripes to the copy's.
    c.request_with_headers("PUT", "/enc/copy", &[], &[("x-amz-copy-source", "/enc/s3")])
        .expect(200);
    assert_eq!(get_digest(&c, "/enc/copy", &[]), (md5, LEN), "the copy");
    // And a part copied from a range of it, larger than a body read whole.
    let upload = create_upload(&c, "/enc/parts");
    let (from, to) = (3 * MIB + 1, 40 * MIB);
    let r = c.request_with_headers(
        "PUT",
        &format!("/enc/parts?partNumber=1&uploadId={upload}"),
        &[],
        &[
            ("x-amz-copy-source", "/enc/s3"),
            ("x-amz-copy-source-range", &format!("bytes={from}-{to}")),
        ],
    );
    r.expect(200);
    let etag = r
        .text()
        .split("<ETag>")
        .nth(1)
        .and_then(|t| t.split("</ETag>").next())
        .expect("a part ETag")
        .replace("&quot;", "")
        .trim_matches('"')
        .to_string();
    complete_upload(&c, "/enc/parts", &upload, &[etag]);
    let (want, _, _) = digests(Gen::at(5, from, to - from + 1));
    assert_eq!(
        get_digest(&c, "/enc/parts", &[]),
        (want, to - from + 1),
        "the part copied from a range"
    );
}

fn mib_per_sec(bytes: u64, took: Duration) -> f64 {
    f64::from(u32::try_from(bytes >> 20).expect("MiB")) / took.as_secs_f64()
}

/// The 5 GiB of the issue: a single PUT and an upload part of 5 GiB each,
/// read back by hash, through a gateway whose memory stays bounded.
#[test]
#[ignore = "measurement: 10 GiB through a debug build takes minutes; run with --ignored"]
fn five_gib_put_and_part_stream_through_bounded_memory() {
    let mut ha = HaCluster::start_with_disk_bytes(1, 6, 1, 4 * GIB);
    ha.restart_gateway_with_args(0, &["--memory-budget", "128MiB"]);
    let c = &ha.clients[0];
    c.json("POST", "/_admin/buckets", json!({"name": "huge"}))
        .expect_ok();
    let pid = ha.gateway_pid(0).expect("the gateway runs");

    let before = reset_peak(pid);
    let started = Instant::now();
    let r = signed_put(c, "/huge/put", 11, MAX_UPLOAD);
    let took = started.elapsed();
    r.expect(200);
    let grew = memory(pid).0.saturating_sub(before);
    eprintln!(
        "5 GiB PUT: {took:?} ({:.0} MiB/s), gateway memory {} MiB before, peak +{} MiB",
        mib_per_sec(MAX_UPLOAD, took),
        before >> 20,
        grew >> 20
    );
    assert!(
        grew < 512 * MIB,
        "the gateway's peak memory grew by {} MiB for a 5 GiB PUT",
        grew >> 20
    );
    let (md5, _, _) = digests(Gen::new(11, MAX_UPLOAD));
    assert_eq!(etag_of(&r), hex::encode(md5));
    let started = Instant::now();
    assert_eq!(get_digest(c, "/huge/put", &[]), (md5, MAX_UPLOAD));
    eprintln!("5 GiB GET: {:?}", started.elapsed());

    let upload = create_upload(c, "/huge/mpu");
    let before = reset_peak(pid);
    let started = Instant::now();
    let r = chunked_part(c, "/huge/mpu", &upload, 1, (12, MAX_UPLOAD), false);
    let took = started.elapsed();
    r.expect(200);
    let grew = memory(pid).0.saturating_sub(before);
    eprintln!(
        "5 GiB UploadPart: {took:?} ({:.0} MiB/s), gateway peak +{} MiB",
        mib_per_sec(MAX_UPLOAD, took),
        grew >> 20
    );
    assert!(
        grew < 512 * MIB,
        "the gateway's peak memory grew by {} MiB for a 5 GiB part",
        grew >> 20
    );
    let (md5, _, _) = digests(Gen::new(12, MAX_UPLOAD));
    assert_eq!(etag_of(&r), hex::encode(md5));
    complete_upload(c, "/huge/mpu", &upload, &[etag_of(&r)]);
    assert_eq!(get_digest(c, "/huge/mpu", &[]), (md5, MAX_UPLOAD));

    // One byte more is refused before it is read.
    let (status, body) = put_headers_only(
        c,
        "/huge/over",
        &format!("Content-Length: {}\r\n", MAX_UPLOAD + 1),
    );
    assert_eq!(status, 400, "{body}");
    assert!(body.contains("EntityTooLarge"), "{body}");
}
