//! The gateway's memory stays bounded whatever its clients do: a GET
//! streams the object stripe by stripe instead of holding it whole, request
//! bodies and read-ahead are reserved from a memory budget, requests beyond
//! the budget or the in-flight limit are refused with `503 SlowDown` rather
//! than queued, and clients that stall (sending headers or a body, or
//! reading a response) are cut off.
//!
//! A GET used to build the whole object (or range) in memory before sending
//! a byte: a multi-gigabyte object exceeded a 1 GiB pod's limit and killed
//! the gateway, and with it every request it was serving.

use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const MIB: usize = 1 << 20;

/// `len` bytes that differ at every offset a stripe could start at.
fn pattern(len: usize, seed: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_add(seed).wrapping_mul(2_654_435_761) >> 24).to_le_bytes()[0])
        .collect()
}

/// Sum of every sample of `name` whose labels contain all of `labels`.
fn metric(c: &Cluster, name: &str, labels: &[&str]) -> u64 {
    reqwest::blocking::get(format!("{}/metrics", c.endpoint))
        .and_then(reqwest::blocking::Response::text)
        .unwrap_or_default()
        .lines()
        .filter(|l| {
            l.split(['{', ' ']).next() == Some(name) && labels.iter().all(|want| l.contains(want))
        })
        .filter_map(|l| l.rsplit(' ').next()?.parse::<u64>().ok())
        .sum()
}

/// Wait for `name{labels}` to reach `want`, or give up at the deadline.
fn await_metric(c: &Cluster, name: &str, labels: &[&str], want: u64) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let got = metric(c, name, labels);
        if got >= want || Instant::now() > deadline {
            return got;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Wait for `name` to fall to 0 (a gauge), or give up at the deadline.
fn await_zero(c: &Cluster, name: &str) -> u64 {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let got = metric(c, name, &[]);
        if got == 0 || Instant::now() > deadline {
            return got;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A presigned URL split into the address to connect to and the request
/// target to send.
fn target(c: &Cluster, method: &str, path: &str) -> (String, String) {
    let url = c.presign(method, path, 3600);
    let rest = url.trim_start_matches("http://");
    let slash = rest.find('/').expect("a path");
    (rest[..slash].to_string(), rest[slash..].to_string())
}

/// A response read off a raw connection.
struct Raw {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Raw {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A response's status line and headers.
fn read_head(r: &mut BufReader<TcpStream>) -> std::io::Result<(u16, Vec<(String, String)>)> {
    let mut line = String::new();
    if r.read_line(&mut line)? == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let mut headers = Vec::new();
    loop {
        line.clear();
        r.read_line(&mut line)?;
        let l = line.trim_end();
        if l.is_empty() {
            break;
        }
        if let Some((k, v)) = l.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((status, headers))
}

/// A whole response (its body by Content-Length).
fn read_response(r: &mut BufReader<TcpStream>) -> Raw {
    let (status, headers) = read_head(r).expect("a response");
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    r.read_exact(&mut body).expect("the body");
    Raw {
        status,
        headers,
        body,
    }
}

/// A PUT sent the way SDKs send a large one: its headers with
/// `Expect: 100-continue`, and its body only once the gateway says to go
/// on. `Ok`: admitted, the body not sent yet; `Err`: the final answer.
fn start_put(c: &Cluster, path: &str, len: usize) -> Result<BufReader<TcpStream>, Raw> {
    let (host, target) = target(c, "PUT", path);
    let mut s = TcpStream::connect(&host).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    write!(
        s,
        "PUT {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len}\r\n\
         Expect: 100-continue\r\n\r\n"
    )
    .unwrap();
    let mut r = BufReader::new(s);
    let (status, headers) = read_head(&mut r).expect("an answer to the headers");
    if status == 100 {
        return Ok(r);
    }
    let len: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    r.read_exact(&mut body).expect("the refusal's body");
    Err(Raw {
        status,
        headers,
        body,
    })
}

/// Send an admitted PUT's body, and its answer.
fn finish_put(mut r: BufReader<TcpStream>, body: &[u8]) -> Raw {
    r.get_mut().write_all(body).expect("send the body");
    read_response(&mut r)
}

/// Store `path` by a multipart upload of `parts` parts, part `n` (from 1)
/// made by `part(n)`.
fn multipart_put(c: &Cluster, path: &str, parts: usize, mut part: impl FnMut(usize) -> Vec<u8>) {
    let r = c.request("POST", &format!("{path}?uploads"), &[]);
    r.expect_ok();
    let text = r.text();
    let upload = text
        .split("<UploadId>")
        .nth(1)
        .and_then(|t| t.split("</UploadId>").next())
        .expect("an upload id")
        .to_string();
    let mut completion = String::from("<CompleteMultipartUpload>");
    for n in 1..=parts {
        let r = c.request(
            "PUT",
            &format!("{path}?partNumber={n}&uploadId={upload}"),
            &part(n),
        );
        r.expect(200);
        let etag = r.header("etag").expect("a part etag");
        let _ = write!(
            completion,
            "<Part><PartNumber>{n}</PartNumber><ETag>{etag}</ETag></Part>"
        );
    }
    completion.push_str("</CompleteMultipartUpload>");
    c.request(
        "POST",
        &format!("{path}?uploadId={upload}"),
        completion.as_bytes(),
    )
    .expect_ok();
}

#[track_caller]
fn assert_slow_down(raw: &Raw, what: &str) {
    assert_eq!(raw.status, 503, "{what}: {}", raw.text());
    assert!(
        raw.text().contains("<Code>SlowDown</Code>"),
        "{what}: {}",
        raw.text()
    );
    assert!(
        raw.header("retry-after").is_some(),
        "{what}: no Retry-After"
    );
}

/// The gateway's peak memory since it was last reset, and its memory now,
/// in bytes (`VmHWM`, `VmRSS`).
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

/// A GET of an object eight times the memory budget is streamed: the
/// gateway's peak memory while serving it grows by much less than the
/// object, and the bytes are the object's.
#[test]
#[allow(clippy::too_many_lines)] // upload, read, measure, read a range
fn a_get_much_larger_than_the_memory_budget_streams_through_bounded_memory() {
    // 256 MiB in 16 MiB parts: no single request near the object's size.
    const PART: usize = 16 * MIB;
    const PARTS: usize = 16;
    let mut ha = HaCluster::start(1, 6, 1);
    let g = 0;
    ha.restart_gateway_with_args(g, &["--memory-budget", "32MiB"]);
    let c = &ha.clients[g];
    c.json("POST", "/_admin/buckets", json!({"name": "big"}))
        .expect_ok();

    let mut whole = Sha256::new();
    multipart_put(c, "/big/obj", PARTS, |n| {
        let part = pattern(PART, n);
        whole.update(&part);
        part
    });
    let want = whole.finalize();

    let pid = ha.gateway_pid(g).expect("the gateway runs");
    // Peak memory from here on (Linux: writing 5 resets VmHWM to VmRSS).
    std::fs::write(format!("/proc/{pid}/clear_refs"), "5").expect("reset VmHWM");
    let (_, before) = memory(pid);

    let url = c.presign("GET", "/big/obj", 3600);
    let mut resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .unwrap()
        .get(url)
        .send()
        .expect("GET");
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.content_length(),
        Some((PART * PARTS) as u64),
        "Content-Length is the object's size, known before the body"
    );
    let mut got = Sha256::new();
    let mut buf = vec![0u8; MIB];
    let mut total = 0usize;
    loop {
        let n = resp.read(&mut buf).expect("the body");
        if n == 0 {
            break;
        }
        got.update(&buf[..n]);
        total += n;
    }
    assert_eq!(total, PART * PARTS);
    assert!(got.finalize() == want, "the object read back other bytes");

    let (peak, _) = memory(pid);
    let grew = peak.saturating_sub(before);
    eprintln!(
        "gateway memory: {} MiB before the GET, peak {} MiB during it (+{} MiB) for a {} MiB object",
        before >> 20,
        peak >> 20,
        grew >> 20,
        (PART * PARTS) >> 20
    );
    // Held whole, the object alone would be 256 MiB; streamed, two stripes
    // in the budget and the shards of the one being decoded.
    assert!(
        grew < (PART * PARTS / 2) as u64,
        "the gateway's peak memory grew by {} MiB serving a {} MiB object",
        grew >> 20,
        (PART * PARTS) >> 20
    );

    // A range across many stripes streams too, and is the range.
    let r = c.request_with_headers(
        "GET",
        "/big/obj",
        &[],
        &[("range", "bytes=20000000-90000000")],
    );
    assert_eq!(r.status, 206);
    let mut expect = Vec::new();
    for n in 1..=PARTS {
        expect.extend_from_slice(&pattern(PART, n));
        if expect.len() > 90_000_000 {
            break;
        }
    }
    assert!(
        r.bytes == expect[20_000_000..=90_000_000],
        "the range read back other bytes"
    );
}

/// A stripe that can't be read once the headers have gone ends the
/// download short of its Content-Length: the client sees it fail, and what
/// it did get is the object's own bytes, never anything else.
#[test]
fn a_stripe_unreadable_after_the_headers_cuts_the_body_short() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--test-hooks"]);
    c.json("POST", "/_admin/buckets", json!({"name": "cut"}))
        .expect_ok();
    // Three stripes; the second is made unreadable: three of its six
    // shards replaced by wrong bytes their recorded checksums refuse.
    let body = pattern(40 * MIB, 3);
    c.request("PUT", "/cut/obj", &body).expect(200);
    for position in 0..3 {
        c.json(
            "POST",
            "/_admin/test/rewrite-shard",
            json!({"bucket": "cut", "key": "obj", "position": position, "stripe": 1}),
        )
        .expect_ok();
    }

    let url = c.presign("GET", "/cut/obj", 3600);
    let mut resp = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap()
        .get(url)
        .send()
        .expect("the headers");
    assert_eq!(resp.status().as_u16(), 200, "the first stripe reads");
    assert_eq!(resp.content_length(), Some(body.len() as u64));
    let mut got = Vec::new();
    let read = resp.read_to_end(&mut got);
    assert!(
        read.is_err(),
        "the body ended cleanly after {} of {} bytes",
        got.len(),
        body.len()
    );
    assert!(got.len() < body.len(), "the whole body was sent");
    assert!(
        got[..] == body[..got.len()],
        "the bytes sent before the cut are not the object's"
    );
    assert!(
        await_metric(
            &c,
            "objectio_gateway_get_aborted_total",
            &["reason=\"read\""],
            1
        ) >= 1,
        "the cut-off GET is not counted"
    );
    // The object's first stripe still reads, as a range.
    let r = c.request_with_headers("GET", "/cut/obj", &[], &[("range", "bytes=0-1023")]);
    assert_eq!(r.status, 206);
    assert!(r.bytes == body[..1024]);
}

/// More large PUTs at once than the memory budget holds: those that fit go
/// in, the rest are refused with `SlowDown` before their bodies are sent, as
/// is a GET with no room for its first stripe; once the room is free they
/// go in too.
#[test]
fn requests_beyond_the_memory_budget_are_refused_with_slow_down() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--memory-budget", "64MiB"]);
    c.json("POST", "/_admin/buckets", json!({"name": "mem"}))
        .expect_ok();
    let existing = pattern(20 * MIB, 9);
    c.request("PUT", "/mem/existing", &existing).expect(200);

    let bodies: Vec<Vec<u8>> = (0..3).map(|i| pattern(30 * MIB, 100 + i)).collect();
    // Two fit in 64 MiB, and hold it while their bodies are on the way.
    let a = start_put(&c, "/mem/a", bodies[0].len()).unwrap_or_else(|r| panic!("a: {}", r.text()));
    let b = start_put(&c, "/mem/b", bodies[1].len()).unwrap_or_else(|r| panic!("b: {}", r.text()));
    let refused = start_put(&c, "/mem/c", bodies[2].len()).expect_err("c does not fit");
    assert_slow_down(&refused, "the third PUT");
    // A GET needs room for a stripe too.
    let get = c.request("GET", "/mem/existing", &[]);
    assert_eq!(get.status, 503, "{}", get.text());
    assert!(get.text().contains("SlowDown"));
    assert!(
        metric(
            &c,
            "objectio_gateway_requests_rejected_total",
            &["reason=\"memory\""]
        ) >= 2
    );

    assert_eq!(finish_put(a, &bodies[0]).status, 200);
    assert_eq!(finish_put(b, &bodies[1]).status, 200);
    // Room again: what was refused goes in.
    let c3 = start_put(&c, "/mem/c", bodies[2].len()).unwrap_or_else(|r| panic!("c: {}", r.text()));
    assert_eq!(finish_put(c3, &bodies[2]).status, 200);
    for (key, body) in ["a", "b", "c"].iter().zip(&bodies) {
        let got = c.request("GET", &format!("/mem/{key}"), &[]);
        assert_eq!(got.status, 200);
        assert!(got.bytes == *body, "{key} read back other bytes");
    }
    let got = c.request("GET", "/mem/existing", &[]);
    assert_eq!(got.status, 200);
    assert!(got.bytes == existing);
    assert_eq!(
        await_zero(&c, "objectio_gateway_memory_budget_in_use_bytes"),
        0,
        "requests done, the budget is still held"
    );
}

/// The in-flight limit: a request beyond it is refused with `SlowDown`, while
/// health, readiness and metrics still answer.
#[test]
fn requests_beyond_the_in_flight_limit_are_refused_but_probes_answer() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--max-requests", "2"]);
    c.json("POST", "/_admin/buckets", json!({"name": "lim"}))
        .expect_ok();
    let body = pattern(MIB, 1);
    let a = start_put(&c, "/lim/a", body.len()).unwrap_or_else(|r| panic!("a: {}", r.text()));
    let b = start_put(&c, "/lim/b", body.len()).unwrap_or_else(|r| panic!("b: {}", r.text()));

    let r = c.request("GET", "/lim/a", &[]);
    assert_eq!(r.status, 503, "a third request: {}", r.text());
    assert!(r.text().contains("<Code>SlowDown</Code>"), "{}", r.text());
    assert!(r.header("retry-after").is_some());
    for probe in ["/health", "/_ready", "/metrics"] {
        let status = reqwest::blocking::get(format!("{}{probe}", c.endpoint))
            .map(|r| r.status().as_u16())
            .unwrap_or(0);
        assert_eq!(status, 200, "{probe} under the limit");
    }
    assert!(
        metric(
            &c,
            "objectio_gateway_requests_rejected_total",
            &["reason=\"requests\""]
        ) >= 1
    );

    assert_eq!(finish_put(a, &body).status, 200);
    assert_eq!(finish_put(b, &body).status, 200);
    let r = c.request("GET", "/lim/a", &[]);
    assert_eq!(r.status, 200);
    assert!(r.bytes == body);
}

/// A request body that stops arriving is cut off after the body timeout
/// with `RequestTimeout`, and nothing is stored.
#[test]
fn a_request_body_that_stops_arriving_is_cut_off() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--body-timeout-secs", "2"]);
    c.json("POST", "/_admin/buckets", json!({"name": "slow"}))
        .expect_ok();
    let (host, target) = target(&c, "PUT", "/slow/obj");
    let mut s = TcpStream::connect(&host).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    write!(
        s,
        "PUT {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {MIB}\r\n\r\n"
    )
    .unwrap();
    s.write_all(&[7u8; 1000]).unwrap();
    let started = Instant::now();
    let raw = read_response(&mut BufReader::new(s));
    let waited = started.elapsed();
    assert_eq!(raw.status, 400, "{}", raw.text());
    assert!(
        raw.text().contains("<Code>RequestTimeout</Code>"),
        "{}",
        raw.text()
    );
    assert!(
        waited < Duration::from_secs(20),
        "cut off only after {waited:?}"
    );
    assert_eq!(c.request("GET", "/slow/obj", &[]).status, 404);
    assert!(metric(&c, "objectio_gateway_timeouts_total", &["kind=\"body\""]) >= 1);
}

/// Headers trickled in (slowloris), and a kept-alive connection left idle,
/// are closed after the header timeout.
#[test]
fn a_client_slow_with_its_headers_or_idle_is_disconnected() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--header-timeout-secs", "2"]);
    let host = c.endpoint.trim_start_matches("http://").to_string();

    let closed_within = |mut s: TcpStream| {
        s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
        let started = Instant::now();
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf) {
                Ok(0) => return started.elapsed(),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                    return started.elapsed();
                }
                Err(e) => panic!("still open after {:?}: {e}", started.elapsed()),
            }
        }
    };

    let mut s = TcpStream::connect(&host).expect("connect");
    write!(s, "GET /health HTTP/1.1\r\nHost: {host}\r\n").unwrap();
    let waited = closed_within(s);
    assert!(waited < Duration::from_secs(15), "closed after {waited:?}");

    // A whole request is answered; then the idle connection is closed.
    let mut s = TcpStream::connect(&host).expect("connect");
    write!(s, "GET /health HTTP/1.1\r\nHost: {host}\r\n\r\n").unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let (status, _) = read_head(&mut r).expect("an answer");
    assert_eq!(status, 200);
    let waited = closed_within(s);
    assert!(
        waited < Duration::from_secs(15),
        "idle connection closed after {waited:?}"
    );
}

/// A client that stops reading a download is disconnected after the body
/// timeout, and what the GET held of the memory budget is given back.
#[test]
fn a_download_the_client_stops_reading_is_cut_off_and_its_memory_freed() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--body-timeout-secs", "2"]);
    c.json("POST", "/_admin/buckets", json!({"name": "stall"}))
        .expect_ok();
    let body = pattern(80 * MIB, 5);
    c.request("PUT", "/stall/obj", &body).expect(200);

    let (host, target) = target(&c, "GET", "/stall/obj");
    let mut s = TcpStream::connect(&host).expect("connect");
    write!(s, "GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let (status, _) = read_head(&mut r).expect("the headers");
    assert_eq!(status, 200);
    // Read nothing more: the socket buffers fill, the gateway's writes wait.
    assert!(
        await_metric(&c, "objectio_gateway_timeouts_total", &["kind=\"send\""], 1) >= 1,
        "the stalled download is still being served"
    );
    assert_eq!(
        await_zero(&c, "objectio_gateway_memory_budget_in_use_bytes"),
        0,
        "the stalled download still holds its read-ahead"
    );
    drop(r);
    drop(s);
}

/// A streamed GET holds nothing on the OSDs' connections once it is done,
/// or while its client has stopped reading: metadata calls to the same
/// OSDs (a delete of the object itself among them) answer at once after a
/// whole many-stripe GET, and while another GET of it is stalled part way.
#[test]
fn a_streamed_get_done_or_stalled_holds_up_no_other_call_to_the_osds() {
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--body-timeout-secs", "60"]);
    c.json("POST", "/_admin/buckets", json!({"name": "chan"}))
        .expect_ok();
    // Many stripes, each part its own.
    let parts = 12;
    multipart_put(&c, "/chan/big", parts, |n| pattern(6 * MIB, n));
    let whole: Vec<u8> = (1..=parts).flat_map(|n| pattern(6 * MIB, n)).collect();
    for i in 0..4 {
        c.request("PUT", &format!("/chan/small-{i}"), &pattern(300_000, i))
            .expect(200);
    }

    // Each call to the OSDs answers well inside their 10 s call timeout.
    let prompt = |what: &str, call: &dyn Fn() -> u16, want: u16| {
        let started = Instant::now();
        let status = call();
        let took = started.elapsed();
        assert_eq!(status, want, "{what}");
        assert!(took < Duration::from_secs(3), "{what} took {took:?}");
    };

    let got = c.request("GET", "/chan/big", &[]);
    assert!(got.bytes == whole, "the whole object, as written");
    prompt(
        "a delete after a whole GET",
        &|| c.request("DELETE", "/chan/small-0", &[]).status,
        204,
    );
    prompt(
        "a PUT after a whole GET",
        &|| c.request("PUT", "/chan/after", b"x").status,
        200,
    );

    // A GET whose client reads its headers and a little, then nothing.
    let (host, target) = target(&c, "GET", "/chan/big");
    let mut s = TcpStream::connect(&host).expect("connect");
    write!(s, "GET {target} HTTP/1.1\r\nHost: {host}\r\n\r\n").unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let (status, _) = read_head(&mut r).expect("the headers");
    assert_eq!(status, 200);
    let mut some = vec![0u8; 64 * 1024];
    r.read_exact(&mut some).expect("the start of the body");
    // Long enough for the socket buffers to fill and the read-ahead to wait.
    std::thread::sleep(Duration::from_secs(2));
    for i in 1..4 {
        let key = format!("/chan/small-{i}");
        prompt(
            "a HEAD while a GET stalls",
            &|| c.request("HEAD", &key, &[]).status,
            200,
        );
        prompt(
            "a delete while a GET stalls",
            &|| c.request("DELETE", &key, &[]).status,
            204,
        );
    }
    prompt(
        "a PUT while a GET stalls",
        &|| c.request("PUT", "/chan/during", b"y").status,
        200,
    );
    prompt(
        "a delete of the object being read",
        &|| c.request("DELETE", "/chan/big", &[]).status,
        204,
    );
    drop(r);
    drop(s);
}

/// A copy that has to rewrite its source's bytes (here into an SSE-C
/// copy) takes them as a PUT takes a body: a source larger than a body read
/// whole is streamed from its stripes to the copy's, never held whole, and
/// the copy reads back as the source. (Over 100 MiB, it used to be
/// refused.)
#[test]
fn a_rewriting_copy_of_a_large_source_streams() {
    let c = Cluster::start_with_ec(6, 4, 2);
    c.json("POST", "/_admin/buckets", json!({"name": "cp"}))
        .expect_ok();
    // 110 MiB, over the 100 MiB a copy used to take.
    multipart_put(&c, "/cp/big", 2, |n| pattern(55 * MIB, n));
    let key = [3u8; 32];
    let b64 = |b: &[u8]| {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b)
    };
    let (k, md5) = (b64(&key), b64(&md5::Md5::digest(key)));
    let sse_c = [
        ("x-amz-server-side-encryption-customer-algorithm", "AES256"),
        ("x-amz-server-side-encryption-customer-key", k.as_str()),
        (
            "x-amz-server-side-encryption-customer-key-md5",
            md5.as_str(),
        ),
    ];
    let mut headers = vec![("x-amz-copy-source", "/cp/big")];
    headers.extend(sse_c);
    c.request_with_headers("PUT", "/cp/enc", &[], &headers)
        .expect(200);
    let got = c.request_with_headers("GET", "/cp/enc", &[], &sse_c);
    assert_eq!(got.status, 200, "{}", got.text());
    let mut want = pattern(55 * MIB, 1);
    want.extend(pattern(55 * MIB, 2));
    assert!(got.bytes == want, "the copy read back other bytes");
    assert_eq!(c.request("GET", "/cp/enc", &[]).status, 400, "no key");

    // Unencrypted, the copy shares the source's stripes: any size.
    c.request_with_headers("PUT", "/cp/plain", &[], &[("x-amz-copy-source", "/cp/big")])
        .expect(200);
    let got = c.request_with_headers("GET", "/cp/plain", &[], &[("range", "bytes=0-1023")]);
    assert!(got.bytes == pattern(55 * MIB, 1)[..1024]);
}
