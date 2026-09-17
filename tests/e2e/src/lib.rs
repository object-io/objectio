//! Harness for end-to-end tests: boots a real `objectio-aio` cluster and
//! drives it over HTTP the way a client does.
//!
//! Every test in this crate exercises a *seam* — gateway to OSD, meta to
//! placement, handler to auth gate. That is deliberate: the workspace has
//! hundreds of unit tests and they are good at what they cover, but of the
//! defects found in this codebase's storage and admin layers, most lived
//! between two components and none of them could have been caught inside
//! one. A unit test cannot see that the gateway never calls `DeleteShard`.
//!
//! `objectio-aio` runs meta, OSD and gateway as tokio tasks in one process,
//! which makes it an unusually cheap thing to boot per test — a few seconds,
//! no containers, no ports to coordinate beyond the one we pick.

// A test harness panics on purpose — that is what an assertion is — and its
// constructors are called for their side effect of booting a cluster. The
// workspace's pedantic lints are right for library code and noise here.
#![allow(
    // A harness panics on purpose — that is what an assertion is — and its
    // constructors are called for the side effect of booting a cluster.
    clippy::must_use_candidate,
    clippy::missing_panics_doc,
    // The date maths below is Howard Hinnant's civil-from-days, transcribed.
    // Its casts are load-bearing and rewriting them to satisfy the lint would
    // make a well-known algorithm harder to check against the original.
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    // Readability over micro-optimisation in test support code.
    clippy::format_collect,
    clippy::needless_pass_by_value
)]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// A running single-process cluster. Killed on drop, so a panicking test
/// cannot leave a gateway holding a port.
pub struct Cluster {
    child: Child,
    pub endpoint: String,
    pub access_key: String,
    pub secret_key: String,
    #[allow(dead_code)]
    data_dir: tempfile::TempDir,
    /// Kept so the cluster can be restarted on the same data and port.
    port: u16,
    osds: usize,
}

impl Drop for Cluster {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn aio_binary() -> PathBuf {
    // CARGO_BIN_EXE_ is only set for the package that declares the binary, so
    // walk out of the test executable's directory instead. `cargo test`
    // places integration tests in target/<profile>/deps/.
    let mut dir = std::env::current_exe().expect("current_exe");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    let direct = dir.join("objectio-aio");
    if direct.exists() {
        return direct;
    }
    // Fall back to the workspace target dir, for a `cargo test -p` run whose
    // profile directory differs.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root");
    for profile in ["debug", "release"] {
        let candidate = root.join("target").join(profile).join("objectio-aio");
        if candidate.exists() {
            return candidate;
        }
    }
    panic!(
        "objectio-aio binary not found — run `cargo build --bin objectio-aio` first \
         (looked in {})",
        dir.display()
    );
}

/// Pick a free port by binding :0 and releasing it.
///
/// Racy in principle, but aio is started immediately after and takes
/// `--strict-port`, so a collision fails loudly rather than silently landing
/// on a different port than the test then talks to.
fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind :0");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

impl Cluster {
    /// Boot a cluster with auth on and wait until it serves.
    pub fn start() -> Self {
        Self::start_with_osds(1)
    }

    pub fn start_with_osds(osds: usize) -> Self {
        let data_dir = tempfile::tempdir().expect("tempdir");
        let port = free_port();

        let child = Command::new(aio_binary())
            .arg("--data")
            .arg(data_dir.path())
            .arg("--port")
            .arg(port.to_string())
            .arg("--listen-addr")
            .arg("127.0.0.1")
            .arg("--strict-port")
            .arg("--osds")
            .arg(osds.to_string())
            .arg("--auth")
            // Both discarded unless asked for. tracing writes to *stdout*
            // here, so an unread pipe wedges the child once its 64 KiB buffer
            // fills — which presents as the cluster hanging at startup with no
            // clue why. Set OBJECTIO_E2E_LOGS=1 to watch it instead.
            .stdout(Self::log_target())
            .stderr(Self::log_target())
            .spawn()
            .expect("spawn objectio-aio");

        // Credentials come from the file meta writes, not from scraping the
        // log. The banner is interleaved with tracing output and its format is
        // presentational; admin-creds.env is a contract.
        let creds_path = data_dir.path().join("meta").join("admin-creds.env");
        let (access_key, secret_key) = Self::await_credentials(&creds_path);

        let endpoint = format!("http://127.0.0.1:{port}");
        let mut cluster = Self {
            child,
            endpoint,
            access_key,
            secret_key,
            data_dir,
            port,
            osds,
        };
        cluster.wait_healthy();
        cluster
    }

    /// Stop the cluster and start it again on the same data directory and
    /// port, the way a `systemctl restart` does.
    ///
    /// Returns once the gateway is serving again, so a test that reads
    /// straight afterwards is asking the question a client would: is the
    /// cluster usable the moment it says it is up?
    pub fn restart(&mut self) {
        self.restart_with_osds(self.osds);
    }

    /// Restart with a different number of OSDs than last time.
    ///
    /// Coming back with fewer leaves the departed ones registered in meta but
    /// not running — a stale registration, which is exactly the state a live
    /// cluster ends up in after an OSD is replaced or its identity is reset.
    pub fn restart_with_osds(&mut self, osds: usize) {
        self.osds = osds;
        let _ = self.child.kill();
        let _ = self.child.wait();

        self.child = Command::new(aio_binary())
            .arg("--data")
            .arg(self.data_dir.path())
            .arg("--port")
            .arg(self.port.to_string())
            .arg("--listen-addr")
            .arg("127.0.0.1")
            .arg("--strict-port")
            .arg("--osds")
            .arg(self.osds.to_string())
            .arg("--auth")
            .stdout(Self::log_target())
            .stderr(Self::log_target())
            .spawn()
            .expect("respawn objectio-aio");

        self.wait_healthy();
    }

    fn log_target() -> Stdio {
        if std::env::var_os("OBJECTIO_E2E_LOGS").is_some() {
            Stdio::inherit()
        } else {
            Stdio::null()
        }
    }

    /// Poll for `admin-creds.env` and parse the two keys out of it.
    ///
    /// Meta writes it on first boot as `export KEY=VALUE` lines.
    fn await_credentials(path: &std::path::Path) -> (String, String) {
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(path) {
                let mut access = String::new();
                let mut secret = String::new();
                for line in text.lines() {
                    if let Some(v) = line.split("AWS_ACCESS_KEY_ID=").nth(1) {
                        access = v.trim().to_string();
                    }
                    if let Some(v) = line.split("AWS_SECRET_ACCESS_KEY=").nth(1) {
                        secret = v.trim().to_string();
                    }
                }
                if !access.is_empty() && !secret.is_empty() {
                    return (access, secret);
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!(
            "admin credentials never appeared at {} — run with OBJECTIO_E2E_LOGS=1 to see why",
            path.display()
        );
    }

    /// Wait until the *gateway* is serving on this port.
    ///
    /// `/health` is not enough on its own: meta and the OSD each serve one on
    /// their metrics listeners, so a 200 there proves only that some `ObjectIO`
    /// process holds the port. When a subsystem was handed the gateway's port
    /// this returned immediately and the first real request came back as a
    /// bare 404 — which reads like a missing route rather than the wrong
    /// server. Probe an admin route as well: unauthenticated it answers 401,
    /// and only the gateway has it at all.
    fn wait_healthy(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(90);
        let client = reqwest::blocking::Client::new();
        let mut last = String::from("no response");
        while Instant::now() < deadline {
            // A child that has already exited will never become healthy.
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "objectio-aio exited during startup with {status}; \
                        set OBJECTIO_E2E_LOGS=1 to see why"
                );
            }
            match client.get(format!("{}/_admin/nodes", self.endpoint)).send() {
                Ok(r) if r.status() == 401 => return,
                Ok(r) => {
                    last = format!(
                        "{} answered /_admin/nodes with {}",
                        self.endpoint,
                        r.status()
                    );
                }
                Err(e) => last = e.to_string(),
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        panic!("the gateway did not come up within 90s — {last}");
    }

    /// Build a presigned URL: `SigV4` credentials in the query string, no
    /// `Authorization` header, valid for `expires_secs`.
    ///
    /// Signed here rather than by calling the gateway's own code, so the tests
    /// check the server against an independent implementation of the spec
    /// rather than against itself.
    pub fn presign(&self, method: &str, path: &str, expires_secs: u64) -> String {
        self.presign_as(
            method,
            path,
            expires_secs,
            &self.access_key,
            &self.secret_key,
        )
    }

    /// As [`Self::presign`], with a chosen key, and with the signing time
    /// shifted by `age_secs` into the past so an expired link can be built.
    pub fn presign_at(&self, method: &str, path: &str, expires_secs: u64, age_secs: i64) -> String {
        self.presign_inner(
            method,
            path,
            expires_secs,
            &self.access_key,
            &self.secret_key,
            age_secs,
        )
    }

    pub fn presign_as(
        &self,
        method: &str,
        path: &str,
        expires_secs: u64,
        access_key: &str,
        secret_key: &str,
    ) -> String {
        self.presign_inner(method, path, expires_secs, access_key, secret_key, 0)
    }

    fn presign_inner(
        &self,
        method: &str,
        path: &str,
        expires_secs: u64,
        access_key: &str,
        secret_key: &str,
        age_secs: i64,
    ) -> String {
        let host = self.endpoint.trim_start_matches("http://").to_string();
        let (path_only, extra_query) = match path.split_once('?') {
            Some((p, q)) => (p, q),
            None => (path, ""),
        };
        let escaped_path = escape_path(path_only);

        let (amz_date, date_stamp) = time_at(-age_secs);
        let scope = format!("{date_stamp}/us-east-1/s3/aws4_request");
        let credential = format!("{access_key}/{scope}");

        // Every X-Amz-* parameter except the signature is part of what is
        // signed, and the canonical query string is sorted by name.
        let mut params: Vec<(String, String)> = vec![
            ("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into()),
            ("X-Amz-Credential".into(), credential),
            ("X-Amz-Date".into(), amz_date.clone()),
            ("X-Amz-Expires".into(), expires_secs.to_string()),
            ("X-Amz-SignedHeaders".into(), "host".into()),
        ];
        for pair in extra_query.split('&').filter(|p| !p.is_empty()) {
            match pair.split_once('=') {
                Some((k, v)) => params.push((k.to_string(), v.to_string())),
                None => params.push((pair.to_string(), String::new())),
            }
        }
        let mut encoded: Vec<(String, String)> = params
            .into_iter()
            .map(|(k, v)| (escape(&k), escape(&v)))
            .collect();
        encoded.sort();
        let canonical_qs = encoded
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");

        // A presigned S3 request signs the literal `UNSIGNED-PAYLOAD`: the URL
        // exists before the body does.
        let canonical_request = format!(
            "{method}\n{escaped_path}\n{canonical_qs}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD"
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        let mut key = hmac(format!("AWS4{secret_key}").as_bytes(), &date_stamp);
        key = hmac(&key, "us-east-1");
        key = hmac(&key, "s3");
        key = hmac(&key, "aws4_request");
        let signature = hex::encode(hmac(&key, &string_to_sign));

        format!(
            "{}{escaped_path}?{canonical_qs}&X-Amz-Signature={signature}",
            self.endpoint
        )
    }

    /// Fetch a URL with no credentials of any kind — what a client handed a
    /// presigned link actually does.
    pub fn fetch(&self, method: &str, url: &str, body: &[u8]) -> Response {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap();
        let mut req = client.request(method.parse().expect("method"), url);
        if !body.is_empty() {
            req = req.body(body.to_vec());
        }
        let resp = req.send().expect("request");
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let bytes = resp.bytes().expect("body").to_vec();
        Response {
            status,
            bytes,
            headers,
        }
    }

    /// Signed request. `body` is sent as-is; pass `&[]` for none.
    pub fn request(&self, method: &str, path: &str, body: &[u8]) -> Response {
        self.request_as(method, path, body, &self.access_key, &self.secret_key)
    }

    /// Signed request carrying extra headers that are *not* signed.
    ///
    /// `SigV4` only covers the headers named in `SignedHeaders`, and real clients
    /// do not sign `Range`, so sending it unsigned is what an SDK does.
    pub fn request_with_headers(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        extra: &[(&str, &str)],
    ) -> Response {
        self.request_inner(
            method,
            path,
            body,
            &self.access_key,
            &self.secret_key,
            extra,
        )
    }

    /// Signed request with specific credentials — for testing what a scoped
    /// or tenant-scoped key is allowed to do.
    pub fn request_as(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        access_key: &str,
        secret_key: &str,
    ) -> Response {
        self.request_inner(method, path, body, access_key, secret_key, &[])
    }

    fn request_inner(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        access_key: &str,
        secret_key: &str,
        extra_headers: &[(&str, &str)],
    ) -> Response {
        let payload_hash = hex::encode(Sha256::digest(body));
        let host = self.endpoint.trim_start_matches("http://").to_string();
        let (path_only, query) = match path.split_once('?') {
            Some((p, q)) => (p, q),
            None => (path, ""),
        };

        // Escape once, here, and use the result for BOTH the canonical request
        // and the URL that is sent. Signing one spelling and sending another
        // is the classic SigV4 failure, and it surfaces as
        // SignatureDoesNotMatch — which reads like bad credentials.
        let escaped_path = escape_path(path_only);

        let now = time_now();
        let amz_date = now.0;
        let date_stamp = now.1;
        let mut headers: Vec<(&str, String)> = vec![
            ("host", host),
            ("x-amz-content-sha256", payload_hash.clone()),
            ("x-amz-date", amz_date.clone()),
        ];
        let json_body = !body.is_empty();
        if json_body {
            headers.push(("content-type", "application/json".into()));
        }
        headers.sort_by(|a, b| a.0.cmp(b.0));

        let canonical_headers: String = headers
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect();
        let signed_headers: Vec<&str> = headers.iter().map(|(k, _)| *k).collect();
        let signed_headers = signed_headers.join(";");

        let canonical_request = format!(
            "{method}\n{escaped_path}\n{}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
            canonical_query(query),
        );
        let scope = format!("{date_stamp}/us-east-1/s3/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );

        let mut key = hmac(format!("AWS4{secret_key}").as_bytes(), &date_stamp);
        key = hmac(&key, "us-east-1");
        key = hmac(&key, "s3");
        key = hmac(&key, "aws4_request");
        let signature = hex::encode(hmac(&key, &string_to_sign));

        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap();
        let mut req = client
            .request(
                method.parse().expect("method"),
                if query.is_empty() {
                    format!("{}{escaped_path}", self.endpoint)
                } else {
                    format!("{}{escaped_path}?{}", self.endpoint, canonical_query(query))
                },
            )
            .header("X-Amz-Date", &amz_date)
            .header("X-Amz-Content-Sha256", &payload_hash)
            .header(
                "Authorization",
                format!(
                    "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, \
                     SignedHeaders={signed_headers}, Signature={signature}"
                ),
            );
        for (k, v) in extra_headers {
            req = req.header(*k, *v);
        }
        if json_body {
            req = req.header("Content-Type", "application/json");
        }
        if !body.is_empty() {
            req = req.body(body.to_vec());
        }

        let resp = req.send().expect("request");
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_ascii_lowercase(),
                    v.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let bytes = resp.bytes().expect("body").to_vec();
        Response {
            status,
            bytes,
            headers,
        }
    }

    /// Convenience: signed request whose body is JSON.
    pub fn json(&self, method: &str, path: &str, body: serde_json::Value) -> Response {
        self.request(method, path, body.to_string().as_bytes())
    }

    /// Bytes currently used on the first disk of the first online OSD.
    ///
    /// The whole point of several tests below: this was hardcoded to zero for
    /// the life of the project, so a disk could be full while reporting empty.
    pub fn used_bytes(&self) -> u64 {
        let r = self.request("GET", "/_admin/nodes", &[]);
        assert_eq!(r.status, 200, "GET /_admin/nodes: {}", r.text());
        let v: serde_json::Value = r.json();
        for node in v["nodes"].as_array().expect("nodes") {
            if node["online"].as_bool() == Some(true)
                && let Some(disk) = node["disks"].as_array().and_then(|d| d.first())
            {
                return disk["used_capacity"].as_u64().unwrap_or(0);
            }
        }
        panic!("no online OSD with a disk");
    }
}

pub struct Response {
    pub status: u16,
    pub bytes: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl Response {
    /// A response header, lowercased name.
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }
}

impl Response {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).to_string()
    }
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.bytes)
            .unwrap_or_else(|e| panic!("body was not JSON ({e}): {}", self.text()))
    }
    /// Any 2xx. For steps that are setup rather than the assertion — which
    /// create returns 200 and which 201 is not what these tests are about,
    /// and pinning it makes them break on an unrelated change.
    #[track_caller]
    pub fn expect_ok(&self) -> &Self {
        assert!(
            (200..300).contains(&self.status),
            "expected 2xx, got {}: {}",
            self.status,
            self.text()
        );
        self
    }

    #[track_caller]
    pub fn expect(&self, status: u16) -> &Self {
        assert_eq!(
            self.status,
            status,
            "expected {status}, got {}: {}",
            self.status,
            self.text()
        );
        self
    }
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// `(amz_date, date_stamp)` in UTC, without pulling in chrono.
fn time_now() -> (String, String) {
    time_at(0)
}

/// As [`time_now`], `offset_secs` away from now. Negative is the past, which
/// is how a test builds a link that has already expired.
fn time_at(offset_secs: i64) -> (String, String) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .saturating_add_signed(offset_secs);
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    (
        format!(
            "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
            tod / 3600,
            (tod % 3600) / 60,
            tod % 60
        ),
        format!("{y:04}{m:02}{d:02}"),
    )
}

/// Howard Hinnant's days-from-civil, inverted. Avoids a chrono dependency in
/// a harness that needs exactly one date format.
const fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn escape_path(path: &str) -> String {
    path.split('/').map(escape).collect::<Vec<_>>().join("/")
}

fn escape(s: &str) -> String {
    const UNRESERVED: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~";
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        if UNRESERVED.contains(b) {
            out.push(*b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let mut parts: Vec<(String, String)> = query
        .split('&')
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (escape(k), escape(v)),
            None => (escape(kv), String::new()),
        })
        .collect();
    parts.sort();
    parts
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}
