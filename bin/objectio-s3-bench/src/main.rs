//! S3 PUT/GET load generator that reports where a request's time went.
//!
//! Usage:
//!
//! ```text
//! objectio-s3-bench \
//!     --endpoint http://127.0.0.1:9000 \
//!     --size 4MiB --objects 200 --concurrency 16 --op both
//! ```
//!
//! Besides client-side throughput and latency percentiles, it scrapes the
//! gateway's `/metrics` before and after each phase and prints the mean time
//! per call of each stage on the data path:
//!
//! * erasure encode / decode on the gateway CPU
//! * a shard write or read as the gateway sees it (network + OSD)
//! * the same call as the OSD's gRPC handler sees it (disk + WAL)
//! * the WAL fsync inside that
//!
//! The difference between the gateway's view of a shard call and the OSD's
//! view of it is the transport — framing, copies and the network. That is
//! the part an RDMA data path can remove, so it is the number to read before
//! deciding whether one is worth building.
//!
//! Stage times come from histograms the servers already export. OSD families
//! only appear when the gateway's `/metrics` includes them (aio does); point
//! `--metrics-url` elsewhere for a split deployment.
//!
//! Requests are signed as presigned URLs when credentials are given, and sent
//! unsigned otherwise (aio runs without auth by default).

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use futures::StreamExt;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(name = "objectio-s3-bench", about, version)]
struct Args {
    /// Gateway S3 endpoint.
    #[arg(long, default_value = "http://127.0.0.1:9000")]
    endpoint: String,

    /// Where to scrape stage metrics. Defaults to `<endpoint>/metrics`.
    #[arg(long)]
    metrics_url: Option<String>,

    /// Access key. Leave unset to send unsigned requests.
    #[arg(long, env = "AWS_ACCESS_KEY_ID")]
    access_key: Option<String>,

    #[arg(long, env = "AWS_SECRET_ACCESS_KEY", hide_env_values = true)]
    secret_key: Option<String>,

    #[arg(long, default_value = "us-east-1")]
    region: String,

    /// Bucket to use; created if missing.
    #[arg(long, default_value = "s3-bench")]
    bucket: String,

    /// Object size, e.g. `65536`, `64KiB`, `4MiB`, `1GiB`.
    #[arg(long, default_value = "4MiB", value_parser = parse_size)]
    size: usize,

    /// Objects per phase.
    #[arg(long, default_value_t = 100)]
    objects: usize,

    /// Requests in flight at once.
    #[arg(long, default_value_t = 8)]
    concurrency: usize,

    #[arg(long, value_enum, default_value_t = Op::Both)]
    op: Op,

    /// How long to wait for the gateway's copy of the OSD metrics to catch
    /// up before each scrape, e.g. `40s`. The gateway polls OSDs every 30 s.
    #[arg(long, default_value = "40", value_parser = parse_secs)]
    metrics_wait: Duration,

    /// Delete the objects written by this run when it finishes.
    #[arg(long)]
    cleanup: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Op {
    Put,
    Get,
    Both,
}

fn parse_size(s: &str) -> Result<usize, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: usize = num.parse().map_err(|_| format!("bad size: {s}"))?;
    let mult = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1 << 10,
        "m" | "mb" | "mib" => 1 << 20,
        "g" | "gb" | "gib" => 1 << 30,
        other => return Err(format!("unknown size unit: {other}")),
    };
    n.checked_mul(mult)
        .ok_or_else(|| format!("size overflows: {s}"))
}

fn parse_secs(s: &str) -> Result<Duration, String> {
    s.trim_end_matches('s')
        .parse()
        .map(Duration::from_secs)
        .map_err(|_| format!("bad duration: {s}"))
}

// -------------------------------------------------------------------
// Signing
// -------------------------------------------------------------------

struct Signer {
    access_key: String,
    secret_key: String,
    region: String,
}

impl Signer {
    /// A presigned URL for `method` on `path`. Presigning signs
    /// `UNSIGNED-PAYLOAD`, so the body never has to be hashed — which keeps
    /// SHA-256 of the payload out of the numbers being measured.
    fn presign(&self, endpoint: &str, method: &str, path: &str) -> String {
        let host = endpoint
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/');
        let (amz_date, date_stamp) = utc_now();
        let scope = format!("{date_stamp}/{}/s3/aws4_request", self.region);
        let mut params = [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256".to_string()),
            ("X-Amz-Credential", format!("{}/{scope}", self.access_key)),
            ("X-Amz-Date", amz_date.clone()),
            ("X-Amz-Expires", "3600".to_string()),
            ("X-Amz-SignedHeaders", "host".to_string()),
        ]
        .map(|(k, v)| (escape(k), escape(&v)));
        params.sort();
        let qs = params
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        let path = path.split('/').map(escape).collect::<Vec<_>>().join("/");
        let canonical = format!("{method}\n{path}\n{qs}\nhost:{host}\n\nhost\nUNSIGNED-PAYLOAD");
        let to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical.as_bytes()))
        );
        let mut key = hmac(format!("AWS4{}", self.secret_key).as_bytes(), &date_stamp);
        for part in [self.region.as_str(), "s3", "aws4_request"] {
            key = hmac(&key, part);
        }
        let sig = hex::encode(hmac(&key, &to_sign));
        format!(
            "{}{path}?{qs}&X-Amz-Signature={sig}",
            endpoint.trim_end_matches('/')
        )
    }
}

fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key");
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// `(amz_date, date_stamp)` in UTC.
fn utc_now() -> (String, String) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs();
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400).cast_signed());
    let tod = secs % 86_400;
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

/// Howard Hinnant's civil-from-days.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
const fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// -------------------------------------------------------------------
// Client
// -------------------------------------------------------------------

struct Client {
    http: reqwest::Client,
    endpoint: String,
    signer: Option<Signer>,
}

impl Client {
    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let url = self.signer.as_ref().map_or_else(
            || format!("{}{path}", self.endpoint.trim_end_matches('/')),
            |s| s.presign(&self.endpoint, method.as_str(), path),
        );
        self.http.request(method, url)
    }

    async fn ensure_bucket(&self, bucket: &str) -> Result<()> {
        let resp = self
            .request(reqwest::Method::PUT, &format!("/{bucket}"))
            .send()
            .await
            .context("create bucket")?;
        // 409 is BucketAlreadyOwnedByYou / BucketAlreadyExists: fine for a rerun.
        if !resp.status().is_success() && resp.status().as_u16() != 409 {
            bail!(
                "create bucket {bucket}: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}

// -------------------------------------------------------------------
// Metrics
// -------------------------------------------------------------------

/// Every sample in a Prometheus text exposition, keyed by the full series
/// (`name{labels}`).
type Samples = BTreeMap<String, f64>;

async fn scrape(http: &reqwest::Client, url: &str) -> Samples {
    let Ok(resp) = http.get(url).send().await else {
        return Samples::new();
    };
    let Ok(text) = resp.text().await else {
        return Samples::new();
    };
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let (series, value) = l.rsplit_once(' ')?;
            Some((series.to_string(), value.parse().ok()?))
        })
        .collect()
}

/// A scrape whose OSD families have caught up with the gateway's own.
///
/// The gateway exports its own histograms live, but re-reads the OSDs' on a
/// background poll (every 30 s), so a scrape straight after a phase shows
/// gateway numbers for the phase next to OSD numbers from before it. Every
/// shard call the gateway times is also counted by an OSD, so once the OSD
/// counters reach the gateway's the two halves describe the same work.
async fn settled_scrape(http: &reqwest::Client, url: &str, wait: Duration) -> Samples {
    const GW: &str = "objectio_gateway_shard_latency_seconds_count";
    const OSD: &str = "objectio_osd_grpc_requests_total";
    let started = Instant::now();
    loop {
        let s = scrape(http, url).await;
        let caught_up =
            [("write", "WriteShard"), ("read", "ReadShard")]
                .iter()
                .all(|(dir, method)| {
                    let gw = total(&s, GW, &[&format!("direction=\"{dir}\"")]);
                    let osd = total(&s, OSD, &[&format!("method=\"{method}\"")]);
                    osd >= gw
                });
        // No OSD families at all: a split deployment, nothing to wait for.
        let has_osd = s.keys().any(|k| k.starts_with(OSD));
        if caught_up || !has_osd {
            return s;
        }
        if started.elapsed() >= wait {
            eprintln!("  (OSD metrics still behind after {wait:?}; OSD stages may be stale)");
            return s;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Sum of every series of `name` whose labels contain all of `labels`.
fn total(samples: &Samples, name: &str, labels: &[&str]) -> f64 {
    samples
        .iter()
        .filter(|(series, _)| {
            let (n, rest) = series.split_once('{').unwrap_or((series.as_str(), ""));
            n == name && labels.iter().all(|l| rest.contains(l))
        })
        .map(|(_, v)| v)
        .sum()
}

/// One stage on the data path: how its time is read out of `/metrics`.
struct Stage {
    label: &'static str,
    /// Series holding total seconds.
    sum: &'static str,
    /// Series holding the call count.
    count: &'static str,
    labels: &'static [&'static str],
}

const PUT_STAGES: &[Stage] = &[
    Stage {
        label: "S3 PutObject (server)",
        sum: "objectio_s3_request_duration_seconds_sum",
        count: "objectio_s3_request_duration_seconds_count",
        labels: &["operation=\"PutObject\""],
    },
    Stage {
        label: "erasure encode (per stripe)",
        sum: "objectio_erasure_encode_seconds_sum",
        count: "objectio_erasure_encode_seconds_count",
        labels: &[],
    },
    Stage {
        label: "shard write, gateway view",
        sum: "objectio_gateway_shard_latency_seconds_sum",
        count: "objectio_gateway_shard_latency_seconds_count",
        labels: &["direction=\"write\""],
    },
    Stage {
        label: "shard write, OSD handler",
        sum: "objectio_osd_grpc_latency_seconds_sum",
        count: "objectio_osd_grpc_requests_total",
        labels: &["method=\"WriteShard\""],
    },
    Stage {
        label: "WAL fsync",
        sum: "objectio_osd_wal_fsync_seconds_sum",
        count: "objectio_osd_wal_fsync_seconds_count",
        labels: &[],
    },
];

const GET_STAGES: &[Stage] = &[
    Stage {
        label: "S3 GetObject (server)",
        sum: "objectio_s3_request_duration_seconds_sum",
        count: "objectio_s3_request_duration_seconds_count",
        labels: &["operation=\"GetObject\""],
    },
    Stage {
        label: "erasure decode (per stripe)",
        sum: "objectio_erasure_decode_seconds_sum",
        count: "objectio_erasure_decode_seconds_count",
        labels: &[],
    },
    Stage {
        label: "shard read, gateway view",
        sum: "objectio_gateway_shard_latency_seconds_sum",
        count: "objectio_gateway_shard_latency_seconds_count",
        labels: &["direction=\"read\""],
    },
    Stage {
        label: "shard read, OSD handler",
        sum: "objectio_osd_grpc_latency_seconds_sum",
        count: "objectio_osd_grpc_requests_total",
        labels: &["method=\"ReadShard\""],
    },
];

/// Mean seconds per call of `stage` between two scrapes, and the call count.
fn stage_mean(stage: &Stage, before: &Samples, after: &Samples) -> Option<(f64, f64)> {
    let calls = total(after, stage.count, stage.labels) - total(before, stage.count, stage.labels);
    let secs = total(after, stage.sum, stage.labels) - total(before, stage.sum, stage.labels);
    (calls > 0.0).then(|| (secs / calls, calls))
}

fn print_stages(stages: &[Stage], before: &Samples, after: &Samples) {
    println!("  {:<30} {:>12} {:>10}", "stage", "mean/call", "calls");
    let mut means = Vec::with_capacity(stages.len());
    for stage in stages {
        let m = stage_mean(stage, before, after);
        match m {
            Some((mean, calls)) => {
                println!(
                    "  {:<30} {:>12} {:>10.0}",
                    stage.label,
                    fmt_secs(mean),
                    calls
                );
            }
            None => println!("  {:<30} {:>12} {:>10}", stage.label, "-", "0"),
        }
        means.push(m.map(|(mean, _)| mean));
    }
    // Stages 2 and 3 are the same shard call seen from each end.
    if let (Some(Some(gw)), Some(Some(osd))) = (means.get(2), means.get(3)) {
        println!(
            "  {:<30} {:>12}   (gateway view − OSD handler: framing, copies, network)",
            "=> transport",
            fmt_secs((gw - osd).max(0.0))
        );
    }
}

/// The gateway's per-phase split of one operation, in handler order.
fn print_phases(operation: &str, before: &Samples, after: &Samples) {
    const SUM: &str = "objectio_gateway_request_phase_seconds_sum";
    const COUNT: &str = "objectio_gateway_request_phase_seconds_count";
    const ORDER: &[&str] = &[
        "etag",
        "sse",
        "meta_lookup",
        "object_meta",
        "shards",
        "listing_commit",
    ];
    let op = format!("operation=\"{operation}\"");
    let mut phases: Vec<String> = after
        .keys()
        .filter(|k| k.starts_with(SUM) && k.contains(&op))
        .filter_map(|k| {
            let rest = k.split("phase=\"").nth(1)?;
            Some(rest.split('"').next()?.to_string())
        })
        .collect();
    if phases.is_empty() {
        return;
    }
    phases.sort_by_key(|p| ORDER.iter().position(|o| o == p).unwrap_or(ORDER.len()));
    println!("  gateway phases ({operation}):");
    for phase in phases {
        let labels = [op.as_str(), &format!("phase=\"{phase}\"")];
        let calls = total(after, COUNT, &labels) - total(before, COUNT, &labels);
        if calls > 0.0 {
            let secs = total(after, SUM, &labels) - total(before, SUM, &labels);
            println!("    {phase:<28} {:>12}", fmt_secs(secs / calls));
        }
    }
}

fn fmt_secs(s: f64) -> String {
    if s >= 1.0 {
        format!("{s:.2} s")
    } else if s >= 1e-3 {
        format!("{:.2} ms", s * 1e3)
    } else {
        format!("{:.1} µs", s * 1e6)
    }
}

// -------------------------------------------------------------------
// Phases
// -------------------------------------------------------------------

struct PhaseResult {
    latencies: Vec<Duration>,
    wall: Duration,
    bytes: usize,
    errors: usize,
}

async fn run_phase<F, Fut>(n: usize, concurrency: usize, op: F) -> PhaseResult
where
    F: Fn(usize) -> Fut + Send + Sync,
    Fut: Future<Output = Result<usize>> + Send,
{
    let started = Instant::now();
    let results: Vec<_> = futures::stream::iter(0..n)
        .map(|i| {
            let fut = op(i);
            async move {
                let t = Instant::now();
                let r = fut.await;
                (t.elapsed(), r)
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;
    let wall = started.elapsed();

    let mut latencies = Vec::with_capacity(n);
    let mut bytes = 0;
    let mut errors = 0;
    for (elapsed, r) in results {
        match r {
            Ok(b) => {
                latencies.push(elapsed);
                bytes += b;
            }
            Err(e) => {
                if errors == 0 {
                    eprintln!("  first error: {e:#}");
                }
                errors += 1;
            }
        }
    }
    latencies.sort_unstable();
    PhaseResult {
        latencies,
        wall,
        bytes,
        errors,
    }
}

#[allow(clippy::cast_precision_loss)]
fn print_phase(name: &str, r: &PhaseResult) {
    let ok = r.latencies.len();
    let secs = r.wall.as_secs_f64();
    let pct = |p: f64| {
        if ok == 0 {
            return "-".to_string();
        }
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let idx = (((ok - 1) as f64) * p).round() as usize;
        fmt_secs(r.latencies[idx].as_secs_f64())
    };
    println!("\n{name}: {ok} ok, {} failed in {secs:.2} s", r.errors);
    println!(
        "  throughput {:.1} MiB/s, {:.1} ops/s",
        r.bytes as f64 / 1_048_576.0 / secs,
        ok as f64 / secs
    );
    println!(
        "  latency p50 {}  p90 {}  p99 {}  max {}",
        pct(0.5),
        pct(0.9),
        pct(0.99),
        pct(1.0)
    );
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if args.concurrency == 0 || args.objects == 0 {
        bail!("--objects and --concurrency must be at least 1");
    }

    let signer = match (&args.access_key, &args.secret_key) {
        (Some(a), Some(s)) => Some(Signer {
            access_key: a.clone(),
            secret_key: s.clone(),
            region: args.region.clone(),
        }),
        (None, None) => None,
        _ => bail!("give both --access-key and --secret-key, or neither"),
    };
    let client = Arc::new(Client {
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(300))
            .build()?,
        endpoint: args.endpoint.clone(),
        signer,
    });
    let metrics_url = args
        .metrics_url
        .clone()
        .unwrap_or_else(|| format!("{}/metrics", args.endpoint.trim_end_matches('/')));

    client.ensure_bucket(&args.bucket).await?;

    // Random, so nothing downstream can compress or deduplicate it. One
    // buffer shared by every PUT: `Bytes` clones are a refcount bump.
    let mut payload = vec![0u8; args.size];
    rand::thread_rng().fill_bytes(&mut payload);
    let payload = Bytes::from(payload);

    let run_id = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let key = |i: usize| format!("/{}/bench-{run_id}/{i:06}", args.bucket);

    println!(
        "objectio-s3-bench: {} objects of {} bytes, concurrency {}, {}",
        args.objects,
        args.size,
        args.concurrency,
        if client.signer.is_some() {
            "signed"
        } else {
            "unsigned"
        }
    );

    // A GET-only run needs objects to read; write them unmeasured.
    if args.op == Op::Get {
        let r = run_phase(args.objects, args.concurrency, |i| {
            put(&client, key(i), payload.clone())
        })
        .await;
        if r.errors > 0 {
            bail!("{} PUTs failed while preparing the GET run", r.errors);
        }
    }

    if matches!(args.op, Op::Put | Op::Both) {
        let before = settled_scrape(&client.http, &metrics_url, args.metrics_wait).await;
        let r = run_phase(args.objects, args.concurrency, |i| {
            put(&client, key(i), payload.clone())
        })
        .await;
        let after = settled_scrape(&client.http, &metrics_url, args.metrics_wait).await;
        print_phase("PUT", &r);
        print_stages(PUT_STAGES, &before, &after);
        print_phases("PutObject", &before, &after);
    }

    if matches!(args.op, Op::Get | Op::Both) {
        let before = settled_scrape(&client.http, &metrics_url, args.metrics_wait).await;
        let r = run_phase(args.objects, args.concurrency, |i| {
            get(&client, key(i), args.size)
        })
        .await;
        let after = settled_scrape(&client.http, &metrics_url, args.metrics_wait).await;
        print_phase("GET", &r);
        print_stages(GET_STAGES, &before, &after);
        print_phases("GetObject", &before, &after);
    }

    if args.cleanup {
        let r = run_phase(args.objects, args.concurrency, |i| delete(&client, key(i))).await;
        println!(
            "\ncleanup: deleted {}, {} failed",
            r.latencies.len(),
            r.errors
        );
    }
    Ok(())
}

async fn put(client: &Client, path: String, body: Bytes) -> Result<usize> {
    let len = body.len();
    let resp = client
        .request(reqwest::Method::PUT, &path)
        .body(body)
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("PUT {path}: {}", resp.status());
    }
    Ok(len)
}

async fn get(client: &Client, path: String, expected: usize) -> Result<usize> {
    let resp = client.request(reqwest::Method::GET, &path).send().await?;
    if !resp.status().is_success() {
        bail!("GET {path}: {}", resp.status());
    }
    let body = resp.bytes().await?;
    if body.len() != expected {
        bail!("GET {path}: {} bytes, expected {expected}", body.len());
    }
    Ok(body.len())
}

async fn delete(client: &Client, path: String) -> Result<usize> {
    let resp = client
        .request(reqwest::Method::DELETE, &path)
        .send()
        .await?;
    if !resp.status().is_success() {
        bail!("DELETE {path}: {}", resp.status());
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sizes() {
        assert_eq!(parse_size("65536"), Ok(65536));
        assert_eq!(parse_size("64KiB"), Ok(64 << 10));
        assert_eq!(parse_size("4MiB"), Ok(4 << 20));
        assert_eq!(parse_size("1g"), Ok(1 << 30));
        assert!(parse_size("4XB").is_err());
    }

    #[test]
    fn sums_matching_series() {
        let s: Samples = [
            ("a_sum{direction=\"write\",address=\"x\"}".to_string(), 1.5),
            ("a_sum{direction=\"write\",address=\"y\"}".to_string(), 0.5),
            ("a_sum{direction=\"read\",address=\"x\"}".to_string(), 9.0),
            ("a_sum_other{direction=\"write\"}".to_string(), 9.0),
        ]
        .into_iter()
        .collect();
        assert!((total(&s, "a_sum", &["direction=\"write\""]) - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn civil_date() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_362), (2025, 10, 1));
    }
}
