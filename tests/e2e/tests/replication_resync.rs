//! Bucket replication, phase 2 (architecture/design/s3/
//! bucket-replication.md): a resync sends a bucket's existing versions to a
//! target, picking up where it was after the source restarts; and a
//! target's bandwidth limit holds, the fast path and a resync sharing it.

use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use serde_json::{Value, json};

fn payload(len: usize, seed: u32) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ u64::from(seed);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

fn versioned_bucket(c: &Cluster, name: &str) {
    c.json("POST", "/_admin/buckets", json!({ "name": name }))
        .expect_ok();
    c.request(
        "PUT",
        &format!("/{name}?versioning"),
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    )
    .expect(200);
}

/// `dst`'s bucket `dst` as `src`'s target `dr`, sent to at up to
/// `bandwidth` bytes a second (0: no limit).
fn add_target(src: &Cluster, dst: &Cluster, bandwidth: u64) {
    src.json(
        "POST",
        "/_admin/replication/targets",
        json!({
            "name": "dr",
            "endpoint": dst.endpoint,
            "bucket": "dst",
            "access_key": dst.access_key,
            "secret_key": dst.secret_key,
            "bandwidth": bandwidth,
        }),
    )
    .expect_ok();
}

fn rules(src: &Cluster) {
    src.request(
        "PUT",
        "/src?replication",
        b"<ReplicationConfiguration><Rule><ID>all</ID><Status>Enabled</Status>\
          <Filter><Prefix></Prefix></Filter>\
          <Destination><Bucket>arn:obio:replication:::dr</Bucket></Destination>\
          </Rule></ReplicationConfiguration>",
    )
    .expect(200);
}

/// Write `n` objects of `size` bytes as `{prefix}{i:05}`, eight at a time;
/// their keys, version ids and bytes.
fn write(src: &Cluster, prefix: &str, count: u32, size: usize) -> Vec<(String, String, Vec<u8>)> {
    let next = std::sync::atomic::AtomicU32::new(0);
    let written = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if index >= count {
                        return;
                    }
                    let key = format!("{prefix}{index:05}");
                    let body = payload(size, index);
                    let put = src.request("PUT", &format!("/src/{key}"), &body);
                    put.expect(200);
                    let version = put.header("x-amz-version-id").expect("a version id");
                    written.lock().unwrap().push((key, version, body));
                }
            });
        }
    });
    written.into_inner().unwrap()
}

/// The resync of `src` to `dr`, as the admin API shows it.
fn resync(src: &Cluster) -> Value {
    let r = src.request("GET", "/_admin/replication/resync?bucket=src", &[]);
    r.expect(200);
    r.json()["resyncs"]
        .as_array()
        .and_then(|a| a.iter().find(|x| x["target"] == "dr").cloned())
        .unwrap_or(Value::Null)
}

fn await_resync(
    src: &Cluster,
    done: impl Fn(&Value) -> bool,
    within: Duration,
    what: &str,
) -> Value {
    let deadline = Instant::now() + within;
    loop {
        let r = resync(src);
        if done(&r) {
            return r;
        }
        assert!(Instant::now() < deadline, "{what}; the resync: {r}");
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Every one of `written` is on the target, the same bytes under the same
/// version id.
fn assert_all_on_target(dst: &Cluster, written: &[(String, String, Vec<u8>)]) {
    for (key, vid, body) in written {
        let r = dst.request("GET", &format!("/dst/{key}?versionId={vid}"), &[]);
        assert_eq!(r.status, 200, "{key} {vid} is not on the target");
        assert!(
            r.bytes == *body,
            "{key} {vid} has other bytes on the target"
        );
    }
}

/// Objects written before the bucket had rules aren't replicated; a resync
/// sends them all. Asked again, a resync with `again` sends a version the
/// target has lost; one without leaves versions already sent alone.
#[test]
fn a_resync_sends_existing_objects() {
    let src = Cluster::start_with_ec_and_args(6, 4, 2, &["--replication-scan-secs", "1"]);
    let dst = Cluster::start_with_ec(6, 4, 2);
    versioned_bucket(&src, "src");
    versioned_bucket(&dst, "dst");
    let mut written = write(&src, "old/", 30, 3_000);
    // A second version of one key, and a delete marker (no rule sends
    // markers here, so it stays).
    let again = payload(5_000, 99);
    let r = src.request("PUT", "/src/old/00000", &again);
    written.push((
        "old/00000".into(),
        r.header("x-amz-version-id").unwrap(),
        again,
    ));
    src.request("DELETE", "/src/old/00001", &[]).expect(204);
    add_target(&src, &dst, 0);
    rules(&src);

    // A resync needs a rule that sends to the target, and the caller to be
    // an admin of the bucket's tenant.
    src.json(
        "POST",
        "/_admin/replication/resync",
        json!({"bucket": "src", "target": "elsewhere"}),
    )
    .expect(400);
    let started = src.json(
        "POST",
        "/_admin/replication/resync",
        json!({"bucket": "src", "target": "dr"}),
    );
    started.expect(202);
    assert_eq!(started.json()["state"], "running");

    let done = await_resync(
        &src,
        |r| r["state"] == "done",
        Duration::from_secs(60),
        "the resync never finished",
    );
    assert_all_on_target(&dst, &written);
    assert_eq!(done["sent"], 31, "{done}");
    assert_eq!(done["failed"], 0, "{done}");
    // 31 versions and a delete marker no rule sends.
    assert_eq!(done["scanned"], 32, "{done}");
    assert_eq!(done["covered"], 31, "{done}");
    let head = src.request("HEAD", "/src/old/00002", &[]);
    assert_eq!(
        head.header("x-amz-replication-status").as_deref(),
        Some("COMPLETED")
    );

    // The target loses a version; a resync without `again` doesn't notice
    // (the source has it as sent), one with `again` sends it back.
    let (key, vid, body) = &written[3];
    dst.request("DELETE", &format!("/dst/{key}?versionId={vid}"), &[])
        .expect(204);
    src.json(
        "POST",
        "/_admin/replication/resync",
        json!({"bucket": "src", "target": "dr"}),
    )
    .expect(202);
    let plain = await_resync(
        &src,
        |r| r["state"] == "done",
        Duration::from_secs(60),
        "the second resync never finished",
    );
    assert_eq!(plain["marked"], 0, "{plain}");
    assert_eq!(plain["sent"], 0, "{plain}");
    assert_eq!(
        dst.request("GET", &format!("/dst/{key}?versionId={vid}"), &[])
            .status,
        404
    );
    src.json(
        "POST",
        "/_admin/replication/resync",
        json!({"bucket": "src", "target": "dr", "again": true}),
    )
    .expect(202);
    let resent = await_resync(
        &src,
        |r| r["state"] == "done",
        Duration::from_secs(60),
        "the resync with again never finished",
    );
    assert_eq!(resent["marked"], 31, "{resent}");
    assert_eq!(resent["sent"], 31, "{resent}");
    let back = dst.request("GET", &format!("/dst/{key}?versionId={vid}"), &[]);
    assert_eq!(back.status, 200);
    assert!(back.bytes == *body);
}

/// The source stops in the middle of a resync (kill, as a crash): started
/// again, the resync goes on from the last page it finished, not from the
/// start, and every object reaches the target.
#[test]
fn a_resync_resumes_after_a_restart() {
    let mut src = Cluster::start_with_ec_and_args(6, 4, 2, &["--replication-scan-secs", "1"]);
    let dst = Cluster::start_with_ec(6, 4, 2);
    versioned_bucket(&src, "src");
    versioned_bucket(&dst, "dst");
    // Two pages (a page is 1000 keys), sent slowly enough (64 KiB/s: about
    // 16 s for the first page, 8 s for the second) to stop it in the
    // second.
    let written = write(&src, "k/", 1_500, 1_024);
    add_target(&src, &dst, 64 << 10);
    rules(&src);
    src.json(
        "POST",
        "/_admin/replication/resync",
        json!({"bucket": "src", "target": "dr"}),
    )
    .expect(202);
    let first = await_resync(
        &src,
        |r| r["after"].as_str().is_some_and(|a| !a.is_empty()),
        Duration::from_secs(120),
        "the first page never finished",
    );
    assert_eq!(first["state"], "running", "{first}");
    assert_eq!(first["scanned"], 1_000, "{first}");

    src.restart();

    let done = await_resync(
        &src,
        |r| r["state"] == "done",
        Duration::from_secs(240),
        "the resync never finished after the restart",
    );
    // Each version counted once: the first page wasn't taken again.
    assert_eq!(done["scanned"], 1_500, "{done}");
    assert_eq!(done["failed"], 0, "{done}");
    assert_all_on_target(&dst, &written);
}

/// `objectio_replication_bytes_total{target="dr"}` on the source.
fn bytes_sent(src: &Cluster) -> u64 {
    src.request("GET", "/metrics", &[])
        .text()
        .lines()
        .find(|l| l.starts_with("objectio_replication_bytes_total{target=\"dr\"}"))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// A target's limit holds for everything sent to it: a resync of existing
/// objects and the fast path's new ones together go no faster than it, over
/// any few seconds, and all of them arrive.
#[test]
fn a_targets_bandwidth_limit_holds() {
    const LIMIT: u64 = 256 << 10;
    const SIZE: usize = 64 << 10;
    // Sends a gateway may have in flight to one target: the fast path's 8
    // and a resync's 8. The metric counts a send once the target has taken
    // it, so a slow target bunches up the counts of all of them.
    const IN_FLIGHT: u64 = 16;
    let src = Cluster::start_with_ec_and_args(6, 4, 2, &["--replication-scan-secs", "1"]);
    let dst = Cluster::start_with_ec(6, 4, 2);
    versioned_bucket(&src, "src");
    versioned_bucket(&dst, "dst");
    let mut written = write(&src, "old/", 48, SIZE);
    add_target(&src, &dst, LIMIT);
    rules(&src);

    let started = Instant::now();
    src.json(
        "POST",
        "/_admin/replication/resync",
        json!({"bucket": "src", "target": "dr"}),
    )
    .expect(202);
    // New writes meanwhile, sent by the fast path, at the same pace.
    let arrived = std::sync::atomic::AtomicBool::new(false);
    let (samples, elapsed) = std::thread::scope(|s| {
        let sampler = s.spawn(|| {
            let mut samples = Vec::new();
            while !arrived.load(std::sync::atomic::Ordering::Relaxed) {
                samples.push((started.elapsed(), bytes_sent(&src)));
                std::thread::sleep(Duration::from_millis(250));
            }
            samples
        });
        written.extend(write(&src, "new/", 16, SIZE));
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut waiting = written.clone();
        while !waiting.is_empty() {
            assert!(
                Instant::now() < deadline,
                "{} objects never reached the target",
                waiting.len()
            );
            waiting.retain(|(key, vid, _)| {
                dst.request("HEAD", &format!("/dst/{key}?versionId={vid}"), &[])
                    .status
                    != 200
            });
            std::thread::sleep(Duration::from_millis(100));
        }
        let elapsed = started.elapsed();
        arrived.store(true, std::sync::atomic::Ordering::Relaxed);
        (sampler.join().unwrap(), elapsed)
    });
    let total = (written.len() * SIZE) as u64;
    assert!(
        bytes_sent(&src) >= total,
        "the source counted {} bytes sent of {total}",
        bytes_sent(&src)
    );

    // As a whole: 4 MiB at 256 KiB/s is 16 s; 10% off for the clocks.
    let least_ms = total * 1000 / LIMIT * 9 / 10;
    assert!(
        elapsed >= Duration::from_millis(least_ms),
        "{total} bytes sent in {elapsed:?}, faster than the limit allows"
    );
    // Over any 4 s: at most the limit's 1 MiB (15% off for the samples'
    // timing), and the sends already paced and under way when the window
    // opened (`IN_FLIGHT`). The pace itself is the whole run's time, above.
    let window = Duration::from_secs(4);
    for (i, (t0, b0)) in samples.iter().enumerate() {
        for (t1, b1) in &samples[i + 1..] {
            let span = t1.saturating_sub(*t0);
            if span > window {
                break;
            }
            let span_ms = u64::try_from(span.as_millis()).unwrap_or(u64::MAX);
            let allowed = LIMIT * span_ms / 1000 * 115 / 100 + IN_FLIGHT * SIZE as u64;
            assert!(
                b1 - b0 <= allowed,
                "{} bytes sent between {t0:?} and {t1:?}: over the limit",
                b1 - b0
            );
        }
    }
    assert_all_on_target(&dst, &written);
}
