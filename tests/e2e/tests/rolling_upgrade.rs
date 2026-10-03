//! A rolling upgrade from the previous release, node by node, under
//! traffic (objectio-docs core/upgrade-path.md, "How it is tested").
//!
//! Needs the previous release's binaries (a release with format levels):
//!
//! ```text
//! OBJECTIO_PREVIOUS_RELEASE_BIN=$(scripts/upgrade-test/previous-release.sh) \
//!   cargo test -p objectio-e2e --test rolling_upgrade
//! ```
//!
//! Without them the test says so and does nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use objectio_common::version::{FORMAT_LEVEL, RELEASE};
use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use serde_json::Value;

const METAS: usize = 3;
const OSDS: usize = 6;
const GATEWAYS: usize = 2;
const MASTER_KEY: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";

fn previous_release() -> Option<PathBuf> {
    std::env::var_os("OBJECTIO_PREVIOUS_RELEASE_BIN").map(PathBuf::from)
}

fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut x = 0x9E37_79B9_7F4A_7C15_u64 ^ seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x.to_le_bytes()[0]
        })
        .collect()
}

/// Objects known to be stored: path → bytes.
type Stored = Arc<Mutex<BTreeMap<String, Vec<u8>>>>;

/// Every stored object reads back byte for byte through `c`, retrying a
/// while for a node that is restarting.
fn assert_all_readable(c: &Cluster, stored: &Stored, when: &str) {
    let objects = stored.lock().unwrap().clone();
    assert!(!objects.is_empty());
    for (path, bytes) in &objects {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let why = match c.try_request("GET", path, &[]) {
                Ok(r) if r.status == 200 => {
                    assert!(r.bytes == *bytes, "{when}: {path} came back different");
                    break;
                }
                Ok(r) => format!("{} {}", r.status, r.text()),
                Err(e) => e.to_string(),
            };
            assert!(
                Instant::now() < deadline,
                "{when}: {path} unreadable: {why}"
            );
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

/// Write objects through `endpoint` until `stop`, keeping those
/// acknowledged. Failures (a node restarting) are expected and not kept.
fn writer(endpoint: &str, ak: &str, sk: &str, stored: &Stored, stop: &AtomicBool) {
    let c = Cluster::client(endpoint, ak, sk);
    let mut n = 0u64;
    while !stop.load(Ordering::Relaxed) {
        let path = format!("/traffic/k{n}");
        let bytes = payload(1000 + usize::try_from(n % 7).unwrap() * 20_000, n);
        if c.try_request("PUT", &path, &bytes)
            .is_ok_and(|r| r.status == 200)
        {
            stored.lock().unwrap().insert(path, bytes);
        }
        n += 1;
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `GET /_admin/upgrade` once `want` holds for it.
fn upgrade_status(c: &Cluster, what: &str, want: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let r = c.request("GET", "/_admin/upgrade", &[]);
        if r.status == 200 && want(&r.json()) {
            return r.json();
        }
        assert!(Instant::now() < deadline, "{what}: {}", r.text());
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// How many nodes of `kind` report `release`.
fn on_release(v: &Value, kind: &str, release: &str) -> usize {
    v["nodes"].as_array().map_or(0, |n| {
        n.iter()
            .filter(|n| n["kind"] == kind && n["release"] == release)
            .count()
    })
}

/// A gateway from `bins`, against a cluster finalized past its level: it
/// must not serve.
fn old_gateway_is_refused(ha: &HaCluster, bins: &Path, path: &str) {
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut child = Command::new(bins.join("objectio-gateway"))
        .env("OBJECTIO_MASTER_KEY", MASTER_KEY)
        .args([
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--meta-endpoint",
            &ha.meta_endpoints(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the old gateway");
    let c = Cluster::client(
        &format!("http://127.0.0.1:{port}"),
        &ha.access_key,
        &ha.secret_key,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut served = None;
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break; // refused at start-up
        }
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            served = Some(c.request("GET", path, &[]).status);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    let _ = child.wait();
    assert_ne!(
        served,
        Some(200),
        "a gateway from the previous release served an object after finalize"
    );
}

/// Objects of every kind the previous release writes, into `stored`.
fn load(c: &Cluster, stored: &Stored) {
    for b in ["/data", "/traffic"] {
        assert_eq!(c.request("PUT", b, &[]).status, 200, "{b}");
    }
    let put = |path: &str, bytes: Vec<u8>, headers: &[(&str, &[u8])]| {
        let r = c.request_signed("PUT", path, &bytes, headers, false);
        assert_eq!(r.status, 200, "{path}: {}", r.text());
        stored.lock().unwrap().insert(path.to_string(), bytes);
    };
    put("/data/tiny", payload(100, 1), &[]);
    put("/data/small", payload(30_000, 2), &[]);
    put("/data/medium", payload(3 << 20, 3), &[]);
    put("/data/large", payload(12 << 20, 4), &[]);
    put(
        "/data/tagged",
        payload(5_000, 5),
        &[("x-amz-tagging", b"team=ml".as_slice())],
    );
    put(
        "/data/encrypted",
        payload(70_000, 6),
        &[("x-amz-server-side-encryption", b"AES256".as_slice())],
    );
    for i in 0..40u64 {
        put(
            &format!("/data/many/{i}"),
            payload(2_000 + usize::try_from(i).unwrap() * 97, 100 + i),
            &[],
        );
    }
}

#[test]
fn a_rolling_upgrade_from_the_previous_release_loses_nothing() {
    let Some(prev) = previous_release() else {
        eprintln!(
            "skipped: set OBJECTIO_PREVIOUS_RELEASE_BIN \
             (scripts/upgrade-test/previous-release.sh)"
        );
        return;
    };
    let mut ha = HaCluster::start_from(Some(&prev), METAS, OSDS, GATEWAYS);
    let _ = ha.await_leader(Duration::from_secs(30));
    let (ak, sk) = (ha.access_key.clone(), ha.secret_key.clone());

    // The previous release, as its nodes report it.
    let v = upgrade_status(&ha.clients[0], "every node reports", |v| {
        v["nodes"]
            .as_array()
            .is_some_and(|n| n.len() == METAS + OSDS + GATEWAYS)
    });
    let prev_release = v["nodes"][0]["release"].as_str().unwrap().to_string();
    let prev_level = u32::try_from(v["active_level"].as_u64().unwrap()).unwrap();
    assert_ne!(prev_release, RELEASE, "the previous release is this one");

    // 1. Data written by the previous release.
    let stored: Stored = Arc::default();
    load(&ha.clients[0], &stored);
    assert_all_readable(&ha.clients[0], &stored, "before the upgrade");

    // 2. Traffic through the second gateway for the whole roll.
    let stop = Arc::new(AtomicBool::new(false));
    let traffic = {
        let (e, a, s, st, sp) = (
            ha.clients[1].endpoint.clone(),
            ak,
            sk,
            Arc::clone(&stored),
            Arc::clone(&stop),
        );
        std::thread::spawn(move || writer(&e, &a, &s, &st, &sp))
    };

    // 3. Roll every node to this build: meta followers, then the leader;
    // OSDs one at a time; gateways.
    let leader = ha.await_leader(Duration::from_secs(30));
    for i in (0..METAS).filter(|&i| i != leader).chain([leader]) {
        ha.restart_meta(i, None);
        let _ = ha.await_leader(Duration::from_secs(30));
        assert_all_readable(&ha.clients[0], &stored, &format!("after meta {i}"));
    }
    for i in 0..OSDS {
        ha.restart_osd(i, None);
        std::thread::sleep(Duration::from_secs(3));
        assert_all_readable(&ha.clients[0], &stored, &format!("after OSD {i}"));
    }
    ha.restart_gateway(0, None);
    assert_all_readable(&ha.clients[0], &stored, "after gateway 0");
    ha.restart_gateway(1, None);
    assert_all_readable(&ha.clients[1], &stored, "after gateway 1");

    upgrade_status(&ha.clients[0], "every node on the new release", |v| {
        on_release(v, "meta", RELEASE) == METAS
            && on_release(v, "osd", RELEASE) == OSDS
            && on_release(v, "gateway", RELEASE) == GATEWAYS
    });

    // 4. One OSD goes back to the previous release and forward again; the
    // data stays readable, and while it is back, finalize waits for it.
    ha.restart_osd(OSDS - 1, Some(&prev));
    if prev_level < FORMAT_LEVEL {
        upgrade_status(&ha.clients[0], "the old OSD blocks finalize", |v| {
            v["can_finalize"] == false
        });
    }
    assert_all_readable(&ha.clients[0], &stored, "with one OSD rolled back");
    ha.restart_osd(OSDS - 1, None);

    stop.store(true, Ordering::Relaxed);
    traffic.join().unwrap();
    assert_all_readable(&ha.clients[0], &stored, "after the roll");

    // 5. Finalize; then a node of the previous release is refused, if the
    // releases differ in format level.
    upgrade_status(&ha.clients[0], "every node forward again", |v| {
        on_release(v, "osd", RELEASE) == OSDS
    });
    let r = ha.clients[0].request("POST", "/_admin/upgrade/finalize", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["active_level"], FORMAT_LEVEL);
    if prev_level < FORMAT_LEVEL {
        old_gateway_is_refused(&ha, &prev, "/data/small");
    }

    // 6. Everything restarted on the new release: all still there.
    for i in 0..METAS {
        ha.restart_meta(i, None);
    }
    let _ = ha.await_leader(Duration::from_secs(30));
    let (osds, gateways) = ha.sizes();
    for i in 0..osds {
        ha.restart_osd(i, None);
    }
    for i in 0..gateways {
        ha.restart_gateway(i, None);
    }
    assert_all_readable(&ha.clients[0], &stored, "after restarting everything");
}
