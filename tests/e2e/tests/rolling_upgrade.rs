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
use objectio_e2e::ha::HaCluster;
use objectio_e2e::{Cluster, Response};
use serde_json::{Value, json};

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

/// What the previous release left that is not just an object to read back.
struct Loaded {
    /// A multipart upload in flight: its path, id, and first part.
    upload: (String, String, String, Vec<u8>),
    /// A tenant user's key, and the object it wrote.
    tenant_key: (String, String),
}

/// Records of every kind the previous release writes: objects (plain,
/// tagged, encrypted, packed, versioned, behind a delete marker), a
/// multipart upload in flight, a tenant with a user and a key, a
/// replication target and rule. Objects go into `stored`.
fn load(c: &Cluster, stored: &Stored) -> Loaded {
    for b in ["/data", "/traffic", "/packed", "/ver", "/ver-dst"] {
        assert_eq!(c.request("PUT", b, &[]).status, 200, "{b}");
    }
    let put = |path: &str, bytes: Vec<u8>, headers: &[(&str, &[u8])]| -> Response {
        let r = c.request_signed("PUT", path, &bytes, headers, false);
        assert_eq!(r.status, 200, "{path}: {}", r.text());
        stored.lock().unwrap().insert(path.to_string(), bytes);
        r
    };
    load_objects(&put);
    load_packed(c, &put);
    load_versioned(c, stored, &put);
    load_replication(c);
    Loaded {
        tenant_key: load_tenant(c),
        upload: load_upload(c),
    }
}

type Put<'a> = dyn Fn(&str, Vec<u8>, &[(&str, &[u8])]) -> Response + 'a;

fn load_objects(put: &Put) {
    put("/data/tiny", payload(100, 1), &[]); // stored inline
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

fn load_packed(c: &Cluster, put: &Put) {
    // Packed: small objects moved into a pack.
    let keys: Vec<String> = (0..8u64).map(|i| format!("p{i}")).collect();
    for (i, k) in (0u64..).zip(&keys) {
        put(
            &format!("/packed/{k}"),
            payload(6_000 + usize::try_from(i).unwrap() * 2_311, 200 + i),
            &[],
        );
    }
    let r = c.json(
        "POST",
        "/_admin/test/pack",
        json!({ "bucket": "packed", "keys": keys }),
    );
    assert_eq!(r.status, 200, "pack: {}", r.text());
    assert_eq!(
        r.json()["packed"].as_array().map(Vec::len),
        Some(keys.len()),
        "{}",
        r.text()
    );
}

fn load_versioned(c: &Cluster, stored: &Stored, put: &Put) {
    // Versioned: three versions of one key, each readable by id; another
    // key behind a delete marker.
    let versioning = b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>";
    for b in ["/ver", "/ver-dst"] {
        assert_eq!(
            c.request("PUT", &format!("{b}?versioning"), versioning)
                .status,
            200
        );
    }
    for n in 0..3u64 {
        let bytes = payload(4_000 + usize::try_from(n).unwrap(), 300 + n);
        let r = put("/ver/k", bytes.clone(), &[]);
        let vid = r.header("x-amz-version-id").expect("a version id");
        stored
            .lock()
            .unwrap()
            .insert(format!("/ver/k?versionId={vid}"), bytes);
    }
    let r = put("/ver/gone", payload(500, 400), &[]);
    let gone = r.header("x-amz-version-id").expect("a version id");
    stored.lock().unwrap().remove("/ver/gone");
    assert_eq!(c.request("DELETE", "/ver/gone", &[]).status, 204);
    stored
        .lock()
        .unwrap()
        .insert(format!("/ver/gone?versionId={gone}"), payload(500, 400));
}

fn load_replication(c: &Cluster) {
    // Replication: a target (this cluster's other bucket) and a rule.
    let r = c.json(
        "POST",
        "/_admin/replication/targets",
        json!({
            "name": "dr",
            "endpoint": c.endpoint,
            "bucket": "ver-dst",
            "access_key": c.access_key,
            "secret_key": c.secret_key,
        }),
    );
    assert!(r.status == 200 || r.status == 201, "target: {}", r.text());
    let rule = "<ReplicationConfiguration><Rule><ID>all</ID><Status>Enabled</Status>\
                <Filter><Prefix></Prefix></Filter>\
                <DeleteMarkerReplication><Status>Enabled</Status></DeleteMarkerReplication>\
                <Destination><Bucket>arn:obio:replication:::dr</Bucket></Destination>\
                </Rule></ReplicationConfiguration>";
    let r = c.request("PUT", "/ver?replication", rule.as_bytes());
    assert_eq!(r.status, 200, "rule: {}", r.text());
}

fn load_tenant(c: &Cluster) -> (String, String) {
    // A tenant, a user in it with a key, and an object it wrote.
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": "acme", "display_name": "acme", "enabled": true}),
    )
    .expect_ok();
    let user = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "acme-user", "tenant": "acme"}),
    );
    user.expect_ok();
    let uid = user.json()["user_id"].as_str().unwrap().to_string();
    let key = c.json(
        "POST",
        &format!("/_admin/users/{uid}/access-keys"),
        json!({}),
    );
    key.expect_ok();
    let (tak, tsk) = (
        key.json()["access_key_id"].as_str().unwrap().to_string(),
        key.json()["secret_access_key"]
            .as_str()
            .unwrap()
            .to_string(),
    );
    let t = Cluster::client(&c.endpoint, &tak, &tsk);
    assert_eq!(t.request("PUT", "/acme-b", &[]).status, 200);
    assert_eq!(t.request("PUT", "/acme-b/k", b"acme's").status, 200);
    (tak, tsk)
}

fn load_upload(c: &Cluster) -> (String, String, String, Vec<u8>) {
    // A multipart upload, its first part written by the previous release.
    let r = c.request("POST", "/data/mpu?uploads", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    let text = r.text();
    let id = text
        .split("<UploadId>")
        .nth(1)
        .and_then(|s| s.split("</UploadId>").next())
        .expect("an upload id")
        .to_string();
    let part1 = payload(5 << 20, 500);
    let r = c.request(
        "PUT",
        &format!("/data/mpu?partNumber=1&uploadId={id}"),
        &part1,
    );
    assert_eq!(r.status, 200, "{}", r.text());
    let etag = r.header("etag").expect("an etag");

    ("/data/mpu".to_string(), id, etag, part1)
}

/// On the new release: the upload in flight completes, the tenant's key
/// still works, the replication target and rule are still there.
fn finish_loaded(c: &Cluster, loaded: &Loaded, stored: &Stored) {
    let (path, id, etag1, part1) = &loaded.upload;
    let part2 = payload(70_000, 501);
    let r = c.request("PUT", &format!("{path}?partNumber=2&uploadId={id}"), &part2);
    assert_eq!(r.status, 200, "{}", r.text());
    let etag2 = r.header("etag").expect("an etag");
    let body = format!(
        "<CompleteMultipartUpload>\
         <Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part>\
         <Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part>\
         </CompleteMultipartUpload>"
    );
    let r = c.request("POST", &format!("{path}?uploadId={id}"), body.as_bytes());
    assert_eq!(r.status, 200, "complete: {}", r.text());
    let mut whole = part1.clone();
    whole.extend_from_slice(&part2);
    stored.lock().unwrap().insert(path.clone(), whole);

    let (tak, tsk) = &loaded.tenant_key;
    let t = Cluster::client(&c.endpoint, tak, tsk);
    let r = t.request("GET", "/acme-b/k", &[]);
    assert!(r.status == 200 && r.bytes == b"acme's", "{}", r.text());
    assert_eq!(t.request("PUT", "/acme-b/k2", b"after").status, 200);

    let r = c.request("GET", "/ver?replication", &[]);
    assert!(
        r.status == 200 && r.text().contains("arn:obio:replication:::dr"),
        "{}",
        r.text()
    );
    let r = c.request("GET", "/_admin/replication/targets", &[]);
    assert!(
        r.status == 200 && r.text().contains("\"dr\""),
        "{}",
        r.text()
    );
}

/// One node of each kind goes back to the previous release and forward
/// again; the data stays readable, through the old gateway too, and while
/// they are back, finalize waits for them.
fn roll_back_and_forward(ha: &mut HaCluster, prev: &Path, prev_level: u32, stored: &Stored) {
    let leader = ha.await_leader(Duration::from_secs(30));
    let follower = (0..METAS).find(|&i| i != leader).unwrap();
    ha.restart_meta(follower, Some(prev));
    let _ = ha.await_leader(Duration::from_secs(30));
    ha.restart_osd(OSDS - 1, Some(prev));
    ha.restart_gateway(1, Some(prev));
    if prev_level < FORMAT_LEVEL {
        upgrade_status(&ha.clients[0], "the old nodes block finalize", |v| {
            v["can_finalize"] == false
        });
    }
    assert_all_readable(&ha.clients[0], stored, "with one node of each kind back");
    assert_all_readable(&ha.clients[1], stored, "through the old gateway");
    ha.restart_meta(follower, None);
    let _ = ha.await_leader(Duration::from_secs(30));
    ha.restart_osd(OSDS - 1, None);
    ha.restart_gateway(1, None);
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
    let loaded = load(&ha.clients[0], &stored);
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

    roll_back_and_forward(&mut ha, &prev, prev_level, &stored);

    stop.store(true, Ordering::Relaxed);
    traffic.join().unwrap();
    assert_all_readable(&ha.clients[0], &stored, "after the roll");

    // 5. Finalize; then a node of the previous release is refused, if the
    // releases differ in format level.
    finish_loaded(&ha.clients[0], &loaded, &stored);
    upgrade_status(&ha.clients[0], "every node forward again", |v| {
        on_release(v, "meta", RELEASE) == METAS
            && on_release(v, "osd", RELEASE) == OSDS
            && on_release(v, "gateway", RELEASE) == GATEWAYS
    });
    let r = ha.clients[0].request("POST", "/_admin/upgrade/finalize", &[]);
    assert_eq!(r.status, 200, "{}", r.text());
    assert_eq!(r.json()["active_level"], FORMAT_LEVEL);
    if prev_level < FORMAT_LEVEL {
        old_gateway_is_refused(&ha, &prev, "/data/small");
    }
    // Objects written at the new level.
    for i in 0..10u64 {
        let path = format!("/data/finalized/{i}");
        let bytes = payload(3_000 + usize::try_from(i).unwrap() * 50_000, 600 + i);
        let r = ha.clients[0].request("PUT", &path, &bytes);
        assert_eq!(r.status, 200, "{path}: {}", r.text());
        stored.lock().unwrap().insert(path, bytes);
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
