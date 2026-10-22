//! One OSD failing while requests go on: killed, restarted, or frozen
//! (SIGSTOP: its connections stay open and its kernel accepts new ones, but
//! nothing answers, as a host hung or cut off without a reset). With 4+2,
//! every write and read still has its quorum on the other five, so no
//! request may fail, and none may wait on the silent OSD for longer than
//! the gateway takes to find it silent.
//!
//! Before, a frozen OSD was taken as up whenever the gateway probed it
//! without TLS (a connection was its only test), so every request opened a
//! new connection to it and waited 5 s on that, for as long as it stayed
//! frozen; and a call already sent to it waited out HTTP/2 keepalive or its
//! own timeout.

use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use serde_json::json;

/// The OSD each test fails.
const VICTIM: usize = 2;

/// The longest a request may take with an OSD that has been found silent:
/// it waits on nothing. Healthy, each takes well under half a second here;
/// before, a DELETE took 3 s with mTLS and every request 5 s without.
const ONCE_FOUND: Duration = Duration::from_millis(2500);

/// The longest a request may take that is the first to meet the frozen OSD:
/// the gateway suspects a call after 2 s and probes for 1 s, then abandons
/// it. Headroom for a loaded runner.
const FIRST_MEETING: Duration = Duration::from_secs(8);

fn payload(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| i.to_le_bytes()[0].wrapping_mul(31) ^ seed)
        .collect()
}

fn xml_tag(xml: &str, name: &str) -> String {
    xml.split(&format!("<{name}>"))
        .nth(1)
        .and_then(|s| s.split(&format!("</{name}>")).next())
        .unwrap_or_else(|| panic!("no <{name}> in {xml}"))
        .to_string()
}

/// Buckets `b` (unversioned) and `v` (versioned), with objects the
/// requests below read, copy and delete.
fn setup(c: &Cluster) {
    c.json("POST", "/_admin/buckets", json!({ "name": "b" }))
        .expect_ok();
    c.json("POST", "/_admin/buckets", json!({ "name": "v" }))
        .expect_ok();
    c.request(
        "PUT",
        "/v?versioning",
        b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
    )
    .expect(200);
    c.request("PUT", "/b/small", &payload(1_000, 1)).expect(200);
    c.request("PUT", "/b/coded", &payload(300_000, 2))
        .expect(200);
    for i in 0..10 {
        c.request("PUT", &format!("/b/gone-{i}"), &payload(40_000, 3))
            .expect(200);
    }
}

/// One of each request a client makes, `round` naming its keys: what it
/// was, and how it went (status, time).
fn every_request(c: &Cluster, round: usize) -> Vec<(&'static str, u16, Duration)> {
    let mut out = Vec::new();
    let mut time = |what: &'static str, expect: u16, f: &dyn Fn() -> objectio_e2e::Response| {
        let started = Instant::now();
        let r = f();
        let took = started.elapsed();
        assert_eq!(
            r.status,
            expect,
            "{what} (round {round}), after {took:?}: {}",
            r.text()
        );
        out.push((what, r.status, took));
        r
    };
    time("PUT of a small object", 200, &|| {
        c.request("PUT", &format!("/b/s-{round}"), &payload(2_000, 4))
    });
    time("PUT of an erasure-coded object", 200, &|| {
        c.request("PUT", &format!("/b/e-{round}"), &payload(300_000, 5))
    });
    let r = time("GET of a small object", 200, &|| {
        c.request("GET", "/b/small", &[])
    });
    assert!(
        r.bytes == payload(1_000, 1),
        "GET of a small object: wrong bytes"
    );
    let r = time("GET of an erasure-coded object", 200, &|| {
        c.request("GET", "/b/coded", &[])
    });
    assert!(r.bytes == payload(300_000, 2), "GET: wrong bytes");
    time("HEAD", 200, &|| c.request("HEAD", "/b/coded", &[]));
    time("HEAD of a key that isn't there", 404, &|| {
        c.request("HEAD", &format!("/b/never-{round}"), &[])
    });
    time("DELETE", 204, &|| {
        c.request("DELETE", &format!("/b/gone-{round}"), &[])
    });
    time("LIST", 200, &|| c.request("GET", "/b?list-type=2", &[]));

    let key = format!("/v/k-{round}");
    time("PUT in a versioned bucket", 200, &|| {
        c.request("PUT", &key, &payload(30_000, 6))
    });
    let vid = c
        .request("PUT", &key, &payload(30_000, 7))
        .header("x-amz-version-id")
        .expect("a version id");
    time("DELETE in a versioned bucket (a marker)", 204, &|| {
        c.request("DELETE", &key, &[])
    });
    time("DELETE of a version", 204, &|| {
        c.request("DELETE", &format!("{key}?versionId={vid}"), &[])
    });
    time("ListObjectVersions", 200, &|| {
        c.request("GET", "/v?versions", &[])
    });

    let key = format!("/b/m-{round}");
    let r = c.request("POST", &format!("{key}?uploads"), &[]);
    r.expect(200);
    let upload = xml_tag(&r.text(), "UploadId");
    let part = c.request(
        "PUT",
        &format!("{key}?partNumber=1&uploadId={upload}"),
        &payload(200_000, 8),
    );
    part.expect(200);
    let etag = part.header("etag").expect("an etag");
    let complete = format!(
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber>\
         <ETag>{etag}</ETag></Part></CompleteMultipartUpload>"
    );
    time("CompleteMultipartUpload", 200, &|| {
        c.request(
            "POST",
            &format!("{key}?uploadId={upload}"),
            complete.as_bytes(),
        )
    });
    time("CopyObject", 200, &|| {
        c.request_with_headers(
            "PUT",
            &format!("/b/c-{round}"),
            &[],
            &[("x-amz-copy-source", "/b/coded")],
        )
    });
    out
}

/// Wait until a PUT succeeds: every OSD reachable again.
fn await_writable(c: &Cluster) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while c.request("PUT", "/b/probe", b"probe").status != 200 {
        assert!(Instant::now() < deadline, "writes never resumed");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// With one OSD frozen, every request succeeds: the first ones to meet it
/// within seconds, and every one after them without waiting on it.
#[test]
fn every_request_succeeds_without_waiting_on_a_frozen_osd() {
    let ha = HaCluster::start(1, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    let c = &ha.clients[0];
    setup(c);
    await_writable(c);

    ha.freeze_osd(VICTIM);
    let first = every_request(c, 0);
    let after = every_request(c, 1);
    ha.thaw_osd(VICTIM);

    for (what, _, took) in &first {
        assert!(
            *took < FIRST_MEETING,
            "{what}, first to meet a frozen OSD, took {took:?}: {first:?}"
        );
    }
    for (what, _, took) in &after {
        assert!(
            *took < ONCE_FOUND,
            "{what} waited on an OSD found frozen: {took:?}: {after:?}"
        );
    }
}

/// Clients making every kind of request see no failure while one OSD is
/// killed, comes back, is restarted twice and then frozen for a while:
/// every write and read has its quorum on the others throughout.
#[test]
fn no_request_fails_while_one_osd_is_killed_restarted_or_frozen() {
    let mut ha = HaCluster::start(1, 6, 1);
    let _ = ha.await_leader(Duration::from_secs(30));
    setup(&ha.clients[0]);
    await_writable(&ha.clients[0]);
    let (endpoint, access, secret) = (
        ha.clients[0].endpoint.clone(),
        ha.access_key.clone(),
        ha.secret_key.clone(),
    );

    let stop = std::sync::atomic::AtomicBool::new(false);
    let rounds = std::thread::scope(|s| {
        let clients: Vec<_> = (0..4)
            .map(|t| {
                let (endpoint, access, secret, stop) = (&endpoint, &access, &secret, &stop);
                s.spawn(move || {
                    let c = Cluster::client(endpoint, access, secret);
                    let mut rounds = Vec::new();
                    let mut round = 100 * (t + 1);
                    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                        rounds.push(every_request(&c, round));
                        round += 1;
                    }
                    rounds
                })
            })
            .collect();

        std::thread::sleep(Duration::from_secs(2));
        ha.stop_osd(VICTIM);
        std::thread::sleep(Duration::from_secs(4));
        ha.start_osd(VICTIM, None);
        for _ in 0..2 {
            std::thread::sleep(Duration::from_secs(3));
            ha.restart_osd(VICTIM, None);
        }
        std::thread::sleep(Duration::from_secs(3));
        ha.freeze_osd(VICTIM);
        std::thread::sleep(Duration::from_secs(8));
        ha.thaw_osd(VICTIM);
        std::thread::sleep(Duration::from_secs(2));
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        clients
            .into_iter()
            .flat_map(|h| h.join().expect("a client failed"))
            .collect::<Vec<_>>()
    });

    let requests: Vec<_> = rounds.iter().flatten().collect();
    assert!(
        requests.len() > 100,
        "too few requests to tell: {}",
        requests.len()
    );
    // Every request succeeded (each asserts its status). None waited long:
    // only those that met the frozen OSD first waited at all.
    let slowest = requests.iter().max_by_key(|r| r.2).expect("requests");
    assert!(
        slowest.2 < FIRST_MEETING,
        "{} took {:?} with one OSD failing",
        slowest.0,
        slowest.2
    );
}
