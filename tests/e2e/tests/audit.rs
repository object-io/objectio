//! The audit stream: every request — allowed or refused, signed or not —
//! becomes one event naming who, from where, what, and how it ended, with
//! the request ID the client was given. Delivery survives a receiver that
//! is down for a while, and tenants can't aim the gateway at internal
//! addresses.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use serde_json::{Value, json};

/// A webhook receiver on `listener`: every event it is sent.
fn receiver(listener: TcpListener) -> Arc<Mutex<Vec<Value>>> {
    receiver_from(listener, Arc::new(AtomicBool::new(true)))
}

/// A port the receiver keeps from the start, so nothing else can take it
/// before the receiver is up: the port, its listener, and the switch that
/// brings the receiver up. Freed and bound again later, the port went to a
/// server of the cluster starting meanwhile, which took (and lost) events.
fn held_receiver() -> (u16, Arc<Mutex<Vec<Value>>>, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let up = Arc::new(AtomicBool::new(false));
    let events = receiver_from(listener, Arc::clone(&up));
    (port, events, up)
}

/// [`receiver`], down (every connection dropped unanswered, as a
/// receiver that isn't there) until `up` is set.
fn receiver_from(listener: TcpListener, up: Arc<AtomicBool>) -> Arc<Mutex<Vec<Value>>> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&events);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            if !up.load(Ordering::SeqCst) {
                continue;
            }
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = v.trim().parse().unwrap_or(0);
                }
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; length];
            let _ = reader.read_exact(&mut body);
            for line in String::from_utf8_lossy(&body).lines() {
                if let Ok(v) = serde_json::from_str(line) {
                    sink.lock().unwrap().push(v);
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        }
    });
    events
}

/// The events matching `pred`, waiting up to `secs` for at least one.
fn wait_for(
    events: &Arc<Mutex<Vec<Value>>>,
    secs: u64,
    pred: impl Fn(&Value) -> bool,
) -> Vec<Value> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let found: Vec<Value> = events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| pred(e))
            .cloned()
            .collect();
        if !found.is_empty() || Instant::now() > deadline {
            return found;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn webhook(port: u16) -> Value {
    json!({"targets": [{"type": "webhook", "name": "siem",
        "url": format!("http://127.0.0.1:{port}/ingest"), "flush_ms": 200}]})
}

#[test]
fn every_request_is_one_event_with_the_id_the_client_got() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let events = receiver(listener);
    let c = Cluster::start();
    c.json("PUT", "/_admin/audit", webhook(port)).expect_ok();

    c.request("PUT", "/logs", &[]).expect(200);
    let put = c.request("PUT", "/logs/k", b"0123456789");
    put.expect(200);
    let id = put.header("x-amz-request-id").expect("a request id");
    let get = c.request("GET", "/logs/k", &[]);
    assert_eq!(get.bytes, b"0123456789");

    let found = wait_for(&events, 10, |e| e["id"] == id.as_str());
    assert_eq!(found.len(), 1, "{found:?}");
    let put_event = &found[0];
    assert_eq!(put_event["api"], "s3");
    assert_eq!(put_event["action"], "s3:PutObject");
    assert_eq!(put_event["bucket"], "logs");
    assert_eq!(put_event["key"], "k");
    assert_eq!(put_event["status"], 200);
    assert_eq!(put_event["request_bytes"], 10);
    assert_eq!(put_event["principal"]["auth"], "Permanent");
    assert_eq!(put_event["principal"]["access_key"], c.access_key.as_str());
    assert_eq!(put_event["source"]["ip"], "127.0.0.1");
    assert_eq!(put_event["complete"], true);

    let get_id = get.header("x-amz-request-id").unwrap();
    let get_event = wait_for(&events, 10, |e| e["id"] == get_id.as_str());
    assert_eq!(get_event[0]["action"], "s3:GetObject");
    assert_eq!(get_event[0]["response_bytes"], 10);

    // A refusal is an event too, and the error body names the same ID.
    let denied = c.fetch("GET", &format!("{}/logs/k", c.endpoint), &[]);
    assert_eq!(denied.status, 403);
    let denied_id = denied.header("x-amz-request-id").unwrap();
    assert!(denied.text().contains(&denied_id), "{}", denied.text());
    let denied_event = wait_for(&events, 10, |e| e["id"] == denied_id.as_str());
    assert_eq!(denied_event[0]["status"], 403);
    assert_eq!(denied_event[0]["error_code"], "AccessDenied");
    assert_eq!(denied_event[0]["principal"]["auth"], "Anonymous");

    // A presigned URL's credentials never reach the stream.
    let url = c.presign("GET", "/logs/k", 300);
    let presigned = c.fetch("GET", &url, &[]);
    let pid = presigned.header("x-amz-request-id").unwrap();
    let presigned_event = wait_for(&events, 10, |e| e["id"] == pid.as_str());
    let query = presigned_event[0]["query"].as_str().unwrap();
    assert!(query.contains("X-Amz-Signature=********"), "{query}");
    assert!(!query.contains(&c.access_key), "{query}");

    // The admin API is audited, with its caller.
    let users = c.request("GET", "/_admin/users", &[]);
    let uid = users.header("x-amz-request-id").unwrap();
    let admin_event = wait_for(&events, 10, |e| e["id"] == uid.as_str());
    assert_eq!(admin_event[0]["api"], "admin");
    assert_eq!(
        admin_event[0]["principal"]["access_key"],
        c.access_key.as_str()
    );
}

#[test]
fn events_wait_for_a_receiver_that_is_down() {
    // Reserve a port, start nothing on it yet.
    let (port, events, up) = held_receiver();
    let c = Cluster::start();
    c.json("PUT", "/_admin/audit", webhook(port)).expect_ok();
    c.request("PUT", "/late", &[]).expect(200);
    let r = c.request("PUT", "/late/k", b"x");
    let id = r.header("x-amz-request-id").unwrap();

    // The receiver comes up a few seconds later: the event still arrives.
    std::thread::sleep(Duration::from_secs(3));
    up.store(true, Ordering::SeqCst);
    let e = wait_for(&events, 40, |e| e["id"] == id.as_str());
    assert!(
        !e.is_empty(),
        "the event was lost while the receiver was down"
    );
}

#[test]
fn a_tenant_streams_only_to_hosts_the_operator_allows() {
    let c = Cluster::start();
    c.json(
        "POST",
        "/_admin/tenants",
        json!({"name": "acme", "display_name": "acme", "enabled": true}),
    )
    .expect_ok();
    let u = c.json(
        "POST",
        "/_admin/users",
        json!({"display_name": "a", "tenant": "acme"}),
    );
    let uid = u.json()["user_id"].as_str().unwrap().to_string();
    c.json(
        "POST",
        "/_admin/tenants/acme/admins",
        json!({"user_id": uid}),
    )
    .expect_ok();
    let k = c.json(
        "POST",
        &format!("/_admin/users/{uid}/access-keys"),
        json!({}),
    );
    let (ak, sk) = (
        k.json()["access_key_id"].as_str().unwrap().to_string(),
        k.json()["secret_access_key"].as_str().unwrap().to_string(),
    );
    let put =
        |doc: Value| c.request_as("PUT", "/_admin/audit", doc.to_string().as_bytes(), &ak, &sk);
    let target = |url: &str| json!({"targets": [{"name": "t", "url": url}]});

    // Nothing allowed yet; and never plain http or an internal address.
    assert_eq!(put(target("https://siem.acme.example/x")).status, 400);
    c.json(
        "PUT",
        "/_admin/audit",
        json!({"targets": [], "allowed_tenant_hosts": ["siem.acme.example"]}),
    )
    .expect_ok();
    assert_eq!(put(target("http://siem.acme.example/x")).status, 400);
    assert_eq!(put(target("https://127.0.0.1:9100/x")).status, 400);
    assert_eq!(
        put(target("https://siem.acme.example@127.0.0.1/x")).status,
        400
    );
    let ok = put(
        json!({"targets": [{"name": "t", "url": "https://siem.acme.example/x",
        "auth_token": "s3cret"}]}),
    );
    assert_eq!(ok.status, 200, "{}", ok.text());
    // Its token reads back redacted, and the operator's settings aren't its.
    let read = c.request_as("GET", "/_admin/audit", &[], &ak, &sk).json();
    assert_eq!(read["targets"][0]["auth_token"], "********");
    assert!(read.get("allowed_tenant_hosts").is_none(), "{read}");
    // Nor can it read or change the operator's.
    let r = c
        .request_as("GET", "/_admin/audit?tenant=", &[], &ak, &sk)
        .json();
    assert_eq!(r["tenant"], "acme");
}

#[test]
fn the_command_line_log_gets_every_event() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("audit.log");
    let c = Cluster::start_with_ec_and_args(6, 4, 2, &["--audit-log", log.to_str().unwrap()]);
    c.request("PUT", "/flog", &[]).expect(200);
    let put = c.request("PUT", "/flog/k", b"x");
    put.expect(200);
    let id = put.header("x-amz-request-id").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        if let Some(line) = text.lines().find(|l| l.contains(&id)) {
            let e: Value = serde_json::from_str(line).unwrap();
            assert_eq!(e["action"], "s3:PutObject");
            assert_eq!(e["status"], 200);
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no event in {}: {text}",
            log.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// A target added gets the event of every request answered after the
/// change was: with and without the spool. The config used to take effect
/// in the background, and the requests right after it lost their events.
#[test]
fn a_target_added_gets_every_request_after_it() {
    for args in [&[][..], &["--audit-system-bucket", "objectio-audit"][..]] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let events = receiver(listener);
        let c = Cluster::start_with_ec_and_args(6, 4, 2, args);
        c.json("PUT", "/_admin/audit", webhook(port)).expect_ok();
        let made = c.request("PUT", "/added", &[]);
        made.expect(200);
        let mut ids = vec![made.header("x-amz-request-id").unwrap()];
        for i in 0..10 {
            let r = c.request("PUT", &format!("/added/k{i}"), b"x");
            r.expect(200);
            ids.push(r.header("x-amz-request-id").unwrap());
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let got: std::collections::HashSet<String> = events
                .lock()
                .unwrap()
                .iter()
                .filter_map(|e| e["id"].as_str().map(str::to_string))
                .collect();
            let missing: Vec<&String> = ids.iter().filter(|id| !got.contains(*id)).collect();
            if missing.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{args:?}: {} of {} events never arrived: {missing:?}",
                missing.len(),
                ids.len()
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// Every event in the system bucket's objects.
fn system_bucket_events(c: &Cluster, bucket: &str) -> Vec<Value> {
    let list = c
        .request("GET", &format!("/{bucket}?list-type=2"), &[])
        .text();
    list.split("<Key>")
        .skip(1)
        .filter_map(|s| s.split("</Key>").next())
        .flat_map(|key| {
            let body = c.request("GET", &format!("/{bucket}/{key}"), &[]).text();
            body.lines()
                .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                .collect::<Vec<_>>()
        })
        .collect()
}

/// A8c: events are spooled on the gateway's disk before delivery. With
/// the receiver down and the gateway killed, every request's event still
/// arrives once both are back, and every one is also in the system
/// bucket, the copy the system always keeps.
#[test]
fn spooled_events_survive_a_killed_gateway_and_a_receiver_down() {
    let (port, events, up) = held_receiver();
    let mut c =
        Cluster::start_with_ec_and_args(6, 4, 2, &["--audit-system-bucket", "objectio-audit"]);
    c.json("PUT", "/_admin/audit", webhook(port)).expect_ok();
    c.request("PUT", "/spool", &[]).expect(200);
    let mut ids = Vec::new();
    let mut put = |c: &Cluster, i: usize| {
        let r = c.request("PUT", &format!("/spool/k{i}"), b"x");
        assert_eq!(r.status, 200, "{}", r.text());
        ids.push(r.header("x-amz-request-id").unwrap());
    };
    for i in 0..50 {
        put(&c, i);
    }
    // Killed the moment the last PUT is answered, with events
    // undelivered: an acknowledged change's event is on its disk.
    c.restart();
    for i in 50..60 {
        put(&c, i);
    }

    up.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let got: std::collections::HashSet<String> = events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| e["id"].as_str().map(str::to_string))
            .collect();
        let missing: Vec<&String> = ids.iter().filter(|id| !got.contains(*id)).collect();
        if missing.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{} of {} events never reached the receiver: {missing:?}",
            missing.len(),
            ids.len()
        );
        std::thread::sleep(Duration::from_millis(300));
    }

    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let kept: std::collections::HashSet<String> = system_bucket_events(&c, "objectio-audit")
            .iter()
            .filter_map(|e| e["id"].as_str().map(str::to_string))
            .collect();
        let missing = ids.iter().filter(|id| !kept.contains(*id)).count();
        if missing == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "{missing} of {} events not in the system bucket",
            ids.len()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}
