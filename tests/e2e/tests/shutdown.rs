//! SIGTERM, which Kubernetes, systemd and `docker stop` send, stops every
//! service cleanly: it finishes what it is doing and exits 0. The services
//! used to wait for Ctrl-C only, so SIGTERM killed them where they stood
//! (or, as PID 1 in a container, was ignored until the kubelet's SIGKILL),
//! and nothing of their shutdown ran: no drain, no last checkpoint.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use objectio_e2e::ha::{HaCluster, Node};
use objectio_e2e::{Cluster, await_exit, binary, sigterm, tls};

/// Ample for a clean stop: the services take well under a second here.
const STOP_WITHIN: Duration = Duration::from_secs(20);

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// `GET /_ready` on `endpoint`: its status and `status` field.
fn ready(endpoint: &str) -> Option<(u16, String)> {
    let r = reqwest::blocking::Client::new()
        .get(format!("{endpoint}/_ready"))
        .timeout(Duration::from_secs(2))
        .send()
        .ok()?;
    let code = r.status().as_u16();
    let body: serde_json::Value = r.json().ok()?;
    Some((
        code,
        body["status"].as_str().unwrap_or_default().to_string(),
    ))
}

/// Wait up to `secs` for `/_ready` on `endpoint` to answer `code`.
fn await_ready(endpoint: &str, code: u16, secs: u64) -> String {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let got = ready(endpoint);
        if let Some((c, status)) = &got
            && *c == code
        {
            return status.clone();
        }
        assert!(
            Instant::now() < deadline,
            "/_ready never answered {code} in {secs} s; last {got:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Meta, the OSDs, the gateway and the block gateway, each its own process,
/// each stopped by SIGTERM. The gateway first leaves the load balancer:
/// `/_ready` answers 503 while it still serves, for its shutdown delay.
#[test]
fn every_service_stops_cleanly_on_sigterm() {
    let mut ha = HaCluster::start(1, 6, 1);
    ha.restart_gateway_with_args(0, &["--shutdown-delay-secs", "3"]);
    let c = &ha.clients[0];
    c.request("PUT", "/stopping", &[]).expect(200);
    c.request("PUT", "/stopping/k", b"kept").expect(200);
    assert_eq!(await_ready(&c.endpoint, 200, 60), "ready");

    ha.sigterm(Node::Gateway(0));
    let c = &ha.clients[0];
    assert_eq!(await_ready(&c.endpoint, 503, 3), "stopping");
    let r = c.request("GET", "/stopping/k", &[]);
    assert_eq!(
        (r.status, r.text()),
        (200, "kept".to_string()),
        "still served while not ready"
    );
    let status = ha.await_exit(Node::Gateway(0), STOP_WITHIN);
    assert!(status.is_some_and(|s| s.success()), "gateway: {status:?}");

    // The block gateway, on the same meta.
    let dir = tempfile::tempdir().unwrap();
    let grpc = free_port();
    let mut cmd = Command::new(binary("objectio-block-gateway"));
    tls::apply(&mut cmd);
    let mut block = cmd
        .args([
            "--listen",
            &format!("127.0.0.1:{grpc}"),
            "--nbd-listen",
            &format!("127.0.0.1:{}", free_port()),
            "--metrics-listen",
            "",
            "--meta-endpoint",
            &ha.meta_endpoints(),
            "--data-dir",
            &dir.path().display().to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn objectio-block-gateway");
    let deadline = Instant::now() + Duration::from_secs(60);
    while std::net::TcpStream::connect(("127.0.0.1", grpc)).is_err() {
        assert!(
            block.try_wait().unwrap().is_none(),
            "the block gateway exited while starting"
        );
        assert!(
            Instant::now() < deadline,
            "the block gateway never listened"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    sigterm(block.id());
    let status = await_exit(&mut block, STOP_WITHIN);
    assert!(
        status.is_some_and(|s| s.success()),
        "block gateway: {status:?}"
    );

    for i in 0..6 {
        ha.sigterm(Node::Osd(i));
        let status = ha.await_exit(Node::Osd(i), STOP_WITHIN);
        assert!(status.is_some_and(|s| s.success()), "OSD {i}: {status:?}");
    }
    ha.sigterm(Node::Meta(0));
    let status = ha.await_exit(Node::Meta(0), STOP_WITHIN);
    assert!(status.is_some_and(|s| s.success()), "meta: {status:?}");
}

/// aio, block gateway included, stops on SIGTERM as on Ctrl-C: every
/// service shuts down and the process exits 0.
#[test]
fn aio_stops_cleanly_on_sigterm() {
    let mut c = Cluster::start_with_ec_and_args(
        6,
        4,
        2,
        &["--block-port", "{free}", "--nbd-port", "{free}"],
    );
    c.request("PUT", "/stopping", &[]).expect(200);
    c.request("PUT", "/stopping/k", b"x").expect(200);
    let status = c.terminate(STOP_WITHIN);
    assert!(status.is_some_and(|s| s.success()), "aio: {status:?}");
    if std::env::var_os("OBJECTIO_E2E_LOGS").is_none() {
        let log = c.log();
        for line in [
            "SIGTERM received",
            "Metadata Service shut down gracefully",
            "OSD shut down gracefully",
            "Gateway shut down gracefully",
            "Block gateway shut down gracefully",
            "all services shut down cleanly",
        ] {
            assert!(log.contains(line), "{line:?} not logged");
        }
    }
}
