//! A service that can't bind one of its ports doesn't start. A meta node
//! whose metrics port another process held used to log the error and run
//! on, and the process that held the port answered its health checks.

use std::process::{Command, Stdio};
use std::time::Duration;

use objectio_e2e::{await_exit, binary, free_port, tls};

/// Start a lone meta node with `metrics` and `admin` as its ports, and wait
/// for it to exit: its status, or `None` if it was still running (it is
/// stopped then).
fn meta_exit(metrics: u16, admin: u16) -> Option<std::process::ExitStatus> {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::new(binary("objectio-meta"));
    tls::apply(&mut cmd, tls::META);
    let grpc = free_port();
    let mut meta = cmd
        .args([
            "--node-id",
            "1",
            "--listen",
            &format!("127.0.0.1:{grpc}"),
            "--raft-advertise",
            &format!("127.0.0.1:{grpc}"),
            "--data-dir",
            &dir.path().display().to_string(),
            "--metrics-port",
            &metrics.to_string(),
            "--admin-port",
            &admin.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn objectio-meta");
    await_exit(&mut meta, Duration::from_secs(30))
}

#[test]
fn a_meta_node_whose_metrics_or_admin_port_is_taken_does_not_start() {
    let held = free_port();
    let _holder = std::net::TcpListener::bind(("0.0.0.0", held)).unwrap();

    let status = meta_exit(held, free_port());
    assert!(
        status.is_some_and(|s| !s.success()),
        "metrics port taken: {status:?}"
    );
    let status = meta_exit(free_port(), held);
    assert!(
        status.is_some_and(|s| !s.success()),
        "admin port taken: {status:?}"
    );
}
