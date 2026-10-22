//! mTLS between the services (A8a): a node accepts gRPC only from peers
//! presenting a certificate the cluster's CA signed, and takes each call
//! only from a peer whose certificate names a role allowed to make it.
//! Meta's admin port takes membership changes only from role admin, and
//! answers its probes without a client certificate; the all-in-one keeps
//! its internal ports on loopback. A peer that never completes its TLS
//! handshake is disconnected within the handshake timeout, and nothing a
//! peer does keeps a node from serving the next.

use std::io::Read;
use std::time::{Duration, Instant};

use objectio_e2e::Cluster;
use objectio_e2e::ha::HaCluster;
use objectio_e2e::tls;
use objectio_proto::metadata::metadata_service_client::MetadataServiceClient;
use objectio_proto::metadata::{
    GetAccessKeyForAuthRequest, GetMetricsRequest, GetStsSigningKeyRequest,
};
use objectio_proto::storage::storage_service_client::StorageServiceClient;
use objectio_proto::storage::{ListPgRequest, PurgeRequest};
use objectio_proto::transport::HANDSHAKE_TIMEOUT;
use tonic::Code;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// The longest a node may take to answer a call or refuse a peer: it
/// refuses within its handshake timeout, and answers in milliseconds.
const WITHIN: Duration = HANDSHAKE_TIMEOUT.saturating_add(Duration::from_secs(10));

/// A call refused at the connection, not answered by meta.
fn refused(r: Result<(), String>) -> bool {
    r.is_err_and(|e| !e.contains("FailedPrecondition") && !e.contains("PermissionDenied"))
}

/// What a call to meta, connected as `ep` describes (a `client`), gets.
///
/// # Panics
/// When meta neither answers nor refuses within [`WITHIN`]: a node that
/// holds a peer it won't serve, rather than refuse it, is a bug, and this
/// test's to find (it hung CI for 18 minutes once).
fn call(
    rt: &tokio::runtime::Runtime,
    client: &str,
    ep: Result<Endpoint, String>,
) -> Result<(), String> {
    let started = Instant::now();
    rt.block_on(async {
        // As the current release: meta refuses a client too old for the
        // cluster, which would look like a refusal for another reason.
        let ep = ep?
            .user_agent(objectio_common::version::user_agent())
            .map_err(|e| e.to_string())?;
        let attempt = async {
            let channel = objectio_proto::transport::connect(&ep)
                .await
                .map_err(|e| e.to_string())?;
            MetadataServiceClient::new(channel)
                .get_metrics(GetMetricsRequest::default())
                .await
                .map(drop)
                .map_err(|e| e.to_string())
        };
        tokio::time::timeout(WITHIN, attempt)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{client}: meta neither answered nor refused it in {:?}",
                    started.elapsed()
                )
            })
    })
}

/// Connect to `addr` and say nothing: the node must close the connection
/// once the handshake timeout is out, and not much before. Returns how
/// long it held it.
fn held_silent(addr: &str) -> Duration {
    let started = Instant::now();
    let mut s = std::net::TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(WITHIN)).unwrap();
    let r = s.read(&mut [0u8; 64]);
    let held = started.elapsed();
    assert!(
        matches!(r, Ok(0))
            || r.as_ref()
                .is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset),
        "{addr} held a client that sent nothing for {held:?} ({r:?}): a peer with no \
         certificate holds a connection and a task until it goes away"
    );
    held
}

#[test]
fn a_node_refuses_a_client_without_the_clusters_certificate() {
    let files = objectio_e2e::tls::files().expect(
        "OBJECTIO_E2E_PLAIN is set: the cluster runs plain gRPC, and this test is about mTLS",
    );
    let ha = HaCluster::start(1, 6, 1);
    let addr = ha
        .meta_endpoints()
        .trim_start_matches("http://")
        .to_string();
    let osd = ha.osd_endpoint(0).trim_start_matches("http://").to_string();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pem = |p: &std::path::Path| std::fs::read(p).unwrap();

    // A client that connects and never starts a TLS handshake: meta and an
    // OSD each disconnect it once the handshake timeout is out.
    let silent: Vec<_> = [addr.clone(), osd]
        .into_iter()
        .map(|a| std::thread::spawn(move || (held_silent(&a), a)))
        .collect();
    for t in silent {
        let (held, a) = t.join().expect("silent client");
        assert!(
            held >= HANDSHAKE_TIMEOUT.saturating_sub(Duration::from_secs(1)),
            "{a} closed a silent client after {held:?}, before the handshake timeout"
        );
    }

    // Plain gRPC.
    let plain = Endpoint::from_shared(format!("http://{addr}")).map_err(|e| e.to_string());
    assert!(
        refused(call(&rt, "a plaintext client", plain)),
        "a plaintext client was served"
    );

    // TLS, trusting the CA, but no certificate of its own.
    let anonymous = Endpoint::from_shared(format!("https://{addr}"))
        .and_then(|e| {
            e.tls_config(
                ClientTlsConfig::new().ca_certificate(Certificate::from_pem(pem(&files.ca))),
            )
        })
        .map_err(|e| e.to_string());
    assert!(
        refused(call(&rt, "a client with no certificate", anonymous)),
        "a client with no certificate was served"
    );

    // A certificate another CA signed.
    let other = {
        use rcgen::{CertificateParams, KeyPair};
        let key = KeyPair::generate().unwrap();
        let cert = CertificateParams::new(vec!["127.0.0.1".to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        Identity::from_pem(cert.pem(), key.serialize_pem())
    };
    let stranger = Endpoint::from_shared(format!("https://{addr}"))
        .and_then(|e| {
            e.tls_config(
                ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(pem(&files.ca)))
                    .identity(other),
            )
        })
        .map_err(|e| e.to_string());
    assert!(
        refused(call(
            &rt,
            "a client with another CA's certificate",
            stranger
        )),
        "a client with another CA's certificate was served"
    );

    // The cluster's certificate: served, all of the above notwithstanding.
    objectio_e2e::tls::client();
    call(
        &rt,
        "a client with the cluster's certificate",
        objectio_proto::transport::endpoint(&addr),
    )
    .expect("the cluster's own certificate");
}

/// A channel to the gRPC server at `addr` presenting the test certificate
/// of `identity` (a role, or `tls::NO_ROLE`). Connecting, and each call,
/// fail rather than wait past [`WITHIN`].
fn channel_as(rt: &tokio::runtime::Runtime, addr: &str, identity: &str) -> Channel {
    let files = tls::files().expect("mTLS");
    let (cert, key) = files.pair(identity);
    let pem = |p: &std::path::Path| std::fs::read(p).unwrap();
    let endpoint = Endpoint::from_shared(format!("https://{addr}"))
        .unwrap()
        .tls_config(
            ClientTlsConfig::new()
                .ca_certificate(Certificate::from_pem(pem(&files.ca)))
                .identity(Identity::from_pem(pem(cert), pem(key))),
        )
        .unwrap()
        .user_agent(objectio_common::version::user_agent())
        .unwrap()
        .connect_timeout(WITHIN)
        .timeout(WITHIN);
    rt.block_on(objectio_proto::transport::connect(&endpoint))
        .unwrap_or_else(|e| panic!("{addr} as {identity}: {e}"))
}

#[test]
fn each_call_between_the_services_is_checked_against_the_callers_role() {
    if tls::files().is_none() {
        return; // the suite runs plain: no roles to check
    }
    let ha = HaCluster::start(1, 6, 1);
    let meta = ha
        .meta_endpoints()
        .trim_start_matches("http://")
        .to_string();
    let osd = ha.osd_endpoint(0).trim_start_matches("http://").to_string();
    let rt = tokio::runtime::Runtime::new().unwrap();

    // The cluster's secret, that STS and console sessions are signed with:
    // a gateway's alone.
    let sts = |identity: &str| {
        let mut c = MetadataServiceClient::new(channel_as(&rt, &meta, identity));
        rt.block_on(c.get_sts_signing_key(GetStsSigningKeyRequest {}))
            .map(|r| r.into_inner().key)
            .map_err(|s| s.code())
    };
    for identity in [tls::OSD, tls::BLOCK_GATEWAY, tls::ADMIN, tls::NO_ROLE] {
        assert_eq!(
            sts(identity),
            Err(Code::PermissionDenied),
            "a peer of role {identity} read the STS signing key"
        );
    }
    assert!(
        sts(tls::GATEWAY).is_ok_and(|k| !k.is_empty()),
        "a gateway is refused the STS signing key"
    );

    // A user's secret key, likewise.
    let key = |identity: &str| {
        let mut c = MetadataServiceClient::new(channel_as(&rt, &meta, identity));
        rt.block_on(c.get_access_key_for_auth(GetAccessKeyForAuthRequest {
            access_key_id: ha.access_key.clone(),
        }))
        .map(|r| {
            r.into_inner()
                .access_key
                .unwrap_or_default()
                .secret_access_key
        })
        .map_err(|s| s.code())
    };
    assert_eq!(key(tls::OSD), Err(Code::PermissionDenied));
    assert_eq!(key(tls::GATEWAY), Ok(ha.secret_key.clone()));

    // On an OSD: placement groups and purges are meta's.
    let list_pg = |identity: &str| {
        let mut c = StorageServiceClient::new(channel_as(&rt, &osd, identity));
        rt.block_on(c.list_pg(ListPgRequest::default()))
            .map(drop)
            .map_err(|s| s.code())
    };
    assert_eq!(list_pg(tls::GATEWAY), Err(Code::PermissionDenied));
    assert_eq!(list_pg(tls::OSD), Err(Code::PermissionDenied));
    assert_ne!(
        list_pg(tls::META),
        Err(Code::PermissionDenied),
        "meta is refused an OSD's placement groups"
    );
    let purge = rt
        .block_on(
            StorageServiceClient::new(channel_as(&rt, &osd, tls::GATEWAY)).purge(PurgeRequest {
                node_id: vec![0; 16],
            }),
        )
        .map(drop)
        .map_err(|s| s.code());
    assert_eq!(
        purge,
        Err(Code::PermissionDenied),
        "a gateway may purge an OSD"
    );
}

#[test]
fn meta_admin_port_changes_membership_only_for_an_admin() {
    tls::files().expect(
        "OBJECTIO_E2E_PLAIN is set: the cluster runs plain gRPC, and this test is about mTLS",
    );
    let ha = HaCluster::start(1, 6, 1);
    let init = serde_json::json!({});
    let learner = serde_json::json!({ "node_id": 99, "addr": "127.0.0.1:1" });
    let voters = serde_json::json!({ "voters": [1] });

    // Plain HTTP isn't served.
    let (plain, _) = tls::admin_http(false, None);
    let r = plain
        .post(
            ha.admin_url(0, "/change-membership")
                .replace("https://", "http://"),
        )
        .json(&voters)
        .send();
    assert!(
        r.as_ref().map_or(true, |r| !r.status().is_success()),
        "a plaintext membership change was served: {:?}",
        r.map(|r| r.status())
    );

    // HTTPS with no client certificate, or another role's: refused.
    for identity in [
        None,
        Some(tls::GATEWAY),
        Some(tls::META),
        Some(tls::NO_ROLE),
    ] {
        let (c, _) = tls::admin_http(true, identity);
        for (path, body) in [
            ("/init", &init),
            ("/add-learner", &learner),
            ("/change-membership", &voters),
        ] {
            let r = c.post(ha.admin_url(0, path)).json(body).send();
            assert_eq!(
                r.as_ref().map(reqwest::blocking::Response::status).ok(),
                Some(reqwest::StatusCode::FORBIDDEN),
                "{path} as {identity:?}: {r:?}"
            );
        }
    }

    // Status stays readable, and nothing changed. What kubelet's probes
    // ask, presenting no certificate, is answered.
    let (c, _) = tls::admin_http(true, None);
    for path in ["/health", "/ready"] {
        let r = c
            .get(ha.admin_url(0, path))
            .send()
            .unwrap_or_else(|e| panic!("{path} without a client certificate: {e}"));
        assert_eq!(r.status(), reqwest::StatusCode::OK, "{path}");
    }
    let status: serde_json::Value = c
        .get(ha.admin_url(0, "/status"))
        .send()
        .expect("status without a client certificate")
        .json()
        .unwrap();
    assert_eq!(status["voters"], serde_json::json!([1]), "{status}");
    assert_eq!(status["learners"], serde_json::json!([]), "{status}");
}

/// The local addresses of the TCP sockets process `pid` listens on.
fn listening(pid: u32) -> Vec<std::net::SocketAddr> {
    let inodes: std::collections::HashSet<String> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .expect("the process's descriptors")
        .filter_map(|e| std::fs::read_link(e.ok()?.path()).ok())
        .filter_map(|l| {
            let l = l.to_string_lossy();
            Some(l.strip_prefix("socket:[")?.strip_suffix(']')?.to_string())
        })
        .collect();
    let mut out = Vec::new();
    for table in ["tcp", "tcp6"] {
        let text = std::fs::read_to_string(format!("/proc/{pid}/net/{table}")).unwrap();
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            // local address, state 0A (LISTEN), inode
            if f.len() < 10 || f[3] != "0A" || !inodes.contains(f[9]) {
                continue;
            }
            let (ip, port) = f[1].split_once(':').unwrap();
            let port = u16::from_str_radix(port, 16).unwrap();
            // /proc prints each 32-bit word of the address in host order.
            let bytes: Vec<u8> = (0..ip.len() / 8)
                .flat_map(|w| {
                    u32::from_str_radix(&ip[w * 8..w * 8 + 8], 16)
                        .unwrap()
                        .to_ne_bytes()
                })
                .collect();
            let ip: std::net::IpAddr = match bytes.len() {
                4 => std::net::Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap()).into(),
                _ => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()).into(),
            };
            out.push(std::net::SocketAddr::new(ip, port));
        }
    }
    out
}

#[test]
fn the_all_in_one_keeps_its_internal_ports_on_loopback() {
    // S3 on every interface, as on a LAN; block storage on.
    let c = Cluster::start_with_args(
        1,
        &[
            "--listen-addr",
            "0.0.0.0",
            "--block-port",
            "{free}",
            "--nbd-port",
            "{free}",
        ],
    );
    let s3: u16 = c.endpoint.rsplit(':').next().unwrap().parse().unwrap();
    let ports = listening(c.pid().expect("aio running"));
    let internal: Vec<_> = ports.iter().filter(|a| a.port() != s3).collect();
    for flag in ["--block-port", "--nbd-port"] {
        let p: u16 = c.arg(flag).unwrap().parse().unwrap();
        assert!(
            internal.iter().any(|a| a.port() == p),
            "{flag} {p} is not among {ports:?}"
        );
    }
    // Meta's gRPC and admin ports, an OSD's, the block gateway's two.
    assert!(internal.len() >= 5, "{ports:?}");
    for a in &internal {
        assert!(
            a.ip().is_loopback(),
            "an internal port is open to the network: {a} (all: {ports:?})"
        );
    }
}
