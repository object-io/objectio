//! mTLS between the services (A8a) in the end-to-end tests.
//!
//! A CA and one certificate for `127.0.0.1` and `localhost`, made once per
//! test process, that every node presents and trusts. On by default, as
//! production should run; `OBJECTIO_E2E_PLAIN=1` runs plain gRPC instead,
//! and so does a node from another release (rolling-upgrade tests: before
//! TLS).

use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// The test certificate's files.
pub struct Files {
    _dir: tempfile::TempDir,
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: PathBuf,
}

static FILES: OnceLock<Option<Files>> = OnceLock::new();

/// The test certificate, made on first use; `None` when the tests run plain.
pub fn files() -> Option<&'static Files> {
    FILES
        .get_or_init(|| {
            if std::env::var_os("OBJECTIO_E2E_PLAIN").is_some() {
                return None;
            }
            Some(make())
        })
        .as_ref()
}

fn make() -> Files {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "objectio e2e CA");
    let ca_key = KeyPair::generate().expect("CA key");
    let ca = ca_params.self_signed(&ca_key).expect("CA certificate");

    let mut params = CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
        .expect("node params");
    params
        .distinguished_name
        .push(DnType::CommonName, "objectio e2e node");
    let key = KeyPair::generate().expect("node key");
    let cert = params
        .signed_by(&key, &ca, &ca_key)
        .expect("node certificate");

    let dir = tempfile::tempdir().expect("tempdir");
    let write = |name: &str, pem: String| {
        let path = dir.path().join(name);
        std::fs::write(&path, pem).expect("write PEM");
        path
    };
    Files {
        cert: write("node.pem", cert.pem()),
        key: write("node.key", key.serialize_pem()),
        ca: write("ca.pem", ca.pem()),
        _dir: dir,
    }
}

/// Give a node of this build the test certificate (nothing when plain).
pub fn apply(cmd: &mut Command) {
    if let Some(f) = files() {
        cmd.env("OBJECTIO_TLS_CERT", &f.cert)
            .env("OBJECTIO_TLS_KEY", &f.key)
            .env("OBJECTIO_TLS_CA", &f.ca);
    }
}

/// The test process's own gRPC clients (a test calling meta or the block
/// gateway directly) speak what the nodes do.
pub fn client() {
    if let Some(f) = files() {
        objectio_proto::transport::configure_tls(&objectio_proto::transport::TlsArgs {
            tls_cert: Some(f.cert.clone()),
            tls_key: Some(f.key.clone()),
            tls_ca: Some(f.ca.clone()),
        })
        .expect("test TLS");
    }
}

/// A channel to the gRPC server at `addr` (`host:port`), as the nodes'
/// TLS setting requires.
///
/// # Errors
/// The address doesn't parse, or nothing answers.
pub async fn channel(addr: &str) -> Result<tonic::transport::Channel, String> {
    client();
    objectio_proto::transport::endpoint(addr)?
        .connect()
        .await
        .map_err(|e| e.to_string())
}
