//! mTLS between the services (A8a) in the end-to-end tests.
//!
//! A CA, and a certificate for `127.0.0.1` and `localhost` per role, made
//! once per test process: each node presents its role's, as in production
//! (a SAN URI `spiffe://objectio/<role>`), and trusts the CA. The
//! all-in-one's certificate names every role, being every component; so
//! does the test process's own, which calls meta, OSDs and block gateways
//! directly as whichever component a test stands in for. On by default, as
//! production should run; `OBJECTIO_E2E_PLAIN=1` runs plain gRPC instead,
//! and so does a node from another release (rolling-upgrade tests).
//! `tests/mtls.rs` fails when the suite runs plain: it has nothing to test.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The roles a certificate may name, and what each test identity names.
pub const META: &str = "meta";
pub const OSD: &str = "osd";
pub const GATEWAY: &str = "gateway";
pub const BLOCK_GATEWAY: &str = "block-gateway";
pub const ADMIN: &str = "admin";
/// The all-in-one: every component in one process.
pub const AIO: &str = "aio";
/// The test process itself.
pub const CLIENT: &str = "client";
/// A certificate the CA signed that names no role.
pub const NO_ROLE: &str = "no-role";

const ALL_ROLES: [&str; 5] = [META, OSD, GATEWAY, BLOCK_GATEWAY, ADMIN];

/// The roles each test identity's certificate names.
fn roles_of(identity: &str) -> Vec<&'static str> {
    match identity {
        AIO | CLIENT => ALL_ROLES.to_vec(),
        NO_ROLE => Vec::new(),
        r => vec![
            *ALL_ROLES
                .iter()
                .find(|x| **x == r)
                .unwrap_or_else(|| panic!("no role {r}")),
        ],
    }
}

/// The test certificates' files.
pub struct Files {
    _dir: tempfile::TempDir,
    pub ca: PathBuf,
    /// Certificate and key, by identity.
    pairs: BTreeMap<&'static str, (PathBuf, PathBuf)>,
}

impl Files {
    /// The certificate and key of `identity` (a role, [`AIO`], [`CLIENT`]
    /// or [`NO_ROLE`]).
    ///
    /// # Panics
    /// For an identity there is none of.
    #[must_use]
    pub fn pair(&self, identity: &str) -> (&Path, &Path) {
        let (c, k) = self
            .pairs
            .get(identity)
            .unwrap_or_else(|| panic!("no test certificate for {identity}"));
        (c, k)
    }
}

static FILES: OnceLock<Option<Files>> = OnceLock::new();

/// The test certificates, made on first use; `None` when the tests run
/// plain.
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
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "objectio e2e CA");
    let ca_key = KeyPair::generate().expect("CA key");
    let ca = ca_params.self_signed(&ca_key).expect("CA certificate");

    let dir = tempfile::tempdir().expect("tempdir");
    let write = |name: &str, pem: String| {
        let path = dir.path().join(name);
        std::fs::write(&path, pem).expect("write PEM");
        path
    };
    let mut pairs = BTreeMap::new();
    for identity in [
        META,
        OSD,
        GATEWAY,
        BLOCK_GATEWAY,
        ADMIN,
        AIO,
        CLIENT,
        NO_ROLE,
    ] {
        let mut params =
            CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
                .expect("node params");
        params
            .distinguished_name
            .push(DnType::CommonName, format!("objectio e2e {identity}"));
        for role in roles_of(identity) {
            params.subject_alt_names.push(SanType::URI(
                format!("spiffe://objectio/{role}")
                    .try_into()
                    .expect("role URI"),
            ));
        }
        let key = KeyPair::generate().expect("node key");
        let cert = params
            .signed_by(&key, &ca, &ca_key)
            .expect("node certificate");
        pairs.insert(
            identity,
            (
                write(&format!("{identity}.pem"), cert.pem()),
                write(&format!("{identity}.key"), key.serialize_pem()),
            ),
        );
    }
    Files {
        ca: write("ca.pem", ca.pem()),
        pairs,
        _dir: dir,
    }
}

/// Give a node of this build the test certificate of `identity` (nothing
/// when plain).
pub fn apply(cmd: &mut Command, identity: &str) {
    if let Some(f) = files() {
        let (cert, key) = f.pair(identity);
        cmd.env("OBJECTIO_TLS_CERT", cert)
            .env("OBJECTIO_TLS_KEY", key)
            .env("OBJECTIO_TLS_CA", &f.ca);
    }
}

/// The test process's own gRPC clients (a test calling meta or the block
/// gateway directly) speak what the nodes do, with a certificate naming
/// every role.
pub fn client() {
    if let Some(f) = files() {
        let (cert, key) = f.pair(CLIENT);
        objectio_proto::transport::configure_tls(&objectio_proto::transport::TlsArgs {
            tls_cert: Some(cert.to_path_buf()),
            tls_key: Some(key.to_path_buf()),
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

/// An HTTP client for meta's admin port: HTTPS presenting `identity`'s
/// certificate (none: no client certificate) under mTLS, plain HTTP
/// otherwise, as `tls` says. Returns the client and the URL scheme.
///
/// # Panics
/// If the test certificates can't be loaded.
#[must_use]
pub fn admin_http(tls: bool, identity: Option<&str>) -> (reqwest::blocking::Client, &'static str) {
    // No idle connection kept, as `crate::http_client`: never one to a
    // node a test restarted since.
    let builder = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .pool_max_idle_per_host(0);
    let Some(f) = files().filter(|_| tls) else {
        return (builder.build().expect("http client"), "http");
    };
    let ca = reqwest::Certificate::from_pem(&std::fs::read(&f.ca).expect("CA")).expect("CA PEM");
    let mut builder = builder
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(ca);
    if let Some(identity) = identity {
        let (cert, key) = f.pair(identity);
        let mut pem = std::fs::read(cert).expect("cert");
        pem.extend(std::fs::read(key).expect("key"));
        builder = builder.identity(reqwest::Identity::from_pem(&pem).expect("identity PEM"));
    }
    (builder.build().expect("https client"), "https")
}
