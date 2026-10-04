//! `obioctl` against a real gateway: the built binary, signing with
//! `SigV4` through the admin API, as an operator would run it.
//!
//! Needs `cargo build --bin obioctl --bin objectio-aio` first.

use objectio_e2e::{Cluster, binary};
use serde_json::Value;
use std::path::Path;
use std::process::{Command, Output};

/// Runs the CLI with a clean environment: only the variables given, and a
/// `HOME` of its own so no real profile file is read.
struct Cli<'a> {
    c: &'a Cluster,
    home: tempfile::TempDir,
}

impl<'a> Cli<'a> {
    fn new(c: &'a Cluster) -> Self {
        Self {
            c,
            home: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(binary("obioctl"));
        cmd.env_clear()
            .env("HOME", self.home.path())
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("OBJECTIO_ENDPOINT", &self.c.endpoint);
        cmd
    }

    /// As the system admin, from the environment.
    fn admin(&self, args: &[&str]) -> Output {
        self.command()
            .env("OBJECTIO_ACCESS_KEY", &self.c.access_key)
            .env("OBJECTIO_SECRET_KEY", &self.c.secret_key)
            .args(args)
            .output()
            .expect("run obioctl")
    }

    /// With the credentials of a profile in the profile file.
    fn profile(&self, profile: &str, args: &[&str]) -> Output {
        self.command()
            .arg("--profile")
            .arg(profile)
            .args(args)
            .output()
            .expect("run obioctl")
    }
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "obioctl failed ({}):\nstdout: {}\nstderr: {}",
        o.status,
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn json(o: &Output) -> Value {
    let text = ok(o);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("not JSON ({e}): {text}"))
}

fn write(dir: &Path, name: &str, content: &str) -> String {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p.to_str().unwrap().to_string()
}

const READ_LOGS: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow",
  "Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::logs","arn:aws:s3:::logs/*"]}]}"#;

const LIFECYCLE: &str = "<LifecycleConfiguration><Rule><ID>expire-tmp</ID>\
  <Filter><Prefix>tmp/</Prefix></Filter><Status>Enabled</Status>\
  <Expiration><Days>7</Days></Expiration></Rule></LifecycleConfiguration>";

#[test]
#[allow(clippy::too_many_lines)] // one operator session, start to finish
fn an_operator_and_a_tenant_admin_manage_the_cluster_through_the_cli() {
    let c = Cluster::start();
    let cli = Cli::new(&c);
    let dir = tempfile::tempdir().unwrap();

    // ── The system admin: a tenant, its admin, and the admin's key ──────
    ok(&cli.admin(&["tenant", "create", "acme", "--display-name", "Acme Corp"]));
    let tenants = json(&cli.admin(&["-o", "json", "tenant", "list"]));
    assert!(
        tenants
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["name"] == "acme" && t["display_name"] == "Acme Corp"),
        "{tenants}"
    );

    let admin = json(&cli.admin(&[
        "-o",
        "json",
        "user",
        "create",
        "acme-admin",
        "--tenant",
        "acme",
    ]));
    assert_eq!(admin["tenant"], "acme");
    let admin_id = admin["user_id"].as_str().unwrap().to_string();
    ok(&cli.admin(&["tenant", "admin", "add", "acme", &admin_id]));
    let admins = json(&cli.admin(&["-o", "json", "tenant", "admin", "list", "acme"]));
    assert!(
        admins
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a == admin_id.as_str())
    );

    let key = json(&cli.admin(&["-o", "json", "key", "create", &admin_id]));
    let ak = key["access_key_id"].as_str().unwrap().to_string();
    let sk = key["secret_access_key"].as_str().unwrap().to_string();

    // A profile for the tenant admin, written by `configure`.
    ok(&cli
        .command()
        .args([
            "--profile",
            "acme",
            "--endpoint",
            &c.endpoint,
            "--access-key",
            &ak,
            "--secret-key",
            &sk,
            "configure",
            "--non-interactive",
        ])
        .output()
        .unwrap());
    let listed = ok(&cli
        .command()
        .args(["configure", "--list"])
        .output()
        .unwrap());
    assert!(listed.contains("acme"), "{listed}");
    assert!(
        !listed.contains(&sk),
        "configure --list printed a secret: {listed}"
    );

    // ── As the tenant admin ─────────────────────────────────────────────
    let alice = json(&cli.profile("acme", &["-o", "json", "user", "create", "alice"]));
    assert_eq!(
        alice["tenant"], "acme",
        "no --tenant means the caller's own"
    );
    let alice_id = alice["user_id"].as_str().unwrap().to_string();
    let alice_key = json(&cli.profile("acme", &["-o", "json", "key", "create", &alice_id]));
    let alice_ak = alice_key["access_key_id"].as_str().unwrap().to_string();

    let policy = write(dir.path(), "read-logs.json", READ_LOGS);
    ok(&cli.profile(
        "acme",
        &["policy", "create", "read-logs", "--file", &policy],
    ));
    ok(&cli.profile(
        "acme",
        &["policy", "attach", "read-logs", "--user", &alice_id],
    ));
    let attached = json(&cli.profile(
        "acme",
        &["-o", "json", "policy", "attached", "--user", &alice_id],
    ));
    assert_eq!(attached["policy_names"], serde_json::json!(["read-logs"]));

    ok(&cli.profile("acme", &["user", "suspend", &alice_id]));
    let shown = json(&cli.profile("acme", &["-o", "json", "user", "show", &alice_id]));
    assert_eq!(shown["status"], "suspended");

    // Block Public Access for the tenant: no --tenant is the admin's own.
    ok(&cli.profile(
        "acme",
        &["public-access-block", "put", "--block-public-policy"],
    ));
    let pab = json(&cli.profile("acme", &["-o", "json", "public-access-block", "get"]));
    assert_eq!(pab["tenant"], "acme");
    assert_eq!(pab["BlockPublicPolicy"], true);
    assert_eq!(pab["BlockPublicAcls"], false, "a put replaces the block");

    // A bucket and its lifecycle, the latter over the S3 path.
    ok(&cli.profile("acme", &["bucket", "create", "logs"]));
    let buckets = json(&cli.profile("acme", &["-o", "json", "bucket", "list"]));
    let logs = buckets["buckets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == "logs")
        .expect("bucket listed")
        .clone();
    assert_eq!(logs["tenant"], "acme");
    assert_eq!(logs["owner"], admin_id.as_str());
    let lifecycle = write(dir.path(), "lifecycle.xml", LIFECYCLE);
    ok(&cli.profile(
        "acme",
        &["bucket", "lifecycle", "put", "logs", "--file", &lifecycle],
    ));
    let got = ok(&cli.profile("acme", &["bucket", "lifecycle", "get", "logs"]));
    assert!(
        got.contains("expire-tmp") && got.contains("<Days>7</Days>"),
        "{got}"
    );

    // Deactivate alice's key; it stays, inactive.
    ok(&cli.profile("acme", &["key", "deactivate", &alice_ak]));
    let keys = json(&cli.profile("acme", &["-o", "json", "key", "list", &alice_id]));
    let k = keys["access_keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["access_key_id"] == alice_ak.as_str())
        .expect("key still listed")
        .clone();
    assert_eq!(k["status"], "inactive");
    assert!(k.get("secret_access_key").is_none());

    // ── Back to the system admin: the cluster's audit stream ────────────
    let audit = write(
        dir.path(),
        "audit.json",
        r#"{"targets":[{"type":"stdout","name":"console"}]}"#,
    );
    ok(&cli.admin(&["audit", "put", "--file", &audit]));
    let got = json(&cli.admin(&["-o", "json", "audit", "get"]));
    assert_eq!(got["tenant"], "");
    assert_eq!(got["targets"][0]["type"], "stdout");
    assert_eq!(got["targets"][0]["name"], "console");
    // And the table form renders it.
    let table = ok(&cli.admin(&["audit", "get"]));
    assert!(
        table.contains("console") && table.contains("(cluster)"),
        "{table}"
    );
}

#[test]
fn errors_exit_non_zero_with_the_servers_message() {
    let cluster = Cluster::start();
    let cli = Cli::new(&cluster);

    let o = cli.admin(&["tenant", "show", "no-such-tenant"]);
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("404") && err.contains("not found"), "{err}");

    // A wrong secret is the server's refusal, not a crash.
    let o = cli
        .command()
        .env("OBJECTIO_ACCESS_KEY", &cluster.access_key)
        .env("OBJECTIO_SECRET_KEY", "wrong")
        .args(["tenant", "list"])
        .output()
        .unwrap();
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains("403") || err.contains("401"), "{err}");

    // No credentials at all is caught before any request.
    let o = cli.command().args(["user", "list"]).output().unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("no credentials"));

    // A tenant admin cannot reach another tenant.
    ok(&cli.admin(&["tenant", "create", "t1"]));
    ok(&cli.admin(&["tenant", "create", "t2"]));
    let user = json(&cli.admin(&["-o", "json", "user", "create", "t1-admin", "--tenant", "t1"]));
    let uid = user["user_id"].as_str().unwrap();
    ok(&cli.admin(&["tenant", "admin", "add", "t1", uid]));
    let key = json(&cli.admin(&["-o", "json", "key", "create", uid]));
    let o = cli
        .command()
        .env(
            "OBJECTIO_ACCESS_KEY",
            key["access_key_id"].as_str().unwrap(),
        )
        .env("OBJECTIO_SECRET_KEY_FILE", {
            let path = cli.home.path().join("sk");
            std::fs::write(
                &path,
                format!("{}\n", key["secret_access_key"].as_str().unwrap()),
            )
            .unwrap();
            path
        })
        .args(["policy", "list", "--tenant", "t2"])
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("403"));
}

/// Block volumes through the CLI: create, attach (an NBD export), list the
/// attachment, detach, delete.
#[test]
fn volumes_are_created_attached_and_detached_through_the_cli() {
    let c = Cluster::start_with_ec_and_args(
        6,
        4,
        2,
        &["--block-port", "{free}", "--nbd-port", "{free}"],
    );
    let block = format!("http://127.0.0.1:{}", c.arg("--block-port").unwrap());
    let cli = Cli::new(&c);
    let run = |args: &[&str]| {
        let mut all = vec!["--block-endpoint", block.as_str(), "-o", "json"];
        all.extend_from_slice(args);
        cli.admin(&all)
    };
    let vol = json(&run(&["volume", "create", "disk1", "--size", "16M"]));
    let id = vol["volume_id"].as_str().expect("volume_id").to_string();
    let att = json(&run(&["volume", "attach", &id, "--read-only"]));
    assert_eq!(att["read_only"], true, "{att}");
    let list = json(&run(&["volume", "attachments"]));
    assert!(list.to_string().contains(&id), "{list}");
    ok(&run(&["volume", "detach", &id]));
    let list = json(&run(&["volume", "attachments", "--volume-id", &id]));
    assert!(!list.to_string().contains("\"read_only\":true"), "{list}");
    ok(&run(&["volume", "delete", &id]));
}
