//! A host set up with `objectio-install` runs a cluster that serves S3
//! (issue #59).
//!
//! The installer wrote units that started meta and the gateway with only
//! `--config`, a file neither reads: an installed meta ran with no peers
//! and the gateway looked for meta at an address nothing listened on. Now
//! the units carry the flags the chart passes, and `cluster init` forms the
//! Raft group. Each test installs hosts under temporary roots (one, then
//! three), runs exactly the command lines their units' `ExecStart=` name,
//! forms the group as the Linux guide does, and writes and reads objects
//! through the gateway with the admin's generated keys.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use objectio_e2e::{Cluster, binary};

/// The processes started from units, killed on drop. A failing test prints
/// the end of each one's log.
struct Services {
    children: Vec<(String, PathBuf, Child)>,
}

impl Drop for Services {
    fn drop(&mut self) {
        for (name, log, child) in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
            if std::thread::panicking() {
                let text = std::fs::read_to_string(&*log).unwrap_or_default();
                let tail: Vec<&str> = text.lines().rev().take(30).collect();
                eprintln!("--- {name} ({}):", log.display());
                for line in tail.iter().rev() {
                    eprintln!("{line}");
                }
            }
        }
    }
}

impl Services {
    const fn new() -> Self {
        Self {
            children: Vec::new(),
        }
    }

    /// Run the command line of `host`'s unit `unit`, as systemd would.
    fn start(&mut self, host: &Path, unit: &str) {
        let argv = exec_start(host, unit);
        let log = host.join(format!("{unit}.log"));
        let out = std::fs::File::create(&log).expect("log file");
        let child = Command::new(&argv[0])
            .args(&argv[1..])
            .current_dir(host)
            .stdout(Stdio::from(out.try_clone().expect("log file")))
            .stderr(Stdio::from(out))
            .spawn()
            .unwrap_or_else(|e| panic!("{unit}: {argv:?}: {e}"));
        self.children.push((unit.to_string(), log, child));
    }
}

/// The arguments of `ExecStart=` in `host`'s unit `unit`, unquoted as
/// systemd unquotes them.
fn exec_start(host: &Path, unit: &str) -> Vec<String> {
    let path = host.join(format!("etc/systemd/system/{unit}.service"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix("ExecStart="))
        .unwrap_or_else(|| panic!("{unit} has no ExecStart"));
    let mut argv = Vec::new();
    let mut arg = String::new();
    let (mut quoted, mut started) = (false, false);
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                quoted = !quoted;
                started = true;
            }
            '\\' => arg.extend(chars.next()),
            '%' | '$' if chars.peek() == Some(&c) => {
                chars.next();
                arg.push(c);
            }
            c if c.is_whitespace() && !quoted => {
                if started || !arg.is_empty() {
                    argv.push(std::mem::take(&mut arg));
                }
                started = false;
            }
            c => arg.push(c),
        }
    }
    if started || !arg.is_empty() {
        argv.push(arg);
    }
    argv
}

/// `objectio-install` with `args`; panics with its output if it fails.
fn installer(args: &[&str]) -> String {
    let out = Command::new(binary("objectio-install"))
        .args(args)
        .output()
        .expect("run objectio-install");
    assert!(
        out.status.success(),
        "objectio-install {args:?}: {}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// `objectio-install init` for a host under `root`, the binaries this
/// build's.
fn install(root: &Path, args: &[&str]) {
    let bin_dir = binary("objectio-meta");
    let bin_dir = bin_dir.parent().unwrap().display().to_string();
    let root = root.display().to_string();
    let mut all = vec!["init", "--root", &root, "--bin-dir", &bin_dir, "--systemd"];
    all.extend_from_slice(args);
    installer(&all);
}

/// A blank disk file under `root`, as a new drive reads.
fn disk(root: &Path, name: &str) -> String {
    let path = root.join("disks").join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::File::create(&path)
        .and_then(|f| f.set_len(2 << 30))
        .expect("disk file");
    path.display().to_string()
}

/// A free port, and `p + 2i` free too for `n` OSDs, below the range the
/// kernel picks ports from (`ip_local_port_range`, 32768 up by default).
///
/// A unit names its ports, so a service can't be moved to another one
/// that's free, as the `ha` harness does when a port it picked was taken
/// before its process bound it: an outgoing connection, which takes a port
/// from that range, once took an OSD's. Below it only another listener can
/// take one, and none of this binary's tests is given a port twice.
fn free_ports(n: u16) -> u16 {
    use std::hash::{BuildHasher, RandomState};
    static GIVEN: std::sync::Mutex<Vec<u16>> = std::sync::Mutex::new(Vec::new());
    loop {
        let r = RandomState::new().hash_one(Instant::now());
        let p = 20_000 + u16::try_from(r % 12_000).unwrap();
        let ports: Vec<u16> = (0..n.max(1)).map(|i| p + 2 * i).collect();
        let mut given = GIVEN.lock().unwrap();
        let free = ports
            .iter()
            .all(|q| !given.contains(q) && std::net::TcpListener::bind(("0.0.0.0", *q)).is_ok());
        if free {
            given.extend(&ports);
        }
        drop(given);
        if free {
            return p;
        }
    }
}

fn free_port() -> u16 {
    free_ports(1)
}

fn await_listening(port: u16, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "{what} never listened on {port}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// The admin's keys, from the file every meta node writes once the first
/// leader made the admin.
fn admin_keys(meta_data: &Path) -> (String, String) {
    let path = meta_data.join("admin-creds.env");
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let get = |name: &str| {
                text.lines()
                    .find_map(|l| l.split(&format!("{name}=")).nth(1))
                    .map(|v| v.trim().to_string())
            };
            if let (Some(a), Some(s)) = (get("AWS_ACCESS_KEY_ID"), get("AWS_SECRET_ACCESS_KEY")) {
                return (a, s);
            }
        }
        assert!(Instant::now() < deadline, "no {}", path.display());
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Wait for `osds` OSDs and the default pool, then write objects and read
/// them back.
fn serves_s3(c: &Cluster, osds: usize) {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let r = c.request("GET", "/_admin/nodes", &[]);
        let n = r
            .json()
            .get("nodes")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        if r.status == 200 && n >= osds {
            break;
        }
        assert!(Instant::now() < deadline, "{n} of {osds} OSDs registered");
        std::thread::sleep(Duration::from_millis(300));
    }
    // The default pool's placement groups are made once the OSDs are in;
    // until then a write is refused.
    loop {
        let r = c.request("GET", "/_admin/pools/default/placement-groups", &[]);
        if r.status == 200 && r.json()["pgs"].as_array().is_some_and(|p| !p.is_empty()) {
            break;
        }
        assert!(Instant::now() < deadline, "the default pool was never made");
        std::thread::sleep(Duration::from_millis(300));
    }
    c.request("PUT", "/installed", &[]).expect(200);
    for (key, len) in [("small", 100_usize), ("large", 3 << 20)] {
        let body: Vec<u8> = (0..len).map(|i| u8::try_from(i % 251).unwrap()).collect();
        c.request("PUT", &format!("/installed/{key}"), &body)
            .expect(200);
        let got = c.request("GET", &format!("/installed/{key}"), &[]);
        got.expect(200);
        assert!(got.bytes == body, "{key} read back differs");
    }
}

#[test]
fn one_host_set_up_by_the_installer_serves_s3() {
    let host = tempfile::tempdir().expect("tempdir");
    let root = host.path();
    let disks: Vec<String> = (0..3).map(|i| disk(root, &format!("d{i}"))).collect();
    let (meta, admin, metrics, gateway) = (free_port(), free_port(), free_port(), free_port());
    let (osd, osd_metrics) = (free_ports(3), free_ports(3));
    install(
        root,
        &[
            "--role",
            "all",
            "--disks",
            &disks.join(","),
            "--ec-profile",
            "2+1",
            "--advertise",
            "127.0.0.1",
            "--meta-port",
            &meta.to_string(),
            "--meta-admin-port",
            &admin.to_string(),
            "--meta-metrics-port",
            &metrics.to_string(),
            "--osd-port",
            &osd.to_string(),
            "--osd-metrics-port",
            &osd_metrics.to_string(),
            "--gateway-port",
            &gateway.to_string(),
        ],
    );
    // Meta and the gateway take flags only; each OSD has a file.
    let etc = root.join("etc/objectio");
    let mut written: Vec<String> = std::fs::read_dir(&etc)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    written.sort();
    assert_eq!(written, ["osd-0.toml", "osd-1.toml", "osd-2.toml"]);
    let meta_argv = exec_start(root, "objectio-meta");
    assert!(!meta_argv.iter().any(|a| a == "--config"), "{meta_argv:?}");

    let mut services = Services::new();
    services.start(root, "objectio-meta");
    await_listening(admin, "meta's admin port");
    let out = installer(&["cluster", "init", &format!("127.0.0.1:{admin}")]);
    assert!(out.contains("voters [1]"), "{out}");
    // Run again, it changes nothing.
    installer(&["cluster", "init", &format!("127.0.0.1:{admin}")]);

    for unit in [
        "objectio-osd-0",
        "objectio-osd-1",
        "objectio-osd-2",
        "objectio-gateway",
    ] {
        services.start(root, unit);
    }
    await_listening(gateway, "the gateway");
    let (ak, sk) = admin_keys(&root.join("var/lib/objectio/meta"));
    let c = Cluster::client(&format!("http://127.0.0.1:{gateway}"), &ak, &sk);
    serves_s3(&c, 3);
}

#[test]
fn three_hosts_set_up_by_the_installer_serve_s3() {
    let hosts: Vec<tempfile::TempDir> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let ports: Vec<(u16, u16, u16, u16)> = (0..3)
        .map(|_| (free_port(), free_port(), free_port(), free_port()))
        .collect();
    let gateway = free_port();
    let metas = ports
        .iter()
        .map(|(meta, ..)| format!("http://127.0.0.1:{meta}"))
        .collect::<Vec<_>>()
        .join(",");
    for (i, host) in hosts.iter().enumerate() {
        let root = host.path();
        let (meta, admin, metrics, osd) = ports[i];
        let d = disk(root, "d0");
        let id = (i + 1).to_string();
        let (meta, admin, metrics, osd) = (
            meta.to_string(),
            admin.to_string(),
            metrics.to_string(),
            osd.to_string(),
        );
        let gw = gateway.to_string();
        let mut args = vec![
            "--role",
            if i == 0 { "all" } else { "meta,osd" },
            "--node-id",
            &id,
            "--disks",
            &d,
            "--ec-profile",
            "2+1",
            "--advertise",
            "127.0.0.1",
            "--meta-endpoint",
            &metas,
            "--meta-port",
            &meta,
            "--meta-admin-port",
            &admin,
            "--meta-metrics-port",
            &metrics,
            "--osd-port",
            &osd,
            "--osd-metrics-port",
            "0",
        ];
        if i == 0 {
            args.extend(["--gateway-port", &gw]);
        }
        install(root, &args);
    }
    assert!(
        !hosts[1]
            .path()
            .join("etc/systemd/system/objectio-gateway.service")
            .exists()
    );

    let mut services = Services::new();
    for (i, host) in hosts.iter().enumerate() {
        services.start(host.path(), "objectio-meta");
        await_listening(ports[i].1, "meta's admin port");
    }
    let nodes: Vec<String> = ports
        .iter()
        .map(|(_, admin, ..)| format!("127.0.0.1:{admin}"))
        .collect();
    let mut args = vec!["cluster", "init"];
    args.extend(nodes.iter().map(String::as_str));
    let out = installer(&args);
    assert!(out.contains("voters [1, 2, 3]"), "{out}");
    // Run again, it changes nothing.
    installer(&args);

    for host in &hosts {
        services.start(host.path(), "objectio-osd-0");
    }
    services.start(hosts[0].path(), "objectio-gateway");
    await_listening(gateway, "the gateway");
    // Every meta node writes the admin's keys: the third host's will do.
    let (ak, sk) = admin_keys(&hosts[2].path().join("var/lib/objectio/meta"));
    let c = Cluster::client(&format!("http://127.0.0.1:{gateway}"), &ak, &sk);
    serves_s3(&c, 3);
}
