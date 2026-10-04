//! A cluster of separate processes, for what one `objectio-aio` can't show.
//!
//! Several meta nodes in one Raft group, OSDs and gateways: losing a meta
//! node, the leader among them, and the cluster going on.
//!
//! Every OSD and gateway is given every meta node's address; any meta node
//! serves any call (a follower forwards it to the leader).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::{Cluster, binary, free_port};

/// One meta node: how to start it again, and its process when running.
struct Meta {
    id: u64,
    grpc: u16,
    admin: u16,
    dir: PathBuf,
    /// Where its binary comes from: `None` for this build, or a directory
    /// holding another release's (rolling-upgrade tests).
    bins: Mutex<Option<PathBuf>>,
    /// Behind a lock so a test can kill and restart nodes while other
    /// threads use the cluster.
    child: Mutex<Option<Child>>,
}

impl Meta {
    fn running(&self) -> bool {
        self.child.lock().unwrap().is_some()
    }
}

/// One OSD: how to start it again, and its process when running.
struct Osd {
    port: u16,
    state: PathBuf,
    disk: PathBuf,
    child: Option<Child>,
}

/// One gateway: how to start it again, and its process when running.
struct Gateway {
    port: u16,
    child: Option<Child>,
    /// Its own flags, after the cluster's.
    args: Vec<String>,
}

/// A binary from `bins` (another release's), or from this build.
fn bin(bins: Option<&Path>, name: &str) -> PathBuf {
    bins.map_or_else(|| binary(name), |dir| dir.join(name))
}

pub struct HaCluster {
    dir: tempfile::TempDir,
    metas: Vec<Meta>,
    osds: Vec<Osd>,
    gateways: Vec<Gateway>,
    /// A signed client of each gateway, as the admin.
    pub clients: Vec<Cluster>,
    pub access_key: String,
    pub secret_key: String,
    /// Flags every meta node gets besides the harness's own.
    meta_args: Vec<String>,
    /// Whether the cluster runs mTLS between its nodes: decided when it
    /// starts, for its whole life. One started from another release (a
    /// rolling upgrade) runs plain, also once its nodes run this build: a
    /// cluster can't run half on TLS.
    tls: bool,
}

impl Drop for HaCluster {
    fn drop(&mut self) {
        let mut metas: Vec<Child> = self
            .metas
            .iter()
            .filter_map(|m| m.child.lock().unwrap().take())
            .collect();
        let children = self
            .gateways
            .iter_mut()
            .filter_map(|g| g.child.as_mut())
            .chain(self.osds.iter_mut().filter_map(|o| o.child.as_mut()))
            .chain(metas.iter_mut());
        for c in children {
            // A frozen process ignores SIGKILL until it runs again.
            let _ = Command::new("kill")
                .args(["-CONT", &c.id().to_string()])
                .status();
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn log_target() -> Stdio {
    if std::env::var_os("OBJECTIO_E2E_LOGS").is_some() {
        Stdio::inherit()
    } else {
        Stdio::null()
    }
}

fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http client")
}

/// A meta node's Raft view, from its admin port.
#[derive(Debug, Clone)]
pub struct RaftStatus {
    pub state: String,
    pub leader: Option<u64>,
    pub term: u64,
    pub last_applied: u64,
    /// Index the last snapshot covers (0: none yet).
    pub snapshot: u64,
    /// Index the log is purged up to (0: nothing purged).
    pub purged: u64,
    pub voters: Vec<u64>,
}

impl HaCluster {
    /// `metas` meta nodes in one Raft group, `osds` OSDs (4+2), and
    /// `gateways` gateways with auth on, all separate processes.
    #[must_use]
    pub fn start(metas: usize, osds: usize, gateways: usize) -> Self {
        Self::start_from(None, metas, osds, gateways)
    }

    /// As [`Self::start`], every node from the binaries in `bins` (another
    /// release's), or from this build when `None`.
    #[must_use]
    pub fn start_from(bins: Option<&Path>, metas: usize, osds: usize, gateways: usize) -> Self {
        Self::start_with(bins, metas, osds, gateways, &[])
    }

    /// As [`Self::start`], every meta node also given `meta_args`.
    #[must_use]
    pub fn start_with_meta_args(
        metas: usize,
        osds: usize,
        gateways: usize,
        meta_args: &[&str],
    ) -> Self {
        Self::start_with(None, metas, osds, gateways, meta_args)
    }

    fn start_with(
        bins: Option<&Path>,
        metas: usize,
        osds: usize,
        gateways: usize,
        meta_args: &[&str],
    ) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cluster = Self {
            metas: (1..=metas)
                .map(|i| Meta {
                    id: i as u64,
                    grpc: free_port(),
                    admin: free_port(),
                    dir: dir.path().join(format!("meta{i}")),
                    bins: Mutex::new(bins.map(Path::to_path_buf)),
                    child: Mutex::new(None),
                })
                .collect(),
            dir,
            osds: Vec::new(),
            gateways: Vec::new(),
            clients: Vec::new(),
            access_key: String::new(),
            secret_key: String::new(),
            meta_args: meta_args.iter().map(ToString::to_string).collect(),
            tls: bins.is_none(),
        };
        for i in 0..metas {
            // A port it lost to another process: new ones, before any peer
            // knows them.
            while !cluster.spawn_meta(i) {
                cluster.metas[i].grpc = free_port();
                cluster.metas[i].admin = free_port();
            }
        }
        cluster.form_raft_group();

        for o in 0..osds {
            let state = cluster.dir.path().join(format!("osd{o}"));
            std::fs::create_dir_all(state.join("state")).expect("osd dir");
            let disk = state.join("disk.raw");
            std::fs::File::create(&disk)
                .and_then(|f| f.set_len(2 << 30))
                .expect("osd disk");
            cluster.osds.push(Osd {
                port: free_port(),
                state,
                disk,
                child: None,
            });
            cluster.spawn_osd(o, bins);
            while !cluster.osd_listening(o) {
                cluster.osds[o].port = free_port();
                cluster.spawn_osd(o, bins);
            }
        }

        let creds = cluster.metas[0].dir.join("admin-creds.env");
        let (ak, sk) = await_credentials(&creds);
        cluster.access_key = ak;
        cluster.secret_key = sk;
        for _ in 0..gateways {
            cluster.add_gateway(bins);
        }
        cluster.await_osds(osds);
        cluster
    }

    /// Every meta node's gRPC address, comma-separated.
    #[must_use]
    pub fn meta_endpoints(&self) -> String {
        self.metas
            .iter()
            .map(|m| format!("http://127.0.0.1:{}", m.grpc))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Start OSD `i` from `bins` (see [`Self::start_from`]).
    fn spawn_osd(&mut self, i: usize, bins: Option<&Path>) {
        let endpoints = self.meta_endpoints();
        let o = &mut self.osds[i];
        let mut cmd = Command::new(bin(bins, "objectio-osd"));
        if self.tls {
            crate::tls::apply(&mut cmd);
        }
        let child = cmd
            .args([
                "--listen",
                &format!("127.0.0.1:{}", o.port),
                "--advertise-addr",
                &format!("http://127.0.0.1:{}", o.port),
                "--meta-endpoint",
                &endpoints,
                "--data-dir",
                &o.state.join("state").display().to_string(),
                "--disks",
                &o.disk.display().to_string(),
                "--metrics-port",
                "0",
            ])
            .stdout(log_target())
            .stderr(log_target())
            .spawn()
            .expect("spawn objectio-osd");
        o.child = Some(child);
    }

    /// Start gateway `i` from `bins`, and wait until it listens. False if
    /// it exited instead (see [`await_child_listening`]).
    fn spawn_gateway(&mut self, i: usize, bins: Option<&Path>) -> bool {
        let endpoints = self.meta_endpoints();
        let port = self.gateways[i].port;
        let mut cmd = Command::new(bin(bins, "objectio-gateway"));
        if self.tls {
            crate::tls::apply(&mut cmd);
        }
        let child = cmd
            // Every gateway the same SSE master key, as in production.
            .env(
                "OBJECTIO_MASTER_KEY",
                "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
            )
            .args([
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--meta-endpoint",
                &endpoints,
                "--external-endpoint",
                &format!("http://127.0.0.1:{port}"),
                "--test-hooks",
            ])
            .args(&self.gateways[i].args)
            .stdout(log_target())
            .stderr(log_target())
            .spawn()
            .expect("spawn objectio-gateway");
        let gateway = &mut self.gateways[i];
        gateway.child = Some(child);
        await_child_listening(gateway.child.as_mut().unwrap(), &[port])
    }

    /// Start one more gateway, from `bins`, with a signed client of it in
    /// `clients`. Returns its index.
    pub fn add_gateway(&mut self, bins: Option<&Path>) -> usize {
        self.add_gateway_with_args(bins, &[])
    }

    /// [`Self::add_gateway`], the gateway started with `args` too.
    pub fn add_gateway_with_args(&mut self, bins: Option<&Path>, args: &[&str]) -> usize {
        self.gateways.push(Gateway {
            port: free_port(),
            child: None,
            args: args.iter().map(ToString::to_string).collect(),
        });
        let i = self.gateways.len() - 1;
        while !self.spawn_gateway(i, bins) {
            self.gateways[i].port = free_port();
        }
        let port = self.gateways[i].port;
        self.clients.push(Cluster::client(
            &format!("http://127.0.0.1:{port}"),
            &self.access_key,
            &self.secret_key,
        ));
        i
    }

    /// Stop OSD `i` and start it again from `bins`, on its own data.
    /// Stop OSD `i` (killed, as a crash); [`Self::start_osd`] brings it back.
    pub fn stop_osd(&mut self, i: usize) {
        if let Some(mut c) = self.osds[i].child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Start OSD `i` again, from `bins`, on its data.
    pub fn start_osd(&mut self, i: usize, bins: Option<&Path>) {
        retry(
            || {
                self.spawn_osd(i, bins);
                self.osd_listening(i)
            },
            "OSD",
        );
    }

    /// Wait until OSD `i` listens; false if it exited instead.
    fn osd_listening(&mut self, i: usize) -> bool {
        let o = &mut self.osds[i];
        await_child_listening(o.child.as_mut().expect("OSD started"), &[o.port])
    }

    pub fn restart_osd(&mut self, i: usize, bins: Option<&Path>) {
        if let Some(mut c) = self.osds[i].child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        self.start_osd(i, bins);
    }

    /// Stop gateway `i` and start it again from `bins`.
    pub fn restart_gateway(&mut self, i: usize, bins: Option<&Path>) {
        if let Some(mut c) = self.gateways[i].child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        retry(|| self.spawn_gateway(i, bins), "gateway");
    }

    /// Stop meta node `i` and start it again from `bins`, on its own data.
    pub fn restart_meta(&self, i: usize, bins: Option<&Path>) {
        self.kill_meta(i);
        *self.metas[i].bins.lock().unwrap() = bins.map(Path::to_path_buf);
        self.start_meta(i);
    }

    /// How many OSDs and gateways the cluster has.
    #[must_use]
    pub const fn sizes(&self) -> (usize, usize) {
        (self.osds.len(), self.gateways.len())
    }

    /// Start meta node `i` (again), on its own data. Its ports are known to
    /// its peers, so one it lost is retried, not changed.
    pub fn start_meta(&self, i: usize) {
        retry(|| self.spawn_meta(i), "meta");
    }

    /// Start meta node `i` and wait until it listens; false if it exited
    /// instead (see [`await_child_listening`]).
    fn spawn_meta(&self, i: usize) -> bool {
        let m = &self.metas[i];
        std::fs::create_dir_all(&m.dir).expect("meta dir");
        let bins = m.bins.lock().unwrap().clone();
        let mut cmd = Command::new(bin(bins.as_deref(), "objectio-meta"));
        if self.tls {
            crate::tls::apply(&mut cmd);
        }
        let child = cmd
            .args([
                "--node-id",
                &m.id.to_string(),
                "--listen",
                &format!("127.0.0.1:{}", m.grpc),
                "--raft-advertise",
                &format!("127.0.0.1:{}", m.grpc),
                "--data-dir",
                &m.dir.display().to_string(),
                "--metrics-port",
                "0",
                "--admin-port",
                &m.admin.to_string(),
                "--ec-k",
                "4",
                "--ec-m",
                "2",
                "--repair-interval-secs",
                "0",
            ])
            .args(&self.meta_args)
            .stdout(log_target())
            .stderr(log_target())
            .spawn()
            .expect("spawn objectio-meta");
        let mut slot = m.child.lock().unwrap();
        *slot = Some(child);
        await_child_listening(slot.as_mut().unwrap(), &[m.grpc, m.admin])
    }

    /// Kill meta node `i` outright.
    pub fn kill_meta(&self, i: usize) {
        let child = self.metas[i].child.lock().unwrap().take();
        if let Some(mut c) = child {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Freeze meta node `i` (SIGSTOP): it holds its connections but answers
    /// nothing, as across a network partition.
    pub fn freeze_meta(&self, i: usize) {
        self.signal(i, "-STOP");
    }

    /// Let a frozen meta node run again (SIGCONT).
    pub fn thaw_meta(&self, i: usize) {
        self.signal(i, "-CONT");
    }

    fn signal(&self, i: usize, sig: &str) {
        let pid = self.metas[i]
            .child
            .lock()
            .unwrap()
            .as_ref()
            .expect("meta running")
            .id();
        Command::new("kill")
            .args([sig, &pid.to_string()])
            .status()
            .expect("kill");
    }

    /// Meta node `i`'s Raft view; `None` if it doesn't answer.
    #[must_use]
    pub fn status(&self, i: usize) -> Option<RaftStatus> {
        let v: serde_json::Value = http()
            .get(format!("http://127.0.0.1:{}/status", self.metas[i].admin))
            .send()
            .ok()?
            .json()
            .ok()?;
        Some(RaftStatus {
            state: v["state"].as_str().unwrap_or_default().to_string(),
            leader: v["leader_id"].as_u64(),
            term: v["current_term"].as_u64().unwrap_or(0),
            last_applied: v["last_applied"].as_u64().unwrap_or(0),
            snapshot: v["snapshot"].as_u64().unwrap_or(0),
            purged: v["purged"].as_u64().unwrap_or(0),
            voters: v["voters"]
                .as_array()
                .map(|a| a.iter().filter_map(serde_json::Value::as_u64).collect())
                .unwrap_or_default(),
        })
    }

    /// The index of the meta node that leads, waiting up to `within` for
    /// one that every running node agrees on.
    ///
    /// # Panics
    /// When none is agreed on in time.
    #[must_use]
    pub fn await_leader(&self, within: Duration) -> usize {
        self.await_leader_among_others(within, &[])
    }

    /// As [`Self::await_leader`], ignoring the nodes in `excluding` (frozen
    /// ones, which answer nothing).
    ///
    /// # Panics
    /// When no leader is agreed on in time.
    #[must_use]
    pub fn await_leader_among_others(&self, within: Duration, excluding: &[usize]) -> usize {
        let deadline = Instant::now() + within;
        loop {
            let running: Vec<usize> = (0..self.metas.len())
                .filter(|&i| self.metas[i].running() && !excluding.contains(&i))
                .collect();
            let views: Vec<Option<RaftStatus>> = running.iter().map(|&i| self.status(i)).collect();
            if let Some(Some(first)) = views.first()
                && let Some(leader) = first.leader
                && views
                    .iter()
                    .all(|v| v.as_ref().and_then(|s| s.leader) == Some(leader))
                && let Some(i) = self.metas.iter().position(|m| m.id == leader)
                && running.contains(&i)
            {
                return i;
            }
            assert!(Instant::now() < deadline, "no agreed leader: {views:?}");
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Bootstrap the first node as a one-voter group, add the rest as
    /// learners, then make every node a voter.
    fn form_raft_group(&self) {
        let admin = |path: &str, body: serde_json::Value| {
            let r = http()
                .post(format!("http://127.0.0.1:{}{path}", self.metas[0].admin))
                .json(&body)
                .send()
                .unwrap_or_else(|e| panic!("{path}: {e}"));
            assert!(
                r.status().is_success(),
                "{path}: {}",
                r.text().unwrap_or_default()
            );
        };
        admin("/init", serde_json::json!({}));
        // The rest join below: only the first has a leader yet.
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.status(0).is_none_or(|s| s.state != "Leader") {
            assert!(Instant::now() < deadline, "the first meta node never led");
            std::thread::sleep(Duration::from_millis(100));
        }
        for m in &self.metas[1..] {
            admin(
                "/add-learner",
                serde_json::json!({ "node_id": m.id, "addr": format!("127.0.0.1:{}", m.grpc) }),
            );
        }
        let voters: Vec<u64> = self.metas.iter().map(|m| m.id).collect();
        admin(
            "/change-membership",
            serde_json::json!({ "voters": voters }),
        );
    }

    /// Replace meta node `i` with a new, empty one (a new id and port): the
    /// old one is taken out of the group and stopped, its data dropped, and
    /// the new one added as a learner and made a voter. Returns the new
    /// node's index.
    ///
    /// # Panics
    /// When the group refuses a step.
    pub fn replace_meta(&mut self, i: usize) -> usize {
        let leader = self.await_leader(Duration::from_secs(20));
        let leader_admin = self.metas[leader].admin;
        let post = |path: &str, body: serde_json::Value| {
            let r = http()
                .post(format!("http://127.0.0.1:{leader_admin}{path}"))
                .json(&body)
                .send()
                .unwrap_or_else(|e| panic!("{path}: {e}"));
            assert!(
                r.status().is_success(),
                "{path}: {}",
                r.text().unwrap_or_default()
            );
        };
        let new_id = self.metas.iter().map(|m| m.id).max().unwrap_or(0) + 1;
        let new = Meta {
            id: new_id,
            grpc: free_port(),
            admin: free_port(),
            dir: self.dir.path().join(format!("meta{new_id}")),
            bins: Mutex::new(None),
            child: Mutex::new(None),
        };
        self.metas.push(new);
        let n = self.metas.len() - 1;
        self.start_meta(n);
        post(
            "/add-learner",
            serde_json::json!({
                "node_id": new_id,
                "addr": format!("127.0.0.1:{}", self.metas[n].grpc),
            }),
        );
        let old_id = self.metas[i].id;
        let voters: Vec<u64> = self
            .metas
            .iter()
            .filter(|m| m.id != old_id && m.running())
            .map(|m| m.id)
            .collect();
        post(
            "/change-membership",
            serde_json::json!({ "voters": voters }),
        );
        self.kill_meta(i);
        let _ = std::fs::remove_dir_all(&self.metas[i].dir);
        n
    }

    /// Wait until every OSD is known to the cluster (placement works).
    fn await_osds(&self, osds: usize) {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            let r = self.clients[0].request("GET", "/_admin/nodes", &[]);
            let online = r
                .json()
                .get("nodes")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            if r.status == 200 && online >= osds {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "only {online} of {osds} OSDs registered"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }
}

/// Wait until every one of `ports` accepts connections, or `child` exits.
/// False if it exited: it most likely lost a port, bound by another
/// process (another test's) between the harness picking it, free, and the
/// child binding it. That made CI fail now and then ("nothing listening").
fn await_child_listening(child: &mut Child, ports: &[u16]) -> bool {
    let deadline = Instant::now() + Duration::from_secs(60);
    let exited = |child: &mut Child| match child.try_wait() {
        Ok(Some(status)) => {
            eprintln!(
                "a process for ports {ports:?} exited before listening ({status}); starting it again"
            );
            true
        }
        _ => false,
    };
    loop {
        if exited(child) {
            return false;
        }
        let up = ports
            .iter()
            .all(|p| std::net::TcpStream::connect(("127.0.0.1", *p)).is_ok());
        if up {
            // Not someone else's listener on a port it lost.
            std::thread::sleep(Duration::from_millis(50));
            return !exited(child);
        }
        assert!(Instant::now() < deadline, "nothing listening on {ports:?}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Start something on ports its peers already know, retrying while it
/// can't get them (held for a moment by another process).
fn retry(mut start: impl FnMut() -> bool, what: &str) {
    for _ in 0..40 {
        if start() {
            return;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    panic!("{what} never started");
}

fn await_credentials(path: &Path) -> (String, String) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            let get = |name: &str| {
                text.lines()
                    .find_map(|l| l.split(&format!("{name}=")).nth(1))
                    .map(|v| v.trim().to_string())
            };
            if let (Some(a), Some(s)) = (get("AWS_ACCESS_KEY_ID"), get("AWS_SECRET_ACCESS_KEY")) {
                return (a, s);
            }
        }
        assert!(
            Instant::now() < deadline,
            "no admin credentials at {}",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}
