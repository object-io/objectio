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
    /// Behind a lock so a test can kill and restart nodes while other
    /// threads use the cluster.
    child: Mutex<Option<Child>>,
}

impl Meta {
    fn running(&self) -> bool {
        self.child.lock().unwrap().is_some()
    }
}

pub struct HaCluster {
    dir: tempfile::TempDir,
    metas: Vec<Meta>,
    osds: Vec<Child>,
    gateways: Vec<Child>,
    /// A signed client of each gateway, as the admin.
    pub clients: Vec<Cluster>,
    pub access_key: String,
    pub secret_key: String,
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
            .chain(self.osds.iter_mut())
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
    pub voters: Vec<u64>,
}

impl HaCluster {
    /// `metas` meta nodes in one Raft group, `osds` OSDs (4+2), and
    /// `gateways` gateways with auth on, all separate processes.
    #[must_use]
    pub fn start(metas: usize, osds: usize, gateways: usize) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cluster = Self {
            metas: (1..=metas)
                .map(|i| Meta {
                    id: i as u64,
                    grpc: free_port(),
                    admin: free_port(),
                    dir: dir.path().join(format!("meta{i}")),
                    child: Mutex::new(None),
                })
                .collect(),
            dir,
            osds: Vec::new(),
            gateways: Vec::new(),
            clients: Vec::new(),
            access_key: String::new(),
            secret_key: String::new(),
        };
        for i in 0..metas {
            cluster.start_meta(i);
        }
        cluster.form_raft_group();

        let endpoints = cluster.meta_endpoints();
        for o in 0..osds {
            let state = cluster.dir.path().join(format!("osd{o}"));
            std::fs::create_dir_all(state.join("state")).expect("osd dir");
            let disk = state.join("disk.raw");
            std::fs::File::create(&disk)
                .and_then(|f| f.set_len(2 << 30))
                .expect("osd disk");
            let port = free_port();
            let child = Command::new(binary("objectio-osd"))
                .args([
                    "--listen",
                    &format!("127.0.0.1:{port}"),
                    "--advertise-addr",
                    &format!("http://127.0.0.1:{port}"),
                    "--meta-endpoint",
                    &endpoints,
                    "--data-dir",
                    &state.join("state").display().to_string(),
                    "--disks",
                    &disk.display().to_string(),
                    "--metrics-port",
                    "0",
                ])
                .stdout(log_target())
                .stderr(log_target())
                .spawn()
                .expect("spawn objectio-osd");
            cluster.osds.push(child);
        }

        let creds = cluster.metas[0].dir.join("admin-creds.env");
        let (ak, sk) = await_credentials(&creds);
        cluster.access_key = ak;
        cluster.secret_key = sk;
        for _ in 0..gateways {
            let port = free_port();
            let child = Command::new(binary("objectio-gateway"))
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
                ])
                .stdout(log_target())
                .stderr(log_target())
                .spawn()
                .expect("spawn objectio-gateway");
            cluster.gateways.push(child);
            let endpoint = format!("http://127.0.0.1:{port}");
            await_listening(port);
            cluster.clients.push(Cluster::client(
                &endpoint,
                &cluster.access_key,
                &cluster.secret_key,
            ));
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

    /// Start meta node `i` (again), on its own data.
    pub fn start_meta(&self, i: usize) {
        let m = &self.metas[i];
        std::fs::create_dir_all(&m.dir).expect("meta dir");
        let child = Command::new(binary("objectio-meta"))
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
            .stdout(log_target())
            .stderr(log_target())
            .spawn()
            .expect("spawn objectio-meta");
        *m.child.lock().unwrap() = Some(child);
        await_listening(m.admin);
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

fn await_listening(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "nothing listening on {port}");
        std::thread::sleep(Duration::from_millis(100));
    }
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
