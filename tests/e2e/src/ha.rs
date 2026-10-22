//! A cluster of separate processes, for what one `objectio-aio` can't show.
//!
//! Several meta nodes in one Raft group, OSDs and gateways: losing a meta
//! node, the leader among them, and the cluster going on.
//!
//! Every OSD and gateway is given every meta node's address; any meta node
//! serves any call (a follower forwards it to the leader).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use crate::{Cluster, binary, free_port};

/// One meta node: how to start it again, and its process when running.
struct Meta {
    id: u64,
    grpc: u16,
    admin: u16,
    /// Known to no peer, so moved to another port when another process
    /// holds it (see [`HaCluster::spawn_meta`]).
    metrics: AtomicU16,
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

/// One process of a [`HaCluster`], by index.
#[derive(Clone, Copy, Debug)]
pub enum Node {
    Meta(usize),
    Osd(usize),
    Gateway(usize),
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
    /// A client of meta's admin ports, as an operator (role admin under
    /// mTLS), and the scheme they speak.
    admin: (reqwest::blocking::Client, &'static str),
    /// Each OSD on a host of its own (`h0`, `h1`, …) rather than all on
    /// one: what a pool with placement groups needs to spread over them.
    osd_hosts: bool,
    /// The rack of each OSD, by index, when given: for pools spread over
    /// racks (B31 phase 1b).
    osd_racks: Vec<String>,
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
        // A failing test keeps its processes' logs, copied next to the
        // target dir (as a single-process cluster keeps its own).
        if std::thread::panicking() {
            let from = self.dir.path().join("logs");
            let to = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/e2e-logs")
                .join(format!(
                    "{}-{}",
                    std::thread::current()
                        .name()
                        .unwrap_or("test")
                        .replace("::", "-"),
                    self.metas.first().map_or(0, |m| m.grpc)
                ));
            let copied = std::fs::read_dir(&from).is_ok_and(|entries| {
                std::fs::create_dir_all(&to).is_ok()
                    && entries
                        .flatten()
                        .all(|e| std::fs::copy(e.path(), to.join(e.file_name())).is_ok())
            });
            if copied {
                eprintln!("cluster logs: {}", to.display());
            }
        }
    }
}

/// Where a process's output goes: the test's own stdout and stderr with
/// `OBJECTIO_E2E_LOGS` set, else `<name>.log` in the cluster's `logs/`
/// (appended to across restarts), which a failing test keeps (see
/// [`HaCluster`]'s `Drop`).
fn log_target(dir: &Path, name: &str) -> (Stdio, Stdio) {
    if std::env::var_os("OBJECTIO_E2E_LOGS").is_some() {
        return (Stdio::inherit(), Stdio::inherit());
    }
    let logs = dir.join("logs");
    std::fs::create_dir_all(&logs).expect("logs dir");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(logs.join(format!("{name}.log")))
        .expect("log file");
    let err = file.try_clone().expect("log file");
    (file.into(), err.into())
}

/// A client for the meta nodes' metrics ports, built once (see
/// [`crate::http_client`]); their admin ports take `HaCluster::admin`.
fn http() -> &'static reqwest::blocking::Client {
    static CLIENT: std::sync::OnceLock<reqwest::blocking::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(0)
            .build()
            .expect("http client")
    })
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
    /// Whether the node's database open at start walked all of it (B25).
    pub open_repair: bool,
    /// Why the node's Raft has stopped for good, if it has.
    pub fatal: Option<String>,
    /// Why the node has no room for writes, if it hasn't.
    pub disk_full: Option<String>,
}

/// The size of each OSD's disk, a sparse file, unless a test asks for
/// another.
const DISK_BYTES: u64 = 2 << 30;

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
        Self::start_with(bins, metas, osds, gateways, &[], false)
    }

    /// As [`Self::start`], every meta node also given `meta_args`.
    #[must_use]
    pub fn start_with_meta_args(
        metas: usize,
        osds: usize,
        gateways: usize,
        meta_args: &[&str],
    ) -> Self {
        Self::start_with(None, metas, osds, gateways, meta_args, false)
    }

    /// As [`Self::start`], each OSD on a host of its own, so a pool's
    /// placement groups can spread over them (one host can't hold k + m
    /// failure domains).
    #[must_use]
    pub fn start_with_osd_hosts(metas: usize, osds: usize, gateways: usize) -> Self {
        Self::start_with(None, metas, osds, gateways, &[], true)
    }

    /// As [`Self::start_with_osd_hosts`], OSD `i` also in rack `racks[i]`
    /// (one OSD per entry): for pools whose copies are spread over racks.
    #[must_use]
    pub fn start_with_osd_racks(metas: usize, racks: &[&str], gateways: usize) -> Self {
        Self::start_with_racks(metas, racks, gateways, &[])
    }

    /// As [`Self::start_with_osd_racks`], every meta node also given
    /// `meta_args`.
    #[must_use]
    pub fn start_with_racks(
        metas: usize,
        racks: &[&str],
        gateways: usize,
        meta_args: &[&str],
    ) -> Self {
        Self::start_inner(
            None,
            metas,
            racks.len(),
            gateways,
            meta_args,
            true,
            racks.iter().map(ToString::to_string).collect(),
            DISK_BYTES,
        )
    }

    /// As [`Self::start`], each OSD's disk `disk_bytes` large (a sparse
    /// file): for tests that store more than the usual disks hold.
    #[must_use]
    pub fn start_with_disk_bytes(
        metas: usize,
        osds: usize,
        gateways: usize,
        disk_bytes: u64,
    ) -> Self {
        Self::start_inner(
            None,
            metas,
            osds,
            gateways,
            &[],
            false,
            Vec::new(),
            disk_bytes,
        )
    }

    fn start_with(
        bins: Option<&Path>,
        metas: usize,
        osds: usize,
        gateways: usize,
        meta_args: &[&str],
        osd_hosts: bool,
    ) -> Self {
        Self::start_inner(
            bins,
            metas,
            osds,
            gateways,
            meta_args,
            osd_hosts,
            Vec::new(),
            DISK_BYTES,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_inner(
        bins: Option<&Path>,
        metas: usize,
        osds: usize,
        gateways: usize,
        meta_args: &[&str],
        osd_hosts: bool,
        osd_racks: Vec<String>,
        disk_bytes: u64,
    ) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut cluster = Self {
            metas: (1..=metas)
                .map(|i| Meta {
                    id: i as u64,
                    grpc: free_port(),
                    admin: free_port(),
                    metrics: AtomicU16::new(free_port()),
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
            admin: crate::tls::admin_http(bins.is_none(), Some(crate::tls::ADMIN)),
            osd_hosts,
            osd_racks,
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
                .and_then(|f| f.set_len(disk_bytes))
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

    /// Meta node `i`'s gRPC address.
    #[must_use]
    pub fn meta_endpoint(&self, i: usize) -> String {
        format!("http://127.0.0.1:{}", self.metas[i].grpc)
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
        let osd_hosts = self.osd_hosts;
        let rack = self
            .osd_racks
            .get(i)
            .map(|r| format!("rack = \"{r}\"\n"))
            .unwrap_or_default();
        let (out, err) = log_target(self.dir.path(), &format!("osd-{i}"));
        let o = &mut self.osds[i];
        let mut cmd = Command::new(bin(bins, "objectio-osd"));
        if self.tls {
            crate::tls::apply(&mut cmd, crate::tls::OSD);
        }
        if osd_hosts {
            let config = o.state.join("osd.toml");
            std::fs::write(
                &config,
                format!("[osd.failure_domain]\nhost = \"h{i}\"\n{rack}"),
            )
            .expect("osd config");
            cmd.arg("--config").arg(&config);
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
            .stdout(out)
            .stderr(err)
            .spawn()
            .expect("spawn objectio-osd");
        o.child = Some(child);
    }

    /// Start gateway `i` from `bins`, and wait until it listens. False if
    /// it exited instead (see [`await_child_listening`]).
    fn spawn_gateway(&mut self, i: usize, bins: Option<&Path>) -> bool {
        let endpoints = self.meta_endpoints();
        let port = self.gateways[i].port;
        let (out, err) = log_target(self.dir.path(), &format!("gateway-{i}"));
        let mut cmd = Command::new(bin(bins, "objectio-gateway"));
        if self.tls {
            crate::tls::apply(&mut cmd, crate::tls::GATEWAY);
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
            .stdout(out)
            .stderr(err)
            .spawn()
            .expect("spawn objectio-gateway");
        let gateway = &mut self.gateways[i];
        gateway.child = Some(child);
        await_child_listening(gateway.child.as_mut().unwrap(), &[port])
    }

    /// The highest value of meta metric `name` (no labels) across the
    /// running meta nodes: the leader's, for a gauge only it sets.
    pub fn meta_metric(&self, name: &str) -> Option<f64> {
        self.metas
            .iter()
            .filter(|m| m.running())
            .filter_map(|m| {
                let text = http()
                    .get(format!(
                        "http://127.0.0.1:{}/metrics",
                        m.metrics.load(Ordering::Relaxed)
                    ))
                    .send()
                    .ok()?
                    .text()
                    .ok()?;
                text.lines()
                    .find_map(|l| l.strip_prefix(name)?.strip_prefix(' ')?.trim().parse().ok())
            })
            .reduce(f64::max)
    }

    /// Start one more gateway, from `bins`, with a signed client of it in
    /// `clients`. Returns its index.
    pub fn add_gateway(&mut self, bins: Option<&Path>) -> usize {
        self.add_gateway_with_args(bins, &[])
    }

    /// Restart gateway `i` with `args` in place of the ones it had.
    pub fn restart_gateway_with_args(&mut self, i: usize, args: &[&str]) {
        self.gateways[i].args = args.iter().map(ToString::to_string).collect();
        self.restart_gateway(i, None);
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

    /// The disk file of OSD `i` (to replace it, as a failed drive).
    #[must_use]
    pub fn osd_disk(&self, i: usize) -> &Path {
        &self.osds[i].disk
    }

    /// Replace OSD `i`'s disk while it is stopped with a blank one of the
    /// same size; its identity and metadata (its state directory) stay.
    pub fn replace_osd_disk(&self, i: usize) {
        let o = &self.osds[i];
        assert!(o.child.is_none(), "stop OSD {i} first");
        let size = std::fs::metadata(&o.disk).expect("disk").len();
        std::fs::remove_file(&o.disk).expect("remove disk");
        std::fs::File::create(&o.disk)
            .and_then(|f| f.set_len(size))
            .expect("blank disk");
    }

    /// Replace OSD `i`'s drive while it is stopped: its disk and its state
    /// directory (its metadata and identity, on the same drive in
    /// production) are gone. Started again, it is a new, empty OSD at the
    /// old one's address.
    pub fn lose_osd_drive(&self, i: usize) {
        let o = &self.osds[i];
        assert!(o.child.is_none(), "stop OSD {i} first");
        let state = o.state.join("state");
        std::fs::remove_dir_all(&state).expect("remove state");
        std::fs::create_dir_all(&state).expect("state dir");
        std::fs::remove_file(&o.disk).expect("remove disk");
        std::fs::File::create(&o.disk)
            .and_then(|f| f.set_len(2 << 30))
            .expect("blank disk");
    }

    /// Wait until meta has seen that writes made short of a shard (an OSD
    /// down) are short: a degraded record, a PG not Clean, or, if both
    /// came and went between looks, `objects` objects recovered. Then a
    /// wait for Clean means repaired. Without it, such a wait right after
    /// the OSD is back can end at once: a PG is marked for peering at its
    /// next look, and reads Clean until then.
    ///
    /// # Panics
    /// If none of those shows within `secs`.
    pub fn await_seen_short(&self, objects: u32, secs: u64) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while self
            .meta_metric("objectio_meta_degraded_objects")
            .unwrap_or(0.0)
            == 0.0
            && self
                .meta_metric("objectio_meta_pgs_not_clean")
                .unwrap_or(0.0)
                == 0.0
            && self
                .meta_metric("objectio_meta_pg_recovered_objects_total")
                .unwrap_or(0.0)
                < f64::from(objects)
        {
            assert!(Instant::now() < deadline, "never seen short after {secs} s");
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The directory OSD `i` keeps its state under (its metadata index
    /// among it), beside its disk file.
    #[must_use]
    pub fn osd_dir(&self, i: usize) -> &Path {
        &self.osds[i].state
    }

    /// The process id of OSD `i`, while it runs.
    #[must_use]
    pub fn osd_pid(&self, i: usize) -> Option<u32> {
        self.osds[i].child.as_ref().map(Child::id)
    }

    /// The gRPC address of OSD `i`.
    #[must_use]
    pub fn osd_endpoint(&self, i: usize) -> String {
        format!("http://127.0.0.1:{}", self.osds[i].port)
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
    /// Gateway `i`'s process id, while it runs: to read its memory from
    /// `/proc`.
    #[must_use]
    pub fn gateway_pid(&self, i: usize) -> Option<u32> {
        self.gateways[i].child.as_ref().map(Child::id)
    }

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
    ///
    /// A metrics port another process took meanwhile (a meta node fails to
    /// start on one it can't bind) is changed first: no peer knows it.
    fn spawn_meta(&self, i: usize) -> bool {
        let m = &self.metas[i];
        std::fs::create_dir_all(&m.dir).expect("meta dir");
        let mut metrics = m.metrics.load(Ordering::Relaxed);
        if std::net::TcpListener::bind(("0.0.0.0", metrics)).is_err() {
            metrics = free_port();
            m.metrics.store(metrics, Ordering::Relaxed);
        }
        let bins = m.bins.lock().unwrap().clone();
        let (out, err) = log_target(self.dir.path(), &format!("meta-{i}"));
        let mut cmd = Command::new(bin(bins.as_deref(), "objectio-meta"));
        if self.tls {
            crate::tls::apply(&mut cmd, crate::tls::META);
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
                &metrics.to_string(),
                "--admin-port",
                &m.admin.to_string(),
                "--ec-k",
                "4",
                "--ec-m",
                "2",
            ])
            // Repair off unless the test turns it on (a flag given twice is
            // refused).
            .args(
                (!self.meta_args.iter().any(|a| a == "--repair-interval-secs"))
                    .then_some(["--repair-interval-secs", "0"])
                    .into_iter()
                    .flatten(),
            )
            .args(&self.meta_args)
            .stdout(out)
            .stderr(err)
            .spawn()
            .expect("spawn objectio-meta");
        let mut slot = m.child.lock().unwrap();
        *slot = Some(child);
        await_child_listening(slot.as_mut().unwrap(), &[m.grpc, m.admin])
    }

    /// Meta node `i`'s data directory (`meta.redb`, `raft-log/`, …).
    #[must_use]
    pub fn meta_dir(&self, i: usize) -> &Path {
        &self.metas[i].dir
    }

    /// Kill meta node `i` outright.
    pub fn kill_meta(&self, i: usize) {
        let child = self.metas[i].child.lock().unwrap().take();
        if let Some(mut c) = child {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    /// Send `node` SIGTERM, as Kubernetes and systemd stop a service.
    pub fn sigterm(&self, node: Node) {
        let pid = match node {
            Node::Meta(i) => self.metas[i].child.lock().unwrap().as_ref().map(Child::id),
            Node::Osd(i) => self.osds[i].child.as_ref().map(Child::id),
            Node::Gateway(i) => self.gateways[i].child.as_ref().map(Child::id),
        };
        crate::sigterm(pid.unwrap_or_else(|| panic!("{node:?} is not running")));
    }

    /// Wait up to `within` for `node` to exit (after [`Self::sigterm`]):
    /// its exit status, or `None` if it was still running (it is killed
    /// then). Stopped either way.
    pub fn await_exit(&mut self, node: Node, within: Duration) -> Option<ExitStatus> {
        let child = match node {
            Node::Meta(i) => self.metas[i].child.lock().unwrap().take(),
            Node::Osd(i) => self.osds[i].child.take(),
            Node::Gateway(i) => self.gateways[i].child.take(),
        };
        let mut child = child.unwrap_or_else(|| panic!("{node:?} is not running"));
        crate::await_exit(&mut child, within)
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

    /// The HTTP status meta node `i`'s `/health` answers (on its metrics
    /// port); `None` if it doesn't answer.
    #[must_use]
    pub fn meta_health(&self, i: usize) -> Option<u16> {
        http()
            .get(format!(
                "http://127.0.0.1:{}/health",
                self.metas[i].metrics.load(Ordering::Relaxed)
            ))
            .send()
            .ok()
            .map(|r| r.status().as_u16())
    }

    /// Whether meta node `i`'s process has exited since it was started.
    #[must_use]
    pub fn meta_exited(&self, i: usize) -> bool {
        self.metas[i]
            .child
            .lock()
            .unwrap()
            .as_mut()
            .is_some_and(|c| matches!(c.try_wait(), Ok(Some(_))))
    }

    /// How many meta nodes the cluster has.
    #[must_use]
    pub const fn meta_count(&self) -> usize {
        self.metas.len()
    }

    /// The URL of `path` on meta node `i`'s admin port: HTTPS under mTLS.
    #[must_use]
    pub fn admin_url(&self, i: usize, path: &str) -> String {
        format!("{}://127.0.0.1:{}{path}", self.admin.1, self.metas[i].admin)
    }

    /// Whether the cluster's nodes run mTLS between them.
    #[must_use]
    pub const fn tls(&self) -> bool {
        self.tls
    }

    /// Meta node `i`'s Raft view; `None` if it doesn't answer.
    #[must_use]
    pub fn status(&self, i: usize) -> Option<RaftStatus> {
        let v: serde_json::Value = self
            .admin
            .0
            .get(self.admin_url(i, "/status"))
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
            open_repair: v["open_repair"].as_bool().unwrap_or(false),
            fatal: v["fatal"].as_str().map(str::to_string),
            disk_full: v["disk_full"].as_str().map(str::to_string),
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
        // Each step is safe to repeat (a second /init answers
        // already_initialized), so one that times out on a loaded host is
        // sent again rather than failing the test.
        let admin = |path: &str, body: serde_json::Value| {
            let deadline = Instant::now() + Duration::from_secs(30);
            let r = loop {
                match self
                    .admin
                    .0
                    .post(self.admin_url(0, path))
                    .json(&body)
                    .send()
                {
                    Ok(r) => break r,
                    Err(e) if Instant::now() < deadline => {
                        eprintln!("{path}: {e}; sending it again");
                        std::thread::sleep(Duration::from_millis(500));
                    }
                    Err(e) => panic!("{path}: {e}"),
                }
            };
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
        let leader_admin = self.admin_url(leader, "");
        let client = self.admin.0.clone();
        let post = |path: &str, body: serde_json::Value| {
            let r = client
                .post(format!("{leader_admin}{path}"))
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
            metrics: AtomicU16::new(free_port()),
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

    /// Meta node `i`'s Raft id.
    #[must_use]
    pub fn meta_id(&self, i: usize) -> u64 {
        self.metas[i].id
    }

    /// Stop meta node `i` and delete its data directory: lost for good.
    /// [`Self::start_meta`] then starts it empty, at its old id and ports.
    pub fn lose_meta(&self, i: usize) {
        self.kill_meta(i);
        let _ = std::fs::remove_dir_all(&self.metas[i].dir);
    }

    /// Restore `backup` into meta node `i`'s data directory (stopped, and
    /// empty), as the one voter at its id and address. Returns what the
    /// tool printed.
    #[must_use]
    pub fn restore_meta(&self, i: usize, backup: &Path) -> String {
        let m = &self.metas[i];
        assert!(!m.running(), "stop meta node {i} first");
        meta_tool(&[
            "restore",
            "--from",
            &backup.display().to_string(),
            "--data-dir",
            &m.dir.display().to_string(),
            "--node-id",
            &m.id.to_string(),
            "--raft-advertise",
            &format!("127.0.0.1:{}", m.grpc),
        ])
    }

    /// Make meta node `i` (stopped) the only voter of its group, on its own
    /// data. Returns what the tool printed.
    #[must_use]
    pub fn force_single_voter(&self, i: usize) -> String {
        let m = &self.metas[i];
        assert!(!m.running(), "stop meta node {i} first");
        meta_tool(&[
            "force-single-voter",
            "--data-dir",
            &m.dir.display().to_string(),
            "--node-id",
            &m.id.to_string(),
            "--others-lost-for-good",
        ])
    }

    /// Add meta nodes `others` (running, empty) to the group meta node
    /// `leader` leads, as the bootstrap does: each as a learner, then all
    /// of them voters beside the leader.
    ///
    /// # Panics
    /// When the group refuses a step.
    pub fn join_metas(&self, leader: usize, others: &[usize]) {
        let post = |path: &str, body: serde_json::Value| {
            let r = self
                .admin
                .0
                .post(self.admin_url(leader, path))
                .json(&body)
                .send()
                .unwrap_or_else(|e| panic!("{path}: {e}"));
            assert!(
                r.status().is_success(),
                "{path}: {}",
                r.text().unwrap_or_default()
            );
        };
        for &i in others {
            let m = &self.metas[i];
            post(
                "/add-learner",
                serde_json::json!({ "node_id": m.id, "addr": format!("127.0.0.1:{}", m.grpc) }),
            );
        }
        let voters: Vec<u64> = std::iter::once(leader)
            .chain(others.iter().copied())
            .map(|i| self.metas[i].id)
            .collect();
        post(
            "/change-membership",
            serde_json::json!({ "voters": voters }),
        );
    }

    /// Run `obioctl` as the admin against gateway `g`.
    #[must_use]
    pub fn obioctl(&self, g: usize, args: &[&str]) -> std::process::Output {
        let mut cmd = Command::new(bin(None, "obioctl"));
        cmd.env_clear();
        if self.tls {
            crate::tls::apply(&mut cmd, crate::tls::ADMIN);
        }
        cmd.env("HOME", self.dir.path())
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("OBJECTIO_ENDPOINT", &self.clients[g].endpoint)
            .env("OBJECTIO_ACCESS_KEY", &self.access_key)
            .env("OBJECTIO_SECRET_KEY", &self.secret_key)
            .args(args)
            .output()
            .expect("run obioctl")
    }

    /// Wait until every OSD is known to the cluster (placement works). A
    /// cluster of meta nodes alone has nothing to wait for.
    fn await_osds(&self, osds: usize) {
        if osds == 0 {
            return;
        }
        // Generous: clusters of ten OSDs start alongside other tests'.
        let deadline = Instant::now() + Duration::from_secs(180);
        loop {
            let r = self.clients[0].request("GET", "/_admin/nodes", &[]);
            let online = r
                .json()
                .get("nodes")
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            if r.status == 200 && online >= osds {
                self.await_default_pool();
                return;
            }
            assert!(
                Instant::now() < deadline,
                "only {online} of {osds} OSDs registered"
            );
            std::thread::sleep(Duration::from_millis(300));
        }
    }

    /// Wait until the default pool's placement groups are made (B31): until
    /// then a PUT is answered 503. A cluster on a release before placement
    /// groups has none: given up on after a while.
    pub fn await_default_pool(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            let r = self.clients[0].request("GET", "/_admin/pools/default/placement-groups", &[]);
            if r.status == 200 && r.json()["pgs"].as_array().is_some_and(|p| !p.is_empty()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// Run `objectio-meta` with `args` (an offline tool), and return what it
/// printed.
///
/// # Panics
/// When it fails.
fn meta_tool(args: &[&str]) -> String {
    let out = Command::new(bin(None, "objectio-meta"))
        .args(args)
        .output()
        .expect("run objectio-meta");
    assert!(
        out.status.success(),
        "objectio-meta {args:?} failed ({}):\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
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
