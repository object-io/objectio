//! What a host runs: each service's command line, and the OSDs' config
//! files.
//!
//! Meta and the gateway are configured by flags alone, the ones the Helm
//! chart passes; an OSD reads a TOML file too (its failure domain is set
//! only there), as the chart renders one for each OSD. A host runs one OSD
//! per disk, as the chart does: an OSD is the smallest failure domain, so
//! one OSD holding every disk of a host could keep a single copy of each
//! object and no erasure-coded stripe.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

/// How the default pool keeps objects: an erasure code, or copies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Protection {
    Ec { k: u32, m: u32 },
    Replication(u32),
}

impl Protection {
    /// From `--ec-profile k+m`, or `--replication n` when given.
    pub fn parse(ec_profile: &str, replication: Option<u32>) -> Result<Self> {
        if let Some(n) = replication {
            if n == 0 {
                bail!("--replication must be at least 1");
            }
            return Ok(Self::Replication(n));
        }
        let parsed = ec_profile
            .split_once('+')
            .and_then(|(k, m)| Some((k.trim().parse().ok()?, m.trim().parse().ok()?)));
        match parsed {
            Some((k, m)) if k > 0 && m > 0 => Ok(Self::Ec { k, m }),
            _ => bail!("invalid EC profile '{ec_profile}': use k+m, both at least 1, e.g. 4+2"),
        }
    }

    /// OSDs (on as many hosts, where there are enough) the pool needs.
    pub fn copies(&self) -> u32 {
        match self {
            Self::Ec { k, m } => k + m,
            Self::Replication(n) => *n,
        }
    }

    fn meta_flags(&self) -> Vec<String> {
        match self {
            Self::Ec { k, m } => strings(&["--ec-k", &k.to_string(), "--ec-m", &m.to_string()]),
            Self::Replication(n) => strings(&["--replication", &n.to_string()]),
        }
    }

    fn gateway_flags(&self) -> Vec<String> {
        match self {
            Self::Ec { k, m } => strings(&["--ec-k", &k.to_string(), "--ec-m", &m.to_string()]),
            Self::Replication(n) => {
                strings(&["--protection", "replication", "--replicas", &n.to_string()])
            }
        }
    }
}

fn strings(s: &[&str]) -> Vec<String> {
    s.iter().map(ToString::to_string).collect()
}

/// Where the installer writes: every path under `root` (`/` on a real
/// host), and every file it writes names paths under it, so a host set up
/// under another root runs from there.
#[derive(Debug, Clone)]
pub struct Layout {
    root: PathBuf,
}

impl Layout {
    pub fn new(root: &Path) -> Result<Self> {
        Ok(Self {
            root: std::path::absolute(root)?,
        })
    }

    /// Whether this is the host's own root.
    pub fn is_host_root(&self) -> bool {
        self.root == Path::new("/")
    }

    fn at(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }

    pub fn config_dir(&self) -> PathBuf {
        self.at("/etc/objectio")
    }

    pub fn unit_dir(&self) -> PathBuf {
        self.at("/etc/systemd/system")
    }

    pub fn meta_data_dir(&self) -> PathBuf {
        self.at("/var/lib/objectio/meta")
    }

    pub fn osd_data_dir(&self, i: usize) -> PathBuf {
        self.at(&format!("/var/lib/objectio/osd-{i}"))
    }

    pub fn osd_config(&self, i: usize) -> PathBuf {
        self.config_dir().join(format!("osd-{i}.toml"))
    }

    pub fn gateway_env(&self) -> PathBuf {
        self.config_dir().join("gateway.env")
    }
}

/// The ports of this host's services. Each OSD after the first takes the
/// next pair: OSD `i` listens on `osd + 2i` and serves metrics on
/// `osd_metrics + 2i`.
#[derive(Debug, Clone)]
pub struct Ports {
    pub meta: u16,
    pub meta_admin: u16,
    pub meta_metrics: u16,
    pub osd: u16,
    pub osd_metrics: u16,
    pub gateway: u16,
}

impl Ports {
    fn osd_port(base: u16, i: usize) -> Result<u16> {
        u16::try_from(i * 2)
            .ok()
            .and_then(|step| base.checked_add(step))
            .ok_or_else(|| anyhow::anyhow!("OSD {i}'s port is past 65535 (base {base})"))
    }

    pub fn osd(&self, i: usize) -> Result<u16> {
        Self::osd_port(self.osd, i)
    }

    /// 0 for every OSD when `osd_metrics` is 0 (no metrics served).
    pub fn osd_metrics(&self, i: usize) -> Result<u16> {
        if self.osd_metrics == 0 {
            return Ok(0);
        }
        Self::osd_port(self.osd_metrics, i)
    }
}

/// Which services this host runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Role {
    All,
    Meta,
    Osd,
    Gateway,
}

/// What `init` was asked for.
#[derive(Debug, Clone)]
pub struct HostSpec {
    pub roles: Vec<Role>,
    pub disks: Vec<String>,
    pub node_id: u64,
    /// The name or address the other nodes reach this host at.
    pub advertise: String,
    /// Every meta node's gRPC address, comma-separated; this host's own
    /// meta when it runs one and none is given.
    pub meta_endpoint: Option<String>,
    pub protection: Protection,
    pub no_auth: bool,
    pub region: String,
    pub external_endpoint: Option<String>,
    /// The gateway's S3 domains, for virtual-hosted addressing.
    pub s3_domains: Vec<String>,
    pub ports: Ports,
    pub bin_dir: PathBuf,
}

impl HostSpec {
    pub fn runs(&self, role: Role) -> bool {
        self.roles.contains(&Role::All) || self.roles.contains(&role)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Meta,
    Osd,
    Gateway,
}

/// One systemd service: its unit name and its command line.
#[derive(Debug, Clone)]
pub struct Service {
    pub unit: String,
    pub kind: Kind,
    pub description: String,
    /// `argv[0]` is the binary's absolute path.
    pub argv: Vec<String>,
}

/// Everything `init` writes for a host.
#[derive(Debug)]
pub struct Plan {
    pub services: Vec<Service>,
    /// Each OSD's config file and its contents.
    pub osd_configs: Vec<(PathBuf, String)>,
    /// Directories to create.
    pub dirs: Vec<PathBuf>,
}

pub fn plan(spec: &HostSpec, layout: &Layout) -> Result<Plan> {
    if spec.roles.is_empty() {
        bail!("--role: name at least one of all, meta, osd, gateway");
    }
    if spec.node_id == 0 {
        bail!("--node-id must be at least 1");
    }
    let meta_endpoint = match (&spec.meta_endpoint, spec.runs(Role::Meta)) {
        (Some(e), _) => e.clone(),
        (None, true) => format!("http://127.0.0.1:{}", spec.ports.meta),
        (None, false) if spec.runs(Role::Osd) || spec.runs(Role::Gateway) => {
            bail!("--meta-endpoint: this host runs no meta, so name every meta node's address")
        }
        (None, false) => String::new(),
    };
    let bin = |name: &str| spec.bin_dir.join(name).display().to_string();
    let mut services = Vec::new();
    let mut osd_configs = Vec::new();
    let mut dirs = vec![layout.config_dir()];
    let mut ports: Vec<(u16, String)> = Vec::new();

    if spec.runs(Role::Meta) {
        let p = &spec.ports;
        let data = layout.meta_data_dir();
        let mut argv = vec![bin("objectio-meta")];
        argv.extend(strings(&[
            "--node-id",
            &spec.node_id.to_string(),
            "--listen",
            &format!("0.0.0.0:{}", p.meta),
            "--raft-advertise",
            &format!("{}:{}", spec.advertise, p.meta),
            "--metrics-port",
            &p.meta_metrics.to_string(),
            "--admin-port",
            &p.meta_admin.to_string(),
            // Every interface: `cluster init` may run on another host.
            // Under mTLS it changes membership only with a certificate of
            // role admin.
            "--admin-host",
            "0.0.0.0",
            "--data-dir",
            &data.display().to_string(),
        ]));
        argv.extend(spec.protection.meta_flags());
        services.push(Service {
            unit: "objectio-meta".into(),
            kind: Kind::Meta,
            description: "ObjectIO metadata service".into(),
            argv,
        });
        dirs.push(data);
        ports.extend([
            (p.meta, "meta".into()),
            (p.meta_admin, "meta admin".into()),
            (p.meta_metrics, "meta metrics".into()),
        ]);
    }

    if spec.runs(Role::Osd) {
        if spec.disks.is_empty() {
            bail!("--disks: name the disks this host's OSDs use (one OSD each)");
        }
        for (i, disk) in spec.disks.iter().enumerate() {
            let port = spec.ports.osd(i)?;
            let metrics = spec.ports.osd_metrics(i)?;
            let config = layout.osd_config(i);
            let data = layout.osd_data_dir(i);
            osd_configs.push((
                config.clone(),
                osd_toml(
                    &format!("0.0.0.0:{port}"),
                    &format!("http://{}:{port}", spec.advertise),
                    &meta_endpoint,
                    disk,
                    &data,
                ),
            ));
            services.push(Service {
                unit: format!("objectio-osd-{i}"),
                kind: Kind::Osd,
                description: format!("ObjectIO OSD {i} ({disk})"),
                argv: vec![
                    bin("objectio-osd"),
                    "--config".into(),
                    config.display().to_string(),
                    "--metrics-port".into(),
                    metrics.to_string(),
                ],
            });
            dirs.push(data);
            ports.push((port, format!("OSD {i}")));
            ports.push((metrics, format!("OSD {i} metrics")));
        }
    }

    if spec.runs(Role::Gateway) {
        let mut argv = vec![bin("objectio-gateway")];
        argv.extend(strings(&[
            "--listen",
            &format!("0.0.0.0:{}", spec.ports.gateway),
            "--meta-endpoint",
            &meta_endpoint,
        ]));
        argv.extend(spec.protection.gateway_flags());
        argv.extend(strings(&["--region", &spec.region]));
        if let Some(url) = &spec.external_endpoint {
            argv.extend(strings(&["--external-endpoint", url]));
        }
        if !spec.s3_domains.is_empty() {
            argv.extend(strings(&["--s3-domain", &spec.s3_domains.join(",")]));
        }
        if spec.no_auth {
            argv.push("--no-auth".into());
        }
        services.push(Service {
            unit: "objectio-gateway".into(),
            kind: Kind::Gateway,
            description: "ObjectIO S3 gateway".into(),
            argv,
        });
        ports.push((spec.ports.gateway, "gateway".into()));
    }

    // 0 is "none" for a metrics port.
    ports.retain(|(p, _)| *p != 0);
    ports.sort();
    if let Some(w) = ports.windows(2).find(|w| w[0].0 == w[1].0) {
        bail!("{} and {} would both use port {}", w[0].1, w[1].1, w[0].0);
    }
    Ok(Plan {
        services,
        osd_configs,
        dirs,
    })
}

/// A TOML string, quoted and escaped.
fn quoted(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn osd_toml(listen: &str, advertise: &str, meta_endpoint: &str, disk: &str, data: &Path) -> String {
    format!(
        r#"# Written by objectio-install. Flags given to objectio-osd win over this file.

[osd]
listen = {listen}
advertise_addr = {advertise}
meta_endpoint = {meta_endpoint}

# Where this OSD sits, set only here: unset levels are "default", and host
# is this machine's hostname.
# [osd.failure_domain]
# region = "eu-west-1"
# datacenter = "dc1"
# rack = "rack1"

[storage]
# A blank disk is formatted when the OSD first starts.
disks = [{disk}]
data_dir = {data}
"#,
        listen = quoted(listen),
        advertise = quoted(advertise),
        meta_endpoint = quoted(meta_endpoint),
        disk = quoted(disk),
        data = quoted(&data.display().to_string()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(roles: &[Role], disks: &[&str]) -> HostSpec {
        HostSpec {
            roles: roles.to_vec(),
            disks: disks.iter().map(ToString::to_string).collect(),
            node_id: 2,
            advertise: "node2.internal".into(),
            meta_endpoint: None,
            protection: Protection::Ec { k: 4, m: 2 },
            no_auth: false,
            region: "us-east-1".into(),
            external_endpoint: None,
            s3_domains: Vec::new(),
            ports: Ports {
                meta: 9100,
                meta_admin: 9102,
                meta_metrics: 9101,
                osd: 9200,
                osd_metrics: 9201,
                gateway: 9000,
            },
            bin_dir: "/usr/local/bin".into(),
        }
    }

    fn host() -> Layout {
        Layout::new(Path::new("/")).unwrap()
    }

    fn argv<'a>(plan: &'a Plan, unit: &str) -> &'a [String] {
        &plan.services.iter().find(|s| s.unit == unit).unwrap().argv
    }

    /// The flag after `flag` in `argv`.
    fn flag<'a>(argv: &'a [String], flag: &str) -> &'a str {
        let i = argv
            .iter()
            .position(|a| a == flag)
            .unwrap_or_else(|| panic!("{flag}"));
        &argv[i + 1]
    }

    #[test]
    fn meta_and_the_gateway_get_the_charts_flags_and_no_config_file() {
        let plan = plan(&spec(&[Role::All], &["/dev/sdb"]), &host()).unwrap();
        let meta = argv(&plan, "objectio-meta");
        assert_eq!(meta[0], "/usr/local/bin/objectio-meta");
        assert_eq!(flag(meta, "--node-id"), "2");
        assert_eq!(flag(meta, "--listen"), "0.0.0.0:9100");
        assert_eq!(flag(meta, "--raft-advertise"), "node2.internal:9100");
        assert_eq!(flag(meta, "--metrics-port"), "9101");
        assert_eq!(flag(meta, "--admin-port"), "9102");
        assert_eq!(flag(meta, "--admin-host"), "0.0.0.0");
        assert_eq!(flag(meta, "--data-dir"), "/var/lib/objectio/meta");
        assert_eq!(flag(meta, "--ec-k"), "4");
        assert_eq!(flag(meta, "--ec-m"), "2");
        let gw = argv(&plan, "objectio-gateway");
        assert_eq!(flag(gw, "--listen"), "0.0.0.0:9000");
        assert_eq!(flag(gw, "--meta-endpoint"), "http://127.0.0.1:9100");
        assert_eq!(flag(gw, "--region"), "us-east-1");
        assert!(!gw.contains(&"--no-auth".to_string()));
        for s in &plan.services {
            if s.kind != Kind::Osd {
                assert!(!s.argv.iter().any(|a| a == "--config"), "{}", s.unit);
            }
        }
    }

    #[test]
    fn each_disk_gets_an_osd_of_its_own_on_the_next_ports() {
        let plan = plan(
            &spec(&[Role::Osd], &["/dev/sdb", "/dev/sdc"]).with_meta(),
            &host(),
        )
        .unwrap();
        assert_eq!(plan.services.len(), 2);
        let osd1 = argv(&plan, "objectio-osd-1");
        assert_eq!(flag(osd1, "--config"), "/etc/objectio/osd-1.toml");
        assert_eq!(flag(osd1, "--metrics-port"), "9203");
        let (path, text) = &plan.osd_configs[1];
        assert_eq!(path, Path::new("/etc/objectio/osd-1.toml"));
        let t: toml::Value = toml::from_str(text).unwrap();
        assert_eq!(t["osd"]["listen"].as_str(), Some("0.0.0.0:9202"));
        assert_eq!(
            t["osd"]["advertise_addr"].as_str(),
            Some("http://node2.internal:9202")
        );
        assert_eq!(
            t["osd"]["meta_endpoint"].as_str(),
            Some("http://m1:9100,http://m2:9100")
        );
        assert_eq!(t["storage"]["disks"][0].as_str(), Some("/dev/sdc"));
        assert_eq!(
            t["storage"]["data_dir"].as_str(),
            Some("/var/lib/objectio/osd-1")
        );
        // The OSD's own block size applies.
        assert!(t["storage"].get("block_size").is_none());
    }

    impl HostSpec {
        fn with_meta(mut self) -> Self {
            self.meta_endpoint = Some("http://m1:9100,http://m2:9100".into());
            self
        }
    }

    #[test]
    fn a_host_without_meta_must_be_told_where_meta_is() {
        let err = plan(&spec(&[Role::Gateway], &[]), &host()).unwrap_err();
        assert!(err.to_string().contains("--meta-endpoint"), "{err}");
        let p = plan(&spec(&[Role::Gateway], &[]).with_meta(), &host()).unwrap();
        assert_eq!(
            flag(argv(&p, "objectio-gateway"), "--meta-endpoint"),
            "http://m1:9100,http://m2:9100"
        );
    }

    #[test]
    fn ports_two_services_would_share_are_refused() {
        let mut s = spec(&[Role::Meta, Role::Osd], &["/a", "/b"]);
        // OSD 0 on meta's port.
        s.ports.osd = 9100;
        s.ports.osd_metrics = 9300;
        let err = plan(&s, &host()).unwrap_err();
        assert!(err.to_string().contains("port 9100"), "{err}");
        let mut s = spec(&[Role::Meta, Role::Osd], &["/a", "/b"]);
        // OSD 1 on it.
        s.ports.osd = 9098;
        s.ports.osd_metrics = 0;
        let err = plan(&s, &host()).unwrap_err();
        assert!(err.to_string().contains("port 9100"), "{err}");
        assert!(err.to_string().contains("OSD 1"), "{err}");
    }

    #[test]
    fn every_path_is_under_the_root() {
        let layout = Layout::new(Path::new("/tmp/host1")).unwrap();
        let plan = plan(&spec(&[Role::All], &["/dev/sdb"]), &layout).unwrap();
        assert_eq!(
            flag(argv(&plan, "objectio-meta"), "--data-dir"),
            "/tmp/host1/var/lib/objectio/meta"
        );
        assert_eq!(
            flag(argv(&plan, "objectio-osd-0"), "--config"),
            "/tmp/host1/etc/objectio/osd-0.toml"
        );
        assert!(plan.dirs.iter().all(|d| d.starts_with("/tmp/host1")));
        assert_eq!(
            layout.unit_dir(),
            Path::new("/tmp/host1/etc/systemd/system")
        );
        assert!(!layout.is_host_root());
        assert!(host().is_host_root());
    }

    #[test]
    fn protection_is_passed_as_the_chart_passes_it() {
        assert_eq!(
            Protection::parse("4+2", None).unwrap(),
            Protection::Ec { k: 4, m: 2 }
        );
        assert_eq!(
            Protection::parse("4+2", Some(3)).unwrap(),
            Protection::Replication(3)
        );
        assert!(Protection::parse("4", None).is_err());
        assert!(Protection::parse("4+0", None).is_err());
        assert!(Protection::parse("x+1", None).is_err());
        assert!(Protection::parse("4+2", Some(0)).is_err());
        let mut s = spec(&[Role::Meta, Role::Gateway], &[]);
        s.protection = Protection::Replication(1);
        let plan = plan(&s, &host()).unwrap();
        assert_eq!(flag(argv(&plan, "objectio-meta"), "--replication"), "1");
        let gw = argv(&plan, "objectio-gateway");
        assert_eq!(flag(gw, "--protection"), "replication");
        assert_eq!(flag(gw, "--replicas"), "1");
    }
}
