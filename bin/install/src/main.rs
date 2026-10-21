//! Sets a Linux host up to run ObjectIO's services under systemd.
//!
//! Usage:
//!   objectio-install init --role all --disks /dev/sdb,/dev/sdc --systemd
//!   objectio-install cluster init meta1:9102 meta2:9102 meta3:9102
//!   objectio-install cluster init --tls-cert admin.pem --tls-key admin.key \
//!     --tls-ca ca.pem meta1 meta2 meta3                  # under mTLS
//!   objectio-install disk list
//!   objectio-install disk prepare /dev/sdb

mod cluster;
mod config;
mod disk;
mod systemd;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use config::{HostSpec, Kind, Layout, Ports, Protection, Role};

#[derive(Parser, Debug)]
#[command(name = "objectio-install")]
#[command(about = "Sets a host up to run ObjectIO's services under systemd")]
#[command(version)]
struct Args {
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Write this host's OSD configs and its services' systemd units
    Init(Box<InitArgs>),

    /// Meta cluster commands
    Cluster {
        #[command(subcommand)]
        command: ClusterCommands,
    },

    /// Disk management commands
    Disk {
        #[command(subcommand)]
        command: DiskCommands,
    },

    /// Show what is installed
    Status {
        /// The root the host was set up under
        #[arg(long, default_value = "/")]
        root: PathBuf,
    },
}

#[derive(clap::Args, Debug)]
struct InitArgs {
    /// The services this host runs: all, meta, osd, gateway (comma-separated)
    #[arg(long, value_delimiter = ',', required = true)]
    role: Vec<Role>,

    /// The disks of this host's OSDs, one OSD each (comma-separated). Each
    /// must be blank, which the OSD formats when it first starts, or an
    /// ObjectIO disk.
    #[arg(long, value_delimiter = ',')]
    disks: Vec<String>,

    /// This host's meta node id: 1, 2, 3 …, each meta node its own
    #[arg(long, default_value_t = 1)]
    node_id: u64,

    /// The name or address the other nodes reach this host at. Default:
    /// its hostname.
    #[arg(long)]
    advertise: Option<String>,

    /// Every meta node's gRPC address, comma-separated
    /// (`http://meta1:9100,http://meta2:9100,…`). Default: this host's own
    /// meta, when it runs one.
    #[arg(long)]
    meta_endpoint: Option<String>,

    /// The default pool's erasure code, `k+m`: it needs k+m OSDs, on as
    /// many hosts where there are that many.
    #[arg(long, default_value = "4+2")]
    ec_profile: String,

    /// Keep this many copies of each object instead of erasure-coding it
    #[arg(long, conflicts_with = "ec_profile")]
    replication: Option<u32>,

    /// Run the gateway without authentication (development only)
    #[arg(long)]
    no_auth: bool,

    /// The gateway's region, for SigV4
    #[arg(long, default_value = "us-east-1")]
    region: String,

    /// The gateway's public URL
    #[arg(long)]
    external_endpoint: Option<String>,

    /// Meta's gRPC port (Raft and the metadata service)
    #[arg(long, default_value_t = 9100)]
    meta_port: u16,

    /// Meta's admin port (Raft bootstrap and membership)
    #[arg(long, default_value_t = 9102)]
    meta_admin_port: u16,

    /// Meta's metrics port (0: none)
    #[arg(long, default_value_t = 9101)]
    meta_metrics_port: u16,

    /// The first OSD's gRPC port; OSD i listens on this + 2i
    #[arg(long, default_value_t = 9200)]
    osd_port: u16,

    /// The first OSD's metrics port; OSD i serves on this + 2i (0: none)
    #[arg(long, default_value_t = 9201)]
    osd_metrics_port: u16,

    /// The gateway's S3 port
    #[arg(long, default_value_t = 9000)]
    gateway_port: u16,

    /// Write everything under this directory instead of `/`: the files
    /// written name paths under it too
    #[arg(long, default_value = "/")]
    root: PathBuf,

    /// Where the ObjectIO binaries are
    #[arg(long, default_value = "/usr/local/bin")]
    bin_dir: PathBuf,

    /// Install the systemd units (else print the services' command lines)
    #[arg(long)]
    systemd: bool,
}

#[derive(Subcommand, Debug)]
enum ClusterCommands {
    /// Form the meta nodes' Raft group, every node a voter. Safe to run
    /// again.
    Init {
        /// Every meta node's admin address (`host`, `host:port` or a URL),
        /// the first the one the group is started from
        #[arg(required = true)]
        nodes: Vec<String>,

        /// The admin port of a node named without one
        #[arg(long, default_value_t = 9102)]
        admin_port: u16,

        /// How long to wait for every node to answer, in seconds
        #[arg(long, default_value_t = 120)]
        wait_secs: u64,

        /// Under mTLS: a certificate of role admin (PEM). The admin ports
        /// are then HTTPS, and change membership only for that role
        #[arg(long, requires_all = ["tls_key", "tls_ca"])]
        tls_cert: Option<PathBuf>,

        /// The key of --tls-cert (PEM)
        #[arg(long, requires_all = ["tls_cert", "tls_ca"])]
        tls_key: Option<PathBuf>,

        /// The CA that signed the meta nodes' certificates (PEM)
        #[arg(long, requires_all = ["tls_cert", "tls_key"])]
        tls_ca: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum DiskCommands {
    /// List available disks
    List {
        /// Include disks that are already in use
        #[arg(long)]
        all: bool,
    },

    /// Format a disk for ObjectIO. Not needed for a blank disk, which its
    /// OSD formats when it first starts.
    Prepare {
        /// Path to the disk device
        path: String,

        /// Format a disk that isn't blank, destroying what it holds
        #[arg(long)]
        force: bool,

        /// Allocation unit in bytes. Default: the OSD's
        #[arg(long)]
        block_size: Option<u32>,
    },

    /// Check disk status
    Check {
        /// Path to the disk device
        path: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.clone().into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    match args.command {
        Commands::Init(init) => init_host(*init)?,
        Commands::Cluster {
            command:
                ClusterCommands::Init {
                    nodes,
                    admin_port,
                    wait_secs,
                    tls_cert,
                    tls_key,
                    tls_ca,
                },
        } => {
            let tls = match (tls_cert, tls_key, tls_ca) {
                (Some(cert), Some(key), Some(ca)) => Some(cluster::Tls { cert, key, ca }),
                _ => None,
            };
            cluster::init(
                &nodes,
                admin_port,
                tls.as_ref(),
                Duration::from_secs(wait_secs),
            )
            .await?;
        }
        Commands::Disk { command } => handle_disk_command(command)?,
        Commands::Status { root } => show_status(&Layout::new(&root)?)?,
    }
    Ok(())
}

fn hostname() -> Result<String> {
    let name = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .context("reading the hostname: pass --advertise")?;
    Ok(name.trim().to_string())
}

/// Write this host's OSD configs and units.
fn init_host(a: InitArgs) -> Result<()> {
    let layout = Layout::new(&a.root)?;
    let spec = HostSpec {
        roles: a.role,
        disks: a.disks,
        node_id: a.node_id,
        advertise: match a.advertise {
            Some(h) => h,
            None => hostname()?,
        },
        meta_endpoint: a.meta_endpoint,
        protection: Protection::parse(&a.ec_profile, a.replication)?,
        no_auth: a.no_auth,
        region: a.region,
        external_endpoint: a.external_endpoint,
        ports: Ports {
            meta: a.meta_port,
            meta_admin: a.meta_admin_port,
            meta_metrics: a.meta_metrics_port,
            osd: a.osd_port,
            osd_metrics: a.osd_metrics_port,
            gateway: a.gateway_port,
        },
        bin_dir: a.bin_dir,
    };
    let plan = config::plan(&spec, &layout)?;
    if spec.runs(Role::Osd) {
        disk::check_for_osd(&spec.disks)?;
        let copies = spec.protection.copies() as usize;
        if spec.disks.len() < copies {
            warn!(
                "this host has {} OSDs; the default pool needs {copies}, on other hosts then",
                spec.disks.len()
            );
        }
    }

    for dir in &plan.dirs {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    for (path, text) in &plan.osd_configs {
        std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
        info!("wrote {}", path.display());
    }

    let units: Vec<&str> = plan.services.iter().map(|s| s.unit.as_str()).collect();
    if a.systemd {
        let dir = layout.unit_dir();
        std::fs::create_dir_all(&dir)?;
        let with_meta = spec.runs(Role::Meta);
        for s in &plan.services {
            let path = dir.join(format!("{}.service", s.unit));
            std::fs::write(&path, systemd::unit(s, &layout, with_meta))
                .with_context(|| format!("writing {}", path.display()))?;
            info!("wrote {}", path.display());
        }
        if layout.is_host_root() {
            if plan.services.iter().any(|s| s.kind != Kind::Osd) {
                ensure_service_user()?;
            }
            if spec.runs(Role::Meta) {
                chown_to_service_user(&layout.meta_data_dir())?;
            }
            run("systemctl", &["daemon-reload"])?;
        }
        println!("Installed: {}", units.join(" "));
        println!();
        println!("Next:");
        if spec.runs(Role::Meta) {
            println!("  systemctl enable --now objectio-meta    # on every meta node");
            println!(
                "  objectio-install cluster init <every meta node's address>:{}    # once, from any host",
                spec.ports.meta_admin
            );
        }
        let rest: Vec<&str> = units
            .iter()
            .copied()
            .filter(|u| *u != "objectio-meta")
            .collect();
        if !rest.is_empty() {
            println!("  systemctl enable --now {}", rest.join(" "));
        }
    } else {
        println!("Run, in this order (meta's Raft group formed by `cluster init` in between):");
        for s in &plan.services {
            println!("  {}", systemd::exec_start(&s.argv));
        }
    }
    Ok(())
}

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("running {cmd}"))?;
    if !status.success() {
        anyhow::bail!("{cmd} {}: {status}", args.join(" "));
    }
    Ok(())
}

/// The system user meta and the gateway run as, made if missing.
fn ensure_service_user() -> Result<()> {
    let user = systemd::SERVICE_USER;
    let exists = std::process::Command::new("id")
        .args(["-u", user])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !exists {
        run(
            "useradd",
            &[
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/var/lib/objectio",
                "--shell",
                "/usr/sbin/nologin",
                user,
            ],
        )?;
        info!("created the system user {user}");
    }
    Ok(())
}

fn chown_to_service_user(dir: &Path) -> Result<()> {
    let owner = format!("{0}:{0}", systemd::SERVICE_USER);
    run("chown", &["-R", &owner, &dir.display().to_string()])
}

/// Handle disk management commands
fn handle_disk_command(command: DiskCommands) -> Result<()> {
    match command {
        DiskCommands::List { all } => {
            let disks = if all {
                disk::list_all_disks()?
            } else {
                disk::detect_available_disks()?
            };
            if disks.is_empty() {
                println!("No disks found.");
            } else {
                println!("Available disks:");
                for disk_path in disks {
                    println!("  {} - {}", disk_path, disk::state(&disk_path));
                }
            }
        }
        DiskCommands::Prepare {
            path,
            force,
            block_size,
        } => {
            let disk_id = disk::prepare_disk(&path, force, block_size)?;
            println!("Disk {path} prepared: ID {disk_id}");
        }
        DiskCommands::Check { path } => {
            println!("Disk: {path}");
            println!("Status: {}", disk::state(&path));
        }
    }
    Ok(())
}

/// What `init` wrote under `layout`.
fn show_status(layout: &Layout) -> Result<()> {
    let list = |dir: &Path, prefix: &str, suffix: &str| -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with(prefix) && n.ends_with(suffix))
            .collect();
        names.sort();
        names
    };
    println!("OSD configs in {}:", layout.config_dir().display());
    for name in list(&layout.config_dir(), "osd-", ".toml") {
        println!("  {name}");
    }
    println!("Units in {}:", layout.unit_dir().display());
    for name in list(&layout.unit_dir(), "objectio-", ".service") {
        println!("  {name}");
    }
    Ok(())
}
