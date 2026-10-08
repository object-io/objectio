//! Command implementations: argument → request → output.

pub mod access;
pub mod bucket;
pub mod cluster;
pub mod iam;

use crate::cli::{Command, TenantOpt};
use crate::http::ApiClient;
use crate::output::Out;
use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use std::io::Read;
use std::path::Path;

pub use crate::sigv4::{escape_path, escape_segment as seg};

/// What every command gets.
pub struct Ctx<'a, 'w> {
    pub api: &'a ApiClient,
    pub out: Out<'w>,
    /// For `provision`: `OBJECTIO_PROVISIONER_USER_ID`.
    pub provisioner: Option<String>,
}

/// Run one management-API command.
pub async fn run(cmd: Command, ctx: &mut Ctx<'_, '_>) -> Result<()> {
    match cmd {
        Command::Tenant { action } => iam::tenant(action, ctx).await,
        Command::User { action } => iam::user(action, ctx).await,
        Command::Key { action } => iam::key(action, ctx).await,
        Command::Policy { action } => iam::policy(action, ctx).await,
        Command::Group { action } => iam::group(action, ctx).await,
        Command::Role { action } => iam::role(action, ctx).await,
        Command::Oidc { action } => access::oidc(action, ctx).await,
        Command::Sts { action } => access::sts(action, ctx).await,
        Command::PublicAccessBlock { action } => access::public_access_block(action, ctx).await,
        Command::Audit { action } => access::audit(action, ctx).await,
        Command::Bucket { action } => bucket::bucket(action, ctx).await,
        Command::Provision { action } => bucket::provision(action, ctx).await,
        Command::Cluster { action } => cluster::cluster(action, ctx).await,
        Command::Upgrade { action } => cluster::upgrade(action, ctx).await,
        Command::Node { action } => cluster::node(action, ctx).await,
        Command::Osd { action } => cluster::osd(action, ctx).await,
        Command::Pool { action } => cluster::pool(action, ctx).await,
        Command::Pg { action } => cluster::pg(action, ctx).await,
        Command::Kms { action } => cluster::kms(action, ctx).await,
        Command::Warehouse { action } => cluster::warehouse(action, ctx).await,
        Command::Config { action } => cluster::config(action, ctx).await,
        Command::Metrics { action } => cluster::metrics(action, ctx).await,
        Command::Configure(_) | Command::Volume { .. } | Command::Snapshot { .. } => {
            Err(anyhow!("not a management-API command"))
        }
    }
}

/// `?tenant=` when one is named, nothing otherwise — never an empty value,
/// which the server would read as naming the system scope.
pub fn tenant_query(t: &TenantOpt) -> Vec<(String, String)> {
    t.tenant
        .iter()
        .map(|t| ("tenant".to_string(), t.clone()))
        .collect()
}

pub fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// Read a file argument; `-` is stdin.
pub fn read_input(path: &Path) -> Result<Vec<u8>> {
    if path == Path::new("-") {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .context("reading stdin")?;
        Ok(buf)
    } else {
        std::fs::read(path).with_context(|| format!("reading {}", path.display()))
    }
}

/// Read a file argument that must be JSON.
pub fn read_json(path: &Path) -> Result<Value> {
    let bytes = read_input(path)?;
    serde_json::from_slice(&bytes).with_context(|| format!("{} is not valid JSON", path.display()))
}

/// Parse `key=value` pairs.
pub fn key_values(items: &[String]) -> Result<serde_json::Map<String, Value>> {
    items
        .iter()
        .map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
                .ok_or_else(|| anyhow!("expected key=value, got {kv:?}"))
        })
        .collect()
}

/// Parse a size like `10`, `512M`, `20G`, `2T` into bytes (binary units,
/// case-insensitive).
pub fn parse_size(s: &str) -> Result<u64> {
    let s = s.trim();
    let last = s.chars().last();
    let (num, multiplier): (&str, u64) = match last.map(|c| c.to_ascii_uppercase()) {
        Some('T') => (&s[..s.len() - 1], 1 << 40),
        Some('G') => (&s[..s.len() - 1], 1 << 30),
        Some('M') => (&s[..s.len() - 1], 1 << 20),
        Some('K') => (&s[..s.len() - 1], 1 << 10),
        _ => (s, 1),
    };
    let value: u64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow!("Invalid size: '{s}'"))?;
    value
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow!("Size '{s}' is larger than 16 EiB"))
}

/// Format bytes in the largest binary unit that divides them exactly, else
/// one decimal place.
#[allow(clippy::cast_precision_loss)] // display only
pub fn format_size(bytes: u64) -> String {
    const TIB: u64 = 1 << 40;
    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;
    if bytes >= TIB && bytes.is_multiple_of(TIB) {
        format!("{} TiB", bytes / TIB)
    } else if bytes >= GIB && bytes.is_multiple_of(GIB) {
        format!("{} GiB", bytes / GIB)
    } else if bytes >= MIB && bytes.is_multiple_of(MIB) {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= TIB {
        format!("{:.1} TiB", bytes as f64 / TIB as f64)
    } else if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_parse_in_binary_units() {
        assert_eq!(parse_size("4096").unwrap(), 4096);
        assert_eq!(parse_size("512M").unwrap(), 512 << 20);
        assert_eq!(parse_size("20g").unwrap(), 20 << 30);
        assert_eq!(parse_size(" 2T ").unwrap(), 2 << 40);
        assert_eq!(parse_size("8k").unwrap(), 8192);
    }

    #[test]
    fn bad_sizes_are_errors_not_panics() {
        for s in ["", "G", "abc", "1.5G", "-5G", "10GB"] {
            assert!(parse_size(s).is_err(), "{s:?} accepted");
        }
        assert!(
            parse_size("16777216T")
                .unwrap_err()
                .to_string()
                .contains("larger than")
        );
    }

    #[test]
    fn sizes_format_exactly_when_they_can() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(4 << 20), "4 MiB");
        assert_eq!(format_size((5 << 30) / 2), "2560 MiB");
        assert_eq!(format_size((3 << 20) / 2), "1.5 MiB");
        for bytes in [1u64 << 20, 512 << 20, 20 << 30, 3 << 40] {
            let compact = format_size(bytes)
                .replace(" TiB", "T")
                .replace(" GiB", "G")
                .replace(" MiB", "M");
            assert_eq!(parse_size(&compact).unwrap(), bytes);
        }
    }

    #[test]
    fn key_value_pairs_parse() {
        let m = key_values(&["a=1".into(), "b=x=y".into()]).unwrap();
        assert_eq!(m["a"], "1");
        assert_eq!(m["b"], "x=y");
        assert!(key_values(&["nope".into()]).is_err());
    }

    #[test]
    fn no_tenant_sends_no_tenant() {
        assert!(tenant_query(&TenantOpt::default()).is_empty());
        assert_eq!(
            tenant_query(&TenantOpt {
                tenant: Some("acme".into())
            }),
            q(&[("tenant", "acme")])
        );
    }
}
