//! `objectio-cli configure`: write a profile to the profile file.

use crate::cli::ConfigureArgs;
use crate::config::{DEFAULT_PROFILE, Flags, Profile, ProfileFile};
use crate::output::Out;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::Path;

/// `AKIA…1234` — enough to tell keys apart, never the secret.
pub fn mask(s: &str) -> String {
    let n = s.chars().count();
    if n <= 8 {
        "****".into()
    } else {
        let tail: String = s.chars().skip(n - 4).collect();
        format!("{}…{tail}", s.chars().take(4).collect::<String>())
    }
}

/// Merge what was given into the named profile: a value left out keeps the
/// one already stored.
pub fn apply(file: &mut ProfileFile, name: &str, given: &Profile) {
    let p = file.profiles.entry(name.to_string()).or_default();
    for (slot, v) in [
        (&mut p.endpoint, &given.endpoint),
        (&mut p.access_key, &given.access_key),
        (&mut p.secret_key, &given.secret_key),
        (&mut p.region, &given.region),
    ] {
        if let Some(v) = v.as_ref().filter(|v| !v.trim().is_empty()) {
            *slot = Some(v.trim().to_string());
        }
    }
}

fn prompt(label: &str, current: Option<&str>, secret: bool) -> Result<Option<String>> {
    let shown = current.map(|c| if secret { mask(c) } else { c.to_string() });
    match shown {
        Some(s) => eprint!("{label} [{s}]: "),
        None => eprint!("{label}: "),
    }
    std::io::stderr().flush().ok();
    // Hide a typed secret where the terminal allows it.
    let hidden = secret
        && std::process::Command::new("stty")
            .arg("-echo")
            .stdin(std::process::Stdio::inherit())
            .status()
            .is_ok_and(|s| s.success());
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    if hidden {
        let _ = std::process::Command::new("stty")
            .arg("echo")
            .stdin(std::process::Stdio::inherit())
            .status();
        eprintln!();
    }
    read.context("reading input")?;
    let line = line.trim().to_string();
    Ok(if line.is_empty() { None } else { Some(line) })
}

pub fn run(args: &ConfigureArgs, flags: &Flags, path: &Path, out: &mut Out<'_>) -> Result<()> {
    let mut file = ProfileFile::load(path)?;
    if args.list {
        let rows: Vec<Value> = file
            .profiles
            .iter()
            .map(|(name, p)| {
                json!({
                    "name": name,
                    "endpoint": p.endpoint,
                    "access_key": p.access_key,
                    "secret_key": p.secret_key.as_deref().map(mask),
                    "region": p.region,
                })
            })
            .collect();
        let raw = json!({ "path": path.display().to_string(), "profiles": rows });
        out.list(
            &raw,
            &rows,
            &[
                ("PROFILE", "name"),
                ("ENDPOINT", "endpoint"),
                ("ACCESS KEY", "access_key"),
                ("SECRET", "secret_key"),
                ("REGION", "region"),
            ],
            &format!("No profiles in {}.", path.display()),
        )?;
        return Ok(());
    }

    let name = flags
        .profile
        .clone()
        .unwrap_or_else(|| DEFAULT_PROFILE.to_string());
    let mut given = Profile {
        endpoint: flags.endpoint.clone(),
        access_key: flags.access_key.clone(),
        secret_key: flags.secret_key.clone(),
        region: flags.region.clone(),
    };
    if !args.non_interactive {
        let existing = file.profiles.get(&name).cloned().unwrap_or_default();
        eprintln!(
            "Configuring profile '{name}' in {} (Enter keeps the value shown)",
            path.display()
        );
        for (slot, label, cur, secret) in [
            (
                &mut given.endpoint,
                "Endpoint URL",
                existing.endpoint.as_deref(),
                false,
            ),
            (
                &mut given.access_key,
                "Access key ID",
                existing.access_key.as_deref(),
                false,
            ),
            (
                &mut given.secret_key,
                "Secret key",
                existing.secret_key.as_deref(),
                true,
            ),
            (
                &mut given.region,
                "Region",
                existing.region.as_deref(),
                false,
            ),
        ] {
            if slot.is_none() {
                *slot = prompt(label, cur, secret)?;
            }
        }
    }
    apply(&mut file, &name, &given);
    let p = &file.profiles[&name];
    if p.endpoint.is_none() {
        bail!("profile '{name}' needs an endpoint (--endpoint)");
    }
    if p.access_key.is_some() != p.secret_key.is_some() {
        bail!("profile '{name}' needs both an access key and a secret key");
    }
    file.save(path)?;
    out.emit(
        &json!({ "profile": name, "path": path.display().to_string() }),
        |_| format!("Saved profile '{name}' to {}\n", path.display()),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masking_keeps_only_the_ends() {
        assert_eq!(mask("short"), "****");
        assert_eq!(mask("AKIAABCDEFGH1234"), "AKIA…1234");
    }

    #[test]
    fn apply_merges_into_the_named_profile() {
        let mut f = ProfileFile::default();
        apply(
            &mut f,
            "p",
            &Profile {
                endpoint: Some("http://a".into()),
                access_key: Some("AK".into()),
                secret_key: Some("SK".into()),
                region: None,
            },
        );
        apply(
            &mut f,
            "p",
            &Profile {
                endpoint: Some("http://b".into()),
                ..Profile::default()
            },
        );
        let p = &f.profiles["p"];
        assert_eq!(p.endpoint.as_deref(), Some("http://b"));
        assert_eq!(p.secret_key.as_deref(), Some("SK"));
        assert_eq!(p.region, None);
    }

    #[test]
    fn non_interactive_configure_writes_and_lists_masked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config");
        let flags = Flags {
            endpoint: Some("http://gw:9000".into()),
            access_key: Some("AKIAEXAMPLE0001".into()),
            secret_key: Some("supersecretvalue".into()),
            region: None,
            profile: Some("lab".into()),
        };
        let mut buf = Vec::new();
        run(
            &ConfigureArgs {
                list: false,
                non_interactive: true,
            },
            &flags,
            &path,
            &mut Out {
                format: crate::output::Format::Table,
                w: &mut buf,
            },
        )
        .unwrap();
        let f = ProfileFile::load(&path).unwrap();
        assert_eq!(
            f.profiles["lab"].secret_key.as_deref(),
            Some("supersecretvalue")
        );

        let mut buf = Vec::new();
        run(
            &ConfigureArgs {
                list: true,
                non_interactive: true,
            },
            &Flags::default(),
            &path,
            &mut Out {
                format: crate::output::Format::Table,
                w: &mut buf,
            },
        )
        .unwrap();
        let listed = String::from_utf8(buf).unwrap();
        assert!(listed.contains("lab"), "{listed}");
        assert!(!listed.contains("supersecretvalue"), "{listed}");
        assert!(listed.contains("supe…alue"), "{listed}");
    }

    #[test]
    fn half_a_key_pair_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let flags = Flags {
            endpoint: Some("http://gw".into()),
            access_key: Some("AK".into()),
            ..Flags::default()
        };
        let mut buf = Vec::new();
        assert!(
            run(
                &ConfigureArgs {
                    list: false,
                    non_interactive: true,
                },
                &flags,
                &dir.path().join("c"),
                &mut Out {
                    format: crate::output::Format::Table,
                    w: &mut buf,
                },
            )
            .is_err()
        );
    }
}
