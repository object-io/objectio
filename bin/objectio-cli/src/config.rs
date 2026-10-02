//! Where the endpoint and credentials come from.
//!
//! In order, first match wins:
//!
//! 1. flags: `--endpoint`, `--access-key`/`--secret-key`, `--region`;
//! 2. the profile named by `--profile`, when given on the command line;
//! 3. the environment, as the SDKs read it: `OBJECTIO_ENDPOINT` |
//!    `OBJECTIO_URL`, `OBJECTIO_ACCESS_KEY(_FILE)` | `AWS_ACCESS_KEY_ID`,
//!    `OBJECTIO_SECRET_KEY(_FILE)` | `AWS_SECRET_ACCESS_KEY`,
//!    `OBJECTIO_REGION` | `AWS_REGION` | `AWS_DEFAULT_REGION`;
//! 4. the profile named by `OBJECTIO_PROFILE`, else `default`, in the
//!    profile file (`$OBJECTIO_CONFIG_FILE`, else `~/.objectio/config`).
//!
//! The access key and secret are taken as a pair from one source: a key
//! from the environment never signs with a secret from a profile.

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_REGION: &str = "us-east-1";
pub const DEFAULT_PROFILE: &str = "default";

/// One named profile in the profile file.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// The profile file: a TOML table per profile name.
///
/// ```toml
/// [default]
/// endpoint = "https://s3.example.com"
/// access_key = "AKIA..."
/// secret_key = "..."
///
/// [acme]
/// endpoint = "https://s3.example.com"
/// access_key = "..."
/// secret_key = "..."
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileFile {
    pub profiles: BTreeMap<String, Profile>,
}

impl ProfileFile {
    pub fn parse(text: &str) -> Result<Self> {
        toml::from_str(text).context("profile file is not valid TOML")
    }

    /// Read `path`; a missing file is an empty one.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text).with_context(|| path.display().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn render(&self) -> Result<String> {
        toml::to_string(self).context("encoding profile file")
    }

    /// Write `path` readable by its owner only — it holds secrets.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
            }
        }
        let text = self.render()?;
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts
                .open(&tmp)
                .with_context(|| format!("writing {}", tmp.display()))?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))
    }
}

/// Where the profile file lives.
pub fn profile_path(env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(p) = env("OBJECTIO_CONFIG_FILE").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    env("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".objectio").join("config"))
}

/// Settings given as flags.
#[derive(Debug, Clone, Default)]
pub struct Flags {
    pub endpoint: Option<String>,
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub region: Option<String>,
    pub profile: Option<String>,
}

/// The resolved connection settings.
#[derive(Clone, PartialEq, Eq)]
pub struct Settings {
    pub endpoint: String,
    /// `None` for a keyless call (STS).
    pub credentials: Option<(String, String)>,
    pub region: String,
    /// Where the credentials came from, for error messages.
    pub source: String,
}

impl std::fmt::Debug for Settings {
    // Never the secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Settings")
            .field("endpoint", &self.endpoint)
            .field("access_key", &self.credentials.as_ref().map(|c| &c.0))
            .field("region", &self.region)
            .field("source", &self.source)
            .finish()
    }
}

/// One value from `<FILE_VAR>` (a path to read), then each direct variable.
/// File contents are trimmed: a mounted secret ends in a newline, and a
/// newline inside a signing key reads like a wrong password.
fn env_value(
    env: &dyn Fn(&str) -> Option<String>,
    file_var: Option<&str>,
    vars: &[&str],
) -> Result<Option<String>> {
    if let Some(fv) = file_var
        && let Some(path) = env(fv).filter(|p| !p.is_empty())
    {
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("reading {fv}={path}"))?;
        return Ok(Some(text.trim().to_string()));
    }
    Ok(vars.iter().find_map(|v| {
        env(v)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }))
}

fn nonempty(v: Option<&String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// A source of settings, in precedence order.
struct Source {
    name: String,
    endpoint: Option<String>,
    access_key: Option<String>,
    secret_key: Option<String>,
    region: Option<String>,
}

impl Source {
    fn from_profile(name: &str, p: &Profile) -> Self {
        Self {
            name: format!("profile '{name}'"),
            endpoint: nonempty(p.endpoint.as_ref()),
            access_key: nonempty(p.access_key.as_ref()),
            secret_key: nonempty(p.secret_key.as_ref()),
            region: nonempty(p.region.as_ref()),
        }
    }
}

/// Resolve settings from flags, the environment and the profile file.
///
/// `need_credentials` false allows a keyless result (for STS); otherwise a
/// missing key is an error that says where it looked.
pub fn resolve(
    flags: &Flags,
    env: &dyn Fn(&str) -> Option<String>,
    file: &ProfileFile,
    need_credentials: bool,
) -> Result<Settings> {
    let mut sources = vec![Source {
        name: "flags".into(),
        endpoint: nonempty(flags.endpoint.as_ref()),
        access_key: nonempty(flags.access_key.as_ref()),
        secret_key: nonempty(flags.secret_key.as_ref()),
        region: nonempty(flags.region.as_ref()),
    }];

    let explicit = nonempty(flags.profile.as_ref());
    if let Some(name) = &explicit {
        let p = file
            .profiles
            .get(name)
            .ok_or_else(|| anyhow!("profile '{name}' not found in the profile file"))?;
        sources.push(Source::from_profile(name, p));
    }

    sources.push(Source {
        name: "environment".into(),
        endpoint: env_value(env, None, &["OBJECTIO_ENDPOINT", "OBJECTIO_URL"])?,
        access_key: env_value(
            env,
            Some("OBJECTIO_ACCESS_KEY_FILE"),
            &["OBJECTIO_ACCESS_KEY", "AWS_ACCESS_KEY_ID"],
        )?,
        secret_key: env_value(
            env,
            Some("OBJECTIO_SECRET_KEY_FILE"),
            &["OBJECTIO_SECRET_KEY", "AWS_SECRET_ACCESS_KEY"],
        )?,
        region: env_value(
            env,
            None,
            &["OBJECTIO_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"],
        )?,
    });

    if explicit.is_none() {
        let name = env("OBJECTIO_PROFILE")
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| DEFAULT_PROFILE.to_string());
        if let Some(p) = file.profiles.get(&name) {
            sources.push(Source::from_profile(&name, p));
        } else if name != DEFAULT_PROFILE {
            bail!("profile '{name}' (from OBJECTIO_PROFILE) not found in the profile file");
        }
    }

    let endpoint = sources
        .iter()
        .find_map(|s| s.endpoint.clone())
        .ok_or_else(|| {
            anyhow!(
                "no endpoint: pass --endpoint, set OBJECTIO_ENDPOINT, or run `objectio-cli configure`"
            )
        })?;
    let region = sources
        .iter()
        .find_map(|s| s.region.clone())
        .unwrap_or_else(|| DEFAULT_REGION.to_string());

    let mut credentials = None;
    let mut source = String::from("none");
    for s in &sources {
        match (&s.access_key, &s.secret_key) {
            (Some(ak), Some(sk)) => {
                credentials = Some((ak.clone(), sk.clone()));
                source.clone_from(&s.name);
                break;
            }
            (Some(_), None) => bail!("{} sets an access key but no secret key", s.name),
            (None, Some(_)) => bail!("{} sets a secret key but no access key", s.name),
            (None, None) => {}
        }
    }
    if need_credentials && credentials.is_none() {
        bail!(
            "no credentials: pass --access-key/--secret-key, set OBJECTIO_ACCESS_KEY and \
             OBJECTIO_SECRET_KEY (or their _FILE forms, or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY), \
             or run `objectio-cli configure`"
        );
    }

    Ok(Settings {
        endpoint: endpoint.trim_end_matches('/').to_string(),
        credentials,
        region,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }

    fn file() -> ProfileFile {
        ProfileFile::parse(
            r#"
[default]
endpoint = "http://default:9000"
access_key = "AKDEFAULT"
secret_key = "skdefault"

[acme]
endpoint = "http://acme:9000/"
access_key = "AKACME"
secret_key = "skacme"
region = "eu-west-1"
"#,
        )
        .unwrap()
    }

    #[test]
    fn the_default_profile_is_the_fallback() {
        let s = resolve(&Flags::default(), &env_of(&[]), &file(), true).unwrap();
        assert_eq!(s.endpoint, "http://default:9000");
        assert_eq!(s.credentials.unwrap().0, "AKDEFAULT");
        assert_eq!(s.region, "us-east-1");
    }

    #[test]
    fn the_environment_beats_the_default_profile() {
        let env = env_of(&[
            ("OBJECTIO_URL", "http://env:9000"),
            ("OBJECTIO_ACCESS_KEY", "AKENV"),
            ("OBJECTIO_SECRET_KEY", "skenv"),
            ("AWS_REGION", "ap-south-1"),
        ]);
        let s = resolve(&Flags::default(), &env, &file(), true).unwrap();
        assert_eq!(s.endpoint, "http://env:9000");
        assert_eq!(s.credentials.unwrap(), ("AKENV".into(), "skenv".into()));
        assert_eq!(s.region, "ap-south-1");
        assert_eq!(s.source, "environment");
    }

    #[test]
    fn an_explicit_profile_beats_the_environment() {
        let env = env_of(&[
            ("OBJECTIO_ENDPOINT", "http://env:9000"),
            ("OBJECTIO_ACCESS_KEY", "AKENV"),
            ("OBJECTIO_SECRET_KEY", "skenv"),
        ]);
        let flags = Flags {
            profile: Some("acme".into()),
            ..Flags::default()
        };
        let s = resolve(&flags, &env, &file(), true).unwrap();
        // Trailing slash dropped, so paths join cleanly.
        assert_eq!(s.endpoint, "http://acme:9000");
        assert_eq!(s.credentials.unwrap().0, "AKACME");
        assert_eq!(s.region, "eu-west-1");
    }

    #[test]
    fn objectio_profile_selects_a_profile_below_the_environment() {
        let env = env_of(&[("OBJECTIO_PROFILE", "acme")]);
        let s = resolve(&Flags::default(), &env, &file(), true).unwrap();
        assert_eq!(s.credentials.unwrap().0, "AKACME");
        let env = env_of(&[("OBJECTIO_PROFILE", "nope")]);
        assert!(resolve(&Flags::default(), &env, &file(), true).is_err());
    }

    #[test]
    fn flags_beat_everything() {
        let flags = Flags {
            endpoint: Some("http://flag:1".into()),
            access_key: Some("AKFLAG".into()),
            secret_key: Some("skflag".into()),
            region: Some("r1".into()),
            profile: Some("acme".into()),
        };
        let env = env_of(&[
            ("OBJECTIO_ACCESS_KEY", "AKENV"),
            ("OBJECTIO_SECRET_KEY", "x"),
        ]);
        let s = resolve(&flags, &env, &file(), true).unwrap();
        assert_eq!(s.endpoint, "http://flag:1");
        assert_eq!(s.credentials.unwrap().0, "AKFLAG");
        assert_eq!(s.region, "r1");
    }

    #[test]
    fn aws_names_are_fallbacks() {
        let env = env_of(&[
            ("OBJECTIO_ENDPOINT", "http://e"),
            ("AWS_ACCESS_KEY_ID", "AKAWS"),
            ("AWS_SECRET_ACCESS_KEY", "skaws"),
            ("AWS_DEFAULT_REGION", "us-west-2"),
        ]);
        let s = resolve(&Flags::default(), &env, &ProfileFile::default(), true).unwrap();
        assert_eq!(s.credentials.unwrap(), ("AKAWS".into(), "skaws".into()));
        assert_eq!(s.region, "us-west-2");
    }

    #[test]
    fn a_secret_file_is_read_and_trimmed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sk");
        std::fs::write(&path, "fromfile\n").unwrap();
        let p = path.to_str().unwrap();
        let pairs = [
            ("OBJECTIO_ENDPOINT", "http://e"),
            ("OBJECTIO_ACCESS_KEY", "AK"),
            ("OBJECTIO_SECRET_KEY", "ignored"),
            ("OBJECTIO_SECRET_KEY_FILE", p),
        ];
        let env = env_of(&pairs);
        let s = resolve(&Flags::default(), &env, &ProfileFile::default(), true).unwrap();
        assert_eq!(s.credentials.unwrap().1, "fromfile");
    }

    #[test]
    fn half_a_key_pair_is_an_error_not_a_mix() {
        let env = env_of(&[("OBJECTIO_ACCESS_KEY", "AKENV")]);
        let err = resolve(&Flags::default(), &env, &file(), true).unwrap_err();
        assert!(err.to_string().contains("no secret key"), "{err}");
    }

    #[test]
    fn nothing_configured_says_where_to_look() {
        let err = resolve(
            &Flags::default(),
            &env_of(&[]),
            &ProfileFile::default(),
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("no endpoint"), "{err}");
        let env = env_of(&[("OBJECTIO_ENDPOINT", "http://e")]);
        let err = resolve(&Flags::default(), &env, &ProfileFile::default(), true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("no credentials"), "{err}");
        // Keyless is fine when the command does not sign.
        let s = resolve(&Flags::default(), &env, &ProfileFile::default(), false).unwrap();
        assert!(s.credentials.is_none());
    }

    #[test]
    fn an_unknown_explicit_profile_is_an_error() {
        let flags = Flags {
            profile: Some("ghost".into()),
            ..Flags::default()
        };
        assert!(resolve(&flags, &env_of(&[]), &file(), true).is_err());
    }

    #[test]
    fn the_profile_path_honours_the_override() {
        let env = env_of(&[("HOME", "/home/u")]);
        assert_eq!(
            profile_path(&env).unwrap(),
            PathBuf::from("/home/u/.objectio/config")
        );
        let env = env_of(&[("HOME", "/home/u"), ("OBJECTIO_CONFIG_FILE", "/etc/o.toml")]);
        assert_eq!(profile_path(&env).unwrap(), PathBuf::from("/etc/o.toml"));
    }

    #[test]
    fn a_saved_file_round_trips_and_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub").join("config");
        let f = file();
        f.save(&path).unwrap();
        assert_eq!(ProfileFile::load(&path).unwrap(), f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(
            ProfileFile::load(&dir.path().join("missing")).unwrap(),
            ProfileFile::default()
        );
    }

    #[test]
    fn debug_never_shows_the_secret() {
        let s = resolve(&Flags::default(), &env_of(&[]), &file(), true).unwrap();
        let shown = format!("{s:?}");
        assert!(!shown.contains("skdefault"), "{shown}");
        assert!(shown.contains("AKDEFAULT"));
    }
}
