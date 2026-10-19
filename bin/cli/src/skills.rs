//! `obioctl skills`: the agent skills this CLI carries, and installing them
//! where coding agents read skills.
//!
//! The skills are markdown in the repository's `skills/` directory, the one
//! copy; they are compiled into the binary, so anywhere `obioctl` is
//! installed can install them, with nothing to fetch.
//!
//! Doc comments on the commands are `--help` text, written for a terminal.
#![allow(clippy::doc_markdown)]

use crate::output::{Out, table};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// Who a skill is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Audience {
    /// Operators: deploying and running a cluster
    Ops,
    /// Application developers: building on ObjectIO's APIs
    Dev,
}

impl Audience {
    const fn name(self) -> &'static str {
        match self {
            Self::Ops => "ops",
            Self::Dev => "dev",
        }
    }
}

pub struct Skill {
    pub name: &'static str,
    pub audience: Audience,
    pub text: &'static str,
}

macro_rules! skill {
    ($name:literal, $audience:ident) => {
        Skill {
            name: $name,
            audience: Audience::$audience,
            text: include_str!(concat!("../../../skills/", $name, "/SKILL.md")),
        }
    };
}

/// Every skill in `skills/`; a test fails if one is missing here.
pub const SKILLS: &[Skill] = &[
    skill!("objectio-deploy", Ops),
    skill!("objectio-admin", Ops),
    skill!("objectio-sdk", Dev),
];

/// The coding agents whose skills directory we know, under `$HOME`: the
/// directory that shows the agent is installed, and where it reads skills.
const AGENTS: &[(&str, &str, &str)] = &[
    ("claude", ".claude", ".claude/skills"),
    ("codex", ".codex", ".codex/skills"),
    ("opencode", ".config/opencode", ".config/opencode/skills"),
    ("pi", ".pi", ".pi/agent/skills"),
    // Read by opencode, goose and others; always installed to.
    ("agents", ".agents", ".agents/skills"),
];

#[derive(clap::Subcommand, Debug)]
pub enum SkillsCmd {
    /// The skills this CLI carries
    List,
    /// Copy the skills where coding agents read them: every agent found
    /// under $HOME (Claude Code, Codex, opencode, pi), and ~/.agents/skills
    Install {
        /// Only these agents (repeatable): claude, codex, opencode, pi, agents
        #[arg(long = "agent")]
        agents: Vec<String>,
        /// Every agent, whether or not it is installed here
        #[arg(long, conflicts_with = "agents")]
        all: bool,
        /// This directory instead, e.g. ./.claude/skills for one project
        #[arg(long, conflicts_with_all = ["agents", "all"])]
        dir: Option<PathBuf>,
        /// Only the skills for operators (ops) or developers (dev)
        #[arg(long, value_enum)]
        audience: Option<Audience>,
        /// Replace skills already there, e.g. after upgrading obioctl
        #[arg(long)]
        force: bool,
    },
}

/// The `description:` line of a skill's front matter.
fn description(text: &str) -> &str {
    text.lines()
        .skip(1)
        .take_while(|l| *l != "---")
        .find_map(|l| l.strip_prefix("description:"))
        .map_or("", str::trim)
}

pub fn run(cmd: SkillsCmd, home: Option<&Path>, out: &mut Out<'_>) -> Result<()> {
    match cmd {
        SkillsCmd::List => {
            let rows: Vec<Value> = SKILLS
                .iter()
                .map(|s| {
                    json!({
                        "name": s.name,
                        "audience": s.audience.name(),
                        "description": description(s.text),
                    })
                })
                .collect();
            out.emit(&Value::Array(rows.clone()), |_| {
                table(
                    &rows,
                    &[
                        ("NAME", "name"),
                        ("FOR", "audience"),
                        ("DESCRIPTION", "description"),
                    ],
                )
            })?;
            Ok(())
        }
        SkillsCmd::Install {
            agents,
            all,
            dir,
            audience,
            force,
        } => {
            let dirs = targets(&agents, all, dir, home)?;
            let skills: Vec<&Skill> = SKILLS
                .iter()
                .filter(|s| audience.is_none_or(|a| a == s.audience))
                .collect();
            let mut rows = Vec::new();
            for d in &dirs {
                for s in &skills {
                    let path = d.join(s.name).join("SKILL.md");
                    let status = install(&path, s.text, force)?;
                    rows.push(json!({
                        "skill": s.name,
                        "path": path.display().to_string(),
                        "status": status,
                    }));
                }
            }
            let kept = rows.iter().any(|r| r["status"] == "kept");
            out.emit(&Value::Array(rows.clone()), |_| {
                let mut s = table(&rows, &[("STATUS", "status"), ("PATH", "path")]);
                if kept {
                    s.push_str("kept: already there and different; --force replaces it\n");
                }
                s
            })?;
            Ok(())
        }
    }
}

/// The skills directories to install into.
fn targets(
    agents: &[String],
    all: bool,
    dir: Option<PathBuf>,
    home: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    if let Some(d) = dir {
        return Ok(vec![d]);
    }
    let home = home.context("HOME is not set: name a directory with --dir")?;
    for a in agents {
        if !AGENTS.iter().any(|(name, ..)| name == a) {
            let known: Vec<&str> = AGENTS.iter().map(|(n, ..)| *n).collect();
            bail!("unknown agent {a:?}; known: {}", known.join(", "));
        }
    }
    Ok(AGENTS
        .iter()
        .filter(|(name, marker, _)| {
            if agents.is_empty() {
                all || *name == "agents" || home.join(marker).is_dir()
            } else {
                agents.iter().any(|a| a == name)
            }
        })
        .map(|(_, _, skills)| home.join(skills))
        .collect())
}

/// Write one skill; an existing, different copy is replaced only with
/// `force`. Returns what happened.
fn install(path: &Path, text: &str, force: bool) -> Result<&'static str> {
    let status = match std::fs::read_to_string(path) {
        Ok(old) if old == text => return Ok("current"),
        Ok(_) if !force => return Ok("kept"),
        Ok(_) => "replaced",
        Err(_) => "installed",
    };
    let parent = path.parent().context("a skill path has a parent")?;
    std::fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Format;

    fn run_to_string(cmd: SkillsCmd, home: &Path, format: Format) -> String {
        let mut buf = Vec::new();
        let mut out = Out {
            format,
            w: &mut buf,
        };
        run(cmd, Some(home), &mut out).unwrap();
        String::from_utf8(buf).unwrap()
    }

    fn install_cmd(dir: Option<PathBuf>, force: bool) -> SkillsCmd {
        SkillsCmd::Install {
            agents: vec![],
            all: false,
            dir,
            audience: None,
            force,
        }
    }

    #[test]
    fn every_skill_in_the_repository_is_carried() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../skills");
        let mut on_disk: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.path().join("SKILL.md").is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        on_disk.sort();
        let mut carried: Vec<String> = SKILLS.iter().map(|s| s.name.to_string()).collect();
        carried.sort();
        assert_eq!(on_disk, carried, "skills/ and SKILLS differ");
    }

    #[test]
    fn each_skill_names_itself_and_says_when_to_use_it() {
        for s in SKILLS {
            assert!(s.text.starts_with("---\n"), "{}: no front matter", s.name);
            let name = s
                .text
                .lines()
                .take_while(|l| !l.is_empty())
                .find_map(|l| l.strip_prefix("name:"))
                .map(str::trim);
            assert_eq!(name, Some(s.name), "{}: front matter name", s.name);
            let d = description(s.text);
            assert!(d.contains("Use when"), "{}: description says when", s.name);
            assert!(d.len() <= 1024, "{}: description too long", s.name);
        }
    }

    #[test]
    fn install_finds_the_agents_present_and_always_the_shared_directory() {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join(".claude")).unwrap();
        let printed = run_to_string(install_cmd(None, false), home.path(), Format::Table);
        for s in SKILLS {
            for dir in [".claude/skills", ".agents/skills"] {
                let p = home.path().join(dir).join(s.name).join("SKILL.md");
                assert_eq!(std::fs::read_to_string(&p).unwrap(), s.text);
            }
        }
        assert!(!home.path().join(".codex").exists(), "no codex here");
        assert!(printed.contains("installed"), "{printed}");
    }

    #[test]
    fn a_changed_copy_is_kept_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        let first = &SKILLS[0];
        let path = dir.path().join(first.name).join("SKILL.md");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "edited").unwrap();

        let d = Some(dir.path().to_path_buf());
        let printed = run_to_string(install_cmd(d.clone(), false), dir.path(), Format::Table);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "edited");
        assert!(printed.contains("--force"), "{printed}");

        run_to_string(install_cmd(d.clone(), true), dir.path(), Format::Table);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), first.text);
        let again = run_to_string(install_cmd(d, false), dir.path(), Format::Json);
        assert!(!again.contains("\"kept\""), "{again}");
    }

    #[test]
    fn an_audience_installs_only_its_skills_and_an_unknown_agent_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let cmd = SkillsCmd::Install {
            agents: vec![],
            all: false,
            dir: Some(dir.path().to_path_buf()),
            audience: Some(Audience::Dev),
            force: false,
        };
        run_to_string(cmd, dir.path(), Format::Table);
        for s in SKILLS {
            let there = dir.path().join(s.name).exists();
            assert_eq!(there, s.audience == Audience::Dev, "{}", s.name);
        }
        let err = targets(&["vim".into()], false, None, Some(dir.path())).unwrap_err();
        assert!(err.to_string().contains("unknown agent"), "{err}");
    }
}
