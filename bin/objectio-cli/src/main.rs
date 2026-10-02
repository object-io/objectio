//! `objectio-cli` — the `ObjectIO` management CLI.
//!
//! A client of the gateway's admin HTTP API, signed with `SigV4` like the
//! SDKs: every call goes through the gateway's authentication, tenant
//! scoping, validation, audit and cache invalidation. Nothing here talks to
//! meta directly. Block `volume`/`snapshot` commands are the exception by
//! design: they speak gRPC to the block gateway's `BlockService`.

// A CLI runs one command on one thread: its futures need not be `Send`
// (they hold the stdout lock), and its command dispatchers are long matches
// with one arm per subcommand.
#![allow(
    clippy::future_not_send,
    clippy::too_many_lines,
    clippy::missing_errors_doc
)]

mod block;
mod cli;
mod commands;
mod config;
mod configure;
mod http;
mod output;
mod sigv4;
#[cfg(test)]
mod stub_tests;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Args, Command, OidcCmd};
use config::{Flags, ProfileFile};
use output::Out;
use std::process::ExitCode;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Run one parsed command line. `env` stands in for the process
/// environment so tests can run commands without touching it.
pub async fn execute(
    args: Args,
    env: &dyn Fn(&str) -> Option<String>,
    w: &mut dyn std::io::Write,
) -> Result<()> {
    let flags = Flags {
        endpoint: args.endpoint,
        access_key: args.access_key,
        secret_key: args.secret_key,
        region: args.region,
        profile: args.profile,
    };
    let mut out = Out {
        format: args.output,
        w,
    };
    match args.command {
        Command::Configure(c) => {
            let path = config::profile_path(env)
                .context("neither OBJECTIO_CONFIG_FILE nor HOME is set")?;
            configure::run(&c, &flags, &path, &mut out)
        }
        Command::Volume { action } => block::volume(action, &args.block_endpoint, &mut out).await,
        Command::Snapshot { action } => {
            block::snapshot(action, &args.block_endpoint, &mut out).await
        }
        Command::Oidc {
            action: OidcCmd::TenantName { tenant },
        } => {
            // No request: nothing to configure.
            let name = commands::access::tenant_provider_name(&tenant);
            out.emit(&serde_json::json!({ "name": name }), |_| {
                format!("{name}\n")
            })?;
            Ok(())
        }
        cmd => {
            let file = match config::profile_path(env) {
                Some(p) => ProfileFile::load(&p)?,
                None => ProfileFile::default(),
            };
            // STS is keyless: the web identity token is the proof.
            let need_credentials = !matches!(cmd, Command::Sts { .. });
            let settings = config::resolve(&flags, env, &file, need_credentials)?;
            tracing::debug!(?settings, "resolved settings");
            let api = http::ApiClient::new(settings)?;
            let mut ctx = commands::Ctx {
                api: &api,
                out,
                provisioner: env("OBJECTIO_PROVISIONER_USER_ID").filter(|s| !s.is_empty()),
            };
            commands::run(cmd, &mut ctx).await
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = Args::parse();
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(&args.log_level))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let env = |k: &str| std::env::var(k).ok();
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    match execute(args, &env, &mut lock).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            drop(lock);
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// clap's own consistency check over the whole command tree: a duplicate
    /// flag or a bad group is a panic at first use, not a build error.
    #[test]
    fn the_command_tree_is_well_formed() {
        use clap::CommandFactory;
        Args::command().debug_assert();
    }

    #[test]
    fn an_empty_tenant_is_refused_at_parse_time() {
        let r = Args::try_parse_from(["objectio-cli", "user", "list", "--tenant", ""]);
        assert!(r.is_err());
    }

    #[test]
    fn a_policy_principal_is_exactly_one() {
        assert!(
            Args::try_parse_from([
                "objectio-cli",
                "policy",
                "attach",
                "p",
                "--user",
                "u",
                "--group",
                "g"
            ])
            .is_err()
        );
        assert!(Args::try_parse_from(["objectio-cli", "policy", "attach", "p"]).is_err());
        assert!(
            Args::try_parse_from(["objectio-cli", "policy", "attach", "p", "--role", "r"]).is_ok()
        );
    }
}
