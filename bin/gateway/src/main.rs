//! ObjectIO Gateway — standalone binary entrypoint.
//!
//! Parses CLI, installs the global tracing subscriber, and hands off
//! to `objectio_gateway::run()`. The same `run()` is invoked in-
//! process by `bin/aio` for the monolithic dev mode.

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn main() -> anyhow::Result<()> {
    objectio_gateway::runtime()?.block_on(serve())
}

async fn serve() -> anyhow::Result<()> {
    let args = objectio_gateway::Args::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.clone().into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    objectio_gateway::run(args, objectio_common::shutdown_signal()?).await
}
