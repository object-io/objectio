//! ObjectIO OSD — standalone binary entrypoint.
//!
//! Parses CLI, installs tracing, delegates to the library crate's
//! `run()` so `bin/aio` can share the implementation.

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = objectio_osd::Args::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.clone().into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    objectio_osd::run(args, async {
        tokio::signal::ctrl_c().await.ok();
    })
    .await
}
