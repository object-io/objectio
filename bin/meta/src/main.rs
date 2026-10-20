//! ObjectIO Metadata Service — standalone binary entrypoint.
//!
//! Parses CLI args, installs the global tracing subscriber, and calls
//! into the library crate. The heavy lifting lives in `lib.rs` so
//! `bin/aio` can re-use it in-process.

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = objectio_meta::Args::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.clone().into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    if let Some(tool) = args.tool.take() {
        return objectio_meta::restore::run(tool).await;
    }
    objectio_meta::run(args, objectio_common::shutdown_signal()?).await
}
