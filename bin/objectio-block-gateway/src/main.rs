//! ObjectIO Block Gateway binary: parse arguments, set up logging, run.

use anyhow::Result;
use clap::Parser;
use objectio_block_gateway::Args;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_new(&args.log_level).unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    objectio_block_gateway::run(args).await
}
