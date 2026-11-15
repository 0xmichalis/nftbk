use anyhow::Result;
use clap::Parser;
use dotenvy::dotenv;
use tracing::debug;

use nftbk::cli::Cli;
use nftbk::envvar::{ProcessEnv, should_enable_color};
use nftbk::logging;

fn main() -> Result<()> {
    // dotenvy writes .env into the process environment. That is only sound while no
    // other thread can read the environment, so it runs before the Tokio runtime starts.
    dotenv().ok();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed building the Runtime")
        .block_on(run())
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let log_level = cli.log_level;
    let enable_color = should_enable_color(cli.no_color, &ProcessEnv);
    logging::init(log_level, enable_color);
    debug!(
        "Version: {} {} (commit {})",
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("GIT_COMMIT")
    );

    cli.run().await
}
