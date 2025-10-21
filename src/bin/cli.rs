use anyhow::Result;
use clap::Parser;
use dotenv::dotenv;
use tracing::debug;

use nftbk::cli::Cli;
use nftbk::logging;

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let cli = Cli::parse();
    let log_level = cli.log_level;
    let no_color = cli.no_color;
    logging::init(log_level, !no_color);
    debug!(
        "Version: {} {} (commit {})",
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("GIT_COMMIT")
    );

    cli.run().await
}
