use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tokio::fs;

mod content;
mod ethereum;
mod tezos;
mod url;

use serde::Deserialize;

// CLI Arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the NFT contracts configuration file (default: config.toml)
    #[arg(short, long, default_value = "config.toml")]
    config_path: PathBuf,

    /// Optional output directory path (defaults to current directory)
    #[arg(short, long)]
    output_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct Config {
    contracts: Contracts,
}

#[derive(Debug, Deserialize)]
struct Contracts {
    ethereum: Vec<String>,
    tezos: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from .env file if it exists
    dotenv::dotenv().ok();

    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args = Args::parse();

    // Use provided output path or current directory as base
    let base_path = args.output_path.unwrap_or_else(|| PathBuf::from("."));

    // Set output path to nft_backup within the base path
    let output_path = base_path.join("nft_backup");

    // Create nft_backup directory if it doesn't exist
    fs::create_dir_all(&output_path).await?;

    // Read and parse config file
    let config_content = fs::read_to_string(&args.config_path)
        .await
        .context("Failed to read config file")?;
    let config: Config = toml::from_str(&config_content).context("Failed to parse config file")?;

    // Process chains based on config
    if !config.contracts.ethereum.is_empty() {
        ethereum::process_nfts(config.contracts.ethereum.clone(), &output_path).await?;
    }

    if !config.contracts.tezos.is_empty() {
        tezos::process_nfts(config.contracts.tezos.clone(), &output_path).await?;
    }

    Ok(())
}
