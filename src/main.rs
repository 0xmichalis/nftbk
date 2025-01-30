use anyhow::{Context, Result};
use clap::Parser;
use logging::LogLevel;
use serde::Deserialize;
use std::path::PathBuf;
use std::{collections::HashMap, time::Instant};
use tokio::fs;
use tracing::{info, warn};

mod chain;
mod content;
mod logging;
mod url;

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

    #[arg(short, long, value_enum, default_value = "info")]
    log_level: LogLevel,
}

#[derive(Debug, Deserialize)]
struct Config {
    chains: HashMap<String, String>,
    tokens: TokenConfig,
}

#[derive(Debug, Deserialize)]
struct TokenConfig {
    #[serde(flatten)]
    chains: HashMap<String, Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize logging
    logging::init(args.log_level);

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

    let start = Instant::now();

    // Process chains from config
    for (chain_name, contracts) in &config.tokens.chains {
        if contracts.is_empty() {
            warn!("No contracts configured for chain {}", chain_name);
            continue;
        }
        info!(
            "Processing {} contracts on {} ...",
            contracts.len(),
            chain_name
        );

        let rpc_url = config
            .chains
            .get(chain_name)
            .context(format!("No RPC URL configured for chain {}", chain_name))?;

        if chain_name != "tezos" {
            chain::evm::process_nfts(chain_name, rpc_url, contracts.clone(), &output_path).await?;
        } else {
            chain::tezos::process_nfts(rpc_url, contracts.clone(), &output_path).await?;
        }
    }

    info!(
        "Backup complete in {:?}s. Files saved in {}",
        start.elapsed().as_secs(),
        output_path.display()
    );

    Ok(())
}
