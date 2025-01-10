use anyhow::{Context, Result};
use clap::Parser;
use std::{path::PathBuf, str::FromStr};
use tokio::fs;

mod ethereum;
mod tezos;
mod url;

// CLI Arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// List of Ethereum or Tezos addresses to fetch NFTs from
    #[arg(required = true)]
    addresses: Vec<String>,

    /// Path to the NFT contracts configuration file (default: config.toml)
    #[arg(short, long, default_value = "config.toml")]
    config_path: PathBuf,

    /// Optional output directory path (defaults to current directory)
    #[arg(short, long)]
    output_path: Option<PathBuf>,
}

#[derive(Debug)]
enum ChainAddress {
    Ethereum,
    Tezos,
}

impl FromStr for ChainAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("KT1") {
            Ok(ChainAddress::Tezos)
        } else {
            // Validate it's a valid Ethereum address
            s.parse::<ethers::types::Address>()
                .context("Failed to parse Ethereum address")?;
            Ok(ChainAddress::Ethereum)
        }
    }
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

    // Process each address
    for addr_str in args.addresses {
        let chain_address = addr_str.parse::<ChainAddress>()?;

        match chain_address {
            ChainAddress::Ethereum => {
                ethereum::process_nfts(&args.config_path, &output_path).await?;
            }
            ChainAddress::Tezos => {
                tezos::process_nfts(&args.config_path, &output_path).await?;
            }
        }
    }

    Ok(())
}
