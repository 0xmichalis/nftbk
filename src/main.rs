use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};
use tokio::fs;
use url::Url;

mod ethereum;
mod tezos;
mod url;

use url::get_url;

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

// NFT Metadata structure
#[derive(Debug, Serialize, Deserialize)]
pub struct NFTMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub animation_url: Option<String>,
    pub external_url: Option<String>,
    pub attributes: Option<Vec<NFTAttribute>>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTAttribute {
    pub trait_type: String,
    pub value: serde_json::Value,
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

pub async fn fetch_and_save_content(
    url: &str,
    output_path: &Path,
    chain: &str,
    token_id: &str,
    contract: &str,
    content_type: &str,
) -> Result<PathBuf> {
    let content_url = get_url(url);
    let client = reqwest::Client::new();
    let response = client.get(&content_url).send().await?;
    let content = response.bytes().await?;

    let url = Url::parse(url)?;
    let file_name = url
        .path_segments()
        .and_then(|segments| segments.last())
        .unwrap_or(content_type);

    let dir_path = output_path.join(chain).join(contract).join(token_id);
    fs::create_dir_all(&dir_path).await?;

    let file_path = dir_path.join(file_name);
    fs::write(&file_path, content).await?;

    Ok(file_path)
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
