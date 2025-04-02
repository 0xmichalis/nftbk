use anyhow::{Context, Result};
use clap::Parser;
use logging::LogLevel;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};
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

    /// Delete directories in the backup folder that are not part of the config
    #[arg(long, default_value = "false")]
    prune_missing: bool,
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

/// Prune directories in the backup folder that are not part of the config
async fn prune_missing_directories(output_path: &Path, config: &Config) -> Result<()> {
    // Build map of valid token IDs per contract per chain
    let mut valid_tokens: HashMap<String, HashMap<String, HashSet<String>>> = HashMap::new();
    for (chain, contracts) in &config.tokens.chains {
        for contract_token in contracts {
            if let Some((contract, token_id)) = contract_token.split_once(':') {
                valid_tokens
                    .entry(chain.clone())
                    .or_default()
                    .entry(contract.to_string())
                    .or_default()
                    .insert(token_id.to_string());
            }
        }
    }

    // Check if output directory exists
    if !fs::try_exists(output_path).await? {
        return Ok(());
    }

    // Iterate through chain directories
    let mut chain_entries = fs::read_dir(output_path).await?;
    while let Some(chain_entry) = chain_entries.next_entry().await? {
        let chain_path = chain_entry.path();
        if !fs::metadata(&chain_path).await?.is_dir() {
            continue;
        }

        let chain_name = chain_path
            .file_name()
            .and_then(|name| name.to_str())
            .map(String::from);

        let Some(chain_name) = chain_name else {
            continue;
        };

        // Remove chain if not in config
        if !valid_tokens.contains_key(&chain_name) {
            info!("Pruning chain directory: {}", chain_path.display());
            fs::remove_dir_all(&chain_path).await?;
            continue;
        }

        // Iterate through contract directories
        let mut contract_entries = fs::read_dir(&chain_path).await?;
        while let Some(contract_entry) = contract_entries.next_entry().await? {
            let contract_path = contract_entry.path();
            if !fs::metadata(&contract_path).await?.is_dir() {
                continue;
            }

            let contract_addr = contract_path
                .file_name()
                .and_then(|name| name.to_str())
                .map(String::from);

            let Some(contract_addr) = contract_addr else {
                continue;
            };

            // Remove contract if not in config
            if !valid_tokens[&chain_name].contains_key(&contract_addr) {
                info!("Pruning contract directory: {}", contract_path.display());
                fs::remove_dir_all(&contract_path).await?;
                continue;
            }

            // Iterate through token directories
            let mut token_entries = fs::read_dir(&contract_path).await?;
            while let Some(token_entry) = token_entries.next_entry().await? {
                let token_path = token_entry.path();
                if !fs::metadata(&token_path).await?.is_dir() {
                    continue;
                }

                let token_id = token_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(String::from);

                let Some(token_id) = token_id else {
                    continue;
                };

                // Remove token directory if not in config for this contract
                if !valid_tokens[&chain_name][&contract_addr].contains(&token_id) {
                    info!("Pruning token directory: {}", token_path.display());
                    fs::remove_dir_all(&token_path).await?;
                }
            }
        }
    }

    Ok(())
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

    // Prune missing directories if the flag is set
    if args.prune_missing {
        info!("Pruning directories not in config...");
        prune_missing_directories(&output_path, &config).await?;
    }

    info!(
        "Backup complete in {:?}s. Files saved in {}",
        start.elapsed().as_secs(),
        output_path.display()
    );

    Ok(())
}
