use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tokio::fs;
use tracing::info;

use crate::Config;

/// Prune directories in the backup folder that are not part of the config
pub async fn prune_missing_directories(output_path: &Path, config: &Config) -> Result<()> {
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
