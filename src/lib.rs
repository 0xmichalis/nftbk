use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use tokio::fs;
use tracing::{info, warn};

pub mod chain;
pub mod content;
pub mod logging;
pub mod prune;
pub mod url;

#[derive(Debug, Deserialize)]
pub struct ChainConfig(pub HashMap<String, String>);

#[derive(Debug, Deserialize)]
pub struct TokenConfig {
    #[serde(flatten)]
    pub chains: HashMap<String, Vec<String>>,
}

pub struct BackupConfig {
    pub chain_config: ChainConfig,
    pub token_config: TokenConfig,
    pub output_path: Option<PathBuf>,
    pub prune_missing: bool,
}

pub mod backup {
    use super::*;
    pub async fn backup_from_config(cfg: BackupConfig) -> Result<()> {
        let base_path = cfg.output_path.unwrap_or_else(|| PathBuf::from("."));
        let output_path = base_path.join("nft_backup");
        fs::create_dir_all(&output_path).await?;
        let chain_config = &cfg.chain_config.0;
        let token_config = &cfg.token_config;
        let start = Instant::now();
        for (chain_name, contracts) in &token_config.chains {
            if contracts.is_empty() {
                warn!("No contracts configured for chain {}", chain_name);
                continue;
            }
            info!(
                "Processing {} contracts on {} ...",
                contracts.len(),
                chain_name
            );
            let rpc_url = chain_config
                .get(chain_name)
                .context(format!("No RPC URL configured for chain {}", chain_name))?;
            if chain_name != "tezos" {
                chain::evm::process_nfts(chain_name, rpc_url, contracts.clone(), &output_path)
                    .await?;
            } else {
                chain::tezos::process_nfts(rpc_url, contracts.clone(), &output_path).await?;
            }
        }
        if cfg.prune_missing {
            info!("Pruning directories not in config...");
            prune::prune_missing_directories(&output_path, token_config).await?;
        }
        info!(
            "Backup complete in {:?}s. Files saved in {}",
            start.elapsed().as_secs(),
            output_path.display()
        );
        Ok(())
    }
    pub use super::{BackupConfig, ChainConfig, TokenConfig};
}
