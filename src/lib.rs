use alloy::providers::ProviderBuilder;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tezos_rpc::client::TezosRpc;
use tezos_rpc::http::default::HttpClient;
use tokio::fs;
use tracing::{info, warn};

use crate::chain::common::ContractWithToken;
use crate::chain::evm::EvmChainProcessor;
use crate::chain::process_nfts;
use crate::chain::tezos::TezosChainProcessor;

pub mod api;
pub mod chain;
pub mod content;
pub mod logging;
pub mod prune;
pub mod url;

#[derive(Debug, Deserialize, Clone)]
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
    pub exit_on_error: bool,
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
        let mut all_files = Vec::new();
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
            let contracts = ContractWithToken::parse_contracts(contracts);

            let files = if chain_name == "tezos" {
                let processor = Arc::new(TezosChainProcessor);
                let provider = Arc::new(TezosRpc::<HttpClient>::new(rpc_url.to_string()));
                process_nfts(
                    processor,
                    provider,
                    contracts,
                    &output_path,
                    chain_name,
                    cfg.exit_on_error,
                    |metadata| metadata.artifact_uri.as_deref(),
                )
                .await?
            } else {
                let processor = Arc::new(EvmChainProcessor);
                let provider = Arc::new(ProviderBuilder::new().on_http(rpc_url.parse().unwrap()));
                process_nfts(
                    processor,
                    provider,
                    contracts,
                    &output_path,
                    chain_name,
                    cfg.exit_on_error,
                    |_metadata| None,
                )
                .await?
            };
            all_files.extend(files);
        }

        if cfg.prune_missing {
            info!("Pruning directories not in config...");
            prune::prune_missing_directories(&output_path, token_config, &all_files).await?;
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
