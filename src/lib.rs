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
pub mod envvar;
pub mod hashing;
pub mod logging;
pub mod prune;
pub mod server;
pub mod url;

#[derive(Debug, Deserialize, Clone)]
pub struct ChainConfig(pub HashMap<String, String>);

impl ChainConfig {
    /// Resolves environment variable references in the form ${VAR_NAME} in all values.
    /// Returns an error if any referenced environment variable is not set.
    pub fn resolve_env_vars(&mut self) -> Result<()> {
        let re = regex::Regex::new(r"\$\{([A-Z0-9_]+)\}").unwrap();
        for (key, value) in self.0.iter_mut() {
            let mut resolved = value.clone();
            for caps in re.captures_iter(value) {
                let var_name = &caps[1];
                let env_val = std::env::var(var_name).with_context(|| {
                    format!(
                        "Environment variable '{}' referenced in '{}' for chain '{}' is not set",
                        var_name, value, key
                    )
                })?;
                resolved = resolved.replace(&format!("${{{}}}", var_name), &env_val);
            }
            *value = resolved;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct TokenConfig {
    #[serde(flatten)]
    pub chains: HashMap<String, Vec<String>>,
}

pub struct BackupConfig {
    pub chain_config: ChainConfig,
    pub token_config: TokenConfig,
    pub output_path: Option<PathBuf>,
    pub prune_redundant: bool,
    pub exit_on_error: bool,
}

pub mod backup {
    use super::*;
    pub async fn backup_from_config(cfg: BackupConfig) -> Result<Vec<PathBuf>> {
        let output_path = cfg.output_path.unwrap();
        fs::create_dir_all(&output_path).await?;

        let chain_config = &cfg.chain_config.0;
        let token_config = &cfg.token_config;

        let start = Instant::now();
        let mut all_files = Vec::new();
        let mut nft_count = 0;
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
            nft_count += contracts.len();

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

        if cfg.prune_redundant {
            info!("Pruning redundant files...");
            prune::prune_redundant_files(&output_path, token_config, &all_files).await?;
        }

        info!(
            "Backup complete in {:?}s. {} NFTs ({} files) saved in {}.",
            start.elapsed().as_secs(),
            nft_count,
            all_files.len(),
            output_path.display(),
        );

        Ok(all_files)
    }
    pub use super::{BackupConfig, ChainConfig, TokenConfig};
}
