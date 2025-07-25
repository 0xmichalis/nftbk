use alloy::providers::ProviderBuilder;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tezos_rpc::client::TezosRpc;
use tezos_rpc::http::default::HttpClient;
use tokio::fs;
use tokio::sync::oneshot;
use tracing::{info, warn, Instrument};

use crate::chain::common::ContractWithToken;
use crate::chain::evm::EvmChainProcessor;
use crate::chain::process_nfts;
use crate::chain::tezos::TezosChainProcessor;

pub mod chain;
pub mod content;
pub mod envvar;
pub mod logging;
pub mod prune;
pub mod server;
pub mod url;

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

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
    pub async fn backup_from_config(
        cfg: BackupConfig,
        span: Option<tracing::Span>,
    ) -> Result<(Vec<PathBuf>, Vec<String>)> {
        backup_from_config_with_shutdown(cfg, span, None).await
    }

    pub async fn backup_from_config_with_shutdown(
        cfg: BackupConfig,
        span: Option<tracing::Span>,
        shutdown_rx: Option<oneshot::Receiver<()>>,
    ) -> Result<(Vec<PathBuf>, Vec<String>)> {
        async fn inner(cfg: BackupConfig, shutdown_flag: Arc<AtomicBool>) -> Result<(Vec<PathBuf>, Vec<String>)> {
            info!(
                "The following user agent will be used to fetch content: {}",
                USER_AGENT
            );
            let output_path = cfg.output_path.unwrap();
            fs::create_dir_all(&output_path).await?;

            let chain_config = &cfg.chain_config.0;
            let token_config = &cfg.token_config;

            let start = Instant::now();
            let mut all_files = Vec::new();
            let mut all_errors = Vec::new();
            let mut nft_count = 0;
            for (chain_name, contracts) in &token_config.chains {
                // Check for shutdown signal at the beginning of each chain processing
                if shutdown_flag.load(Ordering::Relaxed) {
                    warn!("Received shutdown signal, stopping backup");
                    return Err(anyhow::anyhow!("Backup interrupted by shutdown signal"));
                }

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

                let (files, errors) = if chain_name == "tezos" {
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
                        shutdown_flag.clone(),
                    )
                    .await?
                } else {
                    let processor = Arc::new(EvmChainProcessor);
                    let provider =
                        Arc::new(ProviderBuilder::new().on_http(rpc_url.parse().unwrap()));
                    process_nfts(
                        processor,
                        provider,
                        contracts,
                        &output_path,
                        chain_name,
                        cfg.exit_on_error,
                        |_metadata| None,
                        shutdown_flag.clone(),
                    )
                    .await?
                };
                all_files.extend(files);
                all_errors.extend(errors);
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

            Ok((all_files, all_errors))
        }
        
        // Create a shutdown flag and monitor the receiver if provided
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        if let Some(mut shutdown_rx) = shutdown_rx {
            let flag = shutdown_flag.clone();
            tokio::spawn(async move {
                let _ = shutdown_rx.await;
                flag.store(true, Ordering::Relaxed);
            });
        }

        match span {
            Some(span) => inner(cfg, shutdown_flag).instrument(span).await,
            None => inner(cfg, shutdown_flag).await,
        }
    }
    pub use super::{BackupConfig, ChainConfig, TokenConfig};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_graceful_shutdown_library() {
        // Create a simple backup config for testing
        let mut chain_config = HashMap::new();
        chain_config.insert("ethereum".to_string(), "https://ethereum.publicnode.com".to_string());
        
        let mut chains = HashMap::new();
        let contracts = vec![]; // Empty contracts for quick test
        chains.insert("ethereum".to_string(), contracts);

        let cfg = BackupConfig {
            chain_config: ChainConfig(chain_config),
            token_config: TokenConfig { chains },
            output_path: Some("/tmp/test_backup".into()),
            prune_redundant: false,
            exit_on_error: false,
        };

        // Create a shutdown channel
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

        // Start the backup with shutdown support
        let backup_handle = tokio::spawn(async move {
            backup::backup_from_config_with_shutdown(cfg, None, Some(shutdown_rx)).await
        });

        // Send shutdown signal immediately
        let _ = shutdown_tx.send(());

        // The backup should complete quickly due to shutdown
        let result = timeout(Duration::from_secs(5), backup_handle).await;
        
        match result {
            Ok(backup_result) => {
                match backup_result.unwrap() {
                    Ok(_) => println!("Backup completed normally"),
                    Err(e) => {
                        // Should get a shutdown error
                        assert!(e.to_string().contains("shutdown") || e.to_string().contains("interrupted"));
                        println!("Backup was interrupted by shutdown signal as expected: {}", e);
                    }
                }
            }
            Err(_) => panic!("Test timed out - shutdown signal not working properly"),
        }
    }
}
