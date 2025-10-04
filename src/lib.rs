use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tracing::{info, warn, Instrument};

use crate::chain::common::ContractTokenId;
use crate::chain::evm::EvmChainProcessor;
use crate::chain::process_nfts;
use crate::chain::tezos::TezosChainProcessor;

pub mod chain;
pub mod content;
pub mod envvar;
pub mod ipfs;
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
                        "Environment variable '{var_name}' referenced in '{value}' for chain '{key}' is not set",
                    )
                })?;
                resolved = resolved.replace(&format!("${{{var_name}}}"), &env_val);
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

/// Configuration for process management with shutdown and error handling options
#[derive(Clone)]
pub struct ProcessManagementConfig {
    pub exit_on_error: bool,
    pub shutdown_flag: Option<Arc<AtomicBool>>,
}

#[derive(Clone)]
pub struct StorageConfig {
    /// If Some, store content locally under this path
    pub output_path: Option<PathBuf>,
    pub prune_redundant: bool,
    /// Enable IPFS pinning mode: IPFS content will be pinned to the IPFS network
    pub enable_ipfs_pinning: bool,
    pub ipfs_pin_base_url: Option<String>,
    pub ipfs_pin_token: Option<String>,
}

pub struct BackupConfig {
    pub chain_config: ChainConfig,
    pub token_config: TokenConfig,
    pub storage_config: StorageConfig,
    pub process_config: ProcessManagementConfig,
}

pub mod backup {
    use super::*;

    /// Validates that the backup configuration has at least one storage option enabled
    pub fn validate_backup_config(cfg: &BackupConfig) -> Result<()> {
        if cfg.storage_config.output_path.is_none() && !cfg.storage_config.enable_ipfs_pinning {
            return Err(anyhow::anyhow!(
                "At least one storage option must be enabled: either output_path or enable_ipfs_pinning"
            ));
        }
        Ok(())
    }

    /// Backup tokens from config
    /// Returns all files saved, all pins created, and all errors encountered
    pub async fn backup_from_config(
        cfg: BackupConfig,
        span: Option<tracing::Span>,
    ) -> Result<(Vec<PathBuf>, Vec<String>, Vec<String>)> {
        // Validate backup configuration
        validate_backup_config(&cfg)?;

        async fn inner(cfg: BackupConfig) -> Result<(Vec<PathBuf>, Vec<String>, Vec<String>)> {
            info!(
                "The following user agent will be used to fetch content: {}",
                USER_AGENT
            );
            if let Some(ref out) = cfg.storage_config.output_path {
                fs::create_dir_all(out).await?;
            }

            let chain_config = &cfg.chain_config.0;
            let token_config = &cfg.token_config;

            let start = Instant::now();
            let mut all_files = Vec::new();
            let mut all_errors = Vec::new();
            let mut all_pins = Vec::new();
            let mut nft_count = 0;

            for (chain_name, tokens) in &token_config.chains {
                if tokens.is_empty() {
                    warn!("No tokens configured for chain {}", chain_name);
                    continue;
                }
                info!("Processing {} tokens on {} ...", tokens.len(), chain_name);
                let rpc_url = chain_config
                    .get(chain_name)
                    .context(format!("No RPC URL configured for chain {chain_name}"))?;
                let tokens = ContractTokenId::parse_tokens(tokens, chain_name);
                nft_count += tokens.len();

                let (files, pins, errors) = if chain_name == "tezos" {
                    let processor = Arc::new(TezosChainProcessor::new(
                        rpc_url,
                        cfg.storage_config.clone(),
                    )?);
                    let process_config = cfg.process_config.clone();
                    process_nfts(processor, tokens, process_config, |metadata| {
                        metadata.artifact_uri.as_deref()
                    })
                    .await?
                } else {
                    let processor =
                        Arc::new(EvmChainProcessor::new(rpc_url, cfg.storage_config.clone())?);
                    let process_config = cfg.process_config.clone();
                    process_nfts(processor, tokens, process_config, |_metadata| None).await?
                };
                all_files.extend(files);
                all_errors.extend(errors);
                all_pins.extend(pins);
            }

            if cfg.storage_config.prune_redundant {
                if let Some(ref out) = cfg.storage_config.output_path {
                    info!("Pruning redundant files...");
                    prune::prune_redundant_files(out, token_config, &all_files).await?;
                }
            }

            if let Some(ref out) = cfg.storage_config.output_path {
                info!(
                    "Backup complete in {:?}s. {} NFTs ({} files) saved in {}.",
                    start.elapsed().as_secs(),
                    nft_count,
                    all_files.len(),
                    out.display(),
                );
            } else {
                info!(
                    "Pinning complete in {:?}s. {} NFTs ({} CIDs pinned).",
                    start.elapsed().as_secs(),
                    nft_count,
                    all_pins.len(),
                );
            }

            Ok((all_files, all_pins, all_errors))
        }

        match span {
            Some(span) => inner(cfg).instrument(span).await,
            None => inner(cfg).await,
        }
    }
    pub use super::{BackupConfig, ChainConfig, TokenConfig};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn test_validate_backup_config() {
        use crate::backup::validate_backup_config;
        use std::path::PathBuf;

        // Test case 1: Both output_path and enable_ipfs_pinning are enabled - should pass
        let cfg1 = BackupConfig {
            chain_config: ChainConfig(HashMap::new()),
            token_config: TokenConfig {
                chains: HashMap::new(),
            },
            storage_config: StorageConfig {
                output_path: Some(PathBuf::from("/tmp/test")),
                prune_redundant: false,
                enable_ipfs_pinning: true,
                ipfs_pin_base_url: Some("http://example.com".to_string()),
                ipfs_pin_token: None,
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: None,
            },
        };
        assert!(validate_backup_config(&cfg1).is_ok());

        // Test case 2: Only output_path is enabled - should pass
        let cfg2 = BackupConfig {
            chain_config: ChainConfig(HashMap::new()),
            token_config: TokenConfig {
                chains: HashMap::new(),
            },
            storage_config: StorageConfig {
                output_path: Some(PathBuf::from("/tmp/test")),
                prune_redundant: false,
                enable_ipfs_pinning: false,
                ipfs_pin_base_url: None,
                ipfs_pin_token: None,
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: None,
            },
        };
        assert!(validate_backup_config(&cfg2).is_ok());

        // Test case 3: Only enable_ipfs_pinning is enabled - should pass
        let cfg3 = BackupConfig {
            chain_config: ChainConfig(HashMap::new()),
            token_config: TokenConfig {
                chains: HashMap::new(),
            },
            storage_config: StorageConfig {
                output_path: None,
                prune_redundant: false,
                enable_ipfs_pinning: true,
                ipfs_pin_base_url: Some("http://example.com".to_string()),
                ipfs_pin_token: None,
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: None,
            },
        };
        assert!(validate_backup_config(&cfg3).is_ok());

        // Test case 4: Neither output_path nor enable_ipfs_pinning are enabled - should fail
        let cfg4 = BackupConfig {
            chain_config: ChainConfig(HashMap::new()),
            token_config: TokenConfig {
                chains: HashMap::new(),
            },
            storage_config: StorageConfig {
                output_path: None,
                prune_redundant: false,
                enable_ipfs_pinning: false,
                ipfs_pin_base_url: None,
                ipfs_pin_token: None,
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: None,
            },
        };
        assert!(validate_backup_config(&cfg4).is_err());
    }

    #[tokio::test]
    async fn test_graceful_shutdown_library() {
        // Create a simple backup config for testing
        let mut chain_config = HashMap::new();
        chain_config.insert(
            "ethereum".to_string(),
            "https://ethereum.publicnode.com".to_string(),
        );

        let mut chains = HashMap::new();
        let contracts = vec![]; // Empty contracts for quick test
        chains.insert("ethereum".to_string(), contracts);

        // Create a shutdown flag
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        let cfg = BackupConfig {
            chain_config: ChainConfig(chain_config),
            token_config: TokenConfig { chains },
            storage_config: StorageConfig {
                output_path: Some("/tmp/test_backup".into()),
                prune_redundant: false,
                enable_ipfs_pinning: false,
                ipfs_pin_base_url: None,
                ipfs_pin_token: None,
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: Some(shutdown_flag.clone()),
            },
        };

        // Start the backup
        let backup_handle =
            tokio::spawn(async move { backup::backup_from_config(cfg, None).await });

        // Set shutdown flag immediately
        shutdown_flag.store(true, Ordering::Relaxed);

        // The backup should complete quickly due to shutdown
        let result = timeout(Duration::from_secs(5), backup_handle).await;

        match result {
            Ok(backup_result) => {
                match backup_result.unwrap() {
                    Ok(_) => println!("Backup completed normally"),
                    Err(e) => {
                        // Should get a shutdown error
                        assert!(
                            e.to_string().contains("shutdown")
                                || e.to_string().contains("interrupted")
                        );
                        println!(
                            "Backup was interrupted by shutdown signal as expected: {}",
                            e
                        );
                    }
                }
            }
            Err(_) => panic!("Test timed out - shutdown signal not working properly"),
        }
    }
}
