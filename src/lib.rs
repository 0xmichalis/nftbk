use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use tokio::fs;
use tracing::{info, warn, Instrument};

use crate::chain::common::ContractTokenId;
use crate::chain::evm::EvmChainProcessor;
use crate::chain::process_nfts;
use crate::chain::tezos::TezosChainProcessor;

pub mod chain;
pub mod cli;
pub mod consts;
pub mod content;
pub mod envvar;
pub mod httpclient;
pub mod ipfs;
pub mod logging;
pub mod prune;
pub mod server;
pub mod types;
pub mod url;

// Re-export types and constants for convenience
pub use consts::*;
pub use types::*;

pub mod backup {
    use super::*;

    /// Validates that the backup configuration has at least one storage option enabled
    pub fn validate_backup_config(cfg: &BackupConfig) -> Result<()> {
        if cfg.storage_config.output_path.is_none()
            && cfg.storage_config.ipfs_pinning_configs.is_empty()
        {
            return Err(anyhow::anyhow!(
                "At least one storage option must be enabled: either output_path or ipfs_pinning_configs"
            ));
        }
        Ok(())
    }

    /// Backup tokens from config
    /// Returns grouped results for archives and IPFS
    pub async fn backup_from_config(
        cfg: BackupConfig,
        span: Option<tracing::Span>,
    ) -> Result<(ArchiveOutcome, IpfsOutcome)> {
        // Validate backup configuration
        validate_backup_config(&cfg)?;

        async fn inner(cfg: BackupConfig) -> Result<(ArchiveOutcome, IpfsOutcome)> {
            info!(
                "Protection requested: download to disk={}, pin to IPFS={}",
                cfg.storage_config.output_path.is_some(),
                !cfg.storage_config.ipfs_pinning_configs.is_empty(),
            );

            if let Some(ref out) = cfg.storage_config.output_path {
                fs::create_dir_all(out).await?;
            }

            let chain_config = &cfg.chain_config.0;
            let token_config = &cfg.token_config;

            let start = Instant::now();
            let mut all_files = Vec::new();
            let mut all_token_pin_mappings: Vec<TokenPinMapping> = Vec::new();
            let mut all_archive_errors = Vec::new();
            let mut all_ipfs_errors = Vec::new();
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

                let (archive_out, ipfs_out) = if chain_name == "tezos" {
                    let processor = Arc::new(TezosChainProcessor::new(
                        rpc_url,
                        cfg.storage_config.clone(),
                    )?);
                    let process_config = cfg.process_config.clone();
                    process_nfts(
                        processor,
                        tokens,
                        process_config,
                        |metadata| metadata.artifact_uri.as_deref(),
                        cfg.task_id.clone(),
                    )
                    .await?
                } else {
                    let processor = Arc::new(
                        EvmChainProcessor::new(rpc_url, cfg.storage_config.clone()).await?,
                    );
                    let process_config = cfg.process_config.clone();
                    process_nfts(
                        processor,
                        tokens,
                        process_config,
                        |_metadata| None,
                        cfg.task_id.clone(),
                    )
                    .await?
                };
                all_files.extend(archive_out.files);
                all_archive_errors.extend(archive_out.errors);
                all_ipfs_errors.extend(ipfs_out.errors);
                all_token_pin_mappings.extend(ipfs_out.pin_requests);
            }

            if cfg.storage_config.prune_redundant {
                if let Some(ref out) = cfg.storage_config.output_path {
                    info!("Pruning redundant files...");
                    prune::prune_redundant_files(out, token_config, &all_files).await?;
                }
            }

            info!(
                "Protection request complete in {:?}s. {} NFTs are protected.",
                start.elapsed().as_secs(),
                nft_count,
            );
            if let Some(ref out) = cfg.storage_config.output_path {
                info!("{} files saved in {}.", all_files.len(), out.display(),);
            }
            if !cfg.storage_config.ipfs_pinning_configs.is_empty() {
                let total_pins: usize = all_token_pin_mappings
                    .iter()
                    .map(|mapping| mapping.pin_responses.len())
                    .sum();
                info!(
                    "{} CID pins were requested across {} provider(s) for {} tokens.",
                    total_pins,
                    cfg.storage_config.ipfs_pinning_configs.len(),
                    all_token_pin_mappings.len()
                );
            }

            Ok((
                ArchiveOutcome {
                    files: all_files,
                    errors: all_archive_errors,
                },
                IpfsOutcome {
                    pin_requests: all_token_pin_mappings,
                    errors: all_ipfs_errors,
                },
            ))
        }

        match span {
            Some(span) => inner(cfg).instrument(span).await,
            None => inner(cfg).await,
        }
    }
    pub use super::types::{BackupConfig, ChainConfig, TokenConfig};
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicBool;
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
                ipfs_pinning_configs: vec![ipfs::IpfsPinningConfig::IpfsPinningService {
                    base_url: "http://example.com".to_string(),
                    bearer_token_env: None,
                }],
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: None,
            },
            task_id: None,
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
                ipfs_pinning_configs: vec![],
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: None,
            },
            task_id: None,
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
                ipfs_pinning_configs: vec![ipfs::IpfsPinningConfig::IpfsPinningService {
                    base_url: "http://example.com".to_string(),
                    bearer_token_env: None,
                }],
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: None,
            },
            task_id: None,
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
                ipfs_pinning_configs: vec![],
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: None,
            },
            task_id: None,
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
                ipfs_pinning_configs: vec![],
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: Some(shutdown_flag.clone()),
            },
            task_id: None,
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
                        println!("Backup was interrupted by shutdown signal as expected: {e}");
                    }
                }
            }
            Err(_) => panic!("Test timed out - shutdown signal not working properly"),
        }
    }
}
