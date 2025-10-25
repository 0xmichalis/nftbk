use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tracing::{info, warn, Instrument};

use crate::chain::common::ContractTokenId;
use crate::chain::evm::EvmChainProcessor;
use crate::chain::process_nfts;
use crate::chain::tezos::TezosChainProcessor;
use crate::types::{ArchiveOutcome, BackupConfig, IpfsOutcome, TokenPinMapping};

impl BackupConfig {
    /// Validates that the backup configuration has at least one storage option enabled
    pub fn validate(&self) -> Result<()> {
        if self.storage_config.output_path.is_none()
            && self.storage_config.ipfs_pinning_configs.is_empty()
        {
            return Err(anyhow::anyhow!(
                "At least one storage option must be enabled: either output_path or ipfs_pinning_configs"
            ));
        }
        Ok(())
    }

    /// Backup tokens from config
    /// Returns grouped results for archives and IPFS
    pub async fn backup(
        self,
        span: Option<tracing::Span>,
    ) -> Result<(ArchiveOutcome, IpfsOutcome)> {
        // Validate backup configuration
        self.validate()?;

        async fn backup_inner(cfg: BackupConfig) -> Result<(ArchiveOutcome, IpfsOutcome)> {
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
                    crate::prune::prune_redundant_files(out, token_config, &all_files).await?;
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
            Some(span) => backup_inner(self).instrument(span).await,
            None => backup_inner(self).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ChainConfig, ProcessManagementConfig, StorageConfig, TokenConfig};
    use std::collections::HashMap;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use tokio::time::timeout;

    #[test]
    fn test_validate_backup_config() {
        // Test with both storage options enabled
        let config = BackupConfig {
            chain_config: ChainConfig(HashMap::new()),
            token_config: TokenConfig {
                chains: HashMap::new(),
            },
            storage_config: StorageConfig {
                output_path: Some(std::path::PathBuf::from("/tmp")),
                prune_redundant: false,
                ipfs_pinning_configs: vec![],
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: None,
            },
            task_id: None,
        };
        assert!(config.validate().is_ok());

        // Test with only output_path enabled
        let config = BackupConfig {
            chain_config: ChainConfig(HashMap::new()),
            token_config: TokenConfig {
                chains: HashMap::new(),
            },
            storage_config: StorageConfig {
                output_path: Some(std::path::PathBuf::from("/tmp")),
                prune_redundant: false,
                ipfs_pinning_configs: vec![],
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: None,
            },
            task_id: None,
        };
        assert!(config.validate().is_ok());

        // Test with only IPFS pinning enabled
        let config = BackupConfig {
            chain_config: ChainConfig(HashMap::new()),
            token_config: TokenConfig {
                chains: HashMap::new(),
            },
            storage_config: StorageConfig {
                output_path: None,
                prune_redundant: false,
                ipfs_pinning_configs: vec![crate::ipfs::IpfsPinningConfig::Pinata {
                    base_url: "https://api.pinata.cloud".to_string(),
                    bearer_token_env: Some("PINATA_JWT".to_string()),
                }],
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: None,
            },
            task_id: None,
        };
        assert!(config.validate().is_ok());

        // Test with no storage options enabled
        let config = BackupConfig {
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
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn test_graceful_shutdown_library() {
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let config = BackupConfig {
            chain_config: ChainConfig(HashMap::new()),
            token_config: TokenConfig {
                chains: HashMap::new(),
            },
            storage_config: StorageConfig {
                output_path: Some(std::path::PathBuf::from("/tmp")),
                prune_redundant: false,
                ipfs_pinning_configs: vec![],
            },
            process_config: ProcessManagementConfig {
                exit_on_error: false,
                shutdown_flag: Some(shutdown_flag.clone()),
            },
            task_id: None,
        };

        // Start the backup in a separate task
        let backup_handle = tokio::spawn(async move { config.backup(None).await });

        // Give it a moment to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Signal shutdown
        shutdown_flag.store(true, Ordering::Relaxed);

        // Wait for the backup to complete (should be quick since no tokens to process)
        let result = timeout(Duration::from_secs(5), backup_handle).await;
        assert!(result.is_ok(), "Backup should complete within timeout");
    }
}
