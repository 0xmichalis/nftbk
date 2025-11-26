use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context};
use tracing::{error, info, warn};

use crate::server::api::BackupRequest;
use crate::server::x402::PricingConfig;
use crate::server::{AppState, QuoteTask};
use crate::{BackupConfig, ProcessManagementConfig, StorageConfig, TokenConfig};

pub async fn run_quote_task(state: AppState, task: QuoteTask) {
    let quote_id = task.quote_id.clone();
    let task_id = task.task_id.clone();

    let pricing = match &state.x402_config {
        Some(cfg) => &cfg.pricing,
        None => {
            warn!(
                quote_id = %quote_id,
                "x402 configuration not available; removing quote from cache"
            );
            remove_quote_cache_entry(&state, &quote_id).await;
            return;
        }
    };

    if pricing.is_empty() {
        warn!(
            quote_id = %quote_id,
            "Quote pricing configuration is missing; removing quote from cache"
        );
        remove_quote_cache_entry(&state, &quote_id).await;
        return;
    }

    let total_size_bytes = match calculate_total_size_bytes(&state, &task).await {
        Ok(size) => size,
        Err(err) => {
            error!(
                quote_id = %quote_id,
                error = %err,
                "Failed to calculate quote size"
            );
            remove_quote_cache_entry(&state, &quote_id).await;
            return;
        }
    };

    let price_wei = match calculate_price_in_wei(pricing, &task.request, total_size_bytes) {
        Ok(value) => value,
        Err(err) => {
            error!(
                quote_id = %quote_id,
                error = %err,
                "Failed to calculate quote price"
            );
            remove_quote_cache_entry(&state, &quote_id).await;
            return;
        }
    };

    {
        let mut cache = state.quote_cache.lock().await;
        if let Some(entry) = cache.get_mut(&quote_id) {
            if entry.task_id != task_id {
                warn!(
                    quote_id = %quote_id,
                    existing_task = %entry.task_id,
                    new_task = %task_id,
                    "Quote task_id mismatch; ignoring computed price"
                );
                return;
            }
            entry.price = Some(price_wei);
            entry.estimated_size_bytes = Some(total_size_bytes);
        } else {
            warn!(
                quote_id = %quote_id,
                "Quote no longer present in cache; dropping computed price"
            );
            return;
        }
    }

    info!(
        quote_id = %quote_id,
        bytes = total_size_bytes,
        price_wei = price_wei,
        "Quote completed"
    );
}

async fn calculate_total_size_bytes(state: &AppState, task: &QuoteTask) -> anyhow::Result<u64> {
    let backup_cfg = build_backup_config(state, task)?;
    let span = tracing::info_span!(
        "quote_size",
        quote_id = %task.quote_id,
        task_id = %task.task_id
    );
    backup_cfg
        .size(Some(span))
        .await
        .with_context(|| "Failed to estimate backup size")
}

fn build_backup_config(state: &AppState, task: &QuoteTask) -> anyhow::Result<BackupConfig> {
    let mut token_map = HashMap::new();
    for entry in &task.request.tokens {
        token_map.insert(entry.chain.clone(), entry.tokens.clone());
    }

    if token_map.is_empty() {
        return Err(anyhow!("Quote request contained no tokens"));
    }

    let output_path = task.request.create_archive.then(|| {
        let mut base = PathBuf::from(state.base_dir.as_ref().as_str());
        base.push(format!("nftbk-{}", task.task_id));
        base
    });

    let storage_config = StorageConfig {
        prune_redundant: false,
        output_path,
        ipfs_pinning_configs: if task.request.pin_on_ipfs {
            state.ipfs_pinning_configs.clone()
        } else {
            Vec::new()
        },
    };

    Ok(BackupConfig {
        chain_config: (*state.chain_config).clone(),
        token_config: TokenConfig { chains: token_map },
        storage_config,
        process_config: ProcessManagementConfig {
            exit_on_error: true,
            shutdown_flag: Some(state.shutdown_flag.clone()),
        },
        task_id: Some(task.task_id.clone()),
    })
}

fn calculate_price_in_wei(
    pricing: &PricingConfig,
    request: &BackupRequest,
    total_bytes: u64,
) -> anyhow::Result<u64> {
    let gb = bytes_to_gigabytes(total_bytes);
    let mut total = 0u128;

    if request.create_archive {
        let price = pricing
            .archive_price_per_gb
            .ok_or_else(|| anyhow!("archive_price_per_gb is not configured"))?;
        total = total
            .checked_add(price as u128 * gb as u128)
            .ok_or_else(|| anyhow!("archive price overflow"))?;
    }

    if request.pin_on_ipfs {
        let price = pricing
            .pin_price_per_gb
            .ok_or_else(|| anyhow!("pin_price_per_gb is not configured"))?;
        total = total
            .checked_add(price as u128 * gb as u128)
            .ok_or_else(|| anyhow!("pin price overflow"))?;
    }

    if total > u64::MAX as u128 {
        return Err(anyhow!("Total price exceeds supported range"));
    }

    Ok(total as u64)
}

fn bytes_to_gigabytes(bytes: u64) -> u64 {
    const GIGABYTE: u64 = 1024 * 1024 * 1024;
    bytes.div_ceil(GIGABYTE)
}

async fn remove_quote_cache_entry(state: &AppState, quote_id: &str) {
    let mut cache = state.quote_cache.lock().await;
    cache.pop(quote_id);
}

#[cfg(test)]
mod test_utils {
    use super::*;
    use crate::ipfs::IpfsPinningConfig;
    use crate::server::api::Tokens;
    use crate::server::database::Db;
    use sqlx::postgres::PgPoolOptions;
    use std::collections::HashMap;
    use std::num::NonZeroUsize;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    pub fn sample_backup_request(pin_on_ipfs: bool) -> BackupRequest {
        BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs,
            create_archive: true,
        }
    }

    pub fn sample_quote_task(pin_on_ipfs: bool) -> QuoteTask {
        QuoteTask {
            quote_id: "quote".to_string(),
            task_id: "task".to_string(),
            request: sample_backup_request(pin_on_ipfs),
            requestor: None,
        }
    }

    pub fn build_state_with_chains(
        chains: HashMap<String, String>,
        ipfs_configs: Vec<IpfsPinningConfig>,
    ) -> AppState {
        let chain_config = crate::ChainConfig(chains);
        let (tx, _rx) = mpsc::channel(1);
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@localhost/db")
            .unwrap();
        let db = Arc::new(Db { pool });
        AppState {
            chain_config: Arc::new(chain_config),
            base_dir: Arc::new("/tmp".to_string()),
            unsafe_skip_checksum_check: false,
            auth_token: None,
            pruner_retention_days: 7,
            download_tokens: Arc::new(Mutex::new(HashMap::new())),
            quote_cache: Arc::new(Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(16).unwrap(),
            ))),
            backup_task_sender: tx,
            db,
            shutdown_flag: Arc::new(AtomicBool::new(false)),
            ipfs_pinning_configs: ipfs_configs,
            ipfs_pinning_instances: Arc::new(Vec::new()),
            x402_config: None,
        }
    }
}

#[cfg(test)]
mod bytes_to_gigabytes_tests {
    use super::*;

    #[test]
    fn rounds_up() {
        assert_eq!(bytes_to_gigabytes(0), 0);
        assert_eq!(bytes_to_gigabytes(1), 1);
        assert_eq!(bytes_to_gigabytes(1024 * 1024 * 1024 - 1), 1);
        assert_eq!(bytes_to_gigabytes(1024 * 1024 * 1024), 1);
        assert_eq!(bytes_to_gigabytes(1024 * 1024 * 1024 + 1), 2);
    }
}

#[cfg(test)]
mod calculate_price_in_wei_tests {
    use super::*;

    #[test]
    fn sums_archive_and_pin_prices() {
        let pricing = PricingConfig {
            archive_price_per_gb: Some(1_000),
            pin_price_per_gb: Some(500),
        };
        let request = BackupRequest {
            tokens: vec![],
            pin_on_ipfs: true,
            create_archive: true,
        };
        let total = calculate_price_in_wei(&pricing, &request, 2048).unwrap();
        assert_eq!(total, 1_500);
    }

    #[test]
    fn errors_when_archive_price_missing() {
        let pricing = PricingConfig {
            archive_price_per_gb: None,
            pin_price_per_gb: Some(500),
        };
        let request = BackupRequest {
            tokens: vec![],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let err = calculate_price_in_wei(&pricing, &request, 1024).unwrap_err();
        assert!(err
            .to_string()
            .contains("archive_price_per_gb is not configured"));
    }

    #[test]
    fn errors_on_overflow() {
        let pricing = PricingConfig {
            archive_price_per_gb: Some(u64::MAX),
            pin_price_per_gb: None,
        };
        let request = BackupRequest {
            tokens: vec![],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let two_gib = 2 * 1024 * 1024 * 1024;
        let err = calculate_price_in_wei(&pricing, &request, two_gib).unwrap_err();
        assert!(err
            .to_string()
            .contains("Total price exceeds supported range"));
    }
}

#[cfg(test)]
mod build_backup_config_tests {
    use super::*;
    use crate::ipfs::IpfsPinningConfig;
    use std::collections::HashMap;

    fn sample_chain_map() -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("ethereum".to_string(), "rpc://dummy".to_string());
        map
    }

    #[tokio::test]
    async fn copies_ipfs_configs_when_pin_enabled() {
        let ipfs_config = IpfsPinningConfig::Pinata {
            base_url: "https://pinata.test".to_string(),
            bearer_token_env: Some("PINATA_TOKEN".to_string()),
        };
        let state =
            super::test_utils::build_state_with_chains(sample_chain_map(), vec![ipfs_config]);
        let task = super::test_utils::sample_quote_task(true);
        let cfg = build_backup_config(&state, &task).unwrap();
        assert_eq!(cfg.storage_config.ipfs_pinning_configs.len(), 1);
        let expected = PathBuf::from("/tmp").join("nftbk-task");
        assert_eq!(
            cfg.storage_config.output_path.as_deref(),
            Some(expected.as_path())
        );
    }

    #[tokio::test]
    async fn omits_output_path_when_archive_disabled() {
        let state = super::test_utils::build_state_with_chains(sample_chain_map(), Vec::new());
        let mut task = super::test_utils::sample_quote_task(false);
        task.request.create_archive = false;
        let cfg = build_backup_config(&state, &task).unwrap();
        assert!(cfg.storage_config.output_path.is_none());
    }

    #[tokio::test]
    async fn errors_when_no_tokens_present() {
        let state = super::test_utils::build_state_with_chains(sample_chain_map(), Vec::new());
        let mut task = super::test_utils::sample_quote_task(false);
        task.request.tokens.clear();
        let err = build_backup_config(&state, &task).err().unwrap();
        assert!(err
            .to_string()
            .contains("Quote request contained no tokens"));
    }
}

#[cfg(test)]
mod calculate_total_size_bytes_tests {
    use super::*;
    use std::collections::HashMap;

    #[tokio::test]
    async fn errors_when_chain_missing() {
        let state = super::test_utils::build_state_with_chains(HashMap::new(), Vec::new());
        let task = super::test_utils::sample_quote_task(false);
        let err = calculate_total_size_bytes(&state, &task).await.unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("Failed to estimate backup size"),
            "unexpected error: {message}"
        );
    }
}

#[cfg(test)]
mod remove_quote_cache_entry_tests {
    use super::*;
    use crate::server::Quote;
    use std::collections::HashMap;

    #[tokio::test]
    async fn removes_cached_entry() {
        let state = super::test_utils::build_state_with_chains(HashMap::new(), Vec::new());
        {
            let mut cache = state.quote_cache.lock().await;
            cache.put(
                "quote-1".to_string(),
                Quote {
                    price: Some(42),
                    estimated_size_bytes: Some(10),
                    task_id: "task-1".to_string(),
                },
            );
        }
        remove_quote_cache_entry(&state, "quote-1").await;
        let mut cache = state.quote_cache.lock().await;
        assert!(cache.get("quote-1").is_none());
    }
}
