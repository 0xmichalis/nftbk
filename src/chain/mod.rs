use anyhow::anyhow;
use async_trait::async_trait;
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::Ordering;
use tracing::{debug, error, warn};

use crate::content::extra::fetch_and_save_extra_content;
use crate::content::{fetch_and_save_content, Options};
pub use common::ContractTokenInfo;

pub mod common;
pub mod evm;
pub mod tezos;

/// Check for shutdown signal and return error if shutdown is requested
fn check_shutdown_signal(config: &crate::ProcessManagementConfig) -> anyhow::Result<()> {
    if let Some(ref shutdown_flag) = config.shutdown_flag {
        if shutdown_flag.load(Ordering::Relaxed) {
            warn!("Received shutdown signal, stopping NFT processing");
            return Err(anyhow::anyhow!(
                "NFT processing interrupted by shutdown signal"
            ));
        }
    }
    Ok(())
}

/// Trait for NFT chain processors to enable shared logic for fetching metadata and collecting URLs.
#[async_trait]
pub trait NFTChainProcessor {
    type Metadata;
    type ContractWithToken: ContractTokenInfo + Send + Sync;
    type RpcClient: Send + Sync;

    /// Build the chain-specific RPC client from the given URL.
    fn build_rpc_client(&self, rpc_url: &str) -> anyhow::Result<Self::RpcClient>;

    /// Fetch the metadata JSON for a given contract/token.
    async fn fetch_metadata(
        &self,
        token_uri: &str,
        contract: &Self::ContractWithToken,
        output_path: &std::path::Path,
        chain_name: &str,
    ) -> anyhow::Result<(Self::Metadata, std::path::PathBuf)>;

    /// Collect all URLs to download from the metadata.
    fn collect_urls(metadata: &Self::Metadata) -> Vec<(String, Options)>;

    /// Get the token URI for a contract using the chain's RPC client.
    async fn get_uri(
        &self,
        rpc: &Self::RpcClient,
        contract: &Self::ContractWithToken,
        chain_name: &str,
    ) -> anyhow::Result<String>;
}

pub async fn process_nfts<C, FExtraUri>(
    processor: std::sync::Arc<C>,
    rpc_url: &str,
    contracts: Vec<C::ContractWithToken>,
    output_path: &Path,
    chain_name: &str,
    config: crate::ProcessManagementConfig,
    get_extra_content_uri: FExtraUri,
) -> anyhow::Result<(Vec<std::path::PathBuf>, Vec<String>)>
where
    C: NFTChainProcessor + Sync + Send + 'static,
    C::ContractWithToken: ContractTokenInfo,
    FExtraUri: Fn(&C::Metadata) -> Option<&str>,
{
    let mut all_files = Vec::new();
    let mut errors = Vec::new();
    let provider = match processor.build_rpc_client(rpc_url) {
        Ok(p) => std::sync::Arc::new(p),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "Failed to build RPC client for {}: {}",
                chain_name,
                e
            ))
        }
    };
    for contract in contracts {
        check_shutdown_signal(&config)?;

        debug!(
            "Processing {} contract {} (token ID {})",
            chain_name,
            contract.address(),
            contract.token_id()
        );
        let token_uri = match processor.get_uri(&provider, &contract, chain_name).await {
            Ok(uri) => uri,
            Err(e) => {
                let msg = format!(
                    "Failed to get token URI for {} contract {} (token ID {}): {}",
                    chain_name,
                    contract.address(),
                    contract.token_id(),
                    e
                );
                if config.exit_on_error {
                    return Err(anyhow!(msg));
                }
                error!("{}", msg);
                errors.push(msg);
                continue;
            }
        };

        let (metadata, metadata_path) = match processor
            .fetch_metadata(&token_uri, &contract, output_path, chain_name)
            .await
        {
            Ok(pair) => pair,
            Err(e) => {
                let msg = format!(
                    "Failed to fetch metadata for {} contract {} (token ID {}) from {}: {}",
                    chain_name,
                    contract.address(),
                    contract.token_id(),
                    token_uri,
                    e
                );
                if config.exit_on_error {
                    return Err(anyhow!(msg));
                }
                error!("{}", msg);
                errors.push(msg);
                continue;
            }
        };
        all_files.push(metadata_path);

        let urls_to_download = C::collect_urls(&metadata);

        let mut downloaded = HashSet::new();
        for (url, opts) in urls_to_download {
            check_shutdown_signal(&config)?;

            if !downloaded.insert(url.clone()) {
                debug!(
                    "Skipping duplicate {:?} from {}",
                    opts.fallback_filename, url
                );
                continue;
            }
            debug!("Downloading {:?} from {}", opts.fallback_filename, url);
            let opts_for_log = opts.clone();
            match fetch_and_save_content(
                &url,
                chain_name,
                contract.address(),
                contract.token_id(),
                output_path,
                opts,
            )
            .await
            {
                Ok(path) => all_files.push(path),
                Err(e) => {
                    let name_for_log = opts_for_log
                        .fallback_filename
                        .as_deref()
                        .filter(|s| !s.is_empty())
                        .unwrap_or("content");
                    let msg = format!(
                        "Failed to fetch {} for {} contract {} (token ID {}): {}",
                        name_for_log,
                        chain_name,
                        contract.address(),
                        contract.token_id(),
                        e
                    );
                    if config.exit_on_error {
                        return Err(anyhow!(msg));
                    }
                    error!("{}", msg);
                    errors.push(msg);
                }
            }
        }

        // Fetch extra content if needed
        match fetch_and_save_extra_content(
            chain_name,
            contract.address(),
            contract.token_id(),
            output_path,
            get_extra_content_uri(&metadata),
        )
        .await
        {
            Ok(extra_files) => {
                all_files.extend(extra_files);
            }
            Err(e) => {
                let msg = format!(
                    "Failed to fetch extra content for {} contract {} (token ID {}): {}",
                    chain_name,
                    contract.address(),
                    contract.token_id(),
                    e
                );
                if config.exit_on_error {
                    return Err(anyhow!(msg));
                }
                error!("{}", msg);
                errors.push(msg);
            }
        }
    }

    Ok((all_files, errors))
}
