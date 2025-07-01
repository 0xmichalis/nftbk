use async_trait::async_trait;
use std::collections::HashSet;
use std::path::Path;
use tracing::{debug, error};

use crate::content::extra::fetch_and_save_extra_content;
use crate::content::{fetch_and_save_content, Options};
pub use common::ContractTokenInfo;

pub mod common;
pub mod evm;
pub mod tezos;

/// Trait for NFT chain processors to enable shared logic for fetching metadata and collecting URLs.
#[async_trait]
pub trait NFTChainProcessor {
    type Metadata;
    type ContractWithToken: ContractTokenInfo + Send + Sync;
    type RpcClient: Send + Sync;

    /// Fetch the metadata JSON for a given contract/token.
    async fn fetch_metadata(
        &self,
        token_uri: &str,
        contract: &Self::ContractWithToken,
        output_path: &std::path::Path,
        chain_name: &str,
    ) -> anyhow::Result<(Self::Metadata, std::path::PathBuf)>;

    /// Collect all URLs to download from the metadata.
    fn collect_urls_to_download(metadata: &Self::Metadata) -> Vec<(String, Option<String>)>;

    /// Get the token URI for a contract using the chain's RPC client.
    async fn get_uri(
        &self,
        rpc: &Self::RpcClient,
        contract: &Self::ContractWithToken,
    ) -> anyhow::Result<String>;
}

pub async fn process_nfts<C, FExtraUri>(
    processor: std::sync::Arc<C>,
    provider: std::sync::Arc<C::RpcClient>,
    contracts: Vec<C::ContractWithToken>,
    output_path: &Path,
    chain_name: &str,
    exit_on_error: bool,
    get_extra_content_uri: FExtraUri,
) -> anyhow::Result<Vec<std::path::PathBuf>>
where
    C: NFTChainProcessor + Sync + Send + 'static,
    C::ContractWithToken: ContractTokenInfo,
    FExtraUri: Fn(&C::Metadata) -> Option<&str>,
{
    let mut all_files = Vec::new();
    let mut error_log = Vec::new();
    for contract in contracts {
        debug!(
            "Processing contract {} (token ID {})",
            contract.address(),
            contract.token_id()
        );
        let token_uri = match processor.get_uri(&provider, &contract).await {
            Ok(uri) => uri,
            Err(e) => {
                let msg = format!(
                    "Failed to get token URI for contract {} (token ID {}): {}",
                    contract.address(),
                    contract.token_id(),
                    e
                );
                if exit_on_error {
                    return Err(e);
                }
                error!("{}", msg);
                error_log.push(msg);
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
                    "Failed to fetch metadata for contract {} (token ID {}): {}",
                    contract.address(),
                    contract.token_id(),
                    e
                );
                if exit_on_error {
                    return Err(e);
                }
                error!("{}", msg);
                error_log.push(msg);
                continue;
            }
        };
        all_files.push(metadata_path);

        let urls_to_download = C::collect_urls_to_download(&metadata);

        let mut downloaded = HashSet::new();
        for (url, fallback_filename) in urls_to_download {
            if !downloaded.insert(url.clone()) {
                debug!("Skipping duplicate {:?} from {}", fallback_filename, url);
                continue;
            }
            debug!("Downloading {:?} from {}", fallback_filename, url);
            match fetch_and_save_content(
                &url,
                chain_name,
                contract.address(),
                contract.token_id(),
                output_path,
                Options {
                    overriden_filename: None,
                    fallback_filename,
                },
            )
            .await
            {
                Ok(path) => all_files.push(path),
                Err(e) => {
                    let msg = format!(
                        "Failed to fetch content for contract {} (token ID {}): {}",
                        contract.address(),
                        contract.token_id(),
                        e
                    );
                    if exit_on_error {
                        return Err(e);
                    }
                    error!("{}", msg);
                    error_log.push(msg);
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
                    "Failed to fetch extra content (contract: {}, token ID: {}): {}",
                    contract.address(),
                    contract.token_id(),
                    e
                );
                if exit_on_error {
                    return Err(e);
                }
                error!("{}", msg);
                error_log.push(msg);
            }
        }
    }

    // Write error log if needed
    if !exit_on_error && !error_log.is_empty() {
        use tokio::fs::OpenOptions;
        use tokio::io::AsyncWriteExt;
        let mut log_path = output_path.to_path_buf();
        log_path.set_extension("log");
        let log_content = error_log.join("\n") + "\n";
        match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .await
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(log_content.as_bytes()).await {
                    error!("Failed to write error log to {}: {}", log_path.display(), e);
                }
            }
            Err(e) => {
                error!(
                    "Failed to create error log file {}: {}",
                    log_path.display(),
                    e
                );
            }
        }
    }
    Ok(all_files)
}
