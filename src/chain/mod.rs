use anyhow::anyhow;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use tracing::{debug, error, warn};

use crate::content::extra::fetch_and_save_extra_content;
use crate::content::{fetch_and_save_content, save_metadata, Options};
use crate::ipfs::IpfsPinningClient;
use crate::url::extract_ipfs_cid;
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
    type ContractTokenId: ContractTokenInfo + Send + Sync + std::fmt::Display;
    type RpcClient: Send + Sync;

    /// Get the token URI for a contract using the chain's RPC client.
    async fn get_uri(&self, token: &Self::ContractTokenId) -> anyhow::Result<String>;

    /// Fetch the metadata JSON for a given contract/token and return it in-memory
    /// along with the resolved token URI.
    async fn fetch_metadata(
        &self,
        token: &Self::ContractTokenId,
    ) -> anyhow::Result<(Self::Metadata, String)>;

    /// Collect all URLs to download from the metadata.
    fn collect_urls(metadata: &Self::Metadata) -> Vec<(String, Options)>;

    /// Optional IPFS pinning client available to the processor
    fn ipfs_client(&self) -> Option<&IpfsPinningClient>;

    /// Get the output path for local storage
    fn output_path(&self) -> Option<&std::path::Path>;
}

pub async fn process_nfts<C, FExtraUri>(
    processor: std::sync::Arc<C>,
    tokens: Vec<C::ContractTokenId>,
    config: crate::ProcessManagementConfig,
    get_extra_content_uri: FExtraUri,
) -> anyhow::Result<(Vec<std::path::PathBuf>, Vec<String>, Vec<String>)>
where
    C: NFTChainProcessor + Sync + Send + 'static,
    C::ContractTokenId: ContractTokenInfo,
    C::Metadata: serde::Serialize,
    FExtraUri: Fn(&C::Metadata) -> Option<&str>,
{
    let mut all_files = Vec::new();
    let mut errors = Vec::new();
    let mut all_pins = Vec::new();
    for token in tokens {
        check_shutdown_signal(&config)?;

        debug!("Processing {}", token);
        let (metadata, token_uri) = match processor.fetch_metadata(&token).await {
            Ok(pair) => pair,
            Err(e) => {
                let msg = format!("Failed to fetch metadata for {}: {}", token, e);
                if config.exit_on_error {
                    return Err(anyhow!(msg));
                }
                error!("{}", msg);
                errors.push(msg);
                continue;
            }
        };

        // Save metadata to disk only if local storage is enabled
        if processor.output_path().is_some() {
            match save_metadata(
                &token_uri,
                token.chain_name(),
                token.address(),
                token.token_id(),
                processor.output_path().expect("checked is_some above"),
                &metadata,
            )
            .await
            {
                Ok(path) => all_files.push(path),
                Err(e) => {
                    let msg = format!("Failed to save metadata for {}: {}", token, e);
                    if config.exit_on_error {
                        return Err(anyhow!(msg));
                    }
                    error!("{}", msg);
                    errors.push(msg);
                }
            }
        }

        let urls_to_protect = C::collect_urls(&metadata);

        let mut downloaded = HashSet::new();
        for (url, opts) in urls_to_protect {
            check_shutdown_signal(&config)?;

            if !downloaded.insert(url.clone()) {
                debug!(
                    "Skipping duplicate {:?} from {}",
                    opts.fallback_filename, url
                );
                continue;
            }

            // If pinning mode is enabled and URL is IPFS, try pinning
            if let Some(ipfs_client) = processor.ipfs_client() {
                if let Some(cid) = extract_ipfs_cid(&url) {
                    debug!("Pinning {} for {}", cid, token);
                    match ipfs_client
                        .create_pin(&crate::ipfs::Pin {
                            cid: cid.clone(),
                            name: None,
                            origins: Default::default(),
                            meta: None,
                        })
                        .await
                    {
                        Ok(_) => {
                            all_pins.push(cid);
                        }
                        Err(e) => {
                            let msg = format!("Failed to pin {} for {}: {}", cid, token, e);
                            if config.exit_on_error {
                                return Err(anyhow!(msg));
                            }
                            error!("{}", msg);
                            errors.push(msg);
                        }
                    }
                }
            }

            // If no local storage configured, skip download
            if processor.output_path().is_none() {
                continue;
            }

            debug!("Downloading {:?} from {}", opts.fallback_filename, url);
            let opts_for_log = opts.clone();
            match fetch_and_save_content(
                &url,
                token.chain_name(),
                token.address(),
                token.token_id(),
                processor
                    .output_path()
                    .expect("output_path exists when downloading"),
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
                    let msg = format!("Failed to fetch {} for {}: {}", name_for_log, token, e);
                    if config.exit_on_error {
                        return Err(anyhow!(msg));
                    }
                    error!("{}", msg);
                    errors.push(msg);
                }
            }
        }

        // Fetch extra content if needed
        if let Some(out) = processor.output_path() {
            match fetch_and_save_extra_content(
                token.chain_name(),
                token.address(),
                token.token_id(),
                out,
                get_extra_content_uri(&metadata),
            )
            .await
            {
                Ok(extra_files) => {
                    all_files.extend(extra_files);
                }
                Err(e) => {
                    let msg = format!("Failed to fetch extra content for {}: {}", token, e);
                    if config.exit_on_error {
                        return Err(anyhow!(msg));
                    }
                    error!("{}", msg);
                    errors.push(msg);
                }
            }
        }
    }

    Ok((all_files, errors, all_pins))
}
