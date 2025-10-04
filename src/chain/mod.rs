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

/// Helper function to handle errors consistently across processing steps
/// Returns Ok(Some(result)) on success, Ok(None) on error (handled), or Err on exit_on_error
fn process<T>(
    result: anyhow::Result<T>,
    error_msg: String,
    config: &crate::ProcessManagementConfig,
    errors: &mut Vec<String>,
) -> anyhow::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(e) => {
            let full_msg = format!("{}: {}", error_msg, e);
            if config.exit_on_error {
                return Err(anyhow!(full_msg));
            }
            error!("{}", full_msg);
            errors.push(full_msg);
            Ok(None)
        }
    }
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
        let (metadata, token_uri) = match process(
            processor.fetch_metadata(&token).await,
            format!("Failed to fetch metadata for {token}"),
            &config,
            &mut errors,
        )? {
            Some(pair) => pair,
            None => continue,
        };

        // Get output path once and reuse it
        let output_path = processor.output_path();

        // Save metadata to disk only if local storage is enabled
        if let Some(out_path) = output_path {
            if let Some(path) = process(
                save_metadata(&token_uri, &token, out_path, &metadata).await,
                format!("Failed to save metadata for {token}"),
                &config,
                &mut errors,
            )? {
                all_files.push(path);
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
                    if process(
                        ipfs_client
                            .create_pin(&crate::ipfs::Pin {
                                cid: cid.clone(),
                                name: None,
                                origins: Default::default(),
                                meta: None,
                            })
                            .await,
                        format!("Failed to pin {cid} for {token}"),
                        &config,
                        &mut errors,
                    )?
                    .is_some()
                    {
                        all_pins.push(cid);
                    }
                }
            }

            // If no local storage configured, skip download
            if output_path.is_none() {
                continue;
            }

            debug!("Downloading {:?} from {}", opts.fallback_filename, url);
            let fallback_filename = opts.fallback_filename.clone();
            let name_for_log = fallback_filename
                .as_deref()
                .filter(|s| !s.is_empty())
                .unwrap_or("content");
            if let Some(path) = process(
                fetch_and_save_content(
                    &url,
                    &token,
                    output_path.expect("output_path exists when downloading"),
                    opts,
                )
                .await,
                format!("Failed to fetch {name_for_log} for {token}"),
                &config,
                &mut errors,
            )? {
                all_files.push(path);
            }
        }

        // Fetch extra content if needed
        if let Some(out) = output_path {
            if let Some(extra_files) = process(
                fetch_and_save_extra_content(&token, out, get_extra_content_uri(&metadata)).await,
                format!("Failed to fetch extra content for {token}"),
                &config,
                &mut errors,
            )? {
                all_files.extend(extra_files);
            }
        }
    }

    Ok((all_files, errors, all_pins))
}
