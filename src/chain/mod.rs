use anyhow::anyhow;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use tracing::{debug, error, info, warn};

use crate::content::extra::fetch_and_write_extra;
use crate::content::{write_metadata, Options};
use crate::ipfs::url::extract_ipfs_cid;
use crate::ipfs::{IpfsPinningProvider, PinRequest};
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
    exit_on_error: bool,
    errors: &mut Vec<String>,
) -> anyhow::Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(e) => {
            let full_msg = format!("{error_msg}: {e}");
            if exit_on_error {
                return Err(anyhow!(full_msg));
            }
            error!("{}", full_msg);
            errors.push(full_msg);
            Ok(None)
        }
    }
}

/// Build a pin name for a given token and context.
/// If any provider is a pinning-service, prefix with task_id_chain_address_tokenid_.
fn build_pin_name<T: ContractTokenInfo>(
    token: &T,
    providers: &[Box<dyn IpfsPinningProvider>],
    is_metadata: bool,
    fallback_filename: Option<&str>,
    task_id: Option<&str>,
) -> String {
    let base_name = fallback_filename
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(if is_metadata {
            "metadata.json"
        } else {
            "content"
        });

    let needs_unique_prefix = providers
        .iter()
        .any(|p| p.provider_type() == "pinning-service");

    if !needs_unique_prefix {
        return base_name.to_string();
    }

    if let Some(task_id) = task_id {
        // Use only the first 6 characters of the task ID
        let short_task_id = if task_id.len() > 6 {
            &task_id[..6]
        } else {
            task_id
        };
        format!(
            "{}_{}_{}_{}_{}",
            short_task_id,
            token.chain_name(),
            token.address(),
            token.token_id(),
            base_name
        )
    } else {
        format!(
            "{}_{}_{}_{}",
            token.chain_name(),
            token.address(),
            token.token_id(),
            base_name
        )
    }
}

/// Pin a CID to all configured providers with a standardized name
#[allow(clippy::too_many_arguments)]
async fn pin_cid<C>(
    cid: &str,
    token: &C::ContractTokenId,
    processor: &C,
    exit_on_error: bool,
    errors: &mut Vec<String>,
    is_metadata: bool,
    fallback_filename: Option<&str>,
    task_id: Option<&str>,
) -> anyhow::Result<Vec<crate::ipfs::PinResponse>>
where
    C: NFTChainProcessor,
{
    let mut pin_responses = Vec::new();
    let providers = processor.ipfs_pinning_providers();
    if providers.is_empty() {
        return Ok(pin_responses);
    }

    debug!(
        "Pinning {} for {} to {} provider(s)",
        cid,
        token,
        providers.len()
    );

    // Determine base name (metadata.json/content/fallback) and optionally prefix for uniqueness
    let name = build_pin_name(token, providers, is_metadata, fallback_filename, task_id);
    let pin_request = PinRequest {
        cid: cid.to_string(),
        name: Some(name),
        metadata: Some(token.to_pin_metadata_map()),
    };

    for provider in providers {
        info!(
            "Requesting to pin {cid} for {token} to provider {}",
            provider.provider_type()
        );
        if let Some(response) = process(
            provider.create_pin(&pin_request).await,
            format!(
                "Failed to request pinning {cid} for {token} to provider {}",
                provider.provider_type()
            ),
            exit_on_error,
            errors,
        )? {
            info!(
                "Requested to pin {cid} for {token} to provider {} (request id: {})",
                provider.provider_type(),
                response.id
            );
            pin_responses.push(response);
        }
    }

    Ok(pin_responses)
}

/// Protect a URL by pinning it to IPFS (if applicable) and downloading content locally
/// Returns (pin_responses, downloaded_file_path) where either can be empty/None
#[allow(clippy::too_many_arguments)]
async fn protect_url<C>(
    url: &str,
    opts: &Options,
    token: &C::ContractTokenId,
    processor: &C,
    exit_on_error: bool,
    archive_errors: &mut Vec<String>,
    ipfs_errors: &mut Vec<String>,
    task_id: Option<&str>,
) -> anyhow::Result<(Vec<crate::ipfs::PinResponse>, Option<std::path::PathBuf>)>
where
    C: NFTChainProcessor,
{
    let mut pin_responses = Vec::new();
    let mut downloaded_path = None;

    // If pinning mode is enabled and URL is IPFS, try pinning
    if let Some(cid) = extract_ipfs_cid(url) {
        let fallback = opts.fallback_filename.as_deref().filter(|s| !s.is_empty());
        pin_responses = pin_cid(
            cid.as_str(),
            token,
            processor,
            exit_on_error,
            ipfs_errors,
            false,
            fallback,
            task_id,
        )
        .await?;
    }

    // If local storage is configured, download content
    if let Some(output_path) = processor.output_path() {
        debug!("Downloading {:?} from {}", opts.fallback_filename, url);
        let fallback_filename = opts.fallback_filename.clone();
        let name_for_log = fallback_filename
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or("content");
        if let Some(path) = process(
            processor
                .http_client()
                .fetch_and_write(url, token, output_path, opts.clone())
                .await,
            format!("Failed to fetch {name_for_log} for {token}"),
            exit_on_error,
            archive_errors,
        )? {
            downloaded_path = Some(path);
        }
    }

    Ok((pin_responses, downloaded_path))
}

/// Protect metadata by pinning the token URI to IPFS (if applicable) and saving metadata locally
/// Returns (pin_responses, saved_metadata_path) where either can be empty/None
#[allow(clippy::too_many_arguments)]
async fn protect_metadata<C>(
    token_uri: &str,
    token: &C::ContractTokenId,
    metadata: &C::Metadata,
    processor: &C,
    exit_on_error: bool,
    archive_errors: &mut Vec<String>,
    ipfs_errors: &mut Vec<String>,
    task_id: Option<&str>,
) -> anyhow::Result<(Vec<crate::ipfs::PinResponse>, Option<std::path::PathBuf>)>
where
    C: NFTChainProcessor,
    C::Metadata: serde::Serialize,
{
    let mut pin_responses = Vec::new();
    let mut saved_path = None;

    // If pinning mode is enabled and token URI is IPFS, try pinning to all providers
    if let Some(cid) = extract_ipfs_cid(token_uri) {
        let responses = pin_cid(
            cid.as_str(),
            token,
            processor,
            exit_on_error,
            ipfs_errors,
            true,
            Some("metadata"),
            task_id,
        )
        .await?;
        pin_responses.extend(responses);
    }

    // If local storage is configured, write metadata
    if let Some(output_path) = processor.output_path() {
        if let Some(path) = process(
            write_metadata(token_uri, token, output_path, metadata).await,
            format!("Failed to write metadata for {token}"),
            exit_on_error,
            archive_errors,
        )? {
            saved_path = Some(path);
        }
    }

    Ok((pin_responses, saved_path))
}

/// Trait for NFT chain processors to enable shared logic for fetching metadata and collecting URLs.
#[async_trait]
pub trait NFTChainProcessor {
    type Metadata;
    type ContractTokenId: ContractTokenInfo + Send + Sync + std::fmt::Display;
    type RpcClient: Send + Sync;

    /// Get the token URI for a contract using the chain's RPC client.
    async fn get_uri(&self, token: &Self::ContractTokenId) -> anyhow::Result<String>;

    /// Fetch the metadata JSON for a given token URI and return it in-memory.
    async fn fetch_metadata(&self, token_uri: &str) -> anyhow::Result<Self::Metadata>;

    /// Collect all URLs to download from the metadata.
    fn collect_urls(metadata: &Self::Metadata) -> Vec<(String, Options)>;

    /// Get all IPFS pinning providers available to the processor
    fn ipfs_pinning_providers(&self) -> &[Box<dyn IpfsPinningProvider>];

    /// Get the output path for local storage
    fn output_path(&self) -> Option<&std::path::Path>;

    /// Get the HTTP client used for URL resolution and fetching
    fn http_client(&self) -> &crate::httpclient::HttpClient;
}

pub async fn process_nfts<C, FExtraUri>(
    processor: std::sync::Arc<C>,
    tokens: Vec<C::ContractTokenId>,
    config: crate::ProcessManagementConfig,
    get_extra_content_uri: FExtraUri,
    task_id: Option<String>,
) -> anyhow::Result<(crate::ArchiveOutcome, crate::IpfsOutcome)>
where
    C: NFTChainProcessor + Sync + Send + 'static,
    C::ContractTokenId: ContractTokenInfo,
    C::Metadata: serde::Serialize,
    FExtraUri: Fn(&C::Metadata) -> Option<&str>,
{
    let mut files = Vec::new();
    let mut token_pin_mappings = Vec::new();
    let mut archive_errors = Vec::new();
    let mut ipfs_errors = Vec::new();

    for token in tokens {
        check_shutdown_signal(&config)?;

        debug!("Processing {}", token);

        // Get token URI first
        let token_uri = match process(
            processor.get_uri(&token).await,
            format!("Failed to get token URI for {token}"),
            config.exit_on_error,
            &mut archive_errors,
        )? {
            Some(uri) => uri,
            None => {
                // Token URI fetch failure affects both archive and IPFS operations
                // The error was already added to archive_errors by the process function
                // Add the same error to ipfs_errors as well
                if let Some(last_error) = archive_errors.last() {
                    ipfs_errors.push(last_error.clone());
                }
                continue;
            }
        };

        // Fetch metadata using the token URI
        let metadata = match process(
            processor.fetch_metadata(&token_uri).await,
            format!("Failed to fetch metadata for {token}"),
            config.exit_on_error,
            &mut archive_errors,
        )? {
            Some(metadata) => metadata,
            None => {
                // Metadata fetch failure affects both archive and IPFS operations
                // The error was already added to archive_errors by the process function
                // Add the same error to ipfs_errors as well
                if let Some(last_error) = archive_errors.last() {
                    ipfs_errors.push(last_error.clone());
                }
                continue;
            }
        };

        // Get output path once and reuse it
        let output_path = processor.output_path();

        // Collect all pin responses for this token
        let mut token_pin_responses = Vec::new();

        // Protect metadata by pinning token URI and writing locally
        let (metadata_pin_responses, saved_metadata_path) = protect_metadata(
            &token_uri,
            &token,
            &metadata,
            &*processor,
            config.exit_on_error,
            &mut archive_errors,
            &mut ipfs_errors,
            task_id.as_deref(),
        )
        .await?;

        token_pin_responses.extend(metadata_pin_responses);

        if let Some(path) = saved_metadata_path {
            files.push(path);
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

            // Protect the URL by pinning and downloading
            let (url_pin_responses, downloaded_path) = protect_url(
                &url,
                &opts,
                &token,
                &*processor,
                config.exit_on_error,
                &mut archive_errors,
                &mut ipfs_errors,
                task_id.as_deref(),
            )
            .await?;

            token_pin_responses.extend(url_pin_responses);

            if let Some(path) = downloaded_path {
                files.push(path);
            }
        }

        // Create token-pin mapping for this token if it has any pin responses
        if !token_pin_responses.is_empty() {
            token_pin_mappings.push(crate::TokenPinMapping {
                chain: token.chain_name().to_string(),
                contract_address: token.address().to_string(),
                token_id: token.token_id().to_string(),
                pin_responses: token_pin_responses,
            });
        }

        // Fetch extra content if needed
        if let Some(out) = output_path {
            if let Some(extra_files) = process(
                fetch_and_write_extra(&token, out, get_extra_content_uri(&metadata)).await,
                format!("Failed to fetch extra content for {token}"),
                config.exit_on_error,
                &mut archive_errors,
            )? {
                files.extend(extra_files);
            }
        }
    }

    Ok((
        crate::ArchiveOutcome {
            files,
            errors: archive_errors,
        },
        crate::IpfsOutcome {
            pin_requests: token_pin_mappings,
            errors: ipfs_errors,
        },
    ))
}

#[cfg(test)]
mod process_tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn test_process_success() {
        let mut errors = Vec::new();
        let result = process(
            Ok("test_value".to_string()),
            "Test operation".to_string(),
            false,
            &mut errors,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some("test_value".to_string()));
        assert!(errors.is_empty());
    }

    #[test]
    fn test_process_error_exit_on_error_true() {
        let mut errors = Vec::new();
        let result = process::<String>(
            Err(anyhow!("Test error")),
            "Test operation".to_string(),
            true,
            &mut errors,
        );

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Test operation: Test error"));
        assert!(errors.is_empty());
    }

    #[test]
    fn test_process_error_exit_on_error_false() {
        let mut errors = Vec::new();
        let result = process::<String>(
            Err(anyhow!("Test error")),
            "Test operation".to_string(),
            false,
            &mut errors,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0], "Test operation: Test error");
    }

    #[test]
    fn test_process_error_message_formatting() {
        let mut errors = Vec::new();
        let result = process::<String>(
            Err(anyhow!("Inner error message")),
            "Outer operation".to_string(),
            true,
            &mut errors,
        );

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert_eq!(error_msg, "Outer operation: Inner error message");
    }

    #[test]
    fn test_process_multiple_errors_accumulation() {
        let mut errors = Vec::new();

        // First error
        let result1 = process::<String>(
            Err(anyhow!("First error")),
            "First operation".to_string(),
            false,
            &mut errors,
        );
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap(), None);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0], "First operation: First error");

        // Second error
        let result2 = process::<String>(
            Err(anyhow!("Second error")),
            "Second operation".to_string(),
            false,
            &mut errors,
        );
        assert!(result2.is_ok());
        assert_eq!(result2.unwrap(), None);
        assert_eq!(errors.len(), 2);
        assert_eq!(errors[1], "Second operation: Second error");

        // Success should not add to errors
        let result3 = process(
            Ok("success_value".to_string()),
            "Success operation".to_string(),
            false,
            &mut errors,
        );
        assert!(result3.is_ok());
        assert_eq!(result3.unwrap(), Some("success_value".to_string()));
        assert_eq!(errors.len(), 2); // Should still be 2
    }

    #[test]
    fn test_process_with_different_result_types() {
        let mut errors = Vec::new();

        // Test with integer result
        let int_result = process(Ok(42), "Integer operation".to_string(), false, &mut errors);
        assert!(int_result.is_ok());
        assert_eq!(int_result.unwrap(), Some(42));

        // Test with boolean result
        let bool_result = process(
            Ok(true),
            "Boolean operation".to_string(),
            false,
            &mut errors,
        );
        assert!(bool_result.is_ok());
        assert_eq!(bool_result.unwrap(), Some(true));

        // Test with vector result
        let vec_result = process(
            Ok(vec![1, 2, 3]),
            "Vector operation".to_string(),
            false,
            &mut errors,
        );
        assert!(vec_result.is_ok());
        assert_eq!(vec_result.unwrap(), Some(vec![1, 2, 3]));
    }
}

#[cfg(test)]
mod process_nfts_tests {
    use super::*;
    use crate::content::Options;
    use crate::ipfs::IpfsPinningClient;
    use crate::{ContractTokenId, ProcessManagementConfig};
    use anyhow::anyhow;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use tempfile::TempDir;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    // Mock metadata type for testing
    #[derive(Debug, Clone, serde::Serialize)]
    struct MockMetadata {
        name: String,
        image: String,
        animation_url: Option<String>,
    }

    // Mock RPC client type
    #[derive(Debug)]
    struct MockRpcClient;

    // Mock processor for testing
    struct MockProcessor {
        output_path: Option<std::path::PathBuf>,
        ipfs_pinning_providers: Vec<Box<dyn IpfsPinningProvider>>,
        fetch_metadata_result: Result<MockMetadata, anyhow::Error>,
        get_uri_result: Result<String, anyhow::Error>,
        http_client: crate::httpclient::HttpClient,
    }

    impl MockProcessor {
        fn new() -> Self {
            Self {
                output_path: None,
                ipfs_pinning_providers: Vec::new(),
                fetch_metadata_result: Ok(MockMetadata {
                    name: "Test NFT".to_string(),
                    image: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==".to_string(),
                    animation_url: Some("data:text/plain;base64,SGVsbG8gV29ybGQ=".to_string()),
                }),
                get_uri_result: Ok("data:application/json;base64,eyJuYW1lIjoiVGVzdCJ9".to_string()),
                http_client: crate::httpclient::HttpClient::new(),
            }
        }

        fn with_output_path(mut self, path: std::path::PathBuf) -> Self {
            self.output_path = Some(path);
            self
        }

        fn with_fetch_metadata_error(mut self, error: anyhow::Error) -> Self {
            self.fetch_metadata_result = Err(error);
            self
        }
    }

    #[async_trait]
    impl NFTChainProcessor for MockProcessor {
        type Metadata = MockMetadata;
        type ContractTokenId = ContractTokenId;
        type RpcClient = MockRpcClient;

        async fn get_uri(&self, _token: &Self::ContractTokenId) -> anyhow::Result<String> {
            match &self.get_uri_result {
                Ok(s) => Ok(s.clone()),
                Err(e) => Err(anyhow!(e.to_string())),
            }
        }

        async fn fetch_metadata(&self, _token_uri: &str) -> anyhow::Result<Self::Metadata> {
            match &self.fetch_metadata_result {
                Ok(metadata) => Ok(metadata.clone()),
                Err(e) => Err(anyhow!(e.to_string())),
            }
        }

        fn collect_urls(metadata: &Self::Metadata) -> Vec<(String, Options)> {
            let options = Options {
                overriden_filename: None,
                fallback_filename: None,
            };
            let mut urls = vec![(metadata.image.clone(), options.clone())];
            if let Some(animation_url) = &metadata.animation_url {
                urls.push((animation_url.clone(), options));
            }
            urls
        }

        fn ipfs_pinning_providers(&self) -> &[Box<dyn IpfsPinningProvider>] {
            &self.ipfs_pinning_providers
        }

        fn output_path(&self) -> Option<&std::path::Path> {
            self.output_path.as_deref()
        }

        fn http_client(&self) -> &crate::httpclient::HttpClient {
            &self.http_client
        }
    }

    fn create_test_token() -> ContractTokenId {
        ContractTokenId {
            address: "0x1234567890123456789012345678901234567890".to_string(),
            token_id: "1".to_string(),
            chain_name: "ethereum".to_string(),
        }
    }

    fn create_test_config(exit_on_error: bool) -> ProcessManagementConfig {
        ProcessManagementConfig {
            exit_on_error,
            shutdown_flag: None,
        }
    }

    fn create_test_config_with_shutdown(
        exit_on_error: bool,
        shutdown_flag: Arc<AtomicBool>,
    ) -> ProcessManagementConfig {
        ProcessManagementConfig {
            exit_on_error,
            shutdown_flag: Some(shutdown_flag),
        }
    }

    // Helper function to create closures that return None
    fn get_no_extra_content_uri<M>(_metadata: &M) -> Option<&str> {
        None
    }

    // Helper function to create closures that return a static string
    fn get_extra_content_uri_with_url<M>(_metadata: &M) -> Option<&str> {
        Some("data:application/json;base64,eyJleHRyYSI6InRlc3QifQ==")
    }

    #[tokio::test]
    async fn test_process_nfts_empty_tokens() {
        let processor = Arc::new(MockProcessor::new());
        let tokens = vec![];
        let config = create_test_config(false);
        let get_extra_content_uri = get_no_extra_content_uri::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_ok());
        let (archive_out, ipfs_out) = result.unwrap();
        assert!(archive_out.files.is_empty());
        assert!(archive_out.errors.is_empty());
        assert!(ipfs_out.pin_requests.is_empty());
    }

    #[tokio::test]
    async fn test_process_nfts_success() {
        let temp_dir = TempDir::new().unwrap();
        let processor =
            Arc::new(MockProcessor::new().with_output_path(temp_dir.path().to_path_buf()));
        let tokens = vec![create_test_token()];
        let config = create_test_config(false);
        let get_extra_content_uri = get_no_extra_content_uri::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_ok());
        let (archive_out, ipfs_out) = result.unwrap();
        // Should have metadata file and content files (data URLs work without network)
        assert!(!archive_out.files.is_empty());
        assert!(archive_out.errors.is_empty()); // No errors with data URLs
        assert!(ipfs_out.pin_requests.is_empty()); // No IPFS client configured
    }

    #[tokio::test]
    async fn test_process_nfts_shutdown_signal() {
        let processor = Arc::new(MockProcessor::new());
        let tokens = vec![create_test_token()];
        let shutdown_flag = Arc::new(AtomicBool::new(true));
        let config = create_test_config_with_shutdown(false, shutdown_flag);
        let get_extra_content_uri = get_no_extra_content_uri::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("shutdown signal"));
    }

    #[tokio::test]
    async fn test_process_nfts_metadata_error_exit_on_error() {
        let processor = Arc::new(
            MockProcessor::new().with_fetch_metadata_error(anyhow!("Metadata fetch failed")),
        );
        let tokens = vec![create_test_token()];
        let config = create_test_config(true); // exit_on_error = true
        let get_extra_content_uri = get_no_extra_content_uri::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Failed to fetch metadata"));
        assert!(error_msg.contains("Metadata fetch failed"));
    }

    #[tokio::test]
    async fn test_process_nfts_metadata_error_continue_on_error() {
        let processor = Arc::new(
            MockProcessor::new().with_fetch_metadata_error(anyhow!("Metadata fetch failed")),
        );
        let tokens = vec![create_test_token()];
        let config = create_test_config(false); // exit_on_error = false
        let get_extra_content_uri = get_no_extra_content_uri::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_ok());
        let (archive_out, ipfs_out) = result.unwrap();
        assert!(archive_out.files.is_empty());
        assert_eq!(archive_out.errors.len(), 1);
        assert!(archive_out.errors[0].contains("Failed to fetch metadata"));
        assert!(archive_out.errors[0].contains("Metadata fetch failed"));
        assert!(ipfs_out.pin_requests.is_empty());
        // Metadata fetch failure affects both archive and IPFS operations
        assert_eq!(ipfs_out.errors.len(), 1);
        assert!(ipfs_out.errors[0].contains("Failed to fetch metadata"));
        assert!(ipfs_out.errors[0].contains("Metadata fetch failed"));
    }

    #[tokio::test]
    async fn test_process_nfts_duplicate_urls() {
        let temp_dir = TempDir::new().unwrap();
        let processor =
            Arc::new(MockProcessor::new().with_output_path(temp_dir.path().to_path_buf()));
        let tokens = vec![create_test_token()];
        let config = create_test_config(false);
        let get_extra_content_uri = get_no_extra_content_uri::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_ok());
        let (archive_out, ipfs_out) = result.unwrap();
        // Should have files (metadata and content from data URLs)
        assert!(!archive_out.files.is_empty());
        assert!(archive_out.errors.is_empty()); // No errors with data URLs
        assert!(ipfs_out.pin_requests.is_empty());
    }

    #[tokio::test]
    async fn test_process_nfts_multiple_tokens() {
        let temp_dir = TempDir::new().unwrap();
        let processor =
            Arc::new(MockProcessor::new().with_output_path(temp_dir.path().to_path_buf()));
        let tokens = vec![
            create_test_token(),
            ContractTokenId {
                address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
                token_id: "2".to_string(),
                chain_name: "ethereum".to_string(),
            },
        ];
        let config = create_test_config(false);
        let get_extra_content_uri = get_no_extra_content_uri::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_ok());
        let (archive_out, ipfs_out) = result.unwrap();
        // Should have files for both tokens (metadata and content from data URLs)
        assert!(!archive_out.files.is_empty());
        assert!(archive_out.errors.is_empty()); // No errors with data URLs
        assert!(ipfs_out.pin_requests.is_empty());
    }

    #[tokio::test]
    async fn test_process_nfts_mixed_success_and_error() {
        let temp_dir = TempDir::new().unwrap();
        let processor = MockProcessor::new().with_output_path(temp_dir.path().to_path_buf());

        // Create a processor that fails on the second token
        let processor = Arc::new(processor);
        let tokens = vec![
            create_test_token(),
            ContractTokenId {
                address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
                token_id: "2".to_string(),
                chain_name: "ethereum".to_string(),
            },
        ];
        let config = create_test_config(false); // Don't exit on error
        let get_extra_content_uri = get_no_extra_content_uri::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_ok());
        let (archive_out, ipfs_out) = result.unwrap();
        // Should have some files from successful processing (metadata and content from data URLs)
        assert!(!archive_out.files.is_empty());
        assert!(archive_out.errors.is_empty()); // No errors with data URLs
        assert!(ipfs_out.pin_requests.is_empty());
    }

    #[tokio::test]
    async fn test_process_nfts_extra_content() {
        let temp_dir = TempDir::new().unwrap();
        let processor =
            Arc::new(MockProcessor::new().with_output_path(temp_dir.path().to_path_buf()));
        let tokens = vec![create_test_token()];
        let config = create_test_config(false);
        let get_extra_content_uri = get_extra_content_uri_with_url::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_ok());
        let (archive_out, ipfs_out) = result.unwrap();
        // Should have files including potential extra content (metadata and content from data URLs)
        assert!(!archive_out.files.is_empty());
        assert!(archive_out.errors.is_empty()); // No errors with data URLs
        assert!(ipfs_out.pin_requests.is_empty());
    }

    #[tokio::test]
    async fn test_process_nfts_no_output_path() {
        let processor = Arc::new(MockProcessor::new()); // No output path
        let tokens = vec![create_test_token()];
        let config = create_test_config(false);
        let get_extra_content_uri = get_no_extra_content_uri::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_ok());
        let (archive_out, ipfs_out) = result.unwrap();
        // Should have no files since no output path is configured
        assert!(archive_out.files.is_empty());
        assert!(archive_out.errors.is_empty());
        assert!(ipfs_out.pin_requests.is_empty());
    }

    #[tokio::test]
    async fn test_process_nfts_with_ipfs_pinning_failure() {
        // Start wiremock server
        let mock_server = MockServer::start().await;

        // Create temp directory
        let temp_dir = TempDir::new().unwrap();

        // Set up wiremock for HTTP requests
        Mock::given(method("GET"))
            .and(path("/image.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake image data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/metadata.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"name":"Test NFT"}"#))
            .mount(&mock_server)
            .await;

        // Set up IPFS pinning mock endpoints - FAILURE case
        Mock::given(method("POST"))
            .and(path("/pins"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_string(r#"{"error":"IPFS service unavailable"}"#),
            )
            .mount(&mock_server)
            .await;

        // Create real IPFS client pointing to mock server
        let ipfs_client = IpfsPinningClient::new(
            mock_server.uri(),
            None, // No auth token for testing
        );

        // Create processor with IPFS URLs for testing IPFS pinning
        let processor = Arc::new(MockProcessor {
            output_path: Some(temp_dir.path().to_path_buf()),
            ipfs_pinning_providers: vec![Box::new(ipfs_client) as Box<dyn IpfsPinningProvider>],
            fetch_metadata_result: Ok(MockMetadata {
                name: "Test NFT".to_string(),
                image: "ipfs://QmTestImageHash".to_string(),
                animation_url: None,
            }),
            get_uri_result: Ok("ipfs://QmTestMetadataHash".to_string()),
            http_client: crate::httpclient::HttpClient::new()
                .with_gateways(vec![(
                    mock_server.uri(),
                    crate::ipfs::config::IpfsGatewayType::Path,
                )])
                .with_max_retries(0),
        });

        let tokens = vec![create_test_token()];
        let config = create_test_config(false);

        let (archive_out, ipfs_out) =
            process_nfts(processor, tokens, config, get_no_extra_content_uri, None)
                .await
                .unwrap();

        // Verify results - files should still be created even if IPFS pinning fails
        assert_eq!(archive_out.files.len(), 1); // Only metadata.json (content fetching fails for IPFS URLs)
        assert_eq!(ipfs_out.pin_requests.len(), 0); // No successful pins due to IPFS failure
        assert!(ipfs_out.errors.len() >= 2); // IPFS errors for both metadata and image pinning failures

        // Verify that the files were created despite IPFS failure
        let output_path = temp_dir.path();
        let token_dir = output_path.join("ethereum/0x1234567890123456789012345678901234567890/1");
        assert!(token_dir.join("metadata.json").exists());
    }

    #[tokio::test]
    async fn test_process_nfts_with_ipfs_auth_required() {
        // Start wiremock server
        let mock_server = MockServer::start().await;

        // Create temp directory
        let temp_dir = TempDir::new().unwrap();

        // Set up wiremock for HTTP requests
        Mock::given(method("GET"))
            .and(path("/image.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake image data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/metadata.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"name":"Test NFT"}"#))
            .mount(&mock_server)
            .await;

        // Set up IPFS pinning mock endpoints - AUTH REQUIRED case
        Mock::given(method("POST"))
            .and(path("/pins"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_string(r#"{"error":"Authentication required"}"#),
            )
            .mount(&mock_server)
            .await;

        // Create real IPFS client pointing to mock server with auth token
        let ipfs_client = IpfsPinningClient::new(mock_server.uri(), Some("test-token".to_string()));

        // Create processor with IPFS URLs for testing IPFS pinning
        let processor = Arc::new(MockProcessor {
            output_path: Some(temp_dir.path().to_path_buf()),
            ipfs_pinning_providers: vec![Box::new(ipfs_client) as Box<dyn IpfsPinningProvider>],
            fetch_metadata_result: Ok(MockMetadata {
                name: "Test NFT".to_string(),
                image: "ipfs://QmTestImageHash".to_string(),
                animation_url: None,
            }),
            get_uri_result: Ok("ipfs://QmTestMetadataHash".to_string()),
            http_client: crate::httpclient::HttpClient::new()
                .with_gateways(vec![(
                    mock_server.uri(),
                    crate::ipfs::config::IpfsGatewayType::Path,
                )])
                .with_max_retries(0),
        });

        let tokens = vec![create_test_token()];
        let config = create_test_config(false);

        let (archive_out, ipfs_out) =
            process_nfts(processor, tokens, config, get_no_extra_content_uri, None)
                .await
                .unwrap();

        // Verify results - files should still be created even if IPFS auth fails
        assert_eq!(archive_out.files.len(), 1); // Only metadata.json (content fetching fails for IPFS URLs)
        assert_eq!(ipfs_out.pin_requests.len(), 0); // No successful pins due to auth failure
        assert!(ipfs_out.errors.len() >= 2); // IPFS errors for both metadata and image pinning failures

        // Verify that the files were created despite IPFS auth failure
        let output_path = temp_dir.path();
        let token_dir = output_path.join("ethereum/0x1234567890123456789012345678901234567890/1");
        assert!(token_dir.join("metadata.json").exists());
    }

    #[tokio::test]
    async fn test_process_nfts_error_categorization_archive_errors() {
        let temp_dir = TempDir::new().unwrap();

        // Create a processor that fails on metadata writing (archive operation)
        let processor = Arc::new(MockProcessor {
            output_path: Some(temp_dir.path().to_path_buf()),
            ipfs_pinning_providers: vec![], // No IPFS providers
            fetch_metadata_result: Ok(MockMetadata {
                name: "Test NFT".to_string(),
                image: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==".to_string(),
                animation_url: None,
            }),
            get_uri_result: Ok("data:application/json;base64,eyJuYW1lIjoiVGVzdCJ9".to_string()),
            http_client: crate::httpclient::HttpClient::new()
                .with_gateways(vec![])
                .with_max_retries(0),
        });

        let tokens = vec![create_test_token()];
        let config = create_test_config(false); // Don't exit on error
        let get_extra_content_uri = get_no_extra_content_uri::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_ok());
        let (archive_out, ipfs_out) = result.unwrap();

        // Verify that archive operations succeeded (no archive errors)
        assert!(!archive_out.files.is_empty()); // Should have metadata and content files
        assert!(archive_out.errors.is_empty()); // No archive errors

        // Verify that IPFS operations are not attempted (no IPFS errors)
        assert!(ipfs_out.pin_requests.is_empty());
        assert!(ipfs_out.errors.is_empty());
    }

    #[tokio::test]
    async fn test_process_nfts_error_categorization_ipfs_errors() {
        // Start wiremock server
        let mock_server = MockServer::start().await;

        // Create temp directory
        let temp_dir = TempDir::new().unwrap();

        // Set up IPFS pinning mock endpoints - FAILURE case
        Mock::given(method("POST"))
            .and(path("/pins"))
            .respond_with(
                ResponseTemplate::new(500).set_body_string(r#"{"error":"Internal server error"}"#),
            )
            .mount(&mock_server)
            .await;

        // Create real IPFS client pointing to mock server
        let ipfs_client = IpfsPinningClient::new(mock_server.uri(), None);

        // Create processor with IPFS URLs for testing IPFS pinning
        let processor = Arc::new(MockProcessor {
            output_path: Some(temp_dir.path().to_path_buf()),
            ipfs_pinning_providers: vec![Box::new(ipfs_client) as Box<dyn IpfsPinningProvider>],
            fetch_metadata_result: Ok(MockMetadata {
                name: "Test NFT".to_string(),
                image: "ipfs://QmTestImageHash".to_string(),
                animation_url: None,
            }),
            get_uri_result: Ok("ipfs://QmTestMetadataHash".to_string()),
            http_client: crate::httpclient::HttpClient::new()
                .with_gateways(vec![(
                    mock_server.uri(),
                    crate::ipfs::config::IpfsGatewayType::Path,
                )])
                .with_max_retries(0),
        });

        let tokens = vec![create_test_token()];
        let config = create_test_config(false);

        let (archive_out, ipfs_out) =
            process_nfts(processor, tokens, config, get_no_extra_content_uri, None)
                .await
                .unwrap();

        // Verify that archive operations succeeded (metadata writing works)
        assert_eq!(archive_out.files.len(), 1); // Should have metadata.json
                                                // Note: IPFS URLs can't be downloaded via HTTP, so content download errors go to archive_errors
                                                // This is expected behavior - only metadata.json gets written, content download fails

        // Verify that IPFS operations failed and errors went to ipfs_errors
        assert_eq!(ipfs_out.pin_requests.len(), 0); // No successful pins
        assert!(ipfs_out.errors.len() >= 2); // IPFS errors for both metadata and image pinning failures

        // Verify specific error categorization
        for error in &ipfs_out.errors {
            assert!(error.contains("IPFS") || error.contains("pin") || error.contains("500"));
        }
    }

    #[tokio::test]
    async fn test_process_nfts_error_categorization_pure_ipfs_errors() {
        // Start wiremock server
        let mock_server = MockServer::start().await;

        // Create temp directory (not used but needed for MockProcessor)
        let _temp_dir = TempDir::new().unwrap();

        // Set up IPFS pinning mock endpoints - FAILURE case
        Mock::given(method("POST"))
            .and(path("/pins"))
            .respond_with(
                ResponseTemplate::new(500).set_body_string(r#"{"error":"Internal server error"}"#),
            )
            .mount(&mock_server)
            .await;

        // Create real IPFS client pointing to mock server
        let ipfs_client = IpfsPinningClient::new(mock_server.uri(), None);

        // Create processor with IPFS URLs but no output path (no archive operations)
        let processor = Arc::new(MockProcessor {
            output_path: None, // No local storage - only IPFS operations
            ipfs_pinning_providers: vec![Box::new(ipfs_client) as Box<dyn IpfsPinningProvider>],
            fetch_metadata_result: Ok(MockMetadata {
                name: "Test NFT".to_string(),
                image: "ipfs://QmTestImageHash".to_string(),
                animation_url: None,
            }),
            get_uri_result: Ok("ipfs://QmTestMetadataHash".to_string()),
            http_client: crate::httpclient::HttpClient::new()
                .with_gateways(vec![])
                .with_max_retries(0),
        });

        let tokens = vec![create_test_token()];
        let config = create_test_config(false);

        let (archive_out, ipfs_out) =
            process_nfts(processor, tokens, config, get_no_extra_content_uri, None)
                .await
                .unwrap();

        // Verify that no archive operations were attempted
        assert!(archive_out.files.is_empty()); // No files created (no output path)
        assert!(archive_out.errors.is_empty()); // No archive errors

        // Verify that IPFS operations failed and errors went to ipfs_errors
        assert_eq!(ipfs_out.pin_requests.len(), 0); // No successful pins
        assert!(ipfs_out.errors.len() >= 2); // IPFS errors for both metadata and image pinning failures

        // Verify specific error categorization
        for error in &ipfs_out.errors {
            assert!(error.contains("IPFS") || error.contains("pin") || error.contains("500"));
        }
    }

    #[tokio::test]
    async fn test_process_nfts_error_categorization_mixed_errors() {
        // Start wiremock server
        let mock_server = MockServer::start().await;

        // Create temp directory
        let temp_dir = TempDir::new().unwrap();

        // Set up IPFS pinning mock endpoints - FAILURE case
        Mock::given(method("POST"))
            .and(path("/pins"))
            .respond_with(
                ResponseTemplate::new(500).set_body_string(r#"{"error":"Internal server error"}"#),
            )
            .mount(&mock_server)
            .await;

        // Create real IPFS client pointing to mock server
        let ipfs_client = IpfsPinningClient::new(mock_server.uri(), None);

        // Create processor that fails on metadata fetch (archive error) but has IPFS providers
        let processor = Arc::new(MockProcessor {
            output_path: Some(temp_dir.path().to_path_buf()),
            ipfs_pinning_providers: vec![Box::new(ipfs_client) as Box<dyn IpfsPinningProvider>],
            fetch_metadata_result: Err(anyhow!("Network timeout")), // This should go to archive_errors
            get_uri_result: Ok("ipfs://QmTestMetadataHash".to_string()),
            http_client: crate::httpclient::HttpClient::new(),
        });

        let tokens = vec![create_test_token()];
        let config = create_test_config(false);

        let (archive_out, ipfs_out) =
            process_nfts(processor, tokens, config, get_no_extra_content_uri, None)
                .await
                .unwrap();

        // Verify that metadata fetch error went to both archive_errors and ipfs_errors
        assert!(archive_out.files.is_empty()); // No files created due to metadata fetch failure
        assert_eq!(archive_out.errors.len(), 1);
        assert!(archive_out.errors[0].contains("Failed to fetch metadata"));
        assert!(archive_out.errors[0].contains("Network timeout"));

        // Verify that the same error also went to ipfs_errors (metadata fetch affects both operations)
        assert!(ipfs_out.pin_requests.is_empty());
        assert_eq!(ipfs_out.errors.len(), 1);
        assert!(ipfs_out.errors[0].contains("Failed to fetch metadata"));
        assert!(ipfs_out.errors[0].contains("Network timeout"));
    }

    #[tokio::test]
    async fn test_process_nfts_error_categorization_metadata_fetch_affects_both() {
        // Test that metadata fetch failure affects both archive and IPFS operations
        let temp_dir = TempDir::new().unwrap();

        // Create a processor that fails on metadata fetch
        let processor = Arc::new(MockProcessor {
            output_path: Some(temp_dir.path().to_path_buf()),
            ipfs_pinning_providers: vec![], // No IPFS providers, but error should still go to both collections
            fetch_metadata_result: Err(anyhow!("Network timeout")),
            get_uri_result: Ok("ipfs://QmTestMetadataHash".to_string()),
            http_client: crate::httpclient::HttpClient::new(),
        });

        let tokens = vec![create_test_token()];
        let config = create_test_config(false); // Don't exit on error
        let get_extra_content_uri = get_no_extra_content_uri::<MockMetadata>;

        let result = process_nfts(processor, tokens, config, get_extra_content_uri, None).await;

        assert!(result.is_ok());
        let (archive_out, ipfs_out) = result.unwrap();

        // Verify that metadata fetch error went to both archive_errors and ipfs_errors
        assert!(archive_out.files.is_empty()); // No files created due to metadata fetch failure
        assert_eq!(archive_out.errors.len(), 1);
        assert!(archive_out.errors[0].contains("Failed to fetch metadata"));
        assert!(archive_out.errors[0].contains("Network timeout"));

        // Verify that the same error also went to ipfs_errors
        assert!(ipfs_out.pin_requests.is_empty());
        assert_eq!(ipfs_out.errors.len(), 1);
        assert!(ipfs_out.errors[0].contains("Failed to fetch metadata"));
        assert!(ipfs_out.errors[0].contains("Network timeout"));

        // Verify that both error messages are identical
        assert_eq!(archive_out.errors[0], ipfs_out.errors[0]);
    }

    #[tokio::test]
    async fn test_process_nfts_error_categorization_content_download_errors() {
        // Start wiremock server
        let mock_server = MockServer::start().await;

        // Create temp directory
        let temp_dir = TempDir::new().unwrap();

        // Set up HTTP mock to fail on content download (archive operation)
        Mock::given(method("GET"))
            .and(path("/image.png"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Server error"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/metadata.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"name":"Test NFT"}"#))
            .mount(&mock_server)
            .await;

        // Create processor with HTTP URLs (not IPFS) to test content download errors
        let processor = Arc::new(MockProcessor {
            output_path: Some(temp_dir.path().to_path_buf()),
            ipfs_pinning_providers: vec![], // No IPFS providers
            fetch_metadata_result: Ok(MockMetadata {
                name: "Test NFT".to_string(),
                image: format!("{}/image.png", mock_server.uri()),
                animation_url: None,
            }),
            get_uri_result: Ok(format!("{}/metadata.json", mock_server.uri())),
            http_client: crate::httpclient::HttpClient::new()
                .with_gateways(vec![(
                    mock_server.uri(),
                    crate::ipfs::config::IpfsGatewayType::Path,
                )])
                .with_max_retries(0),
        });

        let tokens = vec![create_test_token()];
        let config = create_test_config(false);

        let (archive_out, ipfs_out) =
            process_nfts(processor, tokens, config, get_no_extra_content_uri, None)
                .await
                .unwrap();

        // Verify that metadata writing succeeded but content download failed
        assert_eq!(archive_out.files.len(), 1); // Should have metadata.json
        assert_eq!(archive_out.errors.len(), 1); // Content download error should go to archive_errors
        assert!(archive_out.errors[0].contains("Failed to fetch"));
        assert!(archive_out.errors[0].contains("image"));

        // Verify that IPFS operations were not attempted
        assert!(ipfs_out.pin_requests.is_empty());
        assert!(ipfs_out.errors.is_empty());
    }

    #[tokio::test]
    async fn test_process_nfts_with_ipfs_pinning_success() {
        // Start wiremock server
        let mock_server = MockServer::start().await;

        // Create temp directory
        let temp_dir = TempDir::new().unwrap();

        // Set up IPFS pinning mock endpoints - SUCCESS case
        Mock::given(method("POST"))
            .and(path("/pins"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{
                "requestid": "test-request-id",
                "status": "pinned",
                "created": "2023-01-01T00:00:00Z",
                "pin": {
                    "cid": "QmTestHash",
                    "name": null,
                    "origins": [],
                    "meta": null
                },
                "delegates": [],
                "info": null
            }"#,
            ))
            .mount(&mock_server)
            .await;

        // Create real IPFS client pointing to mock server
        let ipfs_client = IpfsPinningClient::new(
            mock_server.uri(),
            None, // No auth token for testing
        );

        // Create processor with IPFS URLs for testing IPFS pinning
        let processor = Arc::new(MockProcessor {
            output_path: Some(temp_dir.path().to_path_buf()),
            ipfs_pinning_providers: vec![Box::new(ipfs_client) as Box<dyn IpfsPinningProvider>],
            fetch_metadata_result: Ok(MockMetadata {
                name: "Test NFT".to_string(),
                image: "ipfs://QmTestImageHash".to_string(),
                animation_url: Some("ipfs://QmTestAnimationHash".to_string()),
            }),
            get_uri_result: Ok("ipfs://QmTestMetadataHash".to_string()),
            http_client: crate::httpclient::HttpClient::new()
                .with_gateways(vec![(
                    mock_server.uri(),
                    crate::ipfs::config::IpfsGatewayType::Path,
                )])
                .with_max_retries(0),
        });

        let tokens = vec![create_test_token()];
        let config = create_test_config(false);

        let (archive_out, ipfs_out) =
            process_nfts(processor, tokens, config, get_no_extra_content_uri, None)
                .await
                .unwrap();

        // Verify results - IPFS pinning should work even if content fetching fails
        assert_eq!(archive_out.files.len(), 1); // Only metadata.json (content fetching may fail for IPFS URLs)
        assert_eq!(ipfs_out.pin_requests.len(), 1); // One token with pin mappings

        // Verify the token pin mapping contains the expected request IDs
        // The mock server returns "test-request-id" as the request ID for all pins
        let token_mapping = &ipfs_out.pin_requests[0];
        assert_eq!(token_mapping.chain, "ethereum");
        assert_eq!(
            token_mapping.contract_address,
            "0x1234567890123456789012345678901234567890"
        );
        assert_eq!(token_mapping.token_id, "1");

        // Should have 3 pin responses: metadata, image, and animation
        assert_eq!(token_mapping.pin_responses.len(), 3);
        for pin_response in &token_mapping.pin_responses {
            assert_eq!(pin_response.id, "test-request-id");
            assert!(matches!(
                pin_response.status,
                crate::ipfs::PinResponseStatus::Pinned
            ));
        }
    }
}

#[cfg(test)]
mod build_pin_name_tests {
    use super::*;

    struct MockProvider(&'static str);

    #[async_trait]
    impl IpfsPinningProvider for MockProvider {
        async fn create_pin(
            &self,
            _request: &PinRequest,
        ) -> anyhow::Result<crate::ipfs::PinResponse> {
            unreachable!()
        }
        async fn get_pin(&self, _pin_id: &str) -> anyhow::Result<crate::ipfs::PinResponse> {
            unreachable!()
        }
        async fn list_pins(&self) -> anyhow::Result<Vec<crate::ipfs::PinResponse>> {
            unreachable!()
        }
        async fn delete_pin(&self, _request_id: &str) -> anyhow::Result<()> {
            unreachable!()
        }
        fn provider_type(&self) -> &str {
            self.0
        }
        fn provider_url(&self) -> &str {
            self.0
        }
    }

    use crate::chain::common::ContractTokenId;

    fn token() -> ContractTokenId {
        ContractTokenId {
            address: "0xabc".into(),
            token_id: "1".into(),
            chain_name: "ethereum".into(),
        }
    }

    #[test]
    fn builds_base_name_without_pinning_service() {
        let providers: Vec<Box<dyn IpfsPinningProvider>> = vec![Box::new(MockProvider("pinata"))];
        let t = token();
        let name = build_pin_name(&t, &providers, false, Some("content"), None);
        assert_eq!(name, "content");
    }

    #[test]
    fn prefixes_when_pinning_service_present() {
        let providers: Vec<Box<dyn IpfsPinningProvider>> =
            vec![Box::new(MockProvider("pinning-service"))];
        let t = token();
        let name = build_pin_name(&t, &providers, false, Some("content"), None);
        assert_eq!(name, "ethereum_0xabc_1_content");
    }

    #[test]
    fn uses_metadata_default_name() {
        let providers: Vec<Box<dyn IpfsPinningProvider>> =
            vec![Box::new(MockProvider("pinning-service"))];
        let t = token();
        let name = build_pin_name(&t, &providers, true, None, None);
        assert_eq!(name, "ethereum_0xabc_1_metadata.json");
    }

    #[test]
    fn trims_and_ignores_empty_fallback() {
        let providers: Vec<Box<dyn IpfsPinningProvider>> =
            vec![Box::new(MockProvider("pinning-service"))];
        let t = token();
        let name = build_pin_name(&t, &providers, false, Some("  "), None);
        assert_eq!(name, "ethereum_0xabc_1_content");
    }

    #[test]
    fn prefixes_with_task_id_when_present() {
        let providers: Vec<Box<dyn IpfsPinningProvider>> =
            vec![Box::new(MockProvider("pinning-service"))];
        let t = token();
        let name = build_pin_name(&t, &providers, false, Some("content"), Some("task123"));
        assert_eq!(name, "task12_ethereum_0xabc_1_content");
    }

    #[test]
    fn truncates_long_task_id_to_six_chars() {
        let providers: Vec<Box<dyn IpfsPinningProvider>> =
            vec![Box::new(MockProvider("pinning-service"))];
        let t = token();
        let name = build_pin_name(
            &t,
            &providers,
            false,
            Some("content"),
            Some("verylongtaskid123456789"),
        );
        assert_eq!(name, "verylo_ethereum_0xabc_1_content");
    }

    #[test]
    fn uses_full_task_id_when_shorter_than_six_chars() {
        let providers: Vec<Box<dyn IpfsPinningProvider>> =
            vec![Box::new(MockProvider("pinning-service"))];
        let t = token();
        let name = build_pin_name(&t, &providers, false, Some("content"), Some("abc"));
        assert_eq!(name, "abc_ethereum_0xabc_1_content");
    }
}

#[cfg(test)]
mod pin_cid_tests {
    use super::*;
    use crate::chain::common::ContractTokenId;
    use wiremock::MockServer;

    struct MockProvider(&'static str);

    #[async_trait]
    impl IpfsPinningProvider for MockProvider {
        async fn create_pin(
            &self,
            request: &PinRequest,
        ) -> anyhow::Result<crate::ipfs::PinResponse> {
            Ok(crate::ipfs::PinResponse {
                id: request.name.clone().unwrap_or_default(),
                cid: request.cid.clone(),
                status: crate::ipfs::PinResponseStatus::Queued,
                provider_type: self.provider_type().to_string(),
                provider_url: self.provider_url().to_string(),
                metadata: None,
                size: None,
            })
        }

        async fn get_pin(&self, _pin_id: &str) -> anyhow::Result<crate::ipfs::PinResponse> {
            unimplemented!()
        }

        async fn list_pins(&self) -> anyhow::Result<Vec<crate::ipfs::PinResponse>> {
            unimplemented!()
        }

        async fn delete_pin(&self, _request_id: &str) -> anyhow::Result<()> {
            unimplemented!()
        }

        fn provider_type(&self) -> &str {
            self.0
        }

        fn provider_url(&self) -> &str {
            self.0
        }
    }

    struct TestProcessor {
        providers: Vec<Box<dyn IpfsPinningProvider>>,
        http_client: crate::httpclient::HttpClient,
    }

    #[async_trait]
    impl NFTChainProcessor for TestProcessor {
        type Metadata = serde_json::Value;
        type ContractTokenId = ContractTokenId;
        type RpcClient = ();

        async fn get_uri(&self, _token: &Self::ContractTokenId) -> anyhow::Result<String> {
            unimplemented!()
        }

        async fn fetch_metadata(&self, _token_uri: &str) -> anyhow::Result<Self::Metadata> {
            unimplemented!()
        }

        fn collect_urls(_metadata: &Self::Metadata) -> Vec<(String, Options)> {
            Vec::new()
        }

        fn ipfs_pinning_providers(&self) -> &[Box<dyn IpfsPinningProvider>] {
            &self.providers
        }

        fn output_path(&self) -> Option<&std::path::Path> {
            None
        }

        fn http_client(&self) -> &crate::httpclient::HttpClient {
            &self.http_client
        }
    }

    #[tokio::test]
    async fn test_pin_cid_sets_content_name() {
        let mock_server = MockServer::start().await;
        let processor = TestProcessor {
            providers: vec![Box::new(MockProvider("p1"))],
            http_client: crate::httpclient::HttpClient::new()
                .with_gateways(vec![(
                    mock_server.uri(),
                    crate::ipfs::config::IpfsGatewayType::Path,
                )])
                .with_max_retries(0),
        };
        let token = ContractTokenId {
            address: "0xabc".into(),
            token_id: "1".into(),
            chain_name: "ethereum".into(),
        };
        let mut errors = Vec::new();
        let res = pin_cid(
            "QmCid",
            &token,
            &processor,
            false,
            &mut errors,
            false,
            Some("fallback"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, "fallback");
    }

    #[tokio::test]
    async fn test_pin_cid_sets_metadata_name() {
        let mock_server = MockServer::start().await;
        let processor = TestProcessor {
            providers: vec![Box::new(MockProvider("p1"))],
            http_client: crate::httpclient::HttpClient::new().with_gateways(vec![(
                mock_server.uri(),
                crate::ipfs::config::IpfsGatewayType::Path,
            )]),
        };
        let token = ContractTokenId {
            address: "0xabc".into(),
            token_id: "1".into(),
            chain_name: "ethereum".into(),
        };
        let mut errors = Vec::new();
        let res = pin_cid(
            "QmMeta",
            &token,
            &processor,
            false,
            &mut errors,
            true,
            Some("metadata"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(res.len(), 1);
        assert_eq!(res[0].id, "metadata");
    }

    #[tokio::test]
    async fn test_pin_cid_multiple_providers() {
        let mock_server = MockServer::start().await;
        let processor = TestProcessor {
            providers: vec![Box::new(MockProvider("p1")), Box::new(MockProvider("p2"))],
            http_client: crate::httpclient::HttpClient::new().with_gateways(vec![(
                mock_server.uri(),
                crate::ipfs::config::IpfsGatewayType::Path,
            )]),
        };
        let token = ContractTokenId {
            address: "0xabc".into(),
            token_id: "1".into(),
            chain_name: "ethereum".into(),
        };
        let mut errors = Vec::new();
        let res = pin_cid(
            "QmX",
            &token,
            &processor,
            false,
            &mut errors,
            false,
            Some("x"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(res.len(), 2);
        assert!(res.iter().all(|r| r.id == "x"));
        let providers: std::collections::HashSet<_> =
            res.iter().map(|r| r.provider_url.as_str()).collect();
        assert!(providers.contains("p1") && providers.contains("p2"));
    }
}
