use std::path::{Path, PathBuf};

use tracing::info;

use crate::content::get_filename;
use crate::content::{extensions, try_exists, write_and_postprocess_file, Options};
use crate::httpclient::fetch::{try_fetch_response, try_head_content_length};
use crate::httpclient::retry::{retry_operation, should_retry};
use crate::httpclient::stream::stream_http_to_file;
use crate::ipfs::config::{IpfsGatewayConfig, IpfsGatewayType, IPFS_GATEWAYS};
use crate::types::DEFAULT_MAX_CONTENT_REQUEST_RETRIES;
use crate::url::{get_data_url, is_data_url, resolve_url_with_gateways};

pub mod fetch;
pub mod retry;
pub mod stream;

#[derive(Clone, Debug)]
pub struct HttpClient {
    pub(crate) ipfs_gateways: Vec<IpfsGatewayConfig>,
    pub(crate) max_retries: u32,
}

impl HttpClient {
    pub fn new() -> Self {
        let ipfs_gateways = IPFS_GATEWAYS.to_vec();
        Self {
            ipfs_gateways,
            max_retries: DEFAULT_MAX_CONTENT_REQUEST_RETRIES,
        }
    }

    pub fn with_gateways(mut self, gateways: Vec<(String, IpfsGatewayType)>) -> Self {
        self.ipfs_gateways = gateways
            .into_iter()
            .map(|(url, gateway_type)| IpfsGatewayConfig {
                url: Box::leak(url.into_boxed_str()),
                gateway_type,
                bearer_token_env: None,
            })
            .collect();
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub async fn fetch(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        if is_data_url(url) {
            return get_data_url(url)
                .ok_or_else(|| anyhow::anyhow!("Failed to parse data URL: {}", url));
        }

        let resolved_url = resolve_url_with_gateways(url, &self.ipfs_gateways);
        let gateways = self.ipfs_gateways.clone();

        let (result, _status) = retry_operation(
            || {
                let url = resolved_url.clone();
                let gateways = gateways.clone();
                Box::pin(async move {
                    match try_fetch_response(&url, &gateways).await {
                        (Ok(response), status) => match response.bytes().await {
                            Ok(b) => (Ok(b.to_vec()), status),
                            Err(e) => (Err(anyhow::anyhow!(e)), status),
                        },
                        (Err(err), status) => (Err(err), status),
                    }
                })
            },
            self.max_retries,
            should_retry,
            &resolved_url,
        )
        .await;
        result
    }

    pub async fn head_content_length(&self, url: &str) -> anyhow::Result<u64> {
        if is_data_url(url) {
            let data = get_data_url(url)
                .ok_or_else(|| anyhow::anyhow!("Failed to parse data URL: {}", url))?;
            return Ok(data.len() as u64);
        }

        let resolved_url = resolve_url_with_gateways(url, &self.ipfs_gateways);
        let gateways = self.ipfs_gateways.clone();

        let (result, _status) = retry_operation(
            || {
                let url = resolved_url.clone();
                let gateways = gateways.clone();
                Box::pin(async move { try_head_content_length(&url, &gateways).await })
            },
            self.max_retries,
            should_retry,
            &resolved_url,
        )
        .await;
        result
    }

    pub async fn fetch_and_write(
        &self,
        url: &str,
        token: &impl crate::chain::common::ContractTokenInfo,
        output_path: &Path,
        options: Options,
    ) -> anyhow::Result<PathBuf> {
        let mut file_path = get_filename(url, token, output_path, options).await?;

        if let Some(existing_path) = try_exists(&file_path).await? {
            tracing::debug!(
                "File already exists at {} (skipping download)",
                existing_path.display()
            );
            return Ok(existing_path);
        }

        let parent = file_path.parent().ok_or_else(|| {
            anyhow::anyhow!("File path has no parent directory: {}", file_path.display())
        })?;
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            anyhow::anyhow!("Failed to create directory {}: {}", parent.display(), e)
        })?;

        if is_data_url(url) {
            let content = get_data_url(url)
                .ok_or_else(|| anyhow::anyhow!("Failed to parse data URL: {}", url))?;
            if !extensions::has_known_extension(&file_path) {
                if let Some(detected_ext) = extensions::detect_media_extension(&content) {
                    let current_path_str = file_path.to_string_lossy();
                    tracing::debug!("Appending detected media extension: {}", detected_ext);
                    file_path = PathBuf::from(format!("{current_path_str}.{detected_ext}"));
                }
            }

            info!("Saving {} (data url)", file_path.display());
            write_and_postprocess_file(&file_path, &content, url).await?;
            info!("Saved {} (data url)", file_path.display());
            return Ok(file_path);
        }

        let resolved_url = resolve_url_with_gateways(url, &self.ipfs_gateways);
        if url == resolved_url {
            info!("Saving {} (url: {})", file_path.display(), url);
        } else {
            info!(
                "Saving {} (original: {}, resolved: {})",
                file_path.display(),
                url,
                resolved_url
            );
        }
        let file_path = self
            .fetch_and_stream_to_file(&resolved_url, &file_path, self.max_retries)
            .await?;

        write_and_postprocess_file(&file_path, &[], url).await?;
        if url == resolved_url {
            info!("Saved {} (url: {})", file_path.display(), url);
        } else {
            info!(
                "Saved {} (original: {}, resolved: {})",
                file_path.display(),
                url,
                resolved_url
            );
        }
        Ok(file_path)
    }

    pub async fn try_fetch_response(
        &self,
        url: &str,
    ) -> (
        anyhow::Result<reqwest::Response>,
        Option<reqwest::StatusCode>,
    ) {
        try_fetch_response(url, &self.ipfs_gateways).await
    }

    pub(crate) async fn fetch_and_stream_to_file(
        &self,
        url: &str,
        file_path: &Path,
        max_retries: u32,
    ) -> anyhow::Result<PathBuf> {
        fetch_and_stream_to_file(url, file_path, max_retries, &self.ipfs_gateways).await
    }
}

async fn fetch_and_stream_to_file(
    url: &str,
    file_path: &Path,
    max_retries: u32,
    gateways: &[IpfsGatewayConfig],
) -> anyhow::Result<PathBuf> {
    let (result, _status) = retry_operation(
        || {
            let url = url.to_string();
            let file_path = file_path.to_path_buf();
            let gateways = gateways.to_owned();
            Box::pin(async move {
                match try_fetch_response(&url, &gateways).await {
                    (Ok(response), status) => {
                        (stream_http_to_file(response, &file_path).await, status)
                    }
                    (Err(err), status) => (Err(err), status),
                }
            })
        },
        max_retries,
        should_retry,
        url,
    )
    .await;
    result
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod fetch_tests {
    use super::*;
    use crate::ipfs::config::IpfsGatewayType;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_fetch_data_url() {
        let client = HttpClient::new();
        let data_url = "data:text/plain;base64,SGVsbG8gV29ybGQ="; // "Hello World" in base64

        let result = client.fetch(data_url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"Hello World");
    }

    #[tokio::test]
    async fn test_fetch_data_url_invalid() {
        let client = HttpClient::new();
        let invalid_data_url = "data:invalid";

        let result = client.fetch(invalid_data_url).await;
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("Failed to parse data URL"));
    }

    #[tokio::test]
    async fn test_fetch_http_url_success() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/test", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200).set_body_string("HTTP Success"))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new();
        let result = client.fetch(&url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"HTTP Success");
    }

    #[tokio::test]
    async fn test_fetch_ipfs_url_success() {
        let mock_server = MockServer::start().await;
        let cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        let ipfs_url = format!("{}/ipfs/{}", mock_server.uri(), cid);

        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", cid)))
            .respond_with(ResponseTemplate::new(200).set_body_string("IPFS Content"))
            .mount(&mock_server)
            .await;

        let client =
            HttpClient::new().with_gateways(vec![(mock_server.uri(), IpfsGatewayType::Path)]);
        let result = client.fetch(&ipfs_url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"IPFS Content");
    }

    #[tokio::test]
    async fn test_fetch_http_url_404() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/not-found", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/not-found"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new();
        let result = client.fetch(&url).await;
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("HTTP error: status 404"));
    }

    #[tokio::test]
    async fn test_fetch_http_url_500_with_retries() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/server-error", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/server-error"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Server Error"))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new().with_max_retries(2);
        let result = client.fetch(&url).await;
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("HTTP error: status 500"));
    }

    #[tokio::test]
    async fn test_fetch_network_error() {
        // Use a URL that will cause a connection error quickly
        // Port 1 is typically not in use and will fail fast
        let invalid_url = "http://127.0.0.1:1/invalid";
        let client = HttpClient::new().with_max_retries(0); // No retries to make it faster

        let result = client.fetch(invalid_url).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_with_custom_retries() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/test", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Success"))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new().with_max_retries(3);
        let result = client.fetch(&url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"Success");
    }

    #[tokio::test]
    async fn test_fetch_with_custom_gateways() {
        let mock_server = MockServer::start().await;
        let cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        let ipfs_url = format!("{}/ipfs/{}", mock_server.uri(), cid);

        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", cid)))
            .respond_with(ResponseTemplate::new(200).set_body_string("Custom Gateway"))
            .mount(&mock_server)
            .await;

        let client =
            HttpClient::new().with_gateways(vec![(mock_server.uri(), IpfsGatewayType::Path)]);
        let result = client.fetch(&ipfs_url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"Custom Gateway");
    }

    #[tokio::test]
    async fn test_fetch_large_response() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/large", mock_server.uri());
        let large_content = "x".repeat(1024 * 1024); // 1MB

        Mock::given(method("GET"))
            .and(path("/large"))
            .respond_with(ResponseTemplate::new(200).set_body_string(large_content.clone()))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new();
        let result = client.fetch(&url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content.len(), 1024 * 1024);
        assert_eq!(content, large_content.as_bytes());
    }

    #[tokio::test]
    async fn test_fetch_binary_content() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/binary", mock_server.uri());
        let binary_content = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]; // PNG header

        Mock::given(method("GET"))
            .and(path("/binary"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(binary_content.clone()))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new();
        let result = client.fetch(&url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, binary_content);
    }

    #[tokio::test]
    async fn test_httpclient_default_implementation() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/default-test", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/default-test"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("Default Implementation Works"),
            )
            .mount(&mock_server)
            .await;

        // Test that Default::default() creates a working HttpClient
        let client = HttpClient::default();
        let result = client.fetch(&url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"Default Implementation Works");

        // Verify that default has the expected configuration
        assert_eq!(client.max_retries, 5);
        assert!(!client.ipfs_gateways.is_empty()); // Should have default IPFS gateways
    }
}

#[cfg(test)]
mod head_content_length_tests {
    use super::*;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn calculates_size_for_data_url() {
        let client = HttpClient::new();
        let data_url = "data:text/plain;base64,SGVsbG8="; // "Hello"
        let size = client.head_content_length(data_url).await.unwrap();
        assert_eq!(size, 5);
    }

    #[tokio::test]
    async fn calculates_size_for_http_resource() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/asset", mock_server.uri());

        Mock::given(method("HEAD"))
            .and(path("/asset"))
            .respond_with(ResponseTemplate::new(200).insert_header("Content-Length", "1024"))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new();
        let size = client.head_content_length(&url).await.unwrap();
        assert_eq!(size, 1024);
    }
}
