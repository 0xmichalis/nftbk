use std::path::{Path, PathBuf};
use tracing::info;

use crate::content::get_filename;
use crate::content::{extensions, try_exists, write_and_postprocess_file, Options};
use crate::httpclient::fetch::try_fetch_response;
use crate::httpclient::retry::{retry_operation, should_retry};
use crate::httpclient::stream::stream_http_to_file;
use crate::ipfs::config::{IpfsGatewayConfig, IpfsGatewayType, IPFS_GATEWAYS};
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
            max_retries: 5,
        }
    }

    pub fn with_gateways(mut self, gateways: Vec<(String, IpfsGatewayType)>) -> Self {
        self.ipfs_gateways = gateways
            .into_iter()
            .map(|(url, gateway_type)| IpfsGatewayConfig {
                url: Box::leak(url.into_boxed_str()),
                gateway_type,
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

        retry_operation(
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
        .await
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
    retry_operation(
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
    .await
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}
