use crate::url::{get_data_url, get_last_path_segment, get_url, is_data_url};
use anyhow::Result;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, error, info};

pub mod extensions;
pub mod extra;
pub mod html;

async fn fetch_http_content(url: &str) -> Result<Vec<u8>> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;

    let status = response.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch content from {} (status: {})",
            url,
            status
        ));
    }

    let content = response.bytes().await?.to_vec();

    Ok(content)
}

pub struct Options {
    pub overriden_filename: Option<String>,
    pub fallback_filename: Option<String>,
}

async fn get_filename(
    url: &str,
    chain: &str,
    contract_address: &str,
    token_id: &str,
    output_path: &Path,
    options: Options,
) -> Result<PathBuf> {
    let dir_path = output_path
        .join(chain)
        .join(contract_address)
        .join(token_id);

    // Determine filename
    let filename = if let Some(name) = options.overriden_filename {
        name.to_string()
    } else if is_data_url(url) {
        options.fallback_filename.unwrap_or("content".to_string())
    } else {
        // For regular URLs, try to extract filename from path
        get_last_path_segment(
            url,
            options
                .fallback_filename
                .unwrap_or("content".to_string())
                .as_str(),
        )
    };

    let file_path = dir_path.join(&filename);

    Ok(file_path)
}

async fn try_exists(path: &Path) -> Result<Option<PathBuf>> {
    // If the file exists with exact path, return early
    if fs::try_exists(path).await? {
        debug!("File exists at exact path: {}", path.display());
        return Ok(Some(path.to_path_buf()));
    }

    // If the path ends with a known extension and the file does not exist, then
    // we know the file does not exist and needs to be downloaded.
    if extensions::has_known_extension(path) {
        debug!(
            "File with known extension does not exist: {}",
            path.display()
        );
        return Ok(None);
    }

    // If the URL does not contain a file extension then we can use an additional heuristic
    // to check if the file exists by checking for any existing file with a known extension.
    // This is not foolproof and may need to be reconsidered in the future but for now it is
    // needed because sometimes we add the extension to the filename after the fact.
    if let Some(existing_path) = extensions::find_path_with_known_extension(path).await? {
        debug!(
            "File exists with known extension: {}",
            existing_path.display()
        );
        return Ok(Some(existing_path));
    }

    Ok(None)
}

pub async fn fetch_and_save_content(
    url: &str,
    chain: &str,
    contract_address: &str,
    token_id: &str,
    output_path: &Path,
    options: Options,
) -> Result<PathBuf> {
    let mut file_path =
        get_filename(url, chain, contract_address, token_id, output_path, options).await?;

    // Check if file exists (with any extension) using base path and url
    if let Some(existing_path) = try_exists(&file_path).await? {
        debug!(
            "File already exists at {} (skipping download)",
            existing_path.display()
        );
        return Ok(existing_path);
    }

    // Get content based on URL type
    let content = if is_data_url(url) {
        get_data_url(url).unwrap()
    } else {
        let content_url = get_url(url);
        // TODO: Rotate IPFS gateways to handle rate limits
        match fetch_http_content(&content_url).await {
            Ok(data) => data,
            Err(e) => {
                error!("Failed to fetch content from {}: {}", content_url, e);
                return Err(e);
            }
        }
    };

    // Create directory and save content
    if let Err(e) = fs::create_dir_all(file_path.parent().unwrap()).await {
        error!(
            "Failed to create directory {}: {}",
            file_path.parent().unwrap().display(),
            e
        );
        return Err(anyhow::anyhow!(e));
    }

    // Detect media extension from content if not already known from the filename
    if !extensions::has_known_extension(&file_path) {
        if let Some(detected_ext) = extensions::detect_media_extension(&content) {
            let current_path_str = file_path.to_string_lossy();
            debug!("Appending detected media extension: {}", detected_ext);
            file_path = PathBuf::from(format!("{}.{}", current_path_str, detected_ext));
        }
    }

    info!("Saving file: {} (url: {})", file_path.display(), url);
    let write_result = match file_path.extension().unwrap_or_default().to_str() {
        Some("json") => {
            let json_value: Value = match serde_json::from_slice(&content) {
                Ok(val) => val,
                Err(e) => {
                    error!("Failed to parse JSON for {}: {}", file_path.display(), e);
                    return Err(anyhow::anyhow!(e));
                }
            };
            let pretty = match serde_json::to_string_pretty(&json_value) {
                Ok(val) => val,
                Err(e) => {
                    error!(
                        "Failed to pretty-print JSON for {}: {}",
                        file_path.display(),
                        e
                    );
                    return Err(anyhow::anyhow!(e));
                }
            };
            info!("Saving {}", file_path.display());
            fs::write(&file_path, pretty)
                .await
                .map_err(|e| anyhow::anyhow!(e))
        }
        Some("html") => {
            let content_str = String::from_utf8_lossy(&content).to_string();
            info!("Saving {}", file_path.display());
            let write_res = fs::write(&file_path, &content)
                .await
                .map_err(|e| anyhow::anyhow!(e));
            if write_res.is_ok() {
                // Now call download_html_resources after content is dropped
                if let Err(e) = crate::content::html::download_html_resources(
                    &content_str,
                    url,
                    file_path.parent().unwrap(),
                )
                .await
                {
                    error!(
                        "Failed to download HTML resources for {}: {}",
                        file_path.display(),
                        e
                    );
                    return Err(e);
                }
            }
            write_res
        }
        _ => fs::write(&file_path, &content)
            .await
            .map_err(|e| anyhow::anyhow!(e)),
    };
    match write_result {
        Ok(_) => debug!("Successfully saved file: {}", file_path.display()),
        Err(e) => {
            error!("Failed to write file {}: {}", file_path.display(), e);
            return Err(e);
        }
    }

    Ok(file_path)
}
