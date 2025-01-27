use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{info, warn};
use url::{get_data_url_mime_type, get_last_path_segment, get_url, is_data_url};

pub mod extensions;
pub mod html;
pub mod url;

async fn fetch_http_content(url: &str) -> Result<(Vec<u8>, String)> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;

    // Get content type, defaulting to "application/octet-stream" if not specified
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();

    let content = response.bytes().await?.to_vec();

    Ok((content, content_type))
}

async fn get_filename(
    url: &str,
    chain: &str,
    contract_address: &str,
    token_id: &str,
    output_path: &Path,
    default_file_name: Option<&str>,
) -> Result<PathBuf> {
    let dir_path = output_path
        .join(chain)
        .join(contract_address)
        .join(token_id);

    // Determine filename
    let file_name = if let Some(name) = default_file_name {
        name.to_string()
    } else if is_data_url(url) {
        // For data URLs, use content type as filename
        let mime_type = get_data_url_mime_type(url);
        format!("content.{}", mime_type)
    } else {
        // For regular URLs, try to extract filename from path
        get_last_path_segment(url, "content")
    };

    let file_path = dir_path.join(&file_name);

    Ok(file_path)
}

pub async fn fetch_and_save_content(
    url: &str,
    chain: &str,
    contract_address: &str,
    token_id: &str,
    output_path: &Path,
    file_name: Option<&str>,
) -> Result<PathBuf> {
    let mut file_path = get_filename(
        url,
        chain,
        contract_address,
        token_id,
        output_path,
        file_name,
    )
    .await?;

    // Check if file exists before downloading
    if fs::try_exists(&file_path).await? {
        info!("File already exists at {}", file_path.display());
        // TODO: Instead of returning we should check whether we can
        // download additional files, in case this is an HTML file
        return Ok(file_path);
    }

    // Get content based on URL type
    let (mut content, content_type) = if is_data_url(url) {
        let (content, mime_type) = url::get_data_url_content(url)?;
        (content, format!("application/{}", mime_type))
    } else {
        let content_url = get_url(url);
        // TODO: Rotate IPFS gateways to handle rate limits
        fetch_http_content(&content_url).await?
    };

    // Create directory and save content
    fs::create_dir_all(file_path.parent().unwrap()).await?;

    if content_type.contains("text/html") || content_type.contains("application/xhtml") {
        if !file_path.to_string_lossy().ends_with(".html") {
            file_path = file_path.with_extension("html");
        }
        warn!("Downloading HTML content from {}. The saved files may be incomplete as they may have more dependencies.", url);
        let content_str = String::from_utf8_lossy(&content);
        html::download_html_resources(&content_str, url, file_path.parent().unwrap()).await?;
    } else if content_type.contains("application/json") {
        // Try to parse and format JSON content
        if let Ok(content_str) = String::from_utf8(content.clone()) {
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&content_str) {
                content = serde_json::to_string_pretty(&json_value)?.into();
            }
        }
    }

    // TODO: Check whether the file already exists before overwriting
    // if the file is HTML.
    info!("Saving {}", file_path.display());
    fs::write(&file_path, &content).await?;

    Ok(file_path)
}
