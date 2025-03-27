use crate::url::{get_data_url, get_last_path_segment, get_url, is_data_url};
use anyhow::Result;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info};

pub mod extensions;
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

fn detect_media_extension(content: &[u8]) -> Option<&'static str> {
    // Check for common image/video formats
    match content {
        // PNG
        [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, ..] => Some("png"),
        // JPEG
        [0xFF, 0xD8, 0xFF, ..] => Some("jpg"),
        // GIF
        [b'G', b'I', b'F', b'8', b'9', b'a', ..] => Some("gif"),
        [b'G', b'I', b'F', b'8', b'7', b'a', ..] => Some("gif"),
        // WEBP
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => Some("webp"),
        // MP3
        [0x49, 0x44, 0x33, ..] => Some("mp3"),
        // MP4
        [0x00, 0x00, 0x00, _, 0x66, 0x74, 0x79, 0x70, 0x6D, 0x70, 0x34, 0x32, ..] => Some("mp4"),
        [0x00, 0x00, 0x00, _, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6F, 0x6D, ..] => Some("mp4"),
        // QuickTime MOV
        [0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x71, 0x74, 0x20, 0x20, ..] => Some("mov"),
        // MPG
        [0x00, 0x00, 0x01, 0xBA, ..] => Some("mpg"),
        // HTML
        [b'<', b'h', b't', b'm', b'l', ..] => Some("html"),
        // HTML starting with <!DOCTYPE html
        [0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45, 0x20, 0x68, 0x74, 0x6D, 0x6C, ..] => {
            Some("html")
        }
        // JSON
        [b'{', ..] => Some("json"),
        // GLB
        [0x47, 0x4C, 0x42, 0x0D, 0x0A, 0x1A, 0x0A, ..] => Some("glb"),
        [0x67, 0x6C, 0x54, 0x46, 0x02, 0x00, 0x00, 0x00, ..] => Some("glb"),
        _ => None,
    }
}

async fn try_exists(path: &Path) -> Result<Option<PathBuf>> {
    // If the file exists with exact path, return early
    if fs::try_exists(path).await? {
        debug!("File exists at exact path: {}", path.display());
        return Ok(Some(path.to_path_buf()));
    }

    // If the file already has a known extension then we know it does not exist
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

    // Check if file exists (with any extension) using base path
    if let Some(existing_path) = try_exists(&file_path).await? {
        debug!("File already exists at {}", existing_path.display());
        return Ok(existing_path);
    }

    // Get content based on URL type
    let mut content = if is_data_url(url) {
        get_data_url(url).unwrap()
    } else {
        let content_url = get_url(url);
        // TODO: Rotate IPFS gateways to handle rate limits
        fetch_http_content(&content_url).await?
    };

    // Create directory and save content
    fs::create_dir_all(file_path.parent().unwrap()).await?;

    // Always detect media extension from content and append it if not already present
    if let Some(detected_ext) = detect_media_extension(&content) {
        // Only append extension if path doesn't already have a known extension
        if !extensions::has_known_extension(&file_path) {
            let current_path_str = file_path.to_string_lossy();
            debug!("Appending detected media extension: {}", detected_ext);
            file_path = PathBuf::from(format!("{}.{}", current_path_str, detected_ext));
        }
    }

    match file_path.extension().unwrap_or_default().to_str() {
        Some("json") => {
            let json_value: Value = serde_json::from_slice(&content)?;
            content = serde_json::to_string_pretty(&json_value)?.into();
        }
        Some("html") => {
            let content_str = String::from_utf8_lossy(&content);
            html::download_html_resources(&content_str, url, file_path.parent().unwrap()).await?;
        }
        _ => {}
    }

    info!("Saving {}", file_path.display());
    fs::write(&file_path, &content).await?;

    Ok(file_path)
}
