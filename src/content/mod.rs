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

async fn try_exists(path: &Path) -> Result<bool> {
    // If the file exists with exact path, return early
    if fs::try_exists(path).await? {
        return Ok(true);
    }

    // If the file already has an extension then we know it does not exist
    if path.extension().is_some() {
        return Ok(false);
    }

    // If the file has no extension we can check parent directory for files with same stem.
    // For now we ignore any matches but it may be that we need to change this in the future.
    let file_stem = path.file_stem().unwrap().to_string_lossy().to_string();
    if let Some(parent) = path.parent() {
        if fs::try_exists(parent).await? {
            let mut dir = fs::read_dir(parent).await?;
            while let Some(entry) = dir.next_entry().await? {
                if let Some(existing_stem) = entry.path().file_stem() {
                    if existing_stem.to_string_lossy() == file_stem {
                        debug!(
                            "File already exists with extension: {}",
                            entry.path().display()
                        );
                        return Ok(true);
                    }
                }
            }
        }
    }

    Ok(false)
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

    // Check if file exists (with any extension)
    if try_exists(&file_path).await? {
        debug!("File already exists at {}", file_path.display());
        return Ok(file_path);
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

    // Detect media extension if no extension is present
    if file_path.extension().is_none() {
        if let Some(ext) = detect_media_extension(&content) {
            debug!("Detected media extension: {}", ext);
            file_path = file_path.with_extension(ext);
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
