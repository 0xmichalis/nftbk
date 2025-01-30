use crate::url::{
    get_data_url_content, get_data_url_mime_type, get_last_path_segment, get_url, is_data_url,
};
use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info};

pub mod extensions;
pub mod html;

async fn fetch_http_content(url: &str) -> Result<(Vec<u8>, String)> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;

    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .to_string();

    let content = response.bytes().await?.to_vec();

    Ok((content, content_type))
}

pub struct Options {
    pub overriden_filename: Option<String>,
    pub fallback_filename: Option<String>,
    pub fallback_extension: Option<String>,
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
    let mut filename = if let Some(name) = options.overriden_filename {
        name.to_string()
    } else if is_data_url(url) {
        // For data URLs, use content type as filename
        let mime_type = get_data_url_mime_type(url);
        format!(
            "{}.{}",
            options.fallback_filename.unwrap_or("content".to_string()),
            mime_type
        )
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

    if let Some(extension) = options.fallback_extension {
        if !filename.contains('.') {
            filename = format!("{}.{}", filename, extension);
        }
    }

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
        // WEBP
        [b'R', b'I', b'F', b'F', _, _, _, _, b'W', b'E', b'B', b'P', ..] => Some("webp"),
        // MP4
        [0x00, 0x00, 0x00, _, 0x66, 0x74, 0x79, 0x70, 0x6D, 0x70, 0x34, 0x32, ..] => Some("mp4"),
        // QuickTime MOV
        [0x00, 0x00, 0x00, 0x14, 0x66, 0x74, 0x79, 0x70, 0x71, 0x74, 0x20, 0x20, ..] => Some("mov"),
        _ => None,
    }
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

    // Check if file exists before downloading
    if fs::try_exists(&file_path).await? {
        debug!("File already exists at {}", file_path.display());
        return Ok(file_path);
    }

    // Get content based on URL type
    let (mut content, content_type) = if is_data_url(url) {
        get_data_url_content(url)?
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
        debug!("Downloading HTML content from {}. The saved files may be incomplete as they may have more dependencies.", url);
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

    // After the HTML/JSON handling block, add media extension detection:
    // Check for media files if no extension detected
    if file_path.extension().is_none() {
        if let Some(ext) = detect_media_extension(&content) {
            file_path = file_path.with_extension(ext);
            debug!("Detected media extension: {}", ext);
        }
    }

    // Check if file exists again before downloading
    if fs::try_exists(&file_path).await? {
        debug!("File already exists at {}", file_path.display());
        return Ok(file_path);
    }

    info!("Saving {}", file_path.display());
    fs::write(&file_path, &content).await?;

    Ok(file_path)
}
