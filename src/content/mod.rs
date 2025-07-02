use anyhow::Result;
use async_compression::tokio::bufread::GzipDecoder;
use futures_util::TryStreamExt;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncRead;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio_util::io::StreamReader;
use tracing::{debug, info};

use crate::content::html::download_html_resources;
use crate::url::{get_data_url, get_last_path_segment, get_url, is_data_url};

pub mod extensions;
pub mod extra;
pub mod html;

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

pub struct Options {
    pub overriden_filename: Option<String>,
    pub fallback_filename: Option<String>,
}

/// Streams an AsyncRead to a file and flushes it.
async fn stream_response_to_file<R: AsyncRead + Unpin>(
    reader: &mut R,
    file: &mut tokio::fs::File,
) -> anyhow::Result<()> {
    tokio::io::copy(reader, file).await?;
    file.flush().await?;
    Ok(())
}

/// Streams a reqwest::Response to a file, detecting extension if needed.
pub async fn stream_http_to_file(
    response: reqwest::Response,
    file_path: &Path,
) -> anyhow::Result<PathBuf> {
    let stream = response
        .bytes_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
    let mut reader = StreamReader::new(stream);

    // Use the helper to detect extension
    let mut file_path = file_path.to_path_buf();
    let (detected_ext, prefix_buf) = extensions::detect_extension_from_stream(&mut reader).await;
    if !extensions::has_known_extension(&file_path) {
        if let Some(detected_ext) = detected_ext {
            let current_path_str = file_path.to_string_lossy();
            debug!("Appending detected media extension: {}", detected_ext);
            file_path = PathBuf::from(format!("{}.{}", current_path_str, detected_ext));
        }
    }

    // Create file and write the buffer (now we have the prefix buffer to write first)
    let mut file = tokio::fs::File::create(&file_path).await?;
    if !prefix_buf.is_empty() {
        file.write_all(&prefix_buf).await?;
    }
    tokio::io::copy(&mut reader, &mut file).await?;
    file.flush().await?;

    Ok(file_path)
}

/// Streams a gzipped reqwest::Response to a file, decompressing on the fly.
pub async fn stream_gzip_http_to_file(
    response: reqwest::Response,
    file_path: &Path,
) -> anyhow::Result<()> {
    let mut file = tokio::fs::File::create(file_path).await?;
    let stream = response
        .bytes_stream()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
    let reader = StreamReader::new(stream);
    let mut decoder = GzipDecoder::new(BufReader::new(reader));
    stream_response_to_file(&mut decoder, &mut file).await
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

    // Create directory for the file
    fs::create_dir_all(file_path.parent().unwrap()).await?;

    // Handle data URLs (still buffer, as they're usually small)
    if is_data_url(url) {
        let content = get_data_url(url).unwrap();
        // Detect media extension from content if not already known from the filename
        if !extensions::has_known_extension(&file_path) {
            if let Some(detected_ext) = extensions::detect_media_extension(&content) {
                let current_path_str = file_path.to_string_lossy();
                debug!("Appending detected media extension: {}", detected_ext);
                file_path = PathBuf::from(format!("{}.{}", current_path_str, detected_ext));
            }
        }
        info!("Saving {} (url: {})", file_path.display(), url);
        let write_result = match file_path.extension().unwrap_or_default().to_str() {
            Some("json") => {
                let json_value: Value = serde_json::from_slice(&content)?;
                let pretty = serde_json::to_string_pretty(&json_value)?;
                fs::write(&file_path, pretty)
                    .await
                    .map_err(|e| anyhow::anyhow!(e))
            }
            Some("html") => {
                let content_str = String::from_utf8_lossy(&content).to_string();
                let write_res = fs::write(&file_path, &content)
                    .await
                    .map_err(|e| anyhow::anyhow!(e));
                if write_res.is_ok() {
                    download_html_resources(&content_str, url, file_path.parent().unwrap()).await?;
                }
                write_res
            }
            _ => fs::write(&file_path, &content)
                .await
                .map_err(|e| anyhow::anyhow!(e)),
        };
        write_result?;
        debug!("Successfully saved {}", file_path.display());
        return Ok(file_path);
    }

    // For HTTP/IPFS URLs, stream directly to disk and detect extension
    let content_url = get_url(url);
    let client = reqwest::Client::new();
    let response = client.get(&content_url).send().await?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch content from {} (status: {})",
            url,
            status
        ));
    }
    let file_path = stream_http_to_file(response, &file_path).await?;

    // If the file is JSON, pretty-print it
    if file_path.extension().and_then(|e| e.to_str()) == Some("json") {
        let content = tokio::fs::read(&file_path).await?;
        if let Ok(json_value) = serde_json::from_slice::<Value>(&content) {
            let pretty = serde_json::to_string_pretty(&json_value)?;
            fs::write(&file_path, pretty).await?;
        }
    }

    debug!("Successfully saved {}", file_path.display());
    Ok(file_path)
}
