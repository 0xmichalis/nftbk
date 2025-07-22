use anyhow::Result;
use async_compression::tokio::bufread::GzipDecoder;
use futures_util::TryStreamExt;
use rand::{thread_rng, Rng};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use tokio::io::AsyncRead;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::time::sleep;
use tokio_util::io::StreamReader;
use tracing::{debug, info, warn};

use crate::content::html::download_html_resources;
use crate::url::all_ipfs_gateway_urls;
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

    // Sanitize filename to prevent path traversal
    let sanitized_filename = sanitize_filename(&filename);

    let file_path = dir_path.join(&sanitized_filename);

    Ok(file_path)
}

/// Remove any path traversal or separator characters from a filename
fn sanitize_filename(filename: &str) -> String {
    // Remove any path separators and parent directory references
    let mut sanitized = String::new();
    for part in filename.split(['/', '\\'].as_ref()) {
        if part == ".." || part == "." || part.is_empty() {
            continue;
        }
        if !sanitized.is_empty() {
            sanitized.push('_');
        }
        sanitized.push_str(part);
    }
    if sanitized.is_empty() {
        "file".to_string()
    } else {
        sanitized
    }
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

fn get_retry_after_delay(resp: &Result<reqwest::Response, reqwest::Error>) -> Option<Duration> {
    let response = match resp {
        Ok(r) => r,
        Err(_) => return None,
    };
    if response.status().as_u16() != 429 {
        return None;
    }
    let retry_after = response.headers().get("Retry-After")?;
    let retry_after_str = retry_after.to_str().ok()?;
    // Try parsing as integer seconds
    if let Ok(secs) = retry_after_str.parse::<u64>() {
        let delay = Duration::from_secs(secs);
        debug!(
            "429 Retry-After header present as integer seconds, parsed delay: {:?}",
            delay
        );
        return Some(delay);
    }
    // Try parsing as HTTP-date
    if let Ok(date) = httpdate::parse_http_date(retry_after_str) {
        let now = std::time::SystemTime::now();
        if let Ok(duration) = date.duration_since(now) {
            debug!(
                "429 Retry-After header present as HTTP-date, parsed delay: {:?}",
                duration
            );
            return Some(duration);
        }
    }
    None
}

/// Helper to fetch a URL with retries, using exponential backoff and jitter. The retry condition is provided as a closure.
async fn fetch_url<F>(
    url: &str,
    max_retries: u32,
    should_retry: F,
) -> anyhow::Result<reqwest::Response>
where
    F: Fn(&Result<reqwest::Response, reqwest::Error>) -> bool,
{
    let client = reqwest::Client::builder()
        .user_agent(crate::USER_AGENT)
        .build()?;
    let mut attempt = 0;
    loop {
        let resp = client.get(url).send().await;
        if !should_retry(&resp) {
            // Not a retriable error, return immediately (Ok or Err)
            return resp.map_err(anyhow::Error::from);
        }
        if attempt >= max_retries {
            // Retries exhausted, return the last result
            return resp.map_err(anyhow::Error::from);
        }
        attempt += 1;
        let base_delay = 2u64.pow(attempt).min(30); // cap at 30s
        let jitter: u64 = thread_rng().gen_range(0..500); // up to 500ms
        let default_delay = Duration::from_secs(base_delay) + Duration::from_millis(jitter);
        let delay = get_retry_after_delay(&resp).unwrap_or(default_delay);
        warn!(
            "Retriable error for {}, retrying in {:?} (attempt {}/{})",
            url, delay, attempt, max_retries
        );
        sleep(delay).await;
    }
}

/// Fetch a URL and retry various errors:
/// - DNS errors
/// - Server errors (5xx)
/// - Other retriable errors
pub async fn fetch_with_retry(url: &str, max_retries: u32) -> anyhow::Result<reqwest::Response> {
    // Define retriable errors and retry predicate
    const RETRIABLE_ERRORS: [&str; 2] = [
        "end of file before message length reached",
        "tcp connect error",
    ];
    let should_retry = |result: &Result<reqwest::Response, reqwest::Error>| match result {
        Ok(resp) => resp.status().is_server_error() || resp.status().as_u16() == 429,
        Err(err) => {
            let err_str = format!("{}", err);
            RETRIABLE_ERRORS
                .iter()
                .any(|substr| err_str.contains(substr))
        }
    };
    // Try the initial URL with retry logic
    let initial_result = fetch_url(url, max_retries, &should_retry).await;
    match initial_result {
        Ok(response) => Ok(response),
        Err(e) => {
            // Fallback to other gateways if the error is a DNS error
            let is_dns = e.is::<reqwest::Error>() && {
                let err = e.downcast_ref::<reqwest::Error>().unwrap();
                err.is_connect() && format!("{}", err).contains("dns error")
            };
            if is_dns {
                if let Some(gateway_urls) = all_ipfs_gateway_urls(url) {
                    let mut last_err = anyhow::anyhow!(e);
                    for new_url in gateway_urls {
                        match fetch_url(&new_url, max_retries, &should_retry).await {
                            Ok(response) => return Ok(response),
                            Err(err) => last_err = err,
                        }
                    }
                    return Err(last_err);
                }
            }
            Err(anyhow::anyhow!(e))
        }
    }
}

// Helper to write file and postprocess (pretty-print JSON, download HTML resources)
async fn write_and_postprocess_file(
    file_path: &Path,
    content: &[u8],
    url: &str,
) -> anyhow::Result<()> {
    let ext_str = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext_str {
        "json" => {
            let data = if content.is_empty() {
                tokio::fs::read(file_path).await?
            } else {
                content.to_vec()
            };
            if let Ok(json_value) = serde_json::from_slice::<Value>(&data) {
                let pretty = serde_json::to_string_pretty(&json_value)?;
                fs::write(file_path, pretty).await?;
            } else {
                fs::write(file_path, &data).await?;
            }
        }
        "html" => {
            let content_str = if content.is_empty() {
                tokio::fs::read_to_string(file_path).await?
            } else {
                String::from_utf8_lossy(content).to_string()
            };
            if !content.is_empty() {
                fs::write(file_path, content).await?;
            }
            let parent = file_path.parent().ok_or_else(|| {
                anyhow::anyhow!("File path has no parent directory: {}", file_path.display())
            })?;
            download_html_resources(&content_str, url, parent).await?;
        }
        _ => {
            if !content.is_empty() {
                fs::write(file_path, content).await?;
            }
            // Otherwise, do nothing (file already written by streaming)
        }
    }
    Ok(())
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
    let parent = file_path.parent().ok_or_else(|| {
        anyhow::anyhow!("File path has no parent directory: {}", file_path.display())
    })?;
    fs::create_dir_all(parent).await?;

    // Handle data URLs (still buffer, as they're usually small)
    if is_data_url(url) {
        let content = get_data_url(url)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse data URL: {}", url))?;
        // Detect media extension from content if not already known from the filename
        if !extensions::has_known_extension(&file_path) {
            if let Some(detected_ext) = extensions::detect_media_extension(&content) {
                let current_path_str = file_path.to_string_lossy();
                debug!("Appending detected media extension: {}", detected_ext);
                file_path = PathBuf::from(format!("{}.{}", current_path_str, detected_ext));
            }
        }

        info!("Saving {} (data url)", file_path.display());
        write_and_postprocess_file(&file_path, &content, url).await?;
        info!("Saved {} (data url)", file_path.display());
        return Ok(file_path);
    }

    // For HTTP URLs, stream directly to disk
    info!("Saving {} (url: {})", file_path.display(), url);
    let content_url = get_url(url);
    let response = fetch_with_retry(&content_url, 5).await?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Failed to fetch content from {} (status: {})",
            url,
            status
        ));
    }
    let file_path = stream_http_to_file(response, &file_path).await?;

    // Pass empty content since we already streamed to disk and only need to postprocess
    write_and_postprocess_file(&file_path, &[], url).await?;

    info!("Saved {} (url: {})", file_path.display(), url);
    Ok(file_path)
}
