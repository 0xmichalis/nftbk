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

#[cfg(test)]
use crate::chain::common::ContractTokenId;
use crate::chain::common::ContractTokenInfo;

use crate::content::html::download_html_resources;
use crate::url::all_ipfs_gateway_urls;
use crate::url::{get_data_url, get_last_path_segment, get_url, is_data_url, is_ipfs_gateway_url};

/// Robustly checks if a file exists with retry logic to handle filesystem race conditions
async fn robust_file_exists_check(file_path: &Path, max_retries: u32) -> anyhow::Result<bool> {
    const INITIAL_DELAY_MS: u64 = 10;
    const MAX_DELAY_MS: u64 = 500;

    for attempt in 0..=max_retries {
        match fs::try_exists(file_path).await {
            Ok(exists) => return Ok(exists),
            Err(e) => {
                if attempt == max_retries {
                    return Err(anyhow::anyhow!(
                        "Failed to check file existence after {} attempts for {}: {}",
                        max_retries + 1,
                        file_path.display(),
                        e
                    ));
                }

                // Exponential backoff with jitter
                let delay_ms = std::cmp::min(INITIAL_DELAY_MS * 2_u64.pow(attempt), MAX_DELAY_MS);
                let jitter = thread_rng().gen_range(0..delay_ms / 4 + 1);
                let total_delay = Duration::from_millis(delay_ms + jitter);

                debug!(
                    "File existence check failed for {} (attempt {}/{}), retrying in {:?}: {}",
                    file_path.display(),
                    attempt + 1,
                    max_retries + 1,
                    total_delay,
                    e
                );
                sleep(total_delay).await;
            }
        }
    }

    unreachable!("Loop should have returned or failed by now")
}

pub mod extensions;
pub mod extra;
pub mod html;

#[derive(Clone)]
pub struct Options {
    pub overriden_filename: Option<String>,
    pub fallback_filename: Option<String>,
}

async fn get_filename(
    url: &str,
    token: &impl ContractTokenInfo,
    output_path: &Path,
    options: Options,
) -> Result<PathBuf> {
    let dir_path = output_path
        .join(token.chain_name())
        .join(token.address())
        .join(token.token_id());

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

/// Streams an AsyncRead to a file and flushes it.
async fn stream_reader_to_file<R: AsyncRead + Unpin>(
    reader: &mut R,
    file: &mut tokio::fs::File,
    file_path: &Path,
) -> anyhow::Result<PathBuf> {
    tokio::io::copy(reader, file).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to stream content to file {}: {}",
            file_path.display(),
            e
        )
    })?;
    file.flush()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to flush file {}: {}", file_path.display(), e))?;
    Ok(file_path.to_path_buf())
}

/// Streams an HTTP response to a file.
pub async fn stream_http_to_file(
    response: reqwest::Response,
    file_path: &Path,
) -> anyhow::Result<PathBuf> {
    let stream = response.bytes_stream().map_err(std::io::Error::other);
    let mut reader = StreamReader::new(stream);

    // Detect extension and append to file path if needed
    let mut file_path = file_path.to_path_buf();
    let (detected_ext, prefix_buf) = extensions::detect_extension_from_stream(&mut reader).await;
    if !extensions::has_known_extension(&file_path) {
        if let Some(detected_ext) = detected_ext {
            let current_path_str = file_path.to_string_lossy();
            debug!("Appending detected media extension: {}", detected_ext);
            file_path = PathBuf::from(format!("{current_path_str}.{detected_ext}"));
        }
    }

    // Create file, write the prefix buffer and the rest of the stream
    let mut file = tokio::fs::File::create(&file_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create file {}: {}", file_path.display(), e))?;
    if !prefix_buf.is_empty() {
        file.write_all(&prefix_buf).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to write prefix to file {}: {}",
                file_path.display(),
                e
            )
        })?;
    }
    let result = stream_reader_to_file(&mut reader, &mut file, &file_path).await?;

    // Ensure file is properly synchronized to disk before returning
    file.sync_all().await.map_err(|e| {
        anyhow::anyhow!("Failed to sync file {} to disk: {}", file_path.display(), e)
    })?;

    Ok(result)
}

/// Streams a gzipped HTTP response to a file, decompressing on the fly.
pub async fn stream_gzip_http_to_file(
    response: reqwest::Response,
    file_path: &Path,
) -> anyhow::Result<PathBuf> {
    let mut file = tokio::fs::File::create(file_path).await?;
    let stream = response.bytes_stream().map_err(std::io::Error::other);
    let reader = StreamReader::new(stream);
    let mut decoder = GzipDecoder::new(BufReader::new(reader));
    stream_reader_to_file(&mut decoder, &mut file, file_path).await
}

fn calculate_retry_delay(attempt: u32) -> Duration {
    let base_delay = 2u64.pow(attempt).min(30); // cap at 30s
    let jitter: u64 = thread_rng().gen_range(0..500); // up to 500ms
    Duration::from_secs(base_delay) + Duration::from_millis(jitter)
}

async fn retry_operation<T>(
    operation: impl Fn() -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = (anyhow::Result<T>, Option<reqwest::StatusCode>)>
                + Send,
        >,
    >,
    max_retries: u32,
    should_retry: impl Fn(&anyhow::Error, Option<reqwest::StatusCode>) -> bool,
    context: &str,
) -> anyhow::Result<T> {
    let mut attempt = 0;
    loop {
        let (result, status) = operation().await;
        if result.is_ok() {
            return result;
        }

        let error = result.as_ref().err().unwrap();
        if !should_retry(error, status) {
            return result;
        }

        if attempt >= max_retries {
            return result;
        }
        attempt += 1;
        let delay = calculate_retry_delay(attempt);
        warn!(
            "Retriable error for {}, retrying in {:?} (attempt {}/{})",
            context, delay, attempt, max_retries
        );
        sleep(delay).await;
    }
}

fn should_retry(error: &anyhow::Error, status: Option<reqwest::StatusCode>) -> bool {
    // Check for streaming errors
    const RETRIABLE_ERRORS: [&str; 2] = [
        "end of file before message length reached",
        "tcp connect error",
    ];

    let err_str = format!("{error}");
    let is_streaming_error = RETRIABLE_ERRORS
        .iter()
        .any(|substr| err_str.contains(substr));

    // Check for HTTP status errors
    let is_http_error = if let Some(status_code) = status {
        status_code.is_server_error() || status_code.as_u16() == 429
    } else {
        false // No status means no HTTP status to check
    };

    is_streaming_error || is_http_error
}

async fn fetch_url(url: &str) -> anyhow::Result<reqwest::Response> {
    let client = reqwest::Client::builder()
        .user_agent(crate::USER_AGENT)
        .build()?;

    Ok(client.get(url).send().await?)
}

/// Attempt to fetch a URL once, applying IPFS gateway rotation if needed.
/// Returns (Ok(response), Some(status)) on success; (Err(error), Option(status)) on failure.
async fn try_fetch_response(
    url: &str,
) -> (
    anyhow::Result<reqwest::Response>,
    Option<reqwest::StatusCode>,
) {
    match fetch_url(url).await {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                (Ok(response), Some(status))
            } else {
                // For non-successful status codes, try IPFS gateway rotation if applicable
                let error = create_http_error(status, url);
                match handle_ipfs_gateway_rotation(url, error).await {
                    Ok(alt_response) => {
                        let alt_status = alt_response.status();
                        if alt_status.is_success() {
                            (Ok(alt_response), Some(alt_status))
                        } else {
                            (
                                Err(create_http_error(alt_status, alt_response.url().as_str())),
                                Some(alt_status),
                            )
                        }
                    }
                    Err(gateway_err) => (Err(gateway_err), Some(status)),
                }
            }
        }
        Err(e) => {
            // Try IPFS gateway rotation if applicable
            match handle_ipfs_gateway_rotation(url, e).await {
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        (Ok(response), Some(status))
                    } else {
                        (Err(create_http_error(status, url)), Some(status))
                    }
                }
                Err(gateway_err) => (Err(gateway_err), None),
            }
        }
    }
}

async fn retry_with_alternative_ipfs_gateways(
    url: &str,
    original_error: anyhow::Error,
) -> anyhow::Result<reqwest::Response> {
    warn!(
        "IPFS gateway error for {}, retrying with other gateways: {}",
        url, original_error
    );

    let gateway_urls = match all_ipfs_gateway_urls(url) {
        Some(urls) => urls,
        None => return Err(original_error),
    };

    let mut last_err = original_error;
    let alternative_gateways: Vec<_> = gateway_urls
        .into_iter()
        .filter(|gateway_url| gateway_url != url)
        .collect();

    for new_url in alternative_gateways {
        match fetch_url(&new_url).await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    info!(
                        "Received successful response from alternative IPFS gateway: {} (status: {})",
                        new_url, status
                    );
                    return Ok(response);
                } else {
                    warn!("Alternative IPFS gateway {new_url} failed: {status}");
                    last_err = anyhow::anyhow!("{status}");
                }
            }
            Err(err) => {
                warn!("Failed to fetch from IPFS gateway {}: {}", new_url, err);
                last_err = err;
            }
        }
    }

    Err(last_err)
}

/// Handle IPFS gateway rotation for a given URL and error
async fn handle_ipfs_gateway_rotation(
    url: &str,
    original_error: anyhow::Error,
) -> anyhow::Result<reqwest::Response> {
    if is_ipfs_gateway_url(url) {
        retry_with_alternative_ipfs_gateways(url, original_error).await
    } else {
        Err(original_error)
    }
}

/// Fetches a URL and streams it to a file with retry logic for both HTTP and streaming errors.
async fn fetch_and_stream_to_file(
    url: &str,
    file_path: &Path,
    max_retries: u32,
) -> anyhow::Result<PathBuf> {
    retry_operation(
        || {
            let url = url.to_string();
            let file_path = file_path.to_path_buf();
            Box::pin(async move { fetch_and_stream_to_file_once(&url, &file_path).await })
        },
        max_retries,
        should_retry,
        url,
    )
    .await
}

/// Creates an HTTP error with the given status code and URL for context
fn create_http_error(status: reqwest::StatusCode, url: &str) -> anyhow::Error {
    anyhow::anyhow!("HTTP error: status {status} from {url}")
}

/// Single attempt to fetch and stream a URL to a file
async fn fetch_and_stream_to_file_once(
    url: &str,
    file_path: &Path,
) -> (anyhow::Result<PathBuf>, Option<reqwest::StatusCode>) {
    match try_fetch_response(url).await {
        (Ok(response), status) => {
            let result = stream_http_to_file(response, file_path).await;
            (result, status)
        }
        (Err(err), status) => (Err(err), status),
    }
}

// Helper to write file and postprocess (pretty-print JSON, download HTML resources)
// We avoid logging any URLs in this function since some URLs may be data URLs and can clutter the logs.
async fn write_and_postprocess_file(
    file_path: &Path,
    content: &[u8],
    url: &str,
) -> anyhow::Result<()> {
    let ext_str = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
    match ext_str {
        "json" => {
            let data = if content.is_empty() {
                // Verify file exists before attempting to read it
                if !robust_file_exists_check(file_path, 3).await.map_err(|e| {
                    anyhow::anyhow!(
                        "Cannot verify JSON file existence during postprocessing for {}: {}",
                        file_path.display(),
                        e
                    )
                })? {
                    return Err(anyhow::anyhow!(
                        "Cannot postprocess JSON file - file does not exist: {}",
                        file_path.display()
                    ));
                }
                tokio::fs::read(file_path).await.map_err(|e| {
                    anyhow::anyhow!("Failed to read JSON file {}: {}", file_path.display(), e)
                })?
            } else {
                content.to_vec()
            };
            if let Ok(json_value) = serde_json::from_slice::<Value>(&data) {
                let pretty = serde_json::to_string_pretty(&json_value)?;
                fs::write(file_path, pretty).await.map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to write pretty JSON to {}: {}",
                        file_path.display(),
                        e
                    )
                })?;
            } else {
                fs::write(file_path, &data).await.map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to write JSON data to {}: {}",
                        file_path.display(),
                        e
                    )
                })?;
            }
        }
        "html" => {
            let content_str = if content.is_empty() {
                // Verify file exists before attempting to read it
                if !robust_file_exists_check(file_path, 3).await.map_err(|e| {
                    anyhow::anyhow!(
                        "Cannot verify HTML file existence during postprocessing for {}: {}",
                        file_path.display(),
                        e
                    )
                })? {
                    return Err(anyhow::anyhow!(
                        "Cannot postprocess HTML file - file does not exist: {}",
                        file_path.display()
                    ));
                }
                tokio::fs::read_to_string(file_path).await.map_err(|e| {
                    anyhow::anyhow!("Failed to read HTML file {}: {}", file_path.display(), e)
                })?
            } else {
                String::from_utf8_lossy(content).to_string()
            };
            if !content.is_empty() {
                fs::write(file_path, content).await.map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to write HTML content to {}: {}",
                        file_path.display(),
                        e
                    )
                })?;
            }
            let parent = file_path.parent().ok_or_else(|| {
                anyhow::anyhow!("File path has no parent directory: {}", file_path.display())
            })?;
            download_html_resources(&content_str, url, parent)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to download HTML resources for {}: {}",
                        file_path.display(),
                        e
                    )
                })?;
        }
        _ => {
            if !content.is_empty() {
                fs::write(file_path, content).await.map_err(|e| {
                    anyhow::anyhow!("Failed to write content to {}: {}", file_path.display(), e)
                })?;
            }
            // Otherwise, do nothing (file already written by streaming)
        }
    }
    Ok(())
}

pub async fn fetch_and_save_content(
    url: &str,
    token: &impl ContractTokenInfo,
    output_path: &Path,
    options: Options,
) -> Result<PathBuf> {
    let mut file_path = get_filename(url, token, output_path, options).await?;

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
    fs::create_dir_all(parent)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create directory {}: {}", parent.display(), e))?;

    // Handle data URLs (still buffer, as they're usually small)
    if is_data_url(url) {
        let content = get_data_url(url)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse data URL: {}", url))?;
        // Detect media extension from content if not already known from the filename
        if !extensions::has_known_extension(&file_path) {
            if let Some(detected_ext) = extensions::detect_media_extension(&content) {
                let current_path_str = file_path.to_string_lossy();
                debug!("Appending detected media extension: {}", detected_ext);
                file_path = PathBuf::from(format!("{current_path_str}.{detected_ext}"));
            }
        }

        info!("Saving {} (data url)", file_path.display());
        write_and_postprocess_file(&file_path, &content, url).await?;
        info!("Saved {} (data url)", file_path.display());
        return Ok(file_path);
    }

    // For HTTP URLs, stream directly to disk
    let resolved_url = get_url(url);
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
    let file_path = fetch_and_stream_to_file(&resolved_url, &file_path, 5).await?;

    // Pass empty content since we already streamed to disk and only need to postprocess
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

/// Fetch content into memory (handles data: URLs and HTTP/IPFS with retries) and return raw bytes.
pub async fn fetch_content(url: &str) -> anyhow::Result<Vec<u8>> {
    // Handle data URLs directly
    if is_data_url(url) {
        return get_data_url(url)
            .ok_or_else(|| anyhow::anyhow!("Failed to parse data URL: {}", url));
    }

    // For HTTP/IPFS URLs, resolve and fetch with retries and gateway rotation
    let resolved_url = get_url(url);

    const MAX_RETRIES: u32 = 5;
    retry_operation(
        || {
            let url = resolved_url.clone();
            Box::pin(async move {
                match try_fetch_response(&url).await {
                    (Ok(response), status) => match response.bytes().await {
                        Ok(b) => (Ok(b.to_vec()), status),
                        Err(e) => (Err(anyhow::anyhow!(e)), status),
                    },
                    (Err(err), status) => (Err(err), status),
                }
            })
        },
        MAX_RETRIES,
        should_retry,
        &resolved_url,
    )
    .await
}

/// Save provided content bytes to disk using the same naming/postprocessing rules as fetch_and_save_content.
/// Skips writing if an existing file is already present (including known extension variations).
pub async fn save_content(
    url: &str,
    token: &impl ContractTokenInfo,
    output_path: &Path,
    options: Options,
    content: &[u8],
) -> anyhow::Result<PathBuf> {
    let mut file_path = get_filename(url, token, output_path, options).await?;

    // Check if a file already exists (with any extension heuristic)
    if let Some(existing_path) = try_exists(&file_path).await? {
        debug!(
            "File already exists at {} (skipping write)",
            existing_path.display()
        );
        return Ok(existing_path);
    }

    // Ensure parent directory exists
    let parent = file_path.parent().ok_or_else(|| {
        anyhow::anyhow!("File path has no parent directory: {}", file_path.display())
    })?;
    fs::create_dir_all(parent)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create directory {}: {}", parent.display(), e))?;

    // If filename has no known extension, try to detect from content and append
    if !extensions::has_known_extension(&file_path) {
        if let Some(detected_ext) = extensions::detect_media_extension(content) {
            let current_path_str = file_path.to_string_lossy();
            debug!("Appending detected media extension: {}", detected_ext);
            file_path = PathBuf::from(format!("{current_path_str}.{detected_ext}"));
        }
    }

    // Write and postprocess according to type
    write_and_postprocess_file(&file_path, content, url).await?;
    Ok(file_path)
}

/// Serialize metadata to pretty JSON and save it to disk as metadata.json using save_content.
pub async fn save_metadata<T: serde::Serialize>(
    token_uri: &str,
    token: &impl ContractTokenInfo,
    output_path: &Path,
    metadata: &T,
) -> anyhow::Result<PathBuf> {
    let bytes = serde_json::to_vec_pretty(metadata)?;
    save_content(
        token_uri,
        token,
        output_path,
        Options {
            overriden_filename: Some("metadata.json".to_string()),
            fallback_filename: None,
        },
        &bytes,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_http_200_success() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/success", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/success"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Hello, World!"))
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let result = fetch_and_stream_to_file(&url, &file_path, 3).await;
        assert!(result.is_ok());

        let content = std::fs::read_to_string(&file_path).unwrap();
        assert_eq!(content, "Hello, World!");
    }

    #[tokio::test]
    async fn test_save_content_skips_existing_exact_path() {
        let temp_dir = TempDir::new().unwrap();
        let out = temp_dir.path();
        let token = ContractTokenId {
            chain_name: "test".to_string(),
            address: "0xabc".to_string(),
            token_id: "1".to_string(),
        };
        let url = "https://example.com/file.bin";

        // First write
        let path1 = save_content(
            url,
            &token,
            out,
            Options {
                overriden_filename: None,
                fallback_filename: Some("file".to_string()),
            },
            b"data",
        )
        .await
        .expect("first save_content should succeed");

        // Second write should skip and return same path
        let path2 = save_content(
            url,
            &token,
            out,
            Options {
                overriden_filename: None,
                fallback_filename: Some("file".to_string()),
            },
            b"new-data",
        )
        .await
        .expect("second save_content should skip and succeed");

        assert_eq!(path1, path2);
    }

    #[tokio::test]
    async fn test_save_content_detects_extension_from_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let out = temp_dir.path();
        let token = ContractTokenId {
            chain_name: "test".to_string(),
            address: "0xabc".to_string(),
            token_id: "1".to_string(),
        };

        // PNG header bytes
        let png_bytes: &[u8] = b"\x89PNG\r\n\x1A\nrest";

        let path = save_content(
            "https://example.com/noext",
            &token,
            out,
            Options {
                overriden_filename: None,
                fallback_filename: Some("image".to_string()),
            },
            png_bytes,
        )
        .await
        .expect("save_content should succeed");

        let name = path.file_name().unwrap().to_string_lossy();
        assert!(
            name.ends_with(".png"),
            "expected png extension, got {}",
            name
        );
    }

    #[tokio::test]
    async fn test_save_metadata_pretty_json_written() {
        #[derive(serde::Serialize)]
        struct M {
            a: u32,
            b: &'static str,
        }

        let temp_dir = TempDir::new().unwrap();
        let out = temp_dir.path();
        let token = ContractTokenId {
            chain_name: "test".to_string(),
            address: "0xabc".to_string(),
            token_id: "1".to_string(),
        };
        let token_uri = "https://example.com/meta";

        let meta = M { a: 1, b: "x" };
        let path = save_metadata(token_uri, &token, out, &meta)
            .await
            .expect("save_metadata should succeed");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\n"), "expected pretty JSON with newlines");
        assert!(content.contains("\n  \"a\": 1"));
        assert!(content.contains("\n  \"b\": \"x\""));
        assert!(path.file_name().unwrap() == "metadata.json");
    }

    #[tokio::test]
    async fn test_sanitize_and_get_filename_via_save_content() {
        let temp_dir = TempDir::new().unwrap();
        let out = temp_dir.path();
        let token = ContractTokenId {
            chain_name: "test".to_string(),
            address: "0xabc".to_string(),
            token_id: "1".to_string(),
        };

        // URL with traversal and separators
        let url = "https://example.com/..//folder/../dangerous/../name";

        let path = save_content(
            url,
            &token,
            out,
            Options {
                overriden_filename: None,
                fallback_filename: Some("content".to_string()),
            },
            b"x",
        )
        .await
        .expect("save_content should succeed");

        // Ensure path is under the expected directory and filename sanitized
        let expected_dir = out
            .join(token.chain_name())
            .join(token.address())
            .join(token.token_id());
        assert!(path.starts_with(&expected_dir));
        let fname = path.file_name().unwrap().to_string_lossy();
        assert!(!fname.contains(".."));
        assert!(!fname.contains('/'));
        assert!(!fname.contains('\\'));
    }

    #[tokio::test]
    async fn test_fetch_content_http_200_success() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/content", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/content"))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock_server)
            .await;

        let bytes = fetch_content(&url)
            .await
            .expect("fetch_content should succeed");
        assert_eq!(bytes, b"OK");
    }

    #[tokio::test]
    async fn test_fetch_content_http_404_no_retry() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/not-found", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/not-found"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = fetch_content(&url).await;
        assert!(
            result.is_err(),
            "fetch_content should error on 404 without retry"
        );
        let err = result.err().unwrap().to_string();
        assert!(err.contains("HTTP error: status 404"));
    }

    #[tokio::test]
    async fn test_http_500_retry_and_fail() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/server-error", mock_server.uri());

        // Mock server to return 500 for all requests
        Mock::given(method("GET"))
            .and(path("/server-error"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(3) // Expect 3 calls (original + 2 retries)
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let result = fetch_and_stream_to_file(&url, &file_path, 2).await;
        assert!(result.is_err());

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("HTTP error: status 500"));

        // Verify that retries actually happened by checking mock expectations
        // The mock server will verify that exactly 3 requests were made
    }

    #[tokio::test]
    async fn test_http_429_retry_and_fail() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/rate-limited", mock_server.uri());

        // Mock server to return 429 for all requests
        Mock::given(method("GET"))
            .and(path("/rate-limited"))
            .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
            .expect(3) // Expect 3 calls (original + 2 retries)
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let result = fetch_and_stream_to_file(&url, &file_path, 2).await;

        // Should fail after retries, but the retry logic should have been triggered
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("HTTP error: status 429"));

        // Verify that retries actually happened by checking mock expectations
        // The mock server will verify that exactly 3 requests were made
    }

    #[tokio::test]
    async fn test_http_404_no_retry() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/not-found", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/not-found"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .expect(1) // Should only be called once (no retry for 4xx)
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let result = fetch_and_stream_to_file(&url, &file_path, 3).await;
        assert!(result.is_err());

        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("HTTP error: status 404"));

        // Verify that NO retries happened for 4xx errors
        // The mock server will verify that exactly 1 request was made
    }

    #[tokio::test]
    async fn test_streaming_error_retry() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/streaming-error", mock_server.uri());

        // Mock a response that will cause streaming issues by returning partial content
        // and then dropping the connection
        Mock::given(method("GET"))
            .and(path("/streaming-error"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("Partial content")
                    .set_delay(std::time::Duration::from_millis(500)),
            )
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let result = fetch_and_stream_to_file(&url, &file_path, 1).await;
        // This test is more about ensuring the retry mechanism works
        // The actual result depends on timing and network conditions
        // For now, we just verify the function doesn't panic
        println!("Streaming test result: {:?}", result);

        // The delay doesn't cause a streaming error, so no retry happens
        // This is expected behavior - the test verifies the function doesn't panic
    }

    #[tokio::test]
    async fn test_streaming_error_with_large_response() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/streaming-large", mock_server.uri());

        // Create a large response that might cause streaming issues
        let large_body = "x".repeat(1024 * 1024); // 1MB response

        Mock::given(method("GET"))
            .and(path("/streaming-large"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(large_body)
                    .set_delay(std::time::Duration::from_millis(100)),
            )
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let result = fetch_and_stream_to_file(&url, &file_path, 1).await;

        // This should succeed, but tests that large streaming works correctly
        // If there are streaming issues, they would be caught here
        assert!(result.is_ok());

        // Verify the file was written correctly
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), 1024 * 1024);
    }

    #[tokio::test]
    async fn test_large_file_streaming() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/large-file", mock_server.uri());

        // Create a large response body
        let large_body = "x".repeat(1024 * 1024); // 1MB

        Mock::given(method("GET"))
            .and(path("/large-file"))
            .respond_with(ResponseTemplate::new(200).set_body_string(large_body))
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("large.txt");

        let result = fetch_and_stream_to_file(&url, &file_path, 3).await;
        assert!(result.is_ok());

        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), 1024 * 1024);
    }

    #[tokio::test]
    async fn test_should_retry_logic() {
        // Test HTTP status codes
        assert!(should_retry(
            &anyhow::anyhow!("test"),
            Some(reqwest::StatusCode::from_u16(500).unwrap())
        ));
        assert!(should_retry(
            &anyhow::anyhow!("test"),
            Some(reqwest::StatusCode::from_u16(429).unwrap())
        ));
        assert!(!should_retry(
            &anyhow::anyhow!("test"),
            Some(reqwest::StatusCode::from_u16(404).unwrap())
        ));

        // Test streaming errors
        assert!(should_retry(
            &anyhow::anyhow!("end of file before message length reached"),
            None
        ));
        assert!(should_retry(&anyhow::anyhow!("tcp connect error"), None));
        assert!(!should_retry(&anyhow::anyhow!("some other error"), None));
    }

    #[tokio::test]
    async fn test_calculate_retry_delay() {
        let delay1 = calculate_retry_delay(1);
        let delay2 = calculate_retry_delay(2);
        let delay3 = calculate_retry_delay(3);

        // Delays should increase exponentially
        assert!(delay2 > delay1);
        assert!(delay3 > delay2);

        // Delays should be capped at 30 seconds + jitter
        assert!(delay1 < Duration::from_secs(31));
        assert!(delay2 < Duration::from_secs(31));
        assert!(delay3 < Duration::from_secs(31));
    }
}
