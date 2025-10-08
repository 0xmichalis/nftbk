use anyhow::Result;
use rand::{thread_rng, Rng};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::fs;
use tokio::time::sleep;
use tracing::debug;

use crate::chain::common::ContractTokenInfo;
use crate::content::html::download_html_resources;
use crate::url::{get_last_path_segment, is_data_url};

pub mod extensions;
pub mod extra;
pub mod html;

#[derive(Clone)]
pub struct Options {
    pub overriden_filename: Option<String>,
    pub fallback_filename: Option<String>,
}

pub(crate) async fn get_filename(
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

pub(crate) async fn try_exists(path: &Path) -> Result<Option<PathBuf>> {
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

// Helper to write file and postprocess (pretty-print JSON, download HTML resources)
// We avoid logging any URLs in this function since some URLs may be data URLs and can clutter the logs.
pub(crate) async fn write_and_postprocess_file(
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

/// Save provided content bytes to disk using the same naming/postprocessing rules as fetch_and_save.
/// Skips writing if an existing file is already present (including known extension variations).
pub async fn write_content(
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
pub async fn write_metadata<T: serde::Serialize>(
    token_uri: &str,
    token: &impl ContractTokenInfo,
    output_path: &Path,
    metadata: &T,
) -> anyhow::Result<PathBuf> {
    let bytes = serde_json::to_vec_pretty(metadata)?;
    write_content(
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
mod write_content_tests {
    use super::*;
    use crate::chain::common::ContractTokenId;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_write_content_skips_existing_exact_path() {
        let temp_dir = TempDir::new().unwrap();
        let out = temp_dir.path();
        let token = ContractTokenId {
            chain_name: "test".to_string(),
            address: "0xabc".to_string(),
            token_id: "1".to_string(),
        };
        let url = "https://example.com/file.bin";

        let path1 = write_content(
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
        .expect("first write_content should succeed");

        let path2 = write_content(
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
        .expect("second write_content should skip and succeed");

        assert_eq!(path1, path2);
    }

    #[tokio::test]
    async fn test_write_content_detects_extension_from_bytes() {
        let temp_dir = TempDir::new().unwrap();
        let out = temp_dir.path();
        let token = ContractTokenId {
            chain_name: "test".to_string(),
            address: "0xabc".to_string(),
            token_id: "1".to_string(),
        };

        let png_bytes: &[u8] = b"\x89PNG\r\n\x1A\nrest";

        let path = write_content(
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
        .expect("write_content should succeed");

        let name = path.file_name().unwrap().to_string_lossy();
        assert!(name.ends_with(".png"), "expected png extension, got {name}");
    }

    #[tokio::test]
    async fn test_sanitize_and_get_filename_via_write_content() {
        let temp_dir = TempDir::new().unwrap();
        let out = temp_dir.path();
        let token = ContractTokenId {
            chain_name: "test".to_string(),
            address: "0xabc".to_string(),
            token_id: "1".to_string(),
        };

        let url = "https://example.com/..//folder/../dangerous/../name";

        let path = write_content(
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
        .expect("write_content should succeed");

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
}

#[cfg(test)]
mod write_metadata_tests {
    use super::*;
    use crate::chain::common::ContractTokenId;
    use tempfile::TempDir;

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
        let path = write_metadata(token_uri, &token, out, &meta)
            .await
            .expect("write_metadata should succeed");

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("\n"), "expected pretty JSON with newlines");
        assert!(content.contains("\n  \"a\": 1"));
        assert!(content.contains("\n  \"b\": \"x\""));
        assert!(path.file_name().unwrap() == "metadata.json");
    }
}

#[cfg(test)]
mod sanitize_filename_tests {
    use super::sanitize_filename;

    #[test]
    fn removes_traversal_and_separators() {
        let input = "..//folder/../dangerous/./name";
        let out = sanitize_filename(input);
        assert_eq!(out, "folder_dangerous_name");
        assert!(!out.contains(".."));
        assert!(!out.contains('/'));
        assert!(!out.contains('\\'));
    }

    #[test]
    fn empty_becomes_file() {
        let out = sanitize_filename("");
        assert_eq!(out, "file");
    }

    #[test]
    fn preserves_simple_name() {
        let out = sanitize_filename("image.png");
        assert_eq!(out, "image.png");
    }
}

#[cfg(test)]
mod robust_file_exists_check_tests {
    use super::robust_file_exists_check;
    use tempfile::TempDir;

    #[tokio::test]
    async fn returns_true_for_existing_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("a.txt");
        tokio::fs::write(&file, b"x").await.unwrap();
        let exists = robust_file_exists_check(&file, 0).await.unwrap();
        assert!(exists);
    }

    #[tokio::test]
    async fn returns_false_for_missing_file() {
        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("missing.bin");
        let exists = robust_file_exists_check(&file, 0).await.unwrap();
        assert!(!exists);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn errors_on_permission_denied_after_retries() {
        use std::fs as stdfs;
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("noaccess");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        // Remove all permissions so metadata fails
        let mut perms = stdfs::metadata(&dir).unwrap().permissions();
        perms.set_mode(0o000);
        stdfs::set_permissions(&dir, perms).unwrap();

        let file_inside = dir.join("f.txt");
        let err = robust_file_exists_check(&file_inside, 1)
            .await
            .expect_err("should error");
        // Restore permissions for TempDir cleanup
        let restore = stdfs::Permissions::from_mode(0o700);
        stdfs::set_permissions(&dir, restore).unwrap();
        assert!(err.to_string().contains("Failed to check file existence"));
    }
}

#[cfg(test)]
mod write_and_postprocess_file_tests {
    use super::write_and_postprocess_file;
    use tempfile::TempDir;

    #[tokio::test]
    async fn json_valid_content_gets_pretty_printed() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("data.json");
        write_and_postprocess_file(&path, br#"{"a":1,"b":"x"}"#, "https://example/")
            .await
            .unwrap();
        let s = std::fs::read_to_string(&path).unwrap();
        assert!(s.contains("\n  \"a\": 1"));
        assert!(s.contains("\n  \"b\": \"x\""));
    }

    #[tokio::test]
    async fn json_invalid_content_written_raw() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("raw.json");
        let bytes = b"not-json";
        write_and_postprocess_file(&path, bytes, "https://example/")
            .await
            .unwrap();
        let s = std::fs::read(&path).unwrap();
        assert_eq!(s, bytes);
    }

    #[tokio::test]
    async fn json_empty_reads_existing_and_prettifies() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("pre.json");
        tokio::fs::write(&path, br#"{"k":2}"#).await.unwrap();
        write_and_postprocess_file(&path, b"", "https://example/")
            .await
            .unwrap();
        let s = std::fs::read_to_string(&path).unwrap();
        assert!(s.contains("\n  \"k\": 2"));
    }

    #[tokio::test]
    async fn html_with_inline_content_writes_and_processes() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("page.html");
        let html = b"<html><head></head><body><p>Hello</p></body></html>";
        write_and_postprocess_file(&path, html, "https://example/")
            .await
            .unwrap();
        let s = std::fs::read_to_string(&path).unwrap();
        assert!(s.contains("Hello"));
    }

    #[tokio::test]
    async fn html_empty_reads_existing_and_processes() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("page.html");
        tokio::fs::write(&path, b"<html></html>").await.unwrap();
        write_and_postprocess_file(&path, b"", "https://example/")
            .await
            .unwrap();
        let s = std::fs::read_to_string(&path).unwrap();
        assert!(s.contains("<html>"));
    }

    #[tokio::test]
    async fn other_extension_writes_when_non_empty_and_skips_when_empty() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("file.bin");
        write_and_postprocess_file(&path, b"abc", "https://example/")
            .await
            .unwrap();
        let s = std::fs::read(&path).unwrap();
        assert_eq!(s, b"abc");

        // Now call with empty content; file should remain unchanged
        write_and_postprocess_file(&path, b"", "https://example/")
            .await
            .unwrap();
        let s2 = std::fs::read(&path).unwrap();
        assert_eq!(s2, b"abc");
    }
}
