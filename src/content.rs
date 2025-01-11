use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::fs;
use url::Url;

use crate::url::get_url;

pub async fn fetch_and_save_content(
    url: &str,
    output_path: &Path,
    chain: &str,
    token_id: &str,
    contract: &str,
    file_name: Option<&str>,
) -> Result<PathBuf> {
    // Try to extract filename from URL first, then fallback to provided file_name, then "content"
    let file_name = Url::parse(url)
        .ok()
        .and_then(|url| url.path_segments()?.last().map(|s| s.to_string()))
        .or_else(|| file_name.map(|s| s.to_string()))
        .unwrap_or_else(|| "content".to_string());

    let dir_path = output_path.join(chain).join(contract).join(token_id);
    let file_path = dir_path.join(&file_name);

    // Return early if file already exists
    if fs::try_exists(&file_path).await? {
        println!("File already exists at {}", file_path.display());
        return Ok(file_path);
    }

    // File doesn't exist, proceed with download
    let content_url = get_url(url);
    let client = reqwest::Client::new();
    let response = client.get(&content_url).send().await?;
    let content = response.bytes().await?;

    fs::create_dir_all(&dir_path).await?;
    fs::write(&file_path, content).await?;

    Ok(file_path)
}
