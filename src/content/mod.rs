use ::url::Url;
use anyhow::Result;
use scraper::{Html, Selector};
use std::path::{Path, PathBuf};
use tokio::fs;

pub mod extensions;
pub mod url;
use self::url::get_url;

async fn download_html_resources(
    html_content: &str,
    base_url: &str,
    dir_path: &Path,
) -> Result<String> {
    let document = Html::parse_document(html_content);
    let modified_html = html_content.to_string();

    // Define selectors for elements with src or href attributes
    let selectors = [
        (Selector::parse("[src]").unwrap(), "src"),
        (Selector::parse("link[href]").unwrap(), "href"),
    ];

    for (selector, attr) in selectors.iter() {
        for element in document.select(selector) {
            if let Some(resource_url) = element.value().attr(attr) {
                // Skip absolute URLs, data URLs, and javascript
                if resource_url.starts_with("http")
                    || resource_url.starts_with("data:")
                    || resource_url.starts_with("javascript:")
                    || resource_url.starts_with("#")
                {
                    continue;
                }

                // Construct absolute URL for the resource
                let absolute_url = if resource_url.starts_with("//") {
                    format!("https:{}", resource_url)
                } else {
                    let base = Url::parse(base_url)?;
                    base.join(resource_url)?.to_string()
                };

                // Create subdirectory structure
                let resource_path = Path::new(resource_url);
                if let Some(parent) = resource_path.parent() {
                    fs::create_dir_all(dir_path.join(parent)).await?;
                }

                // Clean up resource URL by removing query parameters
                let clean_resource_url = resource_url.split('?').next().unwrap_or(resource_url);
                let resource_path = dir_path.join(clean_resource_url);

                // Skip if file already exists
                if fs::try_exists(&resource_path).await? {
                    println!("Resource already exists at {}", resource_path.display());
                    continue;
                }

                // Download and save the resource
                println!("Downloading resource: {}", absolute_url);
                let client = reqwest::Client::new();
                match client.get(&absolute_url).send().await {
                    Ok(response) => {
                        let content = response.bytes().await?;
                        fs::write(resource_path, content).await?;
                    }
                    Err(e) => {
                        println!(
                            "Warning: Failed to download resource {}: {}",
                            absolute_url, e
                        );
                    }
                }
            }
        }
    }

    Ok(modified_html)
}

async fn fetch_http_content(url: &str) -> Result<(Vec<u8>, bool)> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;

    // Check content type
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown/unknown");

    let is_html = content_type.contains("text/html") || content_type.contains("application/xhtml");
    let content = response.bytes().await?.to_vec();

    Ok((content, is_html))
}

async fn get_filename(
    url: &str,
    chain: &str,
    contract_address: &str,
    token_id: &str,
    output_path: &Path,
    file_name: Option<&str>,
) -> Result<PathBuf> {
    let dir_path = output_path
        .join(chain)
        .join(contract_address)
        .join(token_id);

    // Determine filename
    let file_name = if let Some(name) = file_name {
        name.to_string()
    } else if url.starts_with("data:") {
        // For data URLs, use content type as filename
        let mime_type = url
            .split(';')
            .next()
            .and_then(|s| s.split('/').last())
            .unwrap_or("bin")
            .to_string();
        format!("content.{}", mime_type)
    } else {
        // For regular URLs, try to extract filename from path
        Url::parse(url)
            .ok()
            .and_then(|url| {
                url.path_segments()?
                    .filter(|s| !s.is_empty())
                    .last()
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "content".to_string())
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
        println!("File already exists at {}", file_path.display());
        return Ok(file_path);
    }

    // Get content based on URL type
    let (content, is_html) = if url.starts_with("data:") {
        let (content, _) = url::get_data_url_content(url)?;
        (content, false) // Data URLs are treated as binary content
    } else {
        let content_url = get_url(url);
        fetch_http_content(&content_url).await?
    };

    // Create directory and save content
    fs::create_dir_all(file_path.parent().unwrap()).await?;

    if !is_html {
        fs::write(&file_path, content).await?;
    } else {
        // Ensure HTML files have .html extension
        if !file_path.to_string_lossy().ends_with(".html") {
            file_path = file_path.join(".html");
        }
        // For HTML content, download associated resources
        println!("Warning: Downloading HTML content from {}. The saved file may be incomplete as it might depend on additional resources or backend servers.", url);
        let content_str = String::from_utf8_lossy(&content);
        let modified_html =
            download_html_resources(&content_str, url, file_path.parent().unwrap()).await?;
        fs::write(&file_path, modified_html).await?;
    }

    Ok(file_path)
}
