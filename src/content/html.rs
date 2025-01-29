use crate::url::get_url;
use anyhow::Result;
use scraper::{Html, Selector};
use std::path::Path;
use tokio::fs;
use tracing::{debug, info, warn};
use url::Url;

pub async fn download_html_resources(
    html_content: &str,
    base_url: &str,
    dir_path: &Path,
) -> Result<()> {
    let document = Html::parse_document(html_content);

    // Define selectors for elements with src or href attributes
    let selectors = [
        (Selector::parse("[src]").unwrap(), "src"),
        (Selector::parse("link[href]").unwrap(), "href"),
    ];

    for (selector, attr) in selectors.iter() {
        for element in document.select(selector) {
            if let Some(resource_url) = element.value().attr(attr) {
                // Skip data URLs and javascript
                if resource_url.starts_with("data:")
                    || resource_url.starts_with("javascript:")
                    || resource_url.starts_with("#")
                {
                    continue;
                }

                // Construct absolute URL for the resource
                let mut absolute_url = if resource_url.starts_with("//") {
                    format!("https:{}", resource_url)
                } else {
                    let base = Url::parse(base_url)?;
                    match base.join(resource_url) {
                        Ok(url) => url.to_string(),
                        Err(_) => get_url(resource_url), // Try using get_url as fallback
                    }
                };

                if absolute_url.starts_with("ipfs://") {
                    absolute_url = get_url(&absolute_url);
                }

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
                    debug!("Resource already exists at {}", resource_path.display());
                    continue;
                }

                // Download and save the resource
                debug!("Downloading HTML resource: {}", absolute_url);
                let client = reqwest::Client::new();
                match client.get(&absolute_url).send().await {
                    Ok(response) => {
                        info!("Saving HTML resource at {}", resource_path.display());
                        let content = response.bytes().await?;
                        fs::write(resource_path, content).await?;
                    }
                    Err(e) => {
                        warn!("Failed to download HTML resource {}: {}", absolute_url, e);
                    }
                }
            }
        }
    }

    Ok(())
}
