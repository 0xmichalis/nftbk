use anyhow::Result;
use scraper::{Html, Selector};
use std::path::Path;
use tokio::fs;
use tracing::{debug, info, warn};
use url::Url;

use crate::content::stream_http_to_file;
use crate::url::get_url;

pub async fn download_html_resources(
    html_content: &str,
    base_url: &str,
    dir_path: &Path,
) -> Result<()> {
    let resources = {
        let document = Html::parse_document(html_content);
        let selectors = [
            (Selector::parse("[src]").unwrap(), "src"),
            (Selector::parse("link[href]").unwrap(), "href"),
        ];
        let mut resources = Vec::new();
        for (selector, attr) in selectors.iter() {
            for element in document.select(selector) {
                if let Some(resource_url) = element.value().attr(attr) {
                    if resource_url.starts_with("data:")
                        || resource_url.starts_with("javascript:")
                        || resource_url.starts_with("#")
                    {
                        continue;
                    }
                    let mut absolute_url = if resource_url.starts_with("//") {
                        format!("https:{}", resource_url)
                    } else {
                        let base = Url::parse(base_url)?;
                        match base.join(resource_url) {
                            Ok(url) => url.to_string(),
                            Err(_) => get_url(resource_url),
                        }
                    };
                    if absolute_url.starts_with("ipfs://") {
                        absolute_url = get_url(&absolute_url);
                    }
                    let clean_resource_url = resource_url.split('?').next().unwrap_or(resource_url);
                    let resource_path = dir_path.join(clean_resource_url);
                    resources.push((absolute_url, resource_url.to_string(), resource_path));
                }
            }
        }
        resources
    }; // document and all scraper types are dropped here

    // Now do async I/O
    for (absolute_url, resource_url, resource_path) in resources {
        if let Some(parent) = Path::new(&resource_url).parent() {
            fs::create_dir_all(dir_path.join(parent)).await?;
        }
        if fs::try_exists(&resource_path).await? {
            debug!("Resource already exists at {}", resource_path.display());
            continue;
        }
        debug!("Downloading HTML resource: {}", absolute_url);
        let client = reqwest::Client::new();
        match client.get(&absolute_url).send().await {
            Ok(response) => {
                info!("Saving HTML resource at {}", resource_path.display());
                stream_http_to_file(response, &resource_path).await?;
            }
            Err(e) => {
                warn!("Failed to download HTML resource {}: {}", absolute_url, e);
            }
        }
    }
    Ok(())
}
