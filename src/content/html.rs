use anyhow::Result;
use regex::Regex;
use scraper::{Html, Selector};
use std::path::Path;
use tokio::fs;
use tracing::{debug, info, warn};
use url::Url;

use crate::content::stream_http_to_file;
use crate::url::get_url;

fn add_resource(
    resources: &mut Vec<(String, String, std::path::PathBuf)>,
    resource_url: &str,
    base_url: &str,
    dir_path: &Path,
) {
    if resource_url.contains("..") || resource_url.starts_with('/') {
        warn!("Skipping unsafe or absolute path: {}", resource_url);
        return;
    }
    if resource_url.starts_with("data:")
        || resource_url.starts_with("javascript:")
        || resource_url.starts_with("#")
    {
        return;
    }
    let mut absolute_url = if resource_url.starts_with("//") {
        format!("https:{}", resource_url)
    } else {
        let base = Url::parse(base_url).ok();
        match base.and_then(|b| b.join(resource_url).ok()) {
            Some(url) => url.to_string(),
            None => get_url(resource_url),
        }
    };
    if absolute_url.starts_with("ipfs://") {
        absolute_url = get_url(&absolute_url);
    }
    let clean_resource_url = resource_url.split('?').next().unwrap_or(resource_url);
    let resource_path = dir_path.join(clean_resource_url);
    resources.push((absolute_url, resource_url.to_string(), resource_path));
}

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
            (Selector::parse("script[src]").unwrap(), "src"),
        ];
        let mut resources = Vec::new();

        // Parse HTML attributes for static resources
        for (selector, attr) in selectors.iter() {
            for element in document.select(selector) {
                if let Some(resource_url) = element.value().attr(attr) {
                    add_resource(&mut resources, resource_url, base_url, dir_path);
                }
            }
        }

        // Parse inline <script> tags for dynamic resources
        let js_regex = Regex::new(r#"([\w./-]+\.js)(\?[^"']*)?"#).unwrap();
        let xml_json_regex = Regex::new(r#"([\w./-]+\.(xml|json))(\?[^"']*)?"#).unwrap();
        let script_selector = Selector::parse("script").unwrap();
        for element in document.select(&script_selector) {
            if element.value().attr("src").is_none() {
                let script_text = element.text().collect::<String>();
                for cap in js_regex.captures_iter(&script_text) {
                    let resource_url = &cap[1];
                    add_resource(&mut resources, resource_url, base_url, dir_path);
                }
                for cap in xml_json_regex.captures_iter(&script_text) {
                    let resource_url = &cap[1];
                    add_resource(&mut resources, resource_url, base_url, dir_path);
                }
            }
        }

        resources
    };

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
                info!("Saved HTML resource at {}", resource_path.display());
            }
            Err(e) => {
                warn!("Failed to download HTML resource {}: {}", absolute_url, e);
            }
        }
    }
    Ok(())
}
