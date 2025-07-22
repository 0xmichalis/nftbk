use anyhow::Result;
use regex::Regex;
use scraper::{Html, Selector};
use std::collections::HashSet;
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

fn is_locale_file(path: &Path) -> bool {
    // e.g., locale/en.txt
    if let Some(parent) = path.parent() {
        if parent.file_name().is_some_and(|n| n == "locale") {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                return ext == "txt";
            }
        }
    }
    false
}

fn is_script_js_file(path: &Path) -> bool {
    // e.g., script*.js
    if let Some(fname) = path.file_name().and_then(|f| f.to_str()) {
        fname.starts_with("script") && fname.ends_with(".js")
    } else {
        false
    }
}

fn is_safe_resource_path(resource_url: &str) -> bool {
    if resource_url.contains("..") || resource_url.starts_with('/') {
        warn!("Skipping unsafe or absolute path: {}", resource_url);
        return false;
    }
    if resource_url.starts_with("data:")
        || resource_url.starts_with("javascript:")
        || resource_url.starts_with("#")
    {
        return false;
    }
    true
}

async fn extract_resource_paths_from_file(path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(path).await?;
    let mut found_urls = Vec::new();

    // Regex for any filename with a known extension
    let known_ext_regex = Regex::new(
        r#"([\w./-]+\.(?:jpg|jpeg|png|gif|mp4|webm|mp3|ogg|svg|webp|ico|json|xml|txt|pdf))"#,
    )
    .unwrap();

    // For locale files: extract value part if it looks like a known file
    if is_locale_file(path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((_k, v)) = line.split_once('=') {
                let v = v.trim();
                if known_ext_regex.is_match(v) {
                    found_urls.push(v.to_string());
                }
            }
        }
    }

    // For script JS files: extract all string literals that look like known files
    if is_script_js_file(path) {
        for cap in known_ext_regex.captures_iter(&content) {
            found_urls.push(cap[1].to_string());
        }
    }
    Ok(found_urls)
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

    let mut downloaded_files = Vec::new();
    for (absolute_url, resource_url, resource_path) in &resources {
        if !is_safe_resource_path(resource_url) {
            continue;
        }
        if let Some(parent) = Path::new(resource_url).parent() {
            fs::create_dir_all(dir_path.join(parent)).await?;
        }
        if fs::try_exists(resource_path).await? {
            debug!("Resource already exists at {}", resource_path.display());
        } else {
            debug!("Downloading HTML resource: {}", absolute_url);
            let client = reqwest::Client::new();
            match client.get(absolute_url).send().await {
                Ok(response) => {
                    info!("Saving HTML resource at {}", resource_path.display());
                    stream_http_to_file(response, resource_path).await?;
                    info!("Saved HTML resource at {}", resource_path.display());
                }
                Err(e) => {
                    warn!("Failed to download HTML resource {}: {}", absolute_url, e);
                    continue;
                }
            }
        }
        downloaded_files.push(resource_path.clone());
    }

    // 2. Additive: Recursive post-processing for additional resources
    let mut processed = HashSet::new();
    let mut to_process = downloaded_files;
    while let Some(resource_path) = to_process.pop() {
        if processed.contains(&resource_path) {
            continue;
        }
        processed.insert(resource_path.clone());
        // Only process locale files and script*.js files
        if !(is_locale_file(&resource_path) || is_script_js_file(&resource_path)) {
            continue;
        }
        let found = extract_resource_paths_from_file(&resource_path).await?;
        for found_url in found {
            if !is_safe_resource_path(&found_url) {
                continue;
            }
            if found_url.starts_with("http") || found_url.starts_with("data:") {
                continue;
            }
            let abs_url = if found_url.starts_with("/") {
                format!("{}{}", base_url.trim_end_matches('/'), found_url)
            } else {
                let base = Url::parse(base_url).ok();
                match base.and_then(|b| b.join(&found_url).ok()) {
                    Some(url) => url.to_string(),
                    None => get_url(&found_url),
                }
            };
            let clean_resource_url = found_url.split('?').next().unwrap_or(&found_url);
            if !is_safe_resource_path(clean_resource_url) {
                continue;
            }
            let found_path = dir_path.join(clean_resource_url);
            if !processed.contains(&found_path) {
                // Download the new resource
                if let Some(parent) = found_path.parent() {
                    fs::create_dir_all(parent).await?;
                }
                if fs::try_exists(&found_path).await? {
                    debug!("Resource already exists at {}", found_path.display());
                } else {
                    debug!("Downloading HTML resource: {}", abs_url);
                    let client = reqwest::Client::new();
                    match client.get(&abs_url).send().await {
                        Ok(response) => {
                            info!("Saving HTML resource at {}", found_path.display());
                            stream_http_to_file(response, &found_path).await?;
                            info!("Saved HTML resource at {}", found_path.display());
                        }
                        Err(e) => {
                            warn!("Failed to download HTML resource {}: {}", abs_url, e);
                            continue;
                        }
                    }
                }
                to_process.push(found_path);
            }
        }
    }
    Ok(())
}
