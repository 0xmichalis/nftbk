use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use regex::Regex;
use scraper::{Html, Selector};
use tokio::fs;
use tracing::{debug, info, warn};
use url::Url;

use crate::httpclient::stream::stream_http_to_file;
use crate::url::resolve_url;

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
        format!("https:{resource_url}")
    } else {
        let base = Url::parse(base_url).ok();
        match base.and_then(|b| b.join(resource_url).ok()) {
            Some(url) => url.to_string(),
            None => resolve_url(resource_url),
        }
    };
    if absolute_url.starts_with("ipfs://") {
        absolute_url = resolve_url(&absolute_url);
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
                    None => resolve_url(&found_url),
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

#[cfg(test)]
mod add_resource_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn adds_relative_resource() {
        let mut resources = Vec::new();
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        add_resource(
            &mut resources,
            "style.css",
            "https://example.com/",
            dir_path,
        );

        assert_eq!(resources.len(), 1);
        let (absolute_url, resource_url, resource_path) = &resources[0];
        assert_eq!(absolute_url, "https://example.com/style.css");
        assert_eq!(resource_url, "style.css");
        assert_eq!(resource_path, &dir_path.join("style.css"));
    }

    #[test]
    fn rejects_protocol_relative_urls() {
        let mut resources = Vec::new();
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        add_resource(
            &mut resources,
            "//cdn.example.com/script.js",
            "https://example.com/",
            dir_path,
        );

        // Protocol-relative URLs should be rejected as unsafe (they start with '/')
        assert_eq!(resources.len(), 0);
    }

    #[test]
    fn skips_unsafe_paths() {
        let mut resources = Vec::new();
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        add_resource(
            &mut resources,
            "../style.css",
            "https://example.com/",
            dir_path,
        );
        add_resource(
            &mut resources,
            "/absolute/path.css",
            "https://example.com/",
            dir_path,
        );

        assert_eq!(resources.len(), 0);
    }

    #[test]
    fn skips_data_urls() {
        let mut resources = Vec::new();
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        add_resource(
            &mut resources,
            "data:image/png;base64,iVBORw0KGgo=",
            "https://example.com/",
            dir_path,
        );
        add_resource(
            &mut resources,
            "javascript:alert('x')",
            "https://example.com/",
            dir_path,
        );
        add_resource(&mut resources, "#anchor", "https://example.com/", dir_path);

        assert_eq!(resources.len(), 0);
    }

    #[test]
    fn handles_ipfs_urls() {
        let mut resources = Vec::new();
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        add_resource(
            &mut resources,
            "ipfs://QmHash",
            "https://example.com/",
            dir_path,
        );

        assert_eq!(resources.len(), 1);
        let (absolute_url, _, _) = &resources[0];
        // The resolve_url function should convert ipfs:// to a proper URL
        assert!(absolute_url.starts_with("http"));
    }

    #[test]
    fn strips_query_parameters() {
        let mut resources = Vec::new();
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        add_resource(
            &mut resources,
            "style.css?v=1.0",
            "https://example.com/",
            dir_path,
        );

        assert_eq!(resources.len(), 1);
        let (_, _, resource_path) = &resources[0];
        assert_eq!(resource_path, &dir_path.join("style.css"));
    }
}

#[cfg(test)]
mod is_locale_file_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn identifies_locale_txt_file() {
        let path = PathBuf::from("locale/en.txt");
        assert!(is_locale_file(&path));
    }

    #[test]
    fn identifies_locale_file_with_subdir() {
        let path = PathBuf::from("some/path/locale/fr.txt");
        assert!(is_locale_file(&path));
    }

    #[test]
    fn rejects_non_txt_extension() {
        let path = PathBuf::from("locale/en.json");
        assert!(!is_locale_file(&path));
    }

    #[test]
    fn rejects_non_locale_parent() {
        let path = PathBuf::from("other/en.txt");
        assert!(!is_locale_file(&path));
    }

    #[test]
    fn rejects_file_without_extension() {
        let path = PathBuf::from("locale/en");
        assert!(!is_locale_file(&path));
    }

    #[test]
    fn rejects_root_file() {
        let path = PathBuf::from("locale.txt");
        assert!(!is_locale_file(&path));
    }
}

#[cfg(test)]
mod is_script_js_file_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn identifies_script_js_file() {
        let path = PathBuf::from("script.js");
        assert!(is_script_js_file(&path));
    }

    #[test]
    fn identifies_script_with_numbers() {
        let path = PathBuf::from("script123.js");
        assert!(is_script_js_file(&path));
    }

    #[test]
    fn identifies_script_with_dashes() {
        let path = PathBuf::from("script-main.js");
        assert!(is_script_js_file(&path));
    }

    #[test]
    fn identifies_script_with_path() {
        let path = PathBuf::from("path/to/script.js");
        assert!(is_script_js_file(&path));
    }

    #[test]
    fn rejects_non_script_file() {
        let path = PathBuf::from("other.js");
        assert!(!is_script_js_file(&path));
    }

    #[test]
    fn rejects_script_without_js_extension() {
        let path = PathBuf::from("script.txt");
        assert!(!is_script_js_file(&path));
    }

    #[test]
    fn rejects_script_that_doesnt_start_with_script() {
        let path = PathBuf::from("myscript.js");
        assert!(!is_script_js_file(&path));
    }
}

#[cfg(test)]
mod is_safe_resource_path_tests {
    use super::*;

    #[test]
    fn accepts_safe_relative_paths() {
        assert!(is_safe_resource_path("style.css"));
        assert!(is_safe_resource_path("images/logo.png"));
        assert!(is_safe_resource_path("js/app.js"));
    }

    #[test]
    fn rejects_path_traversal() {
        assert!(!is_safe_resource_path("../style.css"));
        assert!(!is_safe_resource_path("../../etc/passwd"));
        assert!(!is_safe_resource_path("folder/../style.css"));
    }

    #[test]
    fn rejects_absolute_paths() {
        assert!(!is_safe_resource_path("/style.css"));
        assert!(!is_safe_resource_path("/etc/passwd"));
    }

    #[test]
    fn rejects_data_urls() {
        assert!(!is_safe_resource_path("data:image/png;base64,iVBORw0KGgo="));
    }

    #[test]
    fn rejects_javascript_urls() {
        assert!(!is_safe_resource_path("javascript:alert('x')"));
    }

    #[test]
    fn rejects_anchors() {
        assert!(!is_safe_resource_path("#section"));
    }
}

#[cfg(test)]
mod extract_resource_paths_from_file_tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;

    #[tokio::test]
    async fn extracts_from_locale_file() {
        let temp_dir = TempDir::new().unwrap();
        let locale_dir = temp_dir.path().join("locale");
        fs::create_dir_all(&locale_dir).await.unwrap();

        let locale_file = locale_dir.join("en.txt");
        let content = r#"
# This is a comment
key1=image.png
key2=video.mp4
key3=not-a-file
key4=document.pdf
"#;
        fs::write(&locale_file, content).await.unwrap();

        let found_urls = extract_resource_paths_from_file(&locale_file)
            .await
            .unwrap();
        assert_eq!(found_urls.len(), 3);
        assert!(found_urls.contains(&"image.png".to_string()));
        assert!(found_urls.contains(&"video.mp4".to_string()));
        assert!(found_urls.contains(&"document.pdf".to_string()));
    }

    #[tokio::test]
    async fn extracts_from_script_js_file() {
        let temp_dir = TempDir::new().unwrap();
        let script_file = temp_dir.path().join("script.js");
        let content = r#"
var config = {
    image: "logo.png",
    video: "intro.mp4",
    audio: "sound.mp3"
};
loadResource("data.json");
fetch("api.xml");
"#;
        fs::write(&script_file, content).await.unwrap();

        let found_urls = extract_resource_paths_from_file(&script_file)
            .await
            .unwrap();
        assert_eq!(found_urls.len(), 5);
        assert!(found_urls.contains(&"logo.png".to_string()));
        assert!(found_urls.contains(&"intro.mp4".to_string()));
        assert!(found_urls.contains(&"sound.mp3".to_string()));
        assert!(found_urls.contains(&"data.json".to_string()));
        assert!(found_urls.contains(&"api.xml".to_string()));
    }

    #[tokio::test]
    async fn handles_empty_locale_file() {
        let temp_dir = TempDir::new().unwrap();
        let locale_dir = temp_dir.path().join("locale");
        fs::create_dir_all(&locale_dir).await.unwrap();

        let locale_file = locale_dir.join("en.txt");
        fs::write(&locale_file, "").await.unwrap();

        let found_urls = extract_resource_paths_from_file(&locale_file)
            .await
            .unwrap();
        assert_eq!(found_urls.len(), 0);
    }

    #[tokio::test]
    async fn handles_empty_script_file() {
        let temp_dir = TempDir::new().unwrap();
        let script_file = temp_dir.path().join("script.js");
        fs::write(&script_file, "").await.unwrap();

        let found_urls = extract_resource_paths_from_file(&script_file)
            .await
            .unwrap();
        assert_eq!(found_urls.len(), 0);
    }

    #[tokio::test]
    async fn ignores_non_locale_non_script_files() {
        let temp_dir = TempDir::new().unwrap();
        let other_file = temp_dir.path().join("other.txt");
        let content = "image.png video.mp4";
        fs::write(&other_file, content).await.unwrap();

        let found_urls = extract_resource_paths_from_file(&other_file).await.unwrap();
        assert_eq!(found_urls.len(), 0);
    }

    #[tokio::test]
    async fn handles_locale_file_with_comments_and_empty_lines() {
        let temp_dir = TempDir::new().unwrap();
        let locale_dir = temp_dir.path().join("locale");
        fs::create_dir_all(&locale_dir).await.unwrap();

        let locale_file = locale_dir.join("en.txt");
        let content = r#"
# Comment line
key1=image.png

# Another comment
key2=video.mp4

key3=not-a-file
"#;
        fs::write(&locale_file, content).await.unwrap();

        let found_urls = extract_resource_paths_from_file(&locale_file)
            .await
            .unwrap();
        assert_eq!(found_urls.len(), 2);
        assert!(found_urls.contains(&"image.png".to_string()));
        assert!(found_urls.contains(&"video.mp4".to_string()));
    }
}

#[cfg(test)]
mod download_html_resources_tests {
    use super::*;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn downloads_html_resources() {
        let mock_server = MockServer::start().await;
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Mock the main HTML page
        Mock::given(method("GET"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"
                <html>
                    <head>
                        <link rel="stylesheet" href="style.css">
                        <script src="script.js"></script>
                    </head>
                    <body>
                        <img src="image.png" alt="test">
                    </body>
                </html>
            "#,
            ))
            .mount(&mock_server)
            .await;

        // Mock the resources
        Mock::given(method("GET"))
            .and(path("/style.css"))
            .respond_with(ResponseTemplate::new(200).set_body_string("body { color: red; }"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/script.js"))
            .respond_with(ResponseTemplate::new(200).set_body_string("console.log('hello');"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/image.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake-png-data"))
            .mount(&mock_server)
            .await;

        let html_content = r#"
            <html>
                <head>
                    <link rel="stylesheet" href="style.css">
                    <script src="script.js"></script>
                </head>
                <body>
                    <img src="image.png" alt="test">
                </body>
            </html>
        "#;

        let result = download_html_resources(html_content, &mock_server.uri(), dir_path).await;
        assert!(result.is_ok());

        // Check that files were downloaded
        assert!(dir_path.join("style.css").exists());
        assert!(dir_path.join("script.js").exists());
        assert!(dir_path.join("image.png").exists());
    }

    #[tokio::test]
    async fn skips_unsafe_resources() {
        let mock_server = MockServer::start().await;
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Mock the safe resource
        Mock::given(method("GET"))
            .and(path("/safe-image.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake-png-data"))
            .mount(&mock_server)
            .await;

        let html_content = "
            <html>
                <head>
                    <link rel=\"stylesheet\" href=\"../style.css\">
                    <script src=\"/absolute/script.js\"></script>
                    <img src=\"data:image/png;base64,iVBORw0KGgo=\" alt=\"data\">
                    <img src=\"javascript:alert('x')\" alt=\"js\">
                    <img src=\"#anchor\" alt=\"anchor\">
                </head>
                <body>
                    <img src=\"safe-image.png\" alt=\"safe\">
                </body>
            </html>
        ";

        let result = download_html_resources(html_content, &mock_server.uri(), dir_path).await;
        assert!(result.is_ok());

        // Only the safe image should be downloaded
        assert!(dir_path.join("safe-image.png").exists());
    }

    #[tokio::test]
    async fn handles_inline_script_resources() {
        let mock_server = MockServer::start().await;
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Mock the resources that would be extracted from inline script
        Mock::given(method("GET"))
            .and(path("/dynamic.js"))
            .respond_with(ResponseTemplate::new(200).set_body_string("console.log('dynamic');"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"data": "test"}"#))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/config.xml"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<config>test</config>"))
            .mount(&mock_server)
            .await;

        let html_content = r#"
            <html>
                <head>
                    <script>
                        loadScript("dynamic.js");
                        fetchData("api.json");
                        loadConfig("config.xml");
                    </script>
                </head>
                <body></body>
            </html>
        "#;

        let result = download_html_resources(html_content, &mock_server.uri(), dir_path).await;
        assert!(result.is_ok());

        // Check that files were downloaded
        assert!(dir_path.join("dynamic.js").exists());
        assert!(dir_path.join("api.json").exists());
        assert!(dir_path.join("config.xml").exists());
    }

    #[tokio::test]
    async fn handles_protocol_relative_urls() {
        // Test that protocol-relative URLs are correctly rejected as unsafe
        let mut resources = Vec::new();
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        add_resource(
            &mut resources,
            "//cdn.example.com/style.css",
            "https://example.com/",
            dir_path,
        );

        // Protocol-relative URLs should be rejected as unsafe (they start with '/')
        assert_eq!(resources.len(), 0);
    }

    #[tokio::test]
    async fn handles_malformed_html() {
        let mock_server = MockServer::start().await;
        let temp_dir = TempDir::new().unwrap();
        let dir_path = temp_dir.path();

        // Mock the resources that might be extracted from malformed HTML
        Mock::given(method("GET"))
            .and(path("/style.css"))
            .respond_with(ResponseTemplate::new(200).set_body_string("body { color: red; }"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/script.js"))
            .respond_with(ResponseTemplate::new(200).set_body_string("console.log('hello');"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/image.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake-png-data"))
            .mount(&mock_server)
            .await;

        let html_content = r#"
            <html>
                <head>
                    <link rel="stylesheet" href="style.css"
                    <script src="script.js"
                </head>
                <body>
                    <img src="image.png"
                </body>
            </html>
        "#;

        let result = download_html_resources(html_content, &mock_server.uri(), dir_path).await;
        assert!(result.is_ok());

        // Should handle malformed HTML gracefully and still download resources
        assert!(dir_path.join("style.css").exists());
        assert!(dir_path.join("script.js").exists());
        assert!(dir_path.join("image.png").exists());
    }
}
