use ::url::Url;
use anyhow::Result;
use base64::Engine;

pub fn is_data_url(url: &str) -> bool {
    url.starts_with("data:")
}

pub fn get_data_url_mime_type(url: &str) -> String {
    url.trim_start_matches("data:")
        .split(';')
        .next()
        .and_then(|s| s.split('/').last())
        .unwrap_or("bin")
        .to_string()
}

/// Extract content from a data URL
fn get_data_url(url: &str) -> Option<(String, Vec<u8>)> {
    if !is_data_url(url) {
        return None;
    }

    let parts: Vec<&str> = url.splitn(2, "base64,").collect();
    if parts.len() != 2 {
        return None;
    }

    let mime_part = parts[0].trim_start_matches("data:").trim_end_matches(";");
    let data = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .ok()?;

    Some((mime_part.to_string(), data))
}

/// Get content from a data URL, returns the content and suggested file extension
pub fn get_data_url_content(url: &str) -> Result<(Vec<u8>, String)> {
    let (mime_type, content) =
        get_data_url(url).ok_or_else(|| anyhow::anyhow!("Invalid data URL format"))?;

    // Determine file extension based on MIME type
    let extension = if mime_type.is_empty() {
        "bin".to_string()
    } else {
        mime_type.split('/').last().unwrap_or("bin").to_string()
    };

    Ok((content, extension))
}

/// Converts IPFS URLs to use a gateway, otherwise returns the original URL
pub fn get_url(url: &str) -> String {
    if url.starts_with("ipfs://") {
        format!("https://ipfs.io/ipfs/{}", url.trim_start_matches("ipfs://"))
    } else {
        url.to_string()
    }
}

pub fn get_last_path_segment(url: &str, fallback: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|url| {
            url.path_segments()?
                .filter(|s| !s.is_empty())
                .last()
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| fallback.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_url_ipfs() {
        let ipfs_url = "ipfs://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        assert_eq!(
            get_url(ipfs_url),
            "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco"
        );
    }

    #[test]
    fn test_get_url_http() {
        let http_url = "https://example.com/image.png";
        assert_eq!(get_url(http_url), http_url);
    }

    #[test]
    fn test_get_data_url_content_json() {
        let data_url = "data:application/json;base64,eyJuYW1lIjogIlRlc3QifQ==";
        let (content, ext) = get_data_url_content(data_url).unwrap();
        assert_eq!(String::from_utf8_lossy(&content), r#"{"name": "Test"}"#);
        assert_eq!(ext, "json");
    }

    #[test]
    fn test_get_data_url_content_invalid() {
        let result = get_data_url_content("data:text/plain;base64,invalid@@base64");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_data_url_content_not_data_url() {
        let result = get_data_url_content("https://example.com/image.png");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_data_url() {
        assert!(is_data_url("data:text/plain;base64,SGVsbG8="));
        assert!(is_data_url(
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA"
        ));
        assert!(!is_data_url("https://example.com/image.png"));
        assert!(!is_data_url("ipfs://QmXoypizj"));
    }

    #[test]
    fn test_get_data_url_mime_type() {
        assert_eq!(
            get_data_url_mime_type("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA"),
            "png"
        );
        assert_eq!(
            get_data_url_mime_type("data:text/plain;charset=UTF-8;base64,SGVsbG8="),
            "plain"
        );
        assert_eq!(
            get_data_url_mime_type("data:application/vnd.custom+json;base64,eyJhIjogMn0="),
            "vnd.custom+json"
        );
        assert_eq!(
            get_data_url_mime_type("data:invalidmime;base64,SGVsbG8="),
            "invalidmime"
        );
    }

    #[test]
    fn test_get_data_url() {
        // Valid base64 URL
        let (mime, data) = get_data_url("data:text/plain;base64,SGVsbG8gd29ybGQ=").unwrap();
        assert_eq!(mime, "text/plain");
        assert_eq!(data, b"Hello world");

        // URL without base64 marker
        assert!(get_data_url("data:image/png,rawdata").is_none());

        // Invalid base64 data
        assert!(get_data_url("data:text/plain;base64,Invalid@Base64!").is_none());

        // Empty data
        let (mime, data) = get_data_url("data:text/plain;base64,").unwrap();
        assert_eq!(mime, "text/plain");
        assert!(data.is_empty());
    }

    #[test]
    fn test_get_last_path_segment() {
        // Standard URL with path
        assert_eq!(
            get_last_path_segment("https://example.com/path/to/file.txt", "fallback"),
            "file.txt"
        );

        // URL with trailing slash
        assert_eq!(
            get_last_path_segment("https://example.com/path/to/", "fallback"),
            "to"
        );

        // URL without path
        assert_eq!(
            get_last_path_segment("https://example.com", "fallback"),
            "fallback"
        );

        // IPFS-style path
        assert_eq!(
            get_last_path_segment(
                "ipfs://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/images/logo.png",
                "fallback"
            ),
            "logo.png"
        );

        // URL with query parameters
        assert_eq!(
            get_last_path_segment(
                "https://example.com/file.jpg?width=200&quality=85",
                "fallback"
            ),
            "file.jpg"
        );

        // URL with fragment
        assert_eq!(
            get_last_path_segment("https://example.com/docs#section1", "fallback"),
            "docs"
        );
    }

    #[test]
    fn test_get_data_url_content_non_base64() {
        // URL with missing base64 marker
        let result = get_data_url_content("data:text/plain,HelloWorld");
        assert!(result.is_err());
    }

    #[test]
    fn test_get_data_url_content_empty_mime() {
        let (content, ext) = get_data_url_content("data:;base64,SGVsbG8=").unwrap();
        assert_eq!(content, b"Hello");
        assert_eq!(ext, "bin");
    }
}
