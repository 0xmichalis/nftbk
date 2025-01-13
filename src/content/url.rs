use anyhow::Result;
use base64::Engine;

/// Extract content from a data URL
fn extract_data_url(url: &str) -> Option<(String, Vec<u8>)> {
    if !url.starts_with("data:") {
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
        extract_data_url(url).ok_or_else(|| anyhow::anyhow!("Invalid data URL format"))?;

    // Determine file extension based on MIME type
    let extension = mime_type.split('/').last().unwrap_or("bin").to_string();

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
}
