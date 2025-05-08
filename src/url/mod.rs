use ::url::Url;
use base64::Engine;

pub fn is_data_url(url: &str) -> bool {
    url.starts_with("data:")
}

/// Extract content from a data URL
pub fn get_data_url(url: &str) -> Option<Vec<u8>> {
    if !is_data_url(url) {
        return None;
    }

    // Handle JSON data URLs
    if url.starts_with("data:application/json;utf8,") {
        let json_content = url.trim_start_matches("data:application/json;utf8,");
        return Some(json_content.as_bytes().to_vec());
    }

    // Handle base64 encoded data URLs
    let parts: Vec<&str> = url.splitn(2, "base64,").collect();
    if parts.len() != 2 {
        return None;
    }

    let data = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .ok()?;

    Some(data)
}

/// Converts IPFS URLs to use a gateway, otherwise returns the original URL
pub fn get_url(url: &str) -> String {
    // Handle ipfs:// protocol URLs
    if url.starts_with("ipfs://ipfs/") {
        // Handle erroneous ipfs://ipfs/... URLs
        // Saw this pattern in the Makersplace contract
        format!(
            "https://ipfs.io/ipfs/{}",
            url.trim_start_matches("ipfs://ipfs/")
        )
    } else if url.starts_with("ipfs://") {
        format!("https://ipfs.io/ipfs/{}", url.trim_start_matches("ipfs://"))
    }
    // Handle raw IPFS hashes (Qm... or bafy... format)
    // TODO: Use a proper IPFS library to validate formats
    else if url.starts_with("Qm") && url.len() == 46 || url.starts_with("bafy") {
        format!("https://ipfs.io/ipfs/{}", url)
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
                .next_back()
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
    fn test_get_url_raw_ipfs_hash() {
        // Test Qm... hash format
        let raw_hash = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        assert_eq!(
            get_url(raw_hash),
            "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco"
        );

        // Test bafy... hash format
        let bafy_hash = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        assert_eq!(
            get_url(bafy_hash),
            "https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
        );

        // Test non-IPFS hash
        let non_ipfs = "QmInvalidHash";
        assert_eq!(get_url(non_ipfs), non_ipfs);
    }

    #[test]
    fn test_get_url_http() {
        let http_url = "https://example.com/image.png";
        assert_eq!(get_url(http_url), http_url);
    }

    #[test]
    fn test_get_data_url_json() {
        // Test base64 encoded JSON
        let data_url = "data:application/json;base64,eyAidGVzdCI6IDEyMyB9"; // base64 encoded '{ "test": 123 }'
        let content = get_data_url(data_url).unwrap();
        assert_eq!(String::from_utf8_lossy(&content), "{ \"test\": 123 }");

        // Test utf8 encoded JSON
        let utf8_url = r#"data:application/json;utf8,{"name":"BEAR","attributes":[{"trait_type":"name","value":"BEAR"}]}"#;
        let content = get_data_url(utf8_url).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&content),
            r#"{"name":"BEAR","attributes":[{"trait_type":"name","value":"BEAR"}]}"#
        );
    }

    #[test]
    fn test_get_data_url_invalid() {
        assert!(get_data_url("data:text/plain;base64,invalid@@base64").is_none());
    }

    #[test]
    fn test_get_data_url_not_data_url() {
        assert!(get_data_url("https://example.com/image.png").is_none());
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
    fn test_get_data_url_base64() {
        let content = get_data_url("data:text/plain;base64,SGVsbG8gd29ybGQ=").unwrap();
        assert_eq!(content, b"Hello world");

        assert!(get_data_url("data:image/png,rawdata").is_none());
        assert!(get_data_url("data:text/plain;base64,Invalid@Base64!").is_none());

        let empty = get_data_url("data:text/plain;base64,").unwrap();
        assert!(empty.is_empty());
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
    fn test_get_url_erroneous_ipfs_ipfs() {
        let bad_ipfs_url = "ipfs://ipfs/QmdVGrVGuymQRaPxPhVBbCQS2VJ2aZmUMHHubuMnbunTFq";
        assert_eq!(
            get_url(bad_ipfs_url),
            "https://ipfs.io/ipfs/QmdVGrVGuymQRaPxPhVBbCQS2VJ2aZmUMHHubuMnbunTFq"
        );
    }
}
