use base64::Engine;
use url::Url;

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

    // Handle SVG utf8 data URLs
    if url.starts_with("data:image/svg+xml;utf8,") {
        let svg_content = url.trim_start_matches("data:image/svg+xml;utf8,");
        return Some(svg_content.as_bytes().to_vec());
    }

    // Handle SVG base64 data URLs
    if url.starts_with("data:image/svg+xml;base64,") {
        let b64 = url.trim_start_matches("data:image/svg+xml;base64,");
        let data = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
        return Some(data);
    }

    // Handle base64 encoded data URLs (generic)
    let parts: Vec<&str> = url.splitn(2, "base64,").collect();
    if parts.len() != 2 {
        return None;
    }

    let data = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .ok()?;

    Some(data)
}

/// Returns all possible IPFS gateway URLs for a given IPFS URL/hash
fn get_ipfs_gateway_urls(url: &str) -> Vec<String> {
    let ipfs_path = if url.starts_with("ipfs://ipfs/") {
        url.trim_start_matches("ipfs://ipfs/")
    } else if url.starts_with("ipfs://") {
        url.trim_start_matches("ipfs://")
    } else if (url.starts_with("Qm") && url.len() == 46) || url.starts_with("bafy") {
        url
    } else {
        return vec![url.to_string()];
    };
    IPFS_GATEWAYS
        .iter()
        .map(|gw| format!("{}/ipfs/{}", gw.trim_end_matches('/'), ipfs_path))
        .collect()
}

/// Converts IPFS/Arweave URLs to use a gateway, otherwise returns the original URL
pub fn get_url(url: &str) -> String {
    // Handle ar:// URLs
    if url.starts_with("ar://") {
        return format!("https://arweave.net/{}", url.trim_start_matches("ar://"));
    }
    get_ipfs_gateway_urls(url)
        .into_iter()
        .next()
        .unwrap_or_else(|| url.to_string())
}

/// Returns all possible gateway URLs for the given URL, or None if not an IPFS path.
pub fn all_ipfs_gateway_urls(url: &str) -> Option<Vec<String>> {
    let lower = url.to_ascii_lowercase();
    if let Some(idx) = lower.find("/ipfs/") {
        let path = &url[idx..];
        let end = path.find(&['?', '#'][..]).unwrap_or(path.len());
        let ipfs_path = &path[..end];
        Some(
            IPFS_GATEWAYS
                .iter()
                .map(|gw| format!("{}{}", gw.trim_end_matches('/'), ipfs_path))
                .collect(),
        )
    } else {
        None
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

/// List of fallback IPFS gateways to try, in order.
pub const IPFS_GATEWAYS: &[&str] = &[
    "https://ipfs.io",
    "https://cloudflare-ipfs.com",
    "https://gateway.pinata.cloud",
    "https://nftstorage.link",
    "https://cf-ipfs.com",
];

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

    #[test]
    fn test_get_data_url_svg() {
        // SVG base64 (valid minimal SVG)
        let svg_base64 = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnPjwvc3ZnPg==";
        let content = get_data_url(svg_base64).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&content),
            "<svg xmlns='http://www.w3.org/2000/svg'></svg>"
        );
        // SVG utf8
        let svg_utf8 = "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg'></svg>";
        let content = get_data_url(svg_utf8).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&content),
            "<svg xmlns='http://www.w3.org/2000/svg'></svg>"
        );
    }

    #[test]
    fn test_get_ipfs_gateway_urls_variants() {
        let valid_qm = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        let expected: Vec<String> = IPFS_GATEWAYS
            .iter()
            .map(|gw| format!("{}/ipfs/{}", gw.trim_end_matches('/'), valid_qm))
            .collect();

        let ipfs_url = &format!("ipfs://{}", valid_qm);
        let urls = get_ipfs_gateway_urls(ipfs_url);
        assert_eq!(urls, expected);

        let ipfs_url2 = &format!("ipfs://ipfs/{}", valid_qm);
        let urls2 = get_ipfs_gateway_urls(ipfs_url2);
        assert_eq!(urls2, expected);

        let raw_hash = valid_qm;
        let urls3 = get_ipfs_gateway_urls(raw_hash);
        assert_eq!(urls3, expected);

        let bafy_hash = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
        let expected_bafy: Vec<String> = IPFS_GATEWAYS
            .iter()
            .map(|gw| format!("{}/ipfs/{}", gw.trim_end_matches('/'), bafy_hash))
            .collect();
        let urls4 = get_ipfs_gateway_urls(bafy_hash);
        assert_eq!(urls4, expected_bafy);

        let http_url = "https://example.com/file.png";
        let urls5 = get_ipfs_gateway_urls(http_url);
        assert_eq!(urls5, vec![http_url.to_string()]);
    }

    #[test]
    fn test_all_ipfs_gateway_urls() {
        let url = "https://foo.com/ipfs/QmHash/123?foo=bar";
        let urls = all_ipfs_gateway_urls(url).unwrap();
        for gw in IPFS_GATEWAYS {
            assert!(urls.contains(&format!(
                "{}{}",
                gw.trim_end_matches('/'),
                "/ipfs/QmHash/123"
            )));
        }
        assert_eq!(urls.len(), IPFS_GATEWAYS.len());
        assert!(all_ipfs_gateway_urls("https://foo.com/notipfs/QmHash").is_none());
        assert!(all_ipfs_gateway_urls("").is_none());
    }

    #[test]
    fn test_get_url_arweave() {
        let ar_url = "ar://zXX4PCmJoOgFmLsObREHHwNBqnNCwoVNXylCbStZmno";
        assert_eq!(
            get_url(ar_url),
            "https://arweave.net/zXX4PCmJoOgFmLsObREHHwNBqnNCwoVNXylCbStZmno"
        );
        // Should not affect normal https URLs
        let normal_url = "https://arweave.net/zXX4PCmJoOgFmLsObREHHwNBqnNCwoVNXylCbStZmno";
        assert_eq!(get_url(normal_url), normal_url);
    }
}
