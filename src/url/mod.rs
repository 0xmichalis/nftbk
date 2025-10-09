use base64::Engine;
use url::Url;

use crate::ipfs::config::{IpfsGatewayConfig, IPFS_GATEWAYS};
use crate::ipfs::url::get_ipfs_gateway_urls_with_gateways;

pub fn is_data_url(url: &str) -> bool {
    url.starts_with("data:") || is_svg_content(url) || is_json_content(url)
}

/// Extract content from a data URL or inline SVG
pub fn get_data_url(url: &str) -> Option<Vec<u8>> {
    if !is_data_url(url) {
        return None;
    }

    // Handle inline SVGs
    if is_svg_content(url) {
        return Some(url.as_bytes().to_vec());
    }

    // Handle JSON content
    if is_json_content(url) {
        return Some(url.as_bytes().to_vec());
    }

    // Handle common non-base64 data URL prefixes via a single loop
    const NON_BASE64_PREFIXES: &[&str] = &[
        "data:application/json;utf8,",
        "data:text/plain,",
        "data:image/svg+xml;utf8,",
        "data:image/svg+xml,",
    ];
    for prefix in NON_BASE64_PREFIXES {
        if url.starts_with(prefix) {
            return decode_after_prefix(url, prefix);
        }
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

/// Attempts to percent-decode the substring after a given prefix.
/// Falls back to raw bytes if decoding fails.
fn decode_after_prefix(url: &str, prefix: &str) -> Option<Vec<u8>> {
    let content = url.strip_prefix(prefix)?;
    if let Ok(decoded) = urlencoding::decode(content) {
        Some(decoded.into_owned().into_bytes())
    } else {
        Some(content.as_bytes().to_vec())
    }
}

pub fn is_svg_content(s: &str) -> bool {
    s.trim_start().starts_with("<svg")
}

/// Check if the content is JSON (starts with { or [)
pub fn is_json_content(s: &str) -> bool {
    let trimmed = s.trim_start();
    trimmed.starts_with('{') || trimmed.starts_with('[')
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

/// Resolve a potentially special URL (e.g., ar://, ipfs://, gateway) to a concrete HTTP URL
pub fn resolve_url_with_gateways(url: &str, gateways: &[IpfsGatewayConfig]) -> String {
    if url.starts_with("ar://") {
        return format!("https://arweave.net/{}", url.trim_start_matches("ar://"));
    }
    let urls = get_ipfs_gateway_urls_with_gateways(url, gateways);
    urls.into_iter().next().unwrap_or_else(|| url.to_string())
}

/// Convenience wrapper using default `IPFS_GATEWAYS`.
pub fn resolve_url(url: &str) -> String {
    resolve_url_with_gateways(url, IPFS_GATEWAYS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipfs::config::IPFS_GATEWAYS;

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
    fn test_get_data_url_gif() {
        // Test GIF data URL with base64 encoding
        let gif_data_url = "data:image/gif;base64,R0lGODlh"; // base64 encoded "GIF89a"
        let content = get_data_url(gif_data_url).unwrap();
        assert_eq!(content, b"GIF89a");

        // Test that it's recognized as a data URL
        assert!(is_data_url(gif_data_url));

        // Test that the content can be detected as GIF by the extension detection
        use crate::content::extensions::detect_media_extension;
        assert_eq!(detect_media_extension(&content), Some("gif"));
    }

    #[test]
    fn test_json_content_detection() {
        // Test JSON object
        let json_object = r#"{"name": "Test NFT", "description": "Test description"}"#;
        assert!(is_json_content(json_object));
        assert!(is_data_url(json_object));

        let content = get_data_url(json_object).unwrap();
        assert_eq!(content, json_object.as_bytes());

        // Test JSON array
        let json_array = r#"[{"trait_type": "artist", "value": "Test Artist"}]"#;
        assert!(is_json_content(json_array));
        assert!(is_data_url(json_array));

        let content = get_data_url(json_array).unwrap();
        assert_eq!(content, json_array.as_bytes());

        // Test that regular URLs are not detected as JSON
        let regular_url = "https://example.com/image.jpg";
        assert!(!is_json_content(regular_url));
        assert!(!is_data_url(regular_url));
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
    fn test_resolve_url_arweave() {
        let ar_url = "ar://zXX4PCmJoOgFmLsObREHHwNBqnNCwoVNXylCbStZmno";
        let resolved = resolve_url_with_gateways(ar_url, &[]);
        assert_eq!(
            resolved,
            "https://arweave.net/zXX4PCmJoOgFmLsObREHHwNBqnNCwoVNXylCbStZmno"
        );

        let normal = "https://arweave.net/zXX4PCmJoOgFmLsObREHHwNBqnNCwoVNXylCbStZmno";
        assert_eq!(resolve_url_with_gateways(normal, &[]), normal);
    }
    #[test]
    fn test_resolve_url_ipfs() {
        let ipfs_url = "ipfs://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        let resolved = resolve_url_with_gateways(ipfs_url, IPFS_GATEWAYS);
        assert!(resolved.contains("/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco"));
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
        // SVG plain (no encoding specified)
        let svg_plain = "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg'></svg>";
        let content = get_data_url(svg_plain).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&content),
            "<svg xmlns='http://www.w3.org/2000/svg'></svg>"
        );
    }

    #[test]
    fn test_get_data_url_text_plain_utf8() {
        let data_url = "data:text/plain,{\"name\":\"ArcadeGlyph #401\",\"description\":\"\",\"attributes\":[{\"trait_type\":\"Score\",\"value\":20},{\"trait_type\":\"Moves\",\"value\":149},{\"trait_type\": \"State\",\"value\":\"Game Over\"},{\"trait_type\":\"Start Block\",\"value\":\"19106930\"}],\"created_by\":\"Inner Space and Captain Pixel\",\"image\":\"<svg viewBox='0 0 11 17' fill='none' xmlns='http://www.w3.org/2000/svg'><rect x='.5' y='.5' width='10' height='16' fill='#221D42'/><rect x='.5' y='.5' width='10' height='10' fill='#07060E'/><rect x='.5' y='.5' width='10' height='10' stroke='#221D42'/><rect x='.5' y='.5' width='10' height='16' stroke='#221D42'/><rect rx='0.2' x='5' y='1' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='0.0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='3.0s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='7' y='6' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='3.0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='4.750s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='6' y='8' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='4.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='5.500s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='3' y='4' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='5.500s' attributeName='opacity' values='1' fill='freeze' /><animate begin='7.250s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='2' y='6' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='7.250s' attributeName='opacity' values='1' fill='freeze' /><animate begin='8.0s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='8' y='1' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='8.0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='10.750s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='9' y='9' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='10.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='13.0s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='9' y='5' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='13.0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='14.0s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='2' y='3' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='14.0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='16.250s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='2' y='8' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='16.250s' attributeName='opacity' values='1' fill='freeze' /><animate begin='17.500s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='9' y='6' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='17.500s' attributeName='opacity' values='1' fill='freeze' /><animate begin='19.750s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='9' y='2' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='19.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='20.750s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='2' y='9' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='20.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='24.250s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='1' y='1' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='24.250s' attributeName='opacity' values='1' fill='freeze' /><animate begin='26.500s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='9' y='8' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='26.500s' attributeName='opacity' values='1' fill='freeze' /><animate begin='30.750s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='2' y='1' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='30.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='34.250s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='2' y='3' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='34.250s' attributeName='opacity' values='1' fill='freeze' /><animate begin='34.750s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='3' y='6' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='34.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='35.750s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='5' y='3' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='35.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='37.0s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='3' y='2' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='37.0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='37.750s' attributeName='opacity' values='0' fill='freeze' /></rect><rect rx='0.2' x='9' y='6' opacity='0' width='1' height='1' fill='#C82B76'><animate begin='37.750s' attributeName='opacity' values='1' fill='freeze' /></rect><path d='M 1 9 1 9 2 9 3 9 3 8 3 7 3 6 3 5 3 4 3 3 3 2 3 1 4 1 5 1 5 2 5 3 5 4 5 5 5 6 6 6 7 6 7 7 7 8 6 8 6 7 5 7 5 6 5 5 5 4 4 4 3 4 3 5 3 6 2 6 2 5 2 4 2 3 2 2 2 1 3 1 4 1 5 1 6 1 7 1 8 1 8 2 8 3 8 4 8 5 8 6 8 7 8 8 8 9 9 9 9 8 9 7 9 6 9 5 9 4 9 3 8 3 7 3 6 3 5 3 4 3 3 3 2 3 2 4 2 5 2 6 2 7 2 8 3 8 3 7 3 6 4 6 5 6 6 6 7 6 8 6 9 6 9 5 9 4 9 3 9 2 8 2 8 3 8 4 8 5 7 5 6 5 5 6 5 7 5 8 5 9 4 9 3 9 2 9 2 8 2 7 2 6 2 5 2 4 2 3 2 2 2 1 1 1 1 2 1 3 1 4 1 5 1 6 1 7 1 8 1 9 2 9 2 8 3 8 4 8 5 8 6 8 7 8 8 8 9 8 9 7 9 6 9 5 9 4 9 3 9 2 9 1 8 1 7 1 6 1 5 1 4 1 3 1 2 1 2 2 2 3 2 4 2 5 2 6 3 6 3 5 3 4 3 3 4 3 5 3 5 2 4 2 3 2 ' id='p1'/><path d='M 2.5 11.5 h 2 v 4 h -2 v -4.5' opacity='0' stroke='#fff'><animate begin='0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='17.500s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 3 11.5 h 1.5 v 4.5' opacity='0' stroke='#fff'><animate begin='17.500s' attributeName='opacity' values='1' fill='freeze' /><animate begin='37.750s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 2 11.5 h 2.5 v 2 h -2 v 2 h 2.5' opacity='0' stroke='#fff'><animate begin='37.750s' attributeName='opacity' values='1' fill='freeze' /></path><path d='M 6 11.5 h 2.5 v 4 h -2 v -3.5' opacity='0' stroke='#fff'><animate begin='0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='3.0s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 7 11.5 h 1.5 v 4.5' opacity='0' stroke='#fff'><animate begin='3.0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='4.750s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6 11.5 h 2.5 v 2 h -2 v 2 h 2.5' opacity='0' stroke='#fff'><animate begin='4.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='5.500s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6 11.5 h 2.5 v 2 h -2.5 h 2.5 v 2 h -2.5' opacity='0' stroke='#fff'><animate begin='5.500s' attributeName='opacity' values='1' fill='freeze' /><animate begin='7.250s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6.5 11 v 2.5 h 2 v -2.5 v 5' opacity='0' stroke='#fff'><animate begin='7.250s' attributeName='opacity' values='1' fill='freeze' /><animate begin='8.0s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 9 11.5 h -2.5 v 2 h 2 v 2 h -2.5' opacity='0' stroke='#fff'><animate begin='8.0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='10.750s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6.5 11 v 4.5 h 2 v -2 h -2.5' opacity='0' stroke='#fff'><animate begin='10.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='13.0s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6 11.5 h 2.5 v 2.5 M 7.5 14 v 2' opacity='0' stroke='#fff'><animate begin='13.0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='14.0s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6 11.5 h 2.5 v 2 h -2 v -2.5 v 4.5 h 2 v -2.5' opacity='0' stroke='#fff'><animate begin='14.0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='16.250s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 9 13.5 h -2.5 v -2 h 2 v 4.5' opacity='0' stroke='#fff'><animate begin='16.250s' attributeName='opacity' values='1' fill='freeze' /><animate begin='17.500s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6 11.5 h 2.5 v 4 h -2 v -3.5' opacity='0' stroke='#fff'><animate begin='17.500s' attributeName='opacity' values='1' fill='freeze' /><animate begin='19.750s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 7 11.5 h 1.5 v 4.5' opacity='0' stroke='#fff'><animate begin='19.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='20.750s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6 11.5 h 2.5 v 2 h -2 v 2 h 2.5' opacity='0' stroke='#fff'><animate begin='20.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='24.250s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6 11.5 h 2.5 v 2 h -2.5 h 2.5 v 2 h -2.5' opacity='0' stroke='#fff'><animate begin='24.250s' attributeName='opacity' values='1' fill='freeze' /><animate begin='26.500s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6.5 11 v 2.5 h 2 v -2.5 v 5' opacity='0' stroke='#fff'><animate begin='26.500s' attributeName='opacity' values='1' fill='freeze' /><animate begin='30.750s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 9 11.5 h -2.5 v 2 h 2 v 2 h -2.5' opacity='0' stroke='#fff'><animate begin='30.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='34.250s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6.5 11 v 4.5 h 2 v -2 h -2.5' opacity='0' stroke='#fff'><animate begin='34.250s' attributeName='opacity' values='1' fill='freeze' /><animate begin='34.750s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6 11.5 h 2.5 v 2.5 M 7.5 14 v 2' opacity='0' stroke='#fff'><animate begin='34.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='35.750s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6 11.5 h 2.5 v 2 h -2 v -2.5 v 4.5 h 2 v -2.5' opacity='0' stroke='#fff'><animate begin='35.750s' attributeName='opacity' values='1' fill='freeze' /><animate begin='37.0s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 9 13.5 h -2.5 v -2 h 2 v 4.5' opacity='0' stroke='#fff'><animate begin='37.0s' attributeName='opacity' values='1' fill='freeze' /><animate begin='37.750s' attributeName='opacity' values='0' fill='freeze' /></path><path d='M 6 11.5 h 2.5 v 4 h -2 v -3.5' opacity='0' stroke='#fff'><animate begin='37.750s' attributeName='opacity' values='1' fill='freeze' /></path><g><animate attributeName='opacity' values='0;1;' dur='1s' calcMode='discrete' begin='38.0' repeatCount='5'/><rect><animate id='stop' being='0s' dur='38.0s' fill='freeze'/></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#5E05CE'><animateMotion begin='0s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='0s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='0.25s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='0.25s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='0.5s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='0.5s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='0.750s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='3.0s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='1.0s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='4.750s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='1.250s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='5.500s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='1.500s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='7.250s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='1.750s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='8.0s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='2.0s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='10.750s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='2.250s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='13.0s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='2.500s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='14.0s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='2.750s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='16.250s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='3.0s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='17.500s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='3.250s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='19.750s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='3.500s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='20.750s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='3.750s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='24.250s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='4.0s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='26.500s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='4.250s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='30.750s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='4.500s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='34.250s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='4.750s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='34.750s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='5.0s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='35.750s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='5.250s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='37.0s' attributeName='opacity' values='1' fill='freeze' /></rect><rect rx='0.2' width='1' opacity='0' height='1' fill='#8C3BE5'><animateMotion begin='5.500s' end='stop.end' dur='38.0s' fill='freeze'><mpath href='#p1'/></animateMotion><animate begin='37.750s' attributeName='opacity' values='1' fill='freeze' /></rect></g></svg>\"}"
        ;
        let content = get_data_url(data_url).unwrap();
        assert!(String::from_utf8_lossy(&content).starts_with("{\"name\":\"ArcadeGlyph #401\""));
    }

    #[test]
    fn test_get_data_url_inline_svg() {
        let svg = "<svg xmlns='http://www.w3.org/2000/svg'></svg>";
        let content = get_data_url(svg).unwrap();
        assert_eq!(String::from_utf8_lossy(&content), svg);
    }

    #[test]
    fn test_get_data_url_svg_problematic() {
        // Test the specific SVG data URL that was failing
        let problematic_svg = "data:image/svg+xml,<svg width='512' height='512' xmlns='http://www.w3.org/2000/svg'><style>rect{width:16px;height:16px;stroke-width:1px;stroke:#c4c4c4}.b{fill:#000}.w{fill:#fff}</style><rect x='0' y='0' class='w'/></svg>";
        let content = get_data_url(problematic_svg).unwrap();
        let content_str = String::from_utf8_lossy(&content);
        assert!(content_str.starts_with("<svg width='512' height='512'"));
        assert!(content_str.contains("xmlns='http://www.w3.org/2000/svg'"));
        assert!(content_str.ends_with("</svg>"));
    }
}
