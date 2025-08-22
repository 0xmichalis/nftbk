use base64::Engine;
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub enum IpfsGatewayType {
    Path,
    Subdomain,
}

#[derive(Debug, Clone)]
pub struct IpfsGatewayConfig {
    pub url: &'static str,
    pub gateway_type: IpfsGatewayType,
}

// A list of public IPFS gateways can be found here:
// https://ipfs.github.io/public-gateway-checker/
pub const IPFS_GATEWAYS: &[IpfsGatewayConfig] = &[
    IpfsGatewayConfig {
        url: "https://ipfs.io",
        gateway_type: IpfsGatewayType::Path,
    },
    IpfsGatewayConfig {
        url: "https://4everland.io",
        gateway_type: IpfsGatewayType::Subdomain,
    },
    IpfsGatewayConfig {
        url: "https://gateway.pinata.cloud",
        gateway_type: IpfsGatewayType::Path,
    },
];

pub fn is_data_url(url: &str) -> bool {
    url.starts_with("data:") || is_inline_svg(url)
}

/// Extract content from a data URL or inline SVG
pub fn get_data_url(url: &str) -> Option<Vec<u8>> {
    if !is_data_url(url) {
        return None;
    }

    // Handle inline SVGs
    if is_inline_svg(url) {
        return Some(url.as_bytes().to_vec());
    }

    // Handle JSON data URLs
    if url.starts_with("data:application/json;utf8,") {
        let json_content = url.trim_start_matches("data:application/json;utf8,");
        return Some(json_content.as_bytes().to_vec());
    }

    // Handle text/plain utf8 data URLs (not base64)
    if url.starts_with("data:text/plain,") {
        let text_content = url.trim_start_matches("data:text/plain,");
        return Some(text_content.as_bytes().to_vec());
    }

    // Handle SVG utf8 data URLs
    if url.starts_with("data:image/svg+xml;utf8,") {
        let svg_content = url.trim_start_matches("data:image/svg+xml;utf8,");
        return Some(svg_content.as_bytes().to_vec());
    }

    // Handle SVG data URLs without encoding (default charset, plain text)
    if url.starts_with("data:image/svg+xml,") {
        let svg_content = url.trim_start_matches("data:image/svg+xml,");
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

pub fn is_inline_svg(s: &str) -> bool {
    s.trim_start().starts_with("<svg")
}

/// Constructs a gateway URL for the given IPFS content and gateway configuration
fn construct_gateway_url(ipfs_content: &str, gateway: &IpfsGatewayConfig) -> String {
    match gateway.gateway_type {
        IpfsGatewayType::Path => {
            format!(
                "{}/ipfs/{}",
                gateway.url.trim_end_matches('/'),
                ipfs_content
            )
        }
        IpfsGatewayType::Subdomain => {
            // For subdomain gateways, extract the hash part and create subdomain URL
            let hash = ipfs_content.split('/').next().unwrap_or(ipfs_content);
            let path_part = if ipfs_content.contains('/') {
                format!("/{}", ipfs_content.split_once('/').unwrap().1)
            } else {
                String::new()
            };
            let base_domain = gateway.url.trim_start_matches("https://");
            format!("https://{hash}.ipfs.{base_domain}{path_part}")
        }
    }
}

/// Returns all possible IPFS gateway URLs for a given IPFS URL/hash
pub fn get_ipfs_gateway_urls(url: &str) -> Vec<String> {
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
        .map(|gw| construct_gateway_url(ipfs_path, gw))
        .collect()
}

/// Converts IPFS/Arweave URLs to use a gateway, otherwise returns the original URL
pub fn get_url(url: &str) -> String {
    if url.starts_with("ar://") {
        return format!("https://arweave.net/{}", url.trim_start_matches("ar://"));
    }
    get_ipfs_gateway_urls(url)
        .into_iter()
        .next()
        .unwrap_or_else(|| url.to_string())
}

/// Returns all possible gateway URLs for the given IPFS gateway URL, or None if the URL is not an IPFS gateway URL.
/// TODO: Should probably collapse this into get_ipfs_gateway_urls
pub fn all_ipfs_gateway_urls(url: &str) -> Option<Vec<String>> {
    extract_ipfs_content_from_gateway_url(url).map(|ipfs_content| {
        IPFS_GATEWAYS
            .iter()
            .map(|gw| construct_gateway_url(&ipfs_content, gw))
            .collect()
    })
}

/// Extracts IPFS content (hash + path) from a gateway URL
fn extract_ipfs_content_from_gateway_url(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();

    // Check for path-based gateway URLs (e.g., https://ipfs.io/ipfs/QmHash/path)
    if let Some(idx) = lower.find("/ipfs/") {
        let path = &url[idx..];
        let end = path.find(&['?', '#'][..]).unwrap_or(path.len());
        let ipfs_path = &path[..end];
        let ipfs_content = ipfs_path.trim_start_matches("/ipfs/");
        Some(ipfs_content.to_string())
    } else if lower.contains(".ipfs.") {
        // Check for subdomain gateway URLs (e.g., https://QmHash.ipfs.gateway.com/path)
        // Extract the hash and path from the subdomain URL
        if let Some(domain_start) = lower.find(".ipfs.") {
            let hash_part = &url[8..domain_start]; // Skip "https://"
            let domain_end = url[domain_start..]
                .find('/')
                .unwrap_or(url[domain_start..].len());
            let path_part = if domain_end < url[domain_start..].len() {
                let full_path = &url[domain_start + domain_end..];
                // Remove query parameters and fragments
                let end = full_path.find(&['?', '#'][..]).unwrap_or(full_path.len());
                &full_path[..end]
            } else {
                ""
            };

            let ipfs_content = if path_part.is_empty() {
                hash_part.to_string()
            } else {
                format!("{hash_part}{path_part}")
            };

            Some(ipfs_content)
        } else {
            None
        }
    } else {
        None
    }
}

/// Checks if a URL is an IPFS gateway URL by looking for /ipfs/ path
pub fn is_ipfs_gateway_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.contains("/ipfs/")
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
        // Should return the first gateway (https://ipfs.io) which is a path-based gateway
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
    fn test_get_ipfs_gateway_urls_variants() {
        let valid_qm = "bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m";
        let expected: Vec<String> = vec![
            // Path-based gateway (ipfs.io)
            "https://ipfs.io/ipfs/bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m".to_string(),
            // Subdomain gateway (4everland.io)
            "https://bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m.ipfs.4everland.io".to_string(),
            // Path-based gateway (gateway.pinata.cloud)
            "https://gateway.pinata.cloud/ipfs/bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m"
                .to_string(),
        ];

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
        let expected_bafy: Vec<String> = vec![
            // Path-based gateway (ipfs.io)
            "https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string(),
            // Subdomain gateway (4everland.io)
            "https://bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi.ipfs.4everland.io".to_string(),
            // Path-based gateway (gateway.pinata.cloud)
            "https://gateway.pinata.cloud/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string(),
        ];
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

        // Verify we have the expected number of gateways
        assert_eq!(urls.len(), IPFS_GATEWAYS.len());

        // Check specific expected URLs for both path and subdomain gateways
        let expected_urls = vec![
            // Path-based gateway (ipfs.io)
            "https://ipfs.io/ipfs/QmHash/123".to_string(),
            // Subdomain gateway (4everland.io)
            "https://QmHash.ipfs.4everland.io/123".to_string(),
            // Path-based gateway (gateway.pinata.cloud)
            "https://gateway.pinata.cloud/ipfs/QmHash/123".to_string(),
        ];

        for expected_url in &expected_urls {
            assert!(
                urls.contains(expected_url),
                "Missing expected URL: {}",
                expected_url
            );
        }

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

    #[test]
    fn test_is_ipfs_gateway_url() {
        // Test IPFS gateway URLs (any URL with /ipfs/ path)
        assert!(is_ipfs_gateway_url("https://ipfs.io/ipfs/QmHash"));
        assert!(is_ipfs_gateway_url(
            "https://gateway.pinata.cloud/ipfs/QmHash"
        ));
        assert!(is_ipfs_gateway_url("https://nftstorage.link/ipfs/QmHash"));

        // Test case insensitivity
        assert!(is_ipfs_gateway_url("https://IPFS.IO/ipfs/QmHash"));

        // Test other IPFS gateways (not in our predefined list)
        assert!(is_ipfs_gateway_url(
            "https://custom-gateway.com/ipfs/QmHash"
        ));
        assert!(is_ipfs_gateway_url("https://example.com/ipfs/QmHash"));
        assert!(is_ipfs_gateway_url(
            "https://ipfs.io.example.com/ipfs/QmHash"
        ));

        // Test non-IPFS URLs
        assert!(!is_ipfs_gateway_url("https://example.com/image.png"));
        assert!(!is_ipfs_gateway_url("https://ipfs.io/image.png")); // no /ipfs/ path
        assert!(!is_ipfs_gateway_url("https://example.com/ipfs")); // no trailing slash
    }

    #[test]
    fn test_ipfs_gateway_rotation() {
        // Test that IPFS gateway URLs can be detected and rotated
        let ipfs_url = "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";

        // Verify that all_ipfs_gateway_urls returns the expected gateways
        if let Some(gateway_urls) = all_ipfs_gateway_urls(ipfs_url) {
            assert!(!gateway_urls.is_empty());

            // Check that our predefined gateways are included
            let gateway_strings: Vec<&str> = gateway_urls.iter().map(|s| s.as_str()).collect();

            // Check for path-based gateways
            assert!(gateway_strings.iter().any(|url| url.contains("ipfs.io")));
            assert!(gateway_strings
                .iter()
                .any(|url| url.contains("gateway.pinata.cloud")));

            // Check for subdomain gateway
            assert!(gateway_strings.iter().any(|url| url
                .contains("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.4everland.io")));
        } else {
            panic!("all_ipfs_gateway_urls should return Some for IPFS URLs");
        }
    }

    #[test]
    fn test_subdomain_gateway_with_path() {
        // Test subdomain gateway with a path component
        let ipfs_url = "ipfs://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/images/logo.png";
        let urls = get_ipfs_gateway_urls(ipfs_url);

        let expected_subdomain = "https://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.4everland.io/images/logo.png";
        assert!(
            urls.contains(&expected_subdomain.to_string()),
            "URLs should contain subdomain gateway with path: {}",
            expected_subdomain
        );

        let expected_path =
            "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/images/logo.png";
        assert!(
            urls.contains(&expected_path.to_string()),
            "URLs should contain path-based gateway: {}",
            expected_path
        );
    }

    #[test]
    fn test_all_ipfs_gateway_urls_with_path() {
        // Test all_ipfs_gateway_urls with a path component
        let url = "https://foo.com/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/images/logo.png?v=1";
        let urls = all_ipfs_gateway_urls(url).unwrap();

        let expected_subdomain = "https://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.4everland.io/images/logo.png";
        assert!(
            urls.contains(&expected_subdomain.to_string()),
            "URLs should contain subdomain gateway with path: {}",
            expected_subdomain
        );

        let expected_path =
            "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/images/logo.png";
        assert!(
            urls.contains(&expected_path.to_string()),
            "URLs should contain path-based gateway: {}",
            expected_path
        );
    }

    #[test]
    fn test_gateway_types() {
        // Test that we have the expected gateway types
        assert_eq!(IPFS_GATEWAYS.len(), 3);

        // Check ipfs.io is path-based
        let ipfs_io = IPFS_GATEWAYS
            .iter()
            .find(|gw| gw.url == "https://ipfs.io")
            .unwrap();
        assert_eq!(ipfs_io.gateway_type, IpfsGatewayType::Path);

        // Check 4everland.io is subdomain-based
        let everland = IPFS_GATEWAYS
            .iter()
            .find(|gw| gw.url == "https://4everland.io")
            .unwrap();
        assert_eq!(everland.gateway_type, IpfsGatewayType::Subdomain);

        // Check gateway.pinata.cloud is path-based
        let pinata = IPFS_GATEWAYS
            .iter()
            .find(|gw| gw.url == "https://gateway.pinata.cloud")
            .unwrap();
        assert_eq!(pinata.gateway_type, IpfsGatewayType::Path);
    }

    #[test]
    fn test_all_ipfs_gateway_urls_subdomain() {
        // Test subdomain gateway URL from the decoded JSON
        let subdomain_url = "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.nftstorage.link/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4?id=12";
        let urls = all_ipfs_gateway_urls(subdomain_url).unwrap();

        // Verify we have the expected number of gateways
        assert_eq!(urls.len(), IPFS_GATEWAYS.len());

        // Check specific expected URLs for both path and subdomain gateways
        let expected_urls = vec![
            // Path-based gateway (ipfs.io)
            "https://ipfs.io/ipfs/bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4".to_string(),
            // Subdomain gateway (4everland.io)
            "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.4everland.io/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4".to_string(),
            // Path-based gateway (gateway.pinata.cloud)
            "https://gateway.pinata.cloud/ipfs/bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4".to_string(),
        ];

        for expected_url in &expected_urls {
            assert!(
                urls.contains(expected_url),
                "Missing expected URL: {}",
                expected_url
            );
        }

        // Test subdomain URL without path
        let subdomain_url_no_path = "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.nftstorage.link";
        let urls_no_path = all_ipfs_gateway_urls(subdomain_url_no_path).unwrap();
        assert_eq!(urls_no_path.len(), IPFS_GATEWAYS.len());

        // Check that it generates the correct subdomain URL for 4everland
        let expected_subdomain =
            "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.4everland.io";
        assert!(urls_no_path.contains(&expected_subdomain.to_string()));
    }
}
