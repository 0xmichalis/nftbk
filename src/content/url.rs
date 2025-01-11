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
}
