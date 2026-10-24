use std::sync::LazyLock;

use regex::Regex;

pub(crate) fn redact_urls(message: &str) -> String {
    static URL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?i)\b(?:https?|wss?)://[^\s<>"']+"#)
            .expect("Static URL pattern should always be valid")
    });
    URL.replace_all(message, "[redacted URL]").into_owned()
}

#[cfg(test)]
mod redact_urls_tests {
    use super::*;

    #[test]
    fn removes_endpoint_credentials_paths_and_queries() {
        for url in [
            "https://ethereum-mainnet.g.alchemy.com/v2/not-a-real-key",
            "http://example.invalid/rpc?api_key=not-a-real-key",
            "HTTPS://user:not-a-real-key@example.invalid/rpc",
            "wss://example.invalid/not-a-real-key",
            "http://[::1]:8545/not-a-real-key",
        ] {
            assert_eq!(
                redact_urls(&format!("RPC failed: {url}")),
                "RPC failed: [redacted URL]"
            );
        }
    }

    #[test]
    fn preserves_error_context_and_removes_multiple_quoted_urls() {
        assert_eq!(
            redact_urls("RPC failed: \"https://example.invalid/key\"; fallback 'wss://example.invalid/key2'"),
            "RPC failed: \"[redacted URL]\"; fallback '[redacted URL]'"
        );
        assert_eq!(
            redact_urls("RPC failed: connection refused"),
            "RPC failed: connection refused"
        );
    }
}
