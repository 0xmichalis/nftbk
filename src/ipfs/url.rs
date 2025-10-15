use crate::ipfs::config::{IpfsGatewayConfig, IpfsGatewayType, IPFS_GATEWAYS};

pub(crate) fn construct_gateway_url(ipfs_content: &str, gateway: &IpfsGatewayConfig) -> String {
    match gateway.gateway_type {
        IpfsGatewayType::Path => {
            format!(
                "{}/ipfs/{}",
                gateway.url.trim_end_matches('/'),
                ipfs_content
            )
        }
        IpfsGatewayType::Subdomain => {
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

pub fn all_ipfs_gateway_urls_with_gateways(
    url: &str,
    gateways: &[IpfsGatewayConfig],
) -> Option<Vec<String>> {
    extract_ipfs_content_from_gateway_url(url).map(|ipfs_content| {
        gateways
            .iter()
            .map(|gw| construct_gateway_url(&ipfs_content, gw))
            .collect()
    })
}

pub(crate) fn extract_ipfs_content_from_gateway_url(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();

    if let Some(idx) = lower.find("/ipfs/") {
        let path = &url[idx..];
        let end = path.find(&['?', '#'][..]).unwrap_or(path.len());
        let ipfs_path = &path[..end];
        let ipfs_content = ipfs_path.trim_start_matches("/ipfs/");
        Some(ipfs_content.to_string())
    } else if lower.contains(".ipfs.") {
        if let Some(domain_start) = lower.find(".ipfs.") {
            let hash_part = &url[8..domain_start];
            let domain_end = url[domain_start..]
                .find('/')
                .unwrap_or(url[domain_start..].len());
            let path_part = if domain_end < url[domain_start..].len() {
                let full_path = &url[domain_start + domain_end..];
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

pub fn is_ipfs_gateway_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    lower.contains("/ipfs/")
}

pub fn extract_ipfs_cid(url: &str) -> Option<String> {
    extract_ipfs_content(url).map(|s| s.split('/').next().unwrap_or("").to_string())
}

pub fn extract_ipfs_content(url: &str) -> Option<String> {
    // Normalize by stripping query and fragment which sometimes appear on raw CIDs (e.g., fxhash)
    let end = url.find(&['?', '#'][..]).unwrap_or(url.len());
    let base = &url[..end];

    if base.starts_with("ipfs://ipfs/") {
        return Some(base.trim_start_matches("ipfs://ipfs/").to_string());
    }
    if base.starts_with("ipfs://") {
        return Some(base.trim_start_matches("ipfs://").to_string());
    }
    if (base.starts_with("Qm") && base.len() == 46) || base.starts_with("bafy") {
        return Some(base.to_string());
    }
    if let Some(content) = extract_ipfs_content_from_gateway_url(base) {
        return Some(content);
    }
    None
}

pub fn filter_ipfs_urls(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter(|u| {
            u.starts_with("ipfs://")
                || is_ipfs_gateway_url(u)
                || (u.starts_with("Qm") && u.len() == 46)
                || u.starts_with("bafy")
        })
        .cloned()
        .collect()
}

pub fn get_ipfs_gateway_urls_with_gateways(
    url: &str,
    gateways: &[IpfsGatewayConfig],
) -> Vec<String> {
    if let Some(ipfs_path) = extract_ipfs_content(url) {
        return gateways
            .iter()
            .map(|gw| construct_gateway_url(&ipfs_path, gw))
            .collect();
    }
    vec![url.to_string()]
}

pub fn get_ipfs_gateway_urls(url: &str) -> Vec<String> {
    get_ipfs_gateway_urls_with_gateways(url, IPFS_GATEWAYS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipfs::config::{IpfsGatewayType, IPFS_GATEWAYS};

    mod extract_ipfs_content_tests {
        use super::*;

        #[test]
        fn extracts_from_various_sources() {
            let p = extract_ipfs_content("ipfs://QmHash/path/to").unwrap();
            assert_eq!(p, "QmHash/path/to");

            let p2 = extract_ipfs_content("ipfs://ipfs/QmHash/dir/file").unwrap();
            assert_eq!(p2, "QmHash/dir/file");

            let raw = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
            assert_eq!(extract_ipfs_content(raw).as_deref(), Some(raw));

            let bafy = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
            assert_eq!(extract_ipfs_content(bafy).as_deref(), Some(bafy));

            let gw = "https://ipfs.io/ipfs/QmHash/foo?bar=baz#frag";
            assert_eq!(extract_ipfs_content(gw).as_deref(), Some("QmHash/foo"));

            let sub = "https://QmHash.ipfs.4everland.io/path/file";
            assert_eq!(
                extract_ipfs_content(sub).as_deref(),
                Some("QmHash/path/file")
            );

            assert!(extract_ipfs_content("https://example.com").is_none());
        }
    }

    mod extract_ipfs_cid_tests {
        use super::*;

        #[test]
        fn extracts_cid_from_inputs() {
            assert_eq!(
                extract_ipfs_cid("ipfs://QmHash/path/to").as_deref(),
                Some("QmHash")
            );
            assert_eq!(
                extract_ipfs_cid("ipfs://ipfs/QmHash/dir/file").as_deref(),
                Some("QmHash")
            );
            let raw = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
            assert_eq!(extract_ipfs_cid(raw).as_deref(), Some(raw));
            let bafy = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
            assert_eq!(extract_ipfs_cid(bafy).as_deref(), Some(bafy));
            let gw = "https://ipfs.io/ipfs/QmHash/foo?bar=baz#frag";
            assert_eq!(extract_ipfs_cid(gw).as_deref(), Some("QmHash"));
            let sub = "https://QmHash.ipfs.4everland.io/path/file";
            assert_eq!(extract_ipfs_cid(sub).as_deref(), Some("QmHash"));
            assert!(extract_ipfs_cid("https://example.com").is_none());

            // New: raw CID with query params (e.g., fxhash)
            assert_eq!(
                extract_ipfs_cid("Qmes8gbwpWoFLsReGqCGnvjVq2FeSBTVDasKPq8Jr3sef9?fxhash=onh7ZQAaN9y1U5ZVSjBCPRsdptQpS39eJsHJEorp8Vm14dcxTjd")
                    .as_deref(),
                Some("Qmes8gbwpWoFLsReGqCGnvjVq2FeSBTVDasKPq8Jr3sef9")
            );

            // New: ipfs:// URL with query/fragment
            assert_eq!(
                extract_ipfs_cid("ipfs://QmHash/path?foo=bar#frag").as_deref(),
                Some("QmHash")
            );
        }
    }

    mod filter_ipfs_urls_tests {
        use super::*;

        #[test]
        fn filters_mixed_urls() {
            let urls = vec![
                "https://example.com/file.png".to_string(),
                "ipfs://QmHash".to_string(),
                "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco".to_string(),
                "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string(),
                "https://ipfs.io/ipfs/QmHash".to_string(),
            ];
            let filtered = filter_ipfs_urls(&urls);
            assert_eq!(filtered.len(), 4);
            assert!(filtered.iter().any(|u| u.starts_with("ipfs://")));
            assert!(filtered.iter().any(|u| u.starts_with("QmXoypizj")));
            assert!(filtered.iter().any(|u| u.starts_with("bafy")));
            assert!(filtered
                .iter()
                .any(|u| u.contains("/ipfs/") && u.starts_with("https://")));
        }
    }

    mod get_ipfs_gateway_urls_tests {
        use super::*;

        #[test]
        fn returns_expected_variants() {
            let valid_qm = "bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m";
            let expected: Vec<String> = vec![
                "https://ipfs.io/ipfs/bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m".to_string(),
                "https://bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m.ipfs.4everland.io".to_string(),
                "https://gateway.pinata.cloud/ipfs/bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m".to_string(),
            ];

            let ipfs_url = &format!("ipfs://{valid_qm}");
            let urls = get_ipfs_gateway_urls(ipfs_url);
            assert_eq!(urls, expected);

            let ipfs_url2 = &format!("ipfs://ipfs/{valid_qm}");
            let urls2 = get_ipfs_gateway_urls(ipfs_url2);
            assert_eq!(urls2, expected);

            let raw_hash = valid_qm;
            let urls3 = get_ipfs_gateway_urls(raw_hash);
            assert_eq!(urls3, expected);
        }

        #[test]
        fn supports_subdomain_and_path_in_urls() {
            let ipfs_url = "ipfs://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/images/logo.png";
            let urls = get_ipfs_gateway_urls(ipfs_url);
            let expected_subdomain = "https://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.4everland.io/images/logo.png";
            assert!(urls.contains(&expected_subdomain.to_string()));
            let expected_path =
                "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/images/logo.png";
            assert!(urls.contains(&expected_path.to_string()));
        }

        #[test]
        fn accepts_http_non_ipfs() {
            let http_url = "https://example.com/file.png";
            let urls5 = get_ipfs_gateway_urls(http_url);
            assert_eq!(urls5, vec![http_url.to_string()]);
        }

        #[test]
        fn supports_http_ipfs_input() {
            let url = "https://foo.com/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/images/logo.png?v=1";
            let urls = get_ipfs_gateway_urls(url);
            let expected_subdomain = "https://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.4everland.io/images/logo.png";
            assert!(urls.contains(&expected_subdomain.to_string()));
            let expected_path =
                "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/images/logo.png";
            assert!(urls.contains(&expected_path.to_string()));
        }
    }

    mod all_ipfs_gateway_urls_with_gateways_tests {
        use super::*;

        #[test]
        fn builds_all_from_path_gateway_url() {
            let url = "https://foo.com/ipfs/QmHash/123?foo=bar";
            let urls = all_ipfs_gateway_urls_with_gateways(url, IPFS_GATEWAYS).unwrap();
            assert_eq!(urls.len(), IPFS_GATEWAYS.len());
            let expected_urls = vec![
                "https://ipfs.io/ipfs/QmHash/123".to_string(),
                "https://QmHash.ipfs.4everland.io/123".to_string(),
                "https://gateway.pinata.cloud/ipfs/QmHash/123".to_string(),
            ];
            for expected_url in &expected_urls {
                assert!(
                    urls.contains(expected_url),
                    "Missing expected URL: {expected_url}"
                );
            }
            assert!(all_ipfs_gateway_urls_with_gateways(
                "https://foo.com/notipfs/QmHash",
                IPFS_GATEWAYS
            )
            .is_none());
            assert!(all_ipfs_gateway_urls_with_gateways("", IPFS_GATEWAYS).is_none());
        }

        #[test]
        fn builds_all_from_subdomain_gateway_url() {
            let subdomain_url = "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.nftstorage.link/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4?id=12";
            let urls = all_ipfs_gateway_urls_with_gateways(subdomain_url, IPFS_GATEWAYS).unwrap();
            assert_eq!(urls.len(), IPFS_GATEWAYS.len());
            let expected_urls = vec![
                "https://ipfs.io/ipfs/bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4".to_string(),
                "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.4everland.io/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4".to_string(),
                "https://gateway.pinata.cloud/ipfs/bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4".to_string(),
            ];
            for expected_url in &expected_urls {
                assert!(
                    urls.contains(expected_url),
                    "Missing expected URL: {expected_url}"
                );
            }

            let subdomain_url_no_path = "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.nftstorage.link";
            let urls_no_path =
                all_ipfs_gateway_urls_with_gateways(subdomain_url_no_path, IPFS_GATEWAYS).unwrap();
            assert_eq!(urls_no_path.len(), IPFS_GATEWAYS.len());
            let expected_subdomain =
                "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.4everland.io";
            assert!(urls_no_path.contains(&expected_subdomain.to_string()));
        }
    }

    mod is_ipfs_gateway_url_tests {
        use super::*;

        #[test]
        fn detects_gateway_patterns() {
            assert!(is_ipfs_gateway_url("https://ipfs.io/ipfs/QmHash"));
            assert!(is_ipfs_gateway_url(
                "https://gateway.pinata.cloud/ipfs/QmHash"
            ));
            assert!(is_ipfs_gateway_url("https://nftstorage.link/ipfs/QmHash"));
            assert!(is_ipfs_gateway_url("https://IPFS.IO/ipfs/QmHash"));
            assert!(is_ipfs_gateway_url(
                "https://custom-gateway.com/ipfs/QmHash"
            ));
            assert!(is_ipfs_gateway_url("https://example.com/ipfs/QmHash"));
            assert!(is_ipfs_gateway_url(
                "https://ipfs.io.example.com/ipfs/QmHash"
            ));
            assert!(!is_ipfs_gateway_url("https://example.com/image.png"));
            assert!(!is_ipfs_gateway_url("https://ipfs.io/image.png"));
            assert!(!is_ipfs_gateway_url("https://example.com/ipfs"));
        }
    }

    mod gateways_tests {
        use super::*;

        #[test]
        fn gateway_types_are_expected() {
            assert_eq!(IPFS_GATEWAYS.len(), 3);
            let ipfs_io = IPFS_GATEWAYS
                .iter()
                .find(|gw| gw.url == "https://ipfs.io")
                .unwrap();
            assert_eq!(ipfs_io.gateway_type, IpfsGatewayType::Path);
            let everland = IPFS_GATEWAYS
                .iter()
                .find(|gw| gw.url == "https://4everland.io")
                .unwrap();
            assert_eq!(everland.gateway_type, IpfsGatewayType::Subdomain);
            let pinata = IPFS_GATEWAYS
                .iter()
                .find(|gw| gw.url == "https://gateway.pinata.cloud")
                .unwrap();
            assert_eq!(pinata.gateway_type, IpfsGatewayType::Path);
        }
    }

    mod rotation_tests {
        use super::*;

        #[test]
        fn includes_expected_gateways() {
            let ipfs_url = "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
            if let Some(gateway_urls) = all_ipfs_gateway_urls_with_gateways(ipfs_url, IPFS_GATEWAYS)
            {
                assert!(!gateway_urls.is_empty());
                let gateway_strings: Vec<&str> = gateway_urls.iter().map(|s| s.as_str()).collect();
                assert!(gateway_strings.iter().any(|url| url.contains("ipfs.io")));
                assert!(gateway_strings
                    .iter()
                    .any(|url| url.contains("gateway.pinata.cloud")));
                assert!(gateway_strings.iter().any(|url| url
                    .contains("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.4everland.io")));
            } else {
                panic!("all_ipfs_gateway_urls should return Some for IPFS URLs");
            }
        }
    }
}
