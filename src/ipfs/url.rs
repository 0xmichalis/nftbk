use crate::ipfs::config::{IpfsGatewayConfig, IpfsGatewayType, IPFS_GATEWAYS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayUrl {
    pub url: String,
    pub bearer_token: Option<String>,
}

fn is_valid_cid(cid: &str) -> bool {
    // CIDv0: 46 chars, starts with Qm, base58btc charset (no 0, O, I, l)
    if cid.len() == 46 && cid.starts_with("Qm") {
        const BASE58BTC: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        if cid.chars().all(|c| BASE58BTC.contains(c)) {
            return true;
        }
    }
    // CIDv1 (most common): base32lower, typically starts with bafy
    if cid.starts_with("bafy")
        && cid
            .chars()
            .all(|c: char| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
    {
        return true;
    }
    false
}

fn construct_gateway_url(ipfs_path: &str, gateway: &IpfsGatewayConfig) -> String {
    match gateway.gateway_type {
        IpfsGatewayType::Path => {
            format!("{}/ipfs/{}", gateway.url.trim_end_matches('/'), ipfs_path)
        }
        IpfsGatewayType::Subdomain => {
            let hash = ipfs_path.split('/').next().unwrap_or(ipfs_path);
            let path_part = if let Some((_, path)) = ipfs_path.split_once('/') {
                format!("/{}", path)
            } else {
                String::new()
            };
            let base_domain = gateway.url.trim_start_matches("https://");
            format!("https://{hash}.ipfs.{base_domain}{path_part}")
        }
    }
}

fn extract_ipfs_path_from_gateway_url(url: &str) -> Option<String> {
    let lower = url.to_ascii_lowercase();

    if let Some(idx) = lower.find("/ipfs/") {
        let path = &url[idx..];
        let end = path.find(&['?', '#'][..]).unwrap_or(path.len());
        let ipfs_path = &path[..end];
        let ipfs_path = ipfs_path.trim_start_matches("/ipfs/");
        let cid_part = ipfs_path.split('/').next().unwrap_or("");
        if is_valid_cid(cid_part) {
            Some(ipfs_path.to_string())
        } else {
            None
        }
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

            let ipfs_path = if path_part.is_empty() {
                hash_part.to_string()
            } else {
                format!("{hash_part}{path_part}")
            };

            let cid_part = ipfs_path.split('/').next().unwrap_or("");
            if is_valid_cid(cid_part) {
                Some(ipfs_path)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

pub fn generate_url_for_gateways(
    url: &str,
    gateways: &[IpfsGatewayConfig],
) -> Option<Vec<GatewayUrl>> {
    extract_ipfs_path_from_gateway_url(url).map(|ipfs_path| {
        gateways
            .iter()
            .map(|gw| GatewayUrl {
                url: construct_gateway_url(&ipfs_path, gw),
                bearer_token: gw.resolve_bearer_token(),
            })
            .collect()
    })
}

fn extract_ipfs_path(url: &str) -> Option<String> {
    // Normalize by stripping query and fragment which sometimes appear on raw CIDs (e.g., fxhash)
    let end = url.find(&['?', '#'][..]).unwrap_or(url.len());
    let base = &url[..end];

    if base.starts_with("ipfs://ipfs/") {
        return Some(base.trim_start_matches("ipfs://ipfs/").to_string());
    }
    if base.starts_with("ipfs://") {
        return Some(base.trim_start_matches("ipfs://").to_string());
    }
    if is_valid_cid(base) {
        return Some(base.to_string());
    }
    if let Some(content) = extract_ipfs_path_from_gateway_url(base) {
        return Some(content);
    }
    None
}

pub fn extract_ipfs_cid(url: &str) -> Option<String> {
    extract_ipfs_path(url).map(|s| s.split('/').next().unwrap_or("").to_string())
}

pub fn get_ipfs_gateway_urls_with_gateways(
    url: &str,
    gateways: &[IpfsGatewayConfig],
) -> Vec<String> {
    if let Some(ipfs_path) = extract_ipfs_path(url) {
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

    mod extract_ipfs_path_tests {
        use super::*;

        #[test]
        fn extracts_from_various_sources() {
            let p = extract_ipfs_path("ipfs://QmHash/path/to").unwrap();
            assert_eq!(p, "QmHash/path/to");

            let p2 = extract_ipfs_path("ipfs://ipfs/QmHash/dir/file").unwrap();
            assert_eq!(p2, "QmHash/dir/file");

            let raw = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
            assert_eq!(extract_ipfs_path(raw).as_deref(), Some(raw));

            let bafy = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
            assert_eq!(extract_ipfs_path(bafy).as_deref(), Some(bafy));

            let gw = "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/foo?bar=baz#frag";
            assert_eq!(
                extract_ipfs_path(gw).as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/foo")
            );

            let sub = "https://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.4everland.io/path/file";
            assert_eq!(
                extract_ipfs_path(sub).as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/path/file")
            );

            assert!(extract_ipfs_path("https://example.com").is_none());
        }
    }

    mod extract_ipfs_path_from_gateway_url_tests {
        use super::*;

        #[test]
        fn extracts_from_path_gateway_variants() {
            // basic path gateway
            let gw = "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/foo";
            assert_eq!(
                extract_ipfs_path_from_gateway_url(gw).as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/foo")
            );

            // with query and fragment
            let gw_qf =
                "https://example.com/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/bar?x=1#y";
            assert_eq!(
                extract_ipfs_path_from_gateway_url(gw_qf).as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/bar")
            );

            // path gateway without extra path
            let gw_root =
                "https://gateway.pinata.cloud/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
            assert_eq!(
                extract_ipfs_path_from_gateway_url(gw_root).as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco")
            );
        }

        #[test]
        fn extracts_from_subdomain_gateway_variants() {
            // basic subdomain
            let sub = "https://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.4everland.io/path/file";
            assert_eq!(
                extract_ipfs_path_from_gateway_url(sub).as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/path/file")
            );

            // subdomain root
            let sub_root =
                "https://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.nftstorage.link";
            assert_eq!(
                extract_ipfs_path_from_gateway_url(sub_root).as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco")
            );

            // with query/fragment
            let sub_qf = "https://bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m.ipfs.nftstorage.link/images?a=1#b";
            assert_eq!(
                extract_ipfs_path_from_gateway_url(sub_qf).as_deref(),
                Some("bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m/images")
            );
        }

        #[test]
        fn rejects_invalid_gateway_urls() {
            assert!(extract_ipfs_path_from_gateway_url("https://example.com").is_none());
            assert!(extract_ipfs_path_from_gateway_url("https://onpodx.net/ipfs/1").is_none());
            assert!(extract_ipfs_path_from_gateway_url("https://foo.bar/ipfs/").is_none());
            assert!(extract_ipfs_path_from_gateway_url("https://foo.bar/ifps/QmHash").is_none());
            assert!(
                extract_ipfs_path_from_gateway_url("https://notcid.ipfs.nftstorage.link").is_none()
            );
        }
    }

    mod extract_ipfs_cid_tests {
        use super::*;

        #[test]
        fn extracts_cid_from_inputs() {
            assert_eq!(
                extract_ipfs_cid("ipfs://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/path/to")
                    .as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco")
            );
            assert_eq!(
                extract_ipfs_cid(
                    "ipfs://ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/dir/file"
                )
                .as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco")
            );
            let raw = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
            assert_eq!(extract_ipfs_cid(raw).as_deref(), Some(raw));
            let bafy = "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi";
            assert_eq!(extract_ipfs_cid(bafy).as_deref(), Some(bafy));
            let gw = "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/foo?bar=baz#frag";
            assert_eq!(
                extract_ipfs_cid(gw).as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco")
            );
            let sub = "https://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.4everland.io/path/file";
            assert_eq!(
                extract_ipfs_cid(sub).as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco")
            );
            assert!(extract_ipfs_cid("https://example.com").is_none());

            // New: raw CID with query params (e.g., fxhash)
            assert_eq!(
                extract_ipfs_cid("Qmes8gbwpWoFLsReGqCGnvjVq2FeSBTVDasKPq8Jr3sef9?fxhash=onh7ZQAaN9y1U5ZVSjBCPRsdptQpS39eJsHJEorp8Vm14dcxTjd")
                    .as_deref(),
                Some("Qmes8gbwpWoFLsReGqCGnvjVq2FeSBTVDasKPq8Jr3sef9")
            );

            // New: ipfs:// URL with query/fragment
            assert_eq!(
                extract_ipfs_cid(
                    "ipfs://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/path?foo=bar#frag"
                )
                .as_deref(),
                Some("QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco")
            );
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

    mod generate_url_for_gateways_tests {
        use super::*;

        #[test]
        fn builds_all_from_path_gateway_url() {
            let url =
                "https://foo.com/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/123?foo=bar";
            let urls = generate_url_for_gateways(url, IPFS_GATEWAYS).unwrap();
            assert_eq!(urls.len(), IPFS_GATEWAYS.len());
            let expected_urls = vec![
                "https://ipfs.io/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/123".to_string(),
                "https://QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco.ipfs.4everland.io/123".to_string(),
                "https://gateway.pinata.cloud/ipfs/QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/123".to_string(),
            ];
            for expected_url in &expected_urls {
                assert!(
                    urls.iter().any(|g| &g.url == expected_url),
                    "Missing expected URL: {expected_url}"
                );
            }
            assert!(
                generate_url_for_gateways("https://foo.com/notipfs/QmHash", IPFS_GATEWAYS)
                    .is_none()
            );
            assert!(generate_url_for_gateways("", IPFS_GATEWAYS).is_none());
        }

        #[test]
        fn builds_all_from_subdomain_gateway_url() {
            let subdomain_url = "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.nftstorage.link/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4?id=12";
            let urls = generate_url_for_gateways(subdomain_url, IPFS_GATEWAYS).unwrap();
            assert_eq!(urls.len(), IPFS_GATEWAYS.len());
            let expected_urls = vec![
                "https://ipfs.io/ipfs/bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4".to_string(),
                "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.4everland.io/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4".to_string(),
                "https://gateway.pinata.cloud/ipfs/bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya/1080P%20NFT/012_placeholder_minted_UnisocksRedemptionGoesLive.mp4".to_string(),
            ];
            for expected_url in &expected_urls {
                assert!(
                    urls.iter().any(|g| &g.url == expected_url),
                    "Missing expected URL: {expected_url}"
                );
            }

            let subdomain_url_no_path = "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.nftstorage.link";
            let urls_no_path =
                generate_url_for_gateways(subdomain_url_no_path, IPFS_GATEWAYS).unwrap();
            assert_eq!(urls_no_path.len(), IPFS_GATEWAYS.len());
            let expected_subdomain =
                "https://bafybeifx5hyzbmxuyelfka34jvpw4s5dkwuacvch6q2ngqtkzoo6ddmbya.ipfs.4everland.io";
            assert!(urls_no_path.iter().any(|g| g.url == expected_subdomain));
        }
    }

    mod is_valid_cid_tests {
        use super::*;

        #[test]
        fn accepts_common_qm_and_bafy_prefixes() {
            assert!(is_valid_cid(
                "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco"
            ));
            assert!(is_valid_cid(
                "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"
            ));
            assert!(is_valid_cid(
                "bafybeifx7yeb55armcsxwwitkymga5xf53dxiarykms3ygqic223w5sk3m"
            ));
        }

        #[test]
        fn rejects_obviously_invalid_values() {
            assert!(!is_valid_cid(""));
            assert!(!is_valid_cid("1"));
            assert!(!is_valid_cid("http"));
            assert!(!is_valid_cid("ipfs"));
            assert!(!is_valid_cid("bAfySomething")); // mixed case should fail
            assert!(!is_valid_cid("zbafy123"));
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
            if let Some(gateway_urls) = generate_url_for_gateways(ipfs_url, IPFS_GATEWAYS) {
                assert!(!gateway_urls.is_empty());
                let gateway_strings: Vec<&str> =
                    gateway_urls.iter().map(|g| g.url.as_str()).collect();
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
