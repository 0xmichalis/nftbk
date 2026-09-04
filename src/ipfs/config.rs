use anyhow::{Context, Result};
use serde::Deserialize;

use super::provider::IpfsPinningProvider;
use super::{IpfsPinningClient, PinataClient};

#[derive(Debug, Clone, PartialEq)]
pub enum IpfsGatewayType {
    Path,
    Subdomain,
}

#[derive(Debug, Clone)]
pub struct IpfsGatewayConfig {
    pub url: &'static str,
    pub gateway_type: IpfsGatewayType,
    /// Name of environment variable containing the bearer token
    pub bearer_token_env: Option<&'static str>,
}

impl IpfsGatewayConfig {
    pub fn resolve_bearer_token(&self) -> Option<String> {
        let env_name = self.bearer_token_env?;
        std::env::var(env_name)
            .ok()
            .filter(|token| !token.trim().is_empty())
    }
}

// A list of public IPFS gateways can be found here:
// https://ipfs.github.io/public-gateway-checker/
pub const IPFS_GATEWAYS: &[IpfsGatewayConfig] = &[
    IpfsGatewayConfig {
        url: "https://ipfs.io",
        gateway_type: IpfsGatewayType::Path,
        bearer_token_env: None,
    },
    IpfsGatewayConfig {
        url: "https://4everland.io",
        gateway_type: IpfsGatewayType::Subdomain,
        bearer_token_env: None,
    },
    IpfsGatewayConfig {
        url: "https://gateway.pinata.cloud",
        gateway_type: IpfsGatewayType::Path,
        bearer_token_env: Some("PINATA_GATEWAY_TOKEN"),
    },
];

/// Order gateways so that those with a resolvable bearer token are tried first.
/// Authenticated gateways are far less likely to rate-limit or block requests
/// than public ones, so they make the best primary choice.
pub fn prioritize_authenticated(gateways: &[IpfsGatewayConfig]) -> Vec<IpfsGatewayConfig> {
    let (authenticated, public): (Vec<_>, Vec<_>) = gateways
        .iter()
        .cloned()
        .partition(|gw| gw.resolve_bearer_token().is_some());
    authenticated.into_iter().chain(public).collect()
}

/// Configuration for a single IPFS pinning provider
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum IpfsPinningConfig {
    #[serde(rename = "pinning-service")]
    IpfsPinningService {
        base_url: String,
        /// Name of environment variable containing the bearer token
        #[serde(default)]
        bearer_token_env: Option<String>,
    },
    Pinata {
        base_url: String,
        /// Name of environment variable containing the bearer token
        #[serde(default)]
        bearer_token_env: Option<String>,
    },
}

impl IpfsPinningConfig {
    /// Get the provider type as a string
    pub fn provider_type(&self) -> &'static str {
        match self {
            IpfsPinningConfig::IpfsPinningService { .. } => "pinning-service",
            IpfsPinningConfig::Pinata { .. } => "pinata",
        }
    }

    /// Get the base URL for this provider
    pub fn base_url(&self) -> &str {
        match self {
            IpfsPinningConfig::IpfsPinningService { base_url, .. } => base_url,
            IpfsPinningConfig::Pinata { base_url, .. } => base_url,
        }
    }

    /// Create a provider instance from this configuration
    /// Returns an error if a referenced environment variable is not set
    pub fn create_provider(&self) -> Result<Box<dyn IpfsPinningProvider>> {
        match self {
            IpfsPinningConfig::IpfsPinningService {
                base_url,
                bearer_token_env,
            } => {
                let token = Self::resolve_token(bearer_token_env)?;
                Ok(Box::new(IpfsPinningClient::new(base_url.clone(), token)))
            }
            IpfsPinningConfig::Pinata {
                base_url,
                bearer_token_env,
            } => {
                let token = Self::resolve_token(bearer_token_env)?
                    .context("Pinata requires a bearer token")?;
                Ok(Box::new(PinataClient::new(base_url.clone(), token)))
            }
        }
    }

    /// Resolve the token from environment variable (if specified) or use the direct value
    fn resolve_token(env_var_name: &Option<String>) -> Result<Option<String>> {
        if env_var_name.is_none() {
            Ok(None)
        } else {
            let env_name = env_var_name.as_ref().unwrap();
            let token = std::env::var(env_name).with_context(|| {
                format!("Environment variable '{env_name}' not set for IPFS provider token",)
            })?;
            Ok(Some(token))
        }
    }
}

#[cfg(test)]
mod prioritize_authenticated_tests {
    use super::*;

    const PATH: IpfsGatewayType = IpfsGatewayType::Path;

    fn gw(url: &'static str, bearer_token_env: Option<&'static str>) -> IpfsGatewayConfig {
        IpfsGatewayConfig {
            url,
            gateway_type: PATH,
            bearer_token_env,
        }
    }

    #[test]
    fn authenticated_gateways_come_first_preserving_relative_order() {
        std::env::set_var("NFTBK_TEST_GW_TOKEN_A", "tok");
        let gateways = [
            gw("https://a", None),
            gw("https://b", Some("NFTBK_TEST_GW_TOKEN_A")),
            gw("https://c", None),
        ];
        let ordered: Vec<&str> = prioritize_authenticated(&gateways)
            .iter()
            .map(|g| g.url)
            .collect();
        assert_eq!(ordered, vec!["https://b", "https://a", "https://c"]);
    }

    #[test]
    fn blank_token_is_treated_as_absent() {
        std::env::set_var("NFTBK_TEST_GW_TOKEN_BLANK", "  ");
        let gateway = gw("https://a", Some("NFTBK_TEST_GW_TOKEN_BLANK"));
        assert_eq!(gateway.resolve_bearer_token(), None);
    }

    #[test]
    fn unresolvable_token_env_does_not_promote_gateway() {
        let gateways = [
            gw("https://a", None),
            gw("https://b", Some("NFTBK_TEST_GW_TOKEN_UNSET")),
        ];
        let ordered: Vec<&str> = prioritize_authenticated(&gateways)
            .iter()
            .map(|g| g.url)
            .collect();
        assert_eq!(ordered, vec!["https://a", "https://b"]);
    }
}
