use std::str::FromStr;

use alloy::primitives::Address as EvmAddress;
use serde::{Deserialize, Serialize};
use tracing::info;
use url::Url;
use x402_axum::{price::PriceTag, IntoPriceTag, X402Middleware};
use x402_rs::network::{Network, USDCDeployment};
use x402_rs::types::MixedAddress;

use crate::server::auth::x402::coinbase_facilitator::CoinbaseFacilitator;
use crate::server::auth::x402::either_facilitator::EitherFacilitator;

mod coinbase_facilitator;
mod either_facilitator;
mod error_handling;
mod shared_facilitator;
mod settlement_hook;
mod settlement_handler;
mod settlement_middleware;

pub use settlement_hook::X402MiddlewareWithSettlementHook;
pub use settlement_handler::handle_backup_create_with_settlement_hook;
pub use settlement_middleware::SettlementFailureMiddleware;

/// Raw configuration structure for x402 as it appears in the TOML file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402ConfigRaw {
    pub asset_symbol: String,
    pub base_url: String,
    pub recipient_address: String,
    pub max_timeout_seconds: u64,
    pub facilitator: X402FacilitatorConfigRaw,
}

/// Raw facilitator configuration (from TOML)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402FacilitatorConfigRaw {
    pub url: String,
    pub network: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_id_env: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_secret_env: Option<String>,
}

/// Compiled facilitator configuration (parsed)
#[derive(Debug, Clone)]
pub struct X402FacilitatorConfig {
    pub url: String,
    pub network: Network,
    pub api_key_id_env: Option<String>,
    pub api_key_secret_env: Option<String>,
}

/// Compiled x402 configuration
#[derive(Debug, Clone)]
pub struct X402Config {
    pub asset_symbol: String,
    pub base_url: String,
    pub recipient: MixedAddress,
    pub max_timeout_seconds: u64,
    pub facilitator: X402FacilitatorConfig,
}

impl X402Config {
    /// Compile raw configuration into a validated config
    pub fn compile(raw: X402ConfigRaw) -> anyhow::Result<Self> {
        // Only USDC supported for now
        if raw.asset_symbol.to_uppercase() != "USDC" {
            return Err(anyhow::anyhow!("only USDC is supported for now"));
        }
        let normalized_base_url = normalize_base_url(&raw.base_url)?;
        if raw.recipient_address.is_empty() {
            return Err(anyhow::anyhow!("recipient_address cannot be empty"));
        }
        let recipient_evm = EvmAddress::from_str(&raw.recipient_address)
            .map_err(|_| anyhow::anyhow!("invalid EVM recipient address"))?;
        let recipient = MixedAddress::from(recipient_evm);
        if raw.facilitator.url.is_empty() {
            return Err(anyhow::anyhow!("facilitator.url cannot be empty"));
        }
        if raw.facilitator.network.is_empty() {
            return Err(anyhow::anyhow!("facilitator.network cannot be empty"));
        }
        // Only Base and Base Sepolia supported for now
        let network = parse_network(&raw.facilitator.network)?;
        match network {
            Network::Base | Network::BaseSepolia => {}
            _ => {
                return Err(anyhow::anyhow!(
                    "only Base and Base Sepolia are supported for now"
                ))
            }
        }

        Ok(X402Config {
            asset_symbol: raw.asset_symbol,
            base_url: normalized_base_url,
            recipient,
            max_timeout_seconds: raw.max_timeout_seconds,
            facilitator: X402FacilitatorConfig {
                url: raw.facilitator.url,
                network,
                api_key_id_env: raw.facilitator.api_key_id_env,
                api_key_secret_env: raw.facilitator.api_key_secret_env,
            },
        })
    }

    /// Build a preconfigured X402 middleware using this configuration.
    /// Sets base_url, description, mime type and max timeout.
    pub fn to_middleware(&self) -> anyhow::Result<X402Middleware<EitherFacilitator>> {
        let base_url = Url::parse(self.base_url.as_str())?;

        // Choose facilitator: simple client if no API creds, dynamic otherwise
        let facilitator = if self.facilitator.api_key_id_env.is_none()
            || self.facilitator.api_key_secret_env.is_none()
        {
            let client = x402_axum::facilitator_client::FacilitatorClient::try_from(
                self.facilitator.url.as_str(),
            )?;
            EitherFacilitator::from(client)
        } else {
            info!("x402 Coinbase facilitator authentication enabled");
            let client = CoinbaseFacilitator::new_with_url(
                self.facilitator.url.as_str(),
                self.facilitator.api_key_id_env.as_deref(),
                self.facilitator.api_key_secret_env.as_deref(),
            );
            EitherFacilitator::from(client)
        };

        let middleware = X402Middleware::new(facilitator)
            .with_base_url(base_url)
            .with_mime_type("application/json")
            .with_max_timeout_seconds(self.max_timeout_seconds);
        Ok(middleware)
    }

    /// Prepare a USDC price tag builder with the configured network and recipient.
    /// Call `.amount("...")?` on the returned builder and pass to `with_price_tag`.
    fn usdc_price_tag_builder(
        &self,
    ) -> anyhow::Result<x402_axum::price::PriceTagBuilder<(), MixedAddress>> {
        // Validate symbol
        if self.asset_symbol.to_uppercase() != "USDC" {
            return Err(anyhow::anyhow!("only USDC is supported for now"));
        }
        let network = self.facilitator.network;
        match network {
            Network::Base | Network::BaseSepolia => {}
            _ => {
                return Err(anyhow::anyhow!(
                    "only Base and Base Sepolia are supported for now"
                ))
            }
        }
        let builder = USDCDeployment::by_network(network).pay_to(self.recipient.clone());
        Ok(builder)
    }

    /// Build a ready PriceTag for a given human-readable amount (e.g. "0.1").
    pub fn usdc_price_tag_for_amount(&self, amount: &str) -> anyhow::Result<PriceTag> {
        let builder = self.usdc_price_tag_builder()?;
        let builder = builder.amount(amount);
        let price_tag = builder.build().map_err(|e| anyhow::anyhow!(e))?;
        Ok(price_tag)
    }
}

fn normalize_base_url(input: &str) -> anyhow::Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow::anyhow!("base_url cannot be empty"));
    }

    let url = Url::parse(trimmed).map_err(|e| anyhow::anyhow!("invalid base_url: {}", e))?;

    // Enforce http(s) only
    let scheme = url.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(anyhow::anyhow!("base_url must use http or https scheme"));
    }

    // Disallow query and fragment to avoid ambiguity in request construction
    if url.query().is_some() {
        return Err(anyhow::anyhow!("base_url must not contain a query string"));
    }
    if url.fragment().is_some() {
        return Err(anyhow::anyhow!("base_url must not contain a fragment"));
    }

    // Ensure trailing slash
    let mut normalized = url.to_string();
    if !normalized.ends_with('/') {
        normalized.push('/');
    }
    Ok(normalized)
}

fn parse_network(input: &str) -> anyhow::Result<Network> {
    match input {
        "base-sepolia" => Ok(Network::BaseSepolia),
        "base" => Ok(Network::Base),
        other => Err(anyhow::anyhow!("unsupported network: {}", other)),
    }
}

#[cfg(test)]
mod parse_network_tests {
    use super::*;

    #[test]
    fn test_parse_network_valid_cases() {
        // Test base-sepolia network
        let result = parse_network("base-sepolia");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Network::BaseSepolia);

        // Test base network
        let result = parse_network("base");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Network::Base);
    }

    #[test]
    fn test_parse_network_invalid_cases() {
        // Test unsupported network
        let result = parse_network("ethereum");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: ethereum"));

        // Test another unsupported network
        let result = parse_network("polygon");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: polygon"));

        // Test empty string
        let result = parse_network("");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: "));

        // Test partial match
        let result = parse_network("base-");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: base-"));

        // Test with extra characters
        let result = parse_network("base-extra");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: base-extra"));

        // Test with numbers
        let result = parse_network("base1");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: base1"));

        // Test with special characters
        let result = parse_network("base@sepolia");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: base@sepolia"));
    }

    #[test]
    fn test_parse_network_case_sensitivity() {
        // Test uppercase variants (should fail)
        let result = parse_network("BASE");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: BASE"));

        let result = parse_network("BASE-SEPOLIA");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: BASE-SEPOLIA"));

        // Test mixed case variants (should fail)
        let result = parse_network("Base");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: Base"));

        let result = parse_network("Base-Sepolia");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: Base-Sepolia"));
    }

    #[test]
    fn test_parse_network_whitespace_handling() {
        // Test with leading whitespace
        let result = parse_network(" base");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network:  base"));

        // Test with trailing whitespace
        let result = parse_network("base ");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: base "));

        // Test with both leading and trailing whitespace
        let result = parse_network(" base ");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network:  base "));

        // Test with whitespace in the middle
        let result = parse_network("base sepolia");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: base sepolia"));

        // Test with tabs
        let result = parse_network("\tbase");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: \tbase"));
    }

    #[test]
    fn test_parse_network_edge_cases() {
        // Test very long string
        let long_string = "a".repeat(1000);
        let result = parse_network(&long_string);
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains(&format!("unsupported network: {}", long_string)));

        // Test with unicode characters
        let result = parse_network("båse");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: båse"));

        // Test with emoji
        let result = parse_network("base🚀");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: base🚀"));

        // Test with newlines
        let result = parse_network("base\n");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: base\n"));

        // Test with carriage returns
        let result = parse_network("base\r");
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("unsupported network: base\r"));
    }
}

#[cfg(test)]
mod normalize_base_url_tests {
    use super::*;

    #[test]
    fn test_normalize_base_url_success_cases() {
        // HTTP without trailing slash
        let result = normalize_base_url("http://example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "http://example.com/");

        // HTTPS without trailing slash
        let result = normalize_base_url("https://example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/");

        // HTTP with trailing slash
        let result = normalize_base_url("http://example.com/");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "http://example.com/");

        // HTTPS with trailing slash
        let result = normalize_base_url("https://example.com/");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/");

        // With path without trailing slash
        let result = normalize_base_url("https://example.com/api");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/api/");

        // With path with trailing slash
        let result = normalize_base_url("https://example.com/api/");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/api/");

        // With port
        let result = normalize_base_url("http://localhost:8080");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "http://localhost:8080/");

        // With port and path
        let result = normalize_base_url("https://api.example.com:8443/v1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://api.example.com:8443/v1/");

        // With subdomain
        let result = normalize_base_url("https://subdomain.example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://subdomain.example.com/");

        // With multiple path segments
        let result = normalize_base_url("https://example.com/api/v1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/api/v1/");
    }

    #[test]
    fn test_normalize_base_url_whitespace_handling() {
        // Leading whitespace
        let result = normalize_base_url("  https://example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/");

        // Trailing whitespace
        let result = normalize_base_url("https://example.com  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/");

        // Both leading and trailing whitespace
        let result = normalize_base_url("  https://example.com  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/");

        // Whitespace with path
        let result = normalize_base_url("  https://example.com/api  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/api/");

        // Only whitespace
        let result = normalize_base_url("   ");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("base_url cannot be empty"));
    }

    #[test]
    fn test_normalize_base_url_error_cases() {
        // Empty string
        let result = normalize_base_url("");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("base_url cannot be empty"));

        // Invalid URL (no scheme)
        let result = normalize_base_url("example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid base_url"));

        // Invalid URL (malformed)
        let result = normalize_base_url("http://");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid base_url"));

        // Wrong scheme - FTP
        let result = normalize_base_url("ftp://example.com");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("http or https scheme"));

        // Wrong scheme - file
        let result = normalize_base_url("file:///path/to/file");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("http or https scheme"));

        // Wrong scheme - ws
        let result = normalize_base_url("ws://example.com");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("http or https scheme"));

        // Wrong scheme - wss
        let result = normalize_base_url("wss://example.com");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("http or https scheme"));

        // With query string
        let result = normalize_base_url("https://example.com?param=value");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must not contain a query"));

        // With fragment
        let result = normalize_base_url("https://example.com#fragment");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must not contain a fragment"));

        // With both query and fragment
        let result = normalize_base_url("https://example.com?param=value#fragment");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("must not contain a query"));
    }

    #[test]
    fn test_normalize_base_url_edge_cases() {
        // URL with special characters in path
        let result = normalize_base_url("https://example.com/api-v1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/api-v1/");

        // URL with numbers in path
        let result = normalize_base_url("https://example.com/api2");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/api2/");

        // URL with underscores in hostname
        let result = normalize_base_url("https://api_example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://api_example.com/");

        // URL with hyphens in hostname
        let result = normalize_base_url("https://api-example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://api-example.com/");

        // URL with IP address
        let result = normalize_base_url("http://192.168.1.1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "http://192.168.1.1/");

        // URL with IP address and port
        let result = normalize_base_url("http://192.168.1.1:8080");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "http://192.168.1.1:8080/");

        // URL with IPv6 address
        let result = normalize_base_url("http://[::1]");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "http://[::1]/");

        // URL with IPv6 address and port
        let result = normalize_base_url("http://[::1]:8080");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "http://[::1]:8080/");
    }

    #[test]
    fn test_normalize_base_url_preserves_existing_trailing_slash() {
        // Already has trailing slash - should not add another
        let result = normalize_base_url("https://example.com/");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/");

        // Path with trailing slash - should not add another
        let result = normalize_base_url("https://example.com/api/");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/api/");

        // Multiple trailing slashes in path - should preserve and add one at end
        let result = normalize_base_url("https://example.com/api//");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "https://example.com/api//");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x402_config_compile_success() {
        let raw = X402ConfigRaw {
            base_url: "http://localhost:8080/".to_string(),
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            max_timeout_seconds: 300,
            facilitator: X402FacilitatorConfigRaw {
                url: "https://x402.org/facilitator".to_string(),
                network: "base-sepolia".to_string(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            asset_symbol: "USDC".into(),
        };

        let config = X402Config::compile(raw).expect("should compile successfully");
        assert_eq!(config.asset_symbol, "USDC");
        assert_eq!(config.base_url, "http://localhost:8080/");
        let expected_recipient = MixedAddress::from(
            EvmAddress::from_str("0x1234567890123456789012345678901234567890").unwrap(),
        );
        assert_eq!(config.recipient, expected_recipient);
        assert_eq!(config.max_timeout_seconds, 300);
        assert_eq!(config.facilitator.url, "https://x402.org/facilitator");
        assert_eq!(config.facilitator.network, Network::BaseSepolia);
    }

    #[test]
    fn test_x402_config_compile_empty_recipient() {
        let raw = X402ConfigRaw {
            base_url: "https://example.com".to_string(),
            recipient_address: "".to_string(),
            max_timeout_seconds: 300,
            facilitator: X402FacilitatorConfigRaw {
                url: "https://x402.org/facilitator".to_string(),
                network: "base-sepolia".to_string(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            asset_symbol: "USDC".into(),
        };

        let result = X402Config::compile(raw);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("recipient_address cannot be empty"));
    }

    #[test]
    fn test_x402_base_url_variants_and_errors() {
        // No trailing slash -> normalized
        let raw = X402ConfigRaw {
            base_url: "https://example.com".to_string(),
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            max_timeout_seconds: 60,
            facilitator: X402FacilitatorConfigRaw {
                url: "https://x402.org/facilitator".to_string(),
                network: "base-sepolia".to_string(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            asset_symbol: "USDC".into(),
        };
        let cfg = X402Config::compile(raw).unwrap();
        assert_eq!(cfg.base_url, "https://example.com/");

        // With path, ensure trailing slash preserved
        let raw = X402ConfigRaw {
            base_url: "https://example.com/api".to_string(),
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            max_timeout_seconds: 60,
            facilitator: X402FacilitatorConfigRaw {
                url: "https://x402.org/facilitator".to_string(),
                network: "base-sepolia".to_string(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            asset_symbol: "USDC".into(),
        };
        let cfg = X402Config::compile(raw).unwrap();
        assert_eq!(cfg.base_url, "https://example.com/api/");

        // Leading/trailing whitespace
        let raw = X402ConfigRaw {
            base_url: "  https://example.com  ".to_string(),
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            max_timeout_seconds: 60,
            facilitator: X402FacilitatorConfigRaw {
                url: "https://x402.org/facilitator".to_string(),
                network: "base-sepolia".to_string(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            asset_symbol: "USDC".into(),
        };
        let cfg = X402Config::compile(raw).unwrap();
        assert_eq!(cfg.base_url, "https://example.com/");

        // Errors
        let raw = X402ConfigRaw {
            base_url: "".to_string(),
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            max_timeout_seconds: 60,
            facilitator: X402FacilitatorConfigRaw {
                url: "https://x402.org/facilitator".to_string(),
                network: "base-sepolia".to_string(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            asset_symbol: "USDC".into(),
        };
        let err = X402Config::compile(raw).unwrap_err().to_string();
        assert!(err.contains("base_url cannot be empty"));

        let raw = X402ConfigRaw {
            base_url: "example.com".to_string(),
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            max_timeout_seconds: 60,
            facilitator: X402FacilitatorConfigRaw {
                url: "https://x402.org/facilitator".to_string(),
                network: "base-sepolia".to_string(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            asset_symbol: "USDC".into(),
        };
        let err = X402Config::compile(raw).unwrap_err().to_string();
        assert!(err.contains("invalid base_url"));

        let raw = X402ConfigRaw {
            base_url: "ftp://example.com".to_string(),
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            max_timeout_seconds: 60,
            facilitator: X402FacilitatorConfigRaw {
                url: "https://x402.org/facilitator".to_string(),
                network: "base-sepolia".to_string(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            asset_symbol: "USDC".into(),
        };
        let err = X402Config::compile(raw).unwrap_err().to_string();
        assert!(err.contains("http or https"));

        let raw = X402ConfigRaw {
            base_url: "https://example.com?x=1".to_string(),
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            max_timeout_seconds: 60,
            facilitator: X402FacilitatorConfigRaw {
                url: "https://x402.org/facilitator".to_string(),
                network: "base-sepolia".to_string(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            asset_symbol: "USDC".into(),
        };
        let err = X402Config::compile(raw).unwrap_err().to_string();
        assert!(err.contains("must not contain a query"));

        let raw = X402ConfigRaw {
            base_url: "https://example.com#frag".to_string(),
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            max_timeout_seconds: 60,
            facilitator: X402FacilitatorConfigRaw {
                url: "https://x402.org/facilitator".to_string(),
                network: "base-sepolia".to_string(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            asset_symbol: "USDC".into(),
        };
        let err = X402Config::compile(raw).unwrap_err().to_string();
        assert!(err.contains("must not contain a fragment"));
    }
}
