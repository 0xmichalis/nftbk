use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use tracing::{error, info};

use crate::ipfs::IpfsPinningConfig;
use crate::server::auth::JwtCredential;
use crate::server::x402::{X402Config, X402ConfigRaw};
use crate::ChainConfig;

/// Raw configuration structure that combines chains, auth, and IPFS providers
#[derive(Debug, Deserialize)]
pub struct ConfigRaw {
    /// Chain configurations (RPC endpoints)
    #[serde(default)]
    pub chains: HashMap<String, String>,

    /// JWT authentication credentials
    #[serde(default)]
    pub jwt: Vec<JwtCredential>,

    /// x402 payment configuration
    #[serde(default)]
    pub x402: Option<X402ConfigRaw>,

    /// IPFS pinning providers
    #[serde(default)]
    pub ipfs_pinning_provider: Vec<IpfsPinningConfig>,
}

impl ConfigRaw {
    /// Load configuration from a TOML file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file '{}'", path.display()))?;

        let mut config: ConfigRaw = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file '{}'", path.display()))?;

        // Normalize JWT verification keys (replace \n with actual newlines)
        for jwt_cred in &mut config.jwt {
            jwt_cred.verification_key = jwt_cred.verification_key.replace("\\n", "\n");
        }

        Ok(config)
    }

    /// Convert to separate config structures for backward compatibility
    pub fn into_separate_configs(
        self,
    ) -> (
        ChainConfig,
        Vec<JwtCredential>,
        Option<X402ConfigRaw>,
        Vec<IpfsPinningConfig>,
    ) {
        let chain_config = ChainConfig(self.chains);
        (
            chain_config,
            self.jwt,
            self.x402,
            self.ipfs_pinning_provider,
        )
    }

    /// Get chain configuration
    pub fn chain_config(&self) -> anyhow::Result<ChainConfig> {
        let mut chain_config = ChainConfig(self.chains.clone());
        chain_config.resolve_env_vars()?;
        Ok(chain_config)
    }

    /// Get JWT credentials
    pub fn jwt_credentials(&self) -> &[JwtCredential] {
        &self.jwt
    }

    /// Get x402 configuration
    pub fn x402_config(&self) -> Option<&X402ConfigRaw> {
        self.x402.as_ref()
    }

    /// Get IPFS pinning providers
    pub fn ipfs_pinning_providers(&self) -> &[IpfsPinningConfig] {
        &self.ipfs_pinning_provider
    }
}

/// Container for all loaded and validated configuration
#[derive(Debug)]
pub struct Config {
    pub chain_config: ChainConfig,
    pub jwt_credentials: Vec<JwtCredential>,
    pub x402_config: Option<X402Config>,
    pub ipfs_pinning_configs: Vec<IpfsPinningConfig>,
}

/// Load and validate configuration from file with logging
pub fn load_and_validate_config(config_path: &str) -> Result<Config> {
    let config = match ConfigRaw::load_from_file(std::path::Path::new(config_path)) {
        Ok(config) => {
            info!("Loaded unified configuration from '{}'", config_path);
            config
        }
        Err(e) => {
            error!("Failed to load config from '{}': {}", config_path, e);
            return Err(e);
        }
    };

    let jwt_credentials = config.jwt_credentials().to_vec();
    if jwt_credentials.is_empty() {
        info!("No JWT credentials configured");
    } else {
        info!("Loaded {} JWT credential(s):", jwt_credentials.len());
        for cred in &jwt_credentials {
            info!("  - issuer: {}, audience: {}", cred.issuer, cred.audience);
        }
    }

    let x402_config = if let Some(raw_config) = config.x402_config() {
        match X402Config::compile(raw_config.clone()) {
            Ok(compiled_config) => {
                info!(
                    "Loaded x402 config (network: {}, facilitator: {})",
                    compiled_config.facilitator.network, compiled_config.facilitator.url
                );
                Some(compiled_config)
            }
            Err(e) => {
                error!("Failed to compile x402 config: {}", e);
                return Err(e);
            }
        }
    } else {
        None
    };

    let ipfs_pinning_configs = config.ipfs_pinning_providers().to_vec();
    if ipfs_pinning_configs.is_empty() {
        info!("No IPFS pinning providers configured");
    } else {
        info!(
            "Loaded {} IPFS pinning provider(s):",
            ipfs_pinning_configs.len()
        );
        for config in &ipfs_pinning_configs {
            info!(
                "  - type: {}, base_url: {}",
                config.provider_type(),
                config.base_url()
            );
        }
    }

    // Extract and resolve chain configuration
    let chain_config = config
        .chain_config()
        .with_context(|| "Failed to resolve environment variables in chain config")?;

    Ok(Config {
        chain_config,
        jwt_credentials,
        x402_config,
        ipfs_pinning_configs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_config(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", content).unwrap();
        file
    }

    #[test]
    fn loads_complete_config() {
        let config_content = r#"
[chains]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
polygon = "https://polygon-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"

[[jwt]]
issuer = "test-issuer"
audience = "test-audience"
verification_key = "-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----"

[x402]
asset_symbol = "USDC"
base_url = "http://localhost:8080/"
recipient_address = "0x1234567890123456789012345678901234567890"
max_timeout_seconds = 300
price = "0.1"

[x402.facilitator]
url = "https://x402.org/facilitator"
network = "base-sepolia"

[[ipfs_pinning_provider]]
type = "pinning-service"
base_url = "https://api.filebase.io/v1/ipfs"
bearer_token_env = "FILEBASE_TOKEN"
"#;
        let temp_file = create_temp_config(config_content);

        let result = ConfigRaw::load_from_file(temp_file.path());
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.chains.len(), 2);
        assert_eq!(config.jwt.len(), 1);
        assert!(config.x402.is_some());
        assert_eq!(config.ipfs_pinning_provider.len(), 1);
    }

    #[test]
    fn loads_minimal_config() {
        let config_content = r#"
[chains]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
"#;
        let temp_file = create_temp_config(config_content);

        let result = ConfigRaw::load_from_file(temp_file.path());
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.chains.len(), 1);
        assert_eq!(config.jwt.len(), 0);
        assert!(config.x402.is_none());
        assert_eq!(config.ipfs_pinning_provider.len(), 0);
    }

    #[test]
    fn normalizes_jwt_verification_keys() {
        let config_content = r#"
[[jwt]]
issuer = "test-issuer"
audience = "test-audience"
verification_key = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\\n-----END PUBLIC KEY-----"
"#;
        let temp_file = create_temp_config(config_content);

        let result = ConfigRaw::load_from_file(temp_file.path());
        assert!(result.is_ok());

        let config = result.unwrap();
        assert!(config.jwt[0].verification_key.contains('\n'));
        assert!(!config.jwt[0].verification_key.contains("\\n"));
    }

    #[test]
    fn handles_empty_config() {
        let config_content = "";
        let temp_file = create_temp_config(config_content);

        let result = ConfigRaw::load_from_file(temp_file.path());
        assert!(result.is_ok());

        let config = result.unwrap();
        assert_eq!(config.chains.len(), 0);
        assert_eq!(config.jwt.len(), 0);
        assert!(config.x402.is_none());
        assert_eq!(config.ipfs_pinning_provider.len(), 0);
    }

    #[test]
    fn returns_error_for_nonexistent_file() {
        let nonexistent_path = std::path::Path::new("/nonexistent/path/config.toml");

        let result = ConfigRaw::load_from_file(nonexistent_path);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.to_string().contains("Failed to read config file"));
    }

    #[test]
    fn returns_error_for_invalid_toml() {
        let config_content = "invalid toml content {";
        let temp_file = create_temp_config(config_content);

        let result = ConfigRaw::load_from_file(temp_file.path());
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.to_string().contains("Failed to parse config file"));
    }

    mod load_and_validate_config_tests {
        use super::*;

        #[test]
        fn loads_and_validates_complete_config() {
            std::env::set_var("ALCHEMY_API_KEY", "test-key");
            std::env::set_var("FILEBASE_TOKEN", "test-token");

            let config_content = r#"
[chains]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"
polygon = "https://polygon-mainnet.g.alchemy.com/v2/${ALCHEMY_API_KEY}"

[[jwt]]
issuer = "test-issuer"
audience = "test-audience"
verification_key = "-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----"

[x402]
asset_symbol = "USDC"
base_url = "http://localhost:8080/"
recipient_address = "0x1234567890123456789012345678901234567890"
max_timeout_seconds = 300
price = "0.1"

[x402.facilitator]
url = "https://x402.org/facilitator"
network = "base-sepolia"

[[ipfs_pinning_provider]]
type = "pinning-service"
base_url = "https://api.filebase.io/v1/ipfs"
bearer_token_env = "FILEBASE_TOKEN"
"#;
            let temp_file = create_temp_config(config_content);

            let result = load_and_validate_config(&temp_file.path().to_string_lossy());
            assert!(result.is_ok());

            let config = result.unwrap();
            assert_eq!(config.chain_config.0.len(), 2);
            assert_eq!(config.jwt_credentials.len(), 1);
            assert!(config.x402_config.is_some());
            assert_eq!(config.ipfs_pinning_configs.len(), 1);

            // Verify environment variables were resolved
            assert!(config
                .chain_config
                .0
                .get("ethereum")
                .unwrap()
                .contains("test-key"));
            assert!(config
                .chain_config
                .0
                .get("polygon")
                .unwrap()
                .contains("test-key"));

            std::env::remove_var("ALCHEMY_API_KEY");
            std::env::remove_var("FILEBASE_TOKEN");
        }

        #[test]
        fn loads_and_validates_minimal_config() {
            let config_content = r#"
[chains]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/test-key"
"#;
            let temp_file = create_temp_config(config_content);

            let result = load_and_validate_config(&temp_file.path().to_string_lossy());
            assert!(result.is_ok());

            let config = result.unwrap();
            assert_eq!(config.chain_config.0.len(), 1);
            assert_eq!(config.jwt_credentials.len(), 0);
            assert!(config.x402_config.is_none());
            assert_eq!(config.ipfs_pinning_configs.len(), 0);
        }

        #[test]
        fn loads_and_validates_config_with_jwt_only() {
            let config_content = r#"
[chains]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/test-key"

[[jwt]]
issuer = "test-issuer"
audience = "test-audience"
verification_key = "-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----"

[[jwt]]
issuer = "test-issuer-2"
audience = "test-audience-2"
verification_key = "-----BEGIN PUBLIC KEY-----\ntest-key-2\n-----END PUBLIC KEY-----"
"#;
            let temp_file = create_temp_config(config_content);

            let result = load_and_validate_config(&temp_file.path().to_string_lossy());
            assert!(result.is_ok());

            let config = result.unwrap();
            assert_eq!(config.jwt_credentials.len(), 2);
            assert_eq!(config.jwt_credentials[0].issuer, "test-issuer");
            assert_eq!(config.jwt_credentials[1].issuer, "test-issuer-2");
        }

        #[test]
        fn loads_and_validates_config_with_x402_only() {
            let config_content = r#"
[chains]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/test-key"

[x402]
asset_symbol = "USDC"
base_url = "http://localhost:8080/"
recipient_address = "0x1234567890123456789012345678901234567890"
max_timeout_seconds = 300
price = "0.1"

[x402.facilitator]
url = "https://x402.org/facilitator"
network = "base-sepolia"
"#;
            let temp_file = create_temp_config(config_content);

            let result = load_and_validate_config(&temp_file.path().to_string_lossy());
            assert!(result.is_ok());

            let config = result.unwrap();
            assert!(config.x402_config.is_some());
            let x402_config = config.x402_config.unwrap();
            use x402_rs::network::Network;
            assert_eq!(x402_config.facilitator.network, Network::BaseSepolia);
            assert_eq!(x402_config.facilitator.url, "https://x402.org/facilitator");
        }

        #[test]
        fn loads_and_validates_config_with_ipfs_only() {
            let config_content = r#"
[chains]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/test-key"

[[ipfs_pinning_provider]]
type = "pinata"
base_url = "https://api.pinata.cloud"
bearer_token_env = "PINATA_TOKEN"

[[ipfs_pinning_provider]]
type = "pinning-service"
base_url = "https://api.filebase.io/v1/ipfs"
bearer_token_env = "FILEBASE_TOKEN"
"#;
            let temp_file = create_temp_config(config_content);

            let result = load_and_validate_config(&temp_file.path().to_string_lossy());
            assert!(result.is_ok());

            let config = result.unwrap();
            assert_eq!(config.ipfs_pinning_configs.len(), 2);
        }

        #[test]
        fn returns_error_for_nonexistent_file() {
            let result = load_and_validate_config("/nonexistent/path/config.toml");
            assert!(result.is_err());

            let error = result.unwrap_err();
            assert!(error.to_string().contains("Failed to read config file"));
        }

        #[test]
        fn returns_error_for_invalid_toml() {
            let config_content = "invalid toml content {";
            let temp_file = create_temp_config(config_content);

            let result = load_and_validate_config(&temp_file.path().to_string_lossy());
            assert!(result.is_err());

            let error = result.unwrap_err();
            assert!(error.to_string().contains("Failed to parse config file"));
        }

        #[test]
        fn returns_error_for_invalid_x402_config() {
            let config_content = r#"
[chains]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/test-key"

[x402]
asset_symbol = "USDC"
base_url = "http://localhost:8080/"
recipient_address = "invalid-address"
max_timeout_seconds = 300
price = "0.1"

[x402.facilitator]
url = "https://x402.org/facilitator"
network = "base-sepolia"
"#;
            let temp_file = create_temp_config(config_content);

            let result = load_and_validate_config(&temp_file.path().to_string_lossy());
            assert!(result.is_err());

            let error = result.unwrap_err();
            // The error message should contain information about the invalid address
            assert!(error.to_string().contains("invalid"));
        }

        #[test]
        fn returns_error_for_missing_env_vars_in_chain_config() {
            let config_content = r#"
[chains]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/${MISSING_VAR}"
"#;
            let temp_file = create_temp_config(config_content);

            let result = load_and_validate_config(&temp_file.path().to_string_lossy());
            assert!(result.is_err());

            let error = result.unwrap_err();
            assert!(error
                .to_string()
                .contains("Failed to resolve environment variables in chain config"));
        }

        #[test]
        fn handles_empty_config() {
            let config_content = "";
            let temp_file = create_temp_config(config_content);

            let result = load_and_validate_config(&temp_file.path().to_string_lossy());
            assert!(result.is_ok());

            let config = result.unwrap();
            assert_eq!(config.chain_config.0.len(), 0);
            assert_eq!(config.jwt_credentials.len(), 0);
            assert!(config.x402_config.is_none());
            assert_eq!(config.ipfs_pinning_configs.len(), 0);
        }

        #[test]
        fn normalizes_jwt_verification_keys() {
            let config_content = r#"
[chains]
ethereum = "https://eth-mainnet.g.alchemy.com/v2/test-key"

[[jwt]]
issuer = "test-issuer"
audience = "test-audience"
verification_key = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\\n-----END PUBLIC KEY-----"
"#;
            let temp_file = create_temp_config(config_content);

            let result = load_and_validate_config(&temp_file.path().to_string_lossy());
            assert!(result.is_ok());

            let config = result.unwrap();
            assert!(config.jwt_credentials[0].verification_key.contains('\n'));
            assert!(!config.jwt_credentials[0].verification_key.contains("\\n"));
        }
    }
}
