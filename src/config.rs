use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

use crate::ipfs::IpfsPinningConfig;
use crate::server::auth::x402::X402ConfigRaw;
use crate::server::auth::JwtCredential;
use crate::ChainConfig;

/// Unified configuration structure that combines chains, auth, and IPFS providers
#[derive(Debug, Deserialize)]
pub struct Config {
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

impl Config {
    /// Load configuration from a TOML file
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file '{}'", path.display()))?;

        let mut config: Config = toml::from_str(&contents)
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
    pub fn chain_config(&self) -> ChainConfig {
        ChainConfig(self.chains.clone())
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

[x402.facilitator]
url = "https://x402.org/facilitator"
network = "base-sepolia"

[[ipfs_pinning_provider]]
type = "pinning-service"
base_url = "https://api.filebase.io/v1/ipfs"
bearer_token_env = "FILEBASE_TOKEN"
"#;
        let temp_file = create_temp_config(config_content);

        let result = Config::load_from_file(temp_file.path());
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

        let result = Config::load_from_file(temp_file.path());
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

        let result = Config::load_from_file(temp_file.path());
        assert!(result.is_ok());

        let config = result.unwrap();
        assert!(config.jwt[0].verification_key.contains('\n'));
        assert!(!config.jwt[0].verification_key.contains("\\n"));
    }

    #[test]
    fn handles_empty_config() {
        let config_content = "";
        let temp_file = create_temp_config(config_content);

        let result = Config::load_from_file(temp_file.path());
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

        let result = Config::load_from_file(nonexistent_path);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.to_string().contains("Failed to read config file"));
    }

    #[test]
    fn returns_error_for_invalid_toml() {
        let config_content = "invalid toml content {";
        let temp_file = create_temp_config(config_content);

        let result = Config::load_from_file(temp_file.path());
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.to_string().contains("Failed to parse config file"));
    }
}
