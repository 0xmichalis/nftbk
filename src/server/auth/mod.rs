pub mod jwt;
pub mod x402;

use std::path::Path;
use toml;
use tracing::info;

use crate::server::auth::x402::{X402Config, X402ConfigRaw};

#[derive(serde::Deserialize, Clone, Debug)]
pub struct JwtCredential {
    pub issuer: String,
    pub audience: String,
    pub verification_key: String,
}

#[derive(serde::Deserialize)]
struct AuthFile {
    #[serde(default)]
    jwt: Vec<JwtCredential>,
    #[serde(default)]
    x402: Option<X402ConfigRaw>,
}

#[derive(Debug)]
pub struct AuthConfig {
    pub jwt_credentials: Vec<JwtCredential>,
    pub x402_config: Option<X402Config>,
}

pub fn load_auth_config(config_path: &Path) -> Result<AuthConfig, String> {
    let contents = std::fs::read_to_string(config_path).map_err(|e| {
        format!(
            "Failed to read auth config file '{}': {}",
            config_path.display(),
            e
        )
    })?;

    let mut file: AuthFile = toml::from_str(&contents).map_err(|e| {
        format!(
            "Failed to parse auth config file '{}': {}",
            config_path.display(),
            e
        )
    })?;

    let mut jwt_credentials: Vec<JwtCredential> = Vec::new();
    for cred in file.jwt.drain(..) {
        let mut normalized = cred.clone();
        normalized.verification_key = normalized.verification_key.replace("\\n", "\n");
        jwt_credentials.push(normalized.clone());
        info!(
            "Loaded JWT credential set (issuer: {}, audience: {})",
            normalized.issuer, normalized.audience
        );
    }

    let x402_config = if let Some(raw) = file.x402.take() {
        match X402Config::compile(raw) {
            Ok(cfg) => {
                info!(
                    "Loaded x402 config (network: {}, facilitator: {})",
                    cfg.facilitator.network, cfg.facilitator.url
                );
                Some(cfg)
            }
            Err(e) => {
                return Err(format!(
                    "Failed to compile x402 config from '{}': {}",
                    config_path.display(),
                    e
                ));
            }
        }
    } else {
        None
    };

    Ok(AuthConfig {
        jwt_credentials,
        x402_config,
    })
}

#[cfg(test)]
mod load_auth_config_tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_config(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{}", content).unwrap();
        file
    }

    #[test]
    fn loads_jwt_credentials_successfully() {
        let config_content = r#"
[[jwt]]
issuer = "test-issuer"
audience = "test-audience"
verification_key = "test-key"
"#;
        let temp_file = create_temp_config(config_content);

        let result = load_auth_config(temp_file.path());
        assert!(result.is_ok());

        let auth_config = result.unwrap();
        assert_eq!(auth_config.jwt_credentials.len(), 1);
        assert_eq!(auth_config.jwt_credentials[0].issuer, "test-issuer");
        assert_eq!(auth_config.jwt_credentials[0].audience, "test-audience");
        assert_eq!(auth_config.jwt_credentials[0].verification_key, "test-key");
        assert!(auth_config.x402_config.is_none());
    }

    #[test]
    fn loads_multiple_jwt_credentials() {
        let config_content = r#"
[[jwt]]
issuer = "issuer1"
audience = "audience1"
verification_key = "key1"

[[jwt]]
issuer = "issuer2"
audience = "audience2"
verification_key = "key2"
"#;
        let temp_file = create_temp_config(config_content);

        let result = load_auth_config(temp_file.path());
        assert!(result.is_ok());

        let auth_config = result.unwrap();
        assert_eq!(auth_config.jwt_credentials.len(), 2);
        assert_eq!(auth_config.jwt_credentials[0].issuer, "issuer1");
        assert_eq!(auth_config.jwt_credentials[1].issuer, "issuer2");
    }

    #[test]
    fn normalizes_verification_key_newlines() {
        let config_content = r#"
[[jwt]]
issuer = "test-issuer"
audience = "test-audience"
verification_key = "-----BEGIN PUBLIC KEY-----\\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\\n-----END PUBLIC KEY-----"
"#;
        let temp_file = create_temp_config(config_content);

        let result = load_auth_config(temp_file.path());
        assert!(result.is_ok());

        let auth_config = result.unwrap();
        assert!(auth_config.jwt_credentials[0]
            .verification_key
            .contains('\n'));
        assert!(!auth_config.jwt_credentials[0]
            .verification_key
            .contains("\\n"));
    }

    #[test]
    fn loads_x402_config_successfully() {
        let config_content = r#"
[[jwt]]
issuer = "test-issuer"
audience = "test-audience"
verification_key = "test-key"

[x402]
asset_symbol = "USDC"
base_url = "http://localhost:8080/"
recipient_address = "0x1234567890123456789012345678901234567890"
max_timeout_seconds = 300

[x402.facilitator]
url = "https://x402.org/facilitator"
network = "base-sepolia"
"#;
        let temp_file = create_temp_config(config_content);

        let result = load_auth_config(temp_file.path());
        assert!(result.is_ok());

        let auth_config = result.unwrap();
        assert_eq!(auth_config.jwt_credentials.len(), 1);
        assert!(auth_config.x402_config.is_some());
    }

    #[test]
    fn handles_empty_jwt_section() {
        let config_content = r#"
jwt = []
"#;
        let temp_file = create_temp_config(config_content);

        let result = load_auth_config(temp_file.path());
        assert!(result.is_ok());

        let auth_config = result.unwrap();
        assert_eq!(auth_config.jwt_credentials.len(), 0);
        assert!(auth_config.x402_config.is_none());
    }

    #[test]
    fn handles_missing_jwt_section() {
        let config_content = r#"
[x402]
asset_symbol = "USDC"
base_url = "http://localhost:8080/"
recipient_address = "0x1234567890123456789012345678901234567890"
max_timeout_seconds = 300

[x402.facilitator]
url = "https://x402.org/facilitator"
network = "base-sepolia"
"#;
        let temp_file = create_temp_config(config_content);

        let result = load_auth_config(temp_file.path());
        assert!(result.is_ok());

        let auth_config = result.unwrap();
        assert_eq!(auth_config.jwt_credentials.len(), 0);
        assert!(auth_config.x402_config.is_some());
    }

    #[test]
    fn handles_empty_config_file() {
        let config_content = "";
        let temp_file = create_temp_config(config_content);

        let result = load_auth_config(temp_file.path());
        assert!(result.is_ok());

        let auth_config = result.unwrap();
        assert_eq!(auth_config.jwt_credentials.len(), 0);
        assert!(auth_config.x402_config.is_none());
    }

    #[test]
    fn returns_error_for_nonexistent_file() {
        let nonexistent_path = std::path::Path::new("/nonexistent/path/config.toml");

        let result = load_auth_config(nonexistent_path);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.contains("Failed to read auth config file"));
    }

    #[test]
    fn returns_error_for_invalid_toml() {
        let config_content = "invalid toml content {";
        let temp_file = create_temp_config(config_content);

        let result = load_auth_config(temp_file.path());
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.contains("Failed to parse auth config file"));
    }

    #[test]
    fn returns_error_for_invalid_x402_config() {
        let config_content = r#"
[[jwt]]
issuer = "test-issuer"
audience = "test-audience"
verification_key = "test-key"

[x402]
asset_symbol = "USDC"
base_url = "http://localhost:8080/"
recipient_address = "0x1234567890123456789012345678901234567890"
max_timeout_seconds = 300

[x402.facilitator]
url = "https://x402.org/facilitator"
network = "invalid-network"
"#;
        let temp_file = create_temp_config(config_content);

        let result = load_auth_config(temp_file.path());
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.contains("Failed to compile x402 config"));
    }

    #[test]
    fn handles_missing_required_jwt_fields() {
        let config_content = r#"
[[jwt]]
issuer = "test-issuer"
# Missing audience and verification_key
"#;
        let temp_file = create_temp_config(config_content);

        let result = load_auth_config(temp_file.path());
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert!(error.contains("Failed to parse auth config file"));
    }
}
