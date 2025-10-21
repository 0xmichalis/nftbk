use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs;

use crate::backup::{BackupConfig, ChainConfig, TokenConfig};
use crate::config::Config;
use crate::ipfs::IpfsPinningConfig;
use crate::{ProcessManagementConfig, StorageConfig};

#[derive(serde::Deserialize)]
pub struct IpfsConfigFile {
    pub ipfs_pinning_provider: Vec<IpfsPinningConfig>,
}

pub async fn load_token_config(path: &PathBuf) -> Result<TokenConfig> {
    let tokens_content = fs::read_to_string(path)
        .await
        .context("Failed to read tokens config file")?;
    let token_config: TokenConfig =
        toml::from_str(&tokens_content).context("Failed to parse tokens config file")?;
    Ok(token_config)
}

pub async fn load_chain_config(path: &PathBuf) -> Result<ChainConfig> {
    let chains_content = fs::read_to_string(path)
        .await
        .context("Failed to read chains config file")?;
    let mut chain_config: ChainConfig =
        toml::from_str(&chains_content).context("Failed to parse chains config file")?;
    chain_config.resolve_env_vars()?;
    Ok(chain_config)
}

pub fn load_ipfs_config(path: Option<&String>) -> Result<Vec<IpfsPinningConfig>> {
    if path.is_none() {
        return Ok(Vec::new());
    }

    let path = path.unwrap();
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read IPFS config file '{path}'"))?;
    let config: IpfsConfigFile = toml::from_str(&contents)
        .with_context(|| format!("Failed to parse IPFS config file '{path}'"))?;
    Ok(config.ipfs_pinning_provider)
}

pub fn load_config(path: &Path) -> Result<Config> {
    Config::load_from_file(path).context("Failed to load config")
}

pub fn create_backup_config(
    chain_config: ChainConfig,
    token_config: TokenConfig,
    output_path: Option<PathBuf>,
    prune_redundant: bool,
    exit_on_error: bool,
    ipfs_pinning_configs: Vec<IpfsPinningConfig>,
) -> BackupConfig {
    BackupConfig {
        chain_config,
        token_config,
        storage_config: StorageConfig {
            output_path: output_path.clone(),
            prune_redundant,
            ipfs_pinning_configs,
        },
        process_config: ProcessManagementConfig {
            exit_on_error,
            shutdown_flag: None,
        },
        task_id: None, // CLI doesn't have a task ID
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use tempfile::NamedTempFile;

    mod load_token_config_tests {
        use super::*;

        #[tokio::test]
        async fn loads_valid_token_config() {
            let temp_file = NamedTempFile::new().unwrap();
            let config_content = r#"
ethereum = ["0x123:1", "0x456:2"]
tezos = ["KT1ABC:1"]
"#;
            std::fs::write(temp_file.path(), config_content).unwrap();

            let result = load_token_config(&temp_file.path().to_path_buf()).await;
            assert!(result.is_ok());

            let config = result.unwrap();
            assert_eq!(config.chains.len(), 2);
            assert_eq!(config.chains.get("ethereum").unwrap().len(), 2);
            assert_eq!(config.chains.get("tezos").unwrap().len(), 1);
        }

        #[tokio::test]
        async fn returns_error_for_missing_file() {
            let non_existent_path = PathBuf::from("/non/existent/path.toml");
            let result = load_token_config(&non_existent_path).await;
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to read tokens config file"));
        }

        #[tokio::test]
        async fn returns_error_for_invalid_toml() {
            let temp_file = NamedTempFile::new().unwrap();
            let invalid_content = "invalid toml content [";
            std::fs::write(temp_file.path(), invalid_content).unwrap();

            let result = load_token_config(&temp_file.path().to_path_buf()).await;
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse tokens config file"));
        }

        #[tokio::test]
        async fn handles_empty_config() {
            let temp_file = NamedTempFile::new().unwrap();
            let empty_content = "";
            std::fs::write(temp_file.path(), empty_content).unwrap();

            let result = load_token_config(&temp_file.path().to_path_buf()).await;
            assert!(result.is_ok());

            let config = result.unwrap();
            assert_eq!(config.chains.len(), 0);
        }
    }

    mod load_chain_config_tests {
        use super::*;

        #[tokio::test]
        async fn loads_valid_chain_config() {
            let temp_file = NamedTempFile::new().unwrap();
            let config_content = r#"
ethereum = "https://ethereum.publicnode.com"
tezos = "https://tezos.publicnode.com"
"#;
            std::fs::write(temp_file.path(), config_content).unwrap();

            let result = load_chain_config(&temp_file.path().to_path_buf()).await;
            assert!(result.is_ok());

            let config = result.unwrap();
            assert_eq!(config.0.len(), 2);
            assert_eq!(
                config.0.get("ethereum").unwrap(),
                "https://ethereum.publicnode.com"
            );
            assert_eq!(
                config.0.get("tezos").unwrap(),
                "https://tezos.publicnode.com"
            );
        }

        #[tokio::test]
        async fn resolves_environment_variables() {
            std::env::set_var("TEST_RPC_URL", "https://test.example.com");

            let temp_file = NamedTempFile::new().unwrap();
            let config_content = r#"
ethereum = "${TEST_RPC_URL}"
"#;
            std::fs::write(temp_file.path(), config_content).unwrap();

            let result = load_chain_config(&temp_file.path().to_path_buf()).await;
            assert!(result.is_ok());

            let config = result.unwrap();
            assert_eq!(
                config.0.get("ethereum").unwrap(),
                "https://test.example.com"
            );

            std::env::remove_var("TEST_RPC_URL");
        }

        #[tokio::test]
        async fn returns_error_for_missing_env_var() {
            let temp_file = NamedTempFile::new().unwrap();
            let config_content = r#"
ethereum = "${MISSING_VAR}"
"#;
            std::fs::write(temp_file.path(), config_content).unwrap();

            let result = load_chain_config(&temp_file.path().to_path_buf()).await;
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed resolving env vars"));
        }

        #[tokio::test]
        async fn returns_error_for_missing_file() {
            let non_existent_path = PathBuf::from("/non/existent/path.toml");
            let result = load_chain_config(&non_existent_path).await;
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to read chains config file"));
        }
    }

    mod load_ipfs_config_tests {
        use super::*;

        #[test]
        fn returns_empty_vec_when_no_path() {
            let result = load_ipfs_config(None);
            assert!(result.is_ok());
            assert_eq!(result.unwrap().len(), 0);
        }

        #[test]
        fn loads_valid_ipfs_config() {
            let temp_file = NamedTempFile::new().unwrap();
            let config_content = r#"
[[ipfs_pinning_provider]]
type = "pinata"
base_url = "https://api.pinata.cloud"
bearer_token_env = "PINATA_TOKEN"
"#;
            std::fs::write(temp_file.path(), config_content).unwrap();

            let path = temp_file.path().to_string_lossy().to_string();
            let result = load_ipfs_config(Some(&path));
            assert!(result.is_ok());

            let configs = result.unwrap();
            assert_eq!(configs.len(), 1);
        }

        #[test]
        fn returns_error_for_missing_file() {
            let non_existent_path = "/non/existent/path.toml".to_string();
            let result = load_ipfs_config(Some(&non_existent_path));
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to read IPFS config file"));
        }

        #[test]
        fn returns_error_for_invalid_toml() {
            let temp_file = NamedTempFile::new().unwrap();
            let invalid_content = "invalid toml content [";
            std::fs::write(temp_file.path(), invalid_content).unwrap();

            let path = temp_file.path().to_string_lossy().to_string();
            let result = load_ipfs_config(Some(&path));
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse IPFS config file"));
        }
    }

    mod create_backup_config_tests {
        use super::*;

        #[test]
        fn creates_backup_config_with_all_options() {
            let mut chain_map = HashMap::new();
            chain_map.insert(
                "ethereum".to_string(),
                "https://ethereum.publicnode.com".to_string(),
            );
            let chain_config = ChainConfig(chain_map);

            let mut token_map = HashMap::new();
            token_map.insert("ethereum".to_string(), vec!["0x123:1".to_string()]);
            let token_config = TokenConfig { chains: token_map };

            let output_path = Some(PathBuf::from("/tmp/backup"));
            let ipfs_configs = vec![IpfsPinningConfig::IpfsPinningService {
                base_url: "https://pinata.cloud".to_string(),
                bearer_token_env: None,
            }];

            let config = create_backup_config(
                chain_config.clone(),
                token_config.clone(),
                output_path.clone(),
                true,
                false,
                ipfs_configs.clone(),
            );

            assert_eq!(config.chain_config.0, chain_config.0);
            assert_eq!(config.token_config.chains, token_config.chains);
            assert_eq!(config.storage_config.output_path, output_path);
            assert!(config.storage_config.prune_redundant);
            assert!(!config.process_config.exit_on_error);
            assert_eq!(config.storage_config.ipfs_pinning_configs.len(), 1);
            assert!(config.task_id.is_none());
            assert!(config.process_config.shutdown_flag.is_none());
        }

        #[test]
        fn creates_backup_config_with_minimal_options() {
            let chain_config = ChainConfig(HashMap::new());
            let token_config = TokenConfig {
                chains: HashMap::new(),
            };

            let config =
                create_backup_config(chain_config, token_config, None, false, true, Vec::new());

            assert!(config.storage_config.output_path.is_none());
            assert!(!config.storage_config.prune_redundant);
            assert!(config.process_config.exit_on_error);
            assert!(config.storage_config.ipfs_pinning_configs.is_empty());
            assert!(config.task_id.is_none());
            assert!(config.process_config.shutdown_flag.is_none());
        }
    }
}
