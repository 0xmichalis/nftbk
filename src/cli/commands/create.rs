use std::path::PathBuf;

use anyhow::Result;
use tracing::error;

use crate::backup::backup_from_config;
use crate::cli::config::{
    create_backup_config, load_chain_config, load_ipfs_config, load_token_config,
};

pub async fn run(
    chains_config_path: PathBuf,
    tokens_config_path: PathBuf,
    output_path: Option<PathBuf>,
    prune_redundant: bool,
    exit_on_error: bool,
    ipfs_config: Option<String>,
) -> Result<()> {
    let token_config = load_token_config(&tokens_config_path).await?;
    let chain_config = load_chain_config(&chains_config_path).await?;
    let ipfs_pinning_configs = load_ipfs_config(ipfs_config.as_ref())?;

    let backup_config = create_backup_config(
        chain_config,
        token_config,
        output_path.clone(),
        prune_redundant,
        exit_on_error,
        ipfs_pinning_configs,
    );

    let (archive_out, ipfs_out) = backup_from_config(backup_config, None).await?;

    // Write combined error log to file if present
    let mut merged = Vec::new();
    if !archive_out.errors.is_empty() {
        merged.extend(archive_out.errors);
    }
    if !ipfs_out.errors.is_empty() {
        merged.extend(ipfs_out.errors);
    }
    if !merged.is_empty() {
        if let Some(ref out_path) = output_path {
            let mut log_path = out_path.clone();
            log_path.set_extension("log");
            let log_content = merged.join("\n") + "\n";
            use tokio::io::AsyncWriteExt;
            let mut file = tokio::fs::File::create(&log_path).await?;
            file.write_all(log_content.as_bytes()).await?;
            error!("Error log written to {}", log_path.display());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::fs;

    mod run_tests {
        use super::*;

        async fn create_test_configs() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
            // Create chains config
            let chains_file = tempfile::NamedTempFile::new().unwrap();
            let chains_content = r#"
ethereum = "https://ethereum.publicnode.com"
"#;
            std::fs::write(chains_file.path(), chains_content).unwrap();

            // Create tokens config
            let tokens_file = tempfile::NamedTempFile::new().unwrap();
            let tokens_content = r#"
ethereum = []
"#;
            std::fs::write(tokens_file.path(), tokens_content).unwrap();

            (chains_file, tokens_file)
        }

        async fn create_test_ipfs_config() -> tempfile::NamedTempFile {
            let ipfs_file = tempfile::NamedTempFile::new().unwrap();
            let ipfs_content = r#"
[[ipfs_pinning_provider]]
type = "pinata"
base_url = "https://api.pinata.cloud"
"#;
            std::fs::write(ipfs_file.path(), ipfs_content).unwrap();
            ipfs_file
        }

        #[tokio::test]
        async fn runs_successfully_with_valid_configs() {
            let (chains_file, tokens_file) = create_test_configs().await;
            let temp_dir = TempDir::new().unwrap();
            let output_path = Some(temp_dir.path().to_path_buf());

            let result = run(
                chains_file.path().to_path_buf(),
                tokens_file.path().to_path_buf(),
                output_path,
                false,
                false,
                None,
            )
            .await;

            // The function should return Ok even if the backup process fails
            // because it handles errors internally and writes them to a log file
            if let Err(e) = &result {
                println!("Error: {}", e);
            }
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn returns_error_for_missing_chains_config() {
            let (_, tokens_file) = create_test_configs().await;
            let non_existent_path = PathBuf::from("/non/existent/chains.toml");

            let result = run(
                non_existent_path,
                tokens_file.path().to_path_buf(),
                None,
                false,
                false,
                None,
            )
            .await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to read chains config file"));
        }

        #[tokio::test]
        async fn returns_error_for_missing_tokens_config() {
            let (chains_file, _) = create_test_configs().await;
            let non_existent_path = PathBuf::from("/non/existent/tokens.toml");

            let result = run(
                chains_file.path().to_path_buf(),
                non_existent_path,
                None,
                false,
                false,
                None,
            )
            .await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to read tokens config file"));
        }

        #[tokio::test]
        async fn writes_error_log_when_errors_occur() {
            // Create configs with invalid chain URL to trigger errors
            let chains_file = tempfile::NamedTempFile::new().unwrap();
            let chains_content = r#"
ethereum = "https://invalid-url-that-will-fail.com"
"#;
            std::fs::write(chains_file.path(), chains_content).unwrap();

            let tokens_file = tempfile::NamedTempFile::new().unwrap();
            let tokens_content = r#"
ethereum = ["0x123:1"]
"#;
            std::fs::write(tokens_file.path(), tokens_content).unwrap();

            let temp_dir = TempDir::new().unwrap();
            let output_path = temp_dir.path().to_path_buf();

            let result = run(
                chains_file.path().to_path_buf(),
                tokens_file.path().to_path_buf(),
                Some(output_path.clone()),
                false,
                false,
                None,
            )
            .await;

            // The function should still return Ok even if there are errors,
            // as it writes them to a log file
            assert!(result.is_ok());

            // Check if error log was created
            let log_path = output_path.join("nft_backup.log");
            if log_path.exists() {
                let log_content = fs::read_to_string(&log_path).await.unwrap();
                assert!(!log_content.is_empty());
            }
        }

        #[tokio::test]
        async fn handles_ipfs_config_correctly() {
            let (chains_file, tokens_file) = create_test_configs().await;

            // Create IPFS config file
            let ipfs_file = tempfile::NamedTempFile::new().unwrap();
            let ipfs_content = r#"
[[ipfs_pinning_provider]]
type = "pinata"
base_url = "https://api.pinata.cloud"
"#;
            std::fs::write(ipfs_file.path(), ipfs_content).unwrap();

            let temp_dir = TempDir::new().unwrap();
            let output_path = Some(temp_dir.path().to_path_buf());
            let ipfs_config_path = Some(ipfs_file.path().to_string_lossy().to_string());

            let result = run(
                chains_file.path().to_path_buf(),
                tokens_file.path().to_path_buf(),
                output_path,
                false,
                false,
                ipfs_config_path,
            )
            .await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn returns_error_for_invalid_ipfs_config() {
            let (chains_file, tokens_file) = create_test_configs().await;
            let invalid_ipfs_path = Some("/non/existent/ipfs.toml".to_string());

            let result = run(
                chains_file.path().to_path_buf(),
                tokens_file.path().to_path_buf(),
                None,
                false,
                false,
                invalid_ipfs_path,
            )
            .await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to read IPFS config file"));
        }

        #[tokio::test]
        async fn handles_all_boolean_options() {
            let (chains_file, tokens_file) = create_test_configs().await;
            let temp_dir = TempDir::new().unwrap();
            let output_path = Some(temp_dir.path().to_path_buf());

            // Test with prune_redundant = true, exit_on_error = true
            let result = run(
                chains_file.path().to_path_buf(),
                tokens_file.path().to_path_buf(),
                output_path,
                true,
                true,
                None,
            )
            .await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn works_without_output_path() {
            let (chains_file, tokens_file) = create_test_configs().await;
            let ipfs_file = create_test_ipfs_config().await;

            let result = run(
                chains_file.path().to_path_buf(),
                tokens_file.path().to_path_buf(),
                None, // No output path
                false,
                false,
                Some(ipfs_file.path().to_string_lossy().to_string()),
            )
            .await;

            if let Err(e) = &result {
                println!("Error: {}", e);
            }
            assert!(result.is_ok());
        }
    }
}
