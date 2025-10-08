use anyhow::Result;
use std::path::Path;
use std::path::PathBuf;

use crate::chain::common::ContractTokenInfo;
use crate::url::resolve_url;

pub mod croquet;
pub mod fisherman;

/// Extends content handling based on chain, contract address, and token ID.
/// This function is called after the main content has been downloaded and saved.
pub async fn fetch_and_write_extra(
    token: &impl ContractTokenInfo,
    output_path: &Path,
    artifact_url: Option<&str>,
) -> Result<Vec<PathBuf>> {
    fetch_and_write_extra_with_base_url(token, output_path, artifact_url, None).await
}

/// Extends content handling based on chain, contract address, and token ID.
/// This function is called after the main content has been downloaded and saved.
/// For testing purposes, accepts an optional base URL to override the default URLs.
async fn fetch_and_write_extra_with_base_url(
    token: &impl ContractTokenInfo,
    output_path: &Path,
    artifact_url: Option<&str>,
    base_url: Option<&str>,
) -> Result<Vec<PathBuf>> {
    match (token.chain_name(), token.address()) {
        ("ethereum", "0x2A86C5466f088caEbf94e071a77669BAe371CD87") => {
            croquet::fetch_croquet_challenge(
                output_path,
                token.address(),
                token.token_id(),
                base_url,
            )
            .await
        }
        ("tezos", "KT1UcASzQxiWprSmsvpStsxtAZzaRJWR78gz") if artifact_url.is_some() => {
            fisherman::fetch_fisherman(
                output_path,
                token.address(),
                token.token_id(),
                &resolve_url(artifact_url.unwrap()),
            )
            .await
        }
        // Default case - no extension needed
        _ => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::common::ContractTokenId;
    use tempfile::TempDir;

    async fn setup_test_dir() -> TempDir {
        TempDir::new().expect("Failed to create temp dir")
    }

    #[tokio::test]
    async fn test_fetch_and_write_extra_unknown_chain() {
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        let token = ContractTokenId {
            chain_name: "polygon".to_string(),
            address: "0x2A86C5466f088caEbf94e071a77669BAe371CD87".to_string(),
            token_id: "123".to_string(),
        };
        let result = fetch_and_write_extra(&token, output_path, None).await;

        assert!(result.is_ok());
        let files = result.unwrap();
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_and_write_extra_unknown_contract() {
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        let token = ContractTokenId {
            chain_name: "ethereum".to_string(),
            address: "0x1234567890123456789012345678901234567890".to_string(),
            token_id: "123".to_string(),
        };
        let result = fetch_and_write_extra(&token, output_path, None).await;

        assert!(result.is_ok());
        let files = result.unwrap();
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_and_write_extra_tezos_no_artifact_url() {
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        let token = ContractTokenId {
            chain_name: "tezos".to_string(),
            address: "KT1UcASzQxiWprSmsvpStsxtAZzaRJWR78gz".to_string(),
            token_id: "4".to_string(),
        };
        let result = fetch_and_write_extra(&token, output_path, None).await;

        assert!(result.is_ok());
        let files = result.unwrap();
        assert!(files.is_empty());
    }
}
