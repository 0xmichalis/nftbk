use anyhow::Result;
use std::path::Path;
use std::path::PathBuf;

use crate::url::get_url;

pub mod croquet;
pub mod fisherman;

/// Extends content handling based on chain, contract address, and token ID.
/// This function is called after the main content has been downloaded and saved.
pub async fn fetch_and_save_extra_content(
    chain: &str,
    contract: &str,
    token_id: &str,
    output_path: &Path,
    artifact_url: Option<&str>,
) -> Result<Vec<PathBuf>> {
    fetch_and_save_extra_content_with_base_url(
        chain,
        contract,
        token_id,
        output_path,
        artifact_url,
        None,
    )
    .await
}

/// Extends content handling based on chain, contract address, and token ID.
/// This function is called after the main content has been downloaded and saved.
/// For testing purposes, accepts an optional base URL to override the default URLs.
async fn fetch_and_save_extra_content_with_base_url(
    chain: &str,
    contract: &str,
    token_id: &str,
    output_path: &Path,
    artifact_url: Option<&str>,
    base_url: Option<&str>,
) -> Result<Vec<PathBuf>> {
    match (chain, contract) {
        ("ethereum", "0x2A86C5466f088caEbf94e071a77669BAe371CD87") => {
            croquet::fetch_croquet_challenge(output_path, contract, token_id, base_url).await
        }
        ("tezos", "KT1UcASzQxiWprSmsvpStsxtAZzaRJWR78gz") if artifact_url.is_some() => {
            fisherman::fetch_fisherman(
                output_path,
                contract,
                token_id,
                &get_url(artifact_url.unwrap()),
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
    use tempfile::TempDir;

    async fn setup_test_dir() -> TempDir {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        temp_dir
    }

    #[tokio::test]
    async fn test_fetch_and_save_extra_content_unknown_chain() {
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        let result = fetch_and_save_extra_content(
            "polygon", // Unknown chain
            "0x2A86C5466f088caEbf94e071a77669BAe371CD87",
            "123",
            output_path,
            None,
        )
        .await;

        assert!(result.is_ok());
        let files = result.unwrap();
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_and_save_extra_content_unknown_contract() {
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        let result = fetch_and_save_extra_content(
            "ethereum",
            "0x1234567890123456789012345678901234567890", // Unknown contract
            "123",
            output_path,
            None,
        )
        .await;

        assert!(result.is_ok());
        let files = result.unwrap();
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_and_save_extra_content_tezos_no_artifact_url() {
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        let result = fetch_and_save_extra_content(
            "tezos",
            "KT1UcASzQxiWprSmsvpStsxtAZzaRJWR78gz",
            "4",
            output_path,
            None, // No artifact URL
        )
        .await;

        assert!(result.is_ok());
        let files = result.unwrap();
        assert!(files.is_empty());
    }
}
