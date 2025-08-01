use anyhow::Result;
use std::path::Path;
use std::path::PathBuf;
use tokio::fs;
use tracing::{debug, info, warn};

use crate::content::stream_http_to_file;

pub async fn fetch_fisherman(
    output_path: &Path,
    contract: &str,
    token_id: &str,
    artifact_url: &str,
) -> Result<Vec<PathBuf>> {
    if token_id == "4" {
        fetch_the_fisherman_content(output_path, contract, token_id, artifact_url).await
    } else {
        Ok(Vec::new())
    }
}

async fn fetch_the_fisherman_content(
    output_path: &Path,
    contract: &str,
    token_id: &str,
    artifact_url: &str,
) -> Result<Vec<PathBuf>> {
    debug!(
        "Fetching additional content for Tezos contract {} token {}",
        contract, token_id
    );

    // Create token directory
    let token_dir = output_path.join("tezos").join(contract).join(token_id);
    fs::create_dir_all(&token_dir).await?;

    // Files to download
    let files = [
        "0.png",
        "1.png",
        "2.png",
        "4.png",
        "5.png",
        "6.png",
        "7.png",
        "8.png",
        "10.png",
        "11.png",
        "13.png",
        "14.png",
        "sound1.mp3",
        "sound2.mp3",
        "IBMCGAthin.ttf",
    ];

    // Download each file
    let client = reqwest::Client::new();
    let mut files_created = Vec::new();
    for file in files {
        let url = format!("{}/{}", artifact_url.trim_end_matches('/'), file);
        let file_path = token_dir.join(file);

        // Skip if file already exists
        if fs::try_exists(&file_path).await? {
            debug!("File already exists at {}", file_path.display());
            files_created.push(file_path.clone());
            continue;
        }

        match client.get(&url).send().await {
            Ok(response) => {
                let status = response.status();
                if !status.is_success() {
                    warn!("Failed to download {}: HTTP {}", file, status);
                    continue;
                }
                stream_http_to_file(response, &file_path).await?;
                files_created.push(file_path.clone());
                info!("Saved {} from {}", file, url);
            }
            Err(e) => {
                warn!("Failed to download {}: {}", file, e);
            }
        }
    }

    Ok(files_created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn setup_test_dir() -> TempDir {
        let temp_dir = TempDir::new().expect("Failed to create temp dir");
        temp_dir
    }

    async fn setup_mock_server() -> MockServer {
        let mock_server = MockServer::start().await;

        // Mock the HTTP responses for the fisherman content
        Mock::given(method("GET"))
            .and(path("/artifacts/0.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/1.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/2.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/4.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/5.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/6.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/7.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/8.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/10.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/11.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/13.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/14.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake png data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/sound1.mp3"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake mp3 data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/sound2.mp3"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake mp3 data"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/artifacts/IBMCGAthin.ttf"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake font data"))
            .mount(&mock_server)
            .await;

        mock_server
    }

    #[tokio::test]
    async fn test_fetch_fisherman_matching_token() {
        let mock_server = setup_mock_server().await;
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        let result = fetch_fisherman(
            output_path,
            "KT1UcASzQxiWprSmsvpStsxtAZzaRJWR78gz",
            "4",
            &format!("{}/artifacts", mock_server.uri()),
        )
        .await;

        assert!(result.is_ok());
        let files = result.unwrap();
        assert!(
            !files.is_empty(),
            "Should return files when conditions are met"
        );
        assert_eq!(
            files.len(),
            15,
            "Should return exactly 15 files for fisherman content"
        );
    }

    #[tokio::test]
    async fn test_fetch_fisherman_wrong_token() {
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        let result = fetch_fisherman(
            output_path,
            "KT1UcASzQxiWprSmsvpStsxtAZzaRJWR78gz",
            "5", // Wrong token ID
            "https://example.com/artifacts",
        )
        .await;

        assert!(result.is_ok());
        let files = result.unwrap();
        assert!(files.is_empty());
    }
}
