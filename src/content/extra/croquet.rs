use anyhow::Result;
use std::path::Path;
use std::path::PathBuf;
use tokio::fs;
use tracing::{debug, info};

use crate::content::{stream_gzip_http_to_file, stream_http_to_file};

pub async fn fetch_croquet_challenge(
    output_path: &Path,
    contract: &str,
    token_id: &str,
    base_url: Option<&str>,
) -> Result<Vec<PathBuf>> {
    // Check if token_id is in the specified range using string comparison
    let start_id = "25811853076941608055270457512038717433705462539422789705262203111341130500763";
    let end_id = "25811853076941608055270457512038717433705462539422789705262203111341130501225";

    if token_id >= start_id && token_id <= end_id {
        if let Some(base_url) = base_url {
            fetch_croquet_challenge_content_with_base_url(output_path, contract, token_id, base_url)
                .await
        } else {
            fetch_croquet_challenge_content(output_path, contract, token_id).await
        }
    } else {
        Ok(Vec::new())
    }
}

async fn fetch_croquet_challenge_content(
    output_path: &Path,
    contract: &str,
    token_id: &str,
) -> Result<Vec<PathBuf>> {
    fetch_croquet_challenge_content_with_base_url(
        output_path,
        contract,
        token_id,
        "https://chan.gallery",
    )
    .await
}

async fn fetch_croquet_challenge_content_with_base_url(
    output_path: &Path,
    contract: &str,
    token_id: &str,
    base_url: &str,
) -> Result<Vec<PathBuf>> {
    debug!(
        "Fetching additional content for Ethereum contract {} token {}",
        contract, token_id
    );

    // Create Build directory
    let build_dir = output_path
        .join("ethereum")
        .join(contract)
        .join(token_id)
        .join("Build");
    fs::create_dir_all(&build_dir).await?;

    // Files to download with their target names
    let files = [
        ("bb0101.data.gz", "bb0101_uncompressed.data"),
        ("bb0101.framework.js.gz", "bb0101_uncompressed.framework.js"),
        ("bb0101.loader.js", "bb0101_uncompressed.loader.js"),
        ("bb0101.wasm.gz", "bb0101_uncompressed.wasm"),
    ];

    // Download each file
    let client = reqwest::Client::new();
    let mut files_created = Vec::new();
    for (source_file, target_file) in files {
        let url = format!("{base_url}/bb0101/Build/{source_file}");
        let file_path = build_dir.join(target_file);

        // Skip if file already exists
        if fs::try_exists(&file_path).await? {
            debug!("File already exists at {}", file_path.display());
            files_created.push(file_path.clone());
            continue;
        }

        let response = client.get(&url).send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(anyhow::anyhow!(
                "Failed to fetch content from {} (status: {})",
                url,
                status
            ));
        }
        if source_file.ends_with(".gz") {
            stream_gzip_http_to_file(response, &file_path).await?;
        } else {
            stream_http_to_file(response, &file_path).await?;
        }
        files_created.push(file_path.clone());
        info!("Saved {} from {}", target_file, url);
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

        // Mock the HTTP responses for the croquet challenge content
        // Create proper gzipped data
        use flate2::write::GzEncoder;
        use flate2::Compression;
        use std::io::Write;

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"fake data content").unwrap();
        let gzipped_data = encoder.finish().unwrap();

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"fake js content").unwrap();
        let gzipped_js = encoder.finish().unwrap();

        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"fake wasm content").unwrap();
        let gzipped_wasm = encoder.finish().unwrap();

        Mock::given(method("GET"))
            .and(path("/bb0101/Build/bb0101.data.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gzipped_data))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/bb0101/Build/bb0101.framework.js.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gzipped_js))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/bb0101/Build/bb0101.loader.js"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"fake loader js"))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/bb0101/Build/bb0101.wasm.gz"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gzipped_wasm))
            .mount(&mock_server)
            .await;

        mock_server
    }

    #[tokio::test]
    async fn test_fetch_croquet_challenge_in_range() {
        let mock_server = setup_mock_server().await;
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        let result = fetch_croquet_challenge(
            output_path,
            "0x2A86C5466f088caEbf94e071a77669BAe371CD87",
            "25811853076941608055270457512038717433705462539422789705262203111341130500780",
            Some(&mock_server.uri()),
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
            4,
            "Should return exactly 4 files for croquet challenge content"
        );
    }

    #[tokio::test]
    async fn test_fetch_croquet_challenge_below_range() {
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        let result = fetch_croquet_challenge(
            output_path,
            "0x2A86C5466f088caEbf94e071a77669BAe371CD87",
            "25811853076941608055270457512038717433705462539422789705262203111341130500762", // Below range
            None,
        )
        .await;

        assert!(result.is_ok());
        let files = result.unwrap();
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_croquet_challenge_above_range() {
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        let result = fetch_croquet_challenge(
            output_path,
            "0x2A86C5466f088caEbf94e071a77669BAe371CD87",
            "25811853076941608055270457512038717433705462539422789705262203111341130501226", // Above range
            None,
        )
        .await;

        assert!(result.is_ok());
        let files = result.unwrap();
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn test_fetch_croquet_challenge_at_range_boundaries() {
        let mock_server = setup_mock_server().await;
        let temp_dir = setup_test_dir().await;
        let output_path = temp_dir.path();

        // Test start of range
        let result_start = fetch_croquet_challenge(
            output_path,
            "0x2A86C5466f088caEbf94e071a77669BAe371CD87",
            "25811853076941608055270457512038717433705462539422789705262203111341130500763", // Start of range
            Some(&mock_server.uri()),
        )
        .await;

        assert!(result_start.is_ok());
        let files_start = result_start.unwrap();
        assert!(
            !files_start.is_empty(),
            "Should return files at start of range"
        );
        assert_eq!(
            files_start.len(),
            4,
            "Should return exactly 4 files for croquet challenge content"
        );

        // Test end of range
        let result_end = fetch_croquet_challenge(
            output_path,
            "0x2A86C5466f088caEbf94e071a77669BAe371CD87",
            "25811853076941608055270457512038717433705462539422789705262203111341130501225", // End of range
            Some(&mock_server.uri()),
        )
        .await;

        assert!(result_end.is_ok());
        let files_end = result_end.unwrap();
        assert!(!files_end.is_empty(), "Should return files at end of range");
        assert_eq!(
            files_end.len(),
            4,
            "Should return exactly 4 files for croquet challenge content"
        );
    }
}
