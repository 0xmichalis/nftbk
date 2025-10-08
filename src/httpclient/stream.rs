use anyhow::Result;
use async_compression::tokio::bufread::GzipDecoder;
use futures_util::TryStreamExt;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWriteExt, BufReader};
use tokio_util::io::StreamReader;

pub(crate) async fn stream_reader_to_file<R: AsyncRead + Unpin>(
    reader: &mut R,
    file: &mut tokio::fs::File,
    file_path: &Path,
) -> anyhow::Result<std::path::PathBuf> {
    tokio::io::copy(reader, file).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to stream content to file {}: {}",
            file_path.display(),
            e
        )
    })?;
    file.flush()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to flush file {}: {}", file_path.display(), e))?;
    Ok(file_path.to_path_buf())
}

pub(crate) async fn stream_http_to_file(
    response: reqwest::Response,
    file_path: &Path,
) -> anyhow::Result<std::path::PathBuf> {
    let stream = response.bytes_stream().map_err(std::io::Error::other);
    let mut reader = StreamReader::new(stream);

    let mut file_path = file_path.to_path_buf();
    let (detected_ext, prefix_buf) =
        crate::content::extensions::detect_extension_from_stream(&mut reader).await;
    if !crate::content::extensions::has_known_extension(&file_path) {
        if let Some(detected_ext) = detected_ext {
            let current_path_str = file_path.to_string_lossy();
            tracing::debug!("Appending detected media extension: {}", detected_ext);
            file_path = std::path::PathBuf::from(format!("{current_path_str}.{detected_ext}"));
        }
    }

    let mut file = tokio::fs::File::create(&file_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create file {}: {}", file_path.display(), e))?;
    if !prefix_buf.is_empty() {
        file.write_all(&prefix_buf).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to write prefix to file {}: {}",
                file_path.display(),
                e
            )
        })?;
    }
    let result = stream_reader_to_file(&mut reader, &mut file, &file_path).await?;

    file.sync_all().await.map_err(|e| {
        anyhow::anyhow!("Failed to sync file {} to disk: {}", file_path.display(), e)
    })?;

    Ok(result)
}

pub(crate) async fn stream_gzip_http_to_file(
    response: reqwest::Response,
    file_path: &Path,
) -> Result<std::path::PathBuf> {
    let mut file = tokio::fs::File::create(file_path).await?;
    let stream = response.bytes_stream().map_err(std::io::Error::other);
    let reader = StreamReader::new(stream);
    let mut decoder = GzipDecoder::new(BufReader::new(reader));
    stream_reader_to_file(&mut decoder, &mut file, file_path).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_large_file_streaming() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/large-file", mock_server.uri());

        let large_body = "x".repeat(1024 * 1024);
        Mock::given(method("GET"))
            .and(path("/large-file"))
            .respond_with(ResponseTemplate::new(200).set_body_string(large_body))
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("large.txt");

        let client = crate::httpclient::HttpClient::new();
        let (resp, _status) = client.try_fetch_response(&url).await;
        let resp = resp.expect("response ok");
        let result = stream_http_to_file(resp, &file_path).await;
        assert!(result.is_ok());
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), 1024 * 1024);
    }
}
