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
mod stream_reader_to_file_tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn writes_all_bytes_from_reader_to_file() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("ten_kib.bin");
        let mut file = tokio::fs::File::create(&file_path).await.unwrap();

        // Create an AsyncRead that yields exactly 10 KiB of byte 'a'
        let mut reader = tokio::io::repeat(b'a').take(10 * 1024);

        let result = stream_reader_to_file(&mut reader, &mut file, &file_path).await;
        assert!(result.is_ok());

        let data = tokio::fs::read(&file_path).await.unwrap();
        assert_eq!(data.len(), 10 * 1024);
        assert!(data.iter().all(|b| *b == b'a'));
    }

    struct ErrorReader;

    impl tokio::io::AsyncRead for ErrorReader {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::Error::other("simulated read error")))
        }
    }

    #[tokio::test]
    async fn returns_error_when_reader_fails() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("out.bin");
        let mut file = tokio::fs::File::create(&file_path).await.unwrap();

        let mut reader = ErrorReader;
        let err = stream_reader_to_file(&mut reader, &mut file, &file_path)
            .await
            .expect_err("expected error");
        let msg = format!("{err:#}");
        assert!(msg.contains("Failed to stream content to file"));
    }
}

#[cfg(test)]
mod stream_http_to_file_tests {
    use super::*;
    use tempfile::TempDir;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn streams_large_http_body_to_file() {
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

        let response = reqwest::get(&url).await.unwrap();
        let result = stream_http_to_file(response, &file_path).await;
        assert!(result.is_ok());
        let metadata = std::fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.len(), 1024 * 1024);
    }

    #[tokio::test]
    async fn appends_detected_extension_when_missing() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/png", mock_server.uri());

        // Minimal PNG signature + padding
        let mut body = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        body.extend_from_slice(&[0u8; 64]);
        Mock::given(method("GET"))
            .and(path("/png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let base_path = temp_dir.path().join("image");
        let response = reqwest::get(&url).await.unwrap();
        let result_path = stream_http_to_file(response, &base_path).await.unwrap();

        // Should have appended .png
        assert!(result_path.extension().is_some());
        assert_eq!(result_path.extension().unwrap(), "png");
        assert!(result_path.exists());
    }

    #[tokio::test]
    async fn does_not_append_when_known_extension_present() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/any", mock_server.uri());
        Mock::given(method("GET"))
            .and(path("/any"))
            .respond_with(ResponseTemplate::new(200).set_body_string("data"))
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let path_with_ext = temp_dir.path().join("photo.jpg");
        let response = reqwest::get(&url).await.unwrap();
        let result_path = stream_http_to_file(response, &path_with_ext).await.unwrap();

        assert_eq!(result_path, path_with_ext);
        assert!(result_path.exists());
    }

    #[tokio::test]
    async fn returns_error_when_file_creation_fails() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/small", mock_server.uri());
        Mock::given(method("GET"))
            .and(path("/small"))
            .respond_with(ResponseTemplate::new(200).set_body_string("abc"))
            .mount(&mock_server)
            .await;

        // Non-existent parent directory to trigger create error
        let temp_dir = TempDir::new().unwrap();
        let bad_path = temp_dir.path().join("no_such_dir").join("file.bin");

        let response = reqwest::get(&url).await.unwrap();
        let err = stream_http_to_file(response, &bad_path)
            .await
            .expect_err("expected creation error");
        let msg = format!("{err:#}");
        assert!(msg.contains("Failed to create file"));
    }
}

#[cfg(test)]
mod stream_gzip_http_to_file_tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use tempfile::TempDir;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn decodes_gzipped_http_body_to_file() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/gz", mock_server.uri());

        // Prepare gzipped payload for body "hello gzip"
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        std::io::Write::write_all(&mut encoder, b"hello gzip").unwrap();
        let gzipped = encoder.finish().unwrap();

        Mock::given(method("GET"))
            .and(path("/gz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(gzipped)
                    .insert_header("Content-Encoding", "gzip"),
            )
            .mount(&mock_server)
            .await;

        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("out.txt");

        let response = reqwest::get(&url).await.unwrap();
        let result = stream_gzip_http_to_file(response, &file_path).await;
        assert!(result.is_ok());

        let content = tokio::fs::read_to_string(&file_path).await.unwrap();
        assert_eq!(content, "hello gzip");
    }
}
