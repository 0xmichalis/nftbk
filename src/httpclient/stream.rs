use anyhow::{Context, Result};
use async_compression::tokio::bufread::GzipDecoder;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use uuid::Uuid;

use super::limits::{MAX_FILE_BYTES, check_size, response_reader};

async fn stream_reader_to_file<R: AsyncRead + Unpin>(
    reader: &mut R,
    file: &mut tokio::fs::File,
    file_path: &Path,
) -> Result<()> {
    let copied = tokio::io::copy(&mut reader.take(MAX_FILE_BYTES + 1), file)
        .await
        .with_context(|| format!("Failed to stream content to file {}", file_path.display()))?;
    check_size(copied, MAX_FILE_BYTES)?;
    file.flush()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to flush file {}: {}", file_path.display(), e))?;
    Ok(())
}

pub(crate) async fn stream_http_to_file(
    response: reqwest::Response,
    file_path: &Path,
) -> Result<PathBuf> {
    let mut reader = response_reader(response, MAX_FILE_BYTES)?;
    // The extension probe treats read errors as empty content, so check first.
    reader.fill_buf().await?;

    let mut file_path = file_path.to_path_buf();
    let (detected_ext, prefix_buf) =
        crate::content::extensions::detect_extension_from_stream(&mut reader).await;
    if !crate::content::extensions::has_known_extension(&file_path)
        && let Some(detected_ext) = detected_ext
    {
        let current_path_str = file_path.to_string_lossy();
        tracing::debug!("Appending detected media extension: {}", detected_ext);
        file_path = PathBuf::from(format!("{current_path_str}.{detected_ext}"));
    }

    let mut reader = prefix_buf.as_slice().chain(reader);
    write_reader_to_file(&mut reader, &file_path).await
}

async fn write_reader_to_file<R: AsyncRead + Unpin>(
    reader: &mut R,
    file_path: &Path,
) -> Result<PathBuf> {
    // Keep incomplete bytes out of the destination and the sibling dedup scan.
    // Create the guard in the blocking task so cancellation during creation also cleans up.
    let scratch_path = file_path.with_file_name(format!(".nftbk-download-{}", Uuid::new_v4()));
    let (scratch, mut file) = tokio::task::spawn_blocking(move || {
        std::fs::create_dir(&scratch_path)?;
        let scratch = DownloadScratch(scratch_path);
        let file = std::fs::File::create(scratch.0.join("body"))?;
        Ok::<_, std::io::Error>((scratch, tokio::fs::File::from_std(file)))
    })
    .await?
    .with_context(|| format!("Failed to create file {}", file_path.display()))?;

    stream_reader_to_file(reader, &mut file, file_path).await?;
    file.sync_all()
        .await
        .with_context(|| format!("Failed to sync file {} to disk", file_path.display()))?;
    drop(file);

    let path = file_path.to_path_buf();
    tokio::task::spawn_blocking(move || scratch.publish(path)).await?
}

struct DownloadScratch(PathBuf);

impl DownloadScratch {
    fn publish(self, path: PathBuf) -> Result<PathBuf> {
        std::fs::rename(self.0.join("body"), &path)
            .with_context(|| format!("Failed to publish file {}", path.display()))?;
        Ok(path)
    }
}

impl Drop for DownloadScratch {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_dir_all(&self.0) {
            tracing::warn!("Failed to remove temporary download directory: {error}");
        }
    }
}

pub(crate) async fn stream_gzip_http_to_file(
    response: reqwest::Response,
    file_path: &Path,
) -> Result<PathBuf> {
    let reader = response_reader(response, MAX_FILE_BYTES)?;
    let mut decoder = GzipDecoder::new(BufReader::new(reader));
    write_reader_to_file(&mut decoder, file_path).await
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
    use futures_util::StreamExt;
    use std::sync::Arc;
    use std::task::Poll;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::sync::Notify;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[tokio::test]
    async fn rejects_oversized_content_length_without_creating_file() {
        let response = axum::http::Response::builder()
            .header("Content-Length", "268435457")
            .body(Vec::<u8>::new())
            .unwrap()
            .into();
        let out = TempDir::new().unwrap();
        let file_path = out.path().join("large.bin");

        let error = stream_http_to_file(response, &file_path).await.unwrap_err();
        assert_eq!(error.to_string(), "Content exceeds 268435456 byte limit");
        assert!(!crate::httpclient::retry::should_retry(
            &error,
            Some(reqwest::StatusCode::OK)
        ));
        assert!(!file_path.exists());
    }

    #[tokio::test]
    async fn rejects_oversized_chunked_body_and_removes_partial_file() {
        let chunks = futures_util::stream::iter(0..257)
            .map(|_| Ok::<_, std::io::Error>(vec![0; 1024 * 1024]));
        let response = axum::http::Response::new(reqwest::Body::wrap_stream(chunks)).into();
        let out = TempDir::new().unwrap();
        let file_path = out.path().join("large.bin");

        assert!(stream_http_to_file(response, &file_path).await.is_err());
        assert!(!file_path.exists());
    }

    #[tokio::test]
    async fn removes_partial_file_with_detected_extension_after_body_error() {
        let chunks = futures_util::stream::iter([
            Ok(b"\x89PNG\r\n\x1a\npartial image".to_vec()),
            Err(std::io::Error::other("body read timed out")),
        ]);
        let response = axum::http::Response::new(reqwest::Body::wrap_stream(chunks)).into();
        let out = TempDir::new().unwrap();
        let file_path = out.path().join("image");

        let error = stream_http_to_file(response, &file_path).await.unwrap_err();
        assert!(error.downcast_ref::<std::io::Error>().is_some());
        assert!(format!("{error:#}").contains("body read timed out"));
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn interrupted_stream_does_not_publish_partial_file() {
        let out = TempDir::new().unwrap();
        let file_path = out.path().join("image");
        let detected_path = file_path.with_extension("png");
        let stalled = Arc::new(Notify::new());
        let body_stalled = stalled.clone();
        let chunks = futures_util::stream::iter([Ok::<_, std::io::Error>(
            b"\x89PNG\r\n\x1a\npartial image".to_vec(),
        )])
        .chain(futures_util::stream::poll_fn(move |_| {
            body_stalled.notify_one();
            Poll::Pending
        }));
        let response = axum::http::Response::new(reqwest::Body::wrap_stream(chunks)).into();
        let download = tokio::spawn(async move { stream_http_to_file(response, &file_path).await });

        tokio::time::timeout(Duration::from_secs(5), stalled.notified())
            .await
            .unwrap();
        let published_before_end_of_stream = detected_path.exists();
        download.abort();
        assert!(download.await.unwrap_err().is_cancelled());

        assert!(!published_before_end_of_stream);
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn failed_stream_preserves_an_existing_destination() {
        let out = TempDir::new().unwrap();
        let file_path = out.path().join("video.mp4");
        tokio::fs::write(&file_path, b"original").await.unwrap();
        let chunks = futures_util::stream::iter([
            Ok(b"partial replacement".to_vec()),
            Err(std::io::Error::other("body read timed out")),
        ]);
        let response = axum::http::Response::new(reqwest::Body::wrap_stream(chunks)).into();

        assert!(stream_http_to_file(response, &file_path).await.is_err());

        assert_eq!(tokio::fs::read(&file_path).await.unwrap(), b"original");
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn failed_publication_cleans_up_the_temporary_download() {
        let out = TempDir::new().unwrap();
        let file_path = out.path().join("image.png");
        tokio::fs::create_dir(&file_path).await.unwrap();
        let response = axum::http::Response::new(b"image data".to_vec()).into();

        let error = stream_http_to_file(response, &file_path).await.unwrap_err();

        assert!(error.to_string().contains("Failed to publish file"));
        assert!(file_path.is_dir());
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn rejects_failed_body_before_creating_file() {
        let chunks = futures_util::stream::iter([Err::<Vec<u8>, _>(std::io::Error::other(
            "body read timed out",
        ))]);
        let response = axum::http::Response::new(reqwest::Body::wrap_stream(chunks)).into();
        let out = TempDir::new().unwrap();
        let file_path = out.path().join("empty.bin");

        assert!(stream_http_to_file(response, &file_path).await.is_err());
        assert!(!file_path.exists());
    }

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
        assert_eq!(std::fs::read_dir(temp_dir.path()).unwrap().count(), 1);
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
    use flate2::{Compression, write::GzEncoder};
    use tempfile::TempDir;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[tokio::test]
    async fn rejects_oversized_gzip_output_and_removes_partial_file() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        let mut content = std::io::Read::take(std::io::repeat(0), 256 * 1024 * 1024 + 1);
        std::io::copy(&mut content, &mut encoder).unwrap();
        let response = axum::http::Response::new(encoder.finish().unwrap()).into();
        let out = TempDir::new().unwrap();
        let file_path = out.path().join("expanded.bin");

        assert!(
            stream_gzip_http_to_file(response, &file_path)
                .await
                .is_err()
        );
        assert!(!file_path.exists());
    }

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
            .respond_with(ResponseTemplate::new(200).set_body_bytes(gzipped))
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
