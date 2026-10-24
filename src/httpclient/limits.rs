use futures_util::StreamExt;
use tokio::io::{AsyncBufRead, AsyncReadExt};
use tokio_util::io::StreamReader;

pub(super) const MAX_BUFFER_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

pub(super) fn check_size(size: u64, limit: u64) -> anyhow::Result<()> {
    anyhow::ensure!(size <= limit, "Content exceeds {limit} byte limit");
    Ok(())
}

pub(super) fn data_url_bytes(url: &str, limit: u64) -> anyhow::Result<Vec<u8>> {
    // Percent encoding can use three input bytes per decoded byte.
    check_size(url.len() as u64, limit * 3 + 128)?;
    let content =
        crate::url::get_data_url(url).ok_or_else(|| anyhow::anyhow!("Failed to parse data URL"))?;
    check_size(content.len() as u64, limit)?;
    Ok(content)
}

pub(super) fn response_reader(
    response: reqwest::Response,
    limit: u64,
) -> anyhow::Result<impl AsyncBufRead + Unpin> {
    if let Some(length) = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|header| header.to_str().ok())
        .and_then(|value| value.parse().ok())
        .or_else(|| response.content_length())
    {
        check_size(length, limit)?;
    }

    let mut received = 0;
    let stream = response.bytes_stream().map(move |chunk| {
        let chunk = chunk.map_err(|error| std::io::Error::other(error.without_url()))?;
        received += chunk.len() as u64;
        check_size(received, limit).map_err(std::io::Error::other)?;
        Ok::<_, std::io::Error>(chunk)
    });
    Ok(StreamReader::new(stream))
}

pub(super) async fn response_bytes(response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let mut reader = response_reader(response, MAX_BUFFER_BYTES)?;
    let mut content = Vec::new();
    reader.read_to_end(&mut content).await?;
    Ok(content)
}

#[cfg(test)]
mod response_reader_tests {
    use super::*;

    #[tokio::test]
    async fn accepts_the_exact_limit() {
        let response = axum::http::Response::new(b"1234".to_vec()).into();
        let mut reader = response_reader(response, 4).unwrap();
        let mut content = Vec::new();
        reader.read_to_end(&mut content).await.unwrap();
        assert_eq!(content, b"1234");
    }

    #[tokio::test]
    async fn bounds_chunks_without_content_length() {
        let chunks = futures_util::stream::iter([
            Ok::<_, std::io::Error>(b"123".to_vec()),
            Ok(b"45".to_vec()),
        ]);
        let response = axum::http::Response::new(reqwest::Body::wrap_stream(chunks)).into();
        let mut reader = response_reader(response, 4).unwrap();
        let mut content = Vec::new();
        assert_eq!(
            reader
                .read_to_end(&mut content)
                .await
                .unwrap_err()
                .to_string(),
            "Content exceeds 4 byte limit"
        );
        assert_eq!(content, b"123");
    }

    #[test]
    fn rejects_oversized_declared_length_before_reading() {
        let response = axum::http::Response::builder()
            .header("Content-Length", "5")
            .body(Vec::<u8>::new())
            .unwrap()
            .into();
        assert_eq!(
            response_reader(response, 4).err().unwrap().to_string(),
            "Content exceeds 4 byte limit"
        );
    }
}

#[cfg(test)]
mod data_url_bytes_tests {
    use super::*;

    #[test]
    fn bounds_decoded_content() {
        assert_eq!(data_url_bytes("data:text/plain,1234", 4).unwrap(), b"1234");
        for url in [
            "data:text/plain,12345",
            "data:text/plain,%31%32%33%34%35",
            "data:text/plain;base64,MTIzNDU=",
            r#"{"too":"large"}"#,
        ] {
            assert_eq!(
                data_url_bytes(url, 4).unwrap_err().to_string(),
                "Content exceeds 4 byte limit"
            );
        }
    }
}
