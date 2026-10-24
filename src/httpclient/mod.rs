use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::{redirect, ClientBuilder, Method, RequestBuilder};
use tracing::info;
use url::{Host, Url};

use crate::content::dedup::hard_link_to_identical_sibling;
use crate::content::get_filename;
use crate::content::{extensions, try_exists, write_and_postprocess_file, Options};
use crate::httpclient::fetch::{try_fetch_response, try_head_content_length};
use crate::httpclient::limits::{data_url_bytes, response_bytes, MAX_BUFFER_BYTES, MAX_FILE_BYTES};
use crate::httpclient::retry::{retry_operation, should_retry};
use crate::httpclient::stream::stream_http_to_file;
use crate::ipfs::config::{
    prioritize_authenticated, IpfsGatewayConfig, IpfsGatewayType, IPFS_GATEWAYS,
};
use crate::types::DEFAULT_MAX_CONTENT_REQUEST_RETRIES;
use crate::url::{is_data_url, resolve_url_with_gateways};

pub mod fetch;
mod limits;
pub mod retry;
pub mod stream;

#[derive(Clone, Debug)]
pub struct HttpClient {
    pub(crate) ipfs_gateways: Vec<IpfsGatewayConfig>,
    pub(crate) max_retries: u32,
}

impl HttpClient {
    pub fn new() -> Self {
        let ipfs_gateways = prioritize_authenticated(IPFS_GATEWAYS);
        Self {
            ipfs_gateways,
            max_retries: DEFAULT_MAX_CONTENT_REQUEST_RETRIES,
        }
    }

    fn client_builder() -> ClientBuilder {
        reqwest::Client::builder()
            .user_agent(crate::USER_AGENT)
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(300))
            .no_proxy()
            .dns_resolver(Arc::new(PublicResolver))
            .redirect(redirect::Policy::custom(|attempt| {
                if attempt.previous().len() > 5 {
                    attempt.error("Too many content redirects")
                } else if let Err(error) = validate_url(attempt.url()) {
                    attempt.error(error)
                } else {
                    attempt.follow()
                }
            }))
    }

    fn request(&self, method: Method, url: &str, raw_body: bool) -> anyhow::Result<RequestBuilder> {
        let url = Url::parse(url)?;
        // Only unit-test builds may start requests at loopback mock servers.
        let local_mock =
            cfg!(test) && matches!(url.host(), Some(Host::Ipv4(ip)) if ip.is_loopback());
        if !local_mock {
            validate_url(&url)?;
        }

        let builder = Self::client_builder();
        let builder = if raw_body {
            builder.no_gzip().no_brotli().no_deflate().no_zstd()
        } else {
            builder
        };
        Ok(builder.build()?.request(method, url))
    }

    pub(crate) async fn send_request(
        &self,
        method: Method,
        url: &str,
        bearer_token: Option<String>,
    ) -> anyhow::Result<reqwest::Response> {
        let mut request = self.request(method, url, false)?;
        if let Some(token) = bearer_token {
            request = request.bearer_auth(token);
        }
        Ok(request.send().await.map_err(reqwest::Error::without_url)?)
    }

    pub(crate) async fn fetch_raw_response(&self, url: &str) -> anyhow::Result<reqwest::Response> {
        Ok(self
            .request(Method::GET, url, true)?
            .send()
            .await
            .map_err(reqwest::Error::without_url)?)
    }

    pub fn with_gateways(mut self, gateways: Vec<(String, IpfsGatewayType)>) -> Self {
        self.ipfs_gateways = gateways
            .into_iter()
            .map(|(url, gateway_type)| IpfsGatewayConfig {
                url: Box::leak(url.into_boxed_str()),
                gateway_type,
                bearer_token_env: None,
            })
            .collect();
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub async fn fetch(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        if is_data_url(url) {
            return data_url_bytes(url, MAX_BUFFER_BYTES);
        }

        let resolved_url = resolve_url_with_gateways(url, &self.ipfs_gateways);
        let gateways = self.ipfs_gateways.clone();

        let (result, _status) = retry_operation(
            || {
                let url = resolved_url.clone();
                let gateways = gateways.clone();
                Box::pin(async move {
                    match try_fetch_response(&url, &gateways).await {
                        (Ok(response), status) => (response_bytes(response).await, status),
                        (Err(err), status) => (Err(err), status),
                    }
                })
            },
            self.max_retries,
            should_retry,
            &resolved_url,
        )
        .await;
        result
    }

    pub async fn head_content_length(&self, url: &str) -> anyhow::Result<u64> {
        if is_data_url(url) {
            let data = data_url_bytes(url, MAX_FILE_BYTES)?;
            return Ok(data.len() as u64);
        }

        let resolved_url = resolve_url_with_gateways(url, &self.ipfs_gateways);
        let gateways = self.ipfs_gateways.clone();

        let (result, _status) = retry_operation(
            || {
                let url = resolved_url.clone();
                let gateways = gateways.clone();
                Box::pin(async move { try_head_content_length(&url, &gateways).await })
            },
            self.max_retries,
            should_retry,
            &resolved_url,
        )
        .await;
        result
    }

    pub async fn fetch_and_write(
        &self,
        url: &str,
        token: &impl crate::chain::common::ContractTokenInfo,
        output_path: &Path,
        options: Options,
    ) -> anyhow::Result<PathBuf> {
        let mut file_path = get_filename(url, token, output_path, options).await?;

        if let Some(existing_path) = try_exists(&file_path).await? {
            tracing::debug!(
                "File already exists at {} (skipping download)",
                existing_path.display()
            );
            return Ok(existing_path);
        }

        let parent = file_path.parent().ok_or_else(|| {
            anyhow::anyhow!("File path has no parent directory: {}", file_path.display())
        })?;
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            anyhow::anyhow!("Failed to create directory {}: {}", parent.display(), e)
        })?;

        if is_data_url(url) {
            let content = data_url_bytes(url, MAX_FILE_BYTES)?;
            if !extensions::has_known_extension(&file_path) {
                if let Some(detected_ext) = extensions::detect_media_extension(&content) {
                    let current_path_str = file_path.to_string_lossy();
                    tracing::debug!("Appending detected media extension: {}", detected_ext);
                    file_path = PathBuf::from(format!("{current_path_str}.{detected_ext}"));
                }
            }

            info!("Saving {} (data url)", file_path.display());
            write_and_postprocess_file(&file_path, &content, url).await?;
            info!("Saved {} (data url)", file_path.display());
            return Ok(file_path);
        }

        let resolved_url = resolve_url_with_gateways(url, &self.ipfs_gateways);
        if url == resolved_url {
            info!("Saving {} (url: {})", file_path.display(), url);
        } else {
            info!(
                "Saving {} (original: {}, resolved: {})",
                file_path.display(),
                url,
                resolved_url
            );
        }
        let file_path = self
            .fetch_and_stream_to_file(&resolved_url, &file_path, self.max_retries)
            .await?;

        // The same content may already be on disk under a name derived from an
        // earlier URL. Keep a single copy and expose it under both names. This is
        // best effort: the download succeeded, so a failure here must not fail it.
        match hard_link_to_identical_sibling(&file_path).await {
            Ok(Some(original)) => {
                info!(
                    "Saved {} as a hard link to identical {}",
                    file_path.display(),
                    original.display()
                );
                return Ok(file_path);
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(
                "Could not deduplicate {}, keeping the downloaded file: {}",
                file_path.display(),
                e
            ),
        }

        write_and_postprocess_file(&file_path, &[], url).await?;
        if url == resolved_url {
            info!("Saved {} (url: {})", file_path.display(), url);
        } else {
            info!(
                "Saved {} (original: {}, resolved: {})",
                file_path.display(),
                url,
                resolved_url
            );
        }
        Ok(file_path)
    }

    pub async fn try_fetch_response(
        &self,
        url: &str,
    ) -> (
        anyhow::Result<reqwest::Response>,
        Option<reqwest::StatusCode>,
    ) {
        try_fetch_response(url, &self.ipfs_gateways).await
    }

    pub(crate) async fn fetch_and_stream_to_file(
        &self,
        url: &str,
        file_path: &Path,
        max_retries: u32,
    ) -> anyhow::Result<PathBuf> {
        fetch_and_stream_to_file(url, file_path, max_retries, &self.ipfs_gateways).await
    }
}

async fn fetch_and_stream_to_file(
    url: &str,
    file_path: &Path,
    max_retries: u32,
    gateways: &[IpfsGatewayConfig],
) -> anyhow::Result<PathBuf> {
    let (result, _status) = retry_operation(
        || {
            let url = url.to_string();
            let file_path = file_path.to_path_buf();
            let gateways = gateways.to_owned();
            Box::pin(async move {
                match try_fetch_response(&url, &gateways).await {
                    (Ok(response), status) => {
                        (stream_http_to_file(response, &file_path).await, status)
                    }
                    (Err(err), status) => (Err(err), status),
                }
            })
        },
        max_retries,
        should_retry,
        url,
    )
    .await;
    result
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_url(url: &Url) -> io::Result<()> {
    let allowed = matches!(url.scheme(), "http" | "https")
        && match url.host() {
            None => false,
            Some(Host::Domain(_)) => true,
            Some(Host::Ipv4(ip)) => is_public_ip(ip.into()),
            Some(Host::Ipv6(ip)) => is_public_ip(ip.into()),
        };
    if allowed {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Content URL must use HTTP(S) and a public destination",
        ))
    }
}

struct PublicResolver;

impl Resolve for PublicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((name.as_str(), 0)).await?;
            // Return the checked addresses directly to the connector. Never look up
            // the hostname a second time, which would permit DNS rebinding.
            Ok(checked_addresses(addresses)?)
        })
    }
}

fn checked_addresses(addresses: impl Iterator<Item = SocketAddr>) -> io::Result<Addrs> {
    let addresses: Vec<_> = addresses.collect();
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Content hostname must resolve exclusively to public destinations",
        ))
    } else {
        Ok(Box::new(addresses.into_iter()))
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !matches!(
            ip.octets(),
            [0 | 10 | 127, ..]
                | [100, 64..=127, ..]
                | [169, 254, ..]
                | [172, 16..=31, ..]
                | [192, 0, 0 | 2, _]
                | [192, 88, 99, _]
                | [192, 168, ..]
                | [198, 18..=19, ..]
                | [198, 51, 100, _]
                | [203, 0, 113, _]
                | [224..=255, ..]
        ),
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4() {
                return is_public_ip(ipv4.into());
            }
            let segments = ip.segments();
            if segments[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
                let octets = ip.octets();
                return is_public_ip(
                    Ipv4Addr::new(octets[12], octets[13], octets[14], octets[15]).into(),
                );
            }
            // Restrict native IPv6 to global unicast, excluding special-use,
            // documentation and deprecated 6to4 prefixes.
            matches!(segments, [0x2000..=0x3fff, ..])
                && !matches!(
                    segments,
                    [0x2001, 0..=0x1ff | 0xdb8, ..] | [0x2002, ..] | [0x3fff, 0..=0xfff, ..]
                )
        }
    }
}

#[cfg(test)]
mod is_public_ip_tests {
    use super::*;

    #[test]
    fn classifies_ipv4_ranges_and_boundaries() {
        for (ip, expected) in [
            ("0.0.0.0", false),
            ("0.255.255.255", false),
            ("1.0.0.0", true),
            ("9.255.255.255", true),
            ("10.0.0.0", false),
            ("10.255.255.255", false),
            ("11.0.0.0", true),
            ("100.63.255.255", true),
            ("100.64.0.0", false),
            ("100.127.255.255", false),
            ("100.128.0.0", true),
            ("126.255.255.255", true),
            ("127.0.0.0", false),
            ("127.255.255.255", false),
            ("128.0.0.0", true),
            ("169.253.255.255", true),
            ("169.254.0.0", false),
            ("169.254.255.255", false),
            ("169.255.0.0", true),
            ("172.15.255.255", true),
            ("172.16.0.0", false),
            ("172.31.255.255", false),
            ("172.32.0.0", true),
            ("191.255.255.255", true),
            ("192.0.0.0", false),
            ("192.0.0.255", false),
            ("192.0.1.0", true),
            ("192.0.1.255", true),
            ("192.0.2.0", false),
            ("192.0.2.255", false),
            ("192.0.3.0", true),
            ("192.88.98.255", true),
            ("192.88.99.0", false),
            ("192.88.99.255", false),
            ("192.88.100.0", true),
            ("192.167.255.255", true),
            ("192.168.0.0", false),
            ("192.168.255.255", false),
            ("192.169.0.0", true),
            ("198.17.255.255", true),
            ("198.18.0.0", false),
            ("198.19.255.255", false),
            ("198.20.0.0", true),
            ("198.51.99.255", true),
            ("198.51.100.0", false),
            ("198.51.100.255", false),
            ("198.51.101.0", true),
            ("203.0.112.255", true),
            ("203.0.113.0", false),
            ("203.0.113.255", false),
            ("203.0.114.0", true),
            ("223.255.255.255", true),
            ("224.0.0.0", false),
            ("239.255.255.255", false),
            ("240.0.0.0", false),
            ("255.255.255.255", false),
            ("8.8.8.8", true),
        ] {
            assert_eq!(is_public_ip(ip.parse().unwrap()), expected, "{ip}");
        }
    }

    #[test]
    fn classifies_ipv6_ranges_and_embedded_ipv4() {
        for (ip, expected) in [
            ("::", false),
            ("::1", false),
            ("::127.0.0.1", false),
            ("::8.8.8.8", true),
            ("::ffff:127.0.0.1", false),
            ("::ffff:10.0.0.1", false),
            ("::ffff:8.8.8.8", true),
            ("64:ff9b::127.0.0.1", false),
            ("64:ff9b::192.168.1.1", false),
            ("64:ff9b::8.8.8.8", true),
            ("64:ff9b:1::808:808", false),
            ("100::1", false),
            ("100:0:0:1::1", false),
            ("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2000::", true),
            ("2001::", false),
            ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:200::", true),
            ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("2001:db8::", false),
            ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2001:db9::", true),
            ("2002::", false),
            ("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("2003::", true),
            ("3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("3fff::", false),
            ("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("3fff:1000::", true),
            ("4000::", false),
            ("fc00::", false),
            ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("fe80::", false),
            ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
            ("ff00::", false),
            ("2001:4860:4860::8888", true),
            ("2606:4700:4700::1111", true),
        ] {
            assert_eq!(is_public_ip(ip.parse().unwrap()), expected, "{ip}");
        }
    }
}

#[cfg(test)]
mod validate_url_tests {
    use super::*;

    #[test]
    fn rejects_private_ip_literals_and_non_http_schemes() {
        for url in [
            "http://127.0.0.1/",
            "http://2130706433/",
            "http://0177.0.0.1/",
            "http://0x7f000001/",
            "https://10.1.2.3/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[64:ff9b::a00:1]/",
            "file:///etc/passwd",
            "ftp://example.com/file",
        ] {
            assert_eq!(
                validate_url(&Url::parse(url).unwrap()).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied,
                "{url}"
            );
        }
    }

    #[test]
    fn accepts_public_ip_literals_and_domain_names() {
        for url in [
            "https://example.com/file",
            "http://8.8.8.8/",
            "https://[2606:4700:4700::1111]/",
        ] {
            validate_url(&Url::parse(url).unwrap()).unwrap();
        }
    }
}

#[cfg(test)]
mod checked_addresses_tests {
    use super::*;

    #[test]
    fn returns_the_exact_checked_addresses() {
        let addresses = [
            "8.8.8.8:0".parse().unwrap(),
            "[2606:4700:4700::1111]:0".parse().unwrap(),
        ];
        assert_eq!(
            checked_addresses(addresses.into_iter())
                .unwrap()
                .collect::<Vec<_>>(),
            addresses
        );
    }

    #[test]
    fn rejects_empty_private_and_mixed_dns_answers() {
        for addresses in [
            vec![],
            vec!["127.0.0.1:0"],
            vec!["8.8.8.8:0", "10.0.0.1:0"],
            vec!["[::1]:0"],
        ] {
            assert_eq!(
                checked_addresses(
                    addresses
                        .into_iter()
                        .map(|address| address.parse().unwrap())
                )
                .err()
                .unwrap()
                .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
}

#[cfg(test)]
mod public_resolver_tests {
    use super::*;

    #[tokio::test]
    async fn rejects_localhost_from_the_system_resolver() {
        assert!(PublicResolver
            .resolve("localhost".parse().unwrap())
            .await
            .is_err());
    }
}

#[cfg(test)]
mod client_builder_tests {
    use super::*;

    struct PendingResolver;

    impl Resolve for PendingResolver {
        fn resolve(&self, _: Name) -> Resolving {
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn bounds_dns_resolution_by_connect_timeout() {
        let url = "https://never-resolves.invalid/";
        let client = HttpClient::client_builder()
            .dns_resolver(Arc::new(PendingResolver))
            .build()
            .unwrap();
        let start = tokio::time::Instant::now();
        let error = client.get(url).send().await.unwrap_err();

        assert!(error.is_timeout());
        assert!(error.is_connect());
        assert_eq!(start.elapsed(), Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn bounds_the_total_request_time() {
        let url = "https://never-resolves.invalid/";
        let client = HttpClient::client_builder()
            .dns_resolver(Arc::new(PendingResolver))
            .connect_timeout(Duration::from_secs(600))
            .read_timeout(Duration::from_secs(600))
            .build()
            .unwrap();
        let start = tokio::time::Instant::now();
        let error = client.get(url).send().await.unwrap_err();

        assert!(error.is_timeout());
        assert_eq!(start.elapsed(), Duration::from_secs(300));
    }
}

#[cfg(all(test, unix))]
mod fetch_and_write_tests {
    use super::*;
    use crate::chain::common::ContractTokenId;
    use std::os::unix::fs::MetadataExt;
    use tempfile::TempDir;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    const PNG_1X1: &[u8] = &[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0xDA, 0x63, 0x64,
        0x60, 0xF8, 0x5F, 0x0F, 0x00, 0x02, 0x87, 0x01, 0x80, 0xEB, 0x47, 0xBA, 0x92, 0x00, 0x00,
        0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ];

    fn token() -> ContractTokenId {
        ContractTokenId {
            address: "0xabc".to_string(),
            token_id: "1".to_string(),
            chain_name: "ethereum".to_string(),
        }
    }

    fn image_options() -> Options {
        Options {
            overriden_filename: None,
            fallback_filename: Some("image".to_string()),
        }
    }

    #[tokio::test]
    async fn hard_links_download_identical_to_existing_file_under_another_name() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/thumbnails/1667336455"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(PNG_1X1))
            .mount(&server)
            .await;
        let out = TempDir::new().unwrap();
        let token_dir = out.path().join("ethereum").join("0xabc").join("1");
        tokio::fs::create_dir_all(&token_dir).await.unwrap();
        let existing = token_dir.join("old-name.png");
        tokio::fs::write(&existing, PNG_1X1).await.unwrap();

        // Named after the URL's last segment, so it does not collide with old-name.png.
        let url = format!("{}/thumbnails/1667336455", server.uri());
        let saved = HttpClient::new()
            .fetch_and_write(&url, &token(), out.path(), image_options())
            .await
            .unwrap();

        assert_ne!(saved, existing);
        let saved_meta = tokio::fs::metadata(&saved).await.unwrap();
        let existing_meta = tokio::fs::metadata(&existing).await.unwrap();
        assert_eq!(
            saved_meta.ino(),
            existing_meta.ino(),
            "expected a hard link"
        );
        assert_eq!(tokio::fs::read(&saved).await.unwrap(), PNG_1X1);
    }

    #[tokio::test]
    async fn keeps_download_when_no_identical_file_exists() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/thumbnails/1667336455"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(PNG_1X1))
            .mount(&server)
            .await;
        let out = TempDir::new().unwrap();
        let token_dir = out.path().join("ethereum").join("0xabc").join("1");
        tokio::fs::create_dir_all(&token_dir).await.unwrap();
        tokio::fs::write(token_dir.join("other.png"), b"different")
            .await
            .unwrap();

        let url = format!("{}/thumbnails/1667336455", server.uri());
        let saved = HttpClient::new()
            .fetch_and_write(&url, &token(), out.path(), image_options())
            .await
            .unwrap();

        assert_eq!(tokio::fs::metadata(&saved).await.unwrap().nlink(), 1);
        assert_eq!(tokio::fs::read(&saved).await.unwrap(), PNG_1X1);
    }
}

#[cfg(test)]
mod fetch_tests {
    use super::*;
    use crate::ipfs::config::IpfsGatewayType;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn rejects_oversized_buffered_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0; 16 * 1024 * 1024 + 1]))
            .mount(&server)
            .await;

        assert!(HttpClient::new()
            .with_max_retries(0)
            .fetch(&server.uri())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_fetch_data_url() {
        let client = HttpClient::new();
        let data_url = "data:text/plain;base64,SGVsbG8gV29ybGQ="; // "Hello World" in base64

        let result = client.fetch(data_url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"Hello World");
    }

    #[tokio::test]
    async fn test_fetch_data_url_invalid() {
        let client = HttpClient::new();
        let invalid_data_url = "data:invalid";

        let result = client.fetch(invalid_data_url).await;
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("Failed to parse data URL"));
    }

    #[tokio::test]
    async fn test_fetch_http_url_success() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/test", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200).set_body_string("HTTP Success"))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new();
        let result = client.fetch(&url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"HTTP Success");
    }

    #[tokio::test]
    async fn test_fetch_ipfs_url_success() {
        let mock_server = MockServer::start().await;
        let cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        let ipfs_url = format!("{}/ipfs/{}", mock_server.uri(), cid);

        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", cid)))
            .respond_with(ResponseTemplate::new(200).set_body_string("IPFS Content"))
            .mount(&mock_server)
            .await;

        let client =
            HttpClient::new().with_gateways(vec![(mock_server.uri(), IpfsGatewayType::Path)]);
        let result = client.fetch(&ipfs_url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"IPFS Content");
    }

    #[tokio::test]
    async fn test_fetch_http_url_404() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/not-found", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/not-found"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new();
        let result = client.fetch(&url).await;
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("HTTP error: status 404"));
    }

    #[tokio::test]
    async fn test_fetch_http_url_500_with_retries() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/server-error", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/server-error"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Server Error"))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new().with_max_retries(2);
        let result = client.fetch(&url).await;
        assert!(result.is_err());
        let err = result.err().unwrap().to_string();
        assert!(err.contains("HTTP error: status 500"));
    }

    #[tokio::test]
    async fn test_fetch_network_error() {
        // Use a URL that will cause a connection error quickly
        // Port 1 is typically not in use and will fail fast
        let invalid_url = "http://127.0.0.1:1/invalid";
        let client = HttpClient::new().with_max_retries(0); // No retries to make it faster

        let result = client.fetch(invalid_url).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_fetch_with_custom_retries() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/test", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/test"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Success"))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new().with_max_retries(3);
        let result = client.fetch(&url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"Success");
    }

    #[tokio::test]
    async fn test_fetch_with_custom_gateways() {
        let mock_server = MockServer::start().await;
        let cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        let ipfs_url = format!("{}/ipfs/{}", mock_server.uri(), cid);

        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", cid)))
            .respond_with(ResponseTemplate::new(200).set_body_string("Custom Gateway"))
            .mount(&mock_server)
            .await;

        let client =
            HttpClient::new().with_gateways(vec![(mock_server.uri(), IpfsGatewayType::Path)]);
        let result = client.fetch(&ipfs_url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"Custom Gateway");
    }

    #[tokio::test]
    async fn test_fetch_large_response() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/large", mock_server.uri());
        let large_content = "x".repeat(1024 * 1024); // 1MB

        Mock::given(method("GET"))
            .and(path("/large"))
            .respond_with(ResponseTemplate::new(200).set_body_string(large_content.clone()))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new();
        let result = client.fetch(&url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content.len(), 1024 * 1024);
        assert_eq!(content, large_content.as_bytes());
    }

    #[tokio::test]
    async fn test_fetch_binary_content() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/binary", mock_server.uri());
        let binary_content = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]; // PNG header

        Mock::given(method("GET"))
            .and(path("/binary"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(binary_content.clone()))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new();
        let result = client.fetch(&url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, binary_content);
    }

    #[tokio::test]
    async fn test_httpclient_default_implementation() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/default-test", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/default-test"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string("Default Implementation Works"),
            )
            .mount(&mock_server)
            .await;

        // Test that Default::default() creates a working HttpClient
        let client = HttpClient::default();
        let result = client.fetch(&url).await;
        assert!(result.is_ok());
        let content = result.unwrap();
        assert_eq!(content, b"Default Implementation Works");

        // Verify that default has the expected configuration
        assert_eq!(client.max_retries, DEFAULT_MAX_CONTENT_REQUEST_RETRIES);
        assert!(!client.ipfs_gateways.is_empty()); // Should have default IPFS gateways
    }
}

#[cfg(test)]
mod head_content_length_tests {
    use super::*;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn calculates_size_for_data_url() {
        let client = HttpClient::new();
        let data_url = "data:text/plain;base64,SGVsbG8="; // "Hello"
        let size = client.head_content_length(data_url).await.unwrap();
        assert_eq!(size, 5);
    }

    #[tokio::test]
    async fn calculates_size_for_http_resource() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/asset", mock_server.uri());

        Mock::given(method("HEAD"))
            .and(path("/asset"))
            .respond_with(ResponseTemplate::new(200).insert_header("Content-Length", "1024"))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new();
        let size = client.head_content_length(&url).await.unwrap();
        assert_eq!(size, 1024);
    }

    #[tokio::test]
    async fn falls_back_to_get_when_head_forbidden() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/blocked-head", mock_server.uri());

        Mock::given(method("HEAD"))
            .and(path("/blocked-head"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock_server)
            .await;

        Mock::given(method("GET"))
            .and(path("/blocked-head"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 2048]))
            .mount(&mock_server)
            .await;

        let client = HttpClient::new();
        let size = client.head_content_length(&url).await.unwrap();
        assert_eq!(size, 2048);
    }
}
