use reqwest::{header::CONTENT_LENGTH, Method};
use tracing::{info, warn};

use crate::ipfs::config::IpfsGatewayConfig;
use crate::ipfs::url::{generate_url_for_gateways, GatewayUrl};

async fn send_request(
    method: Method,
    url: &str,
    bearer_token: Option<String>,
) -> anyhow::Result<reqwest::Response> {
    let client = reqwest::Client::builder()
        .user_agent(crate::USER_AGENT)
        .build()?;

    let mut req = client.request(method, url);
    if let Some(token) = bearer_token {
        req = req.bearer_auth(token);
    }

    Ok(req.send().await?)
}

pub(crate) async fn fetch_url(
    url: &str,
    bearer_token: Option<String>,
) -> anyhow::Result<reqwest::Response> {
    send_request(Method::GET, url, bearer_token).await
}

pub(crate) async fn head_url(
    url: &str,
    bearer_token: Option<String>,
) -> anyhow::Result<reqwest::Response> {
    send_request(Method::HEAD, url, bearer_token).await
}

pub(crate) fn create_http_error(status: reqwest::StatusCode, url: &str) -> anyhow::Error {
    anyhow::anyhow!("HTTP error: status {status} from {url}")
}

pub(crate) async fn try_fetch_response(
    url: &str,
    gateways: &[IpfsGatewayConfig],
) -> (
    anyhow::Result<reqwest::Response>,
    Option<reqwest::StatusCode>,
) {
    match fetch_url(url, None).await {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                (Ok(response), Some(status))
            } else {
                let error = create_http_error(status, url);
                match retry_with_gateways(url, error, gateways).await {
                    Ok(alt_response) => {
                        let alt_status = alt_response.status();
                        if alt_status.is_success() {
                            (Ok(alt_response), Some(alt_status))
                        } else {
                            (
                                Err(create_http_error(alt_status, alt_response.url().as_str())),
                                Some(alt_status),
                            )
                        }
                    }
                    Err(gateway_err) => (Err(gateway_err), Some(status)),
                }
            }
        }
        Err(e) => match retry_with_gateways(url, e, gateways).await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    (Ok(response), Some(status))
                } else {
                    (Err(create_http_error(status, url)), Some(status))
                }
            }
            Err(gateway_err) => (Err(gateway_err), None),
        },
    }
}

/// Retry a failed HTTP request against configured IPFS gateways using the
/// provided HTTP method so both GET and HEAD flows can share the same logic.
/// The original error is logged for context and returned if no gateway
/// succeeds.
async fn retry_with_gateways_with_method(
    url: &str,
    original_error: anyhow::Error,
    gateways: &[IpfsGatewayConfig],
    method: Method,
) -> anyhow::Result<reqwest::Response> {
    let gateway_urls = match generate_url_for_gateways(url, gateways) {
        Some(urls) => {
            warn!(
                "IPFS gateway error for {}, retrying with other gateways: {}",
                url, original_error
            );
            urls
        }
        None => return Err(original_error),
    };

    let mut last_err = original_error;
    let alternative_gateways: Vec<_> = gateway_urls
        .into_iter()
        .filter(|gateway_url| gateway_url.url != url)
        .collect();

    for GatewayUrl {
        url: new_url,
        bearer_token,
    } in alternative_gateways
    {
        match send_request(method.clone(), &new_url, bearer_token).await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    info!(
                        "Received successful response from alternative IPFS gateway: {} (status: {})",
                        new_url, status
                    );
                    return Ok(response);
                } else {
                    warn!("Alternative IPFS gateway {new_url} failed: {status}");
                    last_err = anyhow::anyhow!("{status}");
                }
            }
            Err(err) => {
                warn!("Failed to fetch from IPFS gateway {}: {}", new_url, err);
                last_err = err;
            }
        }
    }

    Err(last_err)
}

pub(crate) async fn retry_with_gateways(
    url: &str,
    original_error: anyhow::Error,
    gateways: &[IpfsGatewayConfig],
) -> anyhow::Result<reqwest::Response> {
    retry_with_gateways_with_method(url, original_error, gateways, Method::GET).await
}

async fn try_get_content_length(
    url: &str,
    gateways: &[IpfsGatewayConfig],
) -> (anyhow::Result<u64>, Option<reqwest::StatusCode>) {
    info!(
        "HEAD denied for {}; falling back to GET for size estimation",
        url
    );
    match fetch_url(url, None).await {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                if let Some(len) = extract_content_length(&response) {
                    (Ok(len), Some(status))
                } else {
                    (
                        Err(anyhow::anyhow!(
                            "GET response missing Content-Length for {}",
                            url
                        )),
                        Some(status),
                    )
                }
            } else {
                let error = create_http_error(status, url);
                match retry_with_gateways_with_method(url, error, gateways, Method::GET).await {
                    Ok(alt_response) => {
                        let alt_status = alt_response.status();
                        if alt_status.is_success() {
                            if let Some(len) = extract_content_length(&alt_response) {
                                (Ok(len), Some(alt_status))
                            } else {
                                (
                                    Err(anyhow::anyhow!(
                                        "GET response missing Content-Length for {}",
                                        alt_response.url()
                                    )),
                                    Some(alt_status),
                                )
                            }
                        } else {
                            (
                                Err(create_http_error(alt_status, alt_response.url().as_str())),
                                Some(alt_status),
                            )
                        }
                    }
                    Err(gateway_err) => (Err(gateway_err), Some(status)),
                }
            }
        }
        Err(e) => match retry_with_gateways_with_method(url, e, gateways, Method::GET).await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    if let Some(len) = extract_content_length(&response) {
                        (Ok(len), Some(status))
                    } else {
                        (
                            Err(anyhow::anyhow!(
                                "GET response missing Content-Length for {}",
                                response.url()
                            )),
                            Some(status),
                        )
                    }
                } else {
                    (Err(create_http_error(status, url)), Some(status))
                }
            }
            Err(gateway_err) => (Err(gateway_err), None),
        },
    }
}

fn extract_content_length(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| response.content_length())
}

/// Attempt to read the `Content-Length` of `url` using HEAD requests, falling
/// back to alternate IPFS gateways when available. Returns the parsed byte size
/// and the HTTP status code (if any) encountered while probing.
pub(crate) async fn try_head_content_length(
    url: &str,
    gateways: &[IpfsGatewayConfig],
) -> (anyhow::Result<u64>, Option<reqwest::StatusCode>) {
    match head_url(url, None).await {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                if let Some(len) = extract_content_length(&response) {
                    (Ok(len), Some(status))
                } else {
                    (
                        Err(anyhow::anyhow!(
                            "HEAD response missing Content-Length for {}",
                            url
                        )),
                        Some(status),
                    )
                }
            } else if status == reqwest::StatusCode::FORBIDDEN {
                return try_get_content_length(url, gateways).await;
            } else {
                let error = create_http_error(status, url);
                match retry_with_gateways_with_method(url, error, gateways, Method::HEAD).await {
                    Ok(alt_response) => {
                        let alt_status = alt_response.status();
                        if alt_status.is_success() {
                            if let Some(len) = extract_content_length(&alt_response) {
                                (Ok(len), Some(alt_status))
                            } else {
                                (
                                    Err(anyhow::anyhow!(
                                        "HEAD response missing Content-Length for {}",
                                        alt_response.url()
                                    )),
                                    Some(alt_status),
                                )
                            }
                        } else if alt_status == reqwest::StatusCode::FORBIDDEN {
                            let fallback_url = alt_response.url().to_string();
                            return try_get_content_length(&fallback_url, gateways).await;
                        } else {
                            (
                                Err(create_http_error(alt_status, alt_response.url().as_str())),
                                Some(alt_status),
                            )
                        }
                    }
                    Err(gateway_err) => (Err(gateway_err), Some(status)),
                }
            }
        }
        Err(e) => match retry_with_gateways_with_method(url, e, gateways, Method::HEAD).await {
            Ok(response) => {
                let status = response.status();
                if status.is_success() {
                    if let Some(len) = extract_content_length(&response) {
                        (Ok(len), Some(status))
                    } else {
                        (
                            Err(anyhow::anyhow!(
                                "HEAD response missing Content-Length for {}",
                                response.url()
                            )),
                            Some(status),
                        )
                    }
                } else if status == reqwest::StatusCode::FORBIDDEN {
                    let fallback_url = response.url().to_string();
                    return try_get_content_length(&fallback_url, gateways).await;
                } else {
                    (Err(create_http_error(status, url)), Some(status))
                }
            }
            Err(gateway_err) => (Err(gateway_err), None),
        },
    }
}

#[cfg(test)]
mod try_get_content_length_tests {
    use crate::ipfs::config::{IpfsGatewayConfig, IpfsGatewayType};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn leak_str(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    fn gw(base: &str) -> IpfsGatewayConfig {
        IpfsGatewayConfig {
            url: leak_str(base.to_string()),
            gateway_type: IpfsGatewayType::Path,
            bearer_token_env: None,
        }
    }

    #[tokio::test]
    async fn returns_length_from_successful_get() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/asset.png", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/asset.png"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 1234]))
            .mount(&mock_server)
            .await;

        let (res, status) = super::try_get_content_length(&url, &[]).await;
        assert_eq!(status, Some(reqwest::StatusCode::OK));
        assert_eq!(res.unwrap(), 1234);
    }

    #[tokio::test]
    async fn retries_with_gateways_on_error() {
        let server_a = MockServer::start().await;
        let server_b = MockServer::start().await;
        let content_path = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/file";
        let original_url = format!("{}/ipfs/{}", server_a.uri(), content_path);

        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", content_path)))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server_a)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", content_path)))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 4096]))
            .mount(&server_b)
            .await;

        let gateways = vec![gw(&server_a.uri()), gw(&server_b.uri())];

        let (res, status) = super::try_get_content_length(&original_url, &gateways).await;
        assert_eq!(status, Some(reqwest::StatusCode::OK));
        assert_eq!(res.unwrap(), 4096);
    }
}

#[cfg(test)]
mod try_fetch_response_tests {
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::ipfs::config::{IpfsGatewayConfig, IpfsGatewayType};

    fn leak_str(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    fn gw(base: &str) -> IpfsGatewayConfig {
        IpfsGatewayConfig {
            url: leak_str(base.to_string()),
            gateway_type: IpfsGatewayType::Path,
            bearer_token_env: None,
        }
    }

    #[tokio::test]
    async fn test_http_200_success() {
        let mock_server = MockServer::start().await;
        let cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        let url = format!("{}/ipfs/{}", mock_server.uri(), cid);

        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", cid)))
            .respond_with(ResponseTemplate::new(200).set_body_string("Hello, World!"))
            .mount(&mock_server)
            .await;

        let (res, status) = super::try_fetch_response(&url, &[]).await;
        assert!(status.is_some());
        assert_eq!(status.unwrap(), reqwest::StatusCode::OK);
        assert!(res.is_ok());
        let body = res.unwrap().bytes().await.unwrap();
        assert_eq!(body.as_ref(), b"Hello, World!");
    }

    #[tokio::test]
    async fn test_http_404_no_retry() {
        let mock_server = MockServer::start().await;
        let cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        let url = format!("{}/ipfs/{}", mock_server.uri(), cid);

        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", cid)))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (res, status) = super::try_fetch_response(&url, &[]).await;
        assert!(status.is_some());
        assert_eq!(status.unwrap(), reqwest::StatusCode::NOT_FOUND);
        assert!(res.is_err());
        let err = res.err().unwrap().to_string();
        assert!(err.contains("HTTP error: status 404"));
    }

    #[tokio::test]
    async fn test_http_500_retry_and_fail() {
        let mock_server = MockServer::start().await;
        let cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        let url = format!("{}/ipfs/{}", mock_server.uri(), cid);

        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", cid)))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (res, status) = super::try_fetch_response(&url, &[]).await;
        assert!(status.is_some());
        assert_eq!(status.unwrap(), reqwest::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(res.is_err());
        let err = res.err().unwrap().to_string();
        assert!(err.contains("HTTP error: status 500"));
    }

    #[tokio::test]
    async fn test_initial_error_then_alternative_gateway_succeeds() {
        // Arrange: original gateway fails, alternative returns 200
        let server_a = MockServer::start().await;
        let server_b = MockServer::start().await;
        let cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        let content_path = format!("{}/ok", cid);
        let original_url = format!("{}/ipfs/{}", server_a.uri(), content_path);

        // A returns 500 (server error)
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", content_path)))
            .respond_with(ResponseTemplate::new(500).set_body_string("Server Error"))
            .mount(&server_a)
            .await;

        // B returns 200 for the same IPFS path
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", content_path)))
            .respond_with(ResponseTemplate::new(200).set_body_string("ALT OK"))
            .mount(&server_b)
            .await;

        // Gateways: first the failing one (A), then the working mock (B)
        let gateways = vec![gw(&server_a.uri()), gw(&server_b.uri())];

        // Act
        let (res, status) = super::try_fetch_response(&original_url, &gateways).await;

        // Assert
        assert!(res.is_ok());
        assert_eq!(status, Some(reqwest::StatusCode::OK));
        let body = res.unwrap().bytes().await.unwrap();
        assert_eq!(body.as_ref(), b"ALT OK");
    }

    #[tokio::test]
    async fn test_initial_network_error_then_alternative_gateway_succeeds() {
        // Arrange: original gateway has network error, alternative returns 200
        let server_b = MockServer::start().await;
        let dead_gateway_base = "http://127.0.0.1:9"; // simulate connect error
        let cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco";
        let content_path = format!("{}/network_test", cid);
        let original_url = format!("{}/ipfs/{}", dead_gateway_base, content_path);

        // B returns 200 for the same IPFS path
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", content_path)))
            .respond_with(ResponseTemplate::new(200).set_body_string("NETWORK RETRY OK"))
            .mount(&server_b)
            .await;

        // Gateways: first the dead one (original), then the working mock
        let gateways = vec![gw(dead_gateway_base), gw(&server_b.uri())];

        // Act
        let (res, status) = super::try_fetch_response(&original_url, &gateways).await;

        // Assert
        assert!(res.is_ok());
        assert_eq!(status, Some(reqwest::StatusCode::OK));
        let body = res.unwrap().bytes().await.unwrap();
        assert_eq!(body.as_ref(), b"NETWORK RETRY OK");
    }
}

#[cfg(test)]
mod retry_with_gateways_tests {
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use crate::ipfs::config::{IpfsGatewayConfig, IpfsGatewayType};

    // Helper to leak a String into a 'static str for IpfsGatewayConfig
    fn leak_str(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    // Build a path-based gateway config from a base URL
    fn gw(base: &str) -> IpfsGatewayConfig {
        IpfsGatewayConfig {
            url: leak_str(base.to_string()),
            gateway_type: IpfsGatewayType::Path,
            bearer_token_env: None,
        }
    }

    #[tokio::test]
    async fn first_alternative_succeeds() {
        // Arrange gateways A(original), B(success), C(not used)
        let server_a = MockServer::start().await;
        let server_b = MockServer::start().await;
        let server_c = MockServer::start().await;

        let content_path = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/ok";
        let original_url = format!("{}/ipfs/{}", server_a.uri(), content_path);

        // B returns 200
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", content_path)))
            .respond_with(ResponseTemplate::new(200).set_body_string("B OK"))
            .mount(&server_b)
            .await;

        let gateways = vec![
            gw(&server_a.uri()),
            gw(&server_b.uri()),
            gw(&server_c.uri()),
        ];

        // Act
        let res =
            super::retry_with_gateways(&original_url, anyhow::anyhow!("orig err"), &gateways).await;

        // Assert
        assert!(res.is_ok());
        let body = res.unwrap().bytes().await.unwrap();
        assert_eq!(body.as_ref(), b"B OK");
    }

    #[tokio::test]
    async fn first_alternative_http_error_second_succeeds() {
        // Arrange gateways A(original), B(500), C(200)
        let server_a = MockServer::start().await;
        let server_b = MockServer::start().await;
        let server_c = MockServer::start().await;

        let content_path = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/ok2";
        let original_url = format!("{}/ipfs/{}", server_a.uri(), content_path);

        // B returns 500
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", content_path)))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server_b)
            .await;

        // C returns 200
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", content_path)))
            .respond_with(ResponseTemplate::new(200).set_body_string("C OK"))
            .mount(&server_c)
            .await;

        let gateways = vec![
            gw(&server_a.uri()),
            gw(&server_b.uri()),
            gw(&server_c.uri()),
        ];

        // Act
        let res =
            super::retry_with_gateways(&original_url, anyhow::anyhow!("orig err"), &gateways).await;

        // Assert
        assert!(res.is_ok());
        let body = res.unwrap().bytes().await.unwrap();
        assert_eq!(body.as_ref(), b"C OK");
    }

    #[tokio::test]
    async fn first_alternative_non_http_error_second_succeeds() {
        // Arrange gateways A(original), B(non-http error), C(200)
        let server_a = MockServer::start().await;
        let server_c = MockServer::start().await;

        // Use an unroutable/closed port for B to simulate network error
        let dead_gateway_base = "http://127.0.0.1:9"; // port 9 (discard) likely closed

        let content_path = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/ok3";
        let original_url = format!("{}/ipfs/{}", server_a.uri(), content_path);

        // C returns 200
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", content_path)))
            .respond_with(ResponseTemplate::new(200).set_body_string("C OK"))
            .mount(&server_c)
            .await;

        let gateways = vec![
            gw(&server_a.uri()),
            gw(dead_gateway_base),
            gw(&server_c.uri()),
        ];

        // Act
        let res =
            super::retry_with_gateways(&original_url, anyhow::anyhow!("orig err"), &gateways).await;

        // Assert
        assert!(res.is_ok());
        let body = res.unwrap().bytes().await.unwrap();
        assert_eq!(body.as_ref(), b"C OK");
    }

    #[tokio::test]
    async fn both_alternatives_fail() {
        // Arrange gateways A(original), B(500), C(502)
        let server_a = MockServer::start().await;
        let server_b = MockServer::start().await;
        let server_c = MockServer::start().await;

        let content_path = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco/fail";
        let original_url = format!("{}/ipfs/{}", server_a.uri(), content_path);

        // B returns 500
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", content_path)))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server_b)
            .await;

        // C returns 502
        Mock::given(method("GET"))
            .and(path(format!("/ipfs/{}", content_path)))
            .respond_with(ResponseTemplate::new(502))
            .mount(&server_c)
            .await;

        let gateways = vec![
            gw(&server_a.uri()),
            gw(&server_b.uri()),
            gw(&server_c.uri()),
        ];

        // Act
        let res =
            super::retry_with_gateways(&original_url, anyhow::anyhow!("orig err"), &gateways).await;

        // Assert: error should reflect the last error (502)
        assert!(res.is_err());
        let err = res.err().unwrap().to_string();
        assert!(err.contains("502"));
    }

    #[tokio::test]
    async fn non_ipfs_url_returns_original_error_without_warning() {
        // Test that non-IPFS URLs return the original error without logging IPFS gateway warnings
        let non_ipfs_url =
            "https://mirror.xyz/10/0xceda033195af537e16d203a4d7fbfe1c5f0eb843/render";
        let original_error_msg = "HTTP error: status 429 Too Many Requests";
        let original_error = anyhow::anyhow!(original_error_msg);
        let gateways = vec![gw("https://ipfs.io")];

        // Act
        let res = super::retry_with_gateways(non_ipfs_url, original_error, &gateways).await;

        // Assert: should return the original error without trying IPFS gateways
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert_eq!(err.to_string(), original_error_msg);
    }
}

#[cfg(test)]
mod fetch_url_tests {
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_fetch_url_without_bearer_token() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/test", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/test"))
            .and(header("User-Agent", crate::USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock_server)
            .await;

        let result = super::fetch_url(&url, None).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_fetch_url_with_bearer_token() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/protected", mock_server.uri());
        let token = "test-bearer-token-123";
        let auth_header = format!("Bearer {}", token);

        Mock::given(method("GET"))
            .and(path("/protected"))
            .and(header("User-Agent", crate::USER_AGENT))
            .and(header("Authorization", auth_header.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_string("Protected OK"))
            .mount(&mock_server)
            .await;

        let result = super::fetch_url(&url, Some(token.to_string())).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_fetch_url_with_empty_bearer_token() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/test", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/test"))
            .and(header("User-Agent", crate::USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_string("OK"))
            .mount(&mock_server)
            .await;

        // Empty string should not add Authorization header
        let result = super::fetch_url(&url, Some("".to_string())).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_fetch_url_network_error() {
        // Use a non-existent URL to test network error handling
        let url = "http://127.0.0.1:9/nonexistent";

        let result = super::fetch_url(url, None).await;
        assert!(result.is_err());
    }
}
