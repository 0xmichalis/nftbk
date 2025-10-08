use tracing::{info, warn};

use crate::url::{all_ipfs_gateway_urls_with_gateways, IpfsGatewayConfig};

pub(crate) async fn fetch_url(url: &str) -> anyhow::Result<reqwest::Response> {
    let client = reqwest::Client::builder()
        .user_agent(crate::USER_AGENT)
        .build()?;

    Ok(client.get(url).send().await?)
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
    match fetch_url(url).await {
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

pub(crate) async fn retry_with_gateways(
    url: &str,
    original_error: anyhow::Error,
    gateways: &[IpfsGatewayConfig],
) -> anyhow::Result<reqwest::Response> {
    warn!(
        "IPFS gateway error for {}, retrying with other gateways: {}",
        url, original_error
    );

    let gateway_urls = match all_ipfs_gateway_urls_with_gateways(url, gateways) {
        Some(urls) => urls,
        None => return Err(original_error),
    };

    let mut last_err = original_error;
    let alternative_gateways: Vec<_> = gateway_urls
        .into_iter()
        .filter(|gateway_url| gateway_url != url)
        .collect();

    for new_url in alternative_gateways {
        match fetch_url(&new_url).await {
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

#[cfg(test)]
mod try_fetch_response_tests {
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_http_200_success() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/success", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/success"))
            .respond_with(ResponseTemplate::new(200).set_body_string("Hello, World!"))
            .mount(&mock_server)
            .await;

        let (res, _status) = super::try_fetch_response(&url, crate::url::IPFS_GATEWAYS).await;
        assert!(res.is_ok());
        let body = res.unwrap().bytes().await.unwrap();
        assert_eq!(body.as_ref(), b"Hello, World!");
    }

    #[tokio::test]
    async fn test_http_404_no_retry() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/not-found", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/not-found"))
            .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (res, _status) = super::try_fetch_response(&url, crate::url::IPFS_GATEWAYS).await;
        assert!(res.is_err());
        let err = res.err().unwrap().to_string();
        assert!(err.contains("HTTP error: status 404"));
    }

    #[tokio::test]
    async fn test_http_500_retry_and_fail() {
        let mock_server = MockServer::start().await;
        let url = format!("{}/server-error", mock_server.uri());

        Mock::given(method("GET"))
            .and(path("/server-error"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .expect(1)
            .mount(&mock_server)
            .await;

        let (res, _status) = super::try_fetch_response(&url, crate::url::IPFS_GATEWAYS).await;
        assert!(res.is_err());
        let err = res.err().unwrap().to_string();
        assert!(err.contains("HTTP error: status 500"));
    }
}
