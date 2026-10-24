use std::future::Future;

use axum::http::{HeaderMap, HeaderValue};
use x402_axum::facilitator_client::FacilitatorClient;
use x402_types::facilitator::Facilitator;
use x402_types::proto::{
    SettleRequest, SettleResponse, SupportedResponse, VerifyRequest, VerifyResponse,
};

use super::error_handling::{handle_result, tolerant_parse_supported, tolerant_recover_verify};
use crate::server::auth::jwt::generate_cdp_jwt;

#[derive(Clone, Debug)]
pub struct CoinbaseFacilitator {
    base_client: FacilitatorClient,
    api_key_id: Option<String>,
    api_key_secret: Option<String>,
}

impl CoinbaseFacilitator {
    pub fn new_with_url(
        facilitator_url: &str,
        api_key_id_env: Option<&str>,
        api_key_secret_env: Option<&str>,
    ) -> Self {
        let client = FacilitatorClient::try_from(facilitator_url)
            .expect("valid facilitator base url")
            .with_timeout(std::time::Duration::from_secs(15));
        let api_key_id = api_key_id_env.and_then(|k| std::env::var(k).ok());
        let api_key_secret = api_key_secret_env.and_then(|k| std::env::var(k).ok());
        Self {
            base_client: client,
            api_key_id,
            api_key_secret,
        }
    }

    fn client_with_route_auth(&self, method: &str, url_path: &str) -> FacilitatorClient {
        let Some(api_key_id) = self.api_key_id.as_ref() else {
            return self.base_client.clone();
        };
        let Some(api_key_secret) = self.api_key_secret.as_ref() else {
            return self.base_client.clone();
        };
        let host = self.base_client.base_url().host_str().unwrap_or("");
        // TODO: Instead of generating a token per request, cache with a TTL
        let token = generate_cdp_jwt(api_key_id, api_key_secret, method, host, url_path, None)
            .unwrap_or_default();
        let mut headers = HeaderMap::new();
        if !token.is_empty() {
            if let Ok(value) = HeaderValue::from_str(&format!("Bearer {token}")) {
                headers.insert("authorization", value);
            }
        }
        self.base_client.clone().with_headers(headers)
    }
}

impl Facilitator for CoinbaseFacilitator {
    type Error = x402_axum::facilitator_client::FacilitatorClientError;

    fn verify(
        &self,
        request: &VerifyRequest,
    ) -> impl Future<Output = Result<VerifyResponse, Self::Error>> + Send {
        let this = self.clone();
        let req = request.clone();
        async move {
            let verify_path = this.base_client.verify_url().path();
            let client = this.client_with_route_auth("POST", verify_path);
            handle_result(
                &client,
                "POST /verify",
                {
                    let base_client = this.base_client.clone();
                    let req = req.clone();
                    move || {
                        reqwest::Client::new()
                            .post(base_client.verify_url().clone())
                            .json(&req)
                    }
                },
                tolerant_recover_verify,
                client.verify(&req).await,
                3, // Default max retries
            )
            .await
        }
    }

    fn settle(
        &self,
        request: &SettleRequest,
    ) -> impl Future<Output = Result<SettleResponse, Self::Error>> + Send {
        let client = self.client_with_route_auth("POST", self.base_client.settle_url().path());
        let request = request.clone();
        // Settlement retries cannot distinguish a lost response from an executed transfer.
        async move { client.settle(&request).await }
    }

    fn supported(&self) -> impl Future<Output = Result<SupportedResponse, Self::Error>> + Send {
        let this = self.clone();
        async move {
            let supported_path = this.base_client.supported_url().path();
            let client = this.client_with_route_auth("GET", supported_path);
            handle_result(
                &client,
                "GET /supported",
                {
                    let base_client = this.base_client.clone();
                    move || reqwest::Client::new().get(base_client.supported_url().clone())
                },
                |body| tolerant_parse_supported(body).map(Ok),
                client.supported().await,
                3, // Default max retries
            )
            .await
        }
    }
}

#[cfg(test)]
mod verify_tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn accepts_unknown_rejection_reasons_and_empty_payers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"isValid":false,"invalidReason":"new_facilitator_reason","payer":""}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let facilitator = CoinbaseFacilitator::new_with_url(&server.uri(), None, None);
        let response = facilitator
            .verify(&VerifyRequest::from(json!({"x402Version":1})))
            .await
            .unwrap();
        assert_eq!(response.0["isValid"], false);
        assert_eq!(response.0["invalidReason"], "new_facilitator_reason");
    }
}
