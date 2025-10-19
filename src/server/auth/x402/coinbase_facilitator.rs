use std::future::Future;

use axum::http::{HeaderMap, HeaderValue};
use x402_axum::facilitator_client::FacilitatorClient;
use x402_rs::facilitator::Facilitator;
use x402_rs::types::{
    SettleRequest, SettleResponse, SupportedPaymentKindsResponse, VerifyRequest, VerifyResponse,
};

use super::error_handling::{
    handle_result, tolerant_parse_supported, tolerant_recover_payment_required,
    tolerant_recover_verify,
};
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
        let client =
            FacilitatorClient::try_from(facilitator_url).expect("valid facilitator base url");
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
                || {
                    reqwest::Client::new()
                        .post(this.base_client.verify_url().clone())
                        .json(&req)
                },
                tolerant_recover_verify,
                client.verify(&req).await,
            )
            .await
        }
    }

    fn settle(
        &self,
        request: &SettleRequest,
    ) -> impl Future<Output = Result<SettleResponse, Self::Error>> + Send {
        let this = self.clone();
        let req = request.clone();
        async move {
            let settle_path = this.base_client.settle_url().path();
            let client = this.client_with_route_auth("POST", settle_path);
            handle_result(
                &client,
                "POST /settle",
                || {
                    reqwest::Client::new()
                        .post(this.base_client.settle_url().clone())
                        .json(&req)
                },
                |body| tolerant_recover_payment_required::<SettleResponse>("POST /settle", body),
                client.settle(&req).await,
            )
            .await
        }
    }

    fn supported(
        &self,
    ) -> impl Future<Output = Result<SupportedPaymentKindsResponse, Self::Error>> + Send {
        let this = self.clone();
        async move {
            let supported_path = this.base_client.supported_url().path();
            let client = this.client_with_route_auth("GET", supported_path);
            handle_result(
                &client,
                "GET /supported",
                || reqwest::Client::new().get(this.base_client.supported_url().clone()),
                |body| tolerant_parse_supported(body).map(Ok),
                client.supported().await,
            )
            .await
        }
    }
}

#[cfg(test)]
mod dynamic_facilitator_tests {
    use super::*;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use x402_rs::network::Network;
    use x402_rs::types::{
        ExactPaymentPayload, ExactSolanaPayload, FacilitatorErrorReason, MixedAddress,
        PaymentPayload, PaymentRequirements, Scheme, X402Version,
    };

    fn make_facilitator(base: &str) -> CoinbaseFacilitator {
        CoinbaseFacilitator::new_with_url(base, None, None)
    }

    #[tokio::test]
    async fn supported_tolerant_parsing_works_with_empty_extra() {
        let server = MockServer::start().await;
        let body = r#"{"kinds":[{"extra":{},"network":"base-sepolia","scheme":"exact","x402Version":1},{"extra":{},"network":"base","scheme":"exact","x402Version":1},{"extra":{"feePayer":"L54zkaPQFeTn1UsEqieEXBqWrPShiaZEPD7mS5WXfQg"},"network":"solana-devnet","scheme":"exact","x402Version":1},{"extra":{"feePayer":"L54zkaPQFeTn1UsEqieEXBqWrPShiaZEPD7mS5WXfQg"},"network":"solana","scheme":"exact","x402Version":1}]}"#;
        Mock::given(method("GET"))
            .and(path("/supported"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(body)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let facilitator = make_facilitator(&server.uri());
        let resp = facilitator.supported().await.expect("supported OK");
        assert!(!resp.kinds.is_empty());
        assert!(resp.kinds.iter().any(|k| k.network == Network::Base));
    }

    #[tokio::test]
    async fn verify_tolerant_recovery_maps_invalid_reason_and_empty_payer() {
        let server = MockServer::start().await;
        let body = r#"{"invalidReason":"insufficient_funds","isValid":false,"payer":""}"#;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(body)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let facilitator = make_facilitator(&server.uri());

        // Build a minimal, syntactically valid VerifyRequest (fields aren't used by mock)
        let payment_payload = PaymentPayload {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: Network::Base,
            payload: ExactPaymentPayload::Solana(ExactSolanaPayload {
                transaction: "deadbeef".to_string(),
            }),
        };
        let payment_requirements = PaymentRequirements {
            scheme: Scheme::Exact,
            network: Network::Base,
            max_amount_required: 100_000u64.into(),
            resource: Url::parse("https://example.com").unwrap(),
            description: "test".into(),
            mime_type: "application/json".into(),
            output_schema: None,
            pay_to: serde_json::from_str::<MixedAddress>(
                "\"0x0000000000000000000000000000000000000000\"",
            )
            .unwrap(),
            max_timeout_seconds: 300,
            asset: serde_json::from_str::<MixedAddress>(
                "\"0x0000000000000000000000000000000000000000\"",
            )
            .unwrap(),
            extra: None,
        };
        let req = VerifyRequest {
            x402_version: X402Version::V1,
            payment_payload,
            payment_requirements,
        };

        let resp = facilitator.verify(&req).await.expect("verify OK");
        match resp {
            VerifyResponse::Invalid { reason, payer } => {
                assert!(matches!(reason, FacilitatorErrorReason::InsufficientFunds));
                assert!(payer.is_none());
            }
            _ => panic!("expected invalid verify response"),
        }
    }

    #[tokio::test]
    async fn supported_happy_path_no_fallback() {
        let server = MockServer::start().await;
        let body = r#"{"kinds":[{"network":"base","scheme":"exact","x402Version":1},{"network":"base-sepolia","scheme":"exact","x402Version":1},{"network":"solana","scheme":"exact","x402Version":1,"extra":{"feePayer":"L54zkaPQFeTn1UsEqieEXBqWrPShiaZEPD7mS5WXfQg"}}]}"#;
        Mock::given(method("GET"))
            .and(path("/supported"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(body)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let facilitator = make_facilitator(&server.uri());
        let resp = facilitator.supported().await.expect("supported OK");
        assert!(resp.kinds.iter().any(|k| k.network == Network::Base));
        assert!(resp.kinds.iter().any(|k| k.network == Network::Solana));
    }

    #[tokio::test]
    async fn verify_happy_path_valid_no_fallback() {
        let server = MockServer::start().await;
        let body = r#"{"isValid":true,"payer":"0x0000000000000000000000000000000000000001"}"#;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(body)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let facilitator = make_facilitator(&server.uri());

        let payment_payload = PaymentPayload {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: Network::Base,
            payload: ExactPaymentPayload::Solana(ExactSolanaPayload {
                transaction: "deadbeef".into(),
            }),
        };
        let payment_requirements = PaymentRequirements {
            scheme: Scheme::Exact,
            network: Network::Base,
            max_amount_required: 1u64.into(),
            resource: Url::parse("https://example.com").unwrap(),
            description: "test".into(),
            mime_type: "application/json".into(),
            output_schema: None,
            pay_to: serde_json::from_str::<MixedAddress>(
                "\"0x0000000000000000000000000000000000000000\"",
            )
            .unwrap(),
            max_timeout_seconds: 60,
            asset: serde_json::from_str::<MixedAddress>(
                "\"0x0000000000000000000000000000000000000000\"",
            )
            .unwrap(),
            extra: None,
        };
        let req = VerifyRequest {
            x402_version: X402Version::V1,
            payment_payload,
            payment_requirements,
        };

        let resp = facilitator.verify(&req).await.expect("verify OK");
        match resp {
            VerifyResponse::Valid { payer } => match payer {
                MixedAddress::Evm(_) => {}
                _ => panic!("expected EVM payer"),
            },
            _ => panic!("expected valid verify response"),
        }
    }

    #[tokio::test]
    async fn settle_happy_path_success_no_fallback() {
        let server = MockServer::start().await;
        // success true, with EVM tx hash and payer
        let body = r#"{"success":true,"payer":"0x0000000000000000000000000000000000000001","transaction":"0x1111111111111111111111111111111111111111111111111111111111111111","network":"base"}"#;
        Mock::given(method("POST"))
            .and(path("/settle"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(body)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        let facilitator = make_facilitator(&server.uri());

        let payment_payload = PaymentPayload {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: Network::Base,
            payload: ExactPaymentPayload::Solana(ExactSolanaPayload {
                transaction: "deadbeef".into(),
            }),
        };
        let payment_requirements = PaymentRequirements {
            scheme: Scheme::Exact,
            network: Network::Base,
            max_amount_required: 1u64.into(),
            resource: Url::parse("https://example.com").unwrap(),
            description: "test".into(),
            mime_type: "application/json".into(),
            output_schema: None,
            pay_to: serde_json::from_str::<MixedAddress>(
                "\"0x0000000000000000000000000000000000000000\"",
            )
            .unwrap(),
            max_timeout_seconds: 60,
            asset: serde_json::from_str::<MixedAddress>(
                "\"0x0000000000000000000000000000000000000000\"",
            )
            .unwrap(),
            extra: None,
        };
        let req = VerifyRequest {
            x402_version: X402Version::V1,
            payment_payload,
            payment_requirements,
        };

        let resp = facilitator.settle(&req).await.expect("settle OK");
        assert!(resp.success);
        assert!(matches!(resp.network, Network::Base));
    }
}
