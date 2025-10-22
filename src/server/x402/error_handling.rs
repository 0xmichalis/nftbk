use axum::http::StatusCode;
use serde_json;
use tracing::{error, warn};
use x402_axum::facilitator_client::{FacilitatorClient, FacilitatorClientError};
use x402_rs::types::{
    FacilitatorErrorReason, MixedAddress, SupportedPaymentKindsResponse, VerifyResponse,
};

use crate::httpclient::retry::{retry_operation, should_retry};

/// Adds headers from a FacilitatorClient to a reqwest RequestBuilder
async fn add_headers_from_client(
    client: &FacilitatorClient,
    req: reqwest::RequestBuilder,
) -> reqwest::RequestBuilder {
    let mut req = req;
    for (key, value) in client.headers().iter() {
        if let Ok(val_str) = value.to_str() {
            req = req.header(key.as_str(), val_str);
        }
    }
    req
}

/// Logs raw error body with truncation for large responses
async fn log_raw_error_body(method: &str, path: &str, body: &str) {
    let snippet = if body.len() > 4096 {
        &body[..4096]
    } else {
        body
    };
    error!("{} {} raw body (truncated): {}", method, path, snippet);
}

/// Execute a single HTTP request with error handling and recovery
async fn execute_http_request<T, FBuild, FRecover>(
    client: &FacilitatorClient,
    context: &'static str,
    build_req: FBuild,
    recover: FRecover,
) -> (anyhow::Result<T>, Option<reqwest::StatusCode>)
where
    T: serde::de::DeserializeOwned,
    FBuild: Fn() -> reqwest::RequestBuilder + Send + Sync + Clone + 'static,
    FRecover: Fn(&str) -> Option<Result<T, FacilitatorClientError>> + Send + Sync + Clone + 'static,
{
    let req = build_req();
    let req = add_headers_from_client(client, req).await;
    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            match resp.text().await {
                Ok(body) => {
                    // Derive method and path generically from context like "METHOD /path"
                    let mut parts = context.splitn(2, ' ');
                    let method = parts.next().unwrap_or("?");
                    let path = parts.next().unwrap_or("?");
                    log_raw_error_body(method, path, &body).await;

                    // If it's a successful response, try to parse it directly
                    if status.is_success() {
                        // For successful responses, we need to parse them directly
                        // The recovery function is for error cases only
                        match serde_json::from_str::<T>(&body) {
                            Ok(value) => return (Ok(value), Some(status)),
                            Err(e) => {
                                return (
                                    Err(anyhow::anyhow!(
                                        "Failed to parse successful response: {}",
                                        e
                                    )),
                                    Some(status),
                                )
                            }
                        }
                    }

                    // For error responses, try recovery
                    if let Some(recovered) = recover(&body) {
                        return (
                            recovered.map_err(|e| anyhow::anyhow!("{}", e)),
                            Some(status),
                        );
                    }

                    // If no recovery, check if it's a retriable error
                    if status.is_server_error() || status.as_u16() == 429 {
                        (Err(anyhow::anyhow!("Server error: {}", body)), Some(status))
                    } else {
                        (
                            Err(anyhow::anyhow!("Non-recoverable error: {}", body)),
                            Some(status),
                        )
                    }
                }
                Err(e) => (
                    Err(anyhow::anyhow!("Failed to read response body: {}", e)),
                    Some(status),
                ),
            }
        }
        Err(e) => (Err(anyhow::anyhow!("Request failed: {}", e)), None),
    }
}

/// Retry logic for server errors (5xx) and network issues
async fn retry_on_http_error<T, FBuild, FRecover>(
    client: &FacilitatorClient,
    context: &'static str,
    build_req: FBuild,
    recover: FRecover,
    max_retries: u32,
) -> Result<T, FacilitatorClientError>
where
    T: serde::de::DeserializeOwned,
    FBuild: Fn() -> reqwest::RequestBuilder + Send + Sync + Clone + 'static,
    FRecover: Fn(&str) -> Option<Result<T, FacilitatorClientError>> + Send + Sync + Clone + 'static,
{
    warn!("Request failed with server error or ratelimiting, retrying with backoff");

    // Use the retry mechanism for server errors
    let (retry_result, status_code) = retry_operation(
        {
            let client = client.clone();
            let build_req = build_req.clone();
            let recover = recover.clone();
            move || {
                let client = client.clone();
                let build_req = build_req.clone();
                let recover = recover.clone();
                Box::pin(
                    async move { execute_http_request(&client, context, build_req, recover).await },
                )
            }
        },
        max_retries,
        should_retry,
        context,
    )
    .await;

    // Convert back to FacilitatorClientError
    match retry_result {
        Ok(value) => Ok(value),
        Err(e) => {
            let status = if let Some(reqwest_status) = status_code {
                // Convert reqwest::StatusCode to axum::http::StatusCode
                StatusCode::from_u16(reqwest_status.as_u16())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };

            Err(FacilitatorClientError::HttpStatus {
                context,
                status,
                body: e.to_string(),
            })
        }
    }
}

/// Handle JSON deserialization errors by fetching raw response body and applying recovery logic
async fn handle_deserialization_error<T, FBuild, FRecover>(
    client: &FacilitatorClient,
    context: &'static str,
    build_req: FBuild,
    recover: FRecover,
) -> Option<Result<T, FacilitatorClientError>>
where
    T: serde::de::DeserializeOwned,
    FBuild: Fn() -> reqwest::RequestBuilder + Send + Sync + Clone + 'static,
    FRecover: Fn(&str) -> Option<Result<T, FacilitatorClientError>> + Send + Sync + Clone + 'static,
{
    let req = build_req();
    let req = add_headers_from_client(client, req).await;
    match req.send().await {
        Ok(resp) => match resp.text().await {
            Ok(body) => {
                // Derive method and path generically from context like "METHOD /path"
                let mut parts = context.splitn(2, ' ');
                let method = parts.next().unwrap_or("?");
                let path = parts.next().unwrap_or("?");
                log_raw_error_body(method, path, body.as_str()).await;
                recover(body.as_str())
            }
            Err(fetch_err) => {
                error!(
                    "Failed to read response body for {}: {}",
                    context, fetch_err
                );
                None
            }
        },
        Err(fetch_err) => {
            error!("Failed to fetch raw body for {}: {}", context, fetch_err);
            None
        }
    }
}

/// Generic error handling that attempts to recover from JSON deserialization errors
/// by fetching the raw response body and applying recovery logic.
/// Also includes retry logic for server errors (5xx), ratelimiting, and network issues.
pub async fn handle_result<T, FBuild, FRecover>(
    client: &FacilitatorClient,
    context: &'static str,
    build_req: FBuild,
    recover: FRecover,
    result: Result<T, FacilitatorClientError>,
    max_retries: u32,
) -> Result<T, FacilitatorClientError>
where
    T: serde::de::DeserializeOwned,
    FBuild: Fn() -> reqwest::RequestBuilder + Send + Sync + Clone + 'static,
    FRecover: Fn(&str) -> Option<Result<T, FacilitatorClientError>> + Send + Sync + Clone + 'static,
{
    match result {
        Ok(value) => Ok(value),
        Err(err) => {
            error!(error = %err, "{} failed", context);

            // Check if this is a server error (5xx) or rate limit error (429) that should be retried
            if let FacilitatorClientError::HttpStatus { status, .. } = &err {
                if status.is_server_error() || status.as_u16() == 429 {
                    return retry_on_http_error(client, context, build_req, recover, max_retries)
                        .await;
                }
            }

            // Handle JSON deserialization errors
            if let FacilitatorClientError::JsonDeserialization {
                context: err_ctx, ..
            } = &err
            {
                if *err_ctx == context {
                    if let Some(recovered) =
                        handle_deserialization_error(client, context, build_req, recover).await
                    {
                        return recovered;
                    }
                }
            }

            Err(err)
        }
    }
}

/// Tolerant parsing for GET /supported: drop empty extra objects
pub fn tolerant_parse_supported(body: &str) -> Option<SupportedPaymentKindsResponse> {
    let mut value: serde_json::Value = serde_json::from_str(body).ok()?;
    if let Some(kinds) = value.get_mut("kinds").and_then(|k| k.as_array_mut()) {
        // First, clean up empty extra objects
        for kind in kinds.iter_mut() {
            if let Some(obj) = kind.as_object_mut() {
                if let Some(extra) = obj.get("extra") {
                    if let Some(extra_obj) = extra.as_object() {
                        if extra_obj.is_empty() {
                            obj.remove("extra");
                        }
                    }
                }
            }
        }
    }
    let cleaned = serde_json::to_string(&value).ok()?;
    serde_json::from_str::<SupportedPaymentKindsResponse>(&cleaned).ok()
}

/// Tolerant recovery for verify responses that handles various error formats
pub fn tolerant_recover_verify(
    body: &str,
) -> Option<Result<VerifyResponse, FacilitatorClientError>> {
    // 1) If it's a PaymentRequired-like JSON, surface it as a 402 error
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if v.get("error").is_some() && v.get("accepts").is_some() {
            return Some(Err(FacilitatorClientError::HttpStatus {
                context: "POST /verify",
                status: StatusCode::PAYMENT_REQUIRED,
                body: body.to_string(),
            }));
        }

        // 2) If it looks like a VerifyResponse with isValid=false but bad payer, convert to structured VerifyResponse
        let is_valid = v.get("isValid").and_then(|b| b.as_bool());
        let invalid_reason = v.get("invalidReason");
        if matches!(is_valid, Some(false)) && invalid_reason.is_some() {
            // Map known reasons; fallback to free-form
            if let Some(reason_str) = invalid_reason.and_then(|r| r.as_str()) {
                let reason = match reason_str {
                    "insufficient_funds" => FacilitatorErrorReason::InsufficientFunds,
                    "invalid_scheme" => FacilitatorErrorReason::InvalidScheme,
                    "invalid_network" => FacilitatorErrorReason::InvalidNetwork,
                    "unexpected_settle_error" => FacilitatorErrorReason::UnexpectedSettleError,
                    other => FacilitatorErrorReason::FreeForm(other.to_string()),
                };
                // Payer may be invalid (e.g., empty string). Treat invalid/empty payer as None.
                let payer_opt = v.get("payer").and_then(|p| p.as_str());
                let payer = match payer_opt {
                    Some(s) if !s.is_empty() => {
                        // MixedAddress implements Deserialize from a JSON string
                        serde_json::from_str::<MixedAddress>(&format!("\"{}\"", s)).ok()
                    }
                    _ => None,
                };
                let resp = VerifyResponse::invalid(payer, reason);
                return Some(Ok(resp));
            }
        }
    }

    None
}

/// Tolerant recovery for payment required errors in settle responses
pub fn tolerant_recover_payment_required<T>(
    context: &'static str,
    body: &str,
) -> Option<Result<T, FacilitatorClientError>> {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if v.get("error").is_some() && v.get("accepts").is_some() {
            return Some(Err(FacilitatorClientError::HttpStatus {
                context,
                status: StatusCode::PAYMENT_REQUIRED,
                body: body.to_string(),
            }));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use x402_rs::network::Network;
    use x402_rs::timestamp::UnixTimestamp;
    use x402_rs::types::{
        EvmAddress, ExactEvmPayload, ExactEvmPayloadAuthorization, ExactPaymentPayload,
        PaymentPayload, PaymentRequirements, Scheme, SettleRequest, SettleResponse, TokenAmount,
        X402Version,
    };

    #[test]
    fn test_tolerant_parse_supported_with_empty_extra_objects() {
        // This is the exact JSON response that was causing the error
        let json_response = r#"{"kinds":[{"x402Version":1,"scheme":"exact","network":"base-sepolia"},{"x402Version":1,"scheme":"exact","network":"base"},{"x402Version":1,"scheme":"exact","network":"avalanche-fuji"},{"x402Version":1,"scheme":"exact","network":"avalanche"},{"x402Version":1,"scheme":"exact","network":"iotex"},{"x402Version":1,"scheme":"exact","network":"sei-testnet"},{"x402Version":1,"scheme":"exact","network":"sei"},{"x402Version":1,"scheme":"exact","network":"polygon"},{"x402Version":1,"scheme":"exact","network":"polygon-amoy"},{"x402Version":1,"scheme":"exact","network":"peaq"},{"x402Version":1,"scheme":"exact","network":"solana-devnet","extra":{"feePayer":"2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"}},{"x402Version":1,"scheme":"exact","network":"solana","extra":{"feePayer":"2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4"}}]}"#;

        // This should now successfully parse the response
        let result = tolerant_parse_supported(json_response);

        // Verify that the parsing succeeded
        assert!(
            result.is_some(),
            "tolerant_parse_supported should successfully parse the response"
        );

        let supported_response = result.unwrap();

        // Verify that we have all the kinds (no filtering since Network->String change)
        // The original response had 12 kinds, all should be preserved
        assert_eq!(supported_response.kinds.len(), 12);

        // Verify that all networks are present (including previously filtered ones)
        let networks: Vec<String> = supported_response
            .kinds
            .iter()
            .map(|k| k.network.clone())
            .collect();
        assert!(networks.contains(&"base".to_string()));
        assert!(networks.contains(&"base-sepolia".to_string()));
        assert!(networks.contains(&"solana".to_string()));
        assert!(networks.contains(&"iotex".to_string()));
        assert!(networks.contains(&"peaq".to_string()));
    }

    #[test]
    fn test_tolerant_parse_supported_with_empty_extra_removal() {
        // Test case specifically for empty extra objects that should be removed
        let json_with_empty_extra = r#"{"kinds":[{"x402Version":1,"scheme":"exact","network":"base","extra":{}},{"x402Version":1,"scheme":"exact","network":"solana","extra":{"feePayer":"test"}}]}"#;

        let result = tolerant_parse_supported(json_with_empty_extra);
        assert!(result.is_some(), "Should parse successfully");

        let supported_response = result.unwrap();
        assert_eq!(supported_response.kinds.len(), 2);

        // The first kind should have its empty extra object removed
        let base_kind = supported_response
            .kinds
            .iter()
            .find(|k| k.network == "base")
            .unwrap();
        assert!(
            base_kind.extra.is_none(),
            "Empty extra object should be removed"
        );

        // The second kind should keep its non-empty extra object
        let solana_kind = supported_response
            .kinds
            .iter()
            .find(|k| k.network == "solana")
            .unwrap();
        assert!(
            solana_kind.extra.is_some(),
            "Non-empty extra object should be preserved"
        );
    }

    #[test]
    fn test_tolerant_parse_supported_invalid_json() {
        // Test case for invalid JSON
        let invalid_json = r#"{"kinds":[{"x402Version":1,"scheme":"exact","network":"base"}]"#; // Missing closing brace

        let result = tolerant_parse_supported(invalid_json);
        assert!(result.is_none(), "Invalid JSON should return None");
    }

    #[test]
    fn test_tolerant_parse_supported_missing_kinds() {
        // Test case for JSON without kinds array
        let json_without_kinds = r#"{"other_field":"value"}"#;

        let result = tolerant_parse_supported(json_without_kinds);
        assert!(result.is_none(), "JSON without kinds should return None");
    }

    #[test]
    fn test_tolerant_parse_supported_with_all_networks() {
        // Test case for responses with all networks (no filtering)
        let json_with_unsupported = r#"{"kinds":[{"x402Version":1,"scheme":"exact","network":"base"},{"x402Version":1,"scheme":"exact","network":"iotex"},{"x402Version":1,"scheme":"exact","network":"peaq"},{"x402Version":1,"scheme":"exact","network":"solana"}]}"#;

        let result = tolerant_parse_supported(json_with_unsupported);
        // The function should now successfully parse all networks
        assert!(
            result.is_some(),
            "Should parse successfully with all networks"
        );

        let supported_response = result.unwrap();
        assert_eq!(
            supported_response.kinds.len(),
            4,
            "Should preserve all networks"
        );

        // Verify all networks remain (no filtering)
        let networks: Vec<String> = supported_response
            .kinds
            .iter()
            .map(|k| k.network.clone())
            .collect();
        assert!(networks.contains(&"base".to_string()));
        assert!(networks.contains(&"solana".to_string()));
        assert!(networks.contains(&"iotex".to_string()));
        assert!(networks.contains(&"peaq".to_string()));
    }

    #[tokio::test]
    async fn test_retry_on_http_error() {
        let server = MockServer::start().await;

        // Mock server that returns 500 error first, then success
        // First mock: returns 500 error
        Mock::given(method("POST"))
            .and(path("/settle"))
            .respond_with(ResponseTemplate::new(500)
                .set_body_string(r#"{"success":false,"errorReason":"unexpected_settle_error","transaction":"","network":"base-sepolia"}"#)
                .insert_header("content-type", "application/json"))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // Second mock: returns success
        Mock::given(method("POST"))
            .and(path("/settle"))
            .respond_with(ResponseTemplate::new(200)
                .set_body_string(r#"{"success":true,"payer":"0x0000000000000000000000000000000000000001","transaction":"0x1111111111111111111111111111111111111111111111111111111111111111","network":"base-sepolia"}"#)
                .insert_header("content-type", "application/json"))
            .mount(&server)
            .await;

        // Create a test settle request
        let payment_payload = PaymentPayload {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: Network::BaseSepolia,
            payload: ExactPaymentPayload::Evm(ExactEvmPayload {
                signature: x402_rs::types::EvmSignature::from([0x12u8; 65]),
                authorization: ExactEvmPayloadAuthorization {
                    from: EvmAddress::from(address!("0x0000000000000000000000000000000000000001")),
                    to: EvmAddress::from(address!("0x0000000000000000000000000000000000000002")),
                    value: TokenAmount::from(1000000u64),
                    valid_after: UnixTimestamp::try_now().unwrap(),
                    valid_before: UnixTimestamp::try_now().unwrap() + 3600,
                    nonce: x402_rs::types::HexEncodedNonce([0x12u8; 32]),
                },
            }),
        };

        let payment_requirements = PaymentRequirements {
            scheme: Scheme::Exact,
            network: Network::BaseSepolia,
            max_amount_required: TokenAmount::from(1000000u64),
            resource: Url::parse("https://example.com").unwrap(),
            description: "test".to_string(),
            mime_type: "application/json".to_string(),
            output_schema: None,
            pay_to: x402_rs::types::MixedAddress::Evm(EvmAddress::from(address!(
                "0x0000000000000000000000000000000000000002"
            ))),
            max_timeout_seconds: 3600,
            asset: x402_rs::types::MixedAddress::Evm(EvmAddress::from(address!(
                "0x0000000000000000000000000000000000000003"
            ))),
            extra: None,
        };

        let settle_request = SettleRequest {
            x402_version: X402Version::V1,
            payment_payload,
            payment_requirements,
        };

        // Create a facilitator client
        let client = FacilitatorClient::try_new(server.uri().parse().unwrap()).unwrap();

        // Test the retry logic
        let result = handle_result(
            &client,
            "POST /settle",
            {
                let settle_request = settle_request.clone();
                let server_uri = server
                    .uri()
                    .parse::<url::Url>()
                    .unwrap()
                    .join("/settle")
                    .unwrap();
                move || {
                    let settle_request = settle_request.clone();
                    reqwest::Client::new()
                        .post(server_uri.clone())
                        .json(&settle_request)
                }
            },
            |body| tolerant_recover_payment_required::<SettleResponse>("POST /settle", body),
            client.settle(&settle_request).await,
            3, // Default max retries
        )
        .await;

        // Should succeed after retry
        assert!(result.is_ok());
        let settle_response = result.unwrap();
        assert!(settle_response.success);
        assert_eq!(settle_response.network, Network::BaseSepolia);
    }

    // TODO: A bit slow because of the delay in the retry logic (calculate_retry_delay)
    #[tokio::test]
    async fn test_retry_on_http_error_preserves_status_code_on_exhaustion() {
        let server = MockServer::start().await;

        // Mock server that always returns 429 (rate limit) error
        Mock::given(method("POST"))
            .and(path("/settle"))
            .respond_with(
                ResponseTemplate::new(429)
                    .set_body_string(r#"{"error":"rate_limit_exceeded"}"#)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        // Create a test settle request
        let payment_payload = PaymentPayload {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: Network::BaseSepolia,
            payload: ExactPaymentPayload::Evm(ExactEvmPayload {
                signature: x402_rs::types::EvmSignature::from([0x12u8; 65]),
                authorization: ExactEvmPayloadAuthorization {
                    from: EvmAddress::from(address!("0x0000000000000000000000000000000000000001")),
                    to: EvmAddress::from(address!("0x0000000000000000000000000000000000000002")),
                    value: TokenAmount::from(1000000u64),
                    valid_after: UnixTimestamp::try_now().unwrap(),
                    valid_before: UnixTimestamp::try_now().unwrap() + 3600,
                    nonce: x402_rs::types::HexEncodedNonce([0x12u8; 32]),
                },
            }),
        };

        let payment_requirements = PaymentRequirements {
            scheme: Scheme::Exact,
            network: Network::BaseSepolia,
            max_amount_required: TokenAmount::from(1000000u64),
            resource: Url::parse("https://example.com").unwrap(),
            description: "test".to_string(),
            mime_type: "application/json".to_string(),
            output_schema: None,
            pay_to: x402_rs::types::MixedAddress::Evm(EvmAddress::from(address!(
                "0x0000000000000000000000000000000000000002"
            ))),
            max_timeout_seconds: 3600,
            asset: x402_rs::types::MixedAddress::Evm(EvmAddress::from(address!(
                "0x0000000000000000000000000000000000000003"
            ))),
            extra: None,
        };

        let settle_request = SettleRequest {
            x402_version: X402Version::V1,
            payment_payload,
            payment_requirements,
        };

        // Create a facilitator client
        let client = FacilitatorClient::try_new(server.uri().parse().unwrap()).unwrap();

        // Test the retry logic - should fail after exhausting retries
        let result = handle_result(
            &client,
            "POST /settle",
            {
                let settle_request = settle_request.clone();
                let server_uri = server
                    .uri()
                    .parse::<url::Url>()
                    .unwrap()
                    .join("/settle")
                    .unwrap();
                move || {
                    let settle_request = settle_request.clone();
                    reqwest::Client::new()
                        .post(server_uri.clone())
                        .json(&settle_request)
                }
            },
            |_body| None, // No recovery function
            client.settle(&settle_request).await,
            1, // Use 1 retry for faster test
        )
        .await;

        // Should fail after retries are exhausted
        assert!(result.is_err());

        // The error should preserve the original 429 status code, not return 500
        if let FacilitatorClientError::HttpStatus { status, .. } = result.unwrap_err() {
            assert_eq!(
                status.as_u16(),
                429,
                "Should preserve original 429 status code"
            );
        } else {
            panic!("Expected HttpStatus error");
        }
    }

    // TODO: A bit slow because of the delay in the retry logic (calculate_retry_delay)
    #[tokio::test]
    async fn test_retry_on_http_error_preserves_5xx_status_code_on_exhaustion() {
        let server = MockServer::start().await;

        // Mock server that always returns 503 (service unavailable) error
        Mock::given(method("POST"))
            .and(path("/settle"))
            .respond_with(
                ResponseTemplate::new(503)
                    .set_body_string(r#"{"error":"service_unavailable"}"#)
                    .insert_header("content-type", "application/json"),
            )
            .mount(&server)
            .await;

        // Create a test settle request
        let payment_payload = PaymentPayload {
            x402_version: X402Version::V1,
            scheme: Scheme::Exact,
            network: Network::BaseSepolia,
            payload: ExactPaymentPayload::Evm(ExactEvmPayload {
                signature: x402_rs::types::EvmSignature::from([0x12u8; 65]),
                authorization: ExactEvmPayloadAuthorization {
                    from: EvmAddress::from(address!("0x0000000000000000000000000000000000000001")),
                    to: EvmAddress::from(address!("0x0000000000000000000000000000000000000002")),
                    value: TokenAmount::from(1000000u64),
                    valid_after: UnixTimestamp::try_now().unwrap(),
                    valid_before: UnixTimestamp::try_now().unwrap() + 3600,
                    nonce: x402_rs::types::HexEncodedNonce([0x12u8; 32]),
                },
            }),
        };

        let payment_requirements = PaymentRequirements {
            scheme: Scheme::Exact,
            network: Network::BaseSepolia,
            max_amount_required: TokenAmount::from(1000000u64),
            resource: Url::parse("https://example.com").unwrap(),
            description: "test".to_string(),
            mime_type: "application/json".to_string(),
            output_schema: None,
            pay_to: x402_rs::types::MixedAddress::Evm(EvmAddress::from(address!(
                "0x0000000000000000000000000000000000000002"
            ))),
            max_timeout_seconds: 3600,
            asset: x402_rs::types::MixedAddress::Evm(EvmAddress::from(address!(
                "0x0000000000000000000000000000000000000003"
            ))),
            extra: None,
        };

        let settle_request = SettleRequest {
            x402_version: X402Version::V1,
            payment_payload,
            payment_requirements,
        };

        // Create a facilitator client
        let client = FacilitatorClient::try_new(server.uri().parse().unwrap()).unwrap();

        // Test the retry logic - should fail after exhausting retries
        let result = handle_result(
            &client,
            "POST /settle",
            {
                let settle_request = settle_request.clone();
                let server_uri = server
                    .uri()
                    .parse::<url::Url>()
                    .unwrap()
                    .join("/settle")
                    .unwrap();
                move || {
                    let settle_request = settle_request.clone();
                    reqwest::Client::new()
                        .post(server_uri.clone())
                        .json(&settle_request)
                }
            },
            |_body| None, // No recovery function
            client.settle(&settle_request).await,
            1, // Use 1 retry for faster test
        )
        .await;

        // Should fail after retries are exhausted
        assert!(result.is_err());

        // The error should preserve the original 503 status code, not return 500
        if let FacilitatorClientError::HttpStatus { status, .. } = result.unwrap_err() {
            assert_eq!(
                status.as_u16(),
                503,
                "Should preserve original 503 status code"
            );
        } else {
            panic!("Expected HttpStatus error");
        }
    }
}
