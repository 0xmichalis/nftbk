use axum::http::StatusCode;
use serde_json;
use tracing::error;
use x402_axum::facilitator_client::{FacilitatorClient, FacilitatorClientError};
use x402_rs::types::{
    FacilitatorErrorReason, MixedAddress, SupportedPaymentKindsResponse, VerifyResponse,
};

/// Adds headers from a FacilitatorClient to a reqwest RequestBuilder
pub async fn add_headers_from_client(
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
pub async fn log_raw_error_body(method: &str, path: &str, body: &str) {
    let snippet = if body.len() > 4096 {
        &body[..4096]
    } else {
        body
    };
    error!("{} {} raw body (truncated): {}", method, path, snippet);
}

/// Generic error handling that attempts to recover from JSON deserialization errors
/// by fetching the raw response body and applying recovery logic
pub async fn handle_result<T, FBuild, FRecover>(
    client: &FacilitatorClient,
    context: &'static str,
    build_req: FBuild,
    recover: FRecover,
    result: Result<T, FacilitatorClientError>,
) -> Result<T, FacilitatorClientError>
where
    FBuild: FnOnce() -> reqwest::RequestBuilder,
    FRecover: FnOnce(&str) -> Option<Result<T, FacilitatorClientError>>,
{
    match result {
        Ok(value) => Ok(value),
        Err(err) => {
            error!(error = %err, "{} failed", context);
            if let FacilitatorClientError::JsonDeserialization {
                context: err_ctx, ..
            } = &err
            {
                if *err_ctx == context {
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
                                if let Some(recovered) = recover(body.as_str()) {
                                    return recovered;
                                }
                            }
                            Err(fetch_err) => {
                                error!(
                                    "Failed to read response body for {}: {}",
                                    context, fetch_err
                                );
                            }
                        },
                        Err(fetch_err) => {
                            error!("Failed to fetch raw body for {}: {}", context, fetch_err);
                        }
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
}
