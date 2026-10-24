use axum::http::StatusCode;
use serde_json;
use tracing::{error, warn};
use x402_axum::facilitator_client::{FacilitatorClient, FacilitatorClientError};
use x402_types::proto::{SupportedResponse, VerifyResponse};

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
    let req = build_req().timeout(std::time::Duration::from_secs(15));
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
    let req = build_req().timeout(std::time::Duration::from_secs(15));
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
pub fn tolerant_parse_supported(body: &str) -> Option<SupportedResponse> {
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
    serde_json::from_str::<SupportedResponse>(&cleaned).ok()
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
        if matches!(is_valid, Some(false)) && invalid_reason.and_then(|r| r.as_str()).is_some() {
            return Some(Ok(VerifyResponse(v)));
        }
    }

    None
}

#[cfg(test)]
mod handle_result_tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn preserves_status_after_verify_retries_are_exhausted() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({"error":"rate_limited"})))
            .expect(2)
            .mount(&server)
            .await;
        let client = FacilitatorClient::try_from(server.uri().as_str()).unwrap();
        let request = x402_types::proto::VerifyRequest::from(json!({"x402Version":1}));
        let url = client.verify_url().clone();
        let result = handle_result(
            &client,
            "POST /verify",
            move || {
                reqwest::Client::new()
                    .post(url.clone())
                    .json(&json!({"x402Version":1}))
            },
            tolerant_recover_verify,
            client.verify(&request).await,
            0,
        )
        .await;
        assert!(matches!(
            result,
            Err(FacilitatorClientError::HttpStatus {
                status: StatusCode::TOO_MANY_REQUESTS,
                ..
            })
        ));
    }
}
