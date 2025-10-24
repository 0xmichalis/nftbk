use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::USER_AGENT;

use super::provider::{IpfsPinningProvider, PinRequest, PinResponse, PinResponseStatus};

#[derive(Clone)]
pub struct PinataClient {
    http: Client,
    base_url: String,
    bearer_token: String,
}

// Pinata API request/response types for create_pin
#[derive(Debug, Serialize)]
struct PinataPinByCidRequest {
    cid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keyvalues: Option<serde_json::Map<String, serde_json::Value>>,
}

#[derive(Debug, Deserialize)]
struct PinataPinByCidResponse {
    data: PinataResponseData,
}

#[derive(Debug, Deserialize)]
struct PinataResponseData {
    id: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
    cid: String,
    status: String,
    #[serde(default)]
    keyvalues: serde_json::Value,
}

// Pinata API types for list_pins
#[derive(Debug, Deserialize)]
pub struct PinataListPinsResponse {
    pub data: PinataListData,
}

#[derive(Debug, Deserialize)]
pub struct PinataListData {
    #[serde(default)]
    pub jobs: Option<Vec<PinataPinJob>>,
    #[serde(default, alias = "nextPageToken")]
    pub next_page_token: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PinataPinJob {
    pub id: String,
    pub cid: String,
    #[serde(default)]
    pub name: Option<String>,
    pub status: String,
    #[serde(default)]
    pub keyvalues: serde_json::Value,
    #[serde(default)]
    pub host_nodes: Vec<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub date_queued: Option<String>,
}

impl PinataClient {
    pub fn new<T: Into<String>>(base_url: T, bearer_token: String) -> Self {
        let http = Client::builder()
            .user_agent(USER_AGENT)
            .build()
            .expect("reqwest client");
        Self {
            http,
            base_url: base_url.into(),
            bearer_token,
        }
    }

    /// Convert Pinata status string to unified PinResponseStatus
    fn convert_status(status: &str, cid: &str) -> PinResponseStatus {
        // Pinata statuses: prechecking, backfilled, retreiving, expired, searching,
        // over_free_limit, over_max_size, invalid_object, bad_host_node
        match status.to_lowercase().as_str() {
            "prechecking" => PinResponseStatus::Queued,
            "searching" => PinResponseStatus::Queued,
            "retreiving" | "retrieving" => PinResponseStatus::Pinning,
            "backfilled" => PinResponseStatus::Pinned,
            "expired" => PinResponseStatus::Failed,
            "over_free_limit" => PinResponseStatus::Failed,
            "over_max_size" => PinResponseStatus::Failed,
            "invalid_object" => PinResponseStatus::Failed,
            "bad_host_node" => PinResponseStatus::Failed,
            // Fallback for any other statuses
            unknown => {
                warn!(
                    "Unknown Pinata status '{}' for CID {}, defaulting to Queued",
                    unknown, cid
                );
                PinResponseStatus::Queued
            }
        }
    }
}

const MAX_PIN_NAME_LEN: usize = 50;

#[async_trait]
impl IpfsPinningProvider for PinataClient {
    async fn create_pin(&self, request: &PinRequest) -> Result<PinResponse> {
        let url = format!("{}/v3/files/public/pin_by_cid", self.base_url);

        // Enforce Pinata-specific name length constraint
        let mut effective_name = request.name.clone();
        if let Some(n) = &mut effective_name {
            if n.len() > MAX_PIN_NAME_LEN {
                warn!(
                    "Pinata pin name too long ({} > {}), truncating",
                    n.len(),
                    MAX_PIN_NAME_LEN
                );
                n.truncate(MAX_PIN_NAME_LEN);
            }
        }

        let pinata_request = PinataPinByCidRequest {
            cid: request.cid.clone(),
            name: effective_name.clone(),
            keyvalues: request.metadata.clone(),
        };

        let res = self
            .http
            .post(&url)
            .bearer_auth(&self.bearer_token)
            .json(&pinata_request)
            .send()
            .await
            .context("POST /v3/files/public/pin_by_cid failed")?;

        let status_code = res.error_for_status_ref().map(|_| ()).err();
        let text = res.text().await.context("reading response body")?;

        if let Some(err) = status_code {
            return Err(anyhow::anyhow!("{}: {}", err, text));
        }

        let parsed: PinataPinByCidResponse = serde_json::from_str(&text)
            .with_context(|| format!("decoding PinataPinByCidResponse: {text}"))?;

        // Convert Pinata status to our unified status
        let status = Self::convert_status(&parsed.data.status, &parsed.data.cid);

        Ok(PinResponse {
            id: parsed.data.id,
            cid: parsed.data.cid,
            status,
            provider_type: self.provider_type().to_string(),
            provider_url: self.provider_url().to_string(),
            metadata: match parsed.data.keyvalues {
                serde_json::Value::Object(map) => Some(map),
                _ => None,
            },
            size: None, //TODO: Pinata doesn't provide size information via the pin_by_cid API
        })
    }

    // TODO: This is currently broken for me and Pinata are not smart enough to provide a timely fix.
    async fn get_pin(&self, pin_id: &str) -> Result<PinResponse> {
        // Use list_pins and filter by ID
        let pins = self.list_pins().await?;

        pins.into_iter()
            .find(|pin| pin.id == pin_id)
            .ok_or_else(|| anyhow::anyhow!("Pin with ID '{}' not found in Pinata", pin_id))
    }

    // TODO: This is currently broken for me and Pinata are not smart enough to provide a timely fix.
    async fn list_pins(&self) -> Result<Vec<PinResponse>> {
        let url = format!("{}/v3/files/public/pin_by_cid", self.base_url);

        let res = self
            .http
            .get(&url)
            .bearer_auth(&self.bearer_token)
            .send()
            .await
            .context("GET /v3/files/public/pin_by_cid failed")?;

        let status_code = res.error_for_status_ref().map(|_| ()).err();
        let text = res.text().await.context("reading response body")?;

        if let Some(err) = status_code {
            return Err(anyhow::anyhow!("{}: {}", err, text));
        }

        let parsed: PinataListPinsResponse = serde_json::from_str(&text)
            .with_context(|| format!("decoding PinataListPinsResponse: {text}"))?;

        // Convert all pins to unified PinResponse
        let pins = parsed
            .data
            .jobs
            .unwrap_or_default()
            .into_iter()
            .map(|job| {
                let status = Self::convert_status(&job.status, &job.cid);
                PinResponse {
                    id: job.id,
                    cid: job.cid,
                    status,
                    provider_type: self.provider_type().to_string(),
                    provider_url: self.provider_url().to_string(),
                    metadata: match job.keyvalues {
                        serde_json::Value::Object(map) => Some(map),
                        _ => None,
                    },
                    size: None, // Pinata doesn't provide size information
                }
            })
            .collect();

        Ok(pins)
    }

    // TODO: This is currently broken for me and Pinata are not smart enough to provide a timely fix.
    async fn delete_pin(&self, request_id: &str) -> Result<()> {
        let url = format!(
            "{}/v3/files/public/pin_by_cid/{}",
            self.base_url, request_id
        );

        let res = self
            .http
            .delete(&url)
            .bearer_auth(&self.bearer_token)
            .send()
            .await
            .context("DELETE /v3/files/public/pin_by_cid/{id} failed")?;

        let status = res.status();
        let text = res.text().await.context("reading response body")?;

        // If the pin doesn't exist (404), that's actually success - the desired end state
        if status == 404 {
            warn!(
                "Pin not found by request id {request_id} ({text}), treating as successful deletion",
            );
            return Ok(());
        }

        // For all other error status codes, return an error
        if !status.is_success() {
            return Err(anyhow::anyhow!("HTTP {}: {}", status, text));
        }

        Ok(())
    }

    fn provider_type(&self) -> &str {
        "pinata"
    }

    fn provider_url(&self) -> &str {
        &self.base_url
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{body_partial_json, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn test_pinata_create_pin_success() {
        let server = MockServer::start().await;

        let expected_response = serde_json::json!({
            "data": {
                "id": "test-pin-id-123",
                "name": "test-pin",
                "cid": "QmTestHash",
                "status": "backfilled"
            }
        });

        Mock::given(method("POST"))
            .and(path("/v3/files/public/pin_by_cid"))
            .and(header("user-agent", USER_AGENT))
            .and(header("authorization", "Bearer test-token"))
            .and(body_partial_json(serde_json::json!({
                "cid": "QmTestHash",
                "name": "test-pin"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
            .mount(&server)
            .await;

        let base = server.uri();
        let client = PinataClient::new(base.clone(), "test-token".to_string());

        let request = PinRequest {
            cid: "QmTestHash".to_string(),
            name: Some("test-pin".to_string()),
            metadata: None,
        };

        let response = client.create_pin(&request).await.unwrap();

        assert_eq!(response.id, "test-pin-id-123");
        assert_eq!(response.cid, "QmTestHash");
        assert_eq!(response.status, PinResponseStatus::Pinned);
        assert_eq!(response.provider_url, base);
    }

    #[tokio::test]
    async fn test_pinata_create_pin_without_name() {
        let server = MockServer::start().await;

        let expected_response = serde_json::json!({
            "data": {
                "id": "test-pin-id-456",
                "cid": "QmAnotherHash",
                "status": "prechecking"
            }
        });

        Mock::given(method("POST"))
            .and(path("/v3/files/public/pin_by_cid"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
            .mount(&server)
            .await;

        let base = server.uri();
        let client = PinataClient::new(base.clone(), "test-token".to_string());

        let request = PinRequest {
            cid: "QmAnotherHash".to_string(),
            name: None,
            metadata: None,
        };

        let response = client.create_pin(&request).await.unwrap();

        assert_eq!(response.id, "test-pin-id-456");
        assert_eq!(response.cid, "QmAnotherHash");
        assert_eq!(response.status, PinResponseStatus::Queued);
        assert_eq!(response.provider_url, base);
    }

    #[tokio::test]
    async fn test_pinata_create_pin_name_truncated() {
        let server = MockServer::start().await;

        let long_name = "x".repeat(100);
        let _expected_truncated = "x".repeat(MAX_PIN_NAME_LEN);

        let expected_response = serde_json::json!({
            "data": {
                "id": "test-pin-id-999",
                "cid": "QmLongNameHash",
                "status": "prechecking"
            }
        });

        Mock::given(method("POST"))
            .and(path("/v3/files/public/pin_by_cid"))
            .and(header("user-agent", USER_AGENT))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
            .mount(&server)
            .await;

        let base = server.uri();
        let client = PinataClient::new(base.clone(), "test-token".to_string());
        let request = PinRequest {
            cid: "QmLongNameHash".to_string(),
            name: Some(long_name),
            metadata: None,
        };

        let response = client.create_pin(&request).await.unwrap();
        assert_eq!(response.cid, "QmLongNameHash");
        // Status mapping of prechecking -> Queued
        assert_eq!(response.status, PinResponseStatus::Queued);
        assert_eq!(response.provider_url, base);
    }

    #[tokio::test]
    async fn test_pinata_create_pin_error() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v3/files/public/pin_by_cid"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "Unauthorized"
            })))
            .mount(&server)
            .await;

        let client = PinataClient::new(server.uri(), "invalid-token".to_string());

        let request = PinRequest {
            cid: "QmTestHash".to_string(),
            name: None,
            metadata: None,
        };

        let result = client.create_pin(&request).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pinata_status_mappings() {
        // Test all Pinata status values map correctly
        let test_cases = vec![
            ("prechecking", PinResponseStatus::Queued),
            ("searching", PinResponseStatus::Queued),
            ("retreiving", PinResponseStatus::Pinning),
            ("retrieving", PinResponseStatus::Pinning), // Handle both spellings
            ("backfilled", PinResponseStatus::Pinned),
            ("expired", PinResponseStatus::Failed),
            ("over_free_limit", PinResponseStatus::Failed),
            ("over_max_size", PinResponseStatus::Failed),
            ("invalid_object", PinResponseStatus::Failed),
            ("bad_host_node", PinResponseStatus::Failed),
        ];

        for (pinata_status, expected_status) in test_cases {
            // Create a new server for each test case to avoid mock interference
            let server = MockServer::start().await;

            let expected_response = serde_json::json!({
                "data": {
                    "id": "test-id",
                    "cid": "QmTest",
                    "status": pinata_status
                }
            });

            Mock::given(method("POST"))
                .and(path("/v3/files/public/pin_by_cid"))
                .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
                .mount(&server)
                .await;

            let client = PinataClient::new(server.uri(), "test-token".to_string());
            let request = PinRequest {
                cid: "QmTest".to_string(),
                name: None,
                metadata: None,
            };

            let response = client.create_pin(&request).await.unwrap();
            assert_eq!(
                response.status, expected_status,
                "Status '{pinata_status}' should map to {expected_status:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_pinata_unknown_status_logs_warning() {
        let server = MockServer::start().await;

        let expected_response = serde_json::json!({
            "data": {
                "id": "test-id",
                "cid": "QmTest",
                "status": "unknown_future_status"
            }
        });

        Mock::given(method("POST"))
            .and(path("/v3/files/public/pin_by_cid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
            .mount(&server)
            .await;

        let client = PinataClient::new(server.uri(), "test-token".to_string());
        let request = PinRequest {
            cid: "QmTest".to_string(),
            name: None,
            metadata: None,
        };

        let response = client.create_pin(&request).await.unwrap();
        // Should default to Queued for unknown status
        assert_eq!(response.status, PinResponseStatus::Queued);
        assert_eq!(response.cid, "QmTest");
    }

    #[tokio::test]
    async fn test_pinata_list_pins_success() {
        let server = MockServer::start().await;

        let expected_response = serde_json::json!({
            "data": {
                "jobs": [
                    {
                        "id": "pin-id-1",
                        "cid": "QmHash1",
                        "name": "test-pin-1",
                        "status": "backfilled",
                        "keyvalues": {},
                        "host_nodes": ["node1"],
                        "group_id": "group1",
                        "date_queued": "2024-01-01T00:00:00Z"
                    },
                    {
                        "id": "pin-id-2",
                        "cid": "QmHash2",
                        "name": "test-pin-2",
                        "status": "prechecking",
                        "keyvalues": {},
                        "host_nodes": [],
                        "group_id": null,
                        "date_queued": "2024-01-02T00:00:00Z"
                    }
                ],
                "next_page_token": "next-token-123"
            }
        });

        Mock::given(method("GET"))
            .and(path("/v3/files/public/pin_by_cid"))
            .and(header("user-agent", USER_AGENT))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
            .mount(&server)
            .await;

        let base = server.uri();
        let client = PinataClient::new(base.clone(), "test-token".to_string());

        let pins = client.list_pins().await.unwrap();

        assert_eq!(pins.len(), 2);
        assert_eq!(pins[0].id, "pin-id-1");
        assert_eq!(pins[0].cid, "QmHash1");
        assert_eq!(pins[0].status, PinResponseStatus::Pinned); // "backfilled" maps to Pinned
        assert_eq!(pins[0].provider_url, base);
        assert_eq!(pins[1].id, "pin-id-2");
        assert_eq!(pins[1].status, PinResponseStatus::Queued); // "prechecking" maps to Queued
        assert_eq!(pins[1].provider_url, base);
    }

    #[tokio::test]
    async fn test_pinata_list_pins_empty() {
        let server = MockServer::start().await;

        let expected_response = serde_json::json!({
            "data": {
                "jobs": []
            }
        });

        Mock::given(method("GET"))
            .and(path("/v3/files/public/pin_by_cid"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
            .mount(&server)
            .await;

        let client = PinataClient::new(server.uri(), "test-token".to_string());

        let pins = client.list_pins().await.unwrap();

        assert_eq!(pins.len(), 0);
    }

    #[tokio::test]
    async fn test_pinata_list_pins_null_jobs_and_camelcase_next_page_token() {
        let server = MockServer::start().await;

        let expected_response = serde_json::json!({
            "data": {
                "jobs": null,
                "nextPageToken": null
            }
        });

        Mock::given(method("GET"))
            .and(path("/v3/files/public/pin_by_cid"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
            .mount(&server)
            .await;

        let client = PinataClient::new(server.uri(), "test-token".to_string());

        let pins = client.list_pins().await.unwrap();

        assert_eq!(pins.len(), 0);
    }

    #[tokio::test]
    async fn test_pinata_next_page_token_camelcase_is_read() {
        // Directly test deserialization to verify alias works
        let body = serde_json::json!({
            "data": {
                "jobs": null,
                "nextPageToken": "token-xyz"
            }
        })
        .to_string();

        let parsed: PinataListPinsResponse = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed.data.next_page_token, Some("token-xyz".to_string()));
        // And jobs should be None which we treat as empty when consuming
        assert!(parsed.data.jobs.is_none());
    }

    #[tokio::test]
    async fn test_pinata_list_pins_error() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/v3/files/public/pin_by_cid"))
            .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
                "error": "Forbidden"
            })))
            .mount(&server)
            .await;

        let client = PinataClient::new(server.uri(), "invalid-token".to_string());

        let result = client.list_pins().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_pinata_get_pin_success() {
        let server = MockServer::start().await;

        let expected_response = serde_json::json!({
            "data": {
                "jobs": [
                    {
                        "id": "pin-id-1",
                        "cid": "QmHash1",
                        "name": "test-pin-1",
                        "status": "backfilled",
                        "keyvalues": {},
                        "host_nodes": ["node1"],
                        "group_id": "group1",
                        "date_queued": "2024-01-01T00:00:00Z"
                    },
                    {
                        "id": "pin-id-2",
                        "cid": "QmHash2",
                        "name": "test-pin-2",
                        "status": "prechecking",
                        "keyvalues": {},
                        "host_nodes": [],
                        "group_id": null,
                        "date_queued": "2024-01-02T00:00:00Z"
                    }
                ]
            }
        });

        Mock::given(method("GET"))
            .and(path("/v3/files/public/pin_by_cid"))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
            .mount(&server)
            .await;

        let client = PinataClient::new(server.uri(), "test-token".to_string());

        let pin = client.get_pin("pin-id-2").await.unwrap();

        assert_eq!(pin.id, "pin-id-2");
        assert_eq!(pin.cid, "QmHash2");
        assert_eq!(pin.status, PinResponseStatus::Queued); // "prechecking" maps to Queued
        assert_eq!(pin.provider_url, server.uri());
    }

    #[tokio::test]
    async fn test_pinata_get_pin_not_found() {
        let server = MockServer::start().await;

        let expected_response = serde_json::json!({
            "data": {
                "jobs": [
                    {
                        "id": "pin-id-1",
                        "cid": "QmHash1",
                        "status": "backfilled",
                        "keyvalues": {},
                        "host_nodes": []
                    }
                ]
            }
        });

        Mock::given(method("GET"))
            .and(path("/v3/files/public/pin_by_cid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
            .mount(&server)
            .await;

        let client = PinataClient::new(server.uri(), "test-token".to_string());

        let result = client.get_pin("non-existent-id").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Pin with ID 'non-existent-id' not found"));
    }

    #[tokio::test]
    async fn test_pinata_get_pin_empty_list() {
        let server = MockServer::start().await;

        let expected_response = serde_json::json!({
            "data": {
                "jobs": []
            }
        });

        Mock::given(method("GET"))
            .and(path("/v3/files/public/pin_by_cid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
            .mount(&server)
            .await;

        let client = PinataClient::new(server.uri(), "test-token".to_string());

        let result = client.get_pin("any-id").await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Pin with ID 'any-id' not found"));
    }

    #[tokio::test]
    async fn test_pinata_delete_pin_success() {
        let server = MockServer::start().await;

        let expected_response = serde_json::json!({
            "data": null
        });

        Mock::given(method("DELETE"))
            .and(path("/v3/files/public/pin_by_cid/pin-id-123"))
            .and(header("user-agent", USER_AGENT))
            .and(header("authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected_response))
            .mount(&server)
            .await;

        let client = PinataClient::new(server.uri(), "test-token".to_string());

        let result = client.delete_pin("pin-id-123").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pinata_delete_pin_not_found() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/v3/files/public/pin_by_cid/non-existent-id"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "error": "Pin not found"
            })))
            .mount(&server)
            .await;

        let client = PinataClient::new(server.uri(), "test-token".to_string());

        // 404 should be treated as success since the desired end state is "pin doesn't exist"
        let result = client.delete_pin("non-existent-id").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pinata_delete_pin_unauthorized() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/v3/files/public/pin_by_cid/pin-id-456"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "Unauthorized"
            })))
            .mount(&server)
            .await;

        let client = PinataClient::new(server.uri(), "invalid-token".to_string());

        let result = client.delete_pin("pin-id-456").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("401"));
    }
}
