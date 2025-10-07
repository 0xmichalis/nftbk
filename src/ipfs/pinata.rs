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
}

// Pinata API types for list_pins
#[derive(Debug, Deserialize)]
pub struct PinataListPinsResponse {
    pub data: PinataListData,
}

#[derive(Debug, Deserialize)]
pub struct PinataListData {
    pub jobs: Vec<PinataPinJob>,
    #[serde(default)]
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

#[async_trait]
impl IpfsPinningProvider for PinataClient {
    async fn create_pin(&self, request: &PinRequest) -> Result<PinResponse> {
        let url = format!("{}/v3/files/public/pin_by_cid", self.base_url);

        let pinata_request = PinataPinByCidRequest {
            cid: request.cid.clone(),
            name: request.name.clone(),
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
            provider: self.provider_name().to_string(),
        })
    }

    async fn get_pin(&self, pin_id: &str) -> Result<PinResponse> {
        // Use list_pins and filter by ID
        let pins = self.list_pins().await?;

        pins.into_iter()
            .find(|pin| pin.id == pin_id)
            .ok_or_else(|| anyhow::anyhow!("Pin with ID '{}' not found in Pinata", pin_id))
    }

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
            .into_iter()
            .map(|job| {
                let status = Self::convert_status(&job.status, &job.cid);
                PinResponse {
                    id: job.id,
                    cid: job.cid,
                    status,
                    provider: self.provider_name().to_string(),
                }
            })
            .collect();

        Ok(pins)
    }

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

        let status_code = res.error_for_status_ref().map(|_| ()).err();
        let text = res.text().await.context("reading response body")?;

        if let Some(err) = status_code {
            return Err(anyhow::anyhow!("{}: {}", err, text));
        }

        Ok(())
    }

    fn provider_name(&self) -> &str {
        "pinata"
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

        let client = PinataClient::new(server.uri(), "test-token".to_string());

        let request = PinRequest {
            cid: "QmTestHash".to_string(),
            name: Some("test-pin".to_string()),
        };

        let response = client.create_pin(&request).await.unwrap();

        assert_eq!(response.id, "test-pin-id-123");
        assert_eq!(response.cid, "QmTestHash");
        assert_eq!(response.status, PinResponseStatus::Pinned);
        assert_eq!(response.provider, "pinata");
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

        let client = PinataClient::new(server.uri(), "test-token".to_string());

        let request = PinRequest {
            cid: "QmAnotherHash".to_string(),
            name: None,
        };

        let response = client.create_pin(&request).await.unwrap();

        assert_eq!(response.id, "test-pin-id-456");
        assert_eq!(response.cid, "QmAnotherHash");
        assert_eq!(response.status, PinResponseStatus::Queued);
        assert_eq!(response.provider, "pinata");
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
            };

            let response = client.create_pin(&request).await.unwrap();
            assert_eq!(
                response.status, expected_status,
                "Status '{}' should map to {:?}",
                pinata_status, expected_status
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

        let client = PinataClient::new(server.uri(), "test-token".to_string());

        let pins = client.list_pins().await.unwrap();

        assert_eq!(pins.len(), 2);
        assert_eq!(pins[0].id, "pin-id-1");
        assert_eq!(pins[0].cid, "QmHash1");
        assert_eq!(pins[0].status, PinResponseStatus::Pinned); // "backfilled" maps to Pinned
        assert_eq!(pins[0].provider, "pinata");
        assert_eq!(pins[1].id, "pin-id-2");
        assert_eq!(pins[1].status, PinResponseStatus::Queued); // "prechecking" maps to Queued
        assert_eq!(pins[1].provider, "pinata");
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
        assert_eq!(pin.provider, "pinata");
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

        let result = client.delete_pin("non-existent-id").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("404"));
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
