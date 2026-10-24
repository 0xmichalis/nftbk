use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;

use crate::USER_AGENT;

use super::provider::{IpfsPinningProvider, PinRequest, PinResponse, PinResponseStatus};
use super::types::{Pin, PinMeta, PinStatusResponse, PinsListQuery, PinsListResponse};

#[derive(Clone)]
pub struct IpfsPinningClient {
    http: Client,
    base_url: String,
    bearer_token: Option<String>,
}

// Minimal client for interacting with the IPFS Pinning Service API
// https://ipfs.github.io/pinning-services-api-spec/
impl IpfsPinningClient {
    pub fn new<T: Into<String>>(base_url: T, bearer_token: Option<String>) -> Self {
        let http = Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Failed to create reqwest client - this should never fail");
        Self {
            http,
            base_url: base_url.into(),
            bearer_token,
        }
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.bearer_token {
            req.bearer_auth(token)
        } else {
            req
        }
    }

    /// Convert IPFS Pinning Service status to unified PinResponseStatus
    fn convert_status(status: super::types::PinStatus) -> PinResponseStatus {
        match status {
            super::types::PinStatus::Queued => PinResponseStatus::Queued,
            super::types::PinStatus::Pinning => PinResponseStatus::Pinning,
            super::types::PinStatus::Pinned => PinResponseStatus::Pinned,
            super::types::PinStatus::Failed => PinResponseStatus::Failed,
        }
    }

    async fn list_pins(&self, query: &PinsListQuery) -> Result<PinsListResponse> {
        let url = format!("{}/pins", self.base_url);
        let mut req = self.http.get(url);
        // Serialize query into query params according to spec
        if let Some(cids) = &query.cid {
            req = req.query(&[("cid", cids.join(","))]);
        }
        if let Some(name) = &query.name {
            req = req.query(&[("name", name)]);
        }
        if let Some(statuses) = &query.status {
            let statuses = statuses
                .iter()
                .map(|status| match status {
                    super::types::PinStatus::Queued => "queued",
                    super::types::PinStatus::Pinning => "pinning",
                    super::types::PinStatus::Pinned => "pinned",
                    super::types::PinStatus::Failed => "failed",
                })
                .collect::<Vec<_>>()
                .join(",");
            req = req.query(&[("status", statuses)]);
        }
        if let Some(before) = &query.before {
            req = req.query(&[("before", before)]);
        }
        if let Some(after) = &query.after {
            req = req.query(&[("after", after)]);
        }
        if let Some(limit) = &query.limit {
            req = req.query(&[("limit", limit)]);
        }

        let res = self.auth(req).send().await.context("GET /pins failed")?;
        let status = res.error_for_status_ref().map(|_| ()).err();
        let text = res.text().await.context("reading response body")?;
        if let Some(err) = status {
            return Err(anyhow::anyhow!("{}: {}", err, text));
        }
        let parsed: PinsListResponse = serde_json::from_str(&text)
            .with_context(|| format!("decoding PinsListResponse: {text}"))?;
        Ok(parsed)
    }

    async fn all_pins(&self, mut query: PinsListQuery) -> Result<Vec<PinResponse>> {
        query.status = Some(vec![
            super::types::PinStatus::Queued,
            super::types::PinStatus::Pinning,
            super::types::PinStatus::Pinned,
            super::types::PinStatus::Failed,
        ]);
        query.limit = Some(1000);
        let mut pins = vec![];
        loop {
            let response = self.list_pins(&query).await?;
            let complete = response.results.len() as u64 >= response.count;
            let next = response.results.last().map(|pin| pin.created.clone());
            pins.extend(response.results.into_iter().map(|pin| {
                let size = pin.extract_size();
                PinResponse {
                    id: pin.requestid,
                    cid: pin.pin.cid,
                    status: Self::convert_status(pin.status),
                    provider_type: self.provider_type().into(),
                    provider_url: self.provider_url().into(),
                    metadata: pin.pin.meta.map(|m| m.0),
                    size,
                }
            }));
            if complete || next.is_none() {
                return Ok(pins);
            }
            anyhow::ensure!(next != query.before, "Provider pagination did not advance");
            query.before = next;
        }
    }

    pub async fn replace_pin(&self, request_id: &str, pin: &Pin) -> Result<PinStatusResponse> {
        let url = format!("{}/pins/{}", self.base_url, request_id);
        // According to spec, replace is POST /pins/{requestid}
        let req = self.http.post(url).json(pin);
        let res = self
            .auth(req)
            .send()
            .await
            .context("POST /pins/{id} failed")?;
        let status = res.error_for_status_ref().map(|_| ()).err();
        let text = res.text().await.context("reading response body")?;
        if let Some(err) = status {
            return Err(anyhow::anyhow!("{}: {}", err, text));
        }
        let parsed: PinStatusResponse = serde_json::from_str(&text)
            .with_context(|| format!("decoding PinStatusResponse: {text}"))?;
        Ok(parsed)
    }
}

#[async_trait]
impl IpfsPinningProvider for IpfsPinningClient {
    async fn create_pin(&self, request: &PinRequest) -> Result<PinResponse> {
        let url = format!("{}/pins", self.base_url);
        let pin = Pin {
            cid: request.cid.clone(),
            name: request.name.clone(),
            origins: Default::default(),
            meta: request.metadata.as_ref().map(|m| PinMeta(m.clone())),
        };

        let req = self.http.post(url).json(&pin);
        let res = self.auth(req).send().await.context("POST /pins failed")?;
        let status_err = res.error_for_status_ref().map(|_| ()).err();
        let text = res.text().await.context("reading response body")?;

        if let Some(err) = status_err {
            return Err(anyhow::anyhow!("{}: {}", err, text));
        }

        let parsed: PinStatusResponse = serde_json::from_str(&text)
            .with_context(|| format!("decoding PinStatusResponse: {text}"))?;

        let size = parsed.extract_size();
        Ok(PinResponse {
            id: parsed.requestid,
            cid: parsed.pin.cid,
            status: Self::convert_status(parsed.status),
            provider_type: self.provider_type().to_string(),
            provider_url: self.provider_url().to_string(),
            metadata: parsed.pin.meta.map(|m| m.0),
            size,
        })
    }

    async fn get_pin(&self, request_id: &str) -> Result<PinResponse> {
        // Call the inherent method directly
        let url = format!("{}/pins/{}", self.base_url, request_id);
        let req = self.http.get(url);
        let res = self
            .auth(req)
            .send()
            .await
            .context("GET /pins/{id} failed")?;
        let status_code = res.error_for_status_ref().map(|_| ()).err();
        let text = res.text().await.context("reading response body")?;
        if let Some(err) = status_code {
            return Err(anyhow::anyhow!("{}: {}", err, text));
        }
        let parsed: PinStatusResponse = serde_json::from_str(&text)
            .with_context(|| format!("decoding PinStatusResponse: {text}"))?;

        let size = parsed.extract_size();
        Ok(PinResponse {
            id: parsed.requestid,
            cid: parsed.pin.cid,
            status: Self::convert_status(parsed.status),
            provider_type: self.provider_type().to_string(),
            provider_url: self.provider_url().to_string(),
            metadata: parsed.pin.meta.map(|m| m.0),
            size,
        })
    }

    async fn list_pins(&self) -> Result<Vec<PinResponse>> {
        self.all_pins(PinsListQuery::default()).await
    }

    async fn find_pin(&self, cid: &str, pin_id: &str) -> Result<Option<PinResponse>> {
        let pins = self
            .all_pins(PinsListQuery {
                cid: Some(vec![cid.into()]),
                name: Some(format!("nftbk-{pin_id}")),
                ..Default::default()
            })
            .await?;
        Ok(pins.into_iter().find(|pin| {
            pin.cid == cid
                && pin
                    .metadata
                    .as_ref()
                    .and_then(|meta| meta.get("nftbk_pin_id"))
                    .and_then(|id| id.as_str())
                    == Some(pin_id)
        }))
    }

    async fn delete_pin(&self, request_id: &str) -> Result<()> {
        let url = format!("{}/pins/{}", self.base_url, request_id);
        let req = self.http.delete(url);
        let res = self
            .auth(req)
            .send()
            .await
            .context("DELETE /pins/{id} failed")?;
        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        let status = res.error_for_status_ref().map(|_| ()).err();
        let text = res.text().await.context("reading response body")?;
        if let Some(err) = status {
            return Err(anyhow::anyhow!("{}: {}", err, text));
        }
        Ok(())
    }

    fn provider_type(&self) -> &str {
        "pinning-service"
    }

    fn provider_url(&self) -> &str {
        &self.base_url
    }
}

#[cfg(test)]
mod tests {
    use crate::ipfs::{
        IpfsPinningClient, IpfsPinningProvider, Pin, PinOrigins, PinResponseStatus, PinStatus,
        PinsListQuery,
    };
    use crate::USER_AGENT;
    use wiremock::matchers::{
        body_partial_json, header, header_exists, method, path, path_regex, query_param,
    };
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn example_pin_status_response() -> serde_json::Value {
        serde_json::json!({
            "requestid": "req-123",
            "status": "pinned",
            "created": "2020-07-23T15:46:27.390Z",
            "pin": {
                "cid": "bafybeigdyrzt5v276s3jvq7j4q6vti7",
                "name": "my-pin",
                "origins": [],
                "meta": {"app": "nftbk"}
            },
            "delegates": ["/ip4/203.0.113.1/tcp/4001/p2p/12D3KooW"],
            "info": {
                "size": "1024"
            }
        })
    }

    #[tokio::test]
    async fn create_pin_posts_and_parses() {
        use crate::ipfs::{IpfsPinningProvider, PinRequest, PinResponseStatus};

        let server = MockServer::start().await;
        let expected = example_pin_status_response();

        Mock::given(method("POST"))
            .and(path("/pins"))
            .and(header("user-agent", USER_AGENT))
            .and(header("authorization", "Bearer token123"))
            .and(body_partial_json(serde_json::json!({
                "cid": "bafy...",
                "name": "my"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected.clone()))
            .mount(&server)
            .await;

        let base = server.uri();
        let client = IpfsPinningClient::new(base.clone(), Some("token123".into()));
        let request = PinRequest {
            cid: "bafy...".into(),
            name: Some("my".into()),
            metadata: None,
        };

        let res = client.create_pin(&request).await.unwrap();
        assert_eq!(res.id, "req-123");
        assert_eq!(res.cid, "bafybeigdyrzt5v276s3jvq7j4q6vti7"); // CID from server response
        assert!(matches!(res.status, PinResponseStatus::Pinned));
        assert_eq!(res.provider_url, base);
        assert_eq!(res.size, Some(1024));
    }

    #[tokio::test]
    async fn get_pin_fetches_and_parses() {
        let server = MockServer::start().await;
        let expected = example_pin_status_response();

        Mock::given(method("GET"))
            .and(path("/pins/req-123"))
            .and(header("user-agent", USER_AGENT))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected.clone()))
            .mount(&server)
            .await;

        let base = server.uri();
        let client = IpfsPinningClient::new(base.clone(), None);
        let res = client.get_pin("req-123").await.unwrap();
        assert_eq!(res.id, "req-123");
        assert_eq!(res.cid, "bafybeigdyrzt5v276s3jvq7j4q6vti7");
        assert!(matches!(res.status, PinResponseStatus::Pinned));
        assert_eq!(res.provider_url, base);
        assert_eq!(res.size, Some(1024));
    }

    #[tokio::test]
    async fn list_pins_serializes_queries() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/pins"))
            .and(query_param("cid", "bafy1,bafy2"))
            .and(query_param("name", "x"))
            .and(query_param("status", "pinned,failed"))
            .and(query_param("before", "2020-01-01T00:00:00Z"))
            .and(query_param("after", "2019-01-01T00:00:00Z"))
            .and(query_param("limit", "10"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "count": 1u64,
                "results": [example_pin_status_response()]
            })))
            .mount(&server)
            .await;

        let client = IpfsPinningClient::new(server.uri(), None);
        let q = PinsListQuery {
            cid: Some(vec!["bafy1".into(), "bafy2".into()]),
            name: Some("x".into()),
            status: Some(vec![PinStatus::Pinned, PinStatus::Failed]),
            before: Some("2020-01-01T00:00:00Z".into()),
            after: Some("2019-01-01T00:00:00Z".into()),
            limit: Some(10),
        };
        let res = client.list_pins(&q).await.unwrap();
        assert_eq!(res.count, 1);
        assert_eq!(res.results.len(), 1);
    }

    #[tokio::test]
    async fn replace_pin_posts_and_parses() {
        let server = MockServer::start().await;
        let expected = example_pin_status_response();

        Mock::given(method("POST"))
            .and(path_regex("^/pins/req-123$"))
            .and(header("user-agent", USER_AGENT))
            .and(body_partial_json(serde_json::json!({
                "cid": "bafy...2"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(expected.clone()))
            .mount(&server)
            .await;

        let client = IpfsPinningClient::new(server.uri(), None);
        let pin = Pin {
            cid: "bafy...2".into(),
            name: None,
            origins: PinOrigins::default(),
            meta: None,
        };
        let res = client.replace_pin("req-123", &pin).await.unwrap();
        assert_eq!(res.requestid, "req-123");
    }

    #[tokio::test]
    async fn delete_pin_sends_delete() {
        let server = MockServer::start().await;

        Mock::given(method("DELETE"))
            .and(path("/pins/req-123"))
            .and(header_exists("user-agent"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;

        let client = IpfsPinningClient::new(server.uri(), None);
        client.delete_pin("req-123").await.unwrap();
    }
}

#[cfg(test)]
mod find_pin_tests {
    use super::*;
    use serde_json::json;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    #[tokio::test]
    async fn reconciles_pending_requests_on_later_pages_without_submitting_again() {
        let server = MockServer::start().await;
        let pin = |id: &str, created: &str, tag: &str| json!({"requestid":id,"created":created,"status":"queued","pin":{"cid":"bafy-test","name":"nftbk-local","meta":{"nftbk_pin_id":tag}}});
        Mock::given(method("GET"))
            .and(path("/pins"))
            .and(query_param("cid", "bafy-test"))
            .and(query_param("name", "nftbk-local"))
            .and(query_param("status", "queued,pinning,pinned,failed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"count":2,"results":[pin("unrelated","2026-10-23T12:00:00Z","other")]}),
            ))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/pins"))
            .and(query_param("before", "2026-10-23T12:00:00Z"))
            .and(query_param("status", "queued,pinning,pinned,failed"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"count":1,"results":[pin("remote-request","2026-10-22T12:00:00Z","local")]}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let client = IpfsPinningClient::new(server.uri(), None);
        let recovered = client
            .find_pin("bafy-test", "local")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(recovered.id, "remote-request");
        assert_eq!(recovered.status, PinResponseStatus::Queued);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}
