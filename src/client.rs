use anyhow::{Context, Result};
use reqwest::{Client as HttpClient, Method, Response};
use uuid::Uuid;

use crate::model::*;

pub struct Client {
    http: HttpClient,
    base_url: String,
    token: Option<String>,
}
impl Client {
    pub fn new(base_url: &str, token: Option<String>) -> Self {
        Self {
            http: HttpClient::new(),
            base_url: base_url.trim_end_matches('/').into(),
            token,
        }
    }
    pub fn http(&self) -> &HttpClient {
        &self.http
    }
    pub fn request(&self, method: Method, path: &str) -> reqwest::RequestBuilder {
        let request = self
            .http
            .request(method, format!("{}/v2{path}", self.base_url));
        if let Some(token) = &self.token {
            request.bearer_auth(token)
        } else {
            request
        }
    }
    pub async fn check(response: Response) -> Result<Response> {
        if response.status().is_success() {
            return Ok(response);
        }
        let status = response.status();
        let problem = response
            .json::<serde_json::Value>()
            .await
            .unwrap_or_default();
        anyhow::bail!(
            "{}: {}",
            status,
            problem["detail"]
                .as_str()
                .or_else(|| problem["error"].as_str())
                .unwrap_or("API request failed")
        )
    }
    pub async fn create(&self, request: &CreateBackup) -> Result<Backup> {
        Ok(Self::check(
            self.request(Method::POST, "/backups")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .json(request)
                .send()
                .await?,
        )
        .await?
        .json()
        .await?)
    }
    pub async fn get(&self, id: &str) -> Result<Backup> {
        Uuid::parse_str(id)?;
        Ok(Self::check(
            self.request(Method::GET, &format!("/backups/{id}"))
                .send()
                .await?,
        )
        .await?
        .json()
        .await?)
    }
    pub async fn list(&self) -> Result<Vec<Backup>> {
        let mut result = vec![];
        let mut cursor = None;
        loop {
            let mut request = self
                .request(Method::GET, "/backups")
                .query(&[("limit", "100")]);
            if let Some(cursor) = cursor {
                request = request.query(&[("cursor", cursor)]);
            }
            let page: Collection<Backup> = Self::check(request.send().await?).await?.json().await?;
            result.extend(page.data);
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        Ok(result)
    }
    pub async fn delete(&self, id: &str) -> Result<Operation> {
        Uuid::parse_str(id)?;
        Ok(Self::check(
            self.request(Method::DELETE, &format!("/backups/{id}"))
                .send()
                .await?,
        )
        .await?
        .json()
        .await?)
    }
    pub async fn download(&self, archive: &Archive) -> Result<Vec<u8>> {
        Ok(Self::check(
            self.request(Method::GET, &format!("/archives/{}/content", archive.id))
                .send()
                .await?,
        )
        .await?
        .bytes()
        .await?
        .to_vec())
    }
    pub async fn quote(&self, specification: &Specification) -> Result<Quote> {
        Ok(Self::check(
            self.request(Method::POST, "/quotes")
                .header("idempotency-key", Uuid::new_v4().to_string())
                .json(specification)
                .send()
                .await?,
        )
        .await?
        .json()
        .await?)
    }
    pub async fn get_quote(&self, id: &str) -> Result<Quote> {
        Self::check(
            self.request(Method::GET, &format!("/quotes/{id}"))
                .send()
                .await?,
        )
        .await?
        .json()
        .await
        .context("Invalid quote response")
    }
}
