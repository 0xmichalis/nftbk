use std::ops::RangeInclusive;

use axum::body::Body;
use axum::extract::{
    FromRequest, FromRequestParts, OriginalUri, Path, Query, Request, State as AxumState,
};
use axum::http::{header, request::Parts, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

use crate::server::api::{ApiProblem, ProblemJson};
use crate::server::billing;
use crate::server::database::r#trait::{Create, Creation, DatabaseError, Page};
use crate::server::model::*;
use crate::server::storage::{sign_download, verify_download, DownloadGrant};
use crate::server::AppState;

#[derive(Debug)]
pub struct ApiError(pub ApiProblem);
impl ApiError {
    pub fn internal(error: impl std::fmt::Display) -> Self {
        tracing::error!(%error,"API operation failed");
        problem(500, "internal_error", "The request could not be completed")
    }
}
impl From<DatabaseError> for ApiError {
    fn from(error: DatabaseError) -> Self {
        match error {
            DatabaseError::Capacity => {
                problem(503, "queue_full", "Work queue is at capacity; retry later")
            }
            DatabaseError::NotFound => problem(404, "not_found", "Resource not found"),
            DatabaseError::Conflict(message) => problem(409, "conflict", &message),
            DatabaseError::Invalid(message) => problem(422, "invalid_request", &message),
            DatabaseError::LostLease => problem(
                409,
                "lease_lost",
                "Operation is being resumed by another worker",
            ),
            DatabaseError::Storage(error) => Self::internal(error),
        }
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let unauthorized = self.0.status == 401;
        let unavailable = self.0.status == 503;
        let mut response = ProblemJson(self.0).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        if unavailable {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, "5".parse().unwrap());
        }
        if unauthorized {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().unwrap());
        }
        response
    }
}
pub fn problem(status: u16, code: &str, message: &str) -> ApiError {
    let mut problem = ApiProblem::new(
        StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        Some(message.into()),
        None,
    );
    problem.r#type = format!("urn:nftbk:problem:{code}");
    ApiError(problem)
}

pub struct ApiJson<T>(pub T);
impl<T: DeserializeOwned + Send> FromRequest<AppState> for ApiJson<T> {
    type Rejection = ApiError;
    async fn from_request(request: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let uri = request.uri().to_string();
        Json::<T>::from_request(request, state)
            .await
            .map(|Json(value)| Self(value))
            .map_err(|error| {
                let mut failure =
                    problem(error.status().as_u16(), "invalid_json", &error.body_text());
                failure.0.instance = Some(uri);
                failure
            })
    }
}
pub struct ApiPath<T>(pub T);
impl<T: DeserializeOwned + Send> FromRequestParts<AppState> for ApiPath<T> {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(value)| Self(value))
            .map_err(|_| problem(400, "invalid_path", "Invalid resource path"))
    }
}
pub struct ApiPage(pub Page);
impl FromRequestParts<AppState> for ApiPage {
    type Rejection = ApiError;
    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Query(mut page) = Query::<Page>::from_request_parts(parts, state)
            .await
            .map_err(|e| problem(400, "invalid_query", &e.body_text()))?;
        if page.limit.is_some_and(|v| !(1..=100).contains(&v)) {
            return Err(problem(
                422,
                "invalid_limit",
                "limit must be between 1 and 100",
            ));
        }
        if let Some(cursor) = &page.cursor {
            crate::server::database::decode_cursor(cursor)?;
        }
        for id in [&page.backup_id, &page.pin_set_id].into_iter().flatten() {
            validate_id(id)?;
        }
        if let Some(chain_id) = &page.chain_id {
            crate::chain::id::validate_chain_id(chain_id)
                .map_err(|e| problem(422, "invalid_chain_id", &e.to_string()))?;
        }
        if let Some(address) = &mut page.contract_address {
            if page
                .chain_id
                .as_ref()
                .is_some_and(|c| c.starts_with("eip155:"))
                || address.starts_with("0x")
            {
                let parsed: alloy::primitives::Address = address.parse().map_err(|_| {
                    problem(
                        422,
                        "invalid_contract_address",
                        "Invalid EVM contract address",
                    )
                })?;
                *address = format!("{parsed:#x}");
            }
        }
        if let Some(token_id) = &mut page.token_id {
            if token_id.is_empty() || !token_id.bytes().all(|b| b.is_ascii_digit()) {
                return Err(problem(
                    422,
                    "invalid_token_id",
                    "token_id must be a decimal string",
                ));
            }
            *token_id = token_id.trim_start_matches('0').to_string();
            if token_id.is_empty() {
                *token_id = "0".into();
            }
        }
        Ok(Self(page))
    }
}
pub fn validate_id(id: &str) -> Result<(), ApiError> {
    Uuid::parse_str(id)
        .map(|_| ())
        .map_err(|_| problem(400, "invalid_id", "Resource IDs must be UUIDs"))
}

fn key(headers: &HeaderMap, paid: bool) -> Result<String, ApiError> {
    match headers.get("idempotency-key") {
        Some(value) => {
            let value = value
                .to_str()
                .map_err(|_| problem(400, "invalid_idempotency_key", "Invalid Idempotency-Key"))?;
            if value.is_empty() || value.len() > 200 {
                return Err(problem(
                    400,
                    "invalid_idempotency_key",
                    "Idempotency-Key must contain 1 to 200 characters",
                ));
            }
            Ok(value.into())
        }
        None if paid => Err(problem(
            400,
            "idempotency_key_required",
            "An Idempotency-Key is required for a paid request",
        )),
        None => Ok(Uuid::new_v4().to_string()),
    }
}
fn hash(value: &impl serde::Serialize) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("request serialization"))
    )
}
fn normalize(state: &AppState, specification: &mut Specification) -> Result<(), ApiError> {
    specification
        .normalize(state.retention_days)
        .map_err(|e| problem(422, "invalid_specification", &e.to_string()))?;
    for nft in &specification.nfts {
        if !state.chain_config.0.contains_key(&nft.chain_id) {
            return Err(problem(
                422,
                "unsupported_chain",
                &format!("Chain {} is not configured", nft.chain_id),
            ));
        }
    }
    for output in &specification.outputs {
        match output {
            OutputRequest::Ipfs if state.providers.is_empty() => {
                return Err(problem(
                    422,
                    "pinning_unavailable",
                    "No IPFS providers are configured",
                ))
            }
            OutputRequest::Archive {
                retention_days: Some(days),
                ..
            } if *days > state.retention_days => {
                return Err(problem(
                    422,
                    "retention_unavailable",
                    "Requested retention exceeds this server's configured retention",
                ))
            }
            _ => {}
        }
    }
    Ok(())
}
fn redact_failures(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if let Some(message) = object.get_mut("error").and_then(|e| e.get_mut("message")) {
                if let Some(text) = message.as_str() {
                    *message = json!(crate::errors::redact_urls(text));
                }
            }
            for child in object.values_mut() {
                redact_failures(child);
            }
        }
        Value::Array(values) => {
            for child in values {
                redact_failures(child);
            }
        }
        _ => {}
    }
}
fn decorate(resource: Resource, mut value: Value) -> Value {
    redact_failures(&mut value);
    if let Some(id) = value["id"].as_str().map(str::to_owned) {
        let uri = if matches!(resource, Resource::Item) {
            format!(
                "/v2/backups/{}/items/{id}",
                value["backup_id"].as_str().unwrap_or("")
            )
        } else {
            format!("/v2/{}/{id}", resource.collection())
        };
        let mut links = json!({"self":uri});
        if let Some(operation) = value["operation_id"].as_str() {
            links["operation"] = json!(format!("/v2/operations/{operation}"));
        }
        if matches!(resource, Resource::Backup) {
            links["items"] = json!(format!("/v2/backups/{id}/items"));
            links["manifest"] = json!(format!("/v2/backups/{id}/manifest"));
        }
        if matches!(resource, Resource::Archive) {
            links["content"] = json!(format!("/v2/archives/{id}/content"));
        }
        if matches!(resource, Resource::Operation) {
            links["attempts"] = json!(format!("/v2/operations/{id}/attempts"));
        }
        value["links"] = links;
    }
    value
}
fn created(resource: Resource, value: Value, settlement: Option<String>) -> Response {
    let location = format!(
        "/v2/{}/{}",
        resource.collection(),
        value["id"].as_str().unwrap_or("")
    );
    let mut response = (StatusCode::CREATED, Json(decorate(resource, value))).into_response();
    response
        .headers_mut()
        .insert(header::LOCATION, location.parse().unwrap());
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    if let Some(settlement) = settlement {
        if let Ok(header) = settlement.parse() {
            response.headers_mut().insert("x-payment-response", header);
        }
    }
    response
}
async fn read(
    state: &AppState,
    owner: &str,
    resource: Resource,
    id: &str,
    headers: &HeaderMap,
) -> Result<Response, ApiError> {
    validate_id(id)?;
    let value = state
        .db
        .get(resource, owner, id)
        .await?
        .ok_or(DatabaseError::NotFound)?;
    Ok(representation(resource, value, headers))
}
fn representation(resource: Resource, value: Value, headers: &HeaderMap) -> Response {
    let value = decorate(resource, value);
    let etag = format!("\"{}\"", hash(&value));
    let mut response = if matches_etag(
        headers
            .get(header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok()),
        &etag,
    ) {
        StatusCode::NOT_MODIFIED.into_response()
    } else {
        Json(value).into_response()
    };
    response
        .headers_mut()
        .insert(header::ETAG, etag.parse().unwrap());
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "private, no-cache".parse().unwrap());
    response
}
fn matches_etag(header: Option<&str>, etag: &str) -> bool {
    header.is_some_and(|h| {
        h.split(',').any(|s| {
            let s = s.trim().strip_prefix("W/").unwrap_or(s.trim());
            s == etag || s == "*"
        })
    })
}
async fn listing(
    state: &AppState,
    owner: &str,
    resource: Resource,
    page: &Page,
) -> Result<Json<Collection<Value>>, ApiError> {
    if let Some(id) = &page.pin_set_id {
        if !matches!(resource, Resource::Pin) {
            return Err(problem(
                422,
                "invalid_filter",
                "pin_set_id filters the pins collection",
            ));
        }
        state
            .db
            .get(Resource::PinSet, owner, id)
            .await?
            .ok_or(DatabaseError::NotFound)?;
    }
    if page.ipfs_only.is_some() && !matches!(resource, Resource::Item) {
        return Err(problem(
            422,
            "invalid_filter",
            "ipfs_only filters backup items",
        ));
    }
    let mut collection = state.db.list(resource, owner, page).await?;
    collection.data = collection
        .data
        .into_iter()
        .map(|v| decorate(resource, v))
        .collect();
    Ok(Json(collection))
}

#[utoipa::path(post,path="/v2/backups",request_body=CreateBackup,responses((status=201,body=Backup),(status=402,description="x402 payment required"),(status=409,body=ApiProblem),(status=422,body=ApiProblem)),security(("bearer_auth"=[])))]
pub async fn create_backup(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<CreateBackup>,
) -> Result<Response, ApiError> {
    let mut specification = Specification {
        nfts: request.nfts,
        outputs: request.outputs,
    };
    normalize(&state, &mut specification)?;
    if let Some(id) = &request.quote_id {
        validate_id(id)?;
    }
    let payload_hash = hash(&json!({"specification":specification,"quote_id":request.quote_id}));
    let value = state
        .db
        .create(Create {
            owner_id: owner.clone(),
            key: key(&headers, state.x402_config.is_some())?,
            payload_hash,
            resource: Resource::Backup,
            creation: Creation::Backup {
                specification,
                quote_id: request.quote_id,
                pricing_version: state
                    .x402_config
                    .as_ref()
                    .map(|_| state.pricing_version.clone()),
                provider_ids: state.providers.keys().cloned().collect(),
            },
        })
        .await?;
    let id = value["id"]
        .as_str()
        .ok_or_else(|| problem(500, "internal_error", "Missing backup ID"))?;
    let settlement = match billing::pay(&state, Resource::Backup, &owner, id, &headers).await {
        Ok(value) => value,
        Err(mut response) => {
            response.headers_mut().insert(
                header::LOCATION,
                format!("/v2/backups/{id}").parse().unwrap(),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
            return Ok(response);
        }
    };
    let current = state
        .db
        .get(Resource::Backup, &owner, id)
        .await?
        .ok_or(DatabaseError::NotFound)?;
    Ok(created(Resource::Backup, current, settlement))
}

#[utoipa::path(get,path="/v2/backups",params(Page),responses((status=200,body=Collection<Backup>)),security(("bearer_auth"=[])))]
pub async fn list_backups(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPage(page): ApiPage,
) -> Result<Json<Collection<Value>>, ApiError> {
    listing(&state, &owner, Resource::Backup, &page).await
}
#[utoipa::path(get,path="/v2/backups/{id}",params(("id"=String,Path,description="Resource UUID")),responses((status=200,body=Backup),(status=304)),security(("bearer_auth"=[])))]
pub async fn get_backup(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    read(&state, &owner, Resource::Backup, &id, &headers).await
}
#[utoipa::path(get,path="/v2/backups/{id}/items",params(("id"=String,Path,description="Resource UUID"),Page),responses((status=200,body=Collection<Item>)),security(("bearer_auth"=[])))]
pub async fn list_items(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
    ApiPage(mut page): ApiPage,
) -> Result<Json<Collection<Value>>, ApiError> {
    validate_id(&id)?;
    state
        .db
        .get(Resource::Backup, &owner, &id)
        .await?
        .ok_or(DatabaseError::NotFound)?;
    page.backup_id = Some(id);
    listing(&state, &owner, Resource::Item, &page).await
}
#[utoipa::path(get,path="/v2/backups/{id}/items/{item_id}",params(("id"=String,Path,description="Snapshot UUID"),("item_id"=String,Path,description="Item UUID")),responses((status=200,body=Item)),security(("bearer_auth"=[])))]
pub async fn get_item(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath((backup_id, id)): ApiPath<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_id(&backup_id)?;
    validate_id(&id)?;
    let value = state
        .db
        .get(Resource::Item, &owner, &id)
        .await?
        .filter(|v| v["backup_id"] == backup_id)
        .ok_or(DatabaseError::NotFound)?;
    Ok(representation(Resource::Item, value, &headers))
}
#[utoipa::path(get,path="/v2/pins/{id}",params(("id"=String,Path,description="Pin UUID")),responses((status=200,body=Pin)),security(("bearer_auth"=[])))]
pub async fn get_pin(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    read(&state, &owner, Resource::Pin, &id, &headers).await
}
#[utoipa::path(get,path="/v2/backups/{id}/manifest",params(("id"=String,Path,description="Resource UUID")),responses((status=200,body=Manifest)),security(("bearer_auth"=[])))]
pub async fn manifest(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    validate_id(&id)?;
    let backup: Backup = serde_json::from_value(
        state
            .db
            .get(Resource::Backup, &owner, &id)
            .await?
            .ok_or(DatabaseError::NotFound)?,
    )
    .map_err(ApiError::internal)?;
    if backup.state == State::Deleted {
        return Err(problem(
            410,
            "backup_deleted",
            "Backup data has been deleted",
        ));
    }
    if let Some(digest) = backup.manifest_sha256 {
        let etag = format!("\"{digest}\"");
        if matches_etag(
            headers
                .get(header::IF_NONE_MATCH)
                .and_then(|h| h.to_str().ok()),
            &etag,
        ) {
            return Ok((
                StatusCode::NOT_MODIFIED,
                [
                    (header::ETAG, etag),
                    (header::CACHE_CONTROL, "private, no-cache".into()),
                ],
            )
                .into_response());
        }
        let bytes = state
            .storage
            .read(&digest)
            .await
            .map_err(ApiError::internal)?;
        return Ok((
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "private, no-cache"),
                (header::ETAG, &format!("\"{digest}\"")),
            ],
            bytes,
        )
            .into_response());
    }
    if backup.provenance == "legacy" {
        return Ok(Json(Manifest {
            version: 2,
            backup_id: id.clone(),
            created_at: backup.created_at,
            provenance: backup.provenance,
            items: all_items(&state, &owner, &id).await?,
        })
        .into_response());
    }
    Err(problem(
        409,
        "manifest_pending",
        "The snapshot has not been sealed",
    ))
}
async fn all_items(state: &AppState, owner: &str, backup_id: &str) -> Result<Vec<Item>, ApiError> {
    validate_id(backup_id)?;
    state
        .db
        .get(Resource::Backup, owner, backup_id)
        .await?
        .ok_or(DatabaseError::NotFound)?;
    let mut page = Page {
        backup_id: Some(backup_id.into()),
        limit: Some(100),
        ..Page::default()
    };
    let mut items = vec![];
    loop {
        let batch = state.db.list(Resource::Item, owner, &page).await?;
        for item in batch.data {
            items.push(serde_json::from_value(item).map_err(ApiError::internal)?);
        }
        page.cursor = batch.next_cursor;
        if page.cursor.is_none() {
            break;
        }
    }
    Ok(items)
}
async fn output_specification(
    state: &AppState,
    owner: &str,
    backup_id: &str,
    outputs: Vec<OutputRequest>,
) -> Result<Specification, ApiError> {
    let items = all_items(state, owner, backup_id).await?;
    if outputs
        .iter()
        .any(|o| matches!(o, OutputRequest::Archive { .. }))
        && items
            .iter()
            .flat_map(|i| &i.assets)
            .any(|a| a.state == State::Ready && a.sha256.is_none())
    {
        return Err(problem(409,"source_unavailable","This snapshot has assets without retained bytes; request a fresh snapshot with an archive output"));
    }
    let mut specification = Specification {
        nfts: items.into_iter().map(|i| i.nft).collect(),
        outputs,
    };
    normalize(state, &mut specification)?;
    Ok(specification)
}
async fn create_output(
    state: &AppState,
    owner: &str,
    resource: Resource,
    backup_id: String,
    output: OutputRequest,
    quote_id: Option<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(id) = &quote_id {
        validate_id(id)?;
    }
    let specification = output_specification(state, owner, &backup_id, vec![output]).await?;
    let output = specification.outputs[0].clone();
    let specification_hash = specification.hash();
    let value = state
        .db
        .create(Create {
            owner_id: owner.into(),
            key: key(&headers, state.x402_config.is_some())?,
            payload_hash: hash(
                &json!({"specification":specification,"backup_id":backup_id,"quote_id":quote_id}),
            ),
            resource,
            creation: Creation::Output {
                backup_id,
                output,
                provider_ids: state.providers.keys().cloned().collect(),
                quote_id,
                pricing_version: state
                    .x402_config
                    .as_ref()
                    .map(|_| state.pricing_version.clone()),
                specification_hash,
            },
        })
        .await?;
    let id = value["id"]
        .as_str()
        .ok_or_else(|| problem(500, "internal_error", "Missing output ID"))?;
    let settlement = match billing::pay(state, resource, owner, id, &headers).await {
        Ok(value) => value,
        Err(mut response) => {
            response.headers_mut().insert(
                header::LOCATION,
                format!("/v2/{}/{id}", resource.collection())
                    .parse()
                    .unwrap(),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
            return Ok(response);
        }
    };
    Ok(created(
        resource,
        state
            .db
            .get(resource, owner, id)
            .await?
            .ok_or(DatabaseError::NotFound)?,
        settlement,
    ))
}
#[utoipa::path(post,path="/v2/archives",request_body=CreateArchive,responses((status=201,body=Archive)),security(("bearer_auth"=[])))]
pub async fn create_archive(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<CreateArchive>,
) -> Result<Response, ApiError> {
    create_output(
        &state,
        &owner,
        Resource::Archive,
        request.backup_id,
        OutputRequest::Archive {
            format: request.format,
            retention_days: request.retention_days,
        },
        request.quote_id,
        headers,
    )
    .await
}
#[utoipa::path(post,path="/v2/pin-sets",request_body=CreatePinSet,responses((status=201,body=PinSet)),security(("bearer_auth"=[])))]
pub async fn create_pin_set(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<CreatePinSet>,
) -> Result<Response, ApiError> {
    create_output(
        &state,
        &owner,
        Resource::PinSet,
        request.backup_id,
        OutputRequest::Ipfs,
        request.quote_id,
        headers,
    )
    .await
}
#[utoipa::path(get,path="/v2/archives",params(Page),responses((status=200,body=Collection<Archive>)),security(("bearer_auth"=[])))]
pub async fn list_archives(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPage(page): ApiPage,
) -> Result<Json<Collection<Value>>, ApiError> {
    listing(&state, &owner, Resource::Archive, &page).await
}
#[utoipa::path(get,path="/v2/pin-sets",params(Page),responses((status=200,body=Collection<PinSet>)),security(("bearer_auth"=[])))]
pub async fn list_pin_sets(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPage(page): ApiPage,
) -> Result<Json<Collection<Value>>, ApiError> {
    listing(&state, &owner, Resource::PinSet, &page).await
}
#[utoipa::path(get,path="/v2/pins",params(Page),responses((status=200,body=Collection<Pin>)),security(("bearer_auth"=[])))]
pub async fn list_pins(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPage(page): ApiPage,
) -> Result<Json<Collection<Value>>, ApiError> {
    listing(&state, &owner, Resource::Pin, &page).await
}
#[utoipa::path(get,path="/v2/archives/{id}",params(("id"=String,Path,description="Resource UUID")),responses((status=200,body=Archive)),security(("bearer_auth"=[])))]
pub async fn get_archive(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    read(&state, &owner, Resource::Archive, &id, &headers).await
}
#[utoipa::path(get,path="/v2/pin-sets/{id}",params(("id"=String,Path,description="Resource UUID")),responses((status=200,body=PinSet)),security(("bearer_auth"=[])))]
pub async fn get_pin_set(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    read(&state, &owner, Resource::PinSet, &id, &headers).await
}

#[utoipa::path(post,path="/v2/quotes",request_body=QuoteRequest,responses((status=201,body=Quote)),security(("bearer_auth"=[])))]
pub async fn create_quote(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<QuoteRequest>,
) -> Result<Response, ApiError> {
    let (mut specification, backup_id) = match request {
        QuoteRequest::Capture(spec) => (spec, None),
        QuoteRequest::Output(input) => {
            if input.outputs.len() != 1 {
                return Err(problem(
                    422,
                    "invalid_outputs",
                    "Quote one additional output at a time",
                ));
            }
            (
                output_specification(&state, &owner, &input.backup_id, input.outputs).await?,
                Some(input.backup_id),
            )
        }
    };
    normalize(&state, &mut specification)?;
    let payload_hash = hash(&json!({"specification":specification,"backup_id":backup_id}));
    let value = state
        .db
        .create(Create {
            owner_id: owner,
            key: key(&headers, false)?,
            payload_hash,
            resource: Resource::Quote,
            creation: Creation::Quote {
                specification,
                terms: billing::terms(&state)?,
                backup_id,
            },
        })
        .await?;
    Ok(created(Resource::Quote, value, None))
}
#[utoipa::path(get,path="/v2/quotes",params(Page),responses((status=200,body=Collection<Quote>)),security(("bearer_auth"=[])))]
pub async fn list_quotes(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPage(page): ApiPage,
) -> Result<Json<Collection<Value>>, ApiError> {
    listing(&state, &owner, Resource::Quote, &page).await
}
#[utoipa::path(get,path="/v2/operations",params(Page),responses((status=200,body=Collection<Operation>)),security(("bearer_auth"=[])))]
pub async fn list_operations(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPage(page): ApiPage,
) -> Result<Json<Collection<Value>>, ApiError> {
    listing(&state, &owner, Resource::Operation, &page).await
}
#[utoipa::path(get,path="/v2/quotes/{id}",params(("id"=String,Path,description="Resource UUID")),responses((status=200,body=Quote)),security(("bearer_auth"=[])))]
pub async fn get_quote(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    read(&state, &owner, Resource::Quote, &id, &headers).await
}
#[utoipa::path(get,path="/v2/operations/{id}",params(("id"=String,Path,description="Resource UUID")),responses((status=200,body=Operation)),security(("bearer_auth"=[])))]
pub async fn get_operation(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    read(&state, &owner, Resource::Operation, &id, &headers).await
}
#[utoipa::path(get,path="/v2/operations/{id}/attempts",params(("id"=String,Path,description="Resource UUID")),responses((status=200,body=Vec<Attempt>)),security(("bearer_auth"=[])))]
pub async fn attempts(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
) -> Result<Json<Vec<Attempt>>, ApiError> {
    validate_id(&id)?;
    Ok(Json(state.db.attempts(&owner, &id).await?))
}
#[utoipa::path(post,path="/v2/operations/{id}/attempts",params(("id"=String,Path,description="Resource UUID")),responses((status=201,body=Attempt)),security(("bearer_auth"=[])))]
pub async fn retry(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
) -> Result<Response, ApiError> {
    validate_id(&id)?;
    let attempt = state.db.retry(&owner, &id).await?;
    let location = format!("/v2/operations/{id}/attempts/{}", attempt.number);
    Ok((
        StatusCode::CREATED,
        [
            (header::LOCATION, location),
            (header::CACHE_CONTROL, "no-store".into()),
        ],
        Json(attempt),
    )
        .into_response())
}
#[utoipa::path(get,path="/v2/operations/{id}/attempts/{number}",params(("id"=String,Path,description="Resource UUID"),("number"=u32,Path,description="Attempt number")),responses((status=200,body=Attempt)),security(("bearer_auth"=[])))]
pub async fn get_attempt(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath((id, number)): ApiPath<(String, u32)>,
) -> Result<Json<Attempt>, ApiError> {
    validate_id(&id)?;
    state
        .db
        .attempts(&owner, &id)
        .await?
        .into_iter()
        .find(|a| a.number == number)
        .map(Json)
        .ok_or_else(|| DatabaseError::NotFound.into())
}
async fn deletion(
    state: &AppState,
    owner: &str,
    resource: Resource,
    id: &str,
) -> Result<Response, ApiError> {
    validate_id(id)?;
    let operation = state.db.delete(resource, owner, id).await?;
    let location = format!("/v2/operations/{}", operation.id);
    Ok((
        StatusCode::ACCEPTED,
        [
            (header::LOCATION, location),
            (header::CACHE_CONTROL, "no-store".into()),
        ],
        Json(decorate(Resource::Operation, json!(operation))),
    )
        .into_response())
}
#[utoipa::path(delete,path="/v2/backups/{id}",params(("id"=String,Path,description="Resource UUID")),responses((status=202,body=Operation)),security(("bearer_auth"=[])))]
pub async fn delete_backup(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
) -> Result<Response, ApiError> {
    deletion(&state, &owner, Resource::Backup, &id).await
}
#[utoipa::path(delete,path="/v2/archives/{id}",params(("id"=String,Path,description="Resource UUID")),responses((status=202,body=Operation)),security(("bearer_auth"=[])))]
pub async fn delete_archive(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
) -> Result<Response, ApiError> {
    deletion(&state, &owner, Resource::Archive, &id).await
}
#[utoipa::path(delete,path="/v2/pin-sets/{id}",params(("id"=String,Path,description="Resource UUID")),responses((status=202,body=Operation)),security(("bearer_auth"=[])))]
pub async fn delete_pin_set(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
) -> Result<Response, ApiError> {
    deletion(&state, &owner, Resource::PinSet, &id).await
}

#[utoipa::path(post,path="/v2/archives/{id}/download-links",params(("id"=String,Path,description="Resource UUID")),responses((status=201,description="A signed download URL and its expiration")),security(("bearer_auth"=[])))]
pub async fn download_link(
    AxumState(state): AxumState<AppState>,
    Extension(owner): Extension<String>,
    ApiPath(id): ApiPath<String>,
) -> Result<Response, ApiError> {
    validate_id(&id)?;
    let archive: Archive = serde_json::from_value(
        state
            .db
            .get(Resource::Archive, &owner, &id)
            .await?
            .ok_or(DatabaseError::NotFound)?,
    )
    .map_err(ApiError::internal)?;
    if !matches!(archive.state, State::Ready | State::Partial) {
        return Err(problem(
            409,
            "archive_unavailable",
            "Archive is not available for download",
        ));
    }
    let expires_at = Utc::now() + chrono::Duration::minutes(10);
    let token = sign_download(
        &state.download_key,
        &DownloadGrant {
            archive_id: id.clone(),
            owner_id: owner,
            expires_at,
        },
    )
    .map_err(ApiError::internal)?;
    let url = format!("/v2/archives/{id}/content?grant={token}");
    Ok((
        StatusCode::CREATED,
        [
            (header::LOCATION, url.clone()),
            (header::CACHE_CONTROL, "no-store".into()),
        ],
        Json(json!({"url":url,"expires_at":expires_at})),
    )
        .into_response())
}
#[derive(Deserialize, Default)]
pub struct DownloadQuery {
    pub grant: Option<String>,
}
#[utoipa::path(get,path="/v2/archives/{id}/content",params(("id"=String,Path,description="Resource UUID")),responses((status=200,description="Archive bytes"),(status=206,description="Requested byte range"),(status=416,description="Invalid byte range")))]
pub async fn content(
    AxumState(state): AxumState<AppState>,
    ApiPath(id): ApiPath<String>,
    Query(query): Query<DownloadQuery>,
    headers: HeaderMap,
    method: axum::http::Method,
) -> Result<Response, ApiError> {
    validate_id(&id)?;
    let owner = if let Some(grant) = query.grant {
        verify_download(&state.download_key, &grant, &id)
            .map_err(|_| {
                problem(
                    401,
                    "invalid_download_grant",
                    "Invalid or expired download grant",
                )
            })?
            .owner_id
    } else {
        crate::server::router::authenticate(&state, &headers).await?
    };
    let archive: Archive = serde_json::from_value(
        state
            .db
            .get(Resource::Archive, &owner, &id)
            .await?
            .ok_or(DatabaseError::NotFound)?,
    )
    .map_err(ApiError::internal)?;
    if archive.expires_at.is_some_and(|t| t <= Utc::now())
        || matches!(archive.state, State::Expired | State::Deleted)
    {
        return Err(problem(
            410,
            "archive_expired",
            "Archive is no longer retained",
        ));
    }
    if !matches!(archive.state, State::Ready | State::Partial) {
        return Err(problem(409, "archive_pending", "Archive is not ready"));
    }
    // Legacy locations remain usable after migration; new artifacts are addressed by digest.
    let path = if let Some(digest) = &archive.sha256 {
        state.storage.blob_path(digest)
    } else {
        let legacy = state.db.archive_storage(&owner, &id).await?;
        state.storage.path(&legacy)
    }
    .map_err(ApiError::internal)?;
    let metadata = tokio::fs::metadata(&path)
        .await
        .map_err(|_| problem(404, "content_unavailable", "Archive bytes are unavailable"))?;
    let size = metadata.len();
    let digest = if let Some(digest) = archive.sha256.clone() {
        if !state.unsafe_skip_checksum_check
            && crate::server::hashing::compute_file_sha256(&path)
                .await
                .map_err(ApiError::internal)?
                != digest
        {
            return Err(problem(
                500,
                "integrity_failure",
                "Archive failed its integrity check",
            ));
        }
        digest
    } else {
        crate::server::hashing::compute_file_sha256(&path)
            .await
            .map_err(ApiError::internal)?
    };
    let etag = format!("\"{digest}\"");
    if matches_etag(
        headers
            .get(header::IF_NONE_MATCH)
            .and_then(|h| h.to_str().ok()),
        &etag,
    ) {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, etag)]).into_response());
    }
    let range = if headers
        .get(header::IF_RANGE)
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v == etag)
    {
        headers.get(header::RANGE).and_then(|h| h.to_str().ok())
    } else {
        None
    };
    let parsed = match range {
        None => None,
        Some(value) => match byte_range(value, size) {
            Ok(value) => Some(value),
            Err(error) => {
                let mut response = error.into_response();
                response.headers_mut().insert(
                    header::CONTENT_RANGE,
                    format!("bytes */{size}").parse().unwrap(),
                );
                return Ok(response);
            }
        },
    };
    let (start, length, status) = if let Some(range) = &parsed {
        (
            *range.start(),
            range.end() - range.start() + 1,
            StatusCode::PARTIAL_CONTENT,
        )
    } else {
        (0, size, StatusCode::OK)
    };
    let body = if method == axum::http::Method::HEAD {
        Body::empty()
    } else {
        let mut file = tokio::fs::File::open(&path)
            .await
            .map_err(ApiError::internal)?;
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(ApiError::internal)?;
        Body::from_stream(ReaderStream::new(file.take(length)))
    };
    let mut response = (status, body).into_response();
    let output = response.headers_mut();
    output.insert(
        header::CONTENT_TYPE,
        archive.format.content_type().parse().unwrap(),
    );
    output.insert(header::CONTENT_LENGTH, length.to_string().parse().unwrap());
    output.insert(header::ETAG, etag.parse().unwrap());
    output.insert(header::ACCEPT_RANGES, "bytes".parse().unwrap());
    output.insert(header::CACHE_CONTROL, "private, no-cache".parse().unwrap());
    output.insert(
        header::CONTENT_DISPOSITION,
        format!(
            "attachment; filename=\"nftbk-{}.{}\"",
            archive.id,
            archive.format.as_str()
        )
        .parse()
        .unwrap(),
    );
    if let Some(range) = parsed {
        output.insert(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{size}", range.start(), range.end())
                .parse()
                .unwrap(),
        );
    }
    Ok(response)
}
pub fn byte_range(value: &str, size: u64) -> Result<RangeInclusive<u64>, ApiError> {
    let range = value
        .strip_prefix("bytes=")
        .ok_or_else(|| problem(416, "invalid_range", "Only byte ranges are supported"))?;
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| problem(416, "invalid_range", "Invalid byte range"))?;
    if size == 0 {
        return Err(problem(416, "invalid_range", "Empty content has no ranges"));
    }
    let number = |value: &str| {
        value
            .parse::<u64>()
            .map_err(|_| problem(416, "invalid_range", "Invalid byte range"))
    };
    if start.is_empty() {
        let suffix = number(end)?;
        if suffix == 0 {
            return Err(problem(416, "invalid_range", "Suffix must be positive"));
        }
        return Ok(size.saturating_sub(suffix)..=size - 1);
    }
    let start = number(start)?;
    let end = if end.is_empty() {
        size - 1
    } else {
        number(end)?.min(size - 1)
    };
    if start >= size || end < start {
        return Err(problem(416, "invalid_range", "Range is outside content"));
    }
    Ok(start..=end)
}
pub async fn not_found(OriginalUri(uri): OriginalUri) -> Response {
    let mut error = problem(404, "not_found", "API resource not found");
    error.0.instance = Some(uri.to_string());
    error.into_response()
}
pub async fn method_not_allowed() -> Response {
    problem(
        405,
        "method_not_allowed",
        "Method not allowed for this resource",
    )
    .into_response()
}

#[cfg(test)]
mod byte_range_tests {
    use super::*;
    #[test]
    fn handles_resumable_suffix_and_open_ended_downloads() {
        assert_eq!(byte_range("bytes=2-5", 10).unwrap(), 2..=5);
        assert_eq!(byte_range("bytes=5-", 10).unwrap(), 5..=9);
        assert_eq!(byte_range("bytes=-3", 10).unwrap(), 7..=9);
        assert_eq!(byte_range("bytes=-20", 10).unwrap(), 0..=9);
        for invalid in [
            "bytes=10-",
            "bytes=8-2",
            "bytes=0-1,4-5",
            "bytes=-0",
            "items=0-2",
        ] {
            assert!(byte_range(invalid, 10).is_err());
        }
    }
}
