use axum::{
    extract::{Extension, Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashSet;
use tracing::{debug, error, info};
use utoipa::ToSchema;

use crate::server::api::{BackupResponse, Tokens};
use crate::server::db::Db;
use crate::server::hashing::compute_task_id;
use crate::server::{AppState, BackupJob, BackupJobOrShutdown, StorageMode};

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct PinRequest {
    /// List of tokens to pin, organized by blockchain
    pub tokens: Vec<Tokens>,
}

fn validate_pin_request_impl(
    chain_config: &crate::backup::ChainConfig,
    ipfs_providers_len: usize,
    req: &PinRequest,
) -> Result<(), String> {
    // Validate IPFS providers are configured
    if ipfs_providers_len == 0 {
        return Err("No IPFS providers configured".to_string());
    }

    // Validate requested chains
    let configured_chains: HashSet<_> = chain_config.0.keys().cloned().collect();
    let mut unknown_chains = Vec::new();
    for entry in &req.tokens {
        if !configured_chains.contains(&entry.chain) {
            unknown_chains.push(entry.chain.clone());
        }
    }
    if !unknown_chains.is_empty() {
        let msg = format!("Unknown chains requested: {}", unknown_chains.join(", "));
        return Err(msg);
    }

    Ok(())
}

fn validate_pin_request(state: &AppState, req: &PinRequest) -> Result<(), String> {
    validate_pin_request_impl(&state.chain_config, state.ipfs_providers.len(), req)
}

// A minimal trait to enable mocking DB calls for unit tests of this handler
pub trait PinDb {
    fn get_backup_status<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<String>, sqlx::Error>> + Send + 'a>,
    >;

    #[allow(clippy::too_many_arguments)]
    fn insert_protection_job<'a>(
        &'a self,
        task_id: &'a str,
        requestor: &'a str,
        nft_count: i32,
        tokens: &'a serde_json::Value,
        storage_mode: &'a str,
        archive_format: Option<&'a str>,
        retention_days: Option<u64>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>;
}

impl PinDb for Db {
    fn get_backup_status<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<String>, sqlx::Error>> + Send + 'a>,
    > {
        Box::pin(async move { Db::get_backup_status(self, task_id).await })
    }

    fn insert_protection_job<'a>(
        &'a self,
        task_id: &'a str,
        requestor: &'a str,
        nft_count: i32,
        tokens: &'a serde_json::Value,
        storage_mode: &'a str,
        archive_format: Option<&'a str>,
        retention_days: Option<u64>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
    {
        Box::pin(async move {
            Db::insert_protection_job(
                self,
                task_id,
                requestor,
                nft_count,
                tokens,
                storage_mode,
                archive_format,
                retention_days,
            )
            .await
        })
    }
}

async fn handle_create_pins_core<DB: PinDb + ?Sized>(
    db: &DB,
    backup_job_sender: &tokio::sync::mpsc::Sender<BackupJobOrShutdown>,
    requestor: Option<String>,
    req: PinRequest,
) -> axum::response::Response {
    // Convert PinRequest to BackupRequest format for task_id computation
    let backup_req_for_hash = crate::server::api::BackupRequest {
        tokens: req.tokens.clone(),
        pin_on_ipfs: true, // Always true for this endpoint
    };
    let task_id = compute_task_id(&backup_req_for_hash.tokens, requestor.as_deref());

    // Check if task already exists
    if let Ok(Some(status)) = db.get_backup_status(&task_id).await {
        match status.as_str() {
            "in_progress" => {
                debug!(
                    "Duplicate pin request, returning existing task_id {}",
                    task_id
                );
                return (StatusCode::OK, Json(BackupResponse { task_id })).into_response();
            }
            "done" => {
                debug!(
                    "Pin task already completed, returning existing task_id {}",
                    task_id
                );
                return (StatusCode::OK, Json(BackupResponse { task_id })).into_response();
            }
            "error" | "expired" => {
                return (
                    StatusCode::CONFLICT,
            Json(serde_json::json!({
                        "error": format!("Pin task in status {status} cannot be (re)started from /v1/pins. Use the provided retry URL to re-run this task."),
                        "retry_url":  format!("/v1/backups/{task_id}/retry"),
                        "task_id": task_id
                    })),
                )
                    .into_response();
            }
            other => {
                error!(
                    "Unknown status '{}' for task {} when handling /pins",
                    other, task_id
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Unknown task status"})),
                )
                    .into_response();
            }
        }
    }

    // Write metadata to DB (IPFS mode, no archive_format, no retention)
    let nft_count = req.tokens.iter().map(|t| t.tokens.len()).sum::<usize>() as i32;
    let tokens_json = serde_json::to_value(&req.tokens).unwrap();
    if let Err(e) = db
        .insert_protection_job(
            &task_id,
            requestor.as_deref().unwrap_or(""),
            nft_count,
            &tokens_json,
            "ipfs",
            None, // No archive format for IPFS-only
            None, // No retention for IPFS-only
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to write metadata to DB: {}", e)})),
        )
            .into_response();
    }

    // Create backup job with IPFS-only storage mode
    let backup_job = BackupJob {
        task_id: task_id.clone(),
        request: backup_req_for_hash,
        force: false,
        storage_mode: StorageMode::Ipfs,
        archive_format: None,
        requestor: requestor.clone(),
    };

    if let Err(e) = backup_job_sender
        .send(BackupJobOrShutdown::Job(backup_job))
        .await
    {
        error!("Failed to enqueue pin job: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to enqueue pin job"})),
        )
            .into_response();
    }

    info!("Created protection job: {task_id} for {} tokens", nft_count);
    // Canonical Location is the task; clients can derive pin filters
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::LOCATION,
        format!("/v1/backups/{task_id}").parse().unwrap(),
    );
    (
        StatusCode::ACCEPTED,
        headers,
        Json(BackupResponse { task_id }),
    )
        .into_response()
}

#[utoipa::path(
    post,
    path = "/v1/pins",
    request_body = PinRequest,
    responses(
        (status = 202, description = "Pin task accepted and queued", body = BackupResponse),
        (status = 200, description = "Pin task already exists or in progress", body = BackupResponse),
        (status = 400, description = "Invalid request", body = serde_json::Value),
        (status = 409, description = "Task exists in error/expired state", body = serde_json::Value),
        (status = 500, description = "Internal server error", body = serde_json::Value),
    ),
    tag = "pins",
    security(("bearer_auth" = []))
)]
pub async fn handle_create_pins(
    State(state): State<AppState>,
    Extension(requestor): Extension<Option<String>>,
    Json(req): Json<PinRequest>,
) -> axum::response::Response {
    if let Err(msg) = validate_pin_request(&state, &req) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response();
    }

    handle_create_pins_core(&*state.db, &state.backup_job_sender, requestor, req).await
}

#[cfg(test)]
mod handle_create_pins_tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::response::IntoResponse;
    use tokio::sync::mpsc;

    #[derive(Clone, Default)]
    struct MockDb {
        status: Option<String>,
        inserted: std::sync::Arc<std::sync::Mutex<bool>>,
    }

    impl PinDb for MockDb {
        fn get_backup_status<'a>(
            &'a self,
            _task_id: &'a str,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<Option<String>, sqlx::Error>> + Send + 'a>,
        > {
            let status = self.status.clone();
            Box::pin(async move { Ok(status) })
        }

        fn insert_protection_job<'a>(
            &'a self,
            _task_id: &'a str,
            _requestor: &'a str,
            _nft_count: i32,
            _tokens: &'a serde_json::Value,
            storage_mode: &'a str,
            archive_format: Option<&'a str>,
            retention_days: Option<u64>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
        {
            let flag = self.inserted.clone();
            // Verify IPFS-only parameters
            assert_eq!(storage_mode, "ipfs");
            assert!(archive_format.is_none());
            assert!(retention_days.is_none());
            Box::pin(async move {
                *flag.lock().unwrap() = true;
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn returns_202_and_enqueues_on_new_pin_task() {
        let db = MockDb::default();
        let (tx, mut rx) = mpsc::channel(1);
        let req = PinRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string(), "0xdef:2".to_string()],
            }],
        };

        let resp = handle_create_pins_core(&db, &tx, None, req)
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        // Assert Location header equals the URL derived from response body task_id
        let location = resp
            .headers()
            .get(axum::http::header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let body_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        let task_id = v.get("task_id").and_then(|t| t.as_str()).unwrap();
        assert_eq!(location, format!("/v1/backups/{task_id}"));

        // Ensure job enqueued
        let msg = rx.try_recv();
        assert!(msg.is_ok());

        // Verify DB insert happened
        assert!(*db.inserted.lock().unwrap());
    }

    #[tokio::test]
    async fn returns_200_when_pin_task_in_progress() {
        let db = MockDb {
            status: Some("in_progress".to_string()),
            inserted: Default::default(),
        };
        let (tx, _rx) = mpsc::channel(1);
        let req = PinRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
        };

        let resp = handle_create_pins_core(&db, &tx, None, req)
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);

        // Should not insert a new row
        assert!(!*db.inserted.lock().unwrap());
    }

    #[tokio::test]
    async fn returns_200_when_pin_task_done() {
        let db = MockDb {
            status: Some("done".to_string()),
            inserted: Default::default(),
        };
        let (tx, _rx) = mpsc::channel(1);
        let req = PinRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
        };

        let resp = handle_create_pins_core(&db, &tx, None, req)
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::OK);

        // Should not insert a new row
        assert!(!*db.inserted.lock().unwrap());
    }

    #[tokio::test]
    async fn returns_409_when_pin_task_in_error() {
        let db = MockDb {
            status: Some("error".to_string()),
            inserted: Default::default(),
        };
        let (tx, _rx) = mpsc::channel(1);
        let req = PinRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
        };

        let resp = handle_create_pins_core(&db, &tx, None, req)
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // Should not insert a new row
        assert!(!*db.inserted.lock().unwrap());
    }

    #[tokio::test]
    async fn returns_409_when_pin_task_expired() {
        let db = MockDb {
            status: Some("expired".to_string()),
            inserted: Default::default(),
        };
        let (tx, _rx) = mpsc::channel(1);
        let req = PinRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
        };

        let resp = handle_create_pins_core(&db, &tx, None, req)
            .await
            .into_response();

        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // Should not insert a new row
        assert!(!*db.inserted.lock().unwrap());
    }
}
