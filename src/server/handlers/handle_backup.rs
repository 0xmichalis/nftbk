use axum::{
    extract::{Extension, Json, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json;
use std::collections::HashSet;
use tracing::{debug, error, info};

use crate::server::api::{ApiProblem, BackupRequest, BackupResponse, ProblemJson};
use crate::server::archive::negotiate_archive_format;
use crate::server::db::Db;
use crate::server::hashing::compute_task_id;
use crate::server::{AppState, BackupTask, BackupTaskOrShutdown, StorageMode, TaskType};

fn derive_status(meta: &crate::server::db::BackupTask) -> String {
    if meta.archive_fatal_error.is_some() || meta.ipfs_fatal_error.is_some() {
        return "error".to_string();
    }
    let archive_needed = meta.storage_mode != "ipfs";
    let ipfs_needed = meta.storage_mode != "archive";
    let archive_status = meta.archive_status.as_deref().unwrap_or("in_progress");
    let ipfs_status = if ipfs_needed {
        meta.ipfs_status.as_deref().unwrap_or("in_progress")
    } else {
        "done"
    };
    if archive_status == "expired" {
        return "expired".to_string();
    }
    if archive_status == "error" || ipfs_status == "error" {
        return "error".to_string();
    }
    if (!archive_needed || archive_status == "done") && (!ipfs_needed || ipfs_status == "done") {
        return "done".to_string();
    }
    "in_progress".to_string()
}

fn validate_backup_request(state: &AppState, req: &BackupRequest) -> Result<(), String> {
    validate_backup_request_impl(&state.chain_config, state.ipfs_providers.len(), req)
}

fn validate_backup_request_impl(
    chain_config: &crate::backup::ChainConfig,
    ipfs_providers_len: usize,
    req: &BackupRequest,
) -> Result<(), String> {
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
    // Validate requested operation is meaningful
    if !req.create_archive && !req.pin_on_ipfs {
        return Err("Either create_archive must be true or pin_on_ipfs must be true".to_string());
    }
    // Validate IPFS pinning configuration
    if req.pin_on_ipfs && ipfs_providers_len == 0 {
        return Err("pin_on_ipfs requested but no IPFS provider configured".to_string());
    }
    Ok(())
}

/// Create a backup task for the authenticated user. This task will be processed asynchronously and the result will be available in the /v1/backups/{task_id} endpoint.
/// By default, this endpoint creates an archive file with metadata and content from all tokens to be downloaded by the user. The archive format depends on the user-agent (zip or tar.gz).
/// The user can optionally request to pin content that is stored on IPFS.
#[utoipa::path(
    post,
    path = "/v1/backups",
    request_body = BackupRequest,
    params(
        ("accept" = Option<String>, Header, description = "Preferred archive media type for backup content: application/zip or application/gzip. If omitted or undecidable, defaults to zip."),
        ("user-agent" = Option<String>, Header, description = "Used as a heuristic fallback to select archive format when Accept is not provided.")
    ),
    responses(
        (status = 202, description = "Backup task accepted and queued", body = BackupResponse),
        (status = 200, description = "Backup already exists or in progress", body = BackupResponse),
        (status = 400, description = "Invalid request", body = ApiProblem, content_type = "application/problem+json"),
        (status = 409, description = "Backup exists in error/expired state", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup(
    State(state): State<AppState>,
    Extension(requestor): Extension<Option<String>>,
    headers: HeaderMap,
    Json(req): Json<BackupRequest>,
) -> axum::response::Response {
    if let Err(msg) = validate_backup_request(&state, &req) {
        let problem = ProblemJson::from_status(
            StatusCode::BAD_REQUEST,
            Some(msg),
            Some("/v1/backups".to_string()),
        );
        return problem.into_response();
    }
    let response = handle_backup_core(
        &*state.db,
        &state.backup_task_sender,
        requestor,
        &headers,
        req,
        state.pruner_retention_days,
    )
    .await;
    response
}

// A minimal trait to enable mocking DB calls for unit tests of this handler
pub trait BackupDb {
    #[allow(clippy::too_many_arguments)]
    fn insert_backup_task<'a>(
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

impl BackupDb for Db {
    #[allow(clippy::too_many_arguments)]
    fn insert_backup_task<'a>(
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
            Db::insert_backup_task(
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

async fn handle_backup_core<DB: BackupDb + ?Sized + crate::server::BackupTaskDb>(
    db: &DB,
    backup_task_sender: &tokio::sync::mpsc::Sender<BackupTaskOrShutdown>,
    requestor: Option<String>,
    headers: &HeaderMap,
    req: BackupRequest,
    pruner_retention_days: u64,
) -> axum::response::Response {
    // Validate that requestor is present
    let requestor_str = match &requestor {
        Some(s) if !s.is_empty() => s.clone(),
        _ => {
            let problem = ProblemJson::from_status(
                StatusCode::BAD_REQUEST,
                Some("Requestor required".to_string()),
                Some("/v1/backups".to_string()),
            );
            return problem.into_response();
        }
    };

    let task_id = compute_task_id(&req.tokens, Some(&requestor_str));

    if let Ok(Some(task_meta)) = db.get_backup_task(&task_id).await {
        // Check if task is being deleted
        if task_meta.deleted_at.is_some() {
            let problem = ProblemJson::from_status(
                StatusCode::CONFLICT,
                Some("Task is being deleted and cannot be started".to_string()),
                Some(format!("/v1/backups/{task_id}")),
            );
            return problem.into_response();
        }

        match derive_status(&task_meta).as_str() {
            "in_progress" => {
                debug!("Duplicate backup request, returning existing task_id {task_id}");
                return (StatusCode::OK, Json(BackupResponse { task_id })).into_response();
            }
            "done" => {
                debug!("Backup already completed, returning existing task_id {task_id}");
                return (StatusCode::OK, Json(BackupResponse { task_id })).into_response();
            }
            "error" | "expired" => {
                let problem = ProblemJson::from_status(
                    StatusCode::CONFLICT,
                    Some(format!(
                        "Backup in status {} cannot be started. Use retry.",
                        derive_status(&task_meta)
                    )),
                    Some(format!("/v1/backups/{task_id}")),
                );
                return problem.into_response();
            }
            other => {
                error!("Unknown backup status '{other}' for task {task_id} when handling /backup");
                let problem = ProblemJson::from_status(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Some("Unknown backup status".to_string()),
                    Some("/v1/backups".to_string()),
                );
                return problem.into_response();
            }
        }
    }

    // Determine storage mode based on flags
    let storage_mode = match (req.create_archive, req.pin_on_ipfs) {
        (true, true) => StorageMode::Full,
        (true, false) => StorageMode::Archive,
        (false, true) => StorageMode::Ipfs,
        (false, false) => {
            // Should be prevented by validation; return error defensively
            let problem = ProblemJson::from_status(
                StatusCode::BAD_REQUEST,
                Some("Either create_archive must be true or pin_on_ipfs must be true".to_string()),
                Some("/v1/backups".to_string()),
            );
            return problem.into_response();
        }
    };

    // Determine archive format if necessary (None for IPFS-only)
    let archive_format_opt: Option<String> = if storage_mode == StorageMode::Ipfs {
        None
    } else {
        Some(negotiate_archive_format(
            headers.get("accept").and_then(|v| v.to_str().ok()),
            headers.get("user-agent").and_then(|v| v.to_str().ok()),
        ))
    };

    // Write metadata to DB
    let nft_count = req.tokens.iter().map(|t| t.tokens.len()).sum::<usize>() as i32;
    let tokens_json = serde_json::to_value(&req.tokens).unwrap();
    if let Err(e) = db
        .insert_backup_task(
            &task_id,
            &requestor_str,
            nft_count,
            &tokens_json,
            storage_mode.as_str(),
            archive_format_opt.as_deref(),
            Some(pruner_retention_days),
        )
        .await
    {
        let problem = ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some(format!("Failed to write metadata to DB: {e}")),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }

    let backup_task = BackupTask {
        task_id: task_id.clone(),
        request: req.clone(),
        force: false,
        storage_mode: storage_mode.clone(),
        archive_format: archive_format_opt.clone(),
        requestor: Some(requestor_str.clone()),
    };
    if let Err(e) = backup_task_sender
        .send(BackupTaskOrShutdown::Task(TaskType::Creation(backup_task)))
        .await
    {
        error!("Failed to enqueue backup task: {e}");
        let problem = ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to enqueue backup task".to_string()),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }

    info!(
        "Created backup task {} (requestor: {}, count: {}, storage_mode: {})",
        task_id,
        requestor.unwrap_or_default(),
        nft_count,
        storage_mode.as_str()
    );
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

#[cfg(test)]
mod validate_backup_request_impl_tests {
    use super::validate_backup_request_impl;
    use crate::backup::ChainConfig;
    use crate::server::api::{BackupRequest, Tokens};

    fn make_chain_config(chains: &[&str]) -> ChainConfig {
        let mut map = std::collections::HashMap::new();
        for &c in chains {
            map.insert(c.to_string(), "rpc://dummy".to_string());
        }
        ChainConfig(map)
    }

    #[test]
    fn rejects_unknown_chains() {
        let chain_config = make_chain_config(&["ethereum", "tezos"]);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "polygon".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let result = validate_backup_request_impl(&chain_config, 1, &req);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("Unknown chains requested"));
    }

    #[test]
    fn rejects_pin_without_ipfs_providers() {
        let chain_config = make_chain_config(&["ethereum"]);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: true,
            create_archive: true,
        };
        let result = validate_backup_request_impl(&chain_config, 0, &req);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "pin_on_ipfs requested but no IPFS provider configured"
        );
    }

    #[test]
    fn accepts_valid_request_with_ipfs() {
        let chain_config = make_chain_config(&["ethereum"]);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: true,
            create_archive: true,
        };
        let result = validate_backup_request_impl(&chain_config, 2, &req);
        assert!(result.is_ok());
    }

    #[test]
    fn accepts_valid_request_without_ipfs() {
        let chain_config = make_chain_config(&["tezos"]);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "tezos".to_string(),
                tokens: vec!["KT1abc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let result = validate_backup_request_impl(&chain_config, 0, &req);
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_when_both_create_archive_and_pin_false() {
        let chain_config = make_chain_config(&["ethereum"]);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: false,
        };
        let result = validate_backup_request_impl(&chain_config, 1, &req);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.contains("Either create_archive must be true or pin_on_ipfs must be true"));
    }
}

#[cfg(test)]
mod handle_backup_endpoint_tests {
    use super::handle_backup;
    use axum::http::StatusCode;
    use axum::{routing::post, Extension, Router};
    use hyper::Request;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};
    use tower::Service;

    use crate::ipfs::IpfsProviderConfig;
    use crate::server::db::Db;
    use crate::server::AppState;

    fn make_state(ipfs_providers: Vec<IpfsProviderConfig>) -> AppState {
        let mut chains = HashMap::new();
        chains.insert("ethereum".to_string(), "rpc://dummy".to_string());
        let chain_config = crate::backup::ChainConfig(chains);
        let (tx, _rx) = mpsc::channel(1);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@localhost/db")
            .unwrap();
        let db = Arc::new(Db { pool });
        AppState {
            chain_config: Arc::new(chain_config),
            base_dir: Arc::new("/tmp".to_string()),
            unsafe_skip_checksum_check: true,
            auth_token: None,
            pruner_enabled: false,
            pruner_retention_days: 7,
            download_tokens: Arc::new(Mutex::new(HashMap::new())),
            backup_task_sender: tx,
            db,
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ipfs_providers,
            ipfs_provider_instances: Arc::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn returns_400_for_unknown_chain() {
        let state = make_state(Vec::new());
        let app = Router::new()
            .route("/backup", post(handle_backup))
            .with_state(state)
            .layer(Extension::<Option<String>>(None));

        let req_body = json!({
            "tokens": [ { "chain": "polygon", "tokens": ["0xabc:1"] } ]
        });
        let request = Request::builder()
            .method("POST")
            .uri("/backup")
            .header("content-type", "application/json")
            .header("user-agent", "Linux")
            .body(axum::body::Body::from(req_body.to_string()))
            .unwrap();

        let mut app = app;
        let response = app.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_400_for_pin_without_ipfs_providers() {
        let state = make_state(Vec::new());
        let app = Router::new()
            .route("/backup", post(handle_backup))
            .with_state(state)
            .layer(Extension::<Option<String>>(None));

        let req = crate::server::api::BackupRequest {
            tokens: vec![crate::server::api::Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: true,
            create_archive: true,
        };
        let request = Request::builder()
            .method("POST")
            .uri("/backup")
            .header("content-type", "application/json")
            .header("user-agent", "Linux")
            .body(axum::body::Body::from(serde_json::to_string(&req).unwrap()))
            .unwrap();

        let mut app = app;
        let response = app.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

#[cfg(test)]
mod handle_backup_core_tests {
    use super::BackupDb;
    use crate::server::api::{BackupRequest, Tokens};
    use axum::body::to_bytes;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use tokio::sync::mpsc;

    #[derive(Clone, Default)]
    struct MockDb {
        task_meta: Option<crate::server::db::BackupTask>,
        inserted: std::sync::Arc<std::sync::Mutex<bool>>,
        last_archive_format: std::sync::Arc<std::sync::Mutex<Option<String>>>,
    }

    #[async_trait::async_trait]
    impl crate::server::BackupTaskDb for MockDb {
        async fn clear_backup_errors(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn set_backup_error(&self, _task_id: &str, _error: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn insert_pin_requests_with_tokens(
            &self,
            _task_id: &str,
            _requestor: &str,
            _token_pin_mappings: &[crate::TokenPinMapping],
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn set_error_logs(
            &self,
            _task_id: &str,
            _archive_error_log: Option<&str>,
            _ipfs_error_log: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn update_ipfs_task_status(
            &self,
            _task_id: &str,
            _status: &str,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn set_ipfs_task_error(
            &self,
            _task_id: &str,
            _fatal_error: &str,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn update_archive_error_log(
            &self,
            _task_id: &str,
            _error_log: &str,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn update_archive_request_status(
            &self,
            _task_id: &str,
            _status: &str,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn get_backup_task(
            &self,
            _task_id: &str,
        ) -> Result<Option<crate::server::db::BackupTask>, sqlx::Error> {
            Ok(self.task_meta.clone())
        }

        async fn start_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn start_archive_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn start_ipfs_pins_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn delete_backup_task(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn complete_archive_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn complete_ipfs_pins_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }
    }

    impl BackupDb for MockDb {
        #[allow(clippy::too_many_arguments)]
        fn insert_backup_task<'a>(
            &'a self,
            _task_id: &'a str,
            _requestor: &'a str,
            _nft_count: i32,
            _tokens: &'a serde_json::Value,
            _storage_mode: &'a str,
            _archive_format: Option<&'a str>,
            _retention_days: Option<u64>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
        {
            let flag = self.inserted.clone();
            let fmt_store = self.last_archive_format.clone();
            Box::pin(async move {
                *flag.lock().unwrap() = true;
                *fmt_store.lock().unwrap() = _archive_format.map(|s| s.to_string());
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn returns_400_when_missing_requestor() {
        let db = MockDb::default();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let headers = HeaderMap::new();
        let resp = super::handle_backup_core(&db, &tx, None, &headers, req, 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_202_and_enqueues_on_new_task() {
        let db = MockDb::default();
        let (tx, mut rx) = mpsc::channel(1);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let headers = HeaderMap::new();
        let resp =
            super::handle_backup_core(&db, &tx, Some("did:test".to_string()), &headers, req, 7)
                .await
                .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        // Assert Location header points to the created backup resource
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
        // Ensure task enqueued
        let task = rx.try_recv();
        assert!(task.is_ok());
    }

    #[tokio::test]
    async fn returns_409_when_being_deleted() {
        let db = MockDb {
            task_meta: Some(crate::server::db::BackupTask {
                task_id: "test".to_string(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                requestor: "test".to_string(),
                nft_count: 0,
                tokens: serde_json::Value::Null,
                archive_status: Some("done".to_string()),
                ipfs_status: None,
                archive_error_log: None,
                ipfs_error_log: None,
                archive_fatal_error: None,
                ipfs_fatal_error: None,
                storage_mode: "archive".to_string(),
                deleted_at: Some(chrono::Utc::now()),
                archive_format: None,
                expires_at: None,
                archive_deleted_at: None,
                pins_deleted_at: None,
            }),
            inserted: Default::default(),
            last_archive_format: Default::default(),
        };
        let (tx, _rx) = mpsc::channel(1);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let headers = HeaderMap::new();
        let resp =
            super::handle_backup_core(&db, &tx, Some("did:test".to_string()), &headers, req, 7)
                .await
                .into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn returns_200_when_in_progress() {
        let db = MockDb {
            task_meta: Some(crate::server::db::BackupTask {
                task_id: "test".to_string(),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                requestor: "did:privy:alice".to_string(),
                nft_count: 1,
                tokens: serde_json::json!([]),
                archive_status: Some("in_progress".to_string()),
                ipfs_status: None,
                archive_error_log: None,
                ipfs_error_log: None,
                archive_fatal_error: None,
                ipfs_fatal_error: None,
                storage_mode: "archive".to_string(),
                archive_format: Some("zip".to_string()),
                expires_at: None,
                deleted_at: None,
                archive_deleted_at: None,
                pins_deleted_at: None,
            }),
            inserted: Default::default(),
            last_archive_format: Default::default(),
        };
        let (tx, _rx) = mpsc::channel(1);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let headers = HeaderMap::new();
        let resp =
            super::handle_backup_core(&db, &tx, Some("did:test".to_string()), &headers, req, 7)
                .await
                .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn accept_zip_selects_zip() {
        let db = MockDb::default();
        let (tx, _rx) = mpsc::channel(1);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let mut headers = HeaderMap::new();
        headers.insert("accept", "application/zip".parse().unwrap());
        let _ = super::handle_backup_core(&db, &tx, Some("did:test".to_string()), &headers, req, 7)
            .await
            .into_response();
        let chosen = db.last_archive_format.lock().unwrap().clone();
        assert_eq!(chosen.as_deref(), Some("zip"));
    }

    #[tokio::test]
    async fn accept_gzip_selects_tar_gz() {
        let db = MockDb::default();
        let (tx, _rx) = mpsc::channel(1);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let mut headers = HeaderMap::new();
        headers.insert("accept", "application/gzip".parse().unwrap());
        let _ = super::handle_backup_core(&db, &tx, Some("did:test".to_string()), &headers, req, 7)
            .await
            .into_response();
        let chosen = db.last_archive_format.lock().unwrap().clone();
        assert_eq!(chosen.as_deref(), Some("tar.gz"));
    }

    #[tokio::test]
    async fn undecidable_accept_defaults_zip_in_core() {
        let db = MockDb::default();
        let (tx, _rx) = mpsc::channel(1);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let mut headers = HeaderMap::new();
        headers.insert("accept", "application/json".parse().unwrap());
        let _ = super::handle_backup_core(&db, &tx, Some("did:test".to_string()), &headers, req, 7)
            .await
            .into_response();
        let chosen = db.last_archive_format.lock().unwrap().clone();
        assert_eq!(chosen.as_deref(), Some("zip"));
    }

    #[tokio::test]
    async fn selects_from_user_agent() {
        let db = MockDb::default();
        let (tx, _rx) = mpsc::channel(1);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "Linux".parse().unwrap());
        let _ = super::handle_backup_core(&db, &tx, Some("did:test".to_string()), &headers, req, 7)
            .await
            .into_response();
        let chosen = db.last_archive_format.lock().unwrap().clone();
        assert!(matches!(chosen.as_deref(), Some("tar.gz")));
    }

    #[tokio::test]
    async fn both_accept_and_user_agent_present_accept_wins() {
        let db = MockDb::default();
        let (tx, _rx) = mpsc::channel(1);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "Linux TarPreferred".parse().unwrap());
        headers.insert("accept", "application/zip".parse().unwrap());
        let _ = super::handle_backup_core(&db, &tx, Some("did:test".to_string()), &headers, req, 7)
            .await
            .into_response();
        let chosen = db.last_archive_format.lock().unwrap().clone();
        assert_eq!(chosen.as_deref(), Some("zip"));
    }

    #[tokio::test]
    async fn ipfs_only_mode_sets_no_archive_and_accepts() {
        let db = MockDb::default();
        let (tx, mut rx) = mpsc::channel(1);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: true,
            create_archive: false,
        };
        let headers = HeaderMap::new();
        let resp =
            super::handle_backup_core(&db, &tx, Some("did:test".to_string()), &headers, req, 7)
                .await
                .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        // Ensure no archive format was chosen when not creating an archive
        let chosen = db.last_archive_format.lock().unwrap().clone();
        assert_eq!(chosen, None);
        // Ensure task enqueued
        let task = rx.try_recv();
        assert!(task.is_ok());
    }
}
