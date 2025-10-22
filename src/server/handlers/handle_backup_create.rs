use axum::{
    extract::{Extension, Json, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json;
use std::collections::HashSet;
use tracing::{debug, error, info};

use crate::server::api::{ApiProblem, BackupCreateResponse, BackupRequest, ProblemJson};
use crate::server::archive::negotiate_archive_format;
use crate::server::database::r#trait::Database;
use crate::server::hashing::compute_task_id;
use crate::server::{AppState, BackupTask, BackupTaskOrShutdown, StorageMode, TaskType};

fn get_status(meta: &crate::server::database::BackupTask, scope: &StorageMode) -> Option<String> {
    match scope {
        StorageMode::Archive => meta.archive_status.clone(),
        StorageMode::Ipfs => meta.ipfs_status.clone(),
        StorageMode::Full => {
            unreachable!("get_status reached with Full scope in POST /backups path")
        }
    }
}

/// Validate the scope against an existing task.
/// Invalidate Archive scope when the subresource is being deleted.
/// Invalidate Ipfs scope when the subresource is being deleted.
/// Full scope is invalid for existing tasks and clients should ensure to
/// specify the right scope explicitly.
/// Returns true if the requested scope is invalid for an existing task
pub(crate) fn validate_scope(
    scope: &StorageMode,
    meta: &crate::server::database::BackupTask,
) -> bool {
    match scope {
        StorageMode::Archive => meta.archive_deleted_at.is_some(),
        StorageMode::Ipfs => meta.pins_deleted_at.is_some(),
        StorageMode::Full => true,
    }
}

fn validate_backup_request(state: &AppState, req: &BackupRequest) -> Result<(), String> {
    validate_backup_request_impl(&state.chain_config, state.ipfs_pinning_configs.len(), req)
}

fn validate_backup_request_impl(
    chain_config: &crate::backup::ChainConfig,
    ipfs_pinning_configs_len: usize,
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
    if req.pin_on_ipfs && ipfs_pinning_configs_len == 0 {
        return Err("pin_on_ipfs requested but no IPFS pinning providers configured".to_string());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn ensure_backup_exists<DB: Database + ?Sized>(
    db: &DB,
    existing: Option<&crate::server::database::BackupTask>,
    task_id: &str,
    requestor: &str,
    tokens: &Vec<crate::server::api::Tokens>,
    storage_mode: &StorageMode,
    archive_format_opt: &Option<String>,
    pruner_retention_days: u64,
) -> Result<(), sqlx::Error> {
    // If backup exists, upgrade it to full and ensure missing subresource exists
    if let Some(_existing) = existing {
        db.upgrade_backup_to_full(
            task_id,
            *storage_mode == StorageMode::Archive,
            archive_format_opt.as_deref(),
            Some(pruner_retention_days),
        )
        .await?;
        return Ok(());
    }

    // Otherwise, create a new backup
    let nft_count = tokens.iter().map(|t| t.tokens.len()).sum::<usize>() as i32;
    let tokens_json = serde_json::to_value(tokens).unwrap();
    db.insert_backup_task(
        task_id,
        requestor,
        nft_count,
        &tokens_json,
        storage_mode.as_str(),
        archive_format_opt.as_deref(),
        Some(pruner_retention_days),
    )
    .await?;
    Ok(())
}

/// Create a backup task for the authenticated user. This task will be processed asynchronously and the result will be available in the /v1/backups/{task_id} endpoint.
/// By default, this endpoint creates an archive file with metadata and content from all tokens to be downloaded by the user. The archive format depends on the user-agent (zip or tar.gz).
/// The user can optionally request to pin content that is stored on IPFS. If configured in the server, a payment can be required to create the backup task.
#[utoipa::path(
    post,
    path = "/v1/backups",
    request_body = BackupRequest,
    params(
        ("accept" = Option<String>, Header, description = "Preferred archive media type for backup content: application/zip or application/gzip. If omitted or undecidable, defaults to zip."),
        ("user-agent" = Option<String>, Header, description = "Used as a heuristic fallback to select archive format when Accept is not provided.")
    ),
    responses(
        (status = 202, description = "Backup task accepted and queued", body = BackupCreateResponse),
        (status = 200, description = "Backup already exists or in progress", body = BackupCreateResponse),
        (status = 400, description = "Invalid request", body = ApiProblem, content_type = "application/problem+json"),
        (status = 402, description = "Payment required. See https://www.x402.org/ for more details.", body = ApiProblem, content_type = "application/problem+json"),
        (status = 403, description = "Requestor does not match task owner", body = ApiProblem, content_type = "application/problem+json"),
        (status = 409, description = "Invalid scope for existing task", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup_create(
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
    let response = handle_backup_create_core(
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

async fn handle_backup_create_core<DB: Database + ?Sized>(
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

    // Determine storage mode
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

    // Determine task id
    let task_id = compute_task_id(&req.tokens, Some(&requestor_str));

    // Validate against existing tasks
    let existing_meta: Option<crate::server::database::BackupTask> =
        db.get_backup_task(&task_id).await.unwrap_or_default();
    if let Some(task_meta) = existing_meta.clone() {
        // Ensure the requestor matches the existing task owner
        if !task_meta.requestor.is_empty() && task_meta.requestor != requestor_str {
            let problem = ProblemJson::from_status(
                StatusCode::FORBIDDEN,
                Some("Requestor does not match task owner".to_string()),
                Some(format!("/v1/backups/{task_id}")),
            );
            return problem.into_response();
        }

        if validate_scope(&storage_mode, &task_meta) {
            let problem = ProblemJson::from_status(
                StatusCode::CONFLICT,
                Some("Invalid scope for existing task".to_string()),
                Some(format!("/v1/backups/{task_id}")),
            );
            return problem.into_response();
        }

        if let Some(status) = get_status(&task_meta, &storage_mode) {
            match status.as_str() {
                "in_progress" => {
                    debug!("Duplicate backup request, returning existing task_id {task_id}");
                    return (StatusCode::OK, Json(BackupCreateResponse { task_id }))
                        .into_response();
                }
                "done" => {
                    debug!("Backup already completed, returning existing task_id {task_id}");
                    return (StatusCode::OK, Json(BackupCreateResponse { task_id }))
                        .into_response();
                }
                "error" | "expired" | "unpaid" => {
                    let problem = ProblemJson::from_status(
                        StatusCode::CONFLICT,
                        Some(format!(
                            "Backup in status {status} cannot be started. Use retry.",
                        )),
                        Some(format!("/v1/backups/{task_id}")),
                    );
                    return problem.into_response();
                }
                other => {
                    error!(
                        "Unknown backup status '{other}' for task {task_id} when handling /backup"
                    );
                    let problem = ProblemJson::from_status(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Some("Unknown backup status".to_string()),
                        Some("/v1/backups".to_string()),
                    );
                    return problem.into_response();
                }
            }
        }
    }

    // Determine archive format if necessary
    let archive_format_opt: Option<String> = if storage_mode == StorageMode::Ipfs {
        None
    } else {
        Some(negotiate_archive_format(
            headers.get("accept").and_then(|v| v.to_str().ok()),
            headers.get("user-agent").and_then(|v| v.to_str().ok()),
        ))
    };

    // Ensure backup exists in the database
    if let Err(e) = ensure_backup_exists(
        db,
        existing_meta.as_ref(),
        &task_id,
        &requestor_str,
        &req.tokens,
        &storage_mode,
        &archive_format_opt,
        pruner_retention_days,
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

    // Enqueue backup task
    let backup_task = BackupTask {
        task_id: task_id.clone(),
        request: req.clone(),
        scope: storage_mode.clone(),
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
        req.tokens.iter().map(|t| t.tokens.len()).sum::<usize>(),
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
        Json(BackupCreateResponse { task_id }),
    )
        .into_response()
}

#[cfg(test)]
mod ensure_backup_exists_unit_tests {
    use super::ensure_backup_exists;
    use crate::server::api::Tokens;
    use crate::server::database::r#trait::MockDatabase;
    use crate::server::database::BackupTask;
    use crate::server::StorageMode;

    fn sample_meta() -> BackupTask {
        BackupTask {
            task_id: "t".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            requestor: "did:test".to_string(),
            nft_count: 1,
            tokens: serde_json::json!([{"chain":"ethereum","tokens":["0xabc:1"]}]),
            archive_status: Some("done".to_string()),
            ipfs_status: None,
            archive_error_log: None,
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: None,
            storage_mode: "archive".to_string(),
            archive_format: Some("zip".to_string()),
            expires_at: None,
            archive_deleted_at: None,
            pins_deleted_at: None,
        }
    }

    #[tokio::test]
    async fn existing_meta_upgrades_ok() {
        let db = MockDatabase::default();
        let meta = sample_meta();
        let tokens = vec![Tokens {
            chain: "ethereum".to_string(),
            tokens: vec!["0xabc:1".to_string()],
        }];
        let res = ensure_backup_exists(
            &db,
            Some(&meta),
            "t",
            "did:test",
            &tokens,
            &StorageMode::Archive,
            &None,
            7,
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn new_insert_ok() {
        let db = MockDatabase::default();
        let tokens = vec![Tokens {
            chain: "ethereum".to_string(),
            tokens: vec!["0xabc:1".to_string()],
        }];
        let res = ensure_backup_exists(
            &db,
            None,
            "t",
            "did:test",
            &tokens,
            &StorageMode::Archive,
            &Some("zip".to_string()),
            7,
        )
        .await;
        assert!(res.is_ok());
    }

    #[tokio::test]
    async fn insert_error_propagates() {
        let mut db = MockDatabase::default();
        db.set_insert_backup_task_error(Some("boom".to_string()));
        let tokens = vec![Tokens {
            chain: "ethereum".to_string(),
            tokens: vec!["0xabc:1".to_string()],
        }];
        let res = ensure_backup_exists(
            &db,
            None,
            "t",
            "did:test",
            &tokens,
            &StorageMode::Archive,
            &Some("zip".to_string()),
            7,
        )
        .await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn upgrade_error_propagates() {
        let mut db = MockDatabase::default();
        db.set_upgrade_backup_to_full_error(Some("boom".to_string()));
        let meta = sample_meta();
        let tokens = vec![Tokens {
            chain: "ethereum".to_string(),
            tokens: vec!["0xabc:1".to_string()],
        }];
        let res = ensure_backup_exists(
            &db,
            Some(&meta),
            "t",
            "did:test",
            &tokens,
            &StorageMode::Archive,
            &Some("zip".to_string()),
            7,
        )
        .await;
        assert!(res.is_err());
    }
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
    fn rejects_pin_without_ipfs_pinning_configs() {
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
            "pin_on_ipfs requested but no IPFS pinning providers configured"
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
    use super::handle_backup_create as handle_backup;
    use axum::http::StatusCode;
    use axum::{routing::post, Extension, Router};
    use hyper::Request;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};
    use tower::Service;

    use crate::ipfs::IpfsPinningConfig;
    use crate::server::database::Db;
    use crate::server::AppState;

    fn make_state(ipfs_pinning_configs: Vec<IpfsPinningConfig>) -> AppState {
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
            pruner_retention_days: 7,
            download_tokens: Arc::new(Mutex::new(HashMap::new())),
            backup_task_sender: tx,
            db,
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ipfs_pinning_configs,
            ipfs_pinning_instances: Arc::new(Vec::new()),
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
    async fn returns_400_for_pin_without_ipfs_pinning_configs() {
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
    use crate::server::api::{BackupRequest, Tokens};
    use crate::server::database::r#trait::MockDatabase;
    use axum::body::to_bytes;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn returns_400_when_missing_requestor() {
        let db = MockDatabase::default();
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
        let resp = super::handle_backup_create_core(&db, &tx, None, &headers, req, 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_202_and_enqueues_on_new_task() {
        let db = MockDatabase::default();
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
        let resp = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:test".to_string()),
            &headers,
            req,
            7,
        )
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
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(crate::server::database::BackupTask {
            task_id: "test".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            requestor: "did:test".to_string(),
            nft_count: 0,
            tokens: serde_json::Value::Null,
            archive_status: Some("done".to_string()),
            ipfs_status: None,
            archive_error_log: None,
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: None,
            storage_mode: "archive".to_string(),
            archive_format: None,
            expires_at: None,
            archive_deleted_at: Some(chrono::Utc::now()),
            pins_deleted_at: None,
        }));
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
        let resp = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:test".to_string()),
            &headers,
            req,
            7,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn returns_403_when_existing_task_owner_mismatch() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(crate::server::database::BackupTask {
            task_id: "towner".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            requestor: "did:privy:bob".to_string(),
            nft_count: 1,
            tokens: serde_json::json!([]),
            archive_status: Some("done".to_string()),
            ipfs_status: None,
            archive_error_log: None,
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: None,
            storage_mode: "archive".to_string(),
            archive_format: Some("zip".to_string()),
            expires_at: None,
            archive_deleted_at: None,
            pins_deleted_at: None,
        }));
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
        let resp = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:privy:alice".to_string()),
            &headers,
            req,
            7,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_200_when_in_progress() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(crate::server::database::BackupTask {
            task_id: "test".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            requestor: "did:test".to_string(),
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
            archive_deleted_at: None,
            pins_deleted_at: None,
        }));
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
        let resp = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:test".to_string()),
            &headers,
            req,
            7,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn accept_zip_selects_zip() {
        let db = MockDatabase::default();
        let (tx, mut rx) = mpsc::channel(1);
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
        let _ = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:test".to_string()),
            &headers,
            req,
            7,
        )
        .await
        .into_response();

        // Check that the backup task was sent with the correct archive format
        let task = rx.try_recv().unwrap();
        match task {
            crate::server::BackupTaskOrShutdown::Task(crate::server::TaskType::Creation(
                backup_task,
            )) => {
                assert_eq!(backup_task.archive_format, Some("zip".to_string()));
            }
            _ => panic!("Expected Creation task"),
        }
    }

    #[tokio::test]
    async fn accept_gzip_selects_tar_gz() {
        let db = MockDatabase::default();
        let (tx, mut rx) = mpsc::channel(1);
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
        let _ = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:test".to_string()),
            &headers,
            req,
            7,
        )
        .await
        .into_response();

        // Check that the backup task was sent with the correct archive format
        let task = rx.try_recv().unwrap();
        match task {
            crate::server::BackupTaskOrShutdown::Task(crate::server::TaskType::Creation(
                backup_task,
            )) => {
                assert_eq!(backup_task.archive_format, Some("tar.gz".to_string()));
            }
            _ => panic!("Expected Creation task"),
        }
    }

    #[tokio::test]
    async fn undecidable_accept_defaults_zip_in_core() {
        let db = MockDatabase::default();
        let (tx, mut rx) = mpsc::channel(1);
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
        let _ = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:test".to_string()),
            &headers,
            req,
            7,
        )
        .await
        .into_response();

        // Check that the backup task was sent with the default zip format
        let task = rx.try_recv().unwrap();
        match task {
            crate::server::BackupTaskOrShutdown::Task(crate::server::TaskType::Creation(
                backup_task,
            )) => {
                assert_eq!(backup_task.archive_format, Some("zip".to_string()));
            }
            _ => panic!("Expected Creation task"),
        }
    }

    #[tokio::test]
    async fn selects_from_user_agent() {
        let db = MockDatabase::default();
        let (tx, mut rx) = mpsc::channel(1);
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
        let _ = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:test".to_string()),
            &headers,
            req,
            7,
        )
        .await
        .into_response();

        // Check that the backup task was sent with tar.gz format based on user agent
        let task = rx.try_recv().unwrap();
        match task {
            crate::server::BackupTaskOrShutdown::Task(crate::server::TaskType::Creation(
                backup_task,
            )) => {
                assert_eq!(backup_task.archive_format, Some("tar.gz".to_string()));
            }
            _ => panic!("Expected Creation task"),
        }
    }

    #[tokio::test]
    async fn both_accept_and_user_agent_present_accept_wins() {
        let db = MockDatabase::default();
        let (tx, mut rx) = mpsc::channel(1);
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
        let _ = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:test".to_string()),
            &headers,
            req,
            7,
        )
        .await
        .into_response();

        // Check that the backup task was sent with zip format (accept header wins over user agent)
        let task = rx.try_recv().unwrap();
        match task {
            crate::server::BackupTaskOrShutdown::Task(crate::server::TaskType::Creation(
                backup_task,
            )) => {
                assert_eq!(backup_task.archive_format, Some("zip".to_string()));
            }
            _ => panic!("Expected Creation task"),
        }
    }

    #[tokio::test]
    async fn ipfs_only_mode_sets_no_archive_and_accepts() {
        let db = MockDatabase::default();
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
        let resp = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:test".to_string()),
            &headers,
            req,
            7,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Check that the backup task was sent with no archive format (IPFS only mode)
        let task = rx.try_recv().unwrap();
        match task {
            crate::server::BackupTaskOrShutdown::Task(crate::server::TaskType::Creation(
                backup_task,
            )) => {
                assert_eq!(backup_task.archive_format, None);
            }
            _ => panic!("Expected Creation task"),
        }
    }

    #[tokio::test]
    async fn upgrades_to_full_and_enqueues_ipfs_when_archive_exists() {
        let mut db = MockDatabase::default();
        // Existing archive-only task: no ipfs_status present
        db.set_get_backup_task_result(Some(crate::server::database::BackupTask {
            task_id: "t1".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            requestor: "did:test".to_string(),
            nft_count: 1,
            tokens: serde_json::json!([{"chain":"ethereum","tokens":["0xabc:1"]}]),
            archive_status: Some("done".to_string()),
            ipfs_status: None,
            archive_error_log: None,
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: None,
            storage_mode: "archive".to_string(),
            archive_format: Some("zip".to_string()),
            expires_at: None,
            archive_deleted_at: None,
            pins_deleted_at: None,
        }));
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
        let resp = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:test".to_string()),
            &headers,
            req,
            7,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        // Ensure the missing IPFS subresource task enqueued
        let task = rx.try_recv().unwrap();
        match task {
            crate::server::BackupTaskOrShutdown::Task(crate::server::TaskType::Creation(
                backup_task,
            )) => {
                assert_eq!(backup_task.scope.as_str(), "ipfs");
                assert_eq!(backup_task.archive_format, None);
            }
            _ => panic!("Expected Creation task"),
        }
    }

    #[tokio::test]
    async fn upgrades_to_full_and_enqueues_archive_when_ipfs_exists() {
        let mut db = MockDatabase::default();
        // Existing ipfs-only task: no archive_status present
        db.set_get_backup_task_result(Some(crate::server::database::BackupTask {
            task_id: "t2".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            requestor: "did:test".to_string(),
            nft_count: 1,
            tokens: serde_json::json!([{"chain":"ethereum","tokens":["0xabc:1"]}]),
            archive_status: None,
            ipfs_status: Some("done".to_string()),
            archive_error_log: None,
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: None,
            storage_mode: "ipfs".to_string(),
            archive_format: None,
            expires_at: None,
            archive_deleted_at: None,
            pins_deleted_at: None,
        }));
        let (tx, mut rx) = mpsc::channel(1);
        let req = BackupRequest {
            tokens: vec![Tokens {
                chain: "ethereum".to_string(),
                tokens: vec!["0xabc:1".to_string()],
            }],
            pin_on_ipfs: false,
            create_archive: true,
        };
        // No accept header -> default zip
        let headers = HeaderMap::new();
        let resp = super::handle_backup_create_core(
            &db,
            &tx,
            Some("did:test".to_string()),
            &headers,
            req,
            7,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        // Ensure the missing Archive subresource task enqueued with archive format
        let task = rx.try_recv().unwrap();
        match task {
            crate::server::BackupTaskOrShutdown::Task(crate::server::TaskType::Creation(
                backup_task,
            )) => {
                assert_eq!(backup_task.scope.as_str(), "archive");
                assert_eq!(backup_task.archive_format, Some("zip".to_string()));
            }
            _ => panic!("Expected Creation task"),
        }
    }
}

#[cfg(test)]
mod validate_scope_unit_tests {
    use super::validate_scope;
    use crate::server::database::BackupTask;
    use crate::server::StorageMode;

    fn make_meta(archive_deleted: bool, pins_deleted: bool) -> BackupTask {
        BackupTask {
            task_id: "t".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            requestor: "did:test".to_string(),
            nft_count: 0,
            tokens: serde_json::Value::Null,
            archive_status: None,
            ipfs_status: None,
            archive_error_log: None,
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: None,
            storage_mode: "full".to_string(),
            archive_format: None,
            expires_at: None,
            archive_deleted_at: if archive_deleted {
                Some(chrono::Utc::now())
            } else {
                None
            },
            pins_deleted_at: if pins_deleted {
                Some(chrono::Utc::now())
            } else {
                None
            },
        }
    }

    #[test]
    fn archive_invalid_only_when_archive_deletion_active() {
        let meta = make_meta(true, false);
        assert!(validate_scope(&StorageMode::Archive, &meta));
        let meta = make_meta(false, true);
        assert!(!validate_scope(&StorageMode::Archive, &meta));
        let meta = make_meta(false, false);
        assert!(!validate_scope(&StorageMode::Archive, &meta));
    }

    #[test]
    fn ipfs_invalid_only_when_pins_deletion_active() {
        let meta = make_meta(false, true);
        assert!(validate_scope(&StorageMode::Ipfs, &meta));
        let meta = make_meta(true, false);
        assert!(!validate_scope(&StorageMode::Ipfs, &meta));
        let meta = make_meta(false, false);
        assert!(!validate_scope(&StorageMode::Ipfs, &meta));
    }

    #[test]
    fn full_always_invalid_for_existing_tasks() {
        let meta = make_meta(false, false);
        assert!(validate_scope(&StorageMode::Full, &meta));
        let meta = make_meta(true, true);
        assert!(validate_scope(&StorageMode::Full, &meta));
    }
}

#[cfg(test)]
mod get_status_unit_tests {
    use super::get_status;
    use crate::server::database::BackupTask;
    use crate::server::StorageMode;

    fn base_meta() -> BackupTask {
        BackupTask {
            task_id: "t".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            requestor: "did:test".to_string(),
            nft_count: 0,
            tokens: serde_json::Value::Null,
            archive_status: None,
            ipfs_status: None,
            archive_error_log: None,
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: None,
            storage_mode: "archive".to_string(),
            archive_format: None,
            expires_at: None,
            archive_deleted_at: None,
            pins_deleted_at: None,
        }
    }

    #[test]
    fn archive_returns_substatus_or_none() {
        let mut meta = base_meta();
        assert_eq!(get_status(&meta, &StorageMode::Archive), None);
        meta.archive_status = Some("done".to_string());
        assert_eq!(
            get_status(&meta, &StorageMode::Archive),
            Some("done".to_string())
        );
    }

    #[test]
    fn ipfs_returns_substatus_or_none() {
        let mut meta = base_meta();
        meta.storage_mode = "ipfs".to_string();
        assert_eq!(get_status(&meta, &StorageMode::Ipfs), None);
        meta.ipfs_status = Some("in_progress".to_string());
        assert_eq!(
            get_status(&meta, &StorageMode::Ipfs),
            Some("in_progress".to_string())
        );
    }
}
