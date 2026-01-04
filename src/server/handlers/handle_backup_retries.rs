use axum::{
    extract::{Extension, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tracing::{error, info};

use crate::server::api::{ApiProblem, BackupCreateResponse, BackupRequest, ProblemJson};
use crate::server::database::r#trait::Database;
use crate::server::handlers::verify_requestor_owns_task;
use crate::server::{
    parse_scope, AppState, BackupTask, BackupTaskOrShutdown, StorageMode, TaskType, Tokens,
};

#[derive(serde::Deserialize, Debug, Clone)]
pub struct RetryScopeQuery {
    pub scope: Option<String>,
}

fn validate_scope_for_retry(
    meta: &crate::server::database::BackupTask,
    scope: StorageMode,
) -> bool {
    let (archive_needed, ipfs_needed) = match scope {
        StorageMode::Archive => (true, false),
        StorageMode::Ipfs => (false, true),
        StorageMode::Full => (true, true),
    };
    let archive_status = meta.archive_status.as_deref().unwrap_or("in_progress");
    let ipfs_status = if !ipfs_needed {
        "done"
    } else {
        meta.ipfs_status.as_deref().unwrap_or("in_progress")
    };
    (archive_needed && archive_status == "in_progress")
        || (ipfs_needed && ipfs_status == "in_progress")
}

/// Validate if a task is in the process of deletion for the given scope/storage mode.
/// For Archive scope, treat deletion as active when `archive_deleted_at` is set.
/// For Ipfs scope, treat deletion as active when `pins_deleted_at` is set.
/// For Full scope, treat deletion as active when either subresource has deletion started.
fn validate_deletion_with_scope(
    storage_mode: &StorageMode,
    meta: &crate::server::database::BackupTask,
) -> bool {
    match storage_mode {
        StorageMode::Archive => meta.archive_deleted_at.is_some(),
        StorageMode::Ipfs => meta.pins_deleted_at.is_some(),
        StorageMode::Full => meta.archive_deleted_at.is_some() || meta.pins_deleted_at.is_some(),
    }
}

fn prepare_retry_task(
    meta: &crate::server::database::BackupTask,
    task_id: &str,
    requestor: Option<String>,
    storage_mode: StorageMode,
) -> BackupTask {
    let tokens: Vec<Tokens> = serde_json::from_value(meta.tokens.clone()).unwrap_or_default();
    let pin_on_ipfs = storage_mode != StorageMode::Archive;
    let create_archive = storage_mode != StorageMode::Ipfs;
    BackupTask {
        task_id: task_id.to_string(),
        request: BackupRequest {
            tokens,
            pin_on_ipfs,
            create_archive,
        },
        scope: storage_mode,
        archive_format: meta.archive_format.clone(),
        requestor,
    }
}

/// Retry a backup task with optional scope at `/v1/backups/{task_id}/retries`.
#[utoipa::path(
    post,
    path = "/v1/backups/{task_id}/retries",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task"),
        ("scope" = Option<String>, Query, description = "Retry scope: archive | ipfs | full. If omitted, defaults to task's storage mode")
    ),
    responses(
        (status = 202, description = "Backup retry initiated successfully", body = BackupCreateResponse),
        (status = 403, description = "Requestor does not match task owner", body = ApiProblem, content_type = "application/problem+json"),
        (status = 404, description = "Task not found", body = ApiProblem, content_type = "application/problem+json"),
        (status = 409, description = "Task is in progress or being deleted", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup_retries(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    Query(query): Query<RetryScopeQuery>,
    Extension(requestor): Extension<Option<String>>,
) -> impl IntoResponse {
    let scope = query.scope.as_deref().and_then(parse_scope);
    handle_backup_retries_core(
        &*state.db,
        &state.backup_task_sender,
        &task_id,
        scope,
        requestor,
        state.pruner_retention_days,
    )
    .await
}

async fn handle_backup_retries_core<DB: Database + ?Sized>(
    db: &DB,
    backup_task_sender: &tokio::sync::mpsc::Sender<BackupTaskOrShutdown>,
    task_id: &str,
    scope: Option<StorageMode>,
    requestor: Option<String>,
    retention_days: u64,
) -> axum::response::Response {
    // Verify ownership and get metadata
    let (meta, problem) = verify_requestor_owns_task(
        db,
        task_id,
        requestor.clone(),
        &format!("/v1/backups/{task_id}/retries"),
    )
    .await;
    if let Some(resp) = problem {
        return resp;
    }
    let meta = meta.unwrap();

    let scope = scope
        .clone()
        .unwrap_or_else(|| meta.storage_mode.parse().unwrap_or(StorageMode::Full));

    // Check if task is in progress for the selected scope
    if validate_scope_for_retry(&meta, scope.clone()) {
        let problem = ProblemJson::from_status(
            StatusCode::CONFLICT,
            Some("Task is already in progress".to_string()),
            Some(format!("/v1/backups/{task_id}/retries")),
        );
        return problem.into_response();
    }

    // Check if task is being deleted
    if validate_deletion_with_scope(&scope, &meta) {
        let problem = ProblemJson::from_status(
            StatusCode::CONFLICT,
            Some("Task is being deleted".to_string()),
            Some(format!("/v1/backups/{task_id}/retries")),
        );
        return problem.into_response();
    }

    // Re-run backup task
    let _ = db
        .retry_backup(task_id, scope.as_str(), retention_days)
        .await;
    let backup_task = prepare_retry_task(&meta, task_id, requestor.clone(), scope.clone());
    if let Err(e) = backup_task_sender
        .send(BackupTaskOrShutdown::Task(TaskType::Creation(backup_task)))
        .await
    {
        error!("Failed to enqueue backup task: {e}");
        let problem = ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to enqueue backup task".to_string()),
            Some(format!("/v1/backups/{task_id}/retries")),
        );
        return problem.into_response();
    }

    info!("Retrying backup task {task_id} (scope: {scope})");
    (
        StatusCode::ACCEPTED,
        Json(BackupCreateResponse {
            task_id: task_id.to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod handle_backup_retries_core_tests {
    use super::handle_backup_retries_core;
    use crate::server::database::r#trait::MockDatabase;
    use crate::server::database::BackupTask;
    use crate::server::StorageMode;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use tokio::sync::mpsc;

    fn sample_meta(owner: &str, status: &str) -> BackupTask {
        use chrono::{TimeZone, Utc};
        BackupTask {
            task_id: "t1".to_string(),
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            requestor: owner.to_string(),
            nft_count: 1,
            tokens: serde_json::json!([{"chain":"ethereum","tokens":["0xabc:1"]}]),
            archive_status: Some(status.to_string()),
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
    async fn returns_404_when_missing_task() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(None);
        let (tx, _rx) = mpsc::channel(1);
        let resp = handle_backup_retries_core(&db, &tx, "t1", None, Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_error(Some("Database error".to_string()));
        let (tx, _rx) = mpsc::channel(1);
        let resp = handle_backup_retries_core(&db, &tx, "t1", None, Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn returns_409_when_in_progress() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta("did:me", "in_progress")));
        let (tx, _rx) = mpsc::channel(1);
        let resp = handle_backup_retries_core(&db, &tx, "t1", None, Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn returns_409_when_being_deleted() {
        let mut meta = sample_meta("did:me", "done");
        meta.archive_deleted_at = Some(chrono::Utc::now());
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(meta));
        let (tx, _rx) = mpsc::channel(1);
        let resp = handle_backup_retries_core(&db, &tx, "t1", None, Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn returns_403_on_owner_mismatch() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta("did:other", "done")));
        let (tx, _rx) = mpsc::channel(1);
        let resp = handle_backup_retries_core(&db, &tx, "t1", None, Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_500_when_enqueue_fails() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta("did:me", "done")));
        let (tx, rx) = mpsc::channel(1);
        drop(rx); // close receiver to force send error
        let resp = handle_backup_retries_core(&db, &tx, "t1", None, Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn returns_202_on_success_with_scope() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta("did:me", "error")));
        let (tx, mut rx) = mpsc::channel(1);
        let resp = handle_backup_retries_core(
            &db,
            &tx,
            "t1",
            Some(StorageMode::Archive),
            Some("did:me".to_string()),
            7,
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        // Ensure task enqueued
        let task = rx.try_recv();
        assert!(task.is_ok());
    }
}

#[cfg(test)]
mod validate_scope_for_retry_tests {
    use super::validate_scope_for_retry;
    use crate::server::database::BackupTask;
    use crate::server::StorageMode;

    fn sample_meta(owner: &str, status: &str, storage_mode: &str) -> BackupTask {
        use chrono::{TimeZone, Utc};
        BackupTask {
            task_id: "t1".to_string(),
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            requestor: owner.to_string(),
            nft_count: 1,
            tokens: serde_json::json!([["ethereum", "0xabc:1"]]),
            archive_status: Some(status.to_string()),
            ipfs_status: Some(status.to_string()),
            archive_error_log: None,
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: None,
            storage_mode: storage_mode.to_string(),
            archive_format: Some("zip".to_string()),
            expires_at: None,
            archive_deleted_at: None,
            pins_deleted_at: None,
        }
    }

    #[test]
    fn archive_scope_conflicts_when_archive_in_progress() {
        let meta = sample_meta("did:me", "in_progress", "full");
        let conflict = validate_scope_for_retry(&meta, StorageMode::Archive);
        assert!(conflict);
    }

    #[test]
    fn ipfs_scope_conflicts_when_ipfs_in_progress() {
        let meta = sample_meta("did:me", "in_progress", "full");
        let conflict = validate_scope_for_retry(&meta, StorageMode::Ipfs);
        assert!(conflict);
    }

    #[test]
    fn full_scope_conflicts_when_either_in_progress() {
        let meta = sample_meta("did:me", "in_progress", "full");
        let conflict = validate_scope_for_retry(&meta, StorageMode::Full);
        assert!(conflict);
    }
}

#[cfg(test)]
mod validate_deletion_with_scope_tests {
    use super::validate_deletion_with_scope;
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
    fn archive_scope_true_only_when_archive_deleted() {
        let meta = make_meta(true, false);
        assert!(validate_deletion_with_scope(&StorageMode::Archive, &meta));
        let meta = make_meta(false, true);
        assert!(!validate_deletion_with_scope(&StorageMode::Archive, &meta));
        let meta = make_meta(false, false);
        assert!(!validate_deletion_with_scope(&StorageMode::Archive, &meta));
    }

    #[test]
    fn ipfs_scope_true_only_when_pins_deleted() {
        let meta = make_meta(false, true);
        assert!(validate_deletion_with_scope(&StorageMode::Ipfs, &meta));
        let meta = make_meta(true, false);
        assert!(!validate_deletion_with_scope(&StorageMode::Ipfs, &meta));
        let meta = make_meta(false, false);
        assert!(!validate_deletion_with_scope(&StorageMode::Ipfs, &meta));
    }

    #[test]
    fn full_scope_true_when_either_deleted() {
        let meta = make_meta(true, false);
        assert!(validate_deletion_with_scope(&StorageMode::Full, &meta));
        let meta = make_meta(false, true);
        assert!(validate_deletion_with_scope(&StorageMode::Full, &meta));
        let meta = make_meta(true, true);
        assert!(validate_deletion_with_scope(&StorageMode::Full, &meta));
        let meta = make_meta(false, false);
        assert!(!validate_deletion_with_scope(&StorageMode::Full, &meta));
    }
}
