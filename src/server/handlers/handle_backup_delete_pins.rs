use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use tracing::{error, info};

use crate::server::api::{ApiProblem, ProblemJson};
use crate::server::database::r#trait::Database;
use crate::server::AppState;

/// Delete only the IPFS pins for a backup task.
/// If the backup has storage mode "full", it will update the storage mode to "archive".
/// If the backup has storage mode "ipfs", it will delete the entire backup.
/// If the backup has storage mode "archive", it will return an error.
#[utoipa::path(
    delete,
    path = "/v1/backups/{task_id}/pins",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 202, description = "Pins deletion request accepted and will be processed asynchronously"),
        (status = 400, description = "Bad request", body = ApiProblem, content_type = "application/problem+json"),
        (status = 403, description = "Requestor does not match task owner", body = ApiProblem, content_type = "application/problem+json"),
        (status = 404, description = "Task not found", body = ApiProblem, content_type = "application/problem+json"),
        (status = 409, description = "Can only delete completed tasks", body = ApiProblem, content_type = "application/problem+json"),
        (status = 422, description = "Backup does not use IPFS storage", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup_delete_pins(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    Extension(requestor): Extension<Option<String>>,
) -> impl IntoResponse {
    handle_backup_delete_pins_core(&*state.db, &state.backup_task_sender, &task_id, requestor).await
}

async fn handle_backup_delete_pins_core<DB: Database + ?Sized>(
    db: &DB,
    backup_task_sender: &tokio::sync::mpsc::Sender<crate::server::BackupTaskOrShutdown>,
    task_id: &str,
    requestor: Option<String>,
) -> axum::response::Response {
    let requestor_str = match requestor {
        Some(s) if !s.is_empty() => s,
        _ => {
            let problem = ProblemJson::from_status(
                StatusCode::BAD_REQUEST,
                Some("Requestor required".to_string()),
                Some(format!("/v1/backups/{task_id}/pins")),
            );
            return problem.into_response();
        }
    };

    // Check if the task exists and get its metadata
    let meta = match db.get_backup_task(task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let problem = ProblemJson::from_status(
                StatusCode::NOT_FOUND,
                Some("Nothing found to delete".to_string()),
                Some(format!("/v1/backups/{task_id}/pins")),
            );
            return problem.into_response();
        }
        Err(e) => {
            let problem = ProblemJson::from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(format!("Failed to read metadata: {e}")),
                Some(format!("/v1/backups/{task_id}/pins")),
            );
            return problem.into_response();
        }
    };

    // Verify requestor matches task owner
    if meta.requestor != requestor_str {
        let problem = ProblemJson::from_status(
            StatusCode::FORBIDDEN,
            Some("Requestor does not match task owner".to_string()),
            Some(format!("/v1/backups/{task_id}/pins")),
        );
        return problem.into_response();
    }

    // Check if backup uses IPFS storage
    if meta.storage_mode == "archive" {
        let problem = ProblemJson::from_status(
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("Backup does not use IPFS storage".to_string()),
            Some(format!("/v1/backups/{task_id}/pins")),
        );
        return problem.into_response();
    }

    // Check if task is in progress
    if matches!(meta.ipfs_status.as_deref(), Some("in_progress")) {
        let problem = ProblemJson::from_status(
            StatusCode::CONFLICT,
            Some("Can only delete completed tasks".to_string()),
            Some(format!("/v1/backups/{task_id}/pins")),
        );
        return problem.into_response();
    }

    // Enqueue deletion task with IPFS scope and return 202
    let deletion_task = crate::server::DeletionTask {
        task_id: task_id.to_string(),
        requestor: Some(requestor_str),
        scope: crate::server::StorageMode::Ipfs,
    };
    if let Err(e) = backup_task_sender
        .send(crate::server::BackupTaskOrShutdown::Task(
            crate::server::TaskType::Deletion(deletion_task),
        ))
        .await
    {
        error!("Failed to enqueue pins-only deletion for task {task_id}: {e}");
        let problem = ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to enqueue deletion task".to_string()),
            Some(format!("/v1/backups/{task_id}/pins")),
        );
        return problem.into_response();
    }

    info!("Queued pins-only deletion for task {task_id}");
    (StatusCode::ACCEPTED, ()).into_response()
}

#[cfg(test)]
mod handle_backup_delete_pins_core_tests {
    use super::handle_backup_delete_pins_core;
    use crate::server::database::r#trait::MockDatabase;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    fn sample_meta(
        owner: &str,
        status: &str,
        storage_mode: &str,
    ) -> crate::server::database::BackupTask {
        use chrono::{TimeZone, Utc};
        crate::server::database::BackupTask {
            task_id: "t1".to_string(),
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            requestor: owner.to_string(),
            nft_count: 1,
            tokens: serde_json::json!([{"chain":"ethereum","tokens":["0xabc:1"]}]),
            archive_status: Some(status.to_string()),
            ipfs_status: Some(status.to_string()),
            archive_error_log: None,
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: None,
            storage_mode: storage_mode.to_string(),
            archive_format: Some("zip".to_string()),
            expires_at: None,
            deleted_at: None,
            archive_deleted_at: None,
            pins_deleted_at: None,
        }
    }

    #[tokio::test]
    async fn returns_400_when_missing_requestor() {
        let db = MockDatabase::default();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", None)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_404_when_missing_task() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(None);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_error(Some("Database error".to_string()));
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn returns_403_on_owner_mismatch() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta("did:other", "done", "ipfs")));
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_409_when_in_progress() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta("did:me", "in_progress", "ipfs")));
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn returns_422_when_archive_only() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta("did:me", "done", "archive")));
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn deletes_ipfs_task_on_success() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta("did:me", "done", "ipfs")));
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Verify that a deletion task was queued
        let task = rx.try_recv();
        assert!(task.is_ok());
    }

    #[tokio::test]
    async fn updates_storage_mode_for_full_task() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta("did:me", "done", "full")));
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Verify that a deletion task was queued
        let task = rx.try_recv();
        assert!(task.is_ok());
    }
}
