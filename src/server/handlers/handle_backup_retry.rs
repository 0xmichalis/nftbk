use axum::http::StatusCode;
use axum::Json;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension,
};

use crate::server::api::BackupResponse;
use crate::server::api::{ApiProblem, BackupRequest, ProblemJson};
use crate::server::AppState;
use crate::server::BackupTask;
use crate::server::BackupTaskOrShutdown;
use crate::server::TaskType;
use crate::server::Tokens;
use tracing::{error, info};

/// Retry a backup task for the authenticated user. This task will be processed asynchronously and the result will be available in the /v1/backups/{task_id} endpoint.
#[utoipa::path(
    post,
    path = "/v1/backups/{task_id}/retry",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 202, description = "Backup retry initiated successfully", body = BackupResponse),
        (status = 400, description = "Task is already in progress", body = ApiProblem, content_type = "application/problem+json"),
        (status = 403, description = "Requestor does not match task owner", body = ApiProblem, content_type = "application/problem+json"),
        (status = 404, description = "Task not found", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup_retry(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    Extension(requestor): Extension<Option<String>>,
) -> impl IntoResponse {
    handle_backup_retry_core(
        &*state.db,
        &state.backup_task_sender,
        &task_id,
        requestor,
        state.pruner_retention_days,
    )
    .await
}

// Minimal trait to mock DB calls
pub trait RetryDb {
    fn get_backup_task<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Option<crate::server::db::BackupTask>, sqlx::Error>,
                > + Send
                + 'a,
        >,
    >;
    fn retry_backup<'a>(
        &'a self,
        task_id: &'a str,
        retention_days: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>;
}

impl RetryDb for crate::server::db::Db {
    fn get_backup_task<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Option<crate::server::db::BackupTask>, sqlx::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { crate::server::db::Db::get_backup_task(self, task_id).await })
    }
    fn retry_backup<'a>(
        &'a self,
        task_id: &'a str,
        retention_days: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
    {
        Box::pin(
            async move { crate::server::db::Db::retry_backup(self, task_id, retention_days).await },
        )
    }
}

async fn handle_backup_retry_core<DB: RetryDb + ?Sized>(
    db: &DB,
    backup_task_sender: &tokio::sync::mpsc::Sender<BackupTaskOrShutdown>,
    task_id: &str,
    requestor: Option<String>,
    retention_days: u64,
) -> axum::response::Response {
    // Fetch metadata from DB once
    let meta = match db.get_backup_task(task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let problem = ProblemJson::from_status(
                StatusCode::NOT_FOUND,
                Some("Metadata not found".to_string()),
                Some(format!("/v1/backups/{task_id}/retry")),
            );
            return problem.into_response();
        }
        Err(_) => {
            let problem = ProblemJson::from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("Failed to read metadata from DB".to_string()),
                Some(format!("/v1/backups/{task_id}/retry")),
            );
            return problem.into_response();
        }
    };

    // Check if task is in progress or being deleted
    if meta.status == "in_progress" {
        let problem = ProblemJson::from_status(
            StatusCode::BAD_REQUEST,
            Some("Task is already in progress".to_string()),
            Some(format!("/v1/backups/{task_id}/retry")),
        );
        return problem.into_response();
    }

    // Check if task is being deleted
    if meta.deleted_at.is_some() {
        let problem = ProblemJson::from_status(
            StatusCode::BAD_REQUEST,
            Some("Task is being deleted and cannot be retried".to_string()),
            Some(format!("/v1/backups/{task_id}/retry")),
        );
        return problem.into_response();
    }

    // Ensure the requestor matches the one in the metadata
    let req_requestor = requestor.clone().unwrap_or_default();
    let meta_requestor = meta.requestor.clone();
    if !meta_requestor.is_empty() && req_requestor != meta_requestor {
        let problem = ProblemJson::from_status(
            StatusCode::FORBIDDEN,
            Some("Requestor does not match task owner".to_string()),
            Some(format!("/v1/backups/{task_id}/retry")),
        );
        return problem.into_response();
    }

    let _ = db.retry_backup(task_id, retention_days).await;

    // Re-run backup task
    let tokens: Vec<Tokens> = serde_json::from_value(meta.tokens.clone()).unwrap_or_default();
    let storage_mode = meta
        .storage_mode
        .parse()
        .unwrap_or(crate::server::StorageMode::Full);
    let pin_on_ipfs = storage_mode != crate::server::StorageMode::Archive;
    let create_archive = storage_mode != crate::server::StorageMode::Ipfs;

    let backup_task = BackupTask {
        task_id: task_id.to_string(),
        request: BackupRequest {
            tokens,
            pin_on_ipfs,
            create_archive,
        },
        force: true,
        storage_mode,
        archive_format: meta.archive_format.clone(),
        requestor: requestor.clone(),
    };
    if let Err(e) = backup_task_sender
        .send(BackupTaskOrShutdown::Task(TaskType::Creation(backup_task)))
        .await
    {
        error!("Failed to enqueue backup task: {}", e);
        let problem = ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to enqueue backup task".to_string()),
            Some(format!("/v1/backups/{task_id}/retry")),
        );
        return problem.into_response();
    }
    info!(
        "Retrying backup task {} (requestor: {})",
        task_id,
        requestor.clone().unwrap_or_default()
    );
    (
        StatusCode::ACCEPTED,
        Json(BackupResponse {
            task_id: task_id.to_string(),
        }),
    )
        .into_response()
}

#[cfg(test)]
mod handle_backup_retry_core_tests {
    use super::{handle_backup_retry_core, RetryDb};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use tokio::sync::mpsc;

    #[derive(Clone, Default)]
    struct MockDb {
        meta: Option<crate::server::db::BackupTask>,
        get_error: bool,
        retry_error: bool,
    }

    impl RetryDb for MockDb {
        fn get_backup_task<'a>(
            &'a self,
            _task_id: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<Option<crate::server::db::BackupTask>, sqlx::Error>,
                    > + Send
                    + 'a,
            >,
        > {
            let meta = self.meta.clone();
            let err = self.get_error;
            Box::pin(async move {
                if err {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    Ok(meta)
                }
            })
        }
        fn retry_backup<'a>(
            &'a self,
            _task_id: &'a str,
            _retention_days: u64,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
        {
            let err = self.retry_error;
            Box::pin(async move {
                if err {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    Ok(())
                }
            })
        }
    }

    fn sample_meta(owner: &str, status: &str) -> crate::server::db::BackupTask {
        use chrono::{TimeZone, Utc};
        crate::server::db::BackupTask {
            task_id: "t1".to_string(),
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            requestor: owner.to_string(),
            nft_count: 1,
            tokens: serde_json::json!([{"chain":"ethereum","tokens":["0xabc:1"]}]),
            status: status.to_string(),
            archive_error_log: None,
            ipfs_error_log: None,
            fatal_error: None,
            storage_mode: "archive".to_string(),
            archive_format: Some("zip".to_string()),
            expires_at: None,
            deleted_at: None,
            archive_deleted_at: None,
            pins_deleted_at: None,
        }
    }

    #[tokio::test]
    async fn returns_404_when_missing_task() {
        let db = MockDb {
            meta: None,
            ..Default::default()
        };
        let (tx, _rx) = mpsc::channel(1);
        let resp = handle_backup_retry_core(&db, &tx, "t1", Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let db = MockDb {
            meta: None,
            get_error: true,
            retry_error: false,
        };
        let (tx, _rx) = mpsc::channel(1);
        let resp = handle_backup_retry_core(&db, &tx, "t1", Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn returns_400_when_in_progress() {
        let db = MockDb {
            meta: Some(sample_meta("did:me", "in_progress")),
            ..Default::default()
        };
        let (tx, _rx) = mpsc::channel(1);
        let resp = handle_backup_retry_core(&db, &tx, "t1", Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_400_when_being_deleted() {
        let mut meta = sample_meta("did:me", "done");
        meta.deleted_at = Some(chrono::Utc::now());
        let db = MockDb {
            meta: Some(meta),
            ..Default::default()
        };
        let (tx, _rx) = mpsc::channel(1);
        let resp = handle_backup_retry_core(&db, &tx, "t1", Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_403_on_owner_mismatch() {
        let db = MockDb {
            meta: Some(sample_meta("did:other", "done")),
            ..Default::default()
        };
        let (tx, _rx) = mpsc::channel(1);
        let resp = handle_backup_retry_core(&db, &tx, "t1", Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_500_when_enqueue_fails() {
        let db = MockDb {
            meta: Some(sample_meta("did:me", "done")),
            ..Default::default()
        };
        let (tx, rx) = mpsc::channel(1);
        drop(rx); // close receiver to force send error
        let resp = handle_backup_retry_core(&db, &tx, "t1", Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn returns_202_on_success() {
        let db = MockDb {
            meta: Some(sample_meta("did:me", "error")),
            ..Default::default()
        };
        let (tx, mut rx) = mpsc::channel(1);
        let resp = handle_backup_retry_core(&db, &tx, "t1", Some("did:me".to_string()), 7)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        // Ensure task enqueued
        let task = rx.try_recv();
        assert!(task.is_ok());
    }
}
