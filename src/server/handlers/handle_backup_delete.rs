use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use tracing::{error, info};

use crate::server::api::{ApiProblem, ProblemJson};
use crate::server::{AppState, BackupTaskOrShutdown, DeletionTask, TaskType};

/// Delete a backup task for the authenticated user. This will queue a deletion task that will
/// delete the backup files from the filesystem (if the backup used filesystem storage), unpin any IPFS content
/// (if the backup used IPFS storage), and remove the metadata from the database.
/// The deletion is processed asynchronously by workers.
#[utoipa::path(
    delete,
    path = "/v1/backups/{task_id}",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 202, description = "Backup deletion task queued successfully"),
        (status = 400, description = "Bad request", body = ApiProblem, content_type = "application/problem+json"),
        (status = 403, description = "Requestor does not match task owner", body = ApiProblem, content_type = "application/problem+json"),
        (status = 404, description = "Task not found", body = ApiProblem, content_type = "application/problem+json"),
        (status = 409, description = "Can only delete completed tasks", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup_delete(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    Extension(requestor): Extension<Option<String>>,
) -> impl IntoResponse {
    handle_backup_delete_core(&*state.db, &state.backup_task_sender, &task_id, requestor).await
}

// Minimal trait to mock DB calls
pub trait DeleteDb {
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
    fn delete_backup_task<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>;
    fn get_pin_requests_by_task_id<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Vec<crate::server::db::PinRequestRow>, sqlx::Error>,
                > + Send
                + 'a,
        >,
    >;
}

impl DeleteDb for crate::server::db::Db {
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
    fn delete_backup_task<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
    {
        Box::pin(async move { crate::server::db::Db::delete_backup_task(self, task_id).await })
    }
    fn get_pin_requests_by_task_id<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Vec<crate::server::db::PinRequestRow>, sqlx::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(
            async move { crate::server::db::Db::get_pin_requests_by_task_id(self, task_id).await },
        )
    }
}

impl DeleteDb for std::sync::Arc<crate::server::db::Db> {
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
    fn delete_backup_task<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
    {
        Box::pin(async move { crate::server::db::Db::delete_backup_task(self, task_id).await })
    }
    fn get_pin_requests_by_task_id<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Vec<crate::server::db::PinRequestRow>, sqlx::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(
            async move { crate::server::db::Db::get_pin_requests_by_task_id(self, task_id).await },
        )
    }
}

async fn handle_backup_delete_core<DB: DeleteDb + ?Sized>(
    db: &DB,
    backup_task_sender: &tokio::sync::mpsc::Sender<BackupTaskOrShutdown>,
    task_id: &str,
    requestor: Option<String>,
) -> axum::response::Response {
    let requestor_str = match requestor {
        Some(s) if !s.is_empty() => s,
        _ => {
            let problem = ProblemJson::from_status(
                StatusCode::BAD_REQUEST,
                Some("Requestor required".to_string()),
                Some(format!("/v1/backups/{}", task_id)),
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
                Some(format!("/v1/backups/{}", task_id)),
            );
            return problem.into_response();
        }
        Err(e) => {
            let problem = ProblemJson::from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(format!("Failed to read metadata: {}", e)),
                Some(format!("/v1/backups/{}", task_id)),
            );
            return problem.into_response();
        }
    };

    // Verify requestor matches task owner
    if meta.requestor != requestor_str {
        let problem = ProblemJson::from_status(
            StatusCode::FORBIDDEN,
            Some("Requestor does not match task owner".to_string()),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }

    // Check if task is in progress
    if meta.status == "in_progress" {
        let problem = ProblemJson::from_status(
            StatusCode::CONFLICT,
            Some("Can only delete completed tasks".to_string()),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }

    // Create deletion task and queue it
    let deletion_task = DeletionTask {
        task_id: task_id.to_string(),
        requestor: Some(requestor_str.clone()),
        scope: crate::server::StorageMode::Full,
    };

    if let Err(e) = backup_task_sender
        .send(BackupTaskOrShutdown::Task(TaskType::Deletion(
            deletion_task,
        )))
        .await
    {
        error!(
            "Failed to enqueue deletion task for task {}: {}",
            task_id, e
        );
        let problem = ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to enqueue deletion task".to_string()),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }

    info!("Queued deletion task for backup {}", task_id);
    (StatusCode::ACCEPTED, ()).into_response()
}

#[cfg(test)]
mod handle_backup_delete_core_tests {
    use super::{handle_backup_delete_core, DeleteDb};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[derive(Clone, Default)]
    struct MockDb {
        meta: Option<crate::server::db::BackupTask>,
        get_error: bool,
        delete_error: bool,
        pin_requests: Vec<crate::server::db::PinRequestRow>,
    }

    impl DeleteDb for MockDb {
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
        fn delete_backup_task<'a>(
            &'a self,
            _task_id: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
        {
            let err = self.delete_error;
            Box::pin(async move {
                if err {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    Ok(())
                }
            })
        }
        fn get_pin_requests_by_task_id<'a>(
            &'a self,
            _task_id: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<Vec<crate::server::db::PinRequestRow>, sqlx::Error>,
                    > + Send
                    + 'a,
            >,
        > {
            let pin_requests = self.pin_requests.clone();
            Box::pin(async move { Ok(pin_requests) })
        }
    }

    fn sample_meta(owner: &str, status: &str, storage_mode: &str) -> crate::server::db::BackupTask {
        use chrono::{TimeZone, Utc};
        crate::server::db::BackupTask {
            task_id: "t1".to_string(),
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            requestor: owner.to_string(),
            nft_count: 1,
            tokens: serde_json::json!([{"chain":"ethereum","tokens":["0xabc:1"]}]),
            status: status.to_string(),
            error_log: None,
            fatal_error: None,
            storage_mode: storage_mode.to_string(),
            archive_format: if storage_mode == "archive" || storage_mode == "full" {
                Some("zip".to_string())
            } else {
                None
            },
            expires_at: None,
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn returns_400_when_missing_requestor() {
        let db = MockDb::default();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_core(&db, &tx, "t1", None)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_404_when_missing_task() {
        let db = MockDb {
            meta: None,
            get_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let db = MockDb {
            meta: None,
            get_error: true,
            delete_error: false,
            pin_requests: Vec::new(),
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn returns_403_on_owner_mismatch() {
        let db = MockDb {
            meta: Some(sample_meta("did:other", "done", "archive")),
            get_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_409_when_in_progress() {
        let db = MockDb {
            meta: Some(sample_meta("did:me", "in_progress", "archive")),
            get_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn returns_202_on_success_and_queues_deletion() {
        let db = MockDb {
            meta: Some(sample_meta("did:me", "done", "archive")),
            get_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Verify that a deletion task was queued
        let task = rx.try_recv();
        assert!(task.is_ok());
    }
}
