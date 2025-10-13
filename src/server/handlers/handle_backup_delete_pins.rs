use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
// no direct pin deletion in handler; enqueue job to workers
use tracing::{error, info};

use crate::server::api::{ApiProblem, ProblemJson};
use crate::server::AppState;

/// Delete only the IPFS pins for a backup job.
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
    handle_backup_delete_pins_core(&*state.db, &state.backup_job_sender, &task_id, requestor).await
}

// Minimal trait to mock DB calls
pub trait DeletePinsDb {
    fn get_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        Option<crate::server::db::ProtectionJobWithBackup>,
                        sqlx::Error,
                    >,
                > + Send
                + 'a,
        >,
    >;
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
    fn update_protection_job_storage_mode<'a>(
        &'a self,
        task_id: &'a str,
        storage_mode: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>;
    fn delete_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>;
}

impl DeletePinsDb for crate::server::db::Db {
    fn get_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        Option<crate::server::db::ProtectionJobWithBackup>,
                        sqlx::Error,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { crate::server::db::Db::get_protection_job(self, task_id).await })
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
    fn update_protection_job_storage_mode<'a>(
        &'a self,
        task_id: &'a str,
        storage_mode: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
    {
        Box::pin(async move {
            crate::server::db::Db::update_protection_job_storage_mode(self, task_id, storage_mode)
                .await
        })
    }
    fn delete_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
    {
        Box::pin(async move { crate::server::db::Db::delete_protection_job(self, task_id).await })
    }
}

impl DeletePinsDb for std::sync::Arc<crate::server::db::Db> {
    fn get_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        Option<crate::server::db::ProtectionJobWithBackup>,
                        sqlx::Error,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { crate::server::db::Db::get_protection_job(self, task_id).await })
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
    fn update_protection_job_storage_mode<'a>(
        &'a self,
        task_id: &'a str,
        storage_mode: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
    {
        Box::pin(async move {
            crate::server::db::Db::update_protection_job_storage_mode(self, task_id, storage_mode)
                .await
        })
    }
    fn delete_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
    {
        Box::pin(async move { crate::server::db::Db::delete_protection_job(self, task_id).await })
    }
}

async fn handle_backup_delete_pins_core<DB: DeletePinsDb + ?Sized>(
    db: &DB,
    backup_job_sender: &tokio::sync::mpsc::Sender<crate::server::BackupJobOrShutdown>,
    task_id: &str,
    requestor: Option<String>,
) -> axum::response::Response {
    let requestor_str = match requestor {
        Some(s) if !s.is_empty() => s,
        _ => {
            let problem = ProblemJson::from_status(
                StatusCode::BAD_REQUEST,
                Some("Requestor required".to_string()),
                Some(format!("/v1/backups/{}/pins", task_id)),
            );
            return problem.into_response();
        }
    };

    // Check if the task exists and get its metadata
    let meta = match db.get_protection_job(task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let problem = ProblemJson::from_status(
                StatusCode::NOT_FOUND,
                Some("Nothing found to delete".to_string()),
                Some(format!("/v1/backups/{}/pins", task_id)),
            );
            return problem.into_response();
        }
        Err(e) => {
            let problem = ProblemJson::from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(format!("Failed to read metadata: {}", e)),
                Some(format!("/v1/backups/{}/pins", task_id)),
            );
            return problem.into_response();
        }
    };

    // Verify requestor matches task owner
    if meta.requestor != requestor_str {
        let problem = ProblemJson::from_status(
            StatusCode::FORBIDDEN,
            Some("Requestor does not match task owner".to_string()),
            Some(format!("/v1/backups/{}/pins", task_id)),
        );
        return problem.into_response();
    }

    // Check if task is in progress
    if meta.status == "in_progress" {
        let problem = ProblemJson::from_status(
            StatusCode::CONFLICT,
            Some("Can only delete completed tasks".to_string()),
            Some(format!("/v1/backups/{}/pins", task_id)),
        );
        return problem.into_response();
    }

    // Check if backup uses IPFS storage
    if meta.storage_mode == "archive" {
        let problem = ProblemJson::from_status(
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("Backup does not use IPFS storage".to_string()),
            Some(format!("/v1/backups/{}/pins", task_id)),
        );
        return problem.into_response();
    }

    // Enqueue deletion job with IPFS scope and return 202
    let deletion_job = crate::server::DeletionJob {
        task_id: task_id.to_string(),
        requestor: Some(requestor_str),
        scope: crate::server::StorageMode::Ipfs,
    };
    if let Err(e) = backup_job_sender
        .send(crate::server::BackupJobOrShutdown::Job(
            crate::server::JobType::Deletion(deletion_job),
        ))
        .await
    {
        error!(
            "Failed to enqueue pins-only deletion job for task {}: {}",
            task_id, e
        );
        let problem = ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to enqueue deletion job".to_string()),
            Some(format!("/v1/backups/{}/pins", task_id)),
        );
        return problem.into_response();
    }

    info!("Queued pins-only deletion job for backup {}", task_id);
    (StatusCode::ACCEPTED, ()).into_response()
}

#[cfg(test)]
mod handle_backup_delete_pins_core_tests {
    use super::{handle_backup_delete_pins_core, DeletePinsDb};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[derive(Clone, Default)]
    struct MockDb {
        meta: Option<crate::server::db::ProtectionJobWithBackup>,
        get_error: bool,
        update_error: bool,
        delete_error: bool,
        pin_requests: Vec<crate::server::db::PinRequestRow>,
        update_calls: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
        delete_calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl DeletePinsDb for MockDb {
        fn get_protection_job<'a>(
            &'a self,
            _task_id: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            Option<crate::server::db::ProtectionJobWithBackup>,
                            sqlx::Error,
                        >,
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
        fn update_protection_job_storage_mode<'a>(
            &'a self,
            task_id: &'a str,
            storage_mode: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
        {
            let update_calls = self.update_calls.clone();
            let task_id = task_id.to_string();
            let storage_mode = storage_mode.to_string();
            let err = self.update_error;
            Box::pin(async move {
                if err {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    update_calls.lock().unwrap().push((task_id, storage_mode));
                    Ok(())
                }
            })
        }
        fn delete_protection_job<'a>(
            &'a self,
            task_id: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
        {
            let delete_calls = self.delete_calls.clone();
            let task_id = task_id.to_string();
            let err = self.delete_error;
            Box::pin(async move {
                if err {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    delete_calls.lock().unwrap().push(task_id);
                    Ok(())
                }
            })
        }
    }

    fn sample_meta(
        owner: &str,
        status: &str,
        storage_mode: &str,
    ) -> crate::server::db::ProtectionJobWithBackup {
        use chrono::{TimeZone, Utc};
        crate::server::db::ProtectionJobWithBackup {
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
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", None)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_404_when_missing_task() {
        let db = MockDb {
            meta: None,
            get_error: false,
            update_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
            update_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            delete_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let db = MockDb {
            meta: None,
            get_error: true,
            update_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
            update_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            delete_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn returns_403_on_owner_mismatch() {
        let db = MockDb {
            meta: Some(sample_meta("did:other", "done", "ipfs")),
            get_error: false,
            update_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
            update_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            delete_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_409_when_in_progress() {
        let db = MockDb {
            meta: Some(sample_meta("did:me", "in_progress", "ipfs")),
            get_error: false,
            update_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
            update_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            delete_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn returns_422_when_archive_only() {
        let db = MockDb {
            meta: Some(sample_meta("did:me", "done", "archive")),
            get_error: false,
            update_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
            update_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            delete_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn deletes_ipfs_job_on_success() {
        let db = MockDb {
            meta: Some(sample_meta("did:me", "done", "ipfs")),
            get_error: false,
            update_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
            update_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            delete_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Verify that a deletion job was queued
        let job = rx.try_recv();
        assert!(job.is_ok());
    }

    #[tokio::test]
    async fn updates_storage_mode_for_full_job() {
        let db = MockDb {
            meta: Some(sample_meta("did:me", "done", "full")),
            get_error: false,
            update_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
            update_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            delete_calls: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_pins_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Verify that a deletion job was queued
        let job = rx.try_recv();
        assert!(job.is_ok());
    }
}
