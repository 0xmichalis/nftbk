use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use tracing::{error, info};

use crate::server::api::{ApiProblem, ProblemJson};
use crate::server::archive::get_zipped_backup_paths;
use crate::server::{AppState, BackupJobOrShutdown, DeletionJob, JobType};

/// Delete a backup job for the authenticated user. This will queue a deletion job that will
/// delete the backup archive files (if the backup used filesystem storage), unpin any IPFS content
/// (if the backup used IPFS storage), and remove the metadata from the database.
/// The deletion is processed asynchronously by workers.
#[utoipa::path(
    delete,
    path = "/v1/backups/{task_id}",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 202, description = "Backup deletion job queued successfully"),
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
    handle_backup_delete_core(&*state.db, &state.backup_job_sender, &task_id, requestor).await
}

// Minimal trait to mock DB calls
pub trait DeleteDb {
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
    fn delete_protection_job<'a>(
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
    fn delete_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
    {
        Box::pin(async move { crate::server::db::Db::delete_protection_job(self, task_id).await })
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
    fn delete_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
    {
        Box::pin(async move { crate::server::db::Db::delete_protection_job(self, task_id).await })
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

/// Delete filesystem files and directories for a given task
/// Returns true if any files were deleted, false if none existed
pub async fn delete_dir_and_archive_for_task(
    base_dir: &str,
    task_id: &str,
    archive_format: Option<&str>,
) -> Result<bool, String> {
    let mut deleted_anything = false;

    if let Some(archive_format) = archive_format {
        let (archive_path, archive_checksum_path) =
            get_zipped_backup_paths(base_dir, task_id, archive_format);
        for path in [&archive_path, &archive_checksum_path] {
            match tokio::fs::remove_file(path).await {
                Ok(_) => {
                    deleted_anything = true;
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        return Err(format!("Failed to delete file {}: {}", path.display(), e));
                    }
                }
            }
        }
    }

    let backup_dir = format!("{}/nftbk-{}", base_dir, task_id);
    match tokio::fs::remove_dir_all(&backup_dir).await {
        Ok(_) => {
            deleted_anything = true;
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(format!("Failed to delete backup dir {backup_dir}: {e}"));
            }
        }
    }

    Ok(deleted_anything)
}

/// Delete IPFS pins for a given task ID
/// Returns true if any pins were deleted, false if none existed
pub async fn delete_ipfs_pins_for_task<DB: DeleteDb + ?Sized>(
    db: &DB,
    task_id: &str,
    ipfs_providers: &[Box<dyn crate::ipfs::IpfsPinningProvider>],
) -> Result<bool, String> {
    let pin_requests = db
        .get_pin_requests_by_task_id(task_id)
        .await
        .map_err(|e| format!("Failed to get pin requests for task {}: {}", task_id, e))?;

    let mut deleted_anything = false;

    for pin_request in &pin_requests {
        // Find the matching provider instance
        let provider = ipfs_providers
            .iter()
            .find(|provider| provider.provider_name() == pin_request.provider);

        let provider = provider.ok_or_else(|| {
            format!(
                "No provider instance found for provider {} when unpinning {}",
                pin_request.provider, pin_request.cid
            )
        })?;

        provider
            .delete_pin(&pin_request.request_id)
            .await
            .map_err(|e| {
                format!(
                    "Failed to unpin {} from provider {} for task {}: {}",
                    pin_request.cid, pin_request.provider, task_id, e
                )
            })?;

        info!(
            "Successfully unpinned {} from provider {} for task {}",
            pin_request.cid, pin_request.provider, task_id
        );
        deleted_anything = true;
    }

    Ok(deleted_anything)
}

async fn handle_backup_delete_core<DB: DeleteDb + ?Sized>(
    db: &DB,
    backup_job_sender: &tokio::sync::mpsc::Sender<BackupJobOrShutdown>,
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
    let meta = match db.get_protection_job(task_id).await {
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

    // Create deletion job and queue it
    let deletion_job = DeletionJob {
        task_id: task_id.to_string(),
        requestor: Some(requestor_str),
    };

    if let Err(e) = backup_job_sender
        .send(BackupJobOrShutdown::Job(JobType::Deletion(deletion_job)))
        .await
    {
        error!("Failed to enqueue deletion job for task {}: {}", task_id, e);
        let problem = ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to enqueue deletion job".to_string()),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }

    info!("Queued deletion job for backup {}", task_id);
    (StatusCode::ACCEPTED, ()).into_response()
}

#[cfg(test)]
mod handle_backup_delete_core_tests {
    use super::{handle_backup_delete_core, DeleteDb};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[derive(Clone, Default)]
    struct MockDb {
        meta: Option<crate::server::db::ProtectionJobWithBackup>,
        get_error: bool,
        delete_error: bool,
        pin_requests: Vec<crate::server::db::PinRequestRow>,
    }

    impl DeleteDb for MockDb {
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
        fn delete_protection_job<'a>(
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
            archive_format: if storage_mode == "filesystem" || storage_mode == "both" {
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
            meta: Some(sample_meta("did:other", "done", "filesystem")),
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
            meta: Some(sample_meta("did:me", "in_progress", "filesystem")),
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
            meta: Some(sample_meta("did:me", "done", "filesystem")),
            get_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let resp = handle_backup_delete_core(&db, &tx, "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // Verify that a deletion job was queued
        let job = rx.try_recv();
        assert!(job.is_ok());
    }
}
