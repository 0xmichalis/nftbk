use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use tracing::{error, info, warn};

use crate::server::api::{ApiProblem, ProblemJson};
use crate::server::archive::get_zipped_backup_paths;
use crate::server::AppState;

#[utoipa::path(
    delete,
    path = "/v1/backups/{task_id}",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 204, description = "Backup deleted successfully"),
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
    handle_backup_delete_core(&*state.db, &state.base_dir, &task_id, requestor).await
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
}

async fn handle_backup_delete_core<DB: DeleteDb + ?Sized>(
    db: &DB,
    base_dir: &str,
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
    if meta.requestor != requestor_str {
        let problem = ProblemJson::from_status(
            StatusCode::FORBIDDEN,
            Some("Requestor does not match task owner".to_string()),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }
    if meta.status == "in_progress" {
        let problem = ProblemJson::from_status(
            StatusCode::CONFLICT,
            Some("Can only delete completed tasks".to_string()),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }

    let mut errors = Vec::new();
    let mut deleted_anything = false;

    if let Some(archive_format) = &meta.archive_format {
        let (archive_path, archive_checksum_path) =
            get_zipped_backup_paths(base_dir, task_id, archive_format);
        for path in [&archive_path, &archive_checksum_path] {
            match tokio::fs::remove_file(path).await {
                Ok(_) => {
                    deleted_anything = true;
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!("Failed to delete file {}: {}", path.display(), e);
                        errors.push(format!("Failed to delete file {}: {}", path.display(), e));
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
                warn!("Failed to delete backup dir {}: {}", backup_dir, e);
                errors.push(format!("Failed to delete backup dir {backup_dir}: {e}"));
            }
        }
    }

    if let Err(e) = db.delete_protection_job(task_id).await {
        errors.push(format!("Failed to delete metadata from DB: {e}"));
    } else {
        deleted_anything = true;
    }

    if !deleted_anything {
        let problem = ProblemJson::from_status(
            StatusCode::NOT_FOUND,
            Some("Nothing found to delete".to_string()),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }

    if errors.is_empty() {
        info!("Deleted backup {}", task_id);
        (StatusCode::NO_CONTENT, ()).into_response()
    } else {
        error!("Errors during delete: {:?}", errors);
        ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some(format!("{:?}", errors)),
            Some(format!("/v1/backups/{}", task_id)),
        )
        .into_response()
    }
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
    }

    fn sample_meta(owner: &str, status: &str) -> crate::server::db::ProtectionJobWithBackup {
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
            storage_mode: "filesystem".to_string(),
            archive_format: Some("zip".to_string()),
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn returns_400_when_missing_requestor() {
        let db = MockDb::default();
        let resp = handle_backup_delete_core(&db, "/tmp", "t1", None)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_404_when_missing_task() {
        let db = MockDb {
            meta: None,
            ..Default::default()
        };
        let resp = handle_backup_delete_core(&db, "/tmp", "t1", Some("did:me".to_string()))
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
        };
        let resp = handle_backup_delete_core(&db, "/tmp", "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn returns_403_on_owner_mismatch() {
        let db = MockDb {
            meta: Some(sample_meta("did:other", "done")),
            ..Default::default()
        };
        let resp = handle_backup_delete_core(&db, "/tmp", "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_409_when_in_progress() {
        let db = MockDb {
            meta: Some(sample_meta("did:me", "in_progress")),
            ..Default::default()
        };
        let resp = handle_backup_delete_core(&db, "/tmp", "t1", Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn returns_204_on_success_and_deletes_files() {
        let base = format!(
            "{}/nftbk-test-{}",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let task_id = "t1".to_string();
        tokio::fs::create_dir_all(format!("{}/nftbk-{}", base, task_id))
            .await
            .unwrap();
        let db = MockDb {
            meta: Some(sample_meta("did:me", "done")),
            ..Default::default()
        };
        let resp = handle_backup_delete_core(&db, &base, &task_id, Some("did:me".to_string()))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
