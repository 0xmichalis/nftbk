use axum::http::StatusCode as AxumStatusCode;
use axum::response::IntoResponse;
use axum::{
    extract::{Path as AxumPath, State},
    Json,
};

use crate::server::api::{ApiProblem, ProblemJson, StatusResponse};
use crate::server::db::{BackupTask, Db};
use crate::server::AppState;

/// Get the status of a backup task
#[utoipa::path(
    get,
    path = "/v1/backups/{task_id}",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 200, description = "Backup retrieved successfully", body = StatusResponse),
        (status = 404, description = "Backup not found", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_status(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
) -> axum::response::Response {
    match handle_status_core(&*state.db, &task_id).await {
        Ok(json) => json.into_response(),
        Err(status) => {
            let problem =
                ProblemJson::from_status(status, None, Some(format!("/v1/backups/{task_id}")));
            problem.into_response()
        }
    }
}

// Minimal trait to mock DB calls for unit tests
pub trait StatusDb {
    fn get_backup_task<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<BackupTask>, sqlx::Error>> + Send + 'a>,
    >;
}

impl StatusDb for Db {
    fn get_backup_task<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Option<BackupTask>, sqlx::Error>> + Send + 'a>,
    > {
        Box::pin(async move { Db::get_backup_task(self, task_id).await })
    }
}

async fn handle_status_core<DB: StatusDb + ?Sized>(
    db: &DB,
    task_id: &str,
) -> Result<Json<StatusResponse>, AxumStatusCode> {
    let meta = match db.get_backup_task(task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => return Err(AxumStatusCode::NOT_FOUND),
        Err(_) => return Err(AxumStatusCode::INTERNAL_SERVER_ERROR),
    };
    Ok(Json(StatusResponse {
        status: meta.status,
        error: meta.error_log.clone(),
        error_log: meta.error_log,
    }))
}

#[cfg(test)]
mod handle_status_core_tests {
    use super::{handle_status_core, StatusDb};
    use crate::server::api::StatusResponse;
    use crate::server::db::BackupTask;
    use axum::http::StatusCode as AxumStatusCode;
    use chrono::{TimeZone, Utc};

    #[derive(Default)]
    struct MockDb {
        pub meta: Option<BackupTask>,
        pub error: bool,
    }

    impl StatusDb for MockDb {
        fn get_backup_task<'a>(
            &'a self,
            _task_id: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Option<BackupTask>, sqlx::Error>>
                    + Send
                    + 'a,
            >,
        > {
            let has_error = self.error;
            let meta = self.meta.clone();
            Box::pin(async move {
                if has_error {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    Ok(meta)
                }
            })
        }
    }

    fn sample_meta() -> BackupTask {
        BackupTask {
            task_id: "t1".to_string(),
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            requestor: "did:privy:alice".to_string(),
            nft_count: 1,
            tokens: serde_json::json!([{"chain":"ethereum","tokens":["0xabc:1"]}]),
            status: "done".to_string(),
            error_log: None,
            fatal_error: None,
            storage_mode: "archive".to_string(),
            archive_format: Some("zip".to_string()),
            expires_at: None,
            deleted_at: None,
        }
    }

    #[tokio::test]
    async fn returns_200_with_status_payload() {
        let db = MockDb {
            meta: Some(sample_meta()),
            error: false,
        };
        let resp = handle_status_core(&db, "t1").await.unwrap();
        let StatusResponse {
            status,
            error,
            error_log,
        } = resp.0;
        assert_eq!(status, "done");
        assert!(error.is_none());
        assert!(error_log.is_none());
    }

    #[tokio::test]
    async fn returns_404_when_missing() {
        let db = MockDb {
            meta: None,
            error: false,
        };
        let err = handle_status_core(&db, "missing").await.err().unwrap();
        assert_eq!(err, AxumStatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let db = MockDb {
            meta: None,
            error: true,
        };
        let err = handle_status_core(&db, "t1").await.err().unwrap();
        assert_eq!(err, AxumStatusCode::INTERNAL_SERVER_ERROR);
    }
}
