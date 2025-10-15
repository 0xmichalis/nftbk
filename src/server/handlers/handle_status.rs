use axum::http::StatusCode as AxumStatusCode;
use axum::response::IntoResponse;
use axum::{
    extract::{Path as AxumPath, State},
    Json,
};

use crate::server::api::{ApiProblem, ProblemJson, StatusResponse, SubresourceStatus};
use crate::server::database_trait::Database;
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

async fn handle_status_core<DB: Database + ?Sized>(
    db: &DB,
    task_id: &str,
) -> Result<Json<StatusResponse>, AxumStatusCode> {
    let meta = match db.get_backup_task(task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => return Err(AxumStatusCode::NOT_FOUND),
        Err(_) => return Err(AxumStatusCode::INTERNAL_SERVER_ERROR),
    };
    let archive = SubresourceStatus {
        status: meta.archive_status.clone(),
        fatal_error: meta.archive_fatal_error.clone(),
        error_log: meta.archive_error_log.clone(),
    };
    let ipfs = SubresourceStatus {
        status: meta.ipfs_status.clone(),
        fatal_error: meta.ipfs_fatal_error.clone(),
        error_log: meta.ipfs_error_log.clone(),
    };
    Ok(Json(StatusResponse { archive, ipfs }))
}

#[cfg(test)]
mod handle_status_core_tests {
    use super::handle_status_core;
    use crate::server::api::StatusResponse;
    use crate::server::database_trait::MockDatabase;
    use crate::server::db::BackupTask;
    use axum::http::StatusCode as AxumStatusCode;
    use chrono::{TimeZone, Utc};

    fn sample_meta() -> BackupTask {
        BackupTask {
            task_id: "t1".to_string(),
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            requestor: "did:privy:alice".to_string(),
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
            deleted_at: None,
            archive_deleted_at: None,
            pins_deleted_at: None,
        }
    }

    #[tokio::test]
    async fn returns_200_with_status_payload() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta()));
        let resp = handle_status_core(&db, "t1").await.unwrap();
        let StatusResponse { archive, ipfs } = resp.0;
        assert_eq!(archive.status.as_deref(), Some("done"));
        assert!(archive.fatal_error.is_none());
        // ipfs status is null when None
        assert_eq!(ipfs.status, None);
        assert!(ipfs.fatal_error.is_none());
        // non-fatal logs are optional and omitted when none
    }

    #[tokio::test]
    async fn returns_unknown_when_statuses_absent() {
        let mut m = sample_meta();
        m.archive_status = None;
        m.ipfs_status = None;
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(m));
        let resp = handle_status_core(&db, "t1").await.unwrap();
        let StatusResponse { archive, ipfs } = resp.0;
        assert_eq!(archive.status, None);
        assert_eq!(ipfs.status, None);
    }

    #[tokio::test]
    async fn returns_404_when_missing() {
        let db = MockDatabase::default();
        let err = handle_status_core(&db, "missing").await.err().unwrap();
        assert_eq!(err, AxumStatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_error(Some("Database error".to_string()));
        let err = handle_status_core(&db, "t1").await.err().unwrap();
        assert_eq!(err, AxumStatusCode::INTERNAL_SERVER_ERROR);
    }
}
