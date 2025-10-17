pub mod handle_archive_download;
pub mod handle_backup;
pub mod handle_backup_create;
pub mod handle_backup_delete_archive;
pub mod handle_backup_delete_pins;
pub mod handle_backup_retries;
pub mod handle_backups;
pub mod handle_pins;

use axum::http::StatusCode;
use axum::response::IntoResponse;

use crate::server::api::ProblemJson;
use crate::server::database::r#trait::Database;

/// Verify that the `requestor` owns the backup `task_id`.
/// Returns `(Option<BackupTask>, Option<Response>)` where the response is a problem when not OK.
pub async fn verify_requestor_owns_task<DB: Database + ?Sized>(
    db: &DB,
    task_id: &str,
    requestor: Option<String>,
    endpoint_path: &str,
) -> (
    Option<crate::server::database::BackupTask>,
    Option<axum::response::Response>,
) {
    let meta = match db.get_backup_task(task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let problem = ProblemJson::from_status(
                StatusCode::NOT_FOUND,
                Some("Backup not found".to_string()),
                Some(endpoint_path.to_string()),
            );
            return (None, Some(problem.into_response()));
        }
        Err(_) => {
            let problem = ProblemJson::from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("Failed to read metadata from DB".to_string()),
                Some(endpoint_path.to_string()),
            );
            return (None, Some(problem.into_response()));
        }
    };
    let req_requestor = requestor.unwrap_or_default();
    if !meta.requestor.is_empty() && req_requestor != meta.requestor {
        let problem = ProblemJson::from_status(
            StatusCode::FORBIDDEN,
            Some("Requestor does not match task owner".to_string()),
            Some(endpoint_path.to_string()),
        );
        return (None, Some(problem.into_response()));
    }
    (Some(meta), None)
}

#[cfg(test)]
mod verify_owns_task_tests {
    use super::verify_requestor_owns_task;
    use crate::server::database::r#trait::MockDatabase;
    use crate::server::database::BackupTask;
    use axum::http::StatusCode;
    use chrono::{TimeZone, Utc};

    fn sample_meta_with_requestor(req: &str) -> BackupTask {
        BackupTask {
            task_id: "t1".to_string(),
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            requestor: req.to_string(),
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
        }
    }

    #[tokio::test]
    async fn returns_meta_when_owner_matches() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta_with_requestor("did:privy:alice")));
        let (meta, problem) = verify_requestor_owns_task(
            &db,
            "t1",
            Some("did:privy:alice".to_string()),
            "/v1/backups/t1",
        )
        .await;
        assert!(problem.is_none());
        assert!(meta.is_some());
        assert_eq!(meta.unwrap().task_id, "t1");
    }

    #[tokio::test]
    async fn returns_404_when_missing() {
        let db = MockDatabase::default();
        let (_meta, problem) = verify_requestor_owns_task(
            &db,
            "missing",
            Some("did:privy:alice".to_string()),
            "/v1/backups/missing",
        )
        .await;
        let resp = problem.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_403_on_mismatch() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta_with_requestor("did:privy:bob")));
        let (_meta, problem) = verify_requestor_owns_task(
            &db,
            "t1",
            Some("did:privy:alice".to_string()),
            "/v1/backups/t1",
        )
        .await;
        let resp = problem.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_error(Some("db error".to_string()));
        let (_meta, problem) = verify_requestor_owns_task(
            &db,
            "t1",
            Some("did:privy:alice".to_string()),
            "/v1/backups/t1",
        )
        .await;
        let resp = problem.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
