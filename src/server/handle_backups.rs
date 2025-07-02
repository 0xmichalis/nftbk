use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::{DateTime, Duration};
use serde::{Deserialize, Serialize};

use crate::server::{get_backup_status_and_error, AppState};

#[derive(Serialize, Deserialize)]
struct UserBackupMetadata {
    created_at: Option<String>,
    expires_at: Option<String>,
    task_id: String,
    status: String,
    error: Option<String>,
    error_log: Option<String>,
    nft_count: usize,
}

pub async fn handle_backups(
    Extension(user_did): Extension<Option<String>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let user_did = match user_did {
        Some(did) if !did.is_empty() => did,
        _ => return (StatusCode::UNAUTHORIZED, "Missing user DID").into_response(),
    };
    let by_requestor_dir = format!("{}/by_requestor", state.base_dir);
    let user_file = format!("{}/{}.json", by_requestor_dir, user_did);
    let task_ids: Vec<String> = match tokio::fs::read_to_string(&user_file).await {
        Ok(content) => serde_json::from_str::<Vec<String>>(&content).unwrap_or_default(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to read user index",
            )
                .into_response()
        }
    };
    let mut results = Vec::new();
    let tasks = state.tasks.lock().await;
    for task_id in &task_ids {
        let log_path = format!("{}/nftbk-{}.log", state.base_dir, task_id);
        let error_log = (tokio::fs::read_to_string(&log_path).await).ok();
        let metadata_path = format!("{}/nftbk-{}-metadata.json", state.base_dir, task_id);
        let (nft_count, created_at, expires_at, archive_format) =
            match tokio::fs::read_to_string(&metadata_path).await {
                Ok(content) => {
                    let v: serde_json::Value = serde_json::from_str(&content).unwrap_or_default();
                    let nft_count = v
                        .get("nft_count")
                        .and_then(|n| n.as_u64())
                        .map(|n| n as usize)
                        .unwrap_or(0);
                    let created_at_str = v
                        .get("created_at")
                        .and_then(|s| s.as_str())
                        .map(|s| s.to_string());
                    let archive_format = v
                        .get("archive_format")
                        .and_then(|s| s.as_str())
                        .unwrap_or("zip")
                        .to_string();
                    let expires_at = if !state.pruner_enabled {
                        None
                    } else {
                        created_at_str.as_ref().and_then(|s| {
                            DateTime::parse_from_rfc3339(s).ok().map(|dt| {
                                (dt + Duration::days(state.pruner_retention_days as i64))
                                    .to_rfc3339()
                            })
                        })
                    };
                    (nft_count, created_at_str, expires_at, archive_format)
                }
                Err(_) => (0, None, None, "zip".to_string()),
            };
        let (status, error) =
            get_backup_status_and_error(&state, task_id, &tasks, &archive_format).await;
        results.push(UserBackupMetadata {
            task_id: task_id.clone(),
            status,
            error,
            error_log,
            nft_count,
            created_at,
            expires_at,
        });
    }
    Json(results).into_response()
}
