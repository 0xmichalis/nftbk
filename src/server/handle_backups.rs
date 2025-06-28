use crate::server::{check_backup_on_disk, AppState, TaskStatus};
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct UserBackupInfo {
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
        let (status, error) = if let Some(task) = tasks.get(task_id) {
            match &task.status {
                TaskStatus::InProgress => ("in_progress".to_string(), None),
                TaskStatus::Done => ("done".to_string(), None),
                TaskStatus::Error(e) => ("error".to_string(), Some(e.clone())),
            }
        } else if check_backup_on_disk(&state.base_dir, task_id, state.unsafe_skip_checksum_check)
            .await
            .is_some()
        {
            ("done".to_string(), None)
        } else {
            ("unknown".to_string(), None)
        };
        let log_path = format!("{}/nftbk-{}.log", state.base_dir, task_id);
        let error_log = (tokio::fs::read_to_string(&log_path).await).ok();
        let metadata_path = format!("{}/nftbk-{}-metadata.json", state.base_dir, task_id);
        let nft_count = match tokio::fs::read_to_string(&metadata_path).await {
            Ok(content) => serde_json::from_str::<serde_json::Value>(&content)
                .ok()
                .and_then(|v| {
                    v.get("nft_count")
                        .and_then(|n| n.as_u64())
                        .map(|n| n as usize)
                })
                .unwrap_or(0),
            Err(_) => 0,
        };
        results.push(UserBackupInfo {
            task_id: task_id.clone(),
            status,
            error,
            error_log,
            nft_count,
        });
    }
    Json(results).into_response()
}
