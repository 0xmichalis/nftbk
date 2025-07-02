use axum::http::StatusCode as AxumStatusCode;
use axum::{
    extract::{Path as AxumPath, State},
    Json,
};

use crate::api::StatusResponse;
use crate::server::{get_backup_status_and_error, AppState};

pub async fn handle_status(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Result<Json<StatusResponse>, AxumStatusCode> {
    // Read archive_format from metadata
    let metadata_path = format!("{}/nftbk-{}-metadata.json", state.base_dir, task_id);
    let archive_format = match tokio::fs::read_to_string(&metadata_path).await {
        Ok(content) => {
            let v: serde_json::Value = serde_json::from_str(&content).unwrap_or_default();
            v.get("archive_format")
                .and_then(|s| s.as_str())
                .unwrap_or("zip")
                .to_string()
        }
        Err(_) => "zip".to_string(),
    };
    let tasks = state.tasks.lock().await;
    let (status, error) =
        get_backup_status_and_error(&state, &task_id, &tasks, &archive_format).await;
    if status == "expired" {
        return Err(AxumStatusCode::NOT_FOUND);
    }
    Ok(Json(StatusResponse { status, error }))
}
