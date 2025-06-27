use axum::http::StatusCode as AxumStatusCode;
use axum::{
    extract::{Path as AxumPath, State},
    Json,
};

use crate::api::StatusResponse;
use crate::server::{check_backup_on_disk, AppState, TaskStatus};

pub async fn handle_status(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Result<Json<StatusResponse>, AxumStatusCode> {
    // First check in-memory state
    let tasks = state.tasks.lock().await;
    if let Some(task) = tasks.get(&task_id) {
        let (status, error) = match &task.status {
            TaskStatus::InProgress => ("in_progress", None),
            TaskStatus::Done => ("done", None),
            TaskStatus::Error(e) => ("error", Some(e.clone())),
        };
        return Ok(Json(StatusResponse {
            status: status.to_string(),
            error,
        }));
    }

    // If not in memory, check if backup exists on disk
    if check_backup_on_disk(&state.base_dir, &task_id, state.unsafe_skip_checksum_check)
        .await
        .is_some()
    {
        return Ok(Json(StatusResponse {
            status: "done".to_string(),
            error: None,
        }));
    }

    Err(AxumStatusCode::NOT_FOUND)
}
