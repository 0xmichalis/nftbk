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
    let tasks = state.tasks.lock().await;
    let (status, error) = get_backup_status_and_error(&state, &task_id, &tasks).await;
    if status == "expired" {
        return Err(AxumStatusCode::NOT_FOUND);
    }
    Ok(Json(StatusResponse { status, error }))
}
