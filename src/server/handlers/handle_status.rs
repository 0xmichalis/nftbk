use axum::http::StatusCode as AxumStatusCode;
use axum::{
    extract::{Path as AxumPath, State},
    Json,
};

use crate::server::api::StatusResponse;
use crate::server::AppState;

#[utoipa::path(
    get,
    path = "/backup/{task_id}/status",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 200, description = "Backup status retrieved successfully", body = StatusResponse),
        (status = 404, description = "Backup task not found"),
        (status = 500, description = "Internal server error"),
    ),
    tag = "backup",
    security(("bearer_auth" = []))
)]
pub async fn handle_status(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Result<Json<StatusResponse>, AxumStatusCode> {
    // Fetch metadata from DB
    let meta = match state.db.get_protection_job(&task_id).await {
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
