use axum::http::StatusCode as AxumStatusCode;
use axum::{
    extract::{Path as AxumPath, State},
    Json,
};

use crate::server::api::StatusResponse;
use crate::server::AppState;

pub async fn handle_status(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Result<Json<StatusResponse>, AxumStatusCode> {
    // Fetch metadata from DB
    let meta = match state.db.get_backup_metadata(&task_id).await {
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
