use axum::http::StatusCode;
use axum::Json;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension,
};

use crate::server::api::BackupResponse;
use crate::server::AppState;
use crate::server::BackupJob;
use crate::server::Tokens;
use tracing::{error, info};

pub async fn handle_backup_retry(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    Extension(requestor): Extension<Option<String>>,
) -> impl IntoResponse {
    // Fetch metadata from DB once
    let meta = match state.db.get_backup_metadata(&task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Metadata not found"})),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to read metadata from DB"})),
            )
                .into_response();
        }
    };

    // Check if task is in progress
    if meta.status == "in_progress" {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Task is already in progress"})),
        )
            .into_response();
    }

    // Ensure the requestor matches the one in the metadata
    let req_requestor = requestor.clone().unwrap_or_default();
    let meta_requestor = meta.requestor.clone();
    if !meta_requestor.is_empty() && req_requestor != meta_requestor {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requestor does not match task owner"})),
        )
            .into_response();
    }

    let _ = state
        .db
        .update_backup_metadata_status(&task_id, "in_progress")
        .await;

    // Re-run backup job
    let tokens: Vec<Tokens> = serde_json::from_value(meta.tokens.clone()).unwrap_or_default();
    let backup_job = BackupJob {
        task_id: task_id.clone(),
        tokens,
        force: true,
        archive_format: meta.archive_format.clone(),
        requestor: requestor.clone(),
    };
    if let Err(e) = state.backup_job_sender.send(backup_job).await {
        error!("Failed to enqueue backup job: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "Failed to enqueue backup job"})),
        )
            .into_response();
    }
    info!(
        "Retrying backup task {} (requestor: {})",
        task_id,
        requestor.clone().unwrap_or_default()
    );
    (StatusCode::ACCEPTED, Json(BackupResponse { task_id })).into_response()
}
