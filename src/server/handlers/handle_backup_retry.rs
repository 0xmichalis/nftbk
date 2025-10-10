use axum::http::StatusCode;
use axum::Json;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension,
};

use crate::server::api::BackupRequest;
use crate::server::api::BackupResponse;
use crate::server::AppState;
use crate::server::BackupJob;
use crate::server::BackupJobOrShutdown;
use crate::server::Tokens;
use tracing::{error, info};

#[utoipa::path(
    post,
    path = "/v1/backups/{task_id}/retry",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 202, description = "Backup retry initiated successfully", body = BackupResponse),
        (status = 400, description = "Task is already in progress"),
        (status = 403, description = "Requestor does not match task owner"),
        (status = 404, description = "Task not found"),
        (status = 500, description = "Internal server error"),
    ),
    tag = "backup",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup_retry(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    Extension(requestor): Extension<Option<String>>,
) -> impl IntoResponse {
    // Fetch metadata from DB once
    let meta = match state.db.get_protection_job(&task_id).await {
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
        .retry_backup(&task_id, state.pruner_retention_days)
        .await;

    // Re-run backup job
    let tokens: Vec<Tokens> = serde_json::from_value(meta.tokens.clone()).unwrap_or_default();
    let storage_mode = meta
        .storage_mode
        .parse()
        .unwrap_or(crate::server::StorageMode::Both);
    let pin_on_ipfs = storage_mode == crate::server::StorageMode::Ipfs
        || storage_mode == crate::server::StorageMode::Both;

    let backup_job = BackupJob {
        task_id: task_id.clone(),
        request: BackupRequest {
            tokens,
            pin_on_ipfs,
        },
        force: true,
        storage_mode,
        archive_format: meta.archive_format.clone(),
        requestor: requestor.clone(),
    };
    if let Err(e) = state
        .backup_job_sender
        .send(BackupJobOrShutdown::Job(backup_job))
        .await
    {
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
