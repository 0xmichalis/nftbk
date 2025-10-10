use axum::http::StatusCode;
use axum::Json;
use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Extension,
};

use crate::server::api::BackupResponse;
use crate::server::api::{ApiProblem, BackupRequest, ProblemJson};
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
        (status = 400, description = "Task is already in progress", body = ApiProblem, content_type = "application/problem+json"),
        (status = 403, description = "Requestor does not match task owner", body = ApiProblem, content_type = "application/problem+json"),
        (status = 404, description = "Task not found", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
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
            let problem = ProblemJson::from_status(
                StatusCode::NOT_FOUND,
                Some("Metadata not found".to_string()),
                Some(format!("/v1/backups/{task_id}/retry")),
            );
            return problem.into_response();
        }
        Err(_) => {
            let problem = ProblemJson::from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("Failed to read metadata from DB".to_string()),
                Some(format!("/v1/backups/{task_id}/retry")),
            );
            return problem.into_response();
        }
    };

    // Check if task is in progress
    if meta.status == "in_progress" {
        let problem = ProblemJson::from_status(
            StatusCode::BAD_REQUEST,
            Some("Task is already in progress".to_string()),
            Some(format!("/v1/backups/{task_id}/retry")),
        );
        return problem.into_response();
    }

    // Ensure the requestor matches the one in the metadata
    let req_requestor = requestor.clone().unwrap_or_default();
    let meta_requestor = meta.requestor.clone();
    if !meta_requestor.is_empty() && req_requestor != meta_requestor {
        let problem = ProblemJson::from_status(
            StatusCode::FORBIDDEN,
            Some("Requestor does not match task owner".to_string()),
            Some(format!("/v1/backups/{task_id}/retry")),
        );
        return problem.into_response();
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
        let problem = ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("Failed to enqueue backup job".to_string()),
            Some(format!("/v1/backups/{task_id}/retry")),
        );
        return problem.into_response();
    }
    info!(
        "Retrying backup task {} (requestor: {})",
        task_id,
        requestor.clone().unwrap_or_default()
    );
    (StatusCode::ACCEPTED, Json(BackupResponse { task_id })).into_response()
}
