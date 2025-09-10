use axum::{
    extract::{Extension, Json, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde_json;
use std::collections::HashSet;
use tracing::{debug, error, info};

use crate::server::api::{BackupRequest, BackupResponse};
use crate::server::archive::archive_format_from_user_agent;
use crate::server::hashing::compute_task_id;
use crate::server::{AppState, BackupJob, BackupJobOrShutdown};

fn validate_backup_request(state: &AppState, req: &BackupRequest) -> Result<(), String> {
    // Validate requested chains
    let configured_chains: HashSet<_> = state.chain_config.0.keys().cloned().collect();
    let mut unknown_chains = Vec::new();
    for entry in &req.tokens {
        if !configured_chains.contains(&entry.chain) {
            unknown_chains.push(entry.chain.clone());
        }
    }
    if !unknown_chains.is_empty() {
        let msg = format!("Unknown chains requested: {}", unknown_chains.join(", "));
        return Err(msg);
    }
    Ok(())
}

#[utoipa::path(
    post,
    path = "/backup",
    request_body = BackupRequest,
    responses(
        (status = 201, description = "Backup task created successfully", body = BackupResponse),
        (status = 200, description = "Backup already exists or in progress", body = BackupResponse),
        (status = 400, description = "Invalid request", body = serde_json::Value),
        (status = 409, description = "Backup exists in error/expired state", body = serde_json::Value),
        (status = 500, description = "Internal server error", body = serde_json::Value),
    ),
    tag = "backup",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup(
    State(state): State<AppState>,
    Extension(requestor): Extension<Option<String>>,
    headers: HeaderMap,
    Json(req): Json<BackupRequest>,
) -> impl IntoResponse {
    if let Err(msg) = validate_backup_request(&state, &req) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response();
    }

    let task_id = compute_task_id(&req.tokens, requestor.as_deref());

    if let Ok(Some(status)) = state.db.get_backup_status(&task_id).await {
        match status.as_str() {
            "in_progress" => {
                debug!(
                    "Duplicate backup request, returning existing task_id {}",
                    task_id
                );
                return (StatusCode::OK, Json(BackupResponse { task_id })).into_response();
            }
            "done" => {
                debug!(
                    "Backup already completed, returning existing task_id {}",
                    task_id
                );
                return (StatusCode::OK, Json(BackupResponse { task_id })).into_response();
            }
            "error" | "expired" => {
                return (
                    StatusCode::CONFLICT,
                    Json(serde_json::json!({
                        "error": format!("Backup in status {status} cannot be (re)started from /backup. Use the provided retry URL to re-run this task."),
                        "retry_url":  format!("/backup/{task_id}/retry"),
                        "task_id": task_id
                    })),
                )
                    .into_response();
            }
            other => {
                error!(
                    "Unknown backup status '{}' for task {} when handling /backup",
                    other, task_id
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "Unknown backup status"})),
                )
                    .into_response();
            }
        }
    }

    // Select archive format based on user-agent
    let archive_format = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(archive_format_from_user_agent)
        .unwrap_or_else(|| "zip".to_string());

    // Write metadata to Postgres
    let nft_count = req.tokens.iter().map(|t| t.tokens.len()).sum::<usize>() as i32;
    let tokens_json = serde_json::to_value(&req.tokens).unwrap();
    if let Err(e) = state
        .db
        .insert_backup_metadata(
            &task_id,
            requestor.as_deref().unwrap_or(""),
            &archive_format,
            nft_count,
            &tokens_json,
            Some(state.pruner_retention_days),
        )
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to write metadata to DB: {}", e)})),
        )
            .into_response();
    }

    let backup_job = BackupJob {
        task_id: task_id.clone(),
        tokens: req.tokens.clone(),
        force: false,
        archive_format: archive_format.clone(),
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
        "Created backup task {} (requestor: {}, count: {}, archive_format: {})",
        task_id,
        requestor.unwrap_or_default(),
        nft_count,
        archive_format
    );
    (StatusCode::CREATED, Json(BackupResponse { task_id })).into_response()
}
