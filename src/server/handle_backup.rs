use axum::{
    extract::{Extension, Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use futures_util::FutureExt;
use serde_json;
use std::collections::HashSet;
use std::panic::AssertUnwindSafe;
use std::time::Instant;
use tracing::{debug, error, info};

use crate::backup::{backup_from_config, BackupConfig, TokenConfig};
use crate::server::api::{BackupRequest, BackupResponse};
use crate::server::archive::{archive_format_from_user_agent, get_zipped_backup_paths, zip_backup};
use crate::server::hashing::compute_array_sha256;
use crate::server::{check_backup_on_disk, AppState, BackupJob, Tokens};

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

    let task_id = compute_array_sha256(&req.tokens);
    let force = req.force.unwrap_or(false);

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
                if force {
                    info!("Force rerunning backup task {}", task_id);
                } else {
                    debug!(
                        "Backup already completed, returning existing task_id {}",
                        task_id
                    );
                    return (StatusCode::OK, Json(BackupResponse { task_id })).into_response();
                }
            }
            "error" => {
                info!("Rerunning task {} because previous backup failed", task_id);
            }
            _ => {}
        }
    }

    if force {
        let _ = state.db.clear_backup_errors(&task_id).await;
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
        force,
        archive_format: archive_format.clone(),
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
        "Created backup task {} (requestor: {}, count: {}, archive_format: {})",
        task_id,
        requestor.unwrap_or_default(),
        nft_count,
        archive_format
    );
    (StatusCode::CREATED, Json(BackupResponse { task_id })).into_response()
}

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

async fn run_backup_job_inner(
    state: AppState,
    task_id: String,
    tokens: Vec<Tokens>,
    force: bool,
    archive_format: String,
) {
    info!("Running backup job for task {}", task_id);

    // If force is set, clean up the error log if it exists
    // Otherwise, check if backup already exists on disk
    if force {
        let _ = state.db.clear_backup_errors(&task_id).await;
    } else if check_backup_on_disk(
        &state.base_dir,
        &task_id,
        state.unsafe_skip_checksum_check,
        &archive_format,
    )
    .await
    .is_some()
    {
        let _ = state
            .db
            .update_backup_metadata_status(&task_id, "done")
            .await;
        info!("Found existing backup for task {}", task_id);
        return;
    }

    // Prepare backup config
    let mut token_map = std::collections::HashMap::new();
    for entry in tokens.clone() {
        token_map.insert(entry.chain, entry.tokens);
    }
    let token_config = TokenConfig { chains: token_map };
    let out_dir = format!("{}/nftbk-{}", state.base_dir, task_id);
    let out_path = std::path::PathBuf::from(&out_dir);

    // Run backup
    let backup_cfg = BackupConfig {
        chain_config: (*state.chain_config).clone(),
        token_config,
        output_path: Some(out_path.clone()),
        prune_redundant: false,
        exit_on_error: false,
    };
    let backup_result = backup_from_config(backup_cfg).await;
    let (files_written, error_log) = match backup_result {
        Ok((files, errors)) => (files, errors),
        Err(e) => {
            error!("Backup {task_id} failed: {}", e);
            let _ = state
                .db
                .set_backup_error(&task_id, &format!("Backup failed: {}", e))
                .await;
            return;
        }
    };

    // Store non-fatal error log in DB if present
    if !error_log.is_empty() {
        let log_str = error_log.join("\n");
        let _ = state
            .db
            .update_backup_metadata_error_log(&task_id, &log_str)
            .await;
    }

    // Sync all files and directories to disk before zipping
    info!("Syncing {} to disk before zipping", out_path.display());
    sync_files(&files_written);
    info!(
        "Synced {} to disk before zipping ({} files)",
        out_path.display(),
        files_written.len()
    );

    // Zip the output dir
    let (zip_pathbuf, checksum_path) =
        get_zipped_backup_paths(&state.base_dir, &task_id, &archive_format);
    info!("Zipping backup to {}", zip_pathbuf.display());
    let start_time = Instant::now();
    match zip_backup(&out_path, &zip_pathbuf, archive_format) {
        Ok(checksum) => {
            info!(
                "Zipped backup at {} in {:?}s",
                zip_pathbuf.display(),
                start_time.elapsed().as_secs()
            );
            if let Err(e) = tokio::fs::write(&checksum_path, &checksum).await {
                error!("Failed to write checksum file: {}", e);
                let _ = state
                    .db
                    .set_backup_error(&task_id, &format!("Failed to write checksum file: {}", e))
                    .await;
                return;
            }
            let _ = state
                .db
                .update_backup_metadata_status(&task_id, "done")
                .await;
        }
        Err(e) => {
            let _ = state
                .db
                .set_backup_error(&task_id, &format!("Failed to zip backup: {}", e))
                .await;
            return;
        }
    }
    info!("Backup {} ready", task_id);
}

pub async fn run_backup_job(
    state: AppState,
    task_id: String,
    tokens: Vec<Tokens>,
    force: bool,
    archive_format: String,
) {
    let state_clone = state.clone();
    let task_id_clone = task_id.clone();
    let fut = AssertUnwindSafe(run_backup_job_inner(
        state,
        task_id,
        tokens,
        force,
        archive_format,
    ))
    .catch_unwind();

    let result = fut.await;
    if let Err(panic) = result {
        let panic_msg = if let Some(s) = panic.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        error!(
            "Backup job for task {} panicked: {}",
            task_id_clone, panic_msg
        );
        let _ = state_clone
            .db
            .set_backup_error(&task_id_clone, &format!("Panic: {}", panic_msg))
            .await;
    }
}

fn sync_files(files_written: &[std::path::PathBuf]) {
    let mut synced_dirs = HashSet::new();
    for file in files_written {
        if file.is_file() {
            if let Ok(f) = std::fs::File::open(file) {
                let _ = f.sync_all();
            }
        }
        if let Some(parent) = file.parent() {
            if synced_dirs.insert(parent.to_path_buf()) {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
    }
}

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
