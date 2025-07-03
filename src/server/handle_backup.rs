use axum::{
    extract::{Extension, Json, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::Utc;
use serde_json;
use std::collections::HashSet;
use std::time::Instant;
use tracing::{debug, error, info, warn};

use crate::api::{BackupRequest, BackupResponse, Tokens};
use crate::backup::{self, BackupConfig, TokenConfig};
use crate::hashing::compute_array_sha256;
use crate::server::archive::{archive_format_from_user_agent, get_zipped_backup_paths, zip_backup};
use crate::server::check_backup_on_disk;
use crate::server::{AppState, BackupMetadata, TaskInfo, TaskStatus};

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
    let mut tasks = state.tasks.lock().await;

    let force = req.force.unwrap_or(false);

    // Check if task exists and its status
    if let Some(task) = tasks.get(&task_id) {
        match &task.status {
            TaskStatus::InProgress => {
                debug!(
                    "Duplicate backup request, returning existing task_id {}",
                    task_id
                );
                return (StatusCode::OK, Json(BackupResponse { task_id })).into_response();
            }
            TaskStatus::Done => {
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
            TaskStatus::Error(e) => {
                info!(
                    "Rerunning task {} because previous backup failed: {}",
                    task_id, e
                );
            }
        }
    }

    // Insert/update as pending
    tasks.insert(
        task_id.clone(),
        TaskInfo {
            status: TaskStatus::InProgress,
            zip_path: None,
        },
    );
    drop(tasks); // Release lock before spawning

    // Select archive format based on user-agent
    let archive_format = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(archive_format_from_user_agent)
        .unwrap_or_else(|| "zip".to_string());

    // Write metadata file synchronously as part of the HTTP request
    let nft_count = req.tokens.iter().map(|t| t.tokens.len()).sum();
    let metadata = BackupMetadata {
        created_at: Utc::now().to_rfc3339(),
        requestor: requestor.clone().unwrap_or_default(),
        nft_count,
        tokens: req.tokens.clone(),
        archive_format: archive_format.clone(),
    };
    let metadata_path = format!("{}/nftbk-{}-metadata.json", state.base_dir, task_id);
    if let Err(e) = tokio::fs::write(
        &metadata_path,
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to write metadata file: {}", e)})),
        )
            .into_response();
    }

    // Update by_requestor index if requestor is not empty
    let requestor_str = requestor.as_deref().unwrap_or("");
    if !requestor_str.is_empty() {
        let by_requestor_dir = format!("{}/by_requestor", state.base_dir);
        if let Err(e) = tokio::fs::create_dir_all(&by_requestor_dir).await {
            warn!("Failed to create by_requestor dir: {}", e);
        } else {
            let user_file = format!("{}/{}.json", by_requestor_dir, requestor_str);
            let mut task_ids: Vec<String> = match tokio::fs::read_to_string(&user_file).await {
                Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
                Err(_) => Vec::new(),
            };
            if !task_ids.contains(&task_id) {
                task_ids.push(task_id.clone());
                if let Err(e) =
                    tokio::fs::write(&user_file, serde_json::to_vec_pretty(&task_ids).unwrap())
                        .await
                {
                    warn!("Failed to update user index for {}: {}", requestor_str, e);
                }
            }
        }
    }

    // Spawn background job
    let state_clone = state.clone();
    let task_id_clone = task_id.clone();
    let tokens = req.tokens.clone();
    let archive_format_clone = archive_format.clone();
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(run_backup_job(
            state_clone,
            task_id_clone,
            tokens,
            force,
            archive_format_clone,
        ))
    });

    info!(
        "Started backup task {} (requestor: {}, count: {}, archive_format: {})",
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

async fn run_backup_job(
    state: AppState,
    task_id: String,
    tokens: Vec<Tokens>,
    force: bool,
    archive_format: String,
) {
    let out_dir = format!("{}/nftbk-{}", state.base_dir, task_id);
    let out_path = std::path::PathBuf::from(&out_dir);

    // If force is set, delete the error log if it exists
    // Otherwise, check if backup already exists on disk
    if force {
        let log_path = format!("{}/nftbk-{}.log", state.base_dir, task_id);
        match tokio::fs::remove_file(&log_path).await {
            Ok(_) => info!("Deleted error log for task {}", task_id),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // Ignore if not found
            Err(e) => warn!("Failed to delete error log for task {}: {}", task_id, e),
        }
    } else if let Some(zip_path) = check_backup_on_disk(
        &state.base_dir,
        &task_id,
        state.unsafe_skip_checksum_check,
        &archive_format,
    )
    .await
    {
        // Update task state to reflect the existing backup
        let mut tasks = state.tasks.lock().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.status = TaskStatus::Done;
            task.zip_path = Some(zip_path);
        }
        info!("Found existing backup for task {}", task_id);
        return;
    }

    // Build TokenConfig from request
    let mut token_map = std::collections::HashMap::new();
    for entry in tokens {
        token_map.insert(entry.chain, entry.tokens);
    }
    let token_config = TokenConfig { chains: token_map };

    // Run backup
    let backup_cfg = BackupConfig {
        chain_config: (*state.chain_config).clone(),
        token_config,
        output_path: Some(out_path.clone()),
        prune_redundant: false,
        exit_on_error: false,
    };
    let backup_result = backup::backup_from_config(backup_cfg).await;
    let files_written = match backup_result {
        Ok(files) => files,
        Err(e) => {
            error!("Backup {task_id} failed: {}", e);
            let mut tasks = state.tasks.lock().await;
            if let Some(task) = tasks.get_mut(&task_id) {
                task.status = TaskStatus::Error(format!("Backup failed: {}", e));
            }
            return;
        }
    };

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
            // Update task and write checksum
            let mut tasks = state.tasks.lock().await;
            if let Some(task) = tasks.get_mut(&task_id) {
                if let Err(e) = tokio::fs::write(&checksum_path, &checksum).await {
                    error!("Failed to write checksum file: {}", e);
                    task.status = TaskStatus::Error("Failed to write checksum file".to_string());
                    return;
                }
                task.status = TaskStatus::Done;
                task.zip_path = Some(zip_pathbuf.clone());
            }
        }
        Err(e) => {
            let mut tasks = state.tasks.lock().await;
            if let Some(task) = tasks.get_mut(&task_id) {
                task.status = TaskStatus::Error(e);
            }
            return;
        }
    }
    info!("Backup {} ready", task_id);
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
    // Check if task is not InProgress
    let tasks = state.tasks.lock().await;
    let in_progress = matches!(
        tasks.get(&task_id),
        Some(TaskInfo {
            status: TaskStatus::InProgress,
            ..
        })
    );
    drop(tasks);
    if in_progress {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Task is already in progress"})),
        )
            .into_response();
    }

    // Load tokens from metadata file
    let metadata_path = format!("{}/nftbk-{}-metadata.json", state.base_dir, task_id);
    let metadata_bytes = match tokio::fs::read(&metadata_path).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Metadata file not found"})),
            )
                .into_response();
        }
    };
    let metadata: BackupMetadata = match serde_json::from_slice(&metadata_bytes) {
        Ok(m) => m,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Invalid metadata format"})),
            )
                .into_response();
        }
    };

    // Ensure the requestor matches the one in the metadata
    let req_requestor = requestor.clone().unwrap_or_default();
    let meta_requestor = metadata.requestor.clone();
    if !meta_requestor.is_empty() && req_requestor != meta_requestor {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requestor does not match task owner"})),
        )
            .into_response();
    }

    // Set status to in progress
    let mut tasks = state.tasks.lock().await;
    tasks.insert(
        task_id.clone(),
        TaskInfo {
            status: TaskStatus::InProgress,
            zip_path: None,
        },
    );
    drop(tasks);

    // Re-run backup job
    let tokens = metadata.tokens.clone();
    let user = req_requestor;
    let user_for_log = user.clone();
    let state_clone = state.clone();
    let task_id_clone = task_id.clone();
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(run_backup_job(
            state_clone,
            task_id_clone,
            tokens,
            true,
            metadata.archive_format.clone(),
        ))
    });
    info!(
        "Retrying backup task {} (requestor: {})",
        task_id, user_for_log
    );
    (StatusCode::ACCEPTED, Json(BackupResponse { task_id })).into_response()
}
