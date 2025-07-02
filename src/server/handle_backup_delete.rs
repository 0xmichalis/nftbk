use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json;
use tracing::{error, info, warn};

use crate::server::archive::get_zipped_backup_paths;
use crate::server::{get_backup_status_and_error, AppState, BackupMetadata};

pub async fn handle_backup_delete(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    Extension(requestor): Extension<Option<String>>,
) -> impl IntoResponse {
    let base_dir = &state.base_dir;
    let metadata_path = format!("{}/nftbk-{}-metadata.json", base_dir, &task_id);
    let log_path = format!("{}/nftbk-{}.log", base_dir, &task_id);
    let backup_dir = format!("{}/nftbk-{}", base_dir, &task_id);

    // Require requestor
    let requestor_str = match requestor {
        Some(ref s) if !s.is_empty() => s,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "Requestor required"})),
            )
                .into_response();
        }
    };

    // Read metadata.json and check requestor
    let metadata_bytes = match tokio::fs::read(&metadata_path).await {
        Ok(bytes) => bytes,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({"error": "Nothing found to delete"})),
                )
                    .into_response();
            } else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": format!("Failed to read metadata: {}", e)})),
                )
                    .into_response();
            }
        }
    };
    let metadata: BackupMetadata = match serde_json::from_slice(&metadata_bytes) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("Invalid metadata format: {}", e)})),
            )
                .into_response();
        }
    };
    if metadata.requestor != *requestor_str {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requestor does not match task owner"})),
        )
            .into_response();
    }

    let mut errors = Vec::new();
    let mut deleted_anything = false;
    let (archive_path, archive_checksum_path) =
        get_zipped_backup_paths(&state.base_dir, &task_id, &metadata.archive_format);

    // Check task status using get_backup_status_and_error
    let tasks = state.tasks.lock().await;
    let (status, _error) =
        get_backup_status_and_error(&state, &task_id, &tasks, &metadata.archive_format).await;
    drop(tasks);
    if status == "in_progress" {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Can only delete completed tasks"})),
        )
            .into_response();
    }

    // Try to delete files (except metadata, should be deleted last)
    for path in [
        &archive_path,
        &archive_checksum_path,
        std::path::Path::new(&log_path),
    ] {
        match tokio::fs::remove_file(path).await {
            Ok(_) => {
                deleted_anything = true;
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    // not found is fine
                } else {
                    warn!("Failed to delete file {}: {}", path.display(), e);
                    errors.push(format!("Failed to delete file {}: {}", path.display(), e));
                }
            }
        }
    }
    match tokio::fs::remove_dir_all(&backup_dir).await {
        Ok(_) => {
            deleted_anything = true;
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                // not found is fine
            } else {
                warn!("Failed to delete backup dir {}: {}", backup_dir, e);
                errors.push(format!("Failed to delete backup dir {}: {}", backup_dir, e));
            }
        }
    }

    // Remove from by_requestor index
    let by_requestor_dir = format!("{}/by_requestor", base_dir);
    let user_file = format!("{}/{}.json", by_requestor_dir, requestor_str);
    match tokio::fs::read_to_string(&user_file).await {
        Ok(content) => {
            let mut task_ids: Vec<String> = serde_json::from_str(&content).unwrap_or_default();
            let orig_len = task_ids.len();
            task_ids.retain(|tid| tid != &task_id);
            if task_ids.len() != orig_len {
                deleted_anything = true;
                if let Err(e) =
                    tokio::fs::write(&user_file, serde_json::to_vec_pretty(&task_ids).unwrap())
                        .await
                {
                    warn!("Failed to update user index for {}: {}", requestor_str, e);
                    errors.push(format!(
                        "Failed to update user index for {}: {}",
                        requestor_str, e
                    ));
                }
            }
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                // not found is fine
            } else {
                warn!("Failed to read user index for {}: {}", requestor_str, e);
                errors.push(format!(
                    "Failed to read user index for {}: {}",
                    requestor_str, e
                ));
            }
        }
    }

    // Remove from tasks map
    let mut tasks = state.tasks.lock().await;
    let existed = tasks.remove(&task_id).is_some();
    if existed {
        deleted_anything = true;
    }
    drop(tasks);

    // Delete metadata.json last
    match tokio::fs::remove_file(&metadata_path).await {
        Ok(_) => {
            deleted_anything = true;
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                // not found is fine
            } else {
                warn!("Failed to delete file {}: {}", &metadata_path, e);
                errors.push(format!("Failed to delete file {}: {}", &metadata_path, e));
            }
        }
    }

    if !deleted_anything {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Nothing found to delete"})),
        )
            .into_response();
    }

    if errors.is_empty() {
        info!("Deleted backup {}", task_id);
        (StatusCode::NO_CONTENT, ()).into_response()
    } else {
        error!("Errors during delete: {:?}", errors);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": errors})),
        )
            .into_response()
    }
}
