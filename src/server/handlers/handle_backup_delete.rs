use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde_json;
use tracing::{error, info, warn};

use crate::server::archive::get_zipped_backup_paths;
use crate::server::AppState;

#[utoipa::path(
    delete,
    path = "/v1/backups/{task_id}",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 204, description = "Backup deleted successfully"),
        (status = 400, description = "Bad request"),
        (status = 403, description = "Requestor does not match task owner"),
        (status = 404, description = "Task not found"),
        (status = 409, description = "Can only delete completed tasks"),
        (status = 500, description = "Internal server error"),
    ),
    tag = "backup",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup_delete(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    Extension(requestor): Extension<Option<String>>,
) -> impl IntoResponse {
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

    // Read metadata from DB and check requestor
    let meta = match state.db.get_protection_job(&task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "Nothing found to delete"})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to read metadata: {}", e)})),
            )
                .into_response();
        }
    };
    if meta.requestor != *requestor_str {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "Requestor does not match task owner"})),
        )
            .into_response();
    }
    if meta.status == "in_progress" {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Can only delete completed tasks"})),
        )
            .into_response();
    }

    let mut errors = Vec::new();
    let mut deleted_anything = false;

    // Only delete archive if this is a filesystem-based job
    if let Some(archive_format) = &meta.archive_format {
        let (archive_path, archive_checksum_path) =
            get_zipped_backup_paths(&state.base_dir, &task_id, archive_format);
        for path in [&archive_path, &archive_checksum_path] {
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
    }

    let backup_dir = format!("{}/nftbk-{}", state.base_dir, &task_id);
    match tokio::fs::remove_dir_all(&backup_dir).await {
        Ok(_) => {
            deleted_anything = true;
        }
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound {
                // not found is fine
            } else {
                warn!("Failed to delete backup dir {}: {}", backup_dir, e);
                errors.push(format!("Failed to delete backup dir {backup_dir}: {e}"));
            }
        }
    }

    // Delete metadata from DB
    if let Err(e) = state.db.delete_protection_job(&task_id).await {
        errors.push(format!("Failed to delete metadata from DB: {e}"));
    } else {
        deleted_anything = true;
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
