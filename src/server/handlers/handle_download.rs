use axum::response::Response;
use axum::Json;
use axum::{
    body::Body,
    extract::{Path as AxumPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::PathBuf;
use tokio::fs::File;
use tokio_util::io::ReaderStream;

use crate::server::{check_backup_on_disk, AppState};

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct DownloadQuery {
    /// Download token for authenticated access
    pub token: Option<String>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct DownloadTokenResponse {
    /// Download token for authenticated access
    pub token: String,
    /// Token expiration timestamp (Unix timestamp)
    pub expires_at: u64,
}

#[utoipa::path(
    get,
    path = "/backup/{task_id}/download_token",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 200, description = "Download token generated successfully", body = DownloadTokenResponse),
        (status = 401, description = "Unauthorized"),
    ),
    tag = "backup",
    security(("bearer_auth" = []))
)]
pub async fn handle_download_token(
    State(state): axum::extract::State<AppState>,
    axum::extract::Path(task_id): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let expires_at = chrono::Utc::now().timestamp() as u64 + 600; // 10 minutes
    {
        let mut tokens = state.download_tokens.lock().await;
        tokens.insert(token.clone(), (task_id.clone(), expires_at));
    }
    Json(DownloadTokenResponse { token, expires_at })
}

#[utoipa::path(
    get,
    path = "/backup/{task_id}/download",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task"),
        ("token" = Option<String>, Query, description = "Download token for authenticated access")
    ),
    responses(
        (status = 200, description = "Backup file download", content_type = "application/zip"),
        (status = 202, description = "Task not completed yet"),
        (status = 401, description = "Invalid or expired token"),
        (status = 404, description = "Task not found"),
        (status = 500, description = "Internal server error"),
    ),
    tag = "backup"
)]
pub async fn handle_download(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
    Query(query): Query<DownloadQuery>,
) -> impl IntoResponse {
    // If a token is provided, check if it's valid and not expired
    if let Some(token) = query.token {
        let mut tokens = state.download_tokens.lock().await;
        if let Some((token_task_id, expires_at)) = tokens.get(&token) {
            let now = chrono::Utc::now().timestamp() as u64;
            if token_task_id == &task_id && *expires_at > now {
                // Optionally, remove the token for one-time use
                tokens.remove(&token);
                // Serve the file without further auth
                drop(tokens);
                return serve_zip_file_for_token(&state, &task_id).await;
            }
        }
    }
    // If we reach here, token is missing or invalid
    (
        StatusCode::UNAUTHORIZED,
        Body::from("Invalid or expired token"),
    )
        .into_response()
}

async fn serve_zip_file_for_token(state: &AppState, task_id: &str) -> Response {
    // Read archive_format and status from the database
    let meta = match state.db.get_backup_metadata(task_id).await {
        Ok(Some(m)) => m,
        _ => {
            return (StatusCode::NOT_FOUND, Body::from("Task not found")).into_response();
        }
    };
    if meta.status != "done" {
        return (StatusCode::ACCEPTED, Body::from("Task not completed yet")).into_response();
    }
    let archive_format = &meta.archive_format;
    // If backup exists on disk, serve it
    if let Some(zip_path) = check_backup_on_disk(
        &state.base_dir,
        task_id,
        state.unsafe_skip_checksum_check,
        archive_format,
    )
    .await
    {
        return serve_zip_file(&zip_path, task_id, archive_format).await;
    }
    (StatusCode::NOT_FOUND, Body::from("Task not found")).into_response()
}

async fn serve_zip_file(zip_path: &PathBuf, task_id: &str, archive_format: &str) -> Response {
    let file = match File::open(zip_path).await {
        Ok(file) => file,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from("Failed to open zip file"),
            )
                .into_response();
        }
    };
    // Get file size for Content-Length
    let file_size = match tokio::fs::metadata(zip_path).await {
        Ok(meta) => meta.len(),
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from("Failed to get file metadata"),
            )
                .into_response();
        }
    };
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    let mut headers = HeaderMap::new();
    let (content_type, ext) = match archive_format {
        "zip" => ("application/zip", "zip"),
        _ => ("application/gzip", "tar.gz"),
    };
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"nftbk-{task_id}.{ext}\"")
            .parse()
            .unwrap(),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        file_size.to_string().parse().unwrap(),
    );
    (StatusCode::OK, headers, body).into_response()
}
