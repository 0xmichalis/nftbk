use axum::response::Response;
use axum::{
    body::Body,
    extract::{Path as AxumPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::path::PathBuf;
use tokio::fs::File;
use tokio_util::io::ReaderStream;

use crate::server::{check_backup_on_disk, AppState, TaskStatus};

#[derive(serde::Deserialize)]
pub struct DownloadQuery {
    pub token: Option<String>,
}

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

async fn serve_zip_file(zip_path: &PathBuf, task_id: &str) -> Response {
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
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/gzip".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}.tar.gz\"", task_id)
            .parse()
            .unwrap(),
    );
    (StatusCode::OK, headers, body).into_response()
}

async fn serve_zip_file_for_token(state: &AppState, task_id: &str) -> Response {
    // Try to serve from memory first
    let tasks = state.tasks.lock().await;
    if let Some(task) = tasks.get(task_id) {
        if !matches!(task.status, TaskStatus::Done) {
            return (StatusCode::ACCEPTED, Body::from("Task not completed yet")).into_response();
        }
        let Some(ref zip_path) = task.zip_path else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from("No zip file found"),
            )
                .into_response();
        };
        return serve_zip_file(zip_path, task_id).await;
    }
    drop(tasks);
    // If not in memory, check if backup exists on disk
    if let Some(zip_path) =
        check_backup_on_disk(&state.base_dir, task_id, state.unsafe_skip_checksum_check).await
    {
        return serve_zip_file(&zip_path, task_id).await;
    }
    (StatusCode::NOT_FOUND, Body::from("Task not found")).into_response()
}
