use axum::response::Response;
use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::path::PathBuf;
use tokio::fs::File;
use tokio_util::io::ReaderStream;

use crate::server::{check_backup_on_disk, AppState, TaskStatus};

pub async fn handle_download(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
) -> impl IntoResponse {
    // First check in-memory state
    let tasks = state.tasks.lock().await;
    if let Some(task) = tasks.get(&task_id) {
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
        return serve_zip_file(zip_path, &task_id).await;
    }
    drop(tasks);

    // If not in memory, check if backup exists on disk
    if let Some(zip_path) =
        check_backup_on_disk(&state.base_dir, &task_id, state.unsafe_skip_checksum_check).await
    {
        return serve_zip_file(&zip_path, &task_id).await;
    }

    (StatusCode::NOT_FOUND, Body::from("Task not found")).into_response()
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
