use axum::{
    extract::{Path as AxumPath, State},
    http::{header, StatusCode},
    response::IntoResponse,
};

use crate::server::AppState;

pub async fn handle_error_log(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
) -> impl IntoResponse {
    let log_path = format!("{}/nftbk-{}.log", state.base_dir, task_id);
    match tokio::fs::read_to_string(&log_path).await {
        Ok(content) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            content,
        )
            .into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain")],
            "Error log not found".to_string(),
        )
            .into_response(),
    }
}
