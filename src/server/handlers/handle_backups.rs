use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use crate::server::AppState;

#[derive(Deserialize, utoipa::ToSchema)]
pub struct BackupsQuery {
    /// Whether to include token details in the response
    #[serde(default = "default_include_tokens")]
    include_tokens: bool,
}

fn default_include_tokens() -> bool {
    false
}

#[utoipa::path(
    get,
    path = "/backups",
    params(
        ("include_tokens" = Option<bool>, Query, description = "Whether to include token details in the response")
    ),
    responses(
        (status = 200, description = "List of backup jobs for the authenticated user. Returns job metadata including task_id, status, timestamps, and optionally token details.", 
         body = Vec<serde_json::Value>,
         example = json!([
             {
                 "task_id": "abc123def456",
                 "status": "done",
                 "created_at": "2024-01-01T00:00:00Z",
                 "updated_at": "2024-01-01T00:05:00Z",
                 "requestor": "user123",
                 "nft_count": 5,
                 "storage_mode": "local",
                 "archive_format": "tar.gz",
                 "expires_at": null,
                 "error_log": null,
                 "fatal_error": null
             }
         ])
        ),
        (status = 401, description = "Missing user DID"),
        (status = 500, description = "Internal server error"),
    ),
    tag = "backup",
    security(("bearer_auth" = []))
)]
pub async fn handle_backups(
    Extension(user_did): Extension<Option<String>>,
    State(state): State<AppState>,
    Query(query): Query<BackupsQuery>,
) -> impl IntoResponse {
    let user_did = match user_did {
        Some(did) if !did.is_empty() => did,
        _ => return (StatusCode::UNAUTHORIZED, "Missing user DID").into_response(),
    };
    let mut results = Vec::new();
    match state
        .db
        .list_requestor_protection_jobs(&user_did, query.include_tokens)
        .await
    {
        Ok(b) => {
            results.extend(b);
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to query backups: {e}"),
            )
                .into_response();
        }
    };
    Json(results).into_response()
}
