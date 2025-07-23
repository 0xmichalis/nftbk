use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Duration;

use crate::server::AppState;

pub async fn handle_backups(
    Extension(user_did): Extension<Option<String>>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let user_did = match user_did {
        Some(did) if !did.is_empty() => did,
        _ => return (StatusCode::UNAUTHORIZED, "Missing user DID").into_response(),
    };
    let mut results = Vec::new();
    let backups = match state.db.list_requestor_backups(&user_did).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to query backups: {}", e),
            )
                .into_response();
        }
    };
    for mut b in backups {
        b.expires_at = if state.pruner_enabled {
            Some(b.updated_at + Duration::days(state.pruner_retention_days as i64))
        } else {
            None
        };
        results.push(b);
    }
    Json(results).into_response()
}
