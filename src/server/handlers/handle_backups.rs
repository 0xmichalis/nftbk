use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use crate::server::AppState;

#[derive(Deserialize)]
pub struct BackupsQuery {
    #[serde(default = "default_include_tokens")]
    include_tokens: bool,
}

fn default_include_tokens() -> bool {
    false
}

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
        .list_requestor_backups(&user_did, query.include_tokens)
        .await
    {
        Ok(b) => {
            results.extend(b);
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to query backups: {}", e),
            )
                .into_response();
        }
    };
    Json(results).into_response()
}
