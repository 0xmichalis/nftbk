use axum::{
    extract::{Extension, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use crate::server::api::{ApiProblem, BackupResponse, ProblemJson};
use crate::server::database::r#trait::Database;
use crate::server::AppState;

#[derive(Deserialize, utoipa::ToSchema)]
pub struct BackupsQuery {
    /// Page number starting at 1
    #[serde(default = "default_page")]
    page: u32,
    /// Items per page (max 100)
    #[serde(default = "default_limit")]
    limit: u32,
}

fn default_page() -> u32 {
    1
}

fn default_limit() -> u32 {
    50
}

/// List all backup tasks for the authenticated user
#[utoipa::path(
    get,
    path = "/v1/backups",
    params(
        ("page" = Option<u32>, Query, description = "Page number starting at 1 (default 1)"),
        ("limit" = Option<u32>, Query, description = "Items per page, max 100 (default 50)")
    ),
    responses(
        (status = 200, description = "List of backup tasks for the authenticated user. Returns task metadata including task_id, status, timestamps, and optionally token details.", 
         body = Vec<BackupResponse>,
         headers(
             ("Link" = String, description = "Pagination links per RFC 5988: rel=prev,next"),
             ("X-Total-Count" = u32, description = "Total number of items before pagination")
         )
        ),
        (status = 401, description = "Missing requestor", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backups(
    Extension(requestor): Extension<Option<String>>,
    State(state): State<AppState>,
    Query(query): Query<BackupsQuery>,
) -> impl IntoResponse {
    let requestor = match requestor {
        Some(r) if !r.is_empty() => r,
        _ => {
            let problem = ProblemJson::from_status(
                StatusCode::UNAUTHORIZED,
                Some("Missing requestor".to_string()),
                Some("/v1/backups".to_string()),
            );
            return problem.into_response();
        }
    };
    handle_backups_core(&*state.db, &requestor, query.page, query.limit).await
}

async fn handle_backups_core<DB: Database + ?Sized>(
    db: &DB,
    requestor: &str,
    page: u32,
    limit: u32,
) -> axum::response::Response {
    let limit = limit.clamp(1, 100);
    let page = page.max(1);
    let offset = ((page - 1) * limit) as i64;
    match db
        .list_requestor_backup_tasks_paginated(requestor, limit as i64, offset)
        .await
    {
        Ok((items, total)) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                "X-Total-Count",
                total
                    .to_string()
                    .parse()
                    .expect("Failed to parse X-Total-Count header value from total count"),
            );
            // Build Link header (relative URLs)
            let mut links: Vec<String> = Vec::new();
            let last_page = total.div_ceil(limit).max(1);
            if page > 1 {
                links.push(format!(
                    "</v1/backups?page={}&limit={}>; rel=\"prev\"",
                    page - 1,
                    limit
                ));
            }
            if page < last_page {
                links.push(format!(
                    "</v1/backups?page={}&limit={}>; rel=\"next\"",
                    page + 1,
                    limit
                ));
            }
            if !links.is_empty() {
                match links.join(", ").parse() {
                    Ok(link_header) => {
                        headers.insert("Link", link_header);
                    }
                    Err(_) => {
                        let problem = ProblemJson::from_status(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Some("Failed to parse Link header value".to_string()),
                            Some("/v1/backups".to_string()),
                        );
                        return problem.into_response();
                    }
                }
            }
            let mapped: Vec<BackupResponse> = items
                .iter()
                .map(|it| {
                    BackupResponse::from_backup_task(
                        it,
                        Vec::new(),
                        it.nft_count as u32,
                        page,
                        limit,
                    )
                })
                .collect();
            (StatusCode::OK, headers, Json(mapped)).into_response()
        }
        Err(e) => {
            let problem = ProblemJson::from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(format!("Failed to query backups: {e}")),
                Some("/v1/backups".to_string()),
            );
            problem.into_response()
        }
    }
}

#[cfg(test)]
mod handle_backups_core_mockdb_tests {
    use super::handle_backups_core;
    use crate::server::database::r#trait::MockDatabase;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[tokio::test]
    async fn returns_500_problem_on_db_error() {
        let mut db = MockDatabase::default();
        db.set_list_requestor_backup_tasks_paginated_error(Some("Database error".to_string()));
        let resp = handle_backups_core(&db, "did:privy:me", 1, 50)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let problem: crate::server::api::ApiProblem = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem.status, StatusCode::INTERNAL_SERVER_ERROR.as_u16());
    }

    #[tokio::test]
    async fn paginates_and_sets_link_headers() {
        // Build 5 fake records with distinct task_ids
        let mut recs = Vec::new();
        for i in 0..5 {
            recs.push(crate::server::database::BackupTask {
                task_id: format!("t{}", i + 1),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                requestor: "did:privy:alice".to_string(),
                nft_count: 1,
                tokens: serde_json::json!([]),
                archive_status: Some("done".to_string()),
                ipfs_status: None,
                archive_error_log: None,
                ipfs_error_log: None,
                archive_fatal_error: None,
                ipfs_fatal_error: None,
                storage_mode: "archive".to_string(),
                archive_format: Some("zip".to_string()),
                expires_at: None,
                archive_deleted_at: None,
                pins_deleted_at: None,
            });
        }
        let mut db = MockDatabase::default();
        db.set_list_requestor_backup_tasks_paginated_result((recs, 5));
        let resp = handle_backups_core(&db, "did:privy:me", 2, 2)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        // Check Link header
        let link = resp
            .headers()
            .get("Link")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(link.contains("rel=\"prev\""));
        assert!(link.contains("rel=\"next\""));
        // Body should contain items 3 and 4
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        let ids: Vec<String> = items
            .into_iter()
            .map(|v| v.get("task_id").unwrap().as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids, vec!["t3".to_string(), "t4".to_string()]);
    }
}
