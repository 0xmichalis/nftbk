use axum::{
    extract::{Extension, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use crate::server::api::{ApiProblem, ProblemJson};
use crate::server::db::{Db, ProtectionJobWithBackup};
use crate::server::AppState;

#[derive(Deserialize, utoipa::ToSchema)]
pub struct BackupsQuery {
    /// Whether to include token details in the response
    #[serde(default = "default_include_tokens")]
    include_tokens: bool,
    /// Page number starting at 1
    #[serde(default = "default_page")]
    page: u32,
    /// Items per page (max 100)
    #[serde(default = "default_limit")]
    limit: u32,
}

fn default_include_tokens() -> bool {
    false
}

fn default_page() -> u32 {
    1
}

fn default_limit() -> u32 {
    50
}

/// List all backup jobs for the authenticated user
#[utoipa::path(
    get,
    path = "/v1/backups",
    params(
        ("include_tokens" = Option<bool>, Query, description = "Whether to include token details in the response"),
        ("page" = Option<u32>, Query, description = "Page number starting at 1 (default 1)"),
        ("limit" = Option<u32>, Query, description = "Items per page, max 100 (default 50)")
    ),
    responses(
        (status = 200, description = "List of backup jobs for the authenticated user. Returns job metadata including task_id, status, timestamps, and optionally token details.", 
         body = Vec<serde_json::Value>,
         headers(
             ("Link" = String, description = "Pagination links per RFC 5988: rel=prev,next"),
             ("X-Total-Count" = u32, description = "Total number of items before pagination")
         ),
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
        (status = 401, description = "Missing user DID", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backups(
    Extension(user_did): Extension<Option<String>>,
    State(state): State<AppState>,
    Query(query): Query<BackupsQuery>,
) -> impl IntoResponse {
    let user_did = match user_did {
        Some(did) if !did.is_empty() => did,
        _ => {
            let problem = ProblemJson::from_status(
                StatusCode::UNAUTHORIZED,
                Some("Missing user DID".to_string()),
                Some("/v1/backups".to_string()),
            );
            return problem.into_response();
        }
    };
    handle_backups_core(
        &*state.db,
        &user_did,
        query.include_tokens,
        query.page,
        query.limit,
    )
    .await
}

// Minimal trait and core function for mocking
pub trait BackupsDb {
    #[allow(clippy::type_complexity)]
    fn list_requestor_protection_jobs_paginated<'a>(
        &'a self,
        requestor: &'a str,
        include_tokens: bool,
        limit: i64,
        offset: i64,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(Vec<ProtectionJobWithBackup>, u32), sqlx::Error>,
                > + Send
                + 'a,
        >,
    >;
}

impl BackupsDb for Db {
    #[allow(clippy::type_complexity)]
    fn list_requestor_protection_jobs_paginated<'a>(
        &'a self,
        requestor: &'a str,
        include_tokens: bool,
        limit: i64,
        offset: i64,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<(Vec<ProtectionJobWithBackup>, u32), sqlx::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Db::list_requestor_protection_jobs_paginated(
                self,
                requestor,
                include_tokens,
                limit,
                offset,
            )
            .await
        })
    }
}

async fn handle_backups_core<DB: BackupsDb + ?Sized>(
    db: &DB,
    user_did: &str,
    include_tokens: bool,
    page: u32,
    limit: u32,
) -> axum::response::Response {
    let limit = limit.clamp(1, 100);
    let page = page.max(1);
    let offset = ((page - 1) * limit) as i64;
    match db
        .list_requestor_protection_jobs_paginated(user_did, include_tokens, limit as i64, offset)
        .await
    {
        Ok((items, total)) => {
            let mut headers = HeaderMap::new();
            headers.insert("X-Total-Count", total.to_string().parse().unwrap());
            // Build Link header (relative URLs)
            let mut links: Vec<String> = Vec::new();
            let last_page = total.div_ceil(limit).max(1);
            if page > 1 {
                links.push(format!(
                    "</v1/backups?page={}&limit={}&include_tokens={}>; rel=\"prev\"",
                    page - 1,
                    limit,
                    include_tokens
                ));
            }
            if page < last_page {
                links.push(format!(
                    "</v1/backups?page={}&limit={}&include_tokens={}>; rel=\"next\"",
                    page + 1,
                    limit,
                    include_tokens
                ));
            }
            if !links.is_empty() {
                headers.insert("Link", links.join(", ").parse().unwrap());
            }
            (StatusCode::OK, headers, Json(items)).into_response()
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
    use super::{handle_backups_core, BackupsDb};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[derive(Default)]
    struct MockDb {
        records: Vec<crate::server::db::ProtectionJobWithBackup>,
        error: bool,
    }

    impl BackupsDb for MockDb {
        fn list_requestor_protection_jobs_paginated<'a>(
            &'a self,
            _requestor: &'a str,
            _include_tokens: bool,
            limit: i64,
            offset: i64,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            (Vec<crate::server::db::ProtectionJobWithBackup>, u32),
                            sqlx::Error,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            let error = self.error;
            let recs = self.records.clone();
            Box::pin(async move {
                if error {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    let start = offset.max(0) as usize;
                    let end = (start + limit.max(0) as usize).min(recs.len());
                    let page = if start < recs.len() {
                        recs[start..end].to_vec()
                    } else {
                        Vec::new()
                    };
                    Ok((page, recs.len() as u32))
                }
            })
        }
    }

    #[tokio::test]
    async fn returns_500_problem_on_db_error() {
        let db = MockDb {
            records: Vec::new(),
            error: true,
        };
        let resp = handle_backups_core(&db, "did:privy:me", false, 1, 50)
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
            recs.push(crate::server::db::ProtectionJobWithBackup {
                task_id: format!("t{}", i + 1),
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                requestor: "did:privy:me".to_string(),
                nft_count: 1,
                tokens: serde_json::json!([]),
                status: "done".to_string(),
                error_log: None,
                fatal_error: None,
                storage_mode: "filesystem".to_string(),
                archive_format: Some("zip".to_string()),
                expires_at: None,
            });
        }
        let db = MockDb {
            records: recs,
            error: false,
        };
        let resp = handle_backups_core(&db, "did:privy:me", false, 2, 2)
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
