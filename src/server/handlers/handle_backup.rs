use axum::{
    extract::{Extension, Path as AxumPath, Query as AxumQuery, State},
    http::{HeaderMap, StatusCode, StatusCode as AxumStatusCode},
    response::IntoResponse,
    Json,
};

use super::verify_requestor_owns_task;
use crate::server::api::{ApiProblem, BackupResponse, ProblemJson, Tokens};
use crate::server::database::r#trait::Database;
use crate::server::AppState;
use tracing::error;

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct TaskTokensQuery {
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

/// Get the status of a backup task (tokens are paginated via query)
#[utoipa::path(
    get,
    path = "/v1/backups/{task_id}",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task"),
        ("page" = Option<u32>, Query, description = "Page number starting at 1 (default 1)"),
        ("limit" = Option<u32>, Query, description = "Items per page, max 100 (default 50)")
    ),
    responses(
        (status = 200, description = "Backup retrieved successfully", body = BackupResponse,
            headers(
                ("Link" = String, description = "Pagination links per RFC 5988: rel=prev,next"),
                ("X-Total-Tokens" = u32, description = "Total number of tokens for this task before pagination")
            )
        ),
        (status = 401, description = "Requestor missing or unauthorized", body = ApiProblem, content_type = "application/problem+json"),
        (status = 403, description = "Requestor does not match task owner", body = ApiProblem, content_type = "application/problem+json"),
        (status = 404, description = "Backup not found", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
    AxumQuery(TaskTokensQuery { page, limit }): AxumQuery<TaskTokensQuery>,
    Extension(requestor): Extension<Option<String>>,
) -> axum::response::Response {
    // Ownership check before returning backup details
    let (_meta, problem) = verify_requestor_owns_task(
        &*state.db,
        &task_id,
        requestor,
        &format!("/v1/backups/{task_id}"),
    )
    .await;
    if let Some(resp) = problem {
        return resp;
    }

    match handle_backup_core(&*state.db, &task_id, page, limit).await {
        Ok(json) => {
            // Build pagination headers
            let total = json.0.total_tokens;
            let mut headers = HeaderMap::new();
            if let Ok(header_value) = total.to_string().parse() {
                headers.insert("X-Total-Tokens", header_value);
            } else {
                error!(
                    "Failed to parse X-Total-Tokens header value from total token count: {}",
                    total
                );
            }

            let last_page = total.div_ceil(limit).max(1);
            let mut links: Vec<String> = Vec::new();
            if page > 1 {
                links.push(format!(
                    "</v1/backups/{}?page={}&limit={}>; rel=\"prev\"",
                    task_id,
                    page - 1,
                    limit
                ));
            }
            if page < last_page {
                links.push(format!(
                    "</v1/backups/{}?page={}&limit={}>; rel=\"next\"",
                    task_id,
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
                            Some(format!("/v1/backups/{task_id}")),
                        );
                        return problem.into_response();
                    }
                }
            }

            (StatusCode::OK, headers, json).into_response()
        }
        Err(status) => {
            let problem =
                ProblemJson::from_status(status, None, Some(format!("/v1/backups/{task_id}")));
            problem.into_response()
        }
    }
}

async fn handle_backup_core<DB: Database + ?Sized>(
    db: &DB,
    task_id: &str,
    page: u32,
    limit: u32,
) -> Result<Json<BackupResponse>, AxumStatusCode> {
    let limit = limit.clamp(1, 100);
    let page = page.max(1);
    let offset = ((page - 1) * limit) as i64;

    // Fetch meta + paged tokens
    let (meta, total_tokens) = match db
        .get_backup_task_with_tokens(task_id, limit as i64, offset)
        .await
    {
        Ok(Some(mt)) => mt,
        Ok(None) => return Err(AxumStatusCode::NOT_FOUND),
        Err(_) => return Err(AxumStatusCode::INTERNAL_SERVER_ERROR),
    };
    // Convert meta.tokens (Vec<{chain, tokens}>) into Vec<Tokens>
    let mut tokens_resp: Vec<Tokens> = Vec::new();
    if let Some(arr) = meta.tokens.as_array() {
        for v in arr {
            let chain = v
                .get("chain")
                .and_then(|c| c.as_str())
                .unwrap_or_default()
                .to_string();
            let toks: Vec<String> = v
                .get("tokens")
                .and_then(|t| t.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            tokens_resp.push(Tokens {
                chain,
                tokens: toks,
            });
        }
    }

    Ok(Json(BackupResponse::from_backup_task(
        &meta,
        tokens_resp,
        total_tokens,
        page,
        limit,
    )))
}

#[cfg(test)]
mod handle_status_core_tests {
    use super::handle_backup_core as handle_status_core;
    use crate::server::api::BackupResponse;
    use crate::server::database::r#trait::MockDatabase;
    use crate::server::database::BackupTask;
    use crate::server::handlers::verify_requestor_owns_task;
    use axum::http::StatusCode as AxumStatusCode;
    use chrono::{TimeZone, Utc};

    fn sample_meta() -> BackupTask {
        BackupTask {
            task_id: "t1".to_string(),
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            requestor: "did:privy:alice".to_string(),
            nft_count: 1,
            tokens: serde_json::json!([["0xabc:1"]]),
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
        }
    }

    #[tokio::test]
    async fn returns_200_with_status_payload() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(sample_meta()));
        // Call the core with pagination; DB mock ignores it
        let resp = handle_status_core(&db, "t1", 1, 50).await.unwrap();
        let BackupResponse { archive, pins, .. } = resp.0;
        let archive = archive.expect("archive should be present for archive mode");
        assert_eq!(archive.status.status.as_deref(), Some("done"));
        assert!(archive.status.fatal_error.is_none());
        // ipfs should be None in archive-only mode
        assert!(pins.is_none());
        // non-fatal logs are optional and omitted when none
    }

    #[tokio::test]
    async fn returns_unknown_when_statuses_absent() {
        let mut m = sample_meta();
        m.archive_status = None;
        m.ipfs_status = None;
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(Some(m));
        let resp = handle_status_core(&db, "t1", 1, 50).await.unwrap();
        let BackupResponse { archive, pins, .. } = resp.0;
        let archive = archive.expect("archive should be present for archive mode");
        assert_eq!(archive.status.status, None);
        assert!(pins.is_none());
    }

    #[tokio::test]
    async fn returns_404_when_missing() {
        let db = MockDatabase::default();
        let err = handle_status_core(&db, "missing", 1, 50)
            .await
            .err()
            .unwrap();
        assert_eq!(err, AxumStatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_error(Some("Database error".to_string()));
        let err = handle_status_core(&db, "t1", 1, 50).await.err().unwrap();
        assert_eq!(err, AxumStatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn verify_ownership_returns_404_when_missing() {
        let db = MockDatabase::default();
        let (_meta, problem) = verify_requestor_owns_task(
            &db,
            "missing",
            Some("did:privy:alice".to_string()),
            "/v1/backups/missing",
        )
        .await;
        let resp = problem.unwrap();
        assert_eq!(resp.status(), AxumStatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn verify_ownership_returns_403_on_mismatch() {
        let mut db = MockDatabase::default();
        let mut m = sample_meta();
        m.requestor = "did:privy:bob".to_string();
        db.set_get_backup_task_result(Some(m));
        let (_meta, problem) = verify_requestor_owns_task(
            &db,
            "t1",
            Some("did:privy:alice".to_string()),
            "/v1/backups/t1",
        )
        .await;
        let resp = problem.unwrap();
        assert_eq!(resp.status(), AxumStatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn verify_ownership_returns_500_on_db_error() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_error(Some("db error".to_string()));
        let (_meta, problem) = verify_requestor_owns_task(
            &db,
            "t1",
            Some("did:privy:alice".to_string()),
            "/v1/backups/t1",
        )
        .await;
        let resp = problem.unwrap();
        assert_eq!(resp.status(), AxumStatusCode::INTERNAL_SERVER_ERROR);
    }
}
