use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
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
}

fn default_include_tokens() -> bool {
    false
}

#[utoipa::path(
    get,
    path = "/v1/backups",
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
    handle_backups_core(&*state.db, &user_did, query.include_tokens).await
}

// Minimal trait and core function for mocking
pub trait BackupsDb {
    fn list_requestor_protection_jobs<'a>(
        &'a self,
        requestor: &'a str,
        include_tokens: bool,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<ProtectionJobWithBackup>, sqlx::Error>>
                + Send
                + 'a,
        >,
    >;
}

impl BackupsDb for Db {
    fn list_requestor_protection_jobs<'a>(
        &'a self,
        requestor: &'a str,
        include_tokens: bool,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<ProtectionJobWithBackup>, sqlx::Error>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            Db::list_requestor_protection_jobs(self, requestor, include_tokens).await
        })
    }
}

async fn handle_backups_core<DB: BackupsDb + ?Sized>(
    db: &DB,
    user_did: &str,
    include_tokens: bool,
) -> axum::response::Response {
    match db
        .list_requestor_protection_jobs(user_did, include_tokens)
        .await
    {
        Ok(b) => Json(b).into_response(),
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
        fn list_requestor_protection_jobs<'a>(
            &'a self,
            _requestor: &'a str,
            _include_tokens: bool,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            Vec<crate::server::db::ProtectionJobWithBackup>,
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
                    Ok(recs)
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
        let resp = handle_backups_core(&db, "did:privy:me", false)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let problem: crate::server::api::ApiProblem = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem.status, StatusCode::INTERNAL_SERVER_ERROR.as_u16());
    }
}
