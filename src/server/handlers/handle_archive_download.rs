use axum::response::Response;
use axum::Json;
use axum::{
    body::Body,
    extract::{Extension, Path as AxumPath, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::PathBuf;
use tokio::fs::File;
use tokio_util::io::ReaderStream;

use crate::server::api::{ApiProblem, ProblemJson};
use crate::server::database::r#trait::Database;
use crate::server::handlers::verify_requestor_owns_task;
use crate::server::{archive::check_backup_on_disk, AppState};

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct DownloadQuery {
    /// Download token for authenticated access
    pub token: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct DownloadTokenResponse {
    /// Download token for authenticated access
    #[schema(example = "dGVzdF90b2tlbl9leGFtcGxlXzEyMzQ1Njc4")]
    pub token: String,
    /// Token expiration timestamp (Unix timestamp in seconds, typically 10 minutes from creation)
    #[schema(example = 1704067200)]
    pub expires_at: u64,
}

/// Create a download token for the authenticated user. This token can be used in the /v1/backups/{task_id}/download endpoint
/// to download the backup file for the given task_id. The token is valid for 10 minutes.
#[utoipa::path(
    post,
    path = "/v1/backups/{task_id}/download-tokens",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 201, description = "Download token created successfully", body = DownloadTokenResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Requestor does not match task owner"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_archive_download_token(
    State(state): axum::extract::State<AppState>,
    AxumPath(task_id): AxumPath<String>,
    Extension(requestor): Extension<Option<String>>,
) -> impl axum::response::IntoResponse {
    // Ensure the requesting user owns the backup
    let (_meta, problem) = verify_requestor_owns_task(
        &*state.db,
        &task_id,
        requestor,
        &format!("/v1/backups/{task_id}/download-tokens"),
    )
    .await;
    if let Some(resp) = problem {
        return resp;
    }

    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let expires_at = chrono::Utc::now().timestamp() as u64 + 600; // 10 minutes
    {
        let mut tokens = state.download_tokens.lock().await;
        tokens.insert(token.clone(), (task_id.clone(), expires_at));
    }
    {
        let mut headers = HeaderMap::new();
        // Point to the immediate action a client can take with the created token
        headers.insert(
            header::LOCATION,
            format!("/v1/backups/{task_id}/download?token={}", token)
                .parse()
                .unwrap(),
        );
        (
            StatusCode::CREATED,
            headers,
            Json(DownloadTokenResponse { token, expires_at }),
        )
            .into_response()
    }
}

/// Download a backup archive for the authenticated user. The user has to provide a download token to access the archive.
/// The token can be obtained from the /v1/backups/{task_id}/download-tokens endpoint.
#[utoipa::path(
    get,
    path = "/v1/backups/{task_id}/download",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task"),
        ("token" = Option<String>, Query, description = "Download token for authenticated access")
    ),
    responses(
        (status = 200, description = "Backup file download", content_type = "application/zip"),
        (status = 202, description = "Task not completed yet", body = ApiProblem, content_type = "application/problem+json"),
        (status = 401, description = "Invalid or expired token", body = ApiProblem, content_type = "application/problem+json"),
        (status = 404, description = "Task not found", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups"
)]
pub async fn handle_archive_download(
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
                return serve_zip_file_for_token_core(&*state.db, &state, &task_id).await;
            }
        }
    }
    // If we reach here, token is missing or invalid
    (
        // RFC 6750-compliant hint for clients
        [(header::WWW_AUTHENTICATE, "Bearer error=\"invalid_token\"")],
        ProblemJson::from_status(
            StatusCode::UNAUTHORIZED,
            Some("Invalid or expired token".to_string()),
            Some(format!("/v1/backups/{task_id}/download")),
        ),
    )
        .into_response()
}

async fn serve_zip_file_for_token_core<DB: Database + ?Sized>(
    db: &DB,
    state: &AppState,
    task_id: &str,
) -> Response {
    // Read archive_format and subresource statuses from the database
    let meta = match db.get_backup_task(task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return ProblemJson::from_status(
                StatusCode::NOT_FOUND,
                Some("Task not found".to_string()),
                Some(format!("/v1/backups/{task_id}/download")),
            )
            .into_response();
        }
        Err(_) => {
            return ProblemJson::from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("Failed to read metadata".to_string()),
                Some(format!("/v1/backups/{task_id}/download")),
            )
            .into_response();
        }
    };
    // Allow download only when archive subresource is done
    if meta.archive_status.as_deref().unwrap_or("in_progress") != "done" {
        return ProblemJson::from_status(
            StatusCode::ACCEPTED,
            Some("Task not completed yet".to_string()),
            Some(format!("/v1/backups/{task_id}/download")),
        )
        .into_response();
    }

    // Check if this task has an archive backup
    let archive_format = match &meta.archive_format {
        Some(fmt) => fmt,
        None => {
            // IPFS-only task - no download available
            return ProblemJson::from_status(
                StatusCode::BAD_REQUEST,
                Some("This backup task is IPFS-only and has no downloadable archive".to_string()),
                Some(format!("/v1/backups/{task_id}/download")),
            )
            .into_response();
        }
    };

    // If backup exists on disk, serve it
    if let Some(zip_path) = check_backup_on_disk(
        &state.base_dir,
        task_id,
        state.unsafe_skip_checksum_check,
        archive_format,
    )
    .await
    {
        return serve_zip_file(&zip_path, task_id, archive_format).await;
    }
    ProblemJson::from_status(
        StatusCode::NOT_FOUND,
        Some("Task not found".to_string()),
        Some(format!("/v1/backups/{task_id}/download")),
    )
    .into_response()
}

async fn serve_zip_file(zip_path: &PathBuf, task_id: &str, archive_format: &str) -> Response {
    let file = match File::open(zip_path).await {
        Ok(file) => file,
        Err(_) => {
            return ProblemJson::from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("Failed to open archive".to_string()),
                Some(format!("/v1/backups/{task_id}/download")),
            )
            .into_response();
        }
    };
    // Get file size for Content-Length
    let file_size = match tokio::fs::metadata(zip_path).await {
        Ok(meta) => meta.len(),
        Err(_) => {
            return ProblemJson::from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some("Failed to get archive metadata".to_string()),
                Some(format!("/v1/backups/{task_id}/download")),
            )
            .into_response();
        }
    };
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    let mut headers = HeaderMap::new();
    let (content_type, ext) = match archive_format {
        "zip" => ("application/zip", "zip"),
        _ => ("application/gzip", "tar.gz"),
    };
    headers.insert(header::CONTENT_TYPE, content_type.parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"nftbk-{task_id}.{ext}\"")
            .parse()
            .unwrap(),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        file_size.to_string().parse().unwrap(),
    );
    (StatusCode::OK, headers, body).into_response()
}

#[cfg(test)]
mod handle_download_tests {
    use super::{handle_archive_download as handle_download, DownloadQuery};
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};

    use crate::server::database::r#trait::MockDatabase;
    use crate::server::handlers::verify_requestor_owns_task;
    use crate::server::AppState;
    use crate::server::Db;

    fn make_state() -> AppState {
        let mut chains = HashMap::new();
        chains.insert("ethereum".to_string(), "rpc://dummy".to_string());
        let chain_config = crate::backup::ChainConfig(chains);
        // Lazy pool does not actually connect
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@localhost/db")
            .unwrap();
        let db = Arc::new(Db { pool });
        AppState {
            chain_config: Arc::new(chain_config),
            base_dir: Arc::new("/tmp".to_string()),
            unsafe_skip_checksum_check: true,
            auth_token: None,
            pruner_enabled: false,
            pruner_retention_days: 7,
            download_tokens: Arc::new(Mutex::new(HashMap::new())),
            backup_task_sender: mpsc::channel(1).0,
            db,
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ipfs_pinning_configs: Vec::new(),
            ipfs_pinning_instances: Arc::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn post_download_token_returns_404_when_task_missing() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_result(None);
        let (_meta, problem) = verify_requestor_owns_task(
            &db,
            "t-missing",
            Some("did:privy:alice".to_string()),
            "/v1/backups/t-missing/download-tokens",
        )
        .await;
        let resp = problem.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn post_download_token_returns_403_when_owner_mismatch() {
        let mut db = MockDatabase::default();
        let bt = crate::server::database::BackupTask {
            task_id: "t-forbid".to_string(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            requestor: "did:privy:bob".to_string(),
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
        };
        db.set_get_backup_task_result(Some(bt));
        let (_meta, problem) = verify_requestor_owns_task(
            &db,
            "t-forbid",
            Some("did:privy:alice".to_string()),
            "/v1/backups/t-forbid/download-tokens",
        )
        .await;
        let resp = problem.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_download_token_returns_500_on_db_error() {
        let mut db = MockDatabase::default();
        db.set_get_backup_task_error(Some("db error".to_string()));
        let (_meta, problem) = verify_requestor_owns_task(
            &db,
            "t-err",
            Some("did:privy:alice".to_string()),
            "/v1/backups/t-err/download-tokens",
        )
        .await;
        let resp = problem.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_download_returns_401_on_invalid_token() {
        let state = make_state();
        let task_id = "t-abc".to_string();
        let resp = handle_download(
            axum::extract::State(state),
            axum::extract::Path(task_id),
            axum::extract::Query(DownloadQuery {
                token: Some("invalid".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // Parse problem+json
        let body_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let problem: crate::server::api::ApiProblem = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(problem.status, StatusCode::UNAUTHORIZED.as_u16());
    }

    #[tokio::test]
    async fn get_download_401_sets_www_authenticate_header() {
        let state = make_state();
        let task_id = "t-xyz".to_string();
        let resp = handle_download(
            axum::extract::State(state),
            axum::extract::Path(task_id),
            axum::extract::Query(DownloadQuery {
                token: Some("expired-or-invalid".to_string()),
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let header_val = resp
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(header_val, "Bearer error=\"invalid_token\"");
    }
}
