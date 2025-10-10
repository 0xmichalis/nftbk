use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use tracing::{error, info, warn};

use crate::server::api::{ApiProblem, ProblemJson};
use crate::server::archive::get_zipped_backup_paths;
use crate::server::AppState;

/// Delete a backup job for the authenticated user. This will delete the backup archive files
/// (if the backup used filesystem storage), unpin any IPFS content (if the backup used IPFS storage),
/// and remove the metadata from the database.
#[utoipa::path(
    delete,
    path = "/v1/backups/{task_id}",
    params(
        ("task_id" = String, Path, description = "Unique identifier for the backup task")
    ),
    responses(
        (status = 204, description = "Backup deleted successfully"),
        (status = 400, description = "Bad request", body = ApiProblem, content_type = "application/problem+json"),
        (status = 403, description = "Requestor does not match task owner", body = ApiProblem, content_type = "application/problem+json"),
        (status = 404, description = "Task not found", body = ApiProblem, content_type = "application/problem+json"),
        (status = 409, description = "Can only delete completed tasks", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup_delete(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
    Extension(requestor): Extension<Option<String>>,
) -> impl IntoResponse {
    handle_backup_delete_core(
        &*state.db,
        &state.base_dir,
        &task_id,
        requestor,
        &state.ipfs_provider_instances,
    )
    .await
}

// Minimal trait to mock DB calls
pub trait DeleteDb {
    fn get_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        Option<crate::server::db::ProtectionJobWithBackup>,
                        sqlx::Error,
                    >,
                > + Send
                + 'a,
        >,
    >;
    fn delete_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>;
    fn get_pin_requests_by_task_id<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Vec<crate::server::db::PinRequestRow>, sqlx::Error>,
                > + Send
                + 'a,
        >,
    >;
}

impl DeleteDb for crate::server::db::Db {
    fn get_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<
                        Option<crate::server::db::ProtectionJobWithBackup>,
                        sqlx::Error,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move { crate::server::db::Db::get_protection_job(self, task_id).await })
    }
    fn delete_protection_job<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
    {
        Box::pin(async move { crate::server::db::Db::delete_protection_job(self, task_id).await })
    }
    fn get_pin_requests_by_task_id<'a>(
        &'a self,
        task_id: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Vec<crate::server::db::PinRequestRow>, sqlx::Error>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(
            async move { crate::server::db::Db::get_pin_requests_by_task_id(self, task_id).await },
        )
    }
}

/// Delete filesystem files and directories for a given task
/// Returns (deleted_anything, errors)
async fn delete_dir_and_archive_for_task(
    base_dir: &str,
    task_id: &str,
    archive_format: Option<&str>,
) -> (bool, Vec<String>) {
    let mut deleted_anything = false;
    let mut errors = Vec::new();

    if let Some(archive_format) = archive_format {
        let (archive_path, archive_checksum_path) =
            get_zipped_backup_paths(base_dir, task_id, archive_format);
        for path in [&archive_path, &archive_checksum_path] {
            match tokio::fs::remove_file(path).await {
                Ok(_) => {
                    deleted_anything = true;
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        warn!("Failed to delete file {}: {}", path.display(), e);
                        errors.push(format!("Failed to delete file {}: {}", path.display(), e));
                    }
                }
            }
        }
    }

    let backup_dir = format!("{}/nftbk-{}", base_dir, task_id);
    match tokio::fs::remove_dir_all(&backup_dir).await {
        Ok(_) => {
            deleted_anything = true;
        }
        Err(e) => {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("Failed to delete backup dir {}: {}", backup_dir, e);
                errors.push(format!("Failed to delete backup dir {backup_dir}: {e}"));
            }
        }
    }

    (deleted_anything, errors)
}

/// Delete IPFS pins for a given task ID
/// Returns (deleted_anything, errors)
async fn delete_ipfs_pins_for_task<DB: DeleteDb + ?Sized>(
    db: &DB,
    task_id: &str,
    ipfs_providers: &[Box<dyn crate::ipfs::IpfsPinningProvider>],
) -> (bool, Vec<String>) {
    let mut deleted_anything = false;
    let mut errors = Vec::new();

    match db.get_pin_requests_by_task_id(task_id).await {
        Ok(pin_requests) => {
            for pin_request in &pin_requests {
                // Find the matching provider instance
                let provider = ipfs_providers
                    .iter()
                    .find(|provider| provider.provider_name() == pin_request.provider);

                if let Some(provider) = provider {
                    match provider.delete_pin(&pin_request.request_id).await {
                        Ok(()) => {
                            info!(
                                "Successfully unpinned {} from provider {} for task {}",
                                pin_request.cid, pin_request.provider, task_id
                            );
                            deleted_anything = true;
                        }
                        Err(e) => {
                            warn!(
                                "Failed to unpin {} from provider {} for task {}: {}",
                                pin_request.cid, pin_request.provider, task_id, e
                            );
                            errors.push(format!(
                                "Failed to unpin {} from {}: {}",
                                pin_request.cid, pin_request.provider, e
                            ));
                        }
                    }
                } else {
                    warn!(
                        "No provider instance found for provider {} when unpinning {} in task {}",
                        pin_request.provider, pin_request.cid, task_id
                    );
                    errors.push(format!(
                        "No provider instance found for provider {} when unpinning {}",
                        pin_request.provider, pin_request.cid
                    ));
                }
            }
        }
        Err(e) => {
            warn!("Failed to get pin requests for task {}: {}", task_id, e);
            errors.push(format!(
                "Failed to get pin requests for task {}: {}",
                task_id, e
            ));
        }
    }

    (deleted_anything, errors)
}

async fn handle_backup_delete_core<DB: DeleteDb + ?Sized>(
    db: &DB,
    base_dir: &str,
    task_id: &str,
    requestor: Option<String>,
    ipfs_providers: &[Box<dyn crate::ipfs::IpfsPinningProvider>],
) -> axum::response::Response {
    let requestor_str = match requestor {
        Some(s) if !s.is_empty() => s,
        _ => {
            let problem = ProblemJson::from_status(
                StatusCode::BAD_REQUEST,
                Some("Requestor required".to_string()),
                Some(format!("/v1/backups/{}", task_id)),
            );
            return problem.into_response();
        }
    };

    let meta = match db.get_protection_job(task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            let problem = ProblemJson::from_status(
                StatusCode::NOT_FOUND,
                Some("Nothing found to delete".to_string()),
                Some(format!("/v1/backups/{}", task_id)),
            );
            return problem.into_response();
        }
        Err(e) => {
            let problem = ProblemJson::from_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                Some(format!("Failed to read metadata: {}", e)),
                Some(format!("/v1/backups/{}", task_id)),
            );
            return problem.into_response();
        }
    };
    if meta.requestor != requestor_str {
        let problem = ProblemJson::from_status(
            StatusCode::FORBIDDEN,
            Some("Requestor does not match task owner".to_string()),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }
    if meta.status == "in_progress" {
        let problem = ProblemJson::from_status(
            StatusCode::CONFLICT,
            Some("Can only delete completed tasks".to_string()),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }

    let mut errors = Vec::new();
    let mut deleted_anything = false;

    // Handle filesystem cleanup if this backup used filesystem storage
    if meta.storage_mode == "filesystem" || meta.storage_mode == "both" {
        let (fs_deleted, fs_errors) =
            delete_dir_and_archive_for_task(base_dir, task_id, meta.archive_format.as_deref())
                .await;
        if fs_deleted {
            deleted_anything = true;
        }
        errors.extend(fs_errors);
    }

    // Handle IPFS pin deletion if this backup used IPFS storage
    if meta.storage_mode == "ipfs" || meta.storage_mode == "both" {
        let (ipfs_deleted, ipfs_errors) =
            delete_ipfs_pins_for_task(db, task_id, ipfs_providers).await;
        if ipfs_deleted {
            deleted_anything = true;
        }
        errors.extend(ipfs_errors);
    }

    if let Err(e) = db.delete_protection_job(task_id).await {
        errors.push(format!("Failed to delete metadata from DB: {e}"));
    } else {
        deleted_anything = true;
    }

    if !deleted_anything {
        let problem = ProblemJson::from_status(
            StatusCode::NOT_FOUND,
            Some("Nothing found to delete".to_string()),
            Some(format!("/v1/backups/{}", task_id)),
        );
        return problem.into_response();
    }

    if errors.is_empty() {
        info!("Deleted backup {}", task_id);
        (StatusCode::NO_CONTENT, ()).into_response()
    } else {
        error!("Errors during delete: {:?}", errors);
        ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some(format!("{:?}", errors)),
            Some(format!("/v1/backups/{}", task_id)),
        )
        .into_response()
    }
}

#[cfg(test)]
mod handle_backup_delete_core_tests {
    use super::{handle_backup_delete_core, DeleteDb};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    #[derive(Clone, Default)]
    struct MockDb {
        meta: Option<crate::server::db::ProtectionJobWithBackup>,
        get_error: bool,
        delete_error: bool,
        pin_requests: Vec<crate::server::db::PinRequestRow>,
    }

    impl DeleteDb for MockDb {
        fn get_protection_job<'a>(
            &'a self,
            _task_id: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            Option<crate::server::db::ProtectionJobWithBackup>,
                            sqlx::Error,
                        >,
                    > + Send
                    + 'a,
            >,
        > {
            let meta = self.meta.clone();
            let err = self.get_error;
            Box::pin(async move {
                if err {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    Ok(meta)
                }
            })
        }
        fn delete_protection_job<'a>(
            &'a self,
            _task_id: &'a str,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), sqlx::Error>> + Send + 'a>>
        {
            let err = self.delete_error;
            Box::pin(async move {
                if err {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    Ok(())
                }
            })
        }
        fn get_pin_requests_by_task_id<'a>(
            &'a self,
            _task_id: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<Vec<crate::server::db::PinRequestRow>, sqlx::Error>,
                    > + Send
                    + 'a,
            >,
        > {
            let pin_requests = self.pin_requests.clone();
            Box::pin(async move { Ok(pin_requests) })
        }
    }

    fn sample_meta(
        owner: &str,
        status: &str,
        storage_mode: &str,
    ) -> crate::server::db::ProtectionJobWithBackup {
        use chrono::{TimeZone, Utc};
        crate::server::db::ProtectionJobWithBackup {
            task_id: "t1".to_string(),
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated_at: Utc.timestamp_opt(1_700_000_100, 0).unwrap(),
            requestor: owner.to_string(),
            nft_count: 1,
            tokens: serde_json::json!([{"chain":"ethereum","tokens":["0xabc:1"]}]),
            status: status.to_string(),
            error_log: None,
            fatal_error: None,
            storage_mode: storage_mode.to_string(),
            archive_format: if storage_mode == "filesystem" || storage_mode == "both" {
                Some("zip".to_string())
            } else {
                None
            },
            expires_at: None,
        }
    }

    fn sample_pin_request(provider: &str) -> crate::server::db::PinRequestRow {
        crate::server::db::PinRequestRow {
            id: 1,
            task_id: "t1".to_string(),
            provider: provider.to_string(),
            cid: "QmTest123".to_string(),
            request_id: "req_123".to_string(),
            status: "pinned".to_string(),
            requestor: "did:me".to_string(),
        }
    }

    #[tokio::test]
    async fn returns_400_when_missing_requestor() {
        let db = MockDb::default();
        let resp = handle_backup_delete_core(&db, "/tmp", "t1", None, &[])
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn returns_404_when_missing_task() {
        let db = MockDb {
            meta: None,
            get_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
        };
        let resp = handle_backup_delete_core(&db, "/tmp", "t1", Some("did:me".to_string()), &[])
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let db = MockDb {
            meta: None,
            get_error: true,
            delete_error: false,
            pin_requests: Vec::new(),
        };
        let resp = handle_backup_delete_core(&db, "/tmp", "t1", Some("did:me".to_string()), &[])
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn returns_403_on_owner_mismatch() {
        let db = MockDb {
            meta: Some(sample_meta("did:other", "done", "filesystem")),
            get_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
        };
        let resp = handle_backup_delete_core(&db, "/tmp", "t1", Some("did:me".to_string()), &[])
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn returns_409_when_in_progress() {
        let db = MockDb {
            meta: Some(sample_meta("did:me", "in_progress", "filesystem")),
            get_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
        };
        let resp = handle_backup_delete_core(&db, "/tmp", "t1", Some("did:me".to_string()), &[])
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn returns_204_on_success_and_deletes_files() {
        let base = format!(
            "{}/nftbk-test-{}",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let task_id = "t1".to_string();
        tokio::fs::create_dir_all(format!("{}/nftbk-{}", base, task_id))
            .await
            .unwrap();
        let db = MockDb {
            meta: Some(sample_meta("did:me", "done", "filesystem")),
            get_error: false,
            delete_error: false,
            pin_requests: Vec::new(),
        };
        let resp = handle_backup_delete_core(&db, &base, &task_id, Some("did:me".to_string()), &[])
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    // Storage mode specific tests
    #[tokio::test]
    async fn filesystem_only_mode_deletes_files_but_not_ipfs() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let base = format!(
            "{}/nftbk-test-{}",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let task_id = "t1".to_string();

        // Create test files and directory
        tokio::fs::create_dir_all(format!("{}/nftbk-{}", base, task_id))
            .await
            .unwrap();
        tokio::fs::write(format!("{}/nftbk-{}.zip", base, task_id), "test archive")
            .await
            .unwrap();
        tokio::fs::write(
            format!("{}/nftbk-{}.zip.sha256", base, task_id),
            "test checksum",
        )
        .await
        .unwrap();

        // Start WireMock server
        let mock_server = MockServer::start().await;

        // Set up mock for IPFS unpin endpoint (should NOT be called for filesystem mode)
        Mock::given(method("DELETE"))
            .and(path_regex(r"/v3/files/public/pin_by_cid/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"message": "unpinned"})))
            .expect(0) // Expect 0 calls for filesystem mode
            .mount(&mock_server)
            .await;

        let db = MockDb {
            meta: Some(sample_meta("did:me", "done", "filesystem")),
            get_error: false,
            delete_error: false,
            pin_requests: vec![sample_pin_request("pinata")], // Should not be processed
        };

        // Create IPFS provider instance pointing to our mock server
        let mock_provider_config = crate::ipfs::IpfsProviderConfig::Pinata {
            base_url: mock_server.uri(),
            bearer_token: Some("test_token".to_string()),
            bearer_token_env: None,
        };
        let mock_provider = mock_provider_config.create_provider().unwrap();
        let mock_providers = vec![mock_provider];

        let resp = handle_backup_delete_core(
            &db,
            &base,
            &task_id,
            Some("did:me".to_string()),
            &mock_providers,
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verify files were deleted
        assert!(
            tokio::fs::metadata(format!("{}/nftbk-{}.zip", base, task_id))
                .await
                .is_err()
        );
        assert!(
            tokio::fs::metadata(format!("{}/nftbk-{}.zip.sha256", base, task_id))
                .await
                .is_err()
        );
        assert!(tokio::fs::metadata(format!("{}/nftbk-{}", base, task_id))
            .await
            .is_err());

        // WireMock will automatically verify that no unpin requests were made
    }

    #[tokio::test]
    async fn ipfs_only_mode_does_not_delete_files() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let base = format!(
            "{}/nftbk-test-{}",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let task_id = "t1".to_string();

        // Create test files and directory (these should remain)
        tokio::fs::create_dir_all(format!("{}/nftbk-{}", base, task_id))
            .await
            .unwrap();
        tokio::fs::write(format!("{}/nftbk-{}.zip", base, task_id), "test archive")
            .await
            .unwrap();

        // Start WireMock server
        let mock_server = MockServer::start().await;

        // Set up mock for IPFS unpin endpoint (should be called for ipfs mode)
        Mock::given(method("DELETE"))
            .and(path_regex(r"/v3/files/public/pin_by_cid/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"message": "unpinned"})))
            .expect(1) // Expect 1 call for ipfs mode
            .mount(&mock_server)
            .await;

        let db = MockDb {
            meta: Some(sample_meta("did:me", "done", "ipfs")),
            get_error: false,
            delete_error: false,
            pin_requests: vec![sample_pin_request("pinata")], // Should be processed
        };

        // Create IPFS provider instance pointing to our mock server
        let mock_provider_config = crate::ipfs::IpfsProviderConfig::Pinata {
            base_url: mock_server.uri(),
            bearer_token: Some("test_token".to_string()),
            bearer_token_env: None,
        };
        let mock_provider = mock_provider_config.create_provider().unwrap();
        let mock_providers = vec![mock_provider];

        let resp = handle_backup_delete_core(
            &db,
            &base,
            &task_id,
            Some("did:me".to_string()),
            &mock_providers,
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verify files were NOT deleted (since storage_mode is ipfs only)
        assert!(
            tokio::fs::metadata(format!("{}/nftbk-{}.zip", base, task_id))
                .await
                .is_ok()
        );
        assert!(tokio::fs::metadata(format!("{}/nftbk-{}", base, task_id))
            .await
            .is_ok());

        // WireMock will automatically verify that 1 unpin request was made
    }

    #[tokio::test]
    async fn both_mode_deletes_files_and_processes_ipfs() {
        use wiremock::matchers::{method, path_regex};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let base = format!(
            "{}/nftbk-test-{}",
            std::env::temp_dir().display(),
            uuid::Uuid::new_v4()
        );
        let task_id = "t1".to_string();

        // Create test files and directory
        tokio::fs::create_dir_all(format!("{}/nftbk-{}", base, task_id))
            .await
            .unwrap();
        tokio::fs::write(format!("{}/nftbk-{}.zip", base, task_id), "test archive")
            .await
            .unwrap();

        // Start WireMock server
        let mock_server = MockServer::start().await;

        // Set up mock for IPFS unpin endpoint (should be called for both mode)
        Mock::given(method("DELETE"))
            .and(path_regex(r"/v3/files/public/pin_by_cid/.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"message": "unpinned"})))
            .expect(2) // Expect 2 calls for both mode (2 pin requests)
            .mount(&mock_server)
            .await;

        let db = MockDb {
            meta: Some(sample_meta("did:me", "done", "both")),
            get_error: false,
            delete_error: false,
            pin_requests: vec![
                sample_pin_request("pinata"),
                sample_pin_request("pinata"), // Two pin requests to test multiple unpins
            ],
        };

        // Create IPFS provider instance pointing to our mock server
        let mock_provider_config = crate::ipfs::IpfsProviderConfig::Pinata {
            base_url: mock_server.uri(),
            bearer_token: Some("test_token".to_string()),
            bearer_token_env: None,
        };
        let mock_provider = mock_provider_config.create_provider().unwrap();
        let mock_providers = vec![mock_provider];

        let resp = handle_backup_delete_core(
            &db,
            &base,
            &task_id,
            Some("did:me".to_string()),
            &mock_providers,
        )
        .await
        .into_response();

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verify files were deleted (since storage_mode includes filesystem)
        assert!(
            tokio::fs::metadata(format!("{}/nftbk-{}.zip", base, task_id))
                .await
                .is_err()
        );
        assert!(tokio::fs::metadata(format!("{}/nftbk-{}", base, task_id))
            .await
            .is_err());

        // WireMock will automatically verify that 2 unpin requests were made
    }
}
