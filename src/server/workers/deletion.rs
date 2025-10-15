use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;
use tracing::{debug, error, info};

use crate::server::database::r#trait::Database;
use crate::server::{AppState, DeletionTask, StorageMode};

pub fn validate_status_for_scope(
    scope: &StorageMode,
    archive_status: Option<&str>,
    ipfs_status: Option<&str>,
) -> Result<(), &'static str> {
    let a_in_progress = matches!(archive_status, Some("in_progress"));
    let i_in_progress = matches!(ipfs_status, Some("in_progress"));
    match scope {
        StorageMode::Archive => {
            if a_in_progress {
                Err("in_progress")
            } else {
                Ok(())
            }
        }
        StorageMode::Ipfs => {
            if i_in_progress {
                Err("in_progress")
            } else {
                Ok(())
            }
        }
        StorageMode::Full => {
            if a_in_progress || i_in_progress {
                Err("in_progress")
            } else {
                Ok(())
            }
        }
    }
}

/// Helper function to determine which start deletion function to call based on scope and storage mode
pub async fn start_deletion_for_scope<DB: Database + ?Sized>(
    db: &DB,
    task_id: &str,
    scope: &StorageMode,
    storage_mode: &str,
) -> Result<(), sqlx::Error> {
    match scope {
        StorageMode::Full => db.start_deletion(task_id).await,
        StorageMode::Archive => {
            if storage_mode == "full" {
                db.start_archive_deletion(task_id).await
            } else if storage_mode == "archive" {
                db.start_deletion(task_id).await
            } else {
                // No-op for other storage modes
                Ok(())
            }
        }
        StorageMode::Ipfs => {
            if storage_mode == "full" {
                db.start_ipfs_pins_deletion(task_id).await
            } else if storage_mode == "ipfs" {
                db.start_deletion(task_id).await
            } else {
                // No-op for other storage modes
                Ok(())
            }
        }
    }
}

/// Helper function to determine which complete deletion function to call based on scope and storage mode
pub async fn complete_deletion_for_scope<DB: Database + ?Sized>(
    db: &DB,
    task_id: &str,
    scope: &StorageMode,
    storage_mode: &str,
) -> Result<(), sqlx::Error> {
    match scope {
        StorageMode::Full => db.delete_backup_task(task_id).await,
        StorageMode::Archive => {
            if storage_mode == "full" {
                db.complete_archive_deletion(task_id).await
            } else if storage_mode == "archive" {
                db.delete_backup_task(task_id).await
            } else {
                // No-op for other storage modes
                Ok(())
            }
        }
        StorageMode::Ipfs => {
            if storage_mode == "full" {
                db.complete_ipfs_pins_deletion(task_id).await
            } else if storage_mode == "ipfs" {
                db.delete_backup_task(task_id).await
            } else {
                // No-op for other storage modes
                Ok(())
            }
        }
    }
}

async fn delete_dir_and_archive_for_task(
    base_dir: &str,
    task_id: &str,
    archive_format: Option<&str>,
) -> Result<bool, String> {
    let mut deleted_anything = false;

    if let Some(archive_format) = archive_format {
        let (archive_path, archive_checksum_path) =
            crate::server::archive::get_zipped_backup_paths(base_dir, task_id, archive_format);
        for path in [&archive_path, &archive_checksum_path] {
            match tokio::fs::remove_file(path).await {
                Ok(_) => {
                    deleted_anything = true;
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::NotFound {
                        return Err(format!("Failed to delete file {}: {}", path.display(), e));
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
                return Err(format!("Failed to delete backup dir {backup_dir}: {e}"));
            }
        }
    }

    Ok(deleted_anything)
}

async fn delete_ipfs_pins(
    provider_instances: &[std::sync::Arc<dyn crate::ipfs::IpfsPinningProvider>],
    task_id: &str,
    pin_requests: &[crate::server::database::PinRow],
) -> Result<bool, String> {
    let mut deleted_anything = false;
    for pin_request in pin_requests {
        let provider = provider_instances
            .iter()
            .find(|provider| pin_request.provider_url.as_deref() == Some(provider.provider_url()));

        let provider = provider.ok_or_else(|| {
            format!(
                "No provider instance found for provider URL {} when unpinning {}",
                pin_request.provider_url.as_deref().unwrap_or(""),
                pin_request.cid
            )
        })?;

        provider
            .delete_pin(&pin_request.request_id)
            .await
            .map_err(|e| {
                format!(
                    "Failed to unpin {} from provider {} for task {}: {}",
                    pin_request.cid,
                    pin_request.provider_url.as_deref().unwrap_or(""),
                    task_id,
                    e
                )
            })?;

        tracing::info!(
            "Successfully unpinned {} from provider {} for task {}",
            pin_request.cid,
            pin_request.provider_url.as_deref().unwrap_or(""),
            task_id
        );
        deleted_anything = true;
    }

    Ok(deleted_anything)
}

async fn run_deletion_task_inner<DB: Database + ?Sized>(
    state: AppState,
    task: DeletionTask,
    db: &DB,
) {
    let task_id = task.task_id.clone();
    info!("Running deletion task for task {task_id}");

    // Get the backup task metadata
    let meta = match db.get_backup_task(&task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            error!("Backup task {task_id} not found for deletion");
            return;
        }
        Err(e) => {
            error!("Failed to read metadata for task {task_id}: {e}");
            return;
        }
    };

    // Verify requestor matches (if provided)
    if let Some(requestor) = &task.requestor {
        if meta.requestor != *requestor {
            error!(
                "Requestor {requestor} does not match task owner {} for task {task_id}",
                meta.requestor
            );
            return;
        }
    }

    // Check if task is in progress for the requested scope
    if validate_status_for_scope(
        &task.scope,
        meta.archive_status.as_deref(),
        meta.ipfs_status.as_deref(),
    )
    .is_err()
    {
        error!(
            "Cannot delete in progress task {task_id} for scope {:?}",
            task.scope
        );
        return;
    }

    // Mark resources as being deleted based on scope and storage mode
    if let Err(e) = start_deletion_for_scope(db, &task_id, &task.scope, &meta.storage_mode).await {
        error!(
            "Failed to start deletion for task {task_id} with scope {:?} and storage mode {}: {e}",
            task.scope, meta.storage_mode
        );
        return;
    }

    // Handle archive cleanup if requested
    if task.scope == StorageMode::Full || task.scope == StorageMode::Archive {
        if !(meta.storage_mode == "archive" || meta.storage_mode == "full") {
            debug!("Skipping archive cleanup for task {task_id} (no archive data)");
        } else {
            match delete_dir_and_archive_for_task(
                &state.base_dir,
                &task_id,
                meta.archive_format.as_deref(),
            )
            .await
            {
                Ok(_) => {
                    info!("Archive cleanup completed for task {task_id}");
                }
                Err(e) => {
                    error!("Archive deletion failed for task {task_id}: {e}");
                    // Log the error but continue with deletion - don't fail the task
                }
            }
        }
    }

    // Handle IPFS pin deletion if requested
    if task.scope == StorageMode::Full || task.scope == StorageMode::Ipfs {
        if !(meta.storage_mode == "ipfs" || meta.storage_mode == "full") {
            debug!("Skipping IPFS pin cleanup for task {task_id} (no IPFS pins)");
        } else {
            let pin_requests = match state.db.get_pins_by_task_id(&task_id).await {
                Ok(v) => v,
                Err(e) => {
                    error!("Failed to get pin requests for task {task_id}: {e}");
                    Vec::new()
                }
            };
            match delete_ipfs_pins(&state.ipfs_provider_instances, &task_id, &pin_requests).await {
                Ok(_) => {
                    info!("IPFS pin cleanup completed for task {task_id}");
                }
                Err(e) => {
                    error!("IPFS pin deletion failed for task {task_id}: {e}");
                    // Log the error but continue with deletion - don't fail the task
                }
            }
        }
    }

    // Complete the deletion based on scope and storage mode
    if let Err(e) = complete_deletion_for_scope(db, &task_id, &task.scope, &meta.storage_mode).await
    {
        error!(
            "Failed to complete deletion for task {task_id} with scope {:?} and storage mode {}: {e}",
            task.scope, meta.storage_mode
        );
        return;
    }

    info!(
        "Successfully deleted backup {task_id} with scope {:?} and storage mode {}",
        task.scope, meta.storage_mode
    );
}

pub async fn run_deletion_task(state: AppState, task: DeletionTask) {
    let task_id = task.task_id.clone();
    let state_clone = state.clone();

    let fut =
        AssertUnwindSafe(run_deletion_task_inner(state.clone(), task, &*state.db)).catch_unwind();

    let result = fut.await;
    if let Err(panic) = result {
        let panic_msg = if let Some(s) = panic.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        let error_msg = format!("Deletion task for task {task_id} panicked: {panic_msg}");
        error!("{error_msg}");
        let _ = Database::set_backup_error(&*state_clone.db, &task_id, &error_msg).await;
    }
}

#[cfg(test)]
mod validate_status_for_scope_tests {
    use super::{validate_status_for_scope, StorageMode};

    #[test]
    fn table_validates_all_cases() {
        // (scope, archive_status, ipfs_status, expect_ok)
        let cases: Vec<(
            StorageMode,
            Option<&'static str>,
            Option<&'static str>,
            bool,
        )> = vec![
            // Full scope
            (StorageMode::Full, Some("done"), Some("done"), true),
            (StorageMode::Full, Some("error"), Some("done"), true),
            (StorageMode::Full, None, Some("done"), true),
            (StorageMode::Full, Some("done"), None, true),
            (StorageMode::Full, None, None, true),
            (StorageMode::Full, Some("in_progress"), Some("done"), false),
            (StorageMode::Full, Some("done"), Some("in_progress"), false),
            (StorageMode::Full, Some("in_progress"), None, false),
            (StorageMode::Full, None, Some("in_progress"), false),
            // Archive scope
            (StorageMode::Archive, Some("done"), Some("done"), true),
            (StorageMode::Archive, Some("error"), None, true),
            (StorageMode::Archive, None, Some("in_progress"), true),
            (StorageMode::Archive, None, None, true),
            (
                StorageMode::Archive,
                Some("in_progress"),
                Some("done"),
                false,
            ),
            (StorageMode::Archive, Some("in_progress"), None, false),
            // Ipfs scope
            (StorageMode::Ipfs, Some("done"), Some("done"), true),
            (StorageMode::Ipfs, None, Some("error"), true),
            (StorageMode::Ipfs, Some("in_progress"), None, true),
            (StorageMode::Ipfs, None, None, true),
            (StorageMode::Ipfs, Some("done"), Some("in_progress"), false),
            (StorageMode::Ipfs, None, Some("in_progress"), false),
        ];

        for (idx, (scope, a, i, expect_ok)) in cases.into_iter().enumerate() {
            let result = validate_status_for_scope(&scope, a, i);
            let ok = result.is_ok();
            assert_eq!(
                ok, expect_ok,
                "case {} failed: scope={:?}, a={:?}, i={:?}",
                idx, scope, a, i
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delete_dir_and_archive_for_task_removes_files_and_dir() {
        // Arrange: create a unique temp base dir
        let base = std::env::temp_dir()
            .join(format!("nftbk-test-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        let base_dir = base.clone();
        tokio::fs::create_dir_all(&base_dir).await.unwrap();

        let task_id = "tdel";
        let archive_fmt = "zip";

        // Create archive files and backup directory matching get_zipped_backup_paths
        let (archive_path, checksum_path) =
            crate::server::archive::get_zipped_backup_paths(&base_dir, task_id, archive_fmt);
        if let Some(parent) = archive_path.parent() {
            tokio::fs::create_dir_all(parent).await.unwrap();
        }
        tokio::fs::write(&archive_path, b"dummy").await.unwrap();
        tokio::fs::write(&checksum_path, b"deadbeef").await.unwrap();

        let backup_dir = format!("{}/nftbk-{}", base_dir, task_id);
        tokio::fs::create_dir_all(&backup_dir).await.unwrap();
        tokio::fs::write(format!("{backup_dir}/file.txt"), b"x")
            .await
            .unwrap();

        // Act
        let deleted = delete_dir_and_archive_for_task(&base_dir, task_id, Some(archive_fmt))
            .await
            .unwrap();

        // Assert
        assert!(deleted);
        assert!(!tokio::fs::try_exists(&archive_path).await.unwrap());
        assert!(!tokio::fs::try_exists(&checksum_path).await.unwrap());
        assert!(!tokio::fs::try_exists(&backup_dir).await.unwrap());

        // Cleanup
        let _ = tokio::fs::remove_dir_all(&base_dir).await;
    }

    #[tokio::test]
    async fn delete_dir_and_archive_for_task_noop_when_missing() {
        let base_dir = std::env::temp_dir()
            .join(format!("nftbk-test-missing-{}", uuid::Uuid::new_v4()))
            .to_string_lossy()
            .to_string();
        // Do not create anything under base_dir
        let deleted = delete_dir_and_archive_for_task(&base_dir, "nope", Some("zip"))
            .await
            .unwrap();
        assert!(!deleted);
    }

    struct MockProvider {
        name: &'static str,
        deleted: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl crate::ipfs::IpfsPinningProvider for MockProvider {
        fn provider_type(&self) -> &str {
            self.name
        }
        fn provider_url(&self) -> &str {
            self.name
        }
        async fn create_pin(
            &self,
            _request: &crate::ipfs::PinRequest,
        ) -> anyhow::Result<crate::ipfs::PinResponse> {
            unimplemented!()
        }
        async fn get_pin(&self, _pin_id: &str) -> anyhow::Result<crate::ipfs::PinResponse> {
            unimplemented!()
        }
        async fn list_pins(&self) -> anyhow::Result<Vec<crate::ipfs::PinResponse>> {
            unimplemented!()
        }
        async fn delete_pin(&self, request_id: &str) -> anyhow::Result<()> {
            self.deleted.lock().unwrap().push(request_id.to_string());
            Ok(())
        }
    }

    #[tokio::test]
    async fn delete_ipfs_pins_unpins_all_matching_requests() {
        let deleted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let provider = std::sync::Arc::new(MockProvider {
            name: "mock",
            deleted: deleted.clone(),
        });
        let providers: Vec<std::sync::Arc<dyn crate::ipfs::IpfsPinningProvider>> = vec![provider];

        let rows = vec![
            crate::server::database::PinRow {
                id: 1,
                task_id: "t".into(),
                provider_type: "mock".into(),
                provider_url: Some("mock".into()),
                cid: "cid1".into(),
                request_id: "rid1".into(),
                pin_status: "pinned".into(),
                created_at: chrono::Utc::now(),
            },
            crate::server::database::PinRow {
                id: 2,
                task_id: "t".into(),
                provider_type: "mock".into(),
                provider_url: Some("mock".into()),
                cid: "cid2".into(),
                request_id: "rid2".into(),
                pin_status: "pinned".into(),
                created_at: chrono::Utc::now(),
            },
        ];

        let result = delete_ipfs_pins(&providers, "t", &rows).await.unwrap();
        assert!(result);
        let calls = deleted.lock().unwrap().clone();
        assert_eq!(calls, vec!["rid1".to_string(), "rid2".to_string()]);
    }

    #[tokio::test]
    async fn delete_ipfs_pins_errors_when_provider_missing() {
        let providers: Vec<std::sync::Arc<dyn crate::ipfs::IpfsPinningProvider>> = vec![];
        let rows = vec![crate::server::database::PinRow {
            id: 1,
            task_id: "t".into(),
            provider_type: "unknown".into(),
            provider_url: Some("https://unknown".into()),
            cid: "cid".into(),
            request_id: "rid".into(),
            pin_status: "pinned".into(),
            created_at: chrono::Utc::now(),
        }];
        let err = delete_ipfs_pins(&providers, "t", &rows).await.unwrap_err();
        assert!(err.contains("No provider instance"));
    }

    use crate::server::database::r#trait::MockDatabase;

    #[tokio::test]
    async fn test_start_deletion_for_scope_full() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        // Should complete successfully for Full scope with full storage
        let result = start_deletion_for_scope(&mock_db, task_id, &StorageMode::Full, "full").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_start_deletion_for_scope_archive_full_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result =
            start_deletion_for_scope(&mock_db, task_id, &StorageMode::Archive, "full").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_start_deletion_for_scope_archive_archive_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result =
            start_deletion_for_scope(&mock_db, task_id, &StorageMode::Archive, "archive").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_start_deletion_for_scope_archive_ipfs_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result =
            start_deletion_for_scope(&mock_db, task_id, &StorageMode::Archive, "ipfs").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_start_deletion_for_scope_ipfs_full_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result = start_deletion_for_scope(&mock_db, task_id, &StorageMode::Ipfs, "full").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_start_deletion_for_scope_ipfs_ipfs_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result = start_deletion_for_scope(&mock_db, task_id, &StorageMode::Ipfs, "ipfs").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_start_deletion_for_scope_ipfs_archive_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result =
            start_deletion_for_scope(&mock_db, task_id, &StorageMode::Ipfs, "archive").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_start_deletion_for_scope_propagates_errors() {
        let mut mock_db = MockDatabase::default();
        mock_db.set_start_deletion_error(Some("Mock error".to_string()));
        let task_id = "test_task";

        let result = start_deletion_for_scope(&mock_db, task_id, &StorageMode::Full, "full").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_complete_deletion_for_scope_full() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result =
            complete_deletion_for_scope(&mock_db, task_id, &StorageMode::Full, "full").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_complete_deletion_for_scope_archive_full_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result =
            complete_deletion_for_scope(&mock_db, task_id, &StorageMode::Archive, "full").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_complete_deletion_for_scope_archive_archive_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result =
            complete_deletion_for_scope(&mock_db, task_id, &StorageMode::Archive, "archive").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_complete_deletion_for_scope_archive_ipfs_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result =
            complete_deletion_for_scope(&mock_db, task_id, &StorageMode::Archive, "ipfs").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_complete_deletion_for_scope_ipfs_full_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result =
            complete_deletion_for_scope(&mock_db, task_id, &StorageMode::Ipfs, "full").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_complete_deletion_for_scope_ipfs_ipfs_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result =
            complete_deletion_for_scope(&mock_db, task_id, &StorageMode::Ipfs, "ipfs").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_complete_deletion_for_scope_ipfs_archive_storage() {
        let mock_db = MockDatabase::default();
        let task_id = "test_task";

        let result =
            complete_deletion_for_scope(&mock_db, task_id, &StorageMode::Ipfs, "archive").await;
        assert!(result.is_ok());

        // Function should complete successfully
    }

    #[tokio::test]
    async fn test_complete_deletion_for_scope_propagates_errors() {
        let mut mock_db = MockDatabase::default();
        mock_db.set_delete_backup_task_error(Some("Mock error".to_string()));
        let task_id = "test_task";

        let result =
            complete_deletion_for_scope(&mock_db, task_id, &StorageMode::Full, "full").await;
        assert!(result.is_err());
    }
}
