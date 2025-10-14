use futures_util::FutureExt;
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{error, info};

use crate::backup::backup_from_config;
use crate::server::archive::{
    get_zipped_backup_paths, zip_backup, ARCHIVE_INTERRUPTED_BY_SHUTDOWN,
};
use crate::server::{AppState, BackupTask, BackupTaskDb, StorageMode};
use crate::{BackupConfig, ProcessManagementConfig, StorageConfig, TokenConfig};

fn derive_scope_from_request(req: &crate::server::api::BackupRequest) -> StorageMode {
    match (req.create_archive, req.pin_on_ipfs) {
        (true, true) => StorageMode::Full,
        (true, false) => StorageMode::Archive,
        (false, true) => StorageMode::Ipfs,
        (false, false) => StorageMode::Archive, // defensive fallback; validation prevents this
    }
}

/// Persist non-fatal error logs for archive and/or IPFS based on the requested scope
async fn persist_non_fatal_error_logs<DB: BackupTaskDb + ?Sized>(
    db: &DB,
    task_id: &str,
    scope: &crate::server::StorageMode,
    archive_errors: &[String],
    ipfs_errors: &[String],
) {
    // Determine scope based on which non-fatal errors are present
    let archive_log = if archive_errors.is_empty() {
        None
    } else {
        Some(archive_errors.join("\n"))
    };
    let ipfs_log = if ipfs_errors.is_empty() {
        None
    } else {
        Some(ipfs_errors.join("\n"))
    };
    if archive_log.is_none() && ipfs_log.is_none() {
        return;
    }
    match scope {
        crate::server::StorageMode::Full => {
            let _ = db
                .set_error_logs(task_id, archive_log.as_deref(), ipfs_log.as_deref())
                .await;
        }
        crate::server::StorageMode::Archive => {
            if let Some(a) = archive_log.as_deref() {
                let _ = db.update_archive_error_log(task_id, a).await;
            }
        }
        crate::server::StorageMode::Ipfs => {
            if let Some(i) = ipfs_log.as_deref() {
                let _ = db.update_ipfs_task_error_log(task_id, i).await;
            }
        }
    }
}

fn sync_files(files_written: &[std::path::PathBuf]) {
    let mut synced_dirs = std::collections::HashSet::new();
    for file in files_written {
        if file.is_file() {
            if let Ok(f) = std::fs::File::open(file) {
                let _ = f.sync_all();
            }
        }
        if let Some(parent) = file.parent() {
            if synced_dirs.insert(parent.to_path_buf()) {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
    }
}

async fn run_backup_task_inner<DB: BackupTaskDb + ?Sized>(
    state: AppState,
    task: BackupTask,
    db: &DB,
) {
    let task_id = task.task_id.clone();
    let tokens = task.request.tokens.clone();
    let force = task.force;
    let storage_mode = task.storage_mode.clone();
    info!(
        "Running backup task for task {} (storage_mode: {})",
        task_id,
        storage_mode.as_str()
    );

    // If force is set, clean up the error log if it exists
    if force {
        let _ = db.clear_backup_errors(&task_id).await;
    }

    // Prepare backup config
    let shutdown_flag = Some(state.shutdown_flag.clone());
    let mut token_map = HashMap::new();
    for entry in tokens.clone() {
        token_map.insert(entry.chain, entry.tokens);
    }
    let token_config = TokenConfig { chains: token_map };

    // Determine output path and IPFS settings based on storage mode
    let (output_path, ipfs_providers) = match storage_mode {
        StorageMode::Archive => {
            // Filesystem only: permanent directory, no IPFS
            let out_dir = format!("{}/nftbk-{}", state.base_dir, task_id);
            (Some(PathBuf::from(out_dir)), Vec::new())
        }
        StorageMode::Ipfs => {
            // IPFS only: no downloads, just pin existing CIDs
            (None, state.ipfs_providers.clone())
        }
        StorageMode::Full => {
            // Both: permanent directory and IPFS pinning
            let out_dir = format!("{}/nftbk-{}", state.base_dir, task_id);
            (Some(PathBuf::from(out_dir)), state.ipfs_providers.clone())
        }
    };

    // Run backup
    let backup_cfg = BackupConfig {
        chain_config: (*state.chain_config).clone(),
        token_config,
        storage_config: StorageConfig {
            output_path: output_path.clone(),
            prune_redundant: false,
            ipfs_providers,
        },
        process_config: ProcessManagementConfig {
            exit_on_error: false,
            shutdown_flag: shutdown_flag.clone(),
        },
        task_id: Some(task_id.clone()),
    };
    let span = tracing::info_span!("backup_task", task_id = %task_id);
    let backup_result = backup_from_config(backup_cfg, Some(span)).await;

    // Check backup result
    let (archive_outcome, ipfs_outcome) = match backup_result {
        Ok((archive_outcome, ipfs_outcome)) => (archive_outcome, ipfs_outcome),
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("interrupted by shutdown signal") {
                info!(
                    "Backup {} was gracefully interrupted by shutdown signal",
                    task_id
                );
                return;
            }
            error!("Backup {task_id} failed: {}", e);
            let _ = db
                .set_backup_error(&task_id, &format!("Backup failed: {e}"))
                .await;
            return;
        }
    };

    // Persist token-pin request mappings atomically, if any
    if !ipfs_outcome.pin_requests.is_empty() {
        let req = task.requestor.as_deref().unwrap_or("");
        let _ = db
            .insert_pin_requests_with_tokens(&task.task_id, req, &ipfs_outcome.pin_requests)
            .await;
    }

    // Store non-fatal library error logs according to requested scope (derived from request)
    let scope = derive_scope_from_request(&task.request);
    persist_non_fatal_error_logs(
        db,
        &task_id,
        &scope,
        &archive_outcome.errors,
        &ipfs_outcome.errors,
    )
    .await;

    // Handle archiving based on storage mode
    match storage_mode {
        StorageMode::Archive | StorageMode::Full => {
            // We have a filesystem output path
            let out_path = output_path.as_ref().unwrap();

            // Sync all files and directories to disk before archiving
            info!("Syncing {} to disk before archiving", out_path.display());
            let files_written = archive_outcome.files.clone();
            let files_written_clone = files_written.clone();
            tokio::task::spawn_blocking(move || {
                sync_files(&files_written_clone);
            })
            .await
            .unwrap();
            info!(
                "Synced {} to disk before archiving ({} files)",
                out_path.display(),
                files_written.len()
            );

            // Archive the output dir
            let archive_fmt = task.archive_format.as_deref().unwrap_or("zip");
            let (zip_pathbuf, checksum_path) =
                get_zipped_backup_paths(&state.base_dir, &task_id, archive_fmt);
            info!("Archiving backup to {}", zip_pathbuf.display());
            let start_time = Instant::now();
            let out_path_clone = out_path.clone();
            let zip_pathbuf_clone = zip_pathbuf.clone();
            let archive_format_clone = archive_fmt.to_string();
            let shutdown_flag_clone = shutdown_flag.clone();
            let zip_result = tokio::task::spawn_blocking(move || {
                zip_backup(
                    &out_path_clone,
                    &zip_pathbuf_clone,
                    archive_format_clone,
                    shutdown_flag_clone,
                )
            })
            .await
            .unwrap();

            // Check archive result
            match zip_result {
                Ok(checksum) => {
                    info!(
                        "Archived backup at {} in {:?}s",
                        zip_pathbuf.display(),
                        start_time.elapsed().as_secs()
                    );
                    if let Err(e) = tokio::fs::write(&checksum_path, &checksum).await {
                        let error_msg = format!("Failed to write archive checksum file: {e}");
                        error!("{error_msg}");
                        let _ = db.set_backup_error(&task_id, &error_msg).await;
                        return;
                    }
                    let _ = db.update_archive_request_status(&task_id, "done").await;
                }
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains(ARCHIVE_INTERRUPTED_BY_SHUTDOWN) {
                        info!(
                            "Archiving for backup {} was gracefully interrupted by shutdown signal",
                            task_id
                        );
                        let _ = std::fs::remove_file(&zip_pathbuf);
                        return;
                    }
                    let error_msg = format!("Failed to archive backup: {e}");
                    error!("{error_msg}");
                    let _ = db.set_backup_error(&task_id, &error_msg).await;
                    return;
                }
            }

            info!("Backup {} ready", task_id);
        }
        StorageMode::Ipfs => {
            // IPFS-only mode: no filesystem operations needed
            let _ = db.update_pin_request_status(&task_id, "done").await;
            info!("IPFS pinning for {} complete", task_id);
        }
    }
}

pub async fn run_backup_task(state: AppState, task: BackupTask) {
    let task_id = task.task_id.clone();
    let state_clone = state.clone();

    let fut =
        AssertUnwindSafe(run_backup_task_inner(state.clone(), task, &*state.db)).catch_unwind();

    let result = fut.await;
    if let Err(panic) = result {
        let panic_msg = if let Some(s) = panic.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        let error_msg = format!("Backup task for task {task_id} panicked: {panic_msg}");
        error!("{error_msg}");
        let _ = BackupTaskDb::set_backup_error(&*state_clone.db, &task_id, &error_msg).await;
    }
}

#[cfg(test)]
mod persist_error_logs_tests {
    use super::persist_non_fatal_error_logs;
    use crate::server::BackupTaskDb;

    type ErrorLogCall = (String, Option<String>, Option<String>);

    #[derive(Default)]
    struct MockDb {
        calls: std::sync::Arc<std::sync::Mutex<Vec<ErrorLogCall>>>,
    }

    #[async_trait::async_trait]
    impl BackupTaskDb for MockDb {
        async fn clear_backup_errors(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn set_backup_error(&self, _task_id: &str, _error: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn insert_pin_requests_with_tokens(
            &self,
            _task_id: &str,
            _requestor: &str,
            _token_pin_mappings: &[crate::TokenPinMapping],
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn update_archive_error_log(
            &self,
            task_id: &str,
            error_log: &str,
        ) -> Result<(), sqlx::Error> {
            self.calls.lock().unwrap().push((
                task_id.to_string(),
                Some(error_log.to_string()),
                None,
            ));
            Ok(())
        }
        async fn set_error_logs(
            &self,
            task_id: &str,
            archive_error_log: Option<&str>,
            ipfs_error_log: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            self.calls.lock().unwrap().push((
                task_id.to_string(),
                archive_error_log.map(|s| s.to_string()),
                ipfs_error_log.map(|s| s.to_string()),
            ));
            Ok(())
        }
        async fn update_archive_request_status(
            &self,
            _task_id: &str,
            _status: &str,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn update_ipfs_task_error_log(
            &self,
            task_id: &str,
            error_log: &str,
        ) -> Result<(), sqlx::Error> {
            self.calls.lock().unwrap().push((
                task_id.to_string(),
                None,
                Some(error_log.to_string()),
            ));
            Ok(())
        }
        async fn update_pin_request_status(
            &self,
            _task_id: &str,
            _status: &str,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn get_backup_task(
            &self,
            _task_id: &str,
        ) -> Result<Option<crate::server::db::BackupTask>, sqlx::Error> {
            Ok(None)
        }
        async fn start_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn start_archive_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn start_ipfs_pins_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn delete_backup_task(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn complete_archive_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn complete_ipfs_pins_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn update_ipfs_task_status(
            &self,
            _task_id: &str,
            _status: &str,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn set_ipfs_task_error(
            &self,
            _task_id: &str,
            _fatal_error: &str,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn no_errors_makes_no_call() {
        let db = MockDb::default();
        persist_non_fatal_error_logs(&db, "t1", &crate::server::StorageMode::Full, &[], &[]).await;
        assert!(db.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn archive_only_calls_once() {
        let db = MockDb::default();
        persist_non_fatal_error_logs(
            &db,
            "t1",
            &crate::server::StorageMode::Archive,
            &["a1".into(), "a2".into()],
            &[],
        )
        .await;
        let calls = db.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (task_id, a, i) = &calls[0];
        assert_eq!(task_id, "t1");
        assert_eq!(a.as_deref(), Some("a1\na2"));
        assert!(i.is_none());
    }

    #[tokio::test]
    async fn ipfs_only_calls_once() {
        let db = MockDb::default();
        persist_non_fatal_error_logs(
            &db,
            "t1",
            &crate::server::StorageMode::Ipfs,
            &[],
            &["i1".into()],
        )
        .await;
        let calls = db.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (_task_id, a, i) = &calls[0];
        assert!(a.is_none());
        assert_eq!(i.as_deref(), Some("i1"));
    }

    #[tokio::test]
    async fn both_calls_once_with_both_logs() {
        let db = MockDb::default();
        persist_non_fatal_error_logs(
            &db,
            "t1",
            &crate::server::StorageMode::Full,
            &["a".into()],
            &["i1".into(), "i2".into()],
        )
        .await;
        let calls = db.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (_task_id, a, i) = &calls[0];
        assert_eq!(a.as_deref(), Some("a"));
        assert_eq!(i.as_deref(), Some("i1\ni2"));
    }
}
