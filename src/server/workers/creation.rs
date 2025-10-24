use futures_util::FutureExt;
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{error, info};

use crate::backup::backup_from_config;
use crate::server::archive::{
    get_zipped_backup_paths, sync_files, zip_backup, ARCHIVE_INTERRUPTED_BY_SHUTDOWN,
};
use crate::server::database::r#trait::Database;
use crate::server::{AppState, BackupTask, StorageMode};
use crate::{BackupConfig, IpfsOutcome, ProcessManagementConfig, StorageConfig, TokenConfig};

/// Persist non-fatal error logs for archive and/or IPFS based on the requested scope
async fn persist_non_fatal_error_logs<DB: Database + ?Sized>(
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
                let _ = db.update_archive_request_error_log(task_id, a).await;
            }
        }
        crate::server::StorageMode::Ipfs => {
            if let Some(i) = ipfs_log.as_deref() {
                let _ = db.update_pin_request_error_log(task_id, i).await;
            }
        }
    }
}

#[derive(Debug, PartialEq)]
enum ArchiveResult {
    Success,
    Error,
    ShutdownInterrupted,
}

async fn process_archive_outcome<DB: Database + ?Sized>(
    state: &AppState,
    task: &BackupTask,
    task_id: &str,
    out_path: &std::path::Path,
    archive_outcome: &crate::ArchiveOutcome,
    shutdown_flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    db: &DB,
) -> ArchiveResult {
    // Sync all files and directories to disk before archiving
    info!("Syncing {} to disk before archiving", out_path.display());
    let files_written = archive_outcome.files.clone();
    let files_written_clone = files_written.clone();
    if tokio::task::spawn_blocking(move || {
        sync_files(&files_written_clone);
    })
    .await
    .is_err()
    {
        let error_msg = "Sync before archiving failed".to_string();
        error!("{error_msg}");
        let _ = db.set_archive_request_error(task_id, &error_msg).await;
        return ArchiveResult::Error;
    }
    info!(
        "Synced {} to disk before archiving ({} files)",
        out_path.display(),
        files_written.len()
    );

    // Archive the output dir
    let archive_fmt = task.archive_format.as_deref().unwrap_or("zip");
    let (zip_pathbuf, checksum_path) =
        get_zipped_backup_paths(&state.base_dir, task_id, archive_fmt);
    info!("Archiving backup to {}", zip_pathbuf.display());
    let start_time = Instant::now();
    let out_path_clone = out_path.to_path_buf();
    let zip_pathbuf_clone = zip_pathbuf.clone();
    let archive_format_clone = archive_fmt.to_string();
    let shutdown_flag_clone = shutdown_flag.clone();
    let zip_result = match tokio::task::spawn_blocking(move || {
        zip_backup(
            &out_path_clone,
            &zip_pathbuf_clone,
            archive_format_clone,
            shutdown_flag_clone,
        )
    })
    .await
    {
        Ok(r) => r,
        Err(_) => {
            let error_msg = "Archiving task panicked".to_string();
            error!("{error_msg}");
            let _ = db.set_archive_request_error(task_id, &error_msg).await;
            return ArchiveResult::Error;
        }
    };

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
                let _ = db.set_archive_request_error(task_id, &error_msg).await;
                return ArchiveResult::Error;
            }
        }
        Err(e) => {
            let err_str = e.to_string();
            if err_str.contains(ARCHIVE_INTERRUPTED_BY_SHUTDOWN) {
                info!(
                    "Archiving for backup {task_id} was gracefully interrupted by shutdown signal"
                );
                let _ = std::fs::remove_file(&zip_pathbuf);
                return ArchiveResult::ShutdownInterrupted;
            }
            let error_msg = format!("Failed to archive backup: {e}");
            error!("{error_msg}");
            let _ = db.set_archive_request_error(task_id, &error_msg).await;
            return ArchiveResult::Error;
        }
    }

    ArchiveResult::Success
}

async fn process_ipfs_outcome<DB: Database + ?Sized>(
    db: &DB,
    task: &BackupTask,
    ipfs_outcome: &IpfsOutcome,
) -> bool {
    if ipfs_outcome.pin_requests.is_empty() {
        // No pin requests in an IPFS backup means the library failed to contact any of the current IPFS providers
        return false;
    }
    match db
        .insert_pins_with_tokens(&task.task_id, &ipfs_outcome.pin_requests)
        .await
    {
        Ok(_) => true,
        Err(e) => {
            error!("Failed to insert pins for task {}: {}", task.task_id, e);
            false
        }
    }
}

fn prepare_backup_config(
    state: &AppState,
    task_id: &str,
    scope: &StorageMode,
    tokens: &[crate::server::api::Tokens],
) -> BackupConfig {
    let shutdown_flag = Some(state.shutdown_flag.clone());
    let mut token_map = HashMap::new();
    for entry in tokens {
        token_map.insert(entry.chain.clone(), entry.tokens.clone());
    }
    let token_config = TokenConfig { chains: token_map };

    // Determine output path and IPFS settings based on storage mode
    let (output_path, ipfs_pinning_configs) = match scope {
        StorageMode::Archive => {
            // Filesystem only: permanent directory, no IPFS
            let out_dir = format!("{}/nftbk-{}", state.base_dir, task_id);
            (Some(PathBuf::from(out_dir)), Vec::new())
        }
        StorageMode::Ipfs => {
            // IPFS only: no downloads, just pin existing CIDs
            (None, state.ipfs_pinning_configs.clone())
        }
        StorageMode::Full => {
            // Both: permanent directory and IPFS pinning
            let out_dir = format!("{}/nftbk-{}", state.base_dir, task_id);
            (
                Some(PathBuf::from(out_dir)),
                state.ipfs_pinning_configs.clone(),
            )
        }
    };

    BackupConfig {
        chain_config: (*state.chain_config).clone(),
        token_config,
        storage_config: StorageConfig {
            output_path: output_path.clone(),
            prune_redundant: false,
            ipfs_pinning_configs,
        },
        process_config: ProcessManagementConfig {
            exit_on_error: false,
            shutdown_flag: shutdown_flag.clone(),
        },
        task_id: Some(task_id.to_string()),
    }
}

async fn run_backup_task_inner<DB: Database + ?Sized>(state: AppState, task: BackupTask, db: &DB) {
    let task_id = task.task_id.clone();
    let scope = task.scope.clone();
    info!(
        "Running backup task for task {} (scope: {})",
        task_id,
        scope.as_str()
    );

    // Prepare backup config
    let backup_cfg = prepare_backup_config(&state, &task_id, &scope, &task.request.tokens);
    let output_path = backup_cfg.storage_config.output_path.clone();
    let span = tracing::info_span!("backup_task", task_id = %task_id);

    // Run backup
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

    // Store non-fatal library error logs
    persist_non_fatal_error_logs(
        db,
        &task_id,
        &scope,
        &archive_outcome.errors,
        &ipfs_outcome.errors,
    )
    .await;

    // Process archive and IPFS outcomes based on scope of the backup task.
    match scope {
        StorageMode::Ipfs => {
            let success = process_ipfs_outcome(db, &task, &ipfs_outcome).await;
            let status = if success { "done" } else { "error" };
            let _ = db.update_pin_request_status(&task_id, status).await;
        }
        StorageMode::Archive => {
            let out_path = output_path.as_ref().unwrap();
            let result = process_archive_outcome(
                &state,
                &task,
                &task_id,
                out_path,
                &archive_outcome,
                Some(state.shutdown_flag.clone()),
                db,
            )
            .await;
            match result {
                ArchiveResult::Success => {
                    let _ = db.update_archive_request_status(&task_id, "done").await;
                }
                ArchiveResult::Error => {
                    let _ = db.update_archive_request_status(&task_id, "error").await;
                }
                ArchiveResult::ShutdownInterrupted => {
                    // Don't update status; leave it as is (likely "in_progress")
                }
            }
        }
        StorageMode::Full => {
            let out_path = output_path.as_ref().unwrap().clone();
            let state_ref = &state;
            let task_ref = &task;
            let task_id_ref = task_id.clone();

            // Process archive and IPFS outcomes in parallel. This should speed up status
            // updates for ipfs tasks since archives usually take longer to complete.
            let archive_fut = async move {
                let result = process_archive_outcome(
                    state_ref,
                    task_ref,
                    &task_id_ref,
                    &out_path,
                    &archive_outcome,
                    Some(state_ref.shutdown_flag.clone()),
                    db,
                )
                .await;
                match result {
                    ArchiveResult::Success => {
                        let _ = db.update_archive_request_status(&task_id_ref, "done").await;
                    }
                    ArchiveResult::Error => {
                        let _ = db
                            .update_archive_request_status(&task_id_ref, "error")
                            .await;
                    }
                    ArchiveResult::ShutdownInterrupted => {
                        // Don't update status; leave it as is (likely "in_progress")
                    }
                }
            };

            let ipfs_fut = async {
                let success = process_ipfs_outcome(db, &task, &ipfs_outcome).await;
                let status = if success { "done" } else { "error" };
                let _ = db.update_pin_request_status(&task_id, status).await;
            };

            tokio::join!(archive_fut, ipfs_fut);
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
        let _ = Database::set_backup_error(&*state_clone.db, &task_id, &error_msg).await;
    }
}

#[cfg(test)]
mod persist_error_logs_tests {
    use super::persist_non_fatal_error_logs;
    use crate::server::database::r#trait::MockDatabase;

    #[tokio::test]
    async fn no_errors_makes_no_call() {
        let db = MockDatabase::default();
        // Should complete without panicking when no errors are provided
        persist_non_fatal_error_logs(&db, "t1", &crate::server::StorageMode::Full, &[], &[]).await;
    }

    #[tokio::test]
    async fn archive_only_calls_once() {
        let db = MockDatabase::default();
        // Should complete without panicking when only archive errors are provided
        persist_non_fatal_error_logs(
            &db,
            "t1",
            &crate::server::StorageMode::Archive,
            &["a1".into(), "a2".into()],
            &[],
        )
        .await;
    }

    #[tokio::test]
    async fn ipfs_only_calls_once() {
        let db = MockDatabase::default();
        // Should complete without panicking when only IPFS errors are provided
        persist_non_fatal_error_logs(
            &db,
            "t1",
            &crate::server::StorageMode::Ipfs,
            &[],
            &["i1".into()],
        )
        .await;
    }

    #[tokio::test]
    async fn both_calls_once_with_both_logs() {
        let db = MockDatabase::default();
        // Should complete without panicking when both archive and IPFS errors are provided
        persist_non_fatal_error_logs(
            &db,
            "t1",
            &crate::server::StorageMode::Full,
            &["a".into()],
            &["i1".into(), "i2".into()],
        )
        .await;
    }
}
