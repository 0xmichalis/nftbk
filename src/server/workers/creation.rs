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
    };
    let span = tracing::info_span!("backup_task", task_id = %task_id);
    let backup_result = backup_from_config(backup_cfg, Some(span)).await;

    // Check backup result
    let (files_written, token_pin_mappings, error_log) = match backup_result {
        Ok((files, token_pin_mappings, errors)) => (files, token_pin_mappings, errors),
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
    if !token_pin_mappings.is_empty() {
        let req = task.requestor.as_deref().unwrap_or("");
        let _ = db
            .insert_pin_requests_with_tokens(&task.task_id, req, &token_pin_mappings)
            .await;
    }

    // Store non-fatal error log in DB if present
    if !error_log.is_empty() {
        let log_str = error_log.join("\n");
        let _ = db.update_backup_task_error_log(&task_id, &log_str).await;
    }

    // Handle archiving based on storage mode
    match storage_mode {
        StorageMode::Archive | StorageMode::Full => {
            // We have a filesystem output path
            let out_path = output_path.as_ref().unwrap();

            // Sync all files and directories to disk before archiving
            info!("Syncing {} to disk before archiving", out_path.display());
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
                    let _ = db.update_backup_task_status(&task_id, "done").await;
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
            let _ = db.update_backup_task_status(&task_id, "done").await;
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
