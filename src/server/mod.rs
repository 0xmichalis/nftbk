use futures_util::FutureExt;
use std::collections::{HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;
use tokio::fs;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::backup::ChainConfig;
use crate::ipfs::IpfsProviderConfig;
use crate::server::api::{BackupRequest, Tokens};
use crate::server::archive::{
    get_zipped_backup_paths, zip_backup, ARCHIVE_INTERRUPTED_BY_SHUTDOWN,
};
use crate::server::db::Db;
use crate::server::hashing::compute_file_sha256;
use crate::{
    backup::backup_from_config, BackupConfig, ProcessManagementConfig, StorageConfig, TokenConfig,
};

pub mod api;
pub mod archive;
pub mod db;
pub mod handlers;
pub mod hashing;
pub mod privy;
pub mod pruner;
pub mod router;
pub mod workers;
pub use handlers::handle_backup::handle_backup;
pub use handlers::handle_backup_delete::handle_backup_delete;
pub use handlers::handle_backup_retry::handle_backup_retry;
pub use handlers::handle_backups::handle_backups;
pub use handlers::handle_download::handle_download;
pub use handlers::handle_download::handle_download_token;
pub use handlers::handle_status::handle_status;
pub use workers::spawn_backup_workers;

#[derive(Clone)]
pub struct AppState {
    pub chain_config: Arc<ChainConfig>,
    pub base_dir: Arc<String>,
    pub unsafe_skip_checksum_check: bool,
    pub auth_token: Option<String>,
    pub pruner_enabled: bool,
    pub pruner_retention_days: u64,
    pub download_tokens: Arc<Mutex<HashMap<String, (String, u64)>>>,
    pub backup_job_sender: mpsc::Sender<BackupJobOrShutdown>,
    pub db: Arc<Db>,
    pub shutdown_flag: Arc<AtomicBool>,
    pub ipfs_providers: Vec<IpfsProviderConfig>,
}

#[derive(Debug, Clone)]
pub enum BackupJobOrShutdown {
    Job(BackupJob),
    Shutdown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageMode {
    Filesystem,
    Ipfs,
    Both,
}

impl StorageMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageMode::Filesystem => "filesystem",
            StorageMode::Ipfs => "ipfs",
            StorageMode::Both => "both",
        }
    }
}

impl FromStr for StorageMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "filesystem" => Ok(StorageMode::Filesystem),
            "ipfs" => Ok(StorageMode::Ipfs),
            "both" => Ok(StorageMode::Both),
            _ => Err(format!("Unknown storage mode: {}", s)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackupJob {
    pub task_id: String,
    pub request: BackupRequest,
    pub force: bool,
    pub storage_mode: StorageMode,
    pub archive_format: Option<String>,
    pub requestor: Option<String>,
}

impl Default for AppState {
    fn default() -> Self {
        panic!("AppState::default() should not be used; use AppState::new() instead");
    }
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        chain_config_path: &str,
        base_dir: &str,
        unsafe_skip_checksum_check: bool,
        auth_token: Option<String>,
        pruner_enabled: bool,
        pruner_retention_days: u64,
        backup_job_sender: mpsc::Sender<BackupJobOrShutdown>,
        db_url: &str,
        max_connections: u32,
        shutdown_flag: Arc<AtomicBool>,
        ipfs_providers: Vec<IpfsProviderConfig>,
    ) -> Self {
        let config_content = tokio::fs::read_to_string(chain_config_path)
            .await
            .expect("Failed to read chain config");
        let chains: std::collections::HashMap<String, String> =
            toml::from_str(&config_content).expect("Failed to parse chain config");
        let mut chain_config = ChainConfig(chains);
        chain_config
            .resolve_env_vars()
            .expect("Failed to resolve environment variables in chain config");
        let db = Arc::new(Db::new(db_url, max_connections).await);

        AppState {
            chain_config: Arc::new(chain_config),
            base_dir: Arc::new(base_dir.to_string()),
            unsafe_skip_checksum_check,
            auth_token,
            pruner_enabled,
            pruner_retention_days,
            download_tokens: Arc::new(Mutex::new(HashMap::new())),
            backup_job_sender,
            db,
            shutdown_flag,
            ipfs_providers,
        }
    }
}

pub async fn check_backup_on_disk(
    base_dir: &str,
    task_id: &str,
    unsafe_skip_checksum_check: bool,
    archive_format: &str,
) -> Option<PathBuf> {
    let (path, checksum_path) =
        crate::server::archive::get_zipped_backup_paths(base_dir, task_id, archive_format);

    // First check if both files exist
    match (
        fs::try_exists(&path).await,
        fs::try_exists(&checksum_path).await,
    ) {
        (Ok(true), Ok(true)) => {
            if unsafe_skip_checksum_check {
                // Only check for existence, skip reading and comparing checksums
                return Some(path);
            }
            // Read stored checksum
            info!("Checking backup on disk for task {}", task_id);
            let stored_checksum = match fs::read_to_string(&checksum_path).await {
                Ok(checksum) => checksum,
                Err(e) => {
                    warn!("Failed to read checksum file for {}: {}", path.display(), e);
                    return None;
                }
            };

            // Compute current checksum
            debug!("Computing backup checksum for task {}", task_id);
            let current_checksum = match compute_file_sha256(&path).await {
                Ok(checksum) => checksum,
                Err(e) => {
                    warn!("Failed to compute checksum for {}: {}", path.display(), e);
                    return None;
                }
            };

            if stored_checksum.trim() != current_checksum {
                warn!(
                    "Backup archive {} is corrupted: checksum mismatch",
                    path.display()
                );
                return None;
            }

            Some(path)
        }
        _ => None,
    }
}

/// Recover incomplete backup jobs from the database and enqueue them for processing
/// This is called on server startup to handle jobs that were interrupted by server shutdown
pub async fn recover_incomplete_jobs(
    state: &AppState,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    debug!("Recovering incomplete protection jobs from database...");

    let incomplete_jobs = state.db.get_incomplete_protection_jobs().await?;
    let job_count = incomplete_jobs.len();

    if job_count == 0 {
        debug!("No incomplete protection jobs found");
        return Ok(0);
    }

    debug!(
        "Found {} incomplete protection jobs, re-queueing for processing",
        job_count
    );

    for job_meta in incomplete_jobs {
        // Parse the tokens JSON back to Vec<Tokens>
        let tokens: Vec<Tokens> = match serde_json::from_value(job_meta.tokens.clone()) {
            Ok(tokens) => tokens,
            Err(e) => {
                warn!(
                    "Failed to parse tokens for job {}: {}, skipping",
                    job_meta.task_id, e
                );
                // Mark this job as error since we can't process it
                let _ = state
                    .db
                    .set_backup_error(
                        &job_meta.task_id,
                        &format!("Failed to parse tokens during recovery: {e}"),
                    )
                    .await;
                continue;
            }
        };

        let storage_mode = job_meta.storage_mode.parse().unwrap_or(StorageMode::Both);
        let pin_on_ipfs = storage_mode == StorageMode::Ipfs || storage_mode == StorageMode::Both;

        let backup_job = BackupJob {
            task_id: job_meta.task_id.clone(),
            request: BackupRequest {
                tokens,
                pin_on_ipfs,
            },
            force: true, // Force recovery to ensure backup actually runs
            storage_mode,
            archive_format: job_meta.archive_format,
            requestor: Some(job_meta.requestor),
        };

        // Try to enqueue the job
        if let Err(e) = state
            .backup_job_sender
            .send(BackupJobOrShutdown::Job(backup_job))
            .await
        {
            warn!(
                "Failed to enqueue recovered job {}: {}",
                job_meta.task_id, e
            );
            // Mark as error if we can't enqueue it
            let _ = state
                .db
                .set_backup_error(
                    &job_meta.task_id,
                    &format!("Failed to enqueue during recovery: {e}"),
                )
                .await;
        } else {
            debug!("Re-queued backup job: {}", job_meta.task_id);
        }
    }

    Ok(job_count)
}

async fn run_backup_job_inner(state: AppState, job: BackupJob) {
    let task_id = job.task_id.clone();
    let tokens = job.request.tokens.clone();
    let force = job.force;
    let storage_mode = job.storage_mode.clone();
    info!(
        "Running protection job for task {} (storage_mode: {})",
        task_id,
        storage_mode.as_str()
    );

    // If force is set, clean up the error log if it exists
    if force {
        let _ = state.db.clear_backup_errors(&task_id).await;
    }

    // Prepare backup config
    let shutdown_flag = Some(state.shutdown_flag.clone());
    let mut token_map = std::collections::HashMap::new();
    for entry in tokens.clone() {
        token_map.insert(entry.chain, entry.tokens);
    }
    let token_config = TokenConfig { chains: token_map };

    // Determine output path and IPFS settings based on storage mode
    let (output_path, ipfs_providers) = match storage_mode {
        StorageMode::Filesystem => {
            // Filesystem only: permanent directory, no IPFS
            let out_dir = format!("{}/nftbk-{}", state.base_dir, task_id);
            (Some(PathBuf::from(out_dir)), Vec::new())
        }
        StorageMode::Ipfs => {
            // IPFS only: no downloads, just pin existing CIDs
            (None, state.ipfs_providers.clone())
        }
        StorageMode::Both => {
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
    let span = tracing::info_span!("protection_job", task_id = %task_id);
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
            let _ = state
                .db
                .set_backup_error(&task_id, &format!("Backup failed: {e}"))
                .await;
            return;
        }
    };

    // Persist token-pin request mappings atomically, if any
    if !token_pin_mappings.is_empty() {
        let req = job.requestor.as_deref().unwrap_or("");
        let _ = state
            .db
            .insert_pin_requests_with_tokens(&job.task_id, req, &token_pin_mappings)
            .await;
    }

    // Store non-fatal error log in DB if present
    if !error_log.is_empty() {
        let log_str = error_log.join("\n");
        let _ = state
            .db
            .update_protection_job_error_log(&task_id, &log_str)
            .await;
    }

    // Handle archiving based on storage mode
    match storage_mode {
        StorageMode::Filesystem | StorageMode::Both => {
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
            let archive_fmt = job.archive_format.as_deref().unwrap_or("zip");
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
                        let _ = state.db.set_backup_error(&task_id, &error_msg).await;
                        return;
                    }
                    let _ = state
                        .db
                        .update_protection_job_status(&task_id, "done")
                        .await;
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
                    let _ = state.db.set_backup_error(&task_id, &error_msg).await;
                    return;
                }
            }

            info!("Backup {} ready", task_id);
        }
        StorageMode::Ipfs => {
            // IPFS-only mode: no filesystem operations needed
            let _ = state
                .db
                .update_protection_job_status(&task_id, "done")
                .await;
            info!("IPFS pinning for {} complete", task_id);
        }
    }
}

pub async fn run_backup_job(state: AppState, job: BackupJob) {
    let task_id = job.task_id.clone();
    let state_clone = state.clone();
    let task_id_clone = task_id.clone();

    let fut = AssertUnwindSafe(run_backup_job_inner(state, job)).catch_unwind();

    let result = fut.await;
    if let Err(panic) = result {
        let panic_msg = if let Some(s) = panic.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        let error_msg = format!("Backup job for task {task_id_clone} panicked: {panic_msg}");
        error!("{error_msg}");
        let _ = state_clone
            .db
            .set_backup_error(&task_id_clone, &error_msg)
            .await;
    }
}

fn sync_files(files_written: &[std::path::PathBuf]) {
    let mut synced_dirs = HashSet::new();
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
