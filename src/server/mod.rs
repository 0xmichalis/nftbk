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
use crate::ipfs::{IpfsPinningProvider, IpfsProviderConfig};
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
pub mod pin_monitor;
pub mod privy;
pub mod pruner;
pub mod router;
pub mod workers;
pub use handlers::handle_backup::handle_backup;
pub use handlers::handle_backup_delete::handle_backup_delete;
pub use handlers::handle_backup_delete_archive::handle_backup_delete_archive;
pub use handlers::handle_backup_delete_pins::handle_backup_delete_pins;
pub use handlers::handle_backup_retry::handle_backup_retry;
pub use handlers::handle_backups::handle_backups;
pub use handlers::handle_download::handle_download;
pub use handlers::handle_download::handle_download_token;
pub use handlers::handle_status::handle_status;
pub use workers::spawn_backup_workers;

#[derive(Debug, Clone)]
pub enum BackupJobOrShutdown {
    Job(JobType),
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum JobType {
    Creation(BackupJob),
    Deletion(DeletionJob),
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

#[derive(Debug, Clone)]
pub struct DeletionJob {
    pub task_id: String,
    pub requestor: Option<String>,
    /// Determines which parts of the backup to delete (e.g., only the archive, only the IPFS data, or both).
    pub scope: StorageMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageMode {
    Archive,
    Ipfs,
    Full,
}

impl StorageMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            StorageMode::Archive => "archive",
            StorageMode::Ipfs => "ipfs",
            StorageMode::Full => "full",
        }
    }
}

impl FromStr for StorageMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "archive" => Ok(StorageMode::Archive),
            "ipfs" => Ok(StorageMode::Ipfs),
            "full" => Ok(StorageMode::Full),
            _ => Err(format!("Unknown storage mode: {}", s)),
        }
    }
}

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
    pub ipfs_provider_instances: Arc<Vec<Arc<dyn IpfsPinningProvider>>>,
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

        // Create IPFS provider instances at startup
        let mut ipfs_provider_instances = Vec::new();
        for config in &ipfs_providers {
            match config.create_provider() {
                Ok(provider) => {
                    info!(
                        "Successfully created IPFS provider: {}",
                        provider.provider_name()
                    );
                    ipfs_provider_instances.push(Arc::from(provider));
                }
                Err(e) => {
                    error!(
                        "Failed to create IPFS provider from config {:?}: {}",
                        config, e
                    );
                }
            }
        }

        AppState {
            chain_config: Arc::new(chain_config),
            base_dir: Arc::new(base_dir.to_string()),
            unsafe_skip_checksum_check,
            auth_token,
            pruner_enabled,
            pruner_retention_days,
            download_tokens: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            backup_job_sender,
            db,
            shutdown_flag,
            ipfs_providers,
            ipfs_provider_instances: Arc::new(ipfs_provider_instances),
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

// Trait for database operations needed by recovery
#[async_trait::async_trait]
pub trait RecoveryDb {
    async fn get_incomplete_protection_jobs(&self) -> Result<Vec<RecoveryJob>, sqlx::Error>;
    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error>;
}

// Recovery job struct that matches the database schema
#[derive(Debug, Clone)]
pub struct RecoveryJob {
    pub task_id: String,
    pub requestor: String,
    pub tokens: serde_json::Value,
    pub storage_mode: String,
    pub archive_format: Option<String>,
}

// Implement the trait for the real Db
#[async_trait::async_trait]
impl RecoveryDb for Db {
    async fn get_incomplete_protection_jobs(&self) -> Result<Vec<RecoveryJob>, sqlx::Error> {
        let jobs = Db::get_incomplete_protection_jobs(self).await?;
        Ok(jobs
            .into_iter()
            .map(|job| RecoveryJob {
                task_id: job.task_id,
                requestor: job.requestor,
                tokens: job.tokens,
                storage_mode: job.storage_mode,
                archive_format: job.archive_format,
            })
            .collect())
    }

    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error> {
        Db::set_backup_error(self, task_id, error).await
    }
}

// Implement the trait for Arc<Db> to support the AppState usage
#[async_trait::async_trait]
impl RecoveryDb for std::sync::Arc<Db> {
    async fn get_incomplete_protection_jobs(&self) -> Result<Vec<RecoveryJob>, sqlx::Error> {
        let jobs = self.as_ref().get_incomplete_protection_jobs().await?;
        Ok(jobs
            .into_iter()
            .map(|job| RecoveryJob {
                task_id: job.task_id,
                requestor: job.requestor,
                tokens: job.tokens,
                storage_mode: job.storage_mode,
                archive_format: job.archive_format,
            })
            .collect())
    }

    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error> {
        self.as_ref().set_backup_error(task_id, error).await
    }
}

/// Recover incomplete backup jobs from the database and enqueue them for processing
/// This is called on server startup to handle jobs that were interrupted by server shutdown
pub async fn recover_incomplete_jobs<DB: RecoveryDb + ?Sized>(
    db: &DB,
    backup_job_sender: &mpsc::Sender<BackupJobOrShutdown>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    debug!("Recovering incomplete protection jobs from database...");

    let incomplete_jobs = db.get_incomplete_protection_jobs().await?;
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
                let _ = db
                    .set_backup_error(
                        &job_meta.task_id,
                        &format!("Failed to parse tokens during recovery: {e}"),
                    )
                    .await;
                continue;
            }
        };

        let storage_mode = job_meta.storage_mode.parse().unwrap_or(StorageMode::Full);
        let pin_on_ipfs = storage_mode == StorageMode::Ipfs || storage_mode == StorageMode::Full;

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
        if let Err(e) = backup_job_sender
            .send(BackupJobOrShutdown::Job(JobType::Creation(backup_job)))
            .await
        {
            warn!(
                "Failed to enqueue recovered job {}: {}",
                job_meta.task_id, e
            );
            // Mark as error if we can't enqueue it
            let _ = db
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

// Trait for database operations needed by backup and deletion jobs
#[async_trait::async_trait]
pub trait BackupJobDb {
    async fn clear_backup_errors(&self, task_id: &str) -> Result<(), sqlx::Error>;
    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error>;
    async fn insert_pin_requests_with_tokens(
        &self,
        task_id: &str,
        requestor: &str,
        token_pin_mappings: &[crate::TokenPinMapping],
    ) -> Result<(), sqlx::Error>;
    async fn update_protection_job_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error>;
    async fn update_protection_job_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error>;
    async fn get_protection_job(
        &self,
        task_id: &str,
    ) -> Result<Option<crate::server::db::ProtectionJobWithBackup>, sqlx::Error>;
    async fn start_deletion(&self, task_id: &str) -> Result<(), sqlx::Error>;
    async fn delete_protection_job(&self, task_id: &str) -> Result<(), sqlx::Error>;
    async fn downgrade_full_to_ipfs(&self, task_id: &str) -> Result<(), sqlx::Error>;
    async fn downgrade_full_to_archive(&self, task_id: &str) -> Result<(), sqlx::Error>;
}

// Implement BackupJobDb trait for the real Db
#[async_trait::async_trait]
impl BackupJobDb for Db {
    async fn clear_backup_errors(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::clear_backup_errors(self, task_id).await
    }

    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error> {
        Db::set_backup_error(self, task_id, error).await
    }

    async fn insert_pin_requests_with_tokens(
        &self,
        task_id: &str,
        requestor: &str,
        token_pin_mappings: &[crate::TokenPinMapping],
    ) -> Result<(), sqlx::Error> {
        Db::insert_pin_requests_with_tokens(self, task_id, requestor, token_pin_mappings).await
    }

    async fn update_protection_job_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_protection_job_error_log(self, task_id, error_log).await
    }

    async fn update_protection_job_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_protection_job_status(self, task_id, status).await
    }

    async fn get_protection_job(
        &self,
        task_id: &str,
    ) -> Result<Option<crate::server::db::ProtectionJobWithBackup>, sqlx::Error> {
        Db::get_protection_job(self, task_id).await
    }

    async fn start_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::start_deletion(self, task_id).await
    }

    async fn delete_protection_job(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::delete_protection_job(self, task_id).await
    }

    async fn downgrade_full_to_ipfs(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::downgrade_full_to_ipfs(self, task_id).await
    }

    async fn downgrade_full_to_archive(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::downgrade_full_to_archive(self, task_id).await
    }
}

async fn run_backup_job_inner<DB: BackupJobDb + ?Sized>(state: AppState, job: BackupJob, db: &DB) {
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
        let _ = db.clear_backup_errors(&task_id).await;
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
            let _ = db
                .set_backup_error(&task_id, &format!("Backup failed: {e}"))
                .await;
            return;
        }
    };

    // Persist token-pin request mappings atomically, if any
    if !token_pin_mappings.is_empty() {
        let req = job.requestor.as_deref().unwrap_or("");
        let _ = db
            .insert_pin_requests_with_tokens(&job.task_id, req, &token_pin_mappings)
            .await;
    }

    // Store non-fatal error log in DB if present
    if !error_log.is_empty() {
        let log_str = error_log.join("\n");
        let _ = db.update_protection_job_error_log(&task_id, &log_str).await;
    }

    // Handle archiving based on storage mode
    match storage_mode {
        StorageMode::Archive | StorageMode::Full => {
            // We have an archive output path
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
                        let _ = db.set_backup_error(&task_id, &error_msg).await;
                        return;
                    }
                    let _ = db.update_protection_job_status(&task_id, "done").await;
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
            // IPFS-only mode: no archive operations needed
            let _ = db.update_protection_job_status(&task_id, "done").await;
            info!("IPFS pinning for {} complete", task_id);
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
    pin_requests: &[crate::server::db::PinRequestRow],
) -> Result<bool, String> {
    let mut deleted_anything = false;
    for pin_request in pin_requests {
        let provider = provider_instances
            .iter()
            .find(|provider| provider.provider_name() == pin_request.provider);

        let provider = provider.ok_or_else(|| {
            format!(
                "No provider instance found for provider {} when unpinning {}",
                pin_request.provider, pin_request.cid
            )
        })?;

        provider
            .delete_pin(&pin_request.request_id)
            .await
            .map_err(|e| {
                format!(
                    "Failed to unpin {} from provider {} for task {}: {}",
                    pin_request.cid, pin_request.provider, task_id, e
                )
            })?;

        tracing::info!(
            "Successfully unpinned {} from provider {} for task {}",
            pin_request.cid,
            pin_request.provider,
            task_id
        );
        deleted_anything = true;
    }

    Ok(deleted_anything)
}

async fn run_deletion_job_inner<DB: BackupJobDb + ?Sized>(
    state: AppState,
    job: DeletionJob,
    db: &DB,
) {
    let task_id = job.task_id.clone();
    info!("Running deletion job for task {}", task_id);

    // Get the protection job metadata
    let meta = match db.get_protection_job(&task_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            error!("Task {} not found for deletion", task_id);
            let _ = db
                .set_backup_error(&task_id, "Task not found for deletion")
                .await;
            return;
        }
        Err(e) => {
            error!("Failed to read metadata for task {}: {}", task_id, e);
            let _ = db
                .set_backup_error(&task_id, &format!("Failed to read metadata: {}", e))
                .await;
            return;
        }
    };

    // Verify requestor matches (if provided)
    if let Some(requestor) = &job.requestor {
        if meta.requestor != *requestor {
            error!(
                "Requestor {} does not match task owner {} for task {}",
                requestor, meta.requestor, task_id
            );
            let _ = db
                .set_backup_error(&task_id, "Requestor does not match task owner")
                .await;
            return;
        }
    }

    // Check if task is in progress
    if meta.status == "in_progress" {
        error!("Cannot delete task {} that is in progress", task_id);
        let _ = db
            .set_backup_error(&task_id, "Can only delete completed tasks")
            .await;
        return;
    }

    // Set status to in_progress for deletion
    if let Err(e) = db.start_deletion(&task_id).await {
        error!("Failed to start deletion for task {}: {}", task_id, e);
        let _ = db
            .set_backup_error(&task_id, &format!("Failed to start deletion: {}", e))
            .await;
        return;
    }

    // Handle archive cleanup if requested
    if job.scope == StorageMode::Full || job.scope == StorageMode::Archive {
        if !(meta.storage_mode == "archive" || meta.storage_mode == "full") {
            info!(
                "Skipping archive cleanup for task {} (no archive data)",
                task_id
            );
        } else {
            match delete_dir_and_archive_for_task(
                &state.base_dir,
                &task_id,
                meta.archive_format.as_deref(),
            )
            .await
            {
                Ok(_) => {
                    info!("Archive cleanup completed for task {}", task_id);
                }
                Err(e) => {
                    error!("Archive deletion failed for task {}: {}", task_id, e);
                    // Log the error but continue with deletion - don't fail the job
                }
            }
        }
    }

    // Handle IPFS pin deletion if requested
    if job.scope == StorageMode::Full || job.scope == StorageMode::Ipfs {
        if !(meta.storage_mode == "ipfs" || meta.storage_mode == "full") {
            info!(
                "Skipping IPFS pin cleanup for task {} (no IPFS pins)",
                task_id
            );
        } else {
            let pin_requests = match state.db.get_pin_requests_by_task_id(&task_id).await {
                Ok(v) => v,
                Err(e) => {
                    error!("Failed to get pin requests for task {}: {}", task_id, e);
                    Vec::new()
                }
            };
            match delete_ipfs_pins(&state.ipfs_provider_instances, &task_id, &pin_requests).await {
                Ok(_) => {
                    info!("IPFS pin cleanup completed for task {}", task_id);
                }
                Err(e) => {
                    error!("IPFS pin deletion failed for task {}: {}", task_id, e);
                    // Log the error but continue with deletion - don't fail the job
                }
            }
        }
    }

    // Delete or update the protection job metadata depending on scope and storage mode
    match job.scope {
        StorageMode::Full => {
            if let Err(e) = db.delete_protection_job(&task_id).await {
                error!("Database deletion failed for task {}: {}", task_id, e);
                let _ = db
                    .set_backup_error(
                        &task_id,
                        &format!("Failed to delete metadata from database: {}", e),
                    )
                    .await;
                return;
            }
        }
        StorageMode::Archive => {
            if meta.storage_mode == "full" {
                if let Err(e) = db.downgrade_full_to_ipfs(&task_id).await {
                    error!(
                        "Failed to downgrade storage mode for task {}: {}",
                        task_id, e
                    );
                }
            } else if meta.storage_mode == "archive" {
                if let Err(e) = db.delete_protection_job(&task_id).await {
                    error!(
                        "Failed to delete protection job for task {}: {}",
                        task_id, e
                    );
                }
            }
        }
        StorageMode::Ipfs => {
            if meta.storage_mode == "full" {
                if let Err(e) = db.downgrade_full_to_archive(&task_id).await {
                    error!(
                        "Failed to downgrade storage mode for task {}: {}",
                        task_id, e
                    );
                }
            } else if meta.storage_mode == "ipfs" {
                if let Err(e) = db.delete_protection_job(&task_id).await {
                    error!(
                        "Failed to delete protection job for task {}: {}",
                        task_id, e
                    );
                }
            }
        }
    }

    info!("Successfully deleted backup {}", task_id);
}

pub async fn run_backup_job(state: AppState, job: BackupJob) {
    let task_id = job.task_id.clone();
    let state_clone = state.clone();
    let task_id_clone = task_id.clone();

    let fut = AssertUnwindSafe(run_backup_job_inner(state.clone(), job, &*state.db)).catch_unwind();

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
        let _ = BackupJobDb::set_backup_error(&*state_clone.db, &task_id_clone, &error_msg).await;
    }
}

pub async fn run_deletion_job(state: AppState, job: DeletionJob) {
    let task_id = job.task_id.clone();
    let state_clone = state.clone();
    let task_id_clone = task_id.clone();

    let fut =
        AssertUnwindSafe(run_deletion_job_inner(state.clone(), job, &*state.db)).catch_unwind();

    let result = fut.await;
    if let Err(panic) = result {
        let panic_msg = if let Some(s) = panic.downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = panic.downcast_ref::<String>() {
            s.clone()
        } else {
            "Unknown panic".to_string()
        };
        let error_msg = format!("Deletion job for task {task_id_clone} panicked: {panic_msg}");
        error!("{error_msg}");
        let _ = BackupJobDb::set_backup_error(&*state_clone.db, &task_id_clone, &error_msg).await;
    }
}

#[cfg(test)]
mod deletion_utils_tests {
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
        fn provider_name(&self) -> &str {
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
            crate::server::db::PinRequestRow {
                id: 1,
                task_id: "t".into(),
                provider: "mock".into(),
                cid: "cid1".into(),
                request_id: "rid1".into(),
                status: "pinned".into(),
                requestor: "u".into(),
            },
            crate::server::db::PinRequestRow {
                id: 2,
                task_id: "t".into(),
                provider: "mock".into(),
                cid: "cid2".into(),
                request_id: "rid2".into(),
                status: "pinned".into(),
                requestor: "u".into(),
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
        let rows = vec![crate::server::db::PinRequestRow {
            id: 1,
            task_id: "t".into(),
            provider: "unknown".into(),
            cid: "cid".into(),
            request_id: "rid".into(),
            status: "pinned".into(),
            requestor: "u".into(),
        }];
        let err = delete_ipfs_pins(&providers, "t", &rows).await.unwrap_err();
        assert!(err.contains("No provider instance"));
    }
}

#[cfg(test)]
mod recover_incomplete_jobs_tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    // Mock implementation of RecoveryDb for testing
    struct MockRecoveryDb {
        jobs: Vec<RecoveryJob>,
        should_fail_get_jobs: bool,
        should_fail_set_error: bool,
        set_error_calls: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }

    impl MockRecoveryDb {
        fn new(jobs: Vec<RecoveryJob>) -> Self {
            Self {
                jobs,
                should_fail_get_jobs: false,
                should_fail_set_error: false,
                set_error_calls: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn with_get_jobs_failure(mut self) -> Self {
            self.should_fail_get_jobs = true;
            self
        }

        fn get_set_error_calls(&self) -> Vec<(String, String)> {
            self.set_error_calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl RecoveryDb for MockRecoveryDb {
        async fn get_incomplete_protection_jobs(&self) -> Result<Vec<RecoveryJob>, sqlx::Error> {
            if self.should_fail_get_jobs {
                return Err(sqlx::Error::Configuration("Mock error".into()));
            }
            Ok(self.jobs.clone())
        }

        async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error> {
            if self.should_fail_set_error {
                return Err(sqlx::Error::Configuration("Mock error".into()));
            }
            self.set_error_calls
                .lock()
                .unwrap()
                .push((task_id.to_string(), error.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_recover_incomplete_jobs_no_jobs() {
        let mock_db = MockRecoveryDb::new(vec![]);
        let (tx, _rx) = mpsc::channel(10);

        let result = recover_incomplete_jobs(&mock_db, &tx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_recover_incomplete_jobs_success() {
        let jobs = vec![
            RecoveryJob {
                task_id: "task1".to_string(),
                requestor: "user1".to_string(),
                tokens: json!([{"chain": "ethereum", "tokens": ["0x123"]}]),
                storage_mode: "archive".to_string(),
                archive_format: Some("zip".to_string()),
            },
            RecoveryJob {
                task_id: "task2".to_string(),
                requestor: "user2".to_string(),
                tokens: json!([{"chain": "tezos", "tokens": ["KT1ABC"]}]),
                storage_mode: "full".to_string(),
                archive_format: None,
            },
        ];
        let mock_db = MockRecoveryDb::new(jobs);
        let (tx, mut rx) = mpsc::channel(10);

        let result = recover_incomplete_jobs(&mock_db, &tx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);

        // Check that jobs were enqueued (order-independent)
        let j1 = rx.recv().await.unwrap();
        let j2 = rx.recv().await.unwrap();
        let mut seen_task1 = false;
        let mut seen_task2 = false;
        for job in [j1, j2] {
            match job {
                BackupJobOrShutdown::Job(JobType::Creation(job)) => {
                    if job.task_id == "task1" {
                        seen_task1 = true;
                        assert!(job.force);
                        assert_eq!(job.storage_mode, StorageMode::Archive);
                        assert_eq!(job.archive_format, Some("zip".to_string()));
                        assert_eq!(job.requestor, Some("user1".to_string()));
                    } else if job.task_id == "task2" {
                        seen_task2 = true;
                        assert!(job.force);
                        assert_eq!(job.storage_mode, StorageMode::Full);
                        assert_eq!(job.archive_format, None);
                        assert_eq!(job.requestor, Some("user2".to_string()));
                    } else {
                        panic!("Unexpected task id");
                    }
                }
                _ => panic!("Expected backup job"),
            }
        }
        assert!(seen_task1 && seen_task2);
    }

    #[tokio::test]
    async fn test_recover_incomplete_jobs_invalid_tokens() {
        let jobs = vec![RecoveryJob {
            task_id: "task1".to_string(),
            requestor: "user1".to_string(),
            tokens: json!("invalid tokens"), // Invalid JSON for tokens
            storage_mode: "archive".to_string(),
            archive_format: None,
        }];
        let mock_db = MockRecoveryDb::new(jobs);
        let (tx, mut rx) = mpsc::channel(10);

        let result = recover_incomplete_jobs(&mock_db, &tx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Should not enqueue any jobs
        assert!(rx.try_recv().is_err());

        // Should have called set_backup_error
        let error_calls = mock_db.get_set_error_calls();
        assert_eq!(error_calls.len(), 1);
        assert_eq!(error_calls[0].0, "task1");
        assert!(error_calls[0]
            .1
            .contains("Failed to parse tokens during recovery"));
    }

    #[tokio::test]
    async fn test_recover_incomplete_jobs_db_error() {
        let mock_db = MockRecoveryDb::new(vec![]).with_get_jobs_failure();
        let (tx, _rx) = mpsc::channel(10);

        let result = recover_incomplete_jobs(&mock_db, &tx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_recover_incomplete_jobs_storage_mode_parsing() {
        let jobs = vec![RecoveryJob {
            task_id: "task1".to_string(),
            requestor: "user1".to_string(),
            tokens: json!([{"chain": "ethereum", "tokens": ["0x123"]}]),
            storage_mode: "invalid_mode".to_string(), // Invalid storage mode
            archive_format: None,
        }];
        let mock_db = MockRecoveryDb::new(jobs);
        let (tx, mut rx) = mpsc::channel(10);

        let result = recover_incomplete_jobs(&mock_db, &tx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Should default to StorageMode::Full for invalid mode
        let job = rx.recv().await.unwrap();
        match job {
            BackupJobOrShutdown::Job(JobType::Creation(job)) => {
                assert_eq!(job.storage_mode, StorageMode::Full);
                assert!(job.request.pin_on_ipfs); // Both includes IPFS
            }
            _ => panic!("Expected backup job"),
        }
    }
}
