use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::backup::ChainConfig;
use crate::server::api::Tokens;
use crate::server::db::Db;
use crate::server::hashing::compute_file_sha256;

pub mod api;
pub mod archive;
pub mod db;
pub mod handlers;
pub mod hashing;
pub mod privy;
pub mod pruner;
pub use handlers::handle_backup::handle_backup;
pub use handlers::handle_backup_delete::handle_backup_delete;
pub use handlers::handle_backup_retry::handle_backup_retry;
pub use handlers::handle_backups::handle_backups;
pub use handlers::handle_download::handle_download;
pub use handlers::handle_download::handle_download_token;
pub use handlers::handle_status::handle_status;

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
}

#[derive(Debug, Clone)]
pub enum BackupJobOrShutdown {
    Job(BackupJob),
    Shutdown,
}

#[derive(Debug, Clone)]
pub struct BackupJob {
    pub task_id: String,
    pub tokens: Vec<Tokens>,
    pub force: bool,
    pub archive_format: String,
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
    debug!("Recovering incomplete backup jobs from database...");

    let incomplete_jobs = state.db.get_incomplete_backup_jobs().await?;
    let job_count = incomplete_jobs.len();

    if job_count == 0 {
        debug!("No incomplete backup jobs found");
        return Ok(0);
    }

    debug!(
        "Found {} incomplete backup jobs, re-queueing for processing",
        job_count
    );

    for job_meta in incomplete_jobs {
        // Parse the tokens JSON back to Vec<Tokens>
        let tokens: Vec<Tokens> = match serde_json::from_value(job_meta.tokens) {
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

        let backup_job = BackupJob {
            task_id: job_meta.task_id.clone(),
            tokens,
            force: false, // Don't force on recovery, just resume
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
