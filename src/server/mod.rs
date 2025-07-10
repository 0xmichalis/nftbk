use fs2::FileExt;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::backup::ChainConfig;
use crate::hashing::compute_file_sha256;

pub mod archive;
pub mod handle_backup;
pub mod handle_backup_delete;
pub mod handle_backups;
pub mod handle_download;
pub mod handle_error_log;
pub mod handle_status;
pub mod privy;
pub mod pruner;
pub use handle_backup::handle_backup;
pub use handle_backup::handle_backup_retry;
pub use handle_backup_delete::handle_backup_delete;
pub use handle_backups::handle_backups;
pub use handle_download::handle_download;
pub use handle_download::handle_download_token;
pub use handle_error_log::handle_error_log;
pub use handle_status::handle_status;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BackupMetadata {
    pub created_at: String,
    pub requestor: String,
    pub archive_format: String,
    pub nft_count: usize,
    pub tokens: Vec<crate::api::Tokens>,
}

#[derive(Debug, Clone)]
pub enum TaskStatus {
    InProgress,
    Done,
    Error(String),
}

#[derive(Debug, Clone)]
pub struct TaskInfo {
    pub status: TaskStatus,
    pub zip_path: Option<PathBuf>,
}

pub type TaskMap = Arc<Mutex<HashMap<String, TaskInfo>>>;

#[derive(Clone)]
pub struct AppState {
    pub tasks: TaskMap,
    pub chain_config: Arc<ChainConfig>,
    pub base_dir: Arc<String>,
    pub unsafe_skip_checksum_check: bool,
    pub auth_token: Option<String>,
    pub pruner_enabled: bool,
    pub pruner_retention_days: u64,
    /// Maps download tokens to (task_id, expiration timestamp as unix epoch seconds)
    pub download_tokens: Arc<Mutex<HashMap<String, (String, u64)>>>,
    pub parallelism: usize,
    pub backup_job_sender: mpsc::Sender<BackupJob>,
}

#[derive(Debug, Clone)]
pub struct BackupJob {
    pub task_id: String,
    pub tokens: Vec<crate::api::Tokens>,
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
        parallelism: usize,
        backup_job_sender: mpsc::Sender<BackupJob>,
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
        AppState {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            chain_config: Arc::new(chain_config),
            base_dir: Arc::new(base_dir.to_string()),
            unsafe_skip_checksum_check,
            auth_token,
            pruner_enabled,
            pruner_retention_days,
            download_tokens: Arc::new(Mutex::new(HashMap::new())),
            parallelism,
            backup_job_sender,
        }
    }
}

/// Helper for locked read-modify-write of a JSON Vec<String> file.
/// The closure receives the current Vec<String> and returns the new Vec<String>.
pub async fn locked_update_string_vec_json_file<F, R>(
    file_path: &str,
    modify: F,
) -> Result<R, std::io::Error>
where
    F: FnOnce(&mut Vec<String>) -> R + Send + 'static,
    R: Send + 'static,
{
    let file_path = file_path.to_string();
    tokio::task::spawn_blocking(move || {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&file_path)?;
        file.lock_exclusive()?;
        // Read current vec
        let mut content = String::new();
        file.seek(SeekFrom::Start(0))?;
        file.read_to_string(&mut content)?;
        let mut vec: Vec<String> = serde_json::from_str(&content).unwrap_or_default();
        let result = modify(&mut vec);
        // Write updated vec
        let new_content = serde_json::to_string_pretty(&vec).unwrap();
        file.set_len(0)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(new_content.as_bytes())?;
        file.flush()?;
        fs2::FileExt::unlock(&file)?;
        Ok(result)
    })
    .await?
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

/// Returns (status, error) for a given task_id, checking in-memory and on-disk state
pub async fn get_backup_status_and_error(
    state: &AppState,
    task_id: &str,
    tasks: &std::collections::HashMap<String, TaskInfo>,
    archive_format: &str,
) -> (String, Option<String>) {
    if let Some(task) = tasks.get(task_id) {
        match &task.status {
            TaskStatus::InProgress => return ("in_progress".to_string(), None),
            TaskStatus::Error(e) => return ("error".to_string(), Some(e.clone())),
            TaskStatus::Done => { /* fall through to disk check below */ }
        }
    }
    // For Done or missing tasks, check disk
    let backup_on_disk = check_backup_on_disk(
        &state.base_dir,
        task_id,
        state.unsafe_skip_checksum_check,
        archive_format,
    )
    .await
    .is_some();
    if backup_on_disk {
        ("done".to_string(), None)
    } else {
        ("expired".to_string(), None)
    }
}
