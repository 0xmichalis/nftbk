use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::backup::ChainConfig;
use crate::hashing::compute_file_sha256;

pub mod handle_backup;
pub mod handle_backups;
pub mod handle_download;
pub mod handle_error_log;
pub mod handle_status;
pub mod privy;
pub mod pruner;
pub use handle_backup::handle_backup;
pub use handle_backups::handle_backups;
pub use handle_download::handle_download;
pub use handle_error_log::handle_error_log;
pub use handle_status::handle_status;

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
}

impl Default for AppState {
    fn default() -> Self {
        panic!("AppState::default() should not be used; use AppState::new() instead");
    }
}

impl AppState {
    pub async fn new(
        chain_config_path: &str,
        base_dir: &str,
        unsafe_skip_checksum_check: bool,
        auth_token: Option<String>,
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
        }
    }
}

pub fn get_zipped_backup_paths(base_dir: &str, task_id: &str) -> (PathBuf, PathBuf) {
    let zip_path = PathBuf::from(format!("{}/nftbk-{}.tar.gz", base_dir, task_id));
    let checksum_path = PathBuf::from(format!("{}.sha256", zip_path.display()));
    (zip_path, checksum_path)
}

pub async fn check_backup_on_disk(
    base_dir: &str,
    task_id: &str,
    unsafe_skip_checksum_check: bool,
) -> Option<PathBuf> {
    let (path, checksum_path) = get_zipped_backup_paths(base_dir, task_id);

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
