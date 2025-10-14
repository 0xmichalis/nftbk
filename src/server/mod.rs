use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use crate::backup::ChainConfig;
use crate::ipfs::{IpfsPinningProvider, IpfsProviderConfig};
use crate::server::api::{BackupRequest, Tokens};
use crate::server::db::Db;
use crate::server::hashing::compute_file_sha256;

pub mod api;
pub mod archive;
pub mod db;
pub mod handlers;
pub mod hashing;
pub mod pin_monitor;
pub mod privy;
pub mod pruner;
pub mod recovery;
pub mod router;
pub mod workers;
pub use handlers::handle_backup::handle_backup;
pub use handlers::handle_backup_delete_archive::handle_backup_delete_archive;
pub use handlers::handle_backup_delete_pins::handle_backup_delete_pins;
pub use handlers::handle_backup_retry::handle_backup_retry;
pub use handlers::handle_backups::handle_backups;
pub use handlers::handle_download::handle_download;
pub use handlers::handle_download::handle_download_token;
pub use handlers::handle_status::handle_status;
pub use recovery::{recover_incomplete_tasks, RecoveryDb};
pub use workers::deletion::{complete_deletion_for_scope, start_deletion_for_scope};
pub use workers::spawn_backup_workers;

#[derive(Debug, Clone)]
pub enum BackupTaskOrShutdown {
    Task(TaskType),
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum TaskType {
    Creation(BackupTask),
    Deletion(DeletionTask),
}

#[derive(Debug, Clone)]
pub struct BackupTask {
    pub task_id: String,
    pub request: BackupRequest,
    pub force: bool,
    pub scope: StorageMode,
    pub archive_format: Option<String>,
    pub requestor: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DeletionTask {
    pub task_id: String,
    pub requestor: Option<String>,
    /// Determines which parts of the backup to delete (e.g., only the archive, only the IPFS pins, or both).
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
    pub backup_task_sender: mpsc::Sender<BackupTaskOrShutdown>,
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
        backup_task_sender: mpsc::Sender<BackupTaskOrShutdown>,
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
                        "Successfully created IPFS provider {} ({})",
                        provider.provider_type(),
                        provider.provider_url()
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
            backup_task_sender,
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

// Trait for database operations needed by backup and deletion tasks
#[async_trait::async_trait]
pub trait BackupTaskDb {
    async fn clear_backup_errors(&self, task_id: &str, scope: &str) -> Result<(), sqlx::Error>;
    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error>;
    async fn insert_pins_with_tokens(
        &self,
        task_id: &str,
        token_pin_mappings: &[crate::TokenPinMapping],
    ) -> Result<(), sqlx::Error>;
    async fn set_error_logs(
        &self,
        task_id: &str,
        archive_error_log: Option<&str>,
        ipfs_error_log: Option<&str>,
    ) -> Result<(), sqlx::Error>;
    async fn update_archive_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error>;
    async fn update_ipfs_task_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error>;
    async fn set_archive_request_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error>;
    async fn update_archive_request_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error>;
    async fn update_pin_request_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error>;
    async fn update_backup_statuses(
        &self,
        task_id: &str,
        scope: &str,
        archive_status: &str,
        ipfs_status: &str,
    ) -> Result<(), sqlx::Error>;
    async fn get_backup_task(
        &self,
        task_id: &str,
    ) -> Result<Option<crate::server::db::BackupTask>, sqlx::Error>;
    async fn start_deletion(&self, task_id: &str) -> Result<(), sqlx::Error>;
    async fn start_archive_deletion(&self, task_id: &str) -> Result<(), sqlx::Error>;
    async fn start_ipfs_pins_deletion(&self, task_id: &str) -> Result<(), sqlx::Error>;
    async fn delete_backup_task(&self, task_id: &str) -> Result<(), sqlx::Error>;
    async fn complete_archive_deletion(&self, task_id: &str) -> Result<(), sqlx::Error>;
    async fn complete_ipfs_pins_deletion(&self, task_id: &str) -> Result<(), sqlx::Error>;
    async fn update_ipfs_task_status(&self, task_id: &str, status: &str)
        -> Result<(), sqlx::Error>;
    async fn set_ipfs_task_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error>;
}

// Implement BackupTaskDb trait for the real Db
#[async_trait::async_trait]
impl BackupTaskDb for Db {
    async fn clear_backup_errors(&self, task_id: &str, scope: &str) -> Result<(), sqlx::Error> {
        Db::clear_backup_errors(self, task_id, scope).await
    }

    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error> {
        Db::set_backup_error(self, task_id, error).await
    }

    async fn insert_pins_with_tokens(
        &self,
        task_id: &str,
        token_pin_mappings: &[crate::TokenPinMapping],
    ) -> Result<(), sqlx::Error> {
        Db::insert_pins_with_tokens(self, task_id, token_pin_mappings).await
    }

    async fn set_error_logs(
        &self,
        task_id: &str,
        archive_error_log: Option<&str>,
        ipfs_error_log: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        Db::set_error_logs(self, task_id, archive_error_log, ipfs_error_log).await
    }

    async fn update_archive_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_archive_error_log(self, task_id, error_log).await
    }

    async fn update_ipfs_task_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_ipfs_task_error_log(self, task_id, error_log).await
    }

    async fn set_archive_request_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error> {
        Db::set_archive_request_error(self, task_id, fatal_error).await
    }

    async fn update_archive_request_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_archive_request_status(self, task_id, status).await
    }

    async fn update_pin_request_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_pin_request_status(self, task_id, status).await
    }

    async fn update_backup_statuses(
        &self,
        task_id: &str,
        scope: &str,
        archive_status: &str,
        ipfs_status: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_backup_statuses(self, task_id, scope, archive_status, ipfs_status).await
    }

    async fn get_backup_task(
        &self,
        task_id: &str,
    ) -> Result<Option<crate::server::db::BackupTask>, sqlx::Error> {
        Db::get_backup_task(self, task_id).await
    }

    async fn start_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::start_deletion(self, task_id).await
    }

    async fn start_archive_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::start_archive_deletion(self, task_id).await
    }

    async fn start_ipfs_pins_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::start_ipfs_pins_deletion(self, task_id).await
    }

    async fn delete_backup_task(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::delete_backup_task(self, task_id).await
    }

    async fn complete_archive_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::complete_archive_deletion(self, task_id).await
    }

    async fn complete_ipfs_pins_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::complete_ipfs_pins_deletion(self, task_id).await
    }

    async fn update_ipfs_task_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_ipfs_task_status(self, task_id, status).await
    }

    async fn set_ipfs_task_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error> {
        Db::set_ipfs_task_error(self, task_id, fatal_error).await
    }
}
