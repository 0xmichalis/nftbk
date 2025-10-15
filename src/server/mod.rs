use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{error, info};

use crate::backup::ChainConfig;
use crate::ipfs::{IpfsPinningProvider, IpfsProviderConfig};
use crate::server::api::{BackupRequest, Tokens};
use crate::server::database::Db;

pub mod api;
pub mod archive;
pub mod database;
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
