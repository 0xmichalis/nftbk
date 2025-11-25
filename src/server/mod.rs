use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::signal;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{error, info};

use crate::ipfs::{IpfsPinningConfig, IpfsPinningProvider};
use crate::server::api::{BackupRequest, Tokens};
use crate::server::auth::jwt::JwtCredential;
use crate::server::database::Db;
use crate::server::x402::X402Config;
use crate::types::ChainConfig;

pub mod api;
pub mod archive;
pub mod auth;
pub mod config;
pub mod database;
pub mod handlers;
pub mod hashing;
pub mod pin_monitor;
pub mod pruner;
pub mod recovery;
pub mod router;
pub mod workers;
pub mod x402;
pub use handlers::handle_archive_download::handle_archive_download as handle_download;
pub use handlers::handle_archive_download::handle_archive_download_token as handle_download_token;
pub use handlers::handle_backup::handle_backup;
pub use handlers::handle_backup_create::handle_backup_create;
pub use handlers::handle_backup_delete_archive::handle_backup_delete_archive;
pub use handlers::handle_backup_delete_pins::handle_backup_delete_pins;
pub use handlers::handle_backup_retries::handle_backup_retries;
pub use handlers::handle_backups::handle_backups;
pub use recovery::recover_incomplete_tasks;
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
    Quote(QuoteTask),
}

#[derive(Debug, Clone)]
pub struct BackupTask {
    pub task_id: String,
    pub request: BackupRequest,
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

#[derive(Debug, Clone)]
pub struct QuoteTask {
    pub quote_id: String,
    pub task_id: String,
    pub request: BackupRequest,
    pub requestor: Option<String>,
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

impl fmt::Display for StorageMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub fn parse_scope(scope: &str) -> Option<StorageMode> {
    match scope {
        "archive" => Some(StorageMode::Archive),
        "ipfs" => Some(StorageMode::Ipfs),
        "full" => Some(StorageMode::Full),
        _ => None,
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

pub type QuoteCache = Arc<Mutex<lru::LruCache<String, (Option<u64>, String)>>>;

#[derive(Clone)]
pub struct AppState {
    pub chain_config: Arc<ChainConfig>,
    pub base_dir: Arc<String>,
    pub unsafe_skip_checksum_check: bool,
    pub auth_token: Option<String>,
    pub pruner_retention_days: u64,
    pub download_tokens: Arc<Mutex<HashMap<String, (String, u64)>>>,
    pub quote_cache: QuoteCache,
    pub backup_task_sender: mpsc::Sender<BackupTaskOrShutdown>,
    pub db: Arc<Db>,
    pub shutdown_flag: Arc<AtomicBool>,
    pub ipfs_pinning_configs: Vec<IpfsPinningConfig>,
    pub ipfs_pinning_instances: Arc<Vec<Arc<dyn IpfsPinningProvider>>>,
    pub x402_config: Option<crate::server::x402::X402Config>,
}

impl Default for AppState {
    fn default() -> Self {
        panic!("AppState::default() should not be used; use AppState::new() instead");
    }
}

impl AppState {
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        chain_config: ChainConfig,
        base_dir: &str,
        unsafe_skip_checksum_check: bool,
        auth_token: Option<String>,
        pruner_retention_days: u64,
        backup_task_sender: mpsc::Sender<BackupTaskOrShutdown>,
        db_url: &str,
        max_connections: u32,
        shutdown_flag: Arc<AtomicBool>,
        ipfs_pinning_configs: Vec<IpfsPinningConfig>,
        x402_config: Option<crate::server::x402::X402Config>,
        quote_cache_size: usize,
    ) -> Self {
        let db = Arc::new(Db::new(db_url, max_connections).await);

        // Create IPFS provider instances at startup
        let mut ipfs_pinning_instances = Vec::new();
        for config in &ipfs_pinning_configs {
            match config.create_provider() {
                Ok(provider) => {
                    ipfs_pinning_instances.push(Arc::from(provider));
                }
                Err(e) => {
                    error!(
                        "Failed to create IPFS provider from config {:?}: {}",
                        config, e
                    );
                }
            }
        }

        // Create quote cache with configurable size.
        // This LRU cache stores quote IDs and their associated prices for x402 dynamic pricing.
        // When the cache is full, the least recently used quotes are evicted.
        let quote_cache_size = NonZeroUsize::new(quote_cache_size.max(100))
            .expect("quote_cache_size should be at least 100");
        AppState {
            chain_config: Arc::new(chain_config),
            base_dir: Arc::new(base_dir.to_string()),
            unsafe_skip_checksum_check,
            auth_token,
            pruner_retention_days,
            download_tokens: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            quote_cache: Arc::new(tokio::sync::Mutex::new(lru::LruCache::new(
                quote_cache_size,
            ))),
            backup_task_sender,
            db,
            shutdown_flag,
            ipfs_pinning_configs,
            ipfs_pinning_instances: Arc::new(ipfs_pinning_instances),
            x402_config,
        }
    }
}

/// Configuration for running the server
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_address: String,
    pub base_dir: String,
    pub unsafe_skip_checksum_check: bool,
    pub auth_token: Option<String>,
    pub pruner_retention_days: u64,
    pub pruner_interval_seconds: u64,
    pub pin_monitor_interval_seconds: u64,
    pub backup_parallelism: usize,
    pub backup_queue_size: usize,
    pub chain_config: ChainConfig,
    pub jwt_credentials: Vec<JwtCredential>,
    pub x402_config: Option<X402Config>,
    pub ipfs_pinning_configs: Vec<IpfsPinningConfig>,
    pub quote_cache_size: usize,
}

/// Start the HTTP server with the given configuration
async fn start_http_server(
    config: ServerConfig,
    state: AppState,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::server::router::build_router;

    let addr: SocketAddr = config
        .listen_address
        .parse()
        .expect("Invalid listen address");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let app = build_router(
        state.clone(),
        config.jwt_credentials,
        config.x402_config.clone(),
    );
    info!("Listening on {}", addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    Ok(())
}

/// Wait for graceful shutdown of all server components
async fn wait_for_graceful_shutdown(
    pruner_handle: Option<tokio::task::JoinHandle<()>>,
    pin_monitor_handle: Option<tokio::task::JoinHandle<()>>,
    backup_parallelism: usize,
    backup_task_sender: mpsc::Sender<BackupTaskOrShutdown>,
    worker_handles: Vec<tokio::task::JoinHandle<()>>,
) {
    // Graceful shutdown
    if let Some(handle) = pruner_handle {
        let _ = handle.await;
    }
    info!("Pruner has exited");

    if let Some(handle) = pin_monitor_handle {
        let _ = handle.await;
    }
    info!("Pin monitor has exited");

    for _ in 0..backup_parallelism {
        let _ = backup_task_sender
            .send(BackupTaskOrShutdown::Shutdown)
            .await;
    }
    drop(backup_task_sender);
    info!("Backup task sender has exited");

    for handle in worker_handles {
        let _ = handle.await;
    }
    info!("Backup workers have exited");

    // Give time for final logs to flush
    let _ = std::io::stdout().flush();
    std::thread::sleep(std::time::Duration::from_millis(200));
}

/// Run the server with the given configuration
pub async fn run_server(
    config: ServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::server::pin_monitor::spawn_pin_monitor;
    use crate::server::pruner::spawn_pruner;
    let (backup_task_sender, backup_task_receiver) =
        mpsc::channel::<BackupTaskOrShutdown>(config.backup_queue_size);
    let db_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL env var must be set for Postgres");
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    let state = AppState::new(
        config.chain_config.clone(),
        &config.base_dir,
        config.unsafe_skip_checksum_check,
        config.auth_token.clone(),
        config.pruner_retention_days,
        backup_task_sender.clone(),
        &db_url,
        (config.backup_queue_size + 1) as u32,
        shutdown_flag.clone(),
        config.ipfs_pinning_configs.clone(),
        config.x402_config.clone(),
        config.quote_cache_size,
    )
    .await;

    // Spawn worker pool for backup tasks
    let worker_handles = spawn_backup_workers(
        config.backup_parallelism,
        backup_task_receiver,
        state.clone(),
    );

    // Recover incomplete backup tasks from previous server runs
    match recover_incomplete_tasks(&*state.db, &state.backup_task_sender).await {
        Ok(count) => {
            if count > 0 {
                info!("Successfully recovered {} incomplete backup tasks", count);
            }
        }
        Err(e) => {
            error!("Failed to recover incomplete backup tasks: {}", e);
            // Don't exit the server, just log the error and continue
        }
    }

    // Start the pruner thread
    let pruner_handle = spawn_pruner(
        state.db.clone(),
        config.base_dir.clone(),
        config.pruner_interval_seconds,
        state.shutdown_flag.clone(),
    );

    // Start the pin monitor thread if IPFS providers are configured
    let pin_monitor_handle = spawn_pin_monitor(
        state.db.clone(),
        state.ipfs_pinning_instances.clone(),
        config.pin_monitor_interval_seconds,
        state.shutdown_flag.clone(),
    );

    // Add graceful shutdown
    let shutdown_signal = async move {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");

        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received SIGINT (Ctrl+C), shutting down server...");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, shutting down server...");
            }
        }
        shutdown_flag.store(true, Ordering::SeqCst);
    };

    // Start the server
    start_http_server(config.clone(), state.clone(), shutdown_signal).await?;
    info!("Server has exited");

    // Wait for graceful shutdown of all components
    wait_for_graceful_shutdown(
        pruner_handle,
        pin_monitor_handle,
        config.backup_parallelism,
        state.backup_task_sender.clone(),
        worker_handles,
    )
    .await;

    Ok(())
}
