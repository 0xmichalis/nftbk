use clap::Parser;
use dotenv::dotenv;
use std::env;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info};

use nftbk::envvar::is_defined;
use nftbk::logging;
use nftbk::logging::LogLevel;
use nftbk::server::auth::x402::X402Config;
use nftbk::server::auth::{load_auth_config, JwtCredential};
use nftbk::server::pin_monitor::run_pin_monitor;
use nftbk::server::pruner::run_pruner;
use nftbk::server::router::build_router;
use nftbk::server::{
    recover_incomplete_tasks, spawn_backup_workers, AppState, BackupTaskOrShutdown,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The address to listen on
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen_address: String,

    /// The path to the chains configuration file
    #[arg(short = 'c', long, default_value = "config_chains.toml")]
    chain_config: String,

    /// The base directory to save the backup to
    #[arg(long, default_value = "/tmp")]
    base_dir: String,

    /// Set the log level
    #[arg(short, long, value_enum, default_value = "info")]
    log_level: LogLevel,

    /// Skip checksum verification
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    unsafe_skip_checksum_check: bool,

    /// Enable the pruner thread
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    enable_pruner: bool,

    /// Pruner retention period in days
    #[arg(long, default_value_t = 3)]
    pruner_retention_days: u64,

    /// Pruner interval in seconds
    #[arg(long, default_value_t = 3600)]
    pruner_interval_seconds: u64,

    /// Pruner regex pattern for file names to prune
    #[arg(long, default_value = "^nftbk-")]
    pruner_pattern: String,

    /// Pin monitor interval in seconds
    #[arg(long, default_value_t = 120)]
    pin_monitor_interval_seconds: u64,

    /// Number of backup worker threads to run in parallel
    #[arg(long, default_value_t = 4)]
    backup_parallelism: usize,

    /// Maximum number of backup tasks to queue before blocking
    #[arg(long, default_value_t = 10000)]
    backup_queue_size: usize,

    /// Disable colored log output
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    no_color: bool,

    /// Path to a TOML file with one or more JWT credential sets
    #[arg(long)]
    auth_config: Option<String>,

    /// Path to a TOML file with IPFS provider configuration
    /// When provided, this is used instead of IPFS_* env vars
    #[arg(long)]
    ipfs_config: Option<String>,
}

#[derive(serde::Deserialize)]
struct IpfsConfigFile {
    ipfs_pinning_provider: Vec<nftbk::ipfs::IpfsPinningConfig>,
}

#[tokio::main]
async fn main() {
    // We are consuming config both from the environment and from the command line
    dotenv().ok();
    let args = Args::parse();
    logging::init(args.log_level.clone(), !args.no_color);
    info!(
        "Starting {} {} (commit {})",
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("GIT_COMMIT")
    );

    // Load authentication config
    let auth_token = env::var("NFTBK_AUTH_TOKEN").ok();
    let mut jwt_credentials: Vec<JwtCredential> = Vec::new();
    let mut x402_config: Option<X402Config> = None;
    if let Some(path) = &args.auth_config {
        match load_auth_config(std::path::Path::new(path)) {
            Ok(auth_config) => {
                jwt_credentials = auth_config.jwt_credentials;
                x402_config = auth_config.x402_config;
            }
            Err(e) => {
                error!("Failed to load auth config from '{}': {}", path, e);
                std::process::exit(1);
            }
        }
    }

    // Load IPFS provider configuration from file if provided
    let ipfs_pinning_configs = if args.ipfs_config.is_none() {
        // No config file, use empty list (AppState will fall back to env vars)
        Vec::new()
    } else {
        let path = args.ipfs_config.as_ref().unwrap();
        match std::fs::read_to_string(path) {
            Ok(contents) => match toml::from_str::<IpfsConfigFile>(&contents) {
                Ok(file) => {
                    info!(
                        "Loaded {} IPFS pinning provider(s) from config file '{}'",
                        file.ipfs_pinning_provider.len(),
                        path
                    );
                    file.ipfs_pinning_provider
                }
                Err(e) => {
                    error!("Failed to parse IPFS config file '{}': {}", path, e);
                    std::process::exit(1);
                }
            },
            Err(e) => {
                error!("Failed to read IPFS config file '{}': {}", path, e);
                std::process::exit(1);
            }
        }
    };

    let (backup_task_sender, backup_task_receiver) =
        mpsc::channel::<BackupTaskOrShutdown>(args.backup_queue_size);
    let db_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL env var must be set for Postgres");
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let state = AppState::new(
        &args.chain_config,
        &args.base_dir,
        args.unsafe_skip_checksum_check,
        auth_token.clone(),
        args.enable_pruner,
        args.pruner_retention_days,
        backup_task_sender.clone(),
        &db_url,
        (args.backup_queue_size + 1) as u32,
        shutdown_flag.clone(),
        ipfs_pinning_configs,
    )
    .await;

    info!("Starting server with options: {:?}", args);
    info!(
        "Symmetric authentication enabled: {}",
        is_defined(&auth_token)
    );
    info!(
        "JWT authentication enabled: {} ({} credential set(s))",
        !jwt_credentials.is_empty(),
        jwt_credentials.len()
    );

    // Spawn worker pool for backup tasks
    let worker_handles =
        spawn_backup_workers(args.backup_parallelism, backup_task_receiver, state.clone());

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
    let pruner_handle = if !args.enable_pruner {
        None
    } else {
        let db = state.db.clone();
        let base_dir = args.base_dir.clone();
        let interval = args.pruner_interval_seconds;
        let shutdown_flag = state.shutdown_flag.clone();
        Some(tokio::spawn(async move {
            run_pruner(db, base_dir, interval, shutdown_flag).await;
        }))
    };

    // Start the pin monitor thread if IPFS providers are configured
    let pin_monitor_handle = if state.ipfs_pinning_instances.is_empty() {
        None
    } else {
        let db = state.db.clone();
        let providers = state.ipfs_pinning_instances.clone();
        let interval = args.pin_monitor_interval_seconds;
        let shutdown_flag = state.shutdown_flag.clone();
        info!(
            "Starting pin monitor with {} IPFS provider(s) and {} second interval",
            providers.len(),
            interval
        );
        Some(tokio::spawn(async move {
            run_pin_monitor(db, providers.to_vec(), interval, shutdown_flag).await;
        }))
    };

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
    let addr: SocketAddr = args.listen_address.parse().expect("Invalid listen address");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let app = build_router(
        state.clone(),
        jwt_credentials
            .into_iter()
            .map(|c| (c.issuer, c.audience, c.verification_key))
            .collect(),
        x402_config.clone(),
    );
    if let Some(cfg) = x402_config {
        info!("x402 config loaded (facilitator: {})", cfg.facilitator.url);
    }
    info!("Listening on {}", addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .unwrap();
    info!("Server has exited");

    if let Some(handle) = pruner_handle {
        let _ = handle.await;
    }
    info!("Pruner has exited");

    if let Some(handle) = pin_monitor_handle {
        let _ = handle.await;
    }
    info!("Pin monitor has exited");

    // On shutdown, send one Shutdown message per worker
    for _ in 0..args.backup_parallelism {
        let _ = state
            .backup_task_sender
            .send(BackupTaskOrShutdown::Shutdown)
            .await;
    }
    // Drop the last sender to close the channel and signal workers to exit
    drop(state.backup_task_sender);
    info!("Backup task sender has exited");

    // Wait for all workers to finish
    for handle in worker_handles {
        let _ = handle.await;
    }
    info!("Backup workers have exited");

    // Give time for final logs to flush
    let _ = std::io::stdout().flush();
    std::thread::sleep(std::time::Duration::from_millis(200));
}
