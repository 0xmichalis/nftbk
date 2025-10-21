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

use nftbk::config::{load_and_validate_config, Config};
use nftbk::envvar::is_defined;
use nftbk::logging;
use nftbk::logging::LogLevel;
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

    /// The path to the configuration file
    #[arg(short = 'c', long, default_value = "config.toml")]
    config: String,

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
}

#[tokio::main]
async fn main() {
    // We are consuming config both from the environment and from the command line
    dotenv().ok();
    let args = Args::parse();
    logging::init(args.log_level, !args.no_color);
    info!(
        "Version: {} {} (commit {})",
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("GIT_COMMIT")
    );
    info!("Initializing server with options: {:?}", args);

    // Load unified configuration
    let auth_token = env::var("NFTBK_AUTH_TOKEN").ok();
    info!(
        "Symmetric authentication enabled: {}",
        is_defined(&auth_token)
    );

    let Config {
        chain_config,
        jwt_credentials,
        x402_config,
        ipfs_pinning_configs,
    } = match load_and_validate_config(&args.config) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load and validate config: {}", e);
            std::process::exit(1);
        }
    };

    let (backup_task_sender, backup_task_receiver) =
        mpsc::channel::<BackupTaskOrShutdown>(args.backup_queue_size);
    let db_url =
        std::env::var("DATABASE_URL").expect("DATABASE_URL env var must be set for Postgres");
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let state = AppState::new(
        chain_config,
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
