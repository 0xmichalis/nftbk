use axum::http::{header, StatusCode};
use axum::middleware;
use axum::middleware::Next;
use axum::{
    extract::{Request, State},
    response::IntoResponse,
    routing::{delete, get, post},
    Router,
};
use clap::Parser;
use dotenv::dotenv;
use std::env;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{error, info};

use nftbk::envvar::is_defined;
use nftbk::logging;
use nftbk::logging::LogLevel;
use nftbk::server::handlers::handle_backup::handle_backup;
use nftbk::server::handlers::handle_backup_delete::handle_backup_delete;
use nftbk::server::handlers::handle_backup_retry::handle_backup_retry;
use nftbk::server::handlers::handle_backups::handle_backups;
use nftbk::server::handlers::handle_download::{handle_download, handle_download_token};
use nftbk::server::handlers::handle_status::handle_status;
use nftbk::server::privy::verify_privy_jwt;
use nftbk::server::pruner::run_pruner;
use nftbk::server::{recover_incomplete_jobs, run_backup_job, AppState, BackupJobOrShutdown};

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

    /// Number of backup worker threads to run in parallel
    #[arg(long, default_value_t = 4)]
    backup_parallelism: usize,

    /// Maximum number of backup jobs to queue before blocking
    #[arg(long, default_value_t = 10000)]
    backup_queue_size: usize,
}

#[derive(Clone)]
struct AuthState {
    app_state: AppState,
    privy_verification_key: Option<String>,
    privy_app_id: Option<String>,
}

fn spawn_backup_workers(
    parallelism: usize,
    backup_job_receiver: mpsc::Receiver<BackupJobOrShutdown>,
    state: AppState,
) -> Vec<JoinHandle<()>> {
    let mut worker_handles = Vec::with_capacity(parallelism);
    let backup_job_receiver = Arc::new(tokio::sync::Mutex::new(backup_job_receiver));
    for i in 0..parallelism {
        let backup_job_receiver = backup_job_receiver.clone();
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            info!("Worker {} started", i);
            loop {
                let job = {
                    let mut rx = backup_job_receiver.lock().await;
                    rx.recv().await
                };
                match job {
                    Some(BackupJobOrShutdown::Job(job)) => {
                        run_backup_job(
                            state_clone.clone(),
                            job.task_id,
                            job.tokens,
                            job.force,
                            job.archive_format,
                        )
                        .await;
                    }
                    Some(BackupJobOrShutdown::Shutdown) | None => break,
                }
            }
            info!("Worker {} stopped", i);
        });
        worker_handles.push(handle);
    }
    worker_handles
}

async fn auth_middleware(
    State(auth_state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    let state = &auth_state.app_state;
    let privy_app_id = &auth_state.privy_app_id;
    let privy_verification_key = &auth_state.privy_verification_key;

    // 1. Try symmetric token auth
    if let Some(ref token) = state.auth_token {
        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let expected = format!("Bearer {token}");
        if let Some(auth_header) = auth_header {
            if auth_header
                .as_bytes()
                .ct_eq(expected.as_bytes())
                .unwrap_u8()
                == 1
            {
                req.extensions_mut().insert(Some("admin".to_string()));
                return next.run(req).await;
            }
        }
    }

    // 2. Try Privy JWT auth
    if let (Some(app_id), Some(verification_key)) =
        (privy_app_id.as_ref(), privy_verification_key.as_ref())
    {
        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        if let Some(header_value) = auth_header {
            if let Some(jwt) = header_value.strip_prefix("Bearer ") {
                match verify_privy_jwt(jwt, verification_key, app_id).await {
                    Ok(claims) => {
                        req.extensions_mut().insert(Some(claims.sub.clone()));
                        return next.run(req).await;
                    }
                    Err(e) => {
                        tracing::warn!("Privy JWT verification failed: {}", e);
                    }
                }
            }
        }
    }

    // 3. If both fail, return 401
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        "Unauthorized",
    )
        .into_response()
}

#[tokio::main]
async fn main() {
    // We are consuming config both from the environment and from the command line
    dotenv().ok();
    let args = Args::parse();
    logging::init(args.log_level.clone());
    let auth_token = env::var("NFTBK_AUTH_TOKEN").ok();
    let privy_app_id = env::var("PRIVY_APP_ID").ok();
    let privy_verification_key = env::var("PRIVY_VERIFICATION_KEY")
        .ok()
        .map(|s| s.replace("\\n", "\n"));

    let (backup_job_sender, backup_job_receiver) =
        mpsc::channel::<BackupJobOrShutdown>(args.backup_queue_size);
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
        backup_job_sender.clone(),
        &db_url,
        (args.backup_queue_size + 1) as u32,
        shutdown_flag.clone(),
    )
    .await;

    info!("Starting server with options: {:?}", args);
    info!(
        "Symmetric authentication enabled: {}",
        is_defined(&auth_token)
    );
    info!(
        "Privy JWT authentication enabled: {}",
        is_defined(&privy_app_id) && is_defined(&privy_verification_key)
    );

    // Spawn worker pool for backup jobs
    let worker_handles =
        spawn_backup_workers(args.backup_parallelism, backup_job_receiver, state.clone());

    // Recover incomplete backup jobs from previous server runs
    match recover_incomplete_jobs(&state).await {
        Ok(count) => {
            if count > 0 {
                info!("Successfully recovered {} incomplete backup jobs", count);
            }
        }
        Err(e) => {
            error!("Failed to recover incomplete backup jobs: {}", e);
            // Don't exit the server, just log the error and continue
        }
    }

    // Create the public router (no auth middleware)
    let public_router = Router::new()
        .route("/backup/:task_id/download", get(handle_download))
        .with_state(state.clone());

    // Create the authenticated router (all other routes)
    let mut authed_router = Router::new()
        .route("/backup", post(handle_backup))
        .route("/backup/:task_id/status", get(handle_status))
        .route(
            "/backup/:task_id/download_token",
            get(handle_download_token),
        )
        .route("/backup/:task_id/retry", post(handle_backup_retry))
        .route("/backup/:task_id", delete(handle_backup_delete))
        .route("/backups", get(handle_backups))
        .with_state(state.clone());

    // Add auth middleware to authenticated router
    let auth_state = AuthState {
        app_state: state.clone(),
        privy_verification_key,
        privy_app_id,
    };
    if is_defined(&auth_token) || is_defined(&auth_state.privy_verification_key) {
        authed_router =
            authed_router.layer(middleware::from_fn_with_state(auth_state, auth_middleware));
    }

    // Merge routers
    let app = public_router.merge(authed_router);

    // Start the pruner thread
    let pruner_handle = if args.enable_pruner {
        let db = state.db.clone();
        let base_dir = args.base_dir.clone();
        let interval = args.pruner_interval_seconds;
        let shutdown_flag = state.shutdown_flag.clone();
        Some(tokio::spawn(async move {
            run_pruner(db, base_dir, interval, shutdown_flag).await;
        }))
    } else {
        None
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

    // On shutdown, send one Shutdown message per worker
    for _ in 0..args.backup_parallelism {
        let _ = state
            .backup_job_sender
            .send(BackupJobOrShutdown::Shutdown)
            .await;
    }
    // Drop the last sender to close the channel and signal workers to exit
    drop(state.backup_job_sender);
    info!("Backup job sender has exited");

    // Wait for all workers to finish
    for handle in worker_handles {
        let _ = handle.await;
    }
    info!("Backup workers have exited");

    // Give time for final logs to flush
    let _ = std::io::stdout().flush();
    std::thread::sleep(std::time::Duration::from_millis(200));
}
