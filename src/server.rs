use axum::http::{header, HeaderMap, StatusCode};
use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use dotenv::dotenv;
use flate2::write::GzEncoder;
use flate2::Compression;
use nftbk::api::{BackupRequest, BackupResponse, StatusResponse};
use nftbk::backup::{self, BackupConfig, ChainConfig, TokenConfig};
use nftbk::logging::{self, LogLevel};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs::File;
use tokio::sync::Mutex;
use tokio_util::io::ReaderStream;
use tracing::{debug, error, info, warn};

#[allow(dead_code)]
#[derive(Debug, Clone)]
enum TaskStatus {
    InProgress,
    Done,
    Error(String),
}

#[derive(Debug, Clone)]
struct TaskInfo {
    status: TaskStatus,
    #[allow(dead_code)]
    tokens: Vec<String>,
    zip_path: Option<PathBuf>,
}

type TaskMap = Arc<Mutex<HashMap<String, TaskInfo>>>;

#[derive(Clone)]
struct AppState {
    tasks: TaskMap,
    chain_config: Arc<ChainConfig>,
    base_dir: Arc<String>,
}

impl Default for AppState {
    fn default() -> Self {
        panic!("AppState::default() should not be used; use AppState::new() instead");
    }
}

impl AppState {
    async fn new(chain_config_path: &str, base_dir: &str) -> Self {
        let config_content = tokio::fs::read_to_string(chain_config_path)
            .await
            .expect("Failed to read chain config");
        let chains: std::collections::HashMap<String, String> =
            toml::from_str(&config_content).expect("Failed to parse chain config");
        let chain_config = ChainConfig(chains);
        AppState {
            tasks: Arc::new(Mutex::new(HashMap::new())),
            chain_config: Arc::new(chain_config),
            base_dir: Arc::new(base_dir.to_string()),
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Address to listen on (default: 127.0.0.1:8080)
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,

    /// Path to the NFT chains configuration file (default: config_chains.toml)
    #[arg(short = 'c', long, default_value = "config_chains.toml")]
    chain_config: String,

    /// Base directory for backups (default: /tmp)
    #[arg(long, default_value = "/tmp")]
    base_dir: String,

    #[arg(short, long, value_enum, default_value = "info")]
    log_level: LogLevel,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    let args = Args::parse();
    logging::init(args.log_level);
    let state = AppState::new(&args.chain_config, &args.base_dir).await;
    let app = Router::new()
        .route("/backup", post(handle_backup))
        .route("/backup/:task_id/status", get(handle_status))
        .route("/backup/:task_id/download", get(handle_download))
        .with_state(state);
    let addr: SocketAddr = args.listen.parse().expect("Invalid listen address");
    info!("Listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

fn compute_task_id(tokens: &[String]) -> String {
    let mut hasher = Sha256::new();
    let mut sorted = tokens.to_vec();
    sorted.sort();
    for token in &sorted {
        hasher.update(token.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

async fn handle_backup(
    State(state): State<AppState>,
    Json(req): Json<BackupRequest>,
) -> impl IntoResponse {
    // Validate requested chains
    let configured_chains: std::collections::HashSet<_> =
        state.chain_config.0.keys().cloned().collect();
    let mut unknown_chains = Vec::new();
    for entry in &req {
        if !configured_chains.contains(&entry.chain) {
            unknown_chains.push(entry.chain.clone());
        }
    }
    if !unknown_chains.is_empty() {
        let msg = format!("Unknown chains requested: {}", unknown_chains.join(", "));
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response();
    }
    // Flatten all tokens for task_id computation
    let mut all_tokens = Vec::new();
    for entry in &req {
        all_tokens.extend(entry.tokens.iter().cloned());
    }
    let task_id = compute_task_id(&all_tokens);
    let mut tasks = state.tasks.lock().await;

    // Check if task exists and its status
    if let Some(task) = tasks.get(&task_id) {
        match &task.status {
            TaskStatus::InProgress => {
                info!(
                    "Duplicate backup request, returning existing task_id {}",
                    task_id
                );
                return Json(BackupResponse { task_id }).into_response();
            }
            TaskStatus::Done => {
                info!(
                    "Backup already completed, returning existing task_id {}",
                    task_id
                );
                return Json(BackupResponse { task_id }).into_response();
            }
            TaskStatus::Error(e) => {
                info!("Previous backup failed for task {}: {}", task_id, e);
                info!("Rerunning backup task {}", task_id);
            }
        }
    }

    // Insert/update as pending
    tasks.insert(
        task_id.clone(),
        TaskInfo {
            status: TaskStatus::InProgress,
            tokens: all_tokens.clone(),
            zip_path: None,
        },
    );
    drop(tasks); // Release lock before spawning

    // Spawn background job
    let state_clone = state.clone();
    let task_id_clone = task_id.clone();
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(run_backup_job(state_clone, task_id_clone, req))
    });

    info!("Started backup task {}", task_id);
    Json(BackupResponse { task_id }).into_response()
}

/// Helper function to compute SHA256 of a file
async fn compute_file_sha256(path: &Path) -> Result<String, std::io::Error> {
    let contents = tokio::fs::read(path).await?;
    let hash = Sha256::digest(&contents);
    Ok(format!("{:x}", hash))
}

/// Helper function to get backup archive and checksum paths for a given task
fn get_zipped_backup_paths(base_dir: &str, task_id: &str) -> (PathBuf, PathBuf) {
    let zip_path = PathBuf::from(format!("{}/nftbk-{}.tar.gz", base_dir, task_id));
    let checksum_path = zip_path.with_extension("sha256");
    (zip_path, checksum_path)
}

/// Helper function to check if a backup exists on disk and is not corrupted
async fn check_backup_on_disk(base_dir: &str, task_id: &str) -> Option<PathBuf> {
    let (path, checksum_path) = get_zipped_backup_paths(base_dir, task_id);

    // First check if both files exist
    match (
        tokio::fs::try_exists(&path).await,
        tokio::fs::try_exists(&checksum_path).await,
    ) {
        (Ok(true), Ok(true)) => {
            // Read stored checksum
            info!("Checking backup on disk for task {}", task_id);
            let stored_checksum = match tokio::fs::read_to_string(&checksum_path).await {
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

async fn run_backup_job(state: AppState, task_id: String, req: BackupRequest) {
    let out_dir = format!("{}/nftbk-{}", state.base_dir, task_id);
    let out_path = PathBuf::from(&out_dir);

    // First check if backup already exists on disk
    if let Some(zip_path) = check_backup_on_disk(&state.base_dir, &task_id).await {
        // Update task state to reflect the existing backup
        let mut tasks = state.tasks.lock().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.status = TaskStatus::Done;
            task.zip_path = Some(zip_path);
        }
        info!("Found existing backup for task {}", task_id);

        // Delete the unzipped directory to save space
        if let Err(e) = tokio::fs::remove_dir_all(&out_path).await {
            error!("Failed to delete unzipped directory: {}", e);
        }
        return;
    }

    // Build TokenConfig from request
    let mut token_map = std::collections::HashMap::new();
    for entry in req {
        token_map.insert(entry.chain, entry.tokens);
    }
    let token_config = TokenConfig { chains: token_map };
    // Prepare output dir
    if let Err(e) = tokio::fs::create_dir_all(&out_path).await {
        let mut tasks = state.tasks.lock().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.status = TaskStatus::Error(format!("Failed to create output dir: {}", e));
        }
        return;
    }
    // Run backup
    let backup_cfg = BackupConfig {
        chain_config: (*state.chain_config).clone(),
        token_config,
        output_path: Some(out_path.clone()),
        prune_missing: false,
    };
    let backup_result = backup::backup_from_config(backup_cfg).await;
    if let Err(e) = backup_result {
        error!("Backup {task_id} failed: {}", e);
        let mut tasks = state.tasks.lock().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.status = TaskStatus::Error(format!("Backup failed: {}", e));
        }
        return;
    }
    // Zip the output dir
    let (zip_pathbuf, checksum_path) = get_zipped_backup_paths(&state.base_dir, &task_id);
    let zip_path = zip_pathbuf.to_str().unwrap();
    info!("Zipping backup at {}", zip_path);
    let tar_gz = std::fs::File::create(zip_path);
    if let Err(e) = tar_gz {
        let mut tasks = state.tasks.lock().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.status = TaskStatus::Error(format!("Failed to create zip: {}", e));
        }
        return;
    }
    let tar_gz = tar_gz.unwrap();
    let enc = GzEncoder::new(tar_gz, Compression::default());
    let mut tar = tar::Builder::new(enc);
    if let Err(e) = tar.append_dir_all(".", &out_path) {
        let mut tasks = state.tasks.lock().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.status = TaskStatus::Error(format!("Failed to tar dir: {}", e));
        }
        return;
    }
    if let Err(e) = tar.into_inner().and_then(|enc| enc.finish()) {
        let mut tasks = state.tasks.lock().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.status = TaskStatus::Error(format!("Failed to finish zip: {}", e));
        }
        return;
    }
    // Update task and write checksum
    let mut tasks = state.tasks.lock().await;
    if let Some(task) = tasks.get_mut(&task_id) {
        match compute_file_sha256(&zip_pathbuf).await {
            Ok(checksum) => {
                if let Err(e) = tokio::fs::write(&checksum_path, checksum).await {
                    error!("Failed to write checksum file: {}", e);
                    task.status = TaskStatus::Error("Failed to write checksum file".to_string());
                    return;
                }
            }
            Err(e) => {
                error!("Failed to compute checksum: {}", e);
                task.status = TaskStatus::Error("Failed to compute checksum".to_string());
                return;
            }
        }
        task.status = TaskStatus::Done;
        task.zip_path = Some(zip_pathbuf);
    }
    info!("Backup {} ready", task_id);

    // Delete the unzipped directory to save space
    if let Err(e) = tokio::fs::remove_dir_all(&out_path).await {
        error!("Failed to delete unzipped directory: {}", e);
    }
}

async fn handle_status(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
) -> Result<Json<StatusResponse>, axum::http::StatusCode> {
    // First check in-memory state
    let tasks = state.tasks.lock().await;
    if let Some(task) = tasks.get(&task_id) {
        let (status, error) = match &task.status {
            TaskStatus::InProgress => ("in_progress", None),
            TaskStatus::Done => ("done", None),
            TaskStatus::Error(e) => ("error", Some(e.clone())),
        };
        return Ok(Json(StatusResponse {
            status: status.to_string(),
            error,
        }));
    }

    // If not in memory, check if backup exists on disk
    if check_backup_on_disk(&state.base_dir, &task_id)
        .await
        .is_some()
    {
        return Ok(Json(StatusResponse {
            status: "done".to_string(),
            error: None,
        }));
    }

    Err(axum::http::StatusCode::NOT_FOUND)
}

async fn handle_download(
    State(state): State<AppState>,
    AxumPath(task_id): AxumPath<String>,
) -> impl IntoResponse {
    // First check in-memory state
    let tasks = state.tasks.lock().await;
    if let Some(task) = tasks.get(&task_id) {
        if !matches!(task.status, TaskStatus::Done) {
            return (StatusCode::ACCEPTED, Body::from("Task not completed yet")).into_response();
        }
        let Some(ref zip_path) = task.zip_path else {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from("No zip file found"),
            )
                .into_response();
        };
        return serve_zip_file(zip_path, &task_id).await;
    }
    drop(tasks);

    // If not in memory, check if backup exists on disk
    if let Some(zip_path) = check_backup_on_disk(&state.base_dir, &task_id).await {
        return serve_zip_file(&zip_path, &task_id).await;
    }

    (StatusCode::NOT_FOUND, Body::from("Task not found")).into_response()
}

/// Helper function to serve a zip file with proper headers
async fn serve_zip_file(zip_path: &PathBuf, task_id: &str) -> Response {
    let file = match File::open(zip_path).await {
        Ok(file) => file,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Body::from("Failed to open zip file"),
            )
                .into_response();
        }
    };
    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, "application/gzip".parse().unwrap());
    headers.insert(
        header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}.tar.gz\"", task_id)
            .parse()
            .unwrap(),
    );
    (StatusCode::OK, headers, body).into_response()
}
