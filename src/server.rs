use axum::http::{header, HeaderMap, StatusCode};
use axum::{
    body::Body,
    extract::{Path, State},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use flate2::write::GzEncoder;
use flate2::Compression;
use nftbk::backup::{self, BackupConfig, ChainConfig, TokenConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::File;
use tokio::sync::Mutex;
use tokio_util::io::ReaderStream;
use tracing::{info, Level};

#[derive(Debug, Deserialize, Clone)]
struct ChainTokens {
    chain: String,
    tokens: Vec<String>,
}

type BackupRequest = Vec<ChainTokens>;

#[derive(Debug, Serialize)]
struct BackupResponse {
    task_id: String,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    status: String,
    error: Option<String>,
}

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
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    listen: String,

    /// Path to the NFT chains configuration file (default: config_chains.toml)
    #[arg(short = 'c', long, default_value = "config_chains.toml")]
    chain_config: String,

    /// Base directory for backups (default: /tmp)
    #[arg(long, default_value = "/tmp")]
    base_dir: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();
    let args = Args::parse();
    let state = AppState::new(&args.chain_config, &args.base_dir).await;
    let app = Router::new()
        .route("/backup", post(submit_backup))
        .route("/backup/:task_id/status", get(get_status))
        .route("/backup/:task_id/download", get(download_zip))
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

async fn submit_backup(
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
    if let Some(_task) = tasks.get(&task_id) {
        info!("Duplicate backup request, returning existing task_id");
        return Json(BackupResponse { task_id }).into_response();
    }
    // Insert as pending
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
    let req_clone = req.clone();
    let task_id_clone = task_id.clone();
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(run_backup_job(
            state_clone,
            task_id_clone,
            req_clone,
        ))
    });
    info!("Started backup task {}", task_id);
    Json(BackupResponse { task_id }).into_response()
}

async fn run_backup_job(state: AppState, task_id: String, req: BackupRequest) {
    // Build TokenConfig from request
    let mut token_map = std::collections::HashMap::new();
    for entry in req {
        token_map.insert(entry.chain, entry.tokens);
    }
    let token_config = TokenConfig { chains: token_map };
    // Prepare output dir
    let out_dir = format!("{}/nftbk-{}", state.base_dir, task_id);
    let out_path = PathBuf::from(&out_dir);
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
        let mut tasks = state.tasks.lock().await;
        if let Some(task) = tasks.get_mut(&task_id) {
            task.status = TaskStatus::Error(format!("Backup failed: {}", e));
        }
        return;
    }
    // Zip the output dir
    let zip_path = format!("{}/{}.tar.gz", state.base_dir, task_id);
    let tar_gz = std::fs::File::create(&zip_path);
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
    if let Err(e) = tar.append_dir_all("nft_backup", &out_path) {
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
    // Update task
    let mut tasks = state.tasks.lock().await;
    if let Some(task) = tasks.get_mut(&task_id) {
        task.status = TaskStatus::Done;
        task.zip_path = Some(PathBuf::from(&zip_path));
    }
}

async fn get_status(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> Result<Json<StatusResponse>, axum::http::StatusCode> {
    let tasks = state.tasks.lock().await;
    let Some(task) = tasks.get(&task_id) else {
        return Err(axum::http::StatusCode::NOT_FOUND);
    };
    let (status, error) = match &task.status {
        TaskStatus::InProgress => ("in_progress", None),
        TaskStatus::Done => ("done", None),
        TaskStatus::Error(e) => ("error", Some(e.clone())),
    };
    Ok(Json(StatusResponse {
        status: status.to_string(),
        error,
    }))
}

async fn download_zip(
    State(state): State<AppState>,
    Path(task_id): Path<String>,
) -> impl IntoResponse {
    let tasks = state.tasks.lock().await;
    let Some(task) = tasks.get(&task_id) else {
        return (StatusCode::NOT_FOUND, Body::from("Task not found")).into_response();
    };
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
