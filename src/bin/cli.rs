use anyhow::{Context, Result};
use clap::Parser;
use dotenv::dotenv;
use flate2::read::GzDecoder;
use prettytable::{row, Table};
use reqwest::Client;
use std::env;
use std::fs::File;
use std::io::Cursor;
use std::path::PathBuf;
use tar::Archive;
use tokio::fs;
use tracing::{debug, error, warn};
use zip::ZipArchive;

use nftbk::backup::{backup_from_config, BackupConfig, ChainConfig, TokenConfig};
use nftbk::envvar::is_defined;
use nftbk::logging;
use nftbk::logging::LogLevel;
use nftbk::server::api::{BackupRequest, BackupResponse, StatusResponse, Tokens};
use nftbk::server::archive::archive_format_from_user_agent;
use nftbk::{ProcessManagementConfig, StorageConfig};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The path to the chains configuration file
    #[arg(short = 'c', long, default_value = "config_chains.toml")]
    chains_config_path: PathBuf,

    /// The path to the tokens configuration file
    #[arg(short = 't', long, default_value = "config_tokens.toml")]
    tokens_config_path: PathBuf,

    /// The directory to save the backup to
    #[arg(short, long, default_value = "nft_backup")]
    output_path: Option<PathBuf>,

    /// Set the log level
    #[arg(short, long, value_enum, default_value = "info")]
    log_level: LogLevel,

    /// Delete redundant files in the backup folder
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    prune_redundant: bool,

    /// Request a backup from the server instead of running locally
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    server_mode: bool,

    /// The server address to request backups from
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server_address: String,

    /// Exit on the first error encountered
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    exit_on_error: bool,

    /// IPFS pinning service base URL (enables IPFS pinning when provided)
    #[arg(long)]
    ipfs_pin_url: Option<String>,

    /// Force rerunning a completed backup task
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    force: bool,

    /// List existing backups in the server
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    list: bool,

    /// User-Agent to send to the server (affects archive format)
    #[arg(long, default_value = "Linux")]
    user_agent: String,

    /// Disable colored log output
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    no_color: bool,
}

enum BackupStart {
    Created(BackupResponse),
    Conflict {
        task_id: String,
        retry_url: String,
        message: String,
    },
}

async fn backup_from_server(
    token_config: TokenConfig,
    server_address: String,
    output_path: Option<PathBuf>,
    force: bool,
    user_agent: String,
) -> Result<()> {
    let auth_token = env::var("NFTBK_AUTH_TOKEN").ok();
    let client = Client::new();

    // First, try to create the backup
    let start = request_backup(
        &token_config,
        &server_address,
        &client,
        auth_token.as_deref(),
        &user_agent,
    )
    .await?;

    let task_id = match start {
        BackupStart::Created(resp) => {
            let task_id = resp.task_id.clone();
            println!("Task ID: {task_id}");
            task_id
        }
        BackupStart::Conflict {
            task_id,
            retry_url,
            message,
        } => {
            println!("Task ID: {task_id}");
            if force {
                println!("Server response: {message}");
                let server = server_address.trim_end_matches('/');
                println!("Retrying via {server}{retry_url} ...");
                retry_backup(
                    &client,
                    &server_address,
                    &retry_url,
                    &task_id,
                    auth_token.as_deref(),
                )
                .await?;
                task_id
            } else {
                anyhow::bail!(
                    "{}\nRun the CLI with --force true, or POST to {}{}",
                    message,
                    server_address.trim_end_matches('/'),
                    retry_url
                );
            }
        }
    };

    wait_for_done_backup(&client, &server_address, &task_id, auth_token.as_deref()).await?;

    return download_backup(
        &client,
        &server_address,
        &task_id,
        output_path.as_ref(),
        auth_token.as_deref(),
        &archive_format_from_user_agent(&user_agent),
    )
    .await;
}

async fn request_backup(
    token_config: &TokenConfig,
    server_address: &str,
    client: &Client,
    auth_token: Option<&str>,
    user_agent: &str,
) -> Result<BackupStart> {
    let mut backup_req = BackupRequest { tokens: Vec::new() };
    for (chain, tokens) in &token_config.chains {
        backup_req.tokens.push(Tokens {
            chain: chain.clone(),
            tokens: tokens.clone(),
        });
    }

    let server = server_address.trim_end_matches('/');
    println!("Submitting backup request to server at {server}/backup ...",);
    let mut req = client.post(format!("{server}/backup")).json(&backup_req);
    req = req.header("User-Agent", user_agent);
    if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
        req = req.header("Authorization", format!("Bearer {}", auth_token.unwrap()));
    }
    let resp = req
        .send()
        .await
        .context("Failed to send backup request to server")?;
    let status = resp.status();
    if status.is_success() {
        let backup_resp: BackupResponse = resp.json().await.context("Invalid server response")?;
        return Ok(BackupStart::Created(backup_resp));
    }
    if status.as_u16() == 409 {
        let body: serde_json::Value = resp
            .json()
            .await
            .context("Invalid conflict response from server")?;
        let task_id = body
            .get("task_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let retry_url = body
            .get("retry_url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let message = body
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("Server returned conflict for /backup")
            .to_string();
        return Ok(BackupStart::Conflict {
            task_id,
            retry_url,
            message,
        });
    }
    let text = resp.text().await.unwrap_or_default();
    anyhow::bail!("Server error: {}", text);
}

async fn retry_backup(
    client: &Client,
    server_address: &str,
    retry_url: &str,
    task_id: &str,
    auth_token: Option<&str>,
) -> Result<BackupResponse> {
    let server = server_address.trim_end_matches('/');
    let full_url = format!("{server}{retry_url}");
    println!("Retrying backup task {task_id} at {full_url} ...");
    let mut req = client.post(full_url);
    if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
        req = req.header("Authorization", format!("Bearer {}", auth_token.unwrap()));
    }
    let resp = req
        .send()
        .await
        .context("Failed to send retry request to server")?;
    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Server error during retry: {}", text);
    }
    let backup_resp: BackupResponse = resp
        .json()
        .await
        .context("Invalid server response during retry")?;
    Ok(backup_resp)
}

async fn wait_for_done_backup(
    client: &reqwest::Client,
    server_address: &str,
    task_id: &str,
    auth_token: Option<&str>,
) -> Result<()> {
    let status_url = format!(
        "{}/backup/{}/status",
        server_address.trim_end_matches('/'),
        task_id
    );
    let mut in_progress_logged = false;
    loop {
        let mut req = client.get(&status_url);
        if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
            req = req.header("Authorization", format!("Bearer {}", auth_token.unwrap()));
        }
        let resp = req.send().await;
        match resp {
            Ok(r) => {
                if r.status().is_success() {
                    let status: StatusResponse = r.json().await.unwrap_or(StatusResponse {
                        status: "error".to_string(),
                        error: Some("Invalid status response".to_string()),
                        error_log: None,
                    });
                    match status.status.as_str() {
                        "in_progress" => {
                            if !in_progress_logged {
                                println!("Waiting for backup to complete...");
                                in_progress_logged = true;
                            }
                        }
                        "done" => {
                            println!("Backup complete.");
                            if let Some(error_log) = &status.error_log {
                                if !error_log.is_empty() {
                                    warn!("{}", error_log);
                                }
                            }
                            break;
                        }
                        "error" => {
                            anyhow::bail!("Server error: {}", status.error.unwrap_or_default());
                        }
                        _ => {
                            println!("Unknown status: {}", status.status);
                        }
                    }
                } else {
                    println!("Failed to get status: {}", r.status());
                }
            }
            Err(e) => {
                println!("Error polling status: {e}");
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
    Ok(())
}

async fn download_backup(
    client: &Client,
    server_address: &str,
    task_id: &str,
    output_path: Option<&PathBuf>,
    _auth_token: Option<&str>,
    archive_format: &str,
) -> Result<()> {
    // Step 1: Get download token
    let token_url = format!(
        "{}/backup/{}/download_token",
        server_address.trim_end_matches('/'),
        task_id
    );
    let mut token_req = client.get(&token_url);
    if is_defined(&_auth_token.as_ref().map(|s| s.to_string())) {
        token_req = token_req.header("Authorization", format!("Bearer {}", _auth_token.unwrap()));
    }
    let token_resp = token_req
        .send()
        .await
        .context("Failed to get download token")?;
    if !token_resp.status().is_success() {
        anyhow::bail!("Failed to get download token: {}", token_resp.status());
    }
    let token_json: serde_json::Value =
        token_resp.json().await.context("Invalid token response")?;
    let download_token = token_json
        .get("token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("No token in response"))?;

    // Step 2: Download using token
    let download_url = format!(
        "{}/backup/{}/download?token={}",
        server_address.trim_end_matches('/'),
        task_id,
        urlencoding::encode(download_token)
    );
    println!("Downloading archive ...");
    let resp = client
        .get(&download_url)
        .send()
        .await
        .context("Failed to download archive")?;
    if !resp.status().is_success() {
        anyhow::bail!("Failed to download archive: {}", resp.status());
    }
    let bytes = resp.bytes().await.context("Failed to read archive bytes")?;
    let output_path = output_path.cloned().unwrap_or_else(|| PathBuf::from("."));

    println!("Extracting backup to {}...", output_path.display());
    match archive_format {
        "tar.gz" => {
            let gz = GzDecoder::new(Cursor::new(bytes));
            let mut archive = Archive::new(gz);
            archive
                .unpack(&output_path)
                .context("Failed to extract backup archive (tar.gz)")?;
        }
        "zip" => {
            let mut zip =
                ZipArchive::new(Cursor::new(bytes)).context("Failed to read zip archive")?;
            for i in 0..zip.len() {
                let mut file = zip.by_index(i).context("Failed to access file in zip")?;
                let outpath = match file.enclosed_name() {
                    Some(path) => output_path.join(path),
                    None => continue,
                };
                if file.name().ends_with('/') {
                    std::fs::create_dir_all(&outpath)
                        .context("Failed to create directory from zip")?;
                } else {
                    if let Some(p) = outpath.parent() {
                        std::fs::create_dir_all(p)
                            .context("Failed to create parent directory for zip file")?;
                    }
                    let mut outfile =
                        File::create(&outpath).context("Failed to create file from zip")?;
                    std::io::copy(&mut file, &mut outfile)
                        .context("Failed to extract file from zip")?;
                }
            }
        }
        _ => anyhow::bail!("Unknown archive format: {archive_format}"),
    }
    println!("Backup extracted to {}", output_path.display());
    Ok(())
}

async fn list_server_backups(server_address: &str) -> Result<()> {
    let auth_token = env::var("NFTBK_AUTH_TOKEN").ok();
    let client = Client::new();
    let url = format!("{}/backups", server_address.trim_end_matches('/'));
    let mut req = client.get(&url);
    if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
        req = req.header(
            "Authorization",
            format!("Bearer {}", auth_token.as_deref().unwrap()),
        );
    }
    let resp = req
        .send()
        .await
        .context("Failed to fetch backups from server")?;
    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Server error: {}", text);
    }
    let backups: serde_json::Value = resp.json().await.context("Invalid server response")?;
    let arr = backups
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Expected array response"))?;
    let mut table = Table::new();
    table.add_row(row!["Task ID", "Status", "Error", "Error Log", "NFT Count"]);
    for entry in arr {
        let task_id = entry.get("task_id").and_then(|v| v.as_str()).unwrap_or("");
        let status = entry.get("status").and_then(|v| v.as_str()).unwrap_or("");
        let error = entry.get("error").and_then(|v| v.as_str()).unwrap_or("");
        let error_log = entry
            .get("error_log")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let nft_count = entry.get("nft_count").and_then(|v| v.as_u64()).unwrap_or(0);
        table.add_row(row![task_id, status, error, error_log, nft_count]);
    }
    table.printstd();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let args = Args::parse();
    logging::init(args.log_level, !args.no_color);
    debug!(
        "Starting {} {} (commit {})",
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("GIT_COMMIT")
    );

    if args.server_mode && args.list {
        return list_server_backups(&args.server_address).await;
    }

    let tokens_content = fs::read_to_string(&args.tokens_config_path)
        .await
        .context("Failed to read tokens config file")?;
    let token_config: TokenConfig =
        toml::from_str(&tokens_content).context("Failed to parse tokens config file")?;

    if args.server_mode {
        return backup_from_server(
            token_config,
            args.server_address,
            args.output_path,
            args.force,
            args.user_agent,
        )
        .await;
    }

    let chains_content = fs::read_to_string(&args.chains_config_path)
        .await
        .context("Failed to read chains config file")?;
    let mut chain_config: ChainConfig =
        toml::from_str(&chains_content).context("Failed to parse chains config file")?;
    chain_config.resolve_env_vars()?;

    // Get IPFS pin token from environment variable if IPFS URL is provided
    let ipfs_pin_token = if args.ipfs_pin_url.is_some() {
        std::env::var("IPFS_PIN_TOKEN").ok()
    } else {
        None
    };

    let output_path = args.output_path.clone();
    let backup_config = BackupConfig {
        chain_config,
        token_config,
        storage_config: StorageConfig {
            output_path: output_path.clone(),
            prune_redundant: args.prune_redundant,
            enable_ipfs_pinning: args.ipfs_pin_url.is_some(),
            ipfs_pin_base_url: args.ipfs_pin_url,
            ipfs_pin_token,
        },
        process_config: ProcessManagementConfig {
            exit_on_error: args.exit_on_error,
            shutdown_flag: None,
        },
    };
    let (_files, _pins, error_log) = backup_from_config(backup_config, None).await?;
    // Write error log to file if present
    if !error_log.is_empty() {
        if let Some(ref out_path) = output_path {
            let mut log_path = out_path.clone();
            log_path.set_extension("log");
            let log_content = error_log.join("\n") + "\n";
            use tokio::io::AsyncWriteExt;
            let mut file = tokio::fs::File::create(&log_path).await?;
            file.write_all(log_content.as_bytes()).await?;
            error!("Error log written to {}", log_path.display());
        }
    }
    Ok(())
}
