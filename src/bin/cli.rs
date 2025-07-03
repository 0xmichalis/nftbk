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
use tracing::warn;
use zip::ZipArchive;

use nftbk::api::{BackupRequest, BackupResponse, StatusResponse, Tokens};
use nftbk::backup::{backup_from_config, BackupConfig, ChainConfig, TokenConfig};
use nftbk::envvar::is_defined;
use nftbk::logging;
use nftbk::logging::LogLevel;
use nftbk::server::archive::archive_format_from_user_agent;

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

    /// Force rerunning a completed backup task
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    force: bool,

    /// List existing backups in the server
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    list: bool,

    /// User-Agent to send to the server (affects archive format)
    #[arg(long, default_value = "Linux")]
    user_agent: String,
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
    let backup_resp = request_backup(
        &token_config,
        &server_address,
        &client,
        force,
        auth_token.as_deref(),
        &user_agent,
    )
    .await?;
    println!("Task ID: {}", backup_resp.task_id);

    wait_for_done_backup(
        &client,
        &server_address,
        &backup_resp.task_id,
        auth_token.as_deref(),
    )
    .await?;

    fetch_error_log(&server_address, &backup_resp.task_id, auth_token.as_deref()).await?;

    return download_backup(
        &client,
        &server_address,
        &backup_resp.task_id,
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
    force: bool,
    auth_token: Option<&str>,
    user_agent: &str,
) -> Result<BackupResponse> {
    let mut backup_req = BackupRequest {
        tokens: Vec::new(),
        force: Some(force),
    };
    for (chain, tokens) in &token_config.chains {
        backup_req.tokens.push(Tokens {
            chain: chain.clone(),
            tokens: tokens.clone(),
        });
    }

    let server = server_address.trim_end_matches('/');
    println!(
        "Submitting backup request to server at {}/backup ...",
        server
    );
    let mut req = client.post(format!("{}/backup", server)).json(&backup_req);
    req = req.header("User-Agent", user_agent);
    if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
        req = req.header("Authorization", format!("Bearer {}", auth_token.unwrap()));
    }
    let resp = req
        .send()
        .await
        .context("Failed to send backup request to server")?;
    if !resp.status().is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("Server error: {}", text);
    }
    let backup_resp: BackupResponse = resp.json().await.context("Invalid server response")?;
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
                println!("Error polling status: {}", e);
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    }
    Ok(())
}

async fn fetch_error_log(
    server_address: &str,
    task_id: &str,
    auth_token: Option<&str>,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!(
        "{}/backup/{}/error_log",
        server_address.trim_end_matches('/'),
        task_id
    );
    let mut req = client.get(&url);
    if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
        req = req.header("Authorization", format!("Bearer {}", auth_token.unwrap()));
    }
    let resp = req.send().await?;
    if resp.status().is_success() {
        let text = resp.text().await?;
        warn!("{}", text);
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
        _ => anyhow::bail!("Unknown archive format: {}", archive_format),
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
    logging::init(args.log_level);

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

    let backup_config = BackupConfig {
        chain_config,
        token_config,
        output_path: args.output_path,
        prune_redundant: args.prune_redundant,
        exit_on_error: args.exit_on_error,
    };
    backup_from_config(backup_config).await?;
    Ok(())
}
