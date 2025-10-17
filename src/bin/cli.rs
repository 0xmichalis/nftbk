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
use nftbk::ipfs::IpfsPinningConfig;
use nftbk::logging;
use nftbk::logging::LogLevel;
use nftbk::server::api::{BackupCreateResponse, BackupRequest, BackupResponse, Tokens};
use nftbk::server::archive::archive_format_from_user_agent;
use nftbk::{ProcessManagementConfig, StorageConfig};

const BACKUPS_API_PATH: &str = "/v1/backups";

#[derive(serde::Deserialize)]
struct IpfsConfigFile {
    ipfs_pinning_provider: Vec<IpfsPinningConfig>,
}

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

    /// Disable colored log output
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    no_color: bool,

    /// Path to a TOML file with IPFS provider configuration
    #[arg(long)]
    ipfs_config: Option<String>,

    /// Request server to pin downloaded assets on IPFS
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    pin_on_ipfs: bool,
}

enum BackupStart {
    Created(BackupCreateResponse),
    Exists(BackupCreateResponse),
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
    pin_on_ipfs: bool,
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
        pin_on_ipfs,
    )
    .await?;

    let task_id = match start {
        BackupStart::Created(resp) => {
            let task_id = resp.task_id.clone();
            println!("Task ID: {task_id}");
            task_id
        }
        BackupStart::Exists(resp) => {
            let task_id = resp.task_id.clone();
            println!("Task ID (exists): {task_id}");
            if force {
                // Delete and re-request
                let _ =
                    delete_backup(&client, &server_address, &task_id, auth_token.as_deref()).await;
                let second_try = request_backup(
                    &token_config,
                    &server_address,
                    &client,
                    auth_token.as_deref(),
                    &user_agent,
                    pin_on_ipfs,
                )
                .await?;
                match second_try {
                    BackupStart::Created(resp2) | BackupStart::Exists(resp2) => {
                        let task_id2 = resp2.task_id.clone();
                        println!("Task ID (after delete): {task_id2}");
                        task_id2
                    }
                    BackupStart::Conflict {
                        message,
                        retry_url,
                        task_id: _,
                    } => {
                        anyhow::bail!(
                            "{}\nCould not create new task after delete. Try POST to {}{}",
                            message,
                            server_address.trim_end_matches('/'),
                            retry_url
                        );
                    }
                }
            } else {
                task_id
            }
        }
        BackupStart::Conflict {
            task_id,
            retry_url,
            message,
        } => {
            println!("Task ID: {task_id}");
            if force {
                println!("Server response: {message}");
                // Try to delete the existing task by task_id, then request again
                let _ =
                    delete_backup(&client, &server_address, &task_id, auth_token.as_deref()).await;
                let second_try = request_backup(
                    &token_config,
                    &server_address,
                    &client,
                    auth_token.as_deref(),
                    &user_agent,
                    pin_on_ipfs,
                )
                .await?;
                match second_try {
                    BackupStart::Created(resp2) | BackupStart::Exists(resp2) => {
                        let task_id2 = resp2.task_id.clone();
                        println!("Task ID (after delete): {task_id2}");
                        task_id2
                    }
                    BackupStart::Conflict {
                        message,
                        retry_url,
                        task_id: _,
                    } => {
                        anyhow::bail!(
                            "{}\nCould not create new task after delete. Try POST to {}{}",
                            message,
                            server_address.trim_end_matches('/'),
                            retry_url
                        );
                    }
                }
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
async fn delete_backup(
    client: &Client,
    server_address: &str,
    task_id: &str,
    auth_token: Option<&str>,
) -> Result<()> {
    let server = server_address.trim_end_matches('/');
    let url = format!("{server}{BACKUPS_API_PATH}/{task_id}",);
    let mut req = client.delete(url);
    if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
        req = req.header("Authorization", format!("Bearer {}", auth_token.unwrap()));
    }
    let resp = req
        .send()
        .await
        .context("Failed to send DELETE to server")?;

    match resp.status().as_u16() {
        202 => {
            println!("Deletion request sent for backup {task_id}, waiting for completion...");
            // Poll until backup is actually deleted (returns 404)
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let status_url = format!("{server}{BACKUPS_API_PATH}/{task_id}");
                let mut status_req = client.get(&status_url);
                if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
                    status_req = status_req
                        .header("Authorization", format!("Bearer {}", auth_token.unwrap()));
                }
                match status_req.send().await {
                    Ok(status_resp) => {
                        if status_resp.status().as_u16() == 404 {
                            println!("Backup {task_id} successfully deleted");
                            return Ok(());
                        }
                        // Still exists, continue polling
                    }
                    Err(_) => {
                        // Network error, continue polling
                    }
                }
            }
        }
        404 => {
            println!("Backup {task_id} already deleted");
            Ok(())
        }
        409 => {
            // In progress; proceed with new request anyway
            println!("Existing backup {task_id} is in progress; proceeding to create new request");
            Ok(())
        }
        code => {
            let text = resp.text().await.unwrap_or_default();
            println!("Warning: failed to delete existing backup ({code}): {text}");
            Ok(())
        }
    }
}

async fn request_backup(
    token_config: &TokenConfig,
    server_address: &str,
    client: &Client,
    auth_token: Option<&str>,
    user_agent: &str,
    pin_on_ipfs: bool,
) -> Result<BackupStart> {
    let mut backup_req = BackupRequest {
        tokens: Vec::new(),
        pin_on_ipfs,
        create_archive: true,
    };
    for (chain, tokens) in &token_config.chains {
        backup_req.tokens.push(Tokens {
            chain: chain.clone(),
            tokens: tokens.clone(),
        });
    }

    let server = server_address.trim_end_matches('/');
    println!("Submitting backup request to server at {server}{BACKUPS_API_PATH} ...");
    let mut req = client
        .post(format!("{server}{BACKUPS_API_PATH}"))
        .json(&backup_req);
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
        let backup_resp: BackupCreateResponse =
            resp.json().await.context("Invalid server response")?;
        if status.as_u16() == 201 {
            return Ok(BackupStart::Created(backup_resp));
        } else {
            return Ok(BackupStart::Exists(backup_resp));
        }
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
            .unwrap_or(&format!("Server returned conflict for {BACKUPS_API_PATH}"))
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

async fn wait_for_done_backup(
    client: &reqwest::Client,
    server_address: &str,
    task_id: &str,
    auth_token: Option<&str>,
) -> Result<()> {
    let status_url = format!(
        "{}{}/{}",
        server_address.trim_end_matches('/'),
        BACKUPS_API_PATH,
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
                    let status: BackupResponse = r.json().await.unwrap_or({
                        // Fallback shape with nulls
                        BackupResponse {
                            task_id: task_id.to_string(),
                            created_at: String::new(),
                            storage_mode: String::new(),
                            tokens: Vec::new(),
                            total_tokens: 0,
                            page: 1,
                            limit: 50,
                            archive: nftbk::server::api::Archive {
                                status: nftbk::server::api::SubresourceStatus {
                                    status: None,
                                    fatal_error: None,
                                    error_log: None,
                                    deleted_at: None,
                                },
                                format: None,
                                expires_at: None,
                            },
                            pins: nftbk::server::api::Pins {
                                status: nftbk::server::api::SubresourceStatus {
                                    status: None,
                                    fatal_error: None,
                                    error_log: None,
                                    deleted_at: None,
                                },
                            },
                        }
                    });
                    // Aggregate a coarse "overall" view for UX: in_progress if any subresource is in_progress
                    let archive_status = status.archive.status.status.as_deref();
                    let ipfs_status = status.pins.status.status.as_deref();
                    let any_in_progress = matches!(archive_status, Some("in_progress"))
                        || matches!(ipfs_status, Some("in_progress"));
                    let any_error = matches!(archive_status, Some("error"))
                        || matches!(ipfs_status, Some("error"))
                        || status.archive.status.fatal_error.is_some()
                        || status.pins.status.fatal_error.is_some();
                    let all_done = matches!(archive_status, Some("done"))
                        && (ipfs_status.is_none() || matches!(ipfs_status, Some("done")));
                    if any_in_progress {
                        if !in_progress_logged {
                            println!("Waiting for backup to complete...");
                            in_progress_logged = true;
                        }
                    } else if all_done {
                        println!("Backup complete.");
                        if let Some(ref a) = status.archive.status.error_log {
                            if !a.is_empty() {
                                warn!("{}", a);
                            }
                        }
                        if let Some(ref i) = status.pins.status.error_log {
                            if !i.is_empty() {
                                warn!("{}", i);
                            }
                        }
                        break;
                    } else if any_error {
                        let msg = status
                            .archive
                            .status
                            .fatal_error
                            .clone()
                            .or(status.pins.status.fatal_error.clone())
                            .unwrap_or_else(|| "Unknown error".to_string());
                        anyhow::bail!("Server error: {}", msg);
                    } else {
                        println!(
                            "Unknown status: archive={:?} ipfs={:?}",
                            status.archive.status.status, status.pins.status.status
                        );
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
        "{}{}/{}/download-tokens",
        server_address.trim_end_matches('/'),
        BACKUPS_API_PATH,
        task_id
    );
    let mut token_req = client.post(&token_url);
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
        "{}{}/{}/download?token={}",
        server_address.trim_end_matches('/'),
        BACKUPS_API_PATH,
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
    let url = format!(
        "{}{}",
        server_address.trim_end_matches('/'),
        BACKUPS_API_PATH
    );
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
    let arr: Vec<BackupResponse> = resp.json().await.context("Invalid server response")?;
    let mut table = Table::new();
    table.add_row(row!["Task ID", "Status", "Error", "Error Log", "NFT Count"]);
    for entry in arr {
        let task_id = entry.task_id.as_str();
        let archive_status = entry.archive.status.status.as_deref();
        let pins_status = entry.pins.status.status.as_deref();
        let any_in_progress = matches!(archive_status, Some("in_progress"))
            || matches!(pins_status, Some("in_progress"));
        let any_error = matches!(archive_status, Some("error"))
            || matches!(pins_status, Some("error"))
            || entry.archive.status.fatal_error.is_some()
            || entry.pins.status.fatal_error.is_some();
        let all_done = matches!(archive_status, Some("done"))
            && (pins_status.is_none() || matches!(pins_status, Some("done")));
        let status = if any_in_progress {
            "in_progress"
        } else if any_error {
            "error"
        } else if all_done {
            "done"
        } else {
            ""
        };
        let error = entry
            .archive
            .status
            .fatal_error
            .clone()
            .or(entry.pins.status.fatal_error.clone())
            .unwrap_or_default();
        let mut logs = Vec::new();
        if let Some(a) = entry.archive.status.error_log.as_ref() {
            if !a.is_empty() {
                logs.push(a.as_str());
            }
        }
        if let Some(i) = entry.pins.status.error_log.as_ref() {
            if !i.is_empty() {
                logs.push(i.as_str());
            }
        }
        let combined = logs.join(" | ");
        let nft_count = entry.total_tokens as u64;
        table.add_row(row![task_id, status, error, combined, nft_count]);
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
            args.pin_on_ipfs,
        )
        .await;
    }

    let chains_content = fs::read_to_string(&args.chains_config_path)
        .await
        .context("Failed to read chains config file")?;
    let mut chain_config: ChainConfig =
        toml::from_str(&chains_content).context("Failed to parse chains config file")?;
    chain_config.resolve_env_vars()?;

    // Load IPFS provider configuration from file if provided
    let ipfs_pinning_configs = if args.ipfs_config.is_none() {
        Vec::new()
    } else {
        let path = args.ipfs_config.as_ref().unwrap();
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read IPFS config file '{path}'"))?;
        let config: IpfsConfigFile = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse IPFS config file '{path}'"))?;
        config.ipfs_pinning_provider
    };

    let output_path = args.output_path.clone();
    let backup_config = BackupConfig {
        chain_config,
        token_config,
        storage_config: StorageConfig {
            output_path: output_path.clone(),
            prune_redundant: args.prune_redundant,
            ipfs_pinning_configs,
        },
        process_config: ProcessManagementConfig {
            exit_on_error: args.exit_on_error,
            shutdown_flag: None,
        },
        task_id: None, // CLI doesn't have a task ID
    };
    let (archive_out, ipfs_out) = backup_from_config(backup_config, None).await?;
    // Write combined error log to file if present
    let mut merged = Vec::new();
    if !archive_out.errors.is_empty() {
        merged.extend(archive_out.errors);
    }
    if !ipfs_out.errors.is_empty() {
        merged.extend(ipfs_out.errors);
    }
    if !merged.is_empty() {
        if let Some(ref out_path) = output_path {
            let mut log_path = out_path.clone();
            log_path.set_extension("log");
            let log_content = merged.join("\n") + "\n";
            use tokio::io::AsyncWriteExt;
            let mut file = tokio::fs::File::create(&log_path).await?;
            file.write_all(log_content.as_bytes()).await?;
            error!("Error log written to {}", log_path.display());
        }
    }
    Ok(())
}
