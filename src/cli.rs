use anyhow::{Context, Result};
use clap::Parser;
use dotenv::dotenv;
use flate2::read::GzDecoder;
use reqwest::Client;
use std::io::Cursor;
use std::path::PathBuf;
use tar::Archive;
use tokio::fs;
use tracing::warn;

use nftbk::api::{BackupResponse, ChainTokens, StatusResponse};
use nftbk::backup::{backup_from_config, BackupConfig, ChainConfig, TokenConfig};
use nftbk::logging;
use nftbk::logging::LogLevel;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The path to the chains configuration file
    #[arg(short = 'c', long, default_value = "config_chains.toml")]
    chains_config_path: PathBuf,

    /// The path to the tokens configuration file
    #[arg(short = 't', long, default_value = "config_tokens.toml")]
    tokens_config_path: PathBuf,

    /// The directory to save the backup to (defaults to current directory)
    #[arg(short, long)]
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
    server_addr: String,

    /// Exit on the first error encountered
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    exit_on_error: bool,
}

async fn backup_from_server(
    token_config: TokenConfig,
    server_addr: String,
    output_path: Option<PathBuf>,
) -> Result<()> {
    let client = Client::new();
    let backup_resp = request_backup(&token_config, &server_addr, &client).await?;
    println!("Task ID: {}", backup_resp.task_id);

    wait_for_done_backup(&client, &server_addr, &backup_resp.task_id).await?;

    fetch_error_log(&server_addr, &backup_resp.task_id).await?;

    return download_backup(
        &client,
        &server_addr,
        &backup_resp.task_id,
        output_path.as_ref(),
    )
    .await;
}

async fn request_backup(
    token_config: &TokenConfig,
    server_addr: &str,
    client: &Client,
) -> Result<BackupResponse> {
    let mut backup_req = Vec::new();
    for (chain, tokens) in &token_config.chains {
        backup_req.push(ChainTokens {
            chain: chain.clone(),
            tokens: tokens.clone(),
        });
    }

    let server = server_addr.trim_end_matches('/');
    println!(
        "Submitting backup request to server at {}/backup...",
        server
    );
    let resp = client
        .post(format!("{}/backup", server))
        .json(&backup_req)
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
    server_addr: &str,
    task_id: &str,
) -> Result<()> {
    let status_url = format!(
        "{}/backup/{}/status",
        server_addr.trim_end_matches('/'),
        task_id
    );
    let mut in_progress_logged = false;
    loop {
        let resp = client.get(&status_url).send().await;
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
                                println!("Backup in progress...");
                                in_progress_logged = true;
                            }
                        }
                        "done" => {
                            println!("Backup complete! Downloading zip...");
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

async fn fetch_error_log(server_addr: &str, task_id: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let url = format!(
        "{}/backup/{}/error_log",
        server_addr.trim_end_matches('/'),
        task_id
    );
    let resp = client.get(&url).send().await?;
    if resp.status().is_success() {
        let text = resp.text().await?;
        warn!("{}", text);
    }
    Ok(())
}

async fn download_backup(
    client: &Client,
    server_addr: &str,
    task_id: &str,
    output_path: Option<&PathBuf>,
) -> Result<()> {
    let download_url = format!(
        "{}/backup/{}/download",
        server_addr.trim_end_matches('/'),
        task_id
    );
    let resp = client
        .get(&download_url)
        .send()
        .await
        .context("Failed to download zip")?;
    if !resp.status().is_success() {
        anyhow::bail!("Failed to download zip: {}", resp.status());
    }
    let bytes = resp.bytes().await.context("Failed to read zip bytes")?;
    let output_path = output_path.cloned().unwrap_or_else(|| PathBuf::from("."));

    println!("Extracting backup to {}...", output_path.display());
    // Extract tar.gz from bytes
    let gz = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(gz);
    archive
        .unpack(&output_path)
        .context("Failed to extract backup archive")?;
    println!("Backup extracted to {}", output_path.display());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let args = Args::parse();
    logging::init(args.log_level);

    let tokens_content = fs::read_to_string(&args.tokens_config_path)
        .await
        .context("Failed to read tokens config file")?;
    let token_config: TokenConfig =
        toml::from_str(&tokens_content).context("Failed to parse tokens config file")?;

    if args.server_mode {
        return backup_from_server(token_config, args.server_addr, args.output_path).await;
    }

    let chains_content = fs::read_to_string(&args.chains_config_path)
        .await
        .context("Failed to read chains config file")?;
    let chain_config: ChainConfig =
        toml::from_str(&chains_content).context("Failed to parse chains config file")?;

    let backup_config = BackupConfig {
        chain_config,
        token_config,
        output_path: args.output_path,
        prune_redundant: args.prune_redundant,
        exit_on_error: args.exit_on_error,
    };
    return backup_from_config(backup_config).await;
}
