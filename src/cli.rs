use anyhow::{Context, Result};
use clap::Parser;
use dotenv::dotenv;
use flate2::read::GzDecoder;
use nftbk::api::{BackupResponse, ChainTokens, StatusResponse};
use nftbk::backup::{backup_from_config, BackupConfig, ChainConfig, TokenConfig};
use nftbk::logging;
use nftbk::logging::LogLevel;
use reqwest::Client;
use std::io::Cursor;
use std::path::PathBuf;
use std::time::Duration;
use tar::Archive;
use tokio::fs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the NFT chains configuration file (default: config_chains.toml)
    #[arg(short = 'c', long, default_value = "config_chains.toml")]
    chains_config_path: PathBuf,

    /// Path to the NFT tokens configuration file (default: config_tokens.toml)
    #[arg(short = 't', long, default_value = "config_tokens.toml")]
    tokens_config_path: PathBuf,

    /// Optional output directory path (defaults to current directory)
    #[arg(short, long)]
    output_path: Option<PathBuf>,

    #[arg(short, long, value_enum, default_value = "info")]
    log_level: LogLevel,

    /// Delete directories in the backup folder that are not part of the config
    #[arg(long, default_value = "false")]
    prune_missing: bool,

    /// Use the server for backup instead of running locally
    #[arg(long, default_value = "false")]
    server_mode: bool,

    /// Server address (default: http://127.0.0.1:8080)
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    server_addr: String,
}

async fn backup_from_server(
    token_config: TokenConfig,
    server_addr: String,
    output_path: Option<PathBuf>,
) -> Result<()> {
    // Build BackupRequest from TokenConfig
    let mut backup_req = Vec::new();
    for (chain, tokens) in &token_config.chains {
        backup_req.push(ChainTokens {
            chain: chain.clone(),
            tokens: tokens.clone(),
        });
    }

    let client = Client::new();
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
    println!("Backup task submitted. Task ID: {}", backup_resp.task_id);

    // Poll for status
    let status_url = format!("{}/backup/{}/status", server, backup_resp.task_id);
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
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    let download_url = format!("{}/backup/{}/download", server, backup_resp.task_id);
    let resp = client
        .get(&download_url)
        .send()
        .await
        .context("Failed to download zip")?;
    if !resp.status().is_success() {
        anyhow::bail!("Failed to download zip: {}", resp.status());
    }
    let bytes = resp.bytes().await.context("Failed to read zip bytes")?;
    let output_path = output_path.unwrap_or_else(|| PathBuf::from("."));

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

    let chains_content = fs::read_to_string(&args.chains_config_path)
        .await
        .context("Failed to read chains config file")?;
    let chain_config: ChainConfig =
        toml::from_str(&chains_content).context("Failed to parse chains config file")?;

    let tokens_content = fs::read_to_string(&args.tokens_config_path)
        .await
        .context("Failed to read tokens config file")?;
    let token_config: TokenConfig =
        toml::from_str(&tokens_content).context("Failed to parse tokens config file")?;

    if !args.server_mode {
        let backup_config = BackupConfig {
            chain_config,
            token_config,
            output_path: args.output_path,
            prune_missing: args.prune_missing,
        };
        return backup_from_config(backup_config).await;
    }

    backup_from_server(token_config, args.server_addr, args.output_path).await
}
