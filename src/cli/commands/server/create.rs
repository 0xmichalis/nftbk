use std::env;
use std::fs::File;
use std::io::Cursor;
use std::path::PathBuf;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use reqwest::Client;
use tar::Archive;
use zip::ZipArchive;

use crate::cli::config::load_token_config;
use crate::cli::x402::X402PaymentHandler;
use crate::envvar::is_defined;
use crate::server::api::{self, BackupCreateResponse, BackupRequest, BackupResponse, Tokens};
use crate::server::archive::archive_format_from_user_agent;

const BACKUPS_API_PATH: &str = "/v1/backups";

enum BackupStart {
    Created(BackupCreateResponse),
    Exists(BackupCreateResponse),
    Conflict {
        task_id: String,
        retry_url: String,
        message: String,
    },
}

pub async fn run(
    tokens_config_path: PathBuf,
    server_address: String,
    output_path: Option<PathBuf>,
    force: bool,
    user_agent: String,
    _ipfs_config: Option<String>,
    pin_on_ipfs: bool,
) -> Result<()> {
    let token_config = load_token_config(&tokens_config_path).await?;
    let auth_token = env::var("NFTBK_AUTH_TOKEN").ok();
    let x402_private_key = env::var("NFTBK_X402_PRIVATE_KEY").ok();
    let client = Client::new();

    // First, try to create the backup
    let start = request_backup(
        &token_config,
        &server_address,
        &client,
        auth_token.as_deref(),
        &user_agent,
        pin_on_ipfs,
        x402_private_key.as_deref(),
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
                    x402_private_key.as_deref(),
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
                    x402_private_key.as_deref(),
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
    token_config: &crate::backup::TokenConfig,
    server_address: &str,
    client: &Client,
    auth_token: Option<&str>,
    user_agent: &str,
    pin_on_ipfs: bool,
    x402_private_key: Option<&str>,
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
    let mut req_builder = client
        .post(format!("{server}{BACKUPS_API_PATH}"))
        .json(&backup_req);
    req_builder = req_builder.header("User-Agent", user_agent);
    if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
        req_builder =
            req_builder.header("Authorization", format!("Bearer {}", auth_token.unwrap()));
    }
    let req = req_builder.build().context("Failed to build request")?;
    let mut resp = client
        .execute(req.try_clone().context("Failed to clone request")?)
        .await
        .context("Failed to send backup request to server")?;
    let mut status = resp.status();

    // Handle 402 Payment Required response
    if status.as_u16() == 402 {
        resp = handle_402_response(client, resp, &req, x402_private_key).await?;
        status = resp.status();
    }

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

/// Handle 402 Payment Required response by creating a payment and retrying the request
async fn handle_402_response(
    client: &Client,
    response: reqwest::Response,
    original_request: &reqwest::Request,
    x402_private_key: Option<&str>,
) -> Result<reqwest::Response> {
    // Parse the 402 response structure
    let response_text = response
        .text()
        .await
        .context("Failed to read 402 response body")?;
    let response_json: serde_json::Value =
        serde_json::from_str(&response_text).context("Failed to parse 402 response as JSON")?;

    // Extract PaymentRequirements from the accepts array
    let accepts = response_json
        .get("accepts")
        .and_then(|v| v.as_array())
        .context("Missing or invalid 'accepts' field in 402 response")?;

    if accepts.is_empty() {
        anyhow::bail!("No payment options available in 402 response");
    }

    // Use the first payment option
    let payment_requirements: x402_rs::types::PaymentRequirements =
        serde_json::from_value(accepts[0].clone())
            .context("Failed to parse PaymentRequirements from accepts array")?;

    // Create x402 payment handler
    let payment_handler = X402PaymentHandler::new(x402_private_key)
        .context("Failed to create x402 payment handler")?;

    // Handle the payment and retry the request
    let response = payment_handler
        .handle_402_response(client, original_request, payment_requirements)
        .await
        .context("Failed to handle x402 payment")?;

    Ok(response)
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
                            archive: Some(api::Archive {
                                status: api::SubresourceStatus {
                                    status: None,
                                    fatal_error: None,
                                    error_log: None,
                                    deleted_at: None,
                                },
                                format: None,
                                expires_at: None,
                            }),
                            pins: Some(api::Pins {
                                status: api::SubresourceStatus {
                                    status: None,
                                    fatal_error: None,
                                    error_log: None,
                                    deleted_at: None,
                                },
                            }),
                        }
                    });
                    // Aggregate a coarse "overall" view for UX: in_progress if any subresource is in_progress
                    let archive_status = status
                        .archive
                        .as_ref()
                        .and_then(|a| a.status.status.as_deref());
                    let ipfs_status = status
                        .pins
                        .as_ref()
                        .and_then(|p| p.status.status.as_deref());
                    let any_in_progress = matches!(archive_status, Some("in_progress"))
                        || matches!(ipfs_status, Some("in_progress"));
                    let any_error = matches!(archive_status, Some("error"))
                        || matches!(ipfs_status, Some("error"))
                        || status
                            .archive
                            .as_ref()
                            .and_then(|a| a.status.fatal_error.as_ref())
                            .is_some()
                        || status
                            .pins
                            .as_ref()
                            .and_then(|p| p.status.fatal_error.as_ref())
                            .is_some();
                    let all_done = matches!(archive_status, Some("done"))
                        && (ipfs_status.is_none() || matches!(ipfs_status, Some("done")));
                    if any_in_progress {
                        if !in_progress_logged {
                            println!("Waiting for backup to complete...");
                            in_progress_logged = true;
                        }
                    } else if all_done {
                        println!("Backup complete.");
                        if let Some(ref a) = status
                            .archive
                            .as_ref()
                            .and_then(|a| a.status.error_log.as_ref())
                        {
                            if !a.is_empty() {
                                tracing::warn!("{}", a);
                            }
                        }
                        if let Some(ref i) = status
                            .pins
                            .as_ref()
                            .and_then(|p| p.status.error_log.as_ref())
                        {
                            if !i.is_empty() {
                                tracing::warn!("{}", i);
                            }
                        }
                        break;
                    } else if any_error {
                        let msg = status
                            .archive
                            .as_ref()
                            .and_then(|a| a.status.fatal_error.clone())
                            .or(status
                                .pins
                                .as_ref()
                                .and_then(|p| p.status.fatal_error.clone()))
                            .unwrap_or_else(|| "Unknown error".to_string());
                        anyhow::bail!("Server error: {}", msg);
                    } else {
                        println!(
                            "Unknown status: archive={:?} ipfs={:?}",
                            status
                                .archive
                                .as_ref()
                                .and_then(|a| a.status.status.as_deref()),
                            status
                                .pins
                                .as_ref()
                                .and_then(|p| p.status.status.as_deref())
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
