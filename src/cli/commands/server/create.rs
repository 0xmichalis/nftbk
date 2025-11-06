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
use crate::server::hashing::compute_task_id;

use super::common::delete_backup;

const BACKUPS_API_PATH: &str = "/v1/backups";

#[derive(Debug)]
enum BackupStart {
    Created(BackupCreateResponse),
    Exists(BackupCreateResponse),
    Conflict {
        retry_url: String,
        message: String,
        instance: Option<String>,
    },
}

fn extract_task_id_from_retry_url(retry_url: &str) -> Option<String> {
    // Expected format: {BACKUPS_API_PATH}/{task_id}/retry
    let prefix = format!("{}/", BACKUPS_API_PATH);
    if !retry_url.starts_with(&prefix) {
        return None;
    }
    let tail = &retry_url[prefix.len()..];
    let parts: Vec<&str> = tail.split('/').collect();
    if parts.is_empty() {
        return None;
    }
    Some(parts[0].to_string())
}

#[allow(clippy::too_many_arguments)]
async fn force_delete_and_retry(
    client: &Client,
    server_address: &str,
    auth_token: Option<&str>,
    retry_url: &str,
    instance_url: Option<&str>,
    token_config: &crate::TokenConfig,
    user_agent: &str,
    pin_on_ipfs: bool,
    x402_private_key: Option<&str>,
) -> Result<String> {
    let source = if !retry_url.is_empty() {
        Some(retry_url)
    } else {
        instance_url
    };
    if let Some(src) = source {
        if let Some(conflict_task_id) = extract_task_id_from_retry_url(src) {
            let _ = delete_backup(client, server_address, &conflict_task_id, auth_token).await;
            let start2 = request_backup(
                token_config,
                server_address,
                client,
                auth_token,
                user_agent,
                pin_on_ipfs,
                x402_private_key,
            )
            .await?;
            return match start2 {
                BackupStart::Created(r) | BackupStart::Exists(r) => Ok(r.task_id.clone()),
                BackupStart::Conflict {
                    message, retry_url, ..
                } => anyhow::bail!(
                    "{}\nCould not create new task after force delete. Try POST to {}{}",
                    message,
                    server_address.trim_end_matches('/'),
                    retry_url
                ),
            };
        }
    }
    anyhow::bail!(
        "Could not parse conflict task id from server response (missing retry/instance URL)"
    )
}

pub async fn run(
    tokens_config_path: PathBuf,
    server_address: String,
    output_path: Option<PathBuf>,
    force: bool,
    user_agent: String,
    pin_on_ipfs: bool,
    polling_interval_ms: Option<u64>,
) -> Result<()> {
    let token_config = load_token_config(&tokens_config_path).await?;
    let auth_token = env::var("NFTBK_AUTH_TOKEN").ok();
    let x402_private_key = env::var("NFTBK_X402_PRIVATE_KEY").ok();
    let client = Client::new();

    // Build the backup request to compute task_id
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

    // Compute task_id to check if backup exists without making POST request
    let task_id = compute_task_id(&backup_req.tokens, auth_token.as_deref());

    // Check if backup exists using GET endpoint (no payment required)
    let backup_exists =
        check_backup_exists(&client, &server_address, &task_id, auth_token.as_deref()).await?;

    let final_task_id = if backup_exists {
        println!("Task ID (exists): {task_id}");
        if force {
            // Delete existing backup and create new one
            let _ = delete_backup(&client, &server_address, &task_id, auth_token.as_deref()).await;
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
            match start {
                BackupStart::Created(resp) | BackupStart::Exists(resp) => {
                    let task_id2 = resp.task_id.clone();
                    println!("Task ID (after delete): {task_id2}");
                    task_id2
                }
                BackupStart::Conflict {
                    message: _,
                    retry_url,
                    instance,
                } => {
                    let task_id2 = force_delete_and_retry(
                        &client,
                        &server_address,
                        auth_token.as_deref(),
                        &retry_url,
                        instance.as_deref(),
                        &token_config,
                        &user_agent,
                        pin_on_ipfs,
                        x402_private_key.as_deref(),
                    )
                    .await?;
                    println!("Task ID (after force delete): {task_id2}");
                    task_id2
                }
            }
        } else {
            task_id
        }
    } else {
        // Backup doesn't exist, create it
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
        match start {
            BackupStart::Created(resp) => {
                let task_id = resp.task_id.clone();
                println!("Task ID: {task_id}");
                task_id
            }
            BackupStart::Exists(resp) => {
                let task_id = resp.task_id.clone();
                println!("Task ID (exists): {task_id}");
                task_id
            }
            BackupStart::Conflict {
                retry_url,
                message: _,
                instance,
            } => {
                if force {
                    let task_id = force_delete_and_retry(
                        &client,
                        &server_address,
                        auth_token.as_deref(),
                        &retry_url,
                        instance.as_deref(),
                        &token_config,
                        &user_agent,
                        pin_on_ipfs,
                        x402_private_key.as_deref(),
                    )
                    .await?;
                    println!("Task ID (after force delete): {task_id}");
                    task_id
                } else {
                    anyhow::bail!(
                        "Conflict creating backup. Re-run with --force true, or POST to {}{}",
                        server_address.trim_end_matches('/'),
                        retry_url
                    );
                }
            }
        }
    };

    let polling_interval = polling_interval_ms.unwrap_or(10000); // Default 10 seconds
    wait_for_done_backup(
        &client,
        &server_address,
        &final_task_id,
        auth_token.as_deref(),
        polling_interval,
    )
    .await?;

    return download_backup(
        &client,
        &server_address,
        &final_task_id,
        output_path.as_ref(),
        auth_token.as_deref(),
        &archive_format_from_user_agent(&user_agent),
    )
    .await;
}

async fn request_backup(
    token_config: &crate::TokenConfig,
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
        let instance = body
            .get("instance")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        return Ok(BackupStart::Conflict {
            retry_url,
            message,
            instance,
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

/// Check if a backup exists by making a GET request to the backup status endpoint
async fn check_backup_exists(
    client: &Client,
    server_address: &str,
    task_id: &str,
    auth_token: Option<&str>,
) -> Result<bool> {
    let server = server_address.trim_end_matches('/');
    let mut req_builder = client.get(format!("{server}/v1/backups/{task_id}"));

    if let Some(token) = auth_token {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
    }

    let resp = req_builder.send().await?;
    let status = resp.status();

    match status.as_u16() {
        200 => Ok(true),  // Backup exists
        404 => Ok(false), // Backup doesn't exist
        _ => {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Failed to check backup status: {} - {}", status, text);
        }
    }
}

async fn wait_for_done_backup(
    client: &reqwest::Client,
    server_address: &str,
    task_id: &str,
    auth_token: Option<&str>,
    polling_interval_ms: u64,
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
        tokio::time::sleep(std::time::Duration::from_millis(polling_interval_ms)).await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TokenConfig;
    use std::collections::HashMap;
    use tempfile::TempDir;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn create_test_token_config() -> TokenConfig {
        let mut chains = HashMap::new();
        chains.insert("ethereum".to_string(), vec!["0x123:1".to_string()]);
        TokenConfig { chains }
    }

    fn create_test_backup_create_response() -> BackupCreateResponse {
        BackupCreateResponse {
            task_id: "test-task-123".to_string(),
        }
    }

    fn create_test_backup_response() -> BackupResponse {
        BackupResponse {
            task_id: "test-task-123".to_string(),
            created_at: "2023-01-01T00:00:00Z".to_string(),
            storage_mode: "full".to_string(),
            tokens: vec![],
            total_tokens: 5,
            page: 1,
            limit: 50,
            archive: Some(api::Archive {
                status: api::SubresourceStatus {
                    status: Some("done".to_string()),
                    fatal_error: None,
                    error_log: None,
                    deleted_at: None,
                },
                format: Some("zip".to_string()),
                expires_at: None,
            }),
            pins: Some(api::Pins {
                status: api::SubresourceStatus {
                    status: Some("done".to_string()),
                    fatal_error: None,
                    error_log: None,
                    deleted_at: None,
                },
            }),
        }
    }

    mod request_backup_tests {
        use super::*;

        #[tokio::test]
        async fn creates_new_backup_successfully() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let token_config = create_test_token_config();

            let backup_response = create_test_backup_create_response();

            Mock::given(method("POST"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(201).set_body_json(&backup_response))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result = request_backup(
                &token_config,
                &server_address,
                &client,
                None,
                "TestAgent",
                false,
                None,
            )
            .await;

            assert!(result.is_ok());
            match result.unwrap() {
                BackupStart::Created(resp) => {
                    assert_eq!(resp.task_id, "test-task-123");
                }
                _ => panic!("Expected Created variant"),
            }
        }

        #[tokio::test]
        async fn handles_existing_backup() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let token_config = create_test_token_config();

            let backup_response = create_test_backup_create_response();

            Mock::given(method("POST"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&backup_response))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result = request_backup(
                &token_config,
                &server_address,
                &client,
                None,
                "TestAgent",
                false,
                None,
            )
            .await;

            assert!(result.is_ok());
            match result.unwrap() {
                BackupStart::Exists(resp) => {
                    assert_eq!(resp.task_id, "test-task-123");
                }
                _ => panic!("Expected Exists variant"),
            }
        }

        #[tokio::test]
        async fn handles_conflict_response() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let token_config = create_test_token_config();

            let conflict_response = serde_json::json!({
                "task_id": "conflict-task-456",
                "retry_url": "/v1/backups/conflict-task-456/retry",
                "error": "Task already in progress"
            });

            Mock::given(method("POST"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(409).set_body_json(&conflict_response))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result = request_backup(
                &token_config,
                &server_address,
                &client,
                None,
                "TestAgent",
                false,
                None,
            )
            .await;

            assert!(result.is_ok());
            match result.unwrap() {
                BackupStart::Conflict {
                    retry_url, message, ..
                } => {
                    assert_eq!(retry_url, "/v1/backups/conflict-task-456/retry");
                    assert_eq!(message, "Task already in progress");
                }
                _ => panic!("Expected Conflict variant"),
            }
        }

        #[tokio::test]
        async fn includes_auth_header_when_token_present() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let token_config = create_test_token_config();

            let backup_response = create_test_backup_create_response();

            Mock::given(method("POST"))
                .and(path("/v1/backups"))
                .and(header("Authorization", "Bearer test-token-123"))
                .respond_with(ResponseTemplate::new(201).set_body_json(&backup_response))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result = request_backup(
                &token_config,
                &server_address,
                &client,
                Some("test-token-123"),
                "TestAgent",
                false,
                None,
            )
            .await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn includes_user_agent_header() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let token_config = create_test_token_config();

            let backup_response = create_test_backup_create_response();

            Mock::given(method("POST"))
                .and(path("/v1/backups"))
                .and(header("User-Agent", "CustomAgent/1.0"))
                .respond_with(ResponseTemplate::new(201).set_body_json(&backup_response))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result = request_backup(
                &token_config,
                &server_address,
                &client,
                None,
                "CustomAgent/1.0",
                false,
                None,
            )
            .await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn handles_server_error() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let token_config = create_test_token_config();

            Mock::given(method("POST"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result = request_backup(
                &token_config,
                &server_address,
                &client,
                None,
                "TestAgent",
                false,
                None,
            )
            .await;

            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Server error"));
        }
    }

    mod wait_for_done_backup_tests {
        use super::*;

        #[tokio::test]
        async fn waits_for_backup_completion() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let task_id = "test-task-123";

            let backup_response = create_test_backup_response();

            Mock::given(method("GET"))
                .and(path(format!("/v1/backups/{}", task_id)))
                .respond_with(ResponseTemplate::new(200).set_body_json(&backup_response))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result = wait_for_done_backup(&client, &server_address, task_id, None, 10).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn handles_backup_with_errors() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let task_id = "test-task-error";

            let mut backup_response = create_test_backup_response();
            backup_response.archive.as_mut().unwrap().status.status = Some("error".to_string());
            backup_response.archive.as_mut().unwrap().status.fatal_error =
                Some("Archive creation failed".to_string());

            Mock::given(method("GET"))
                .and(path(format!("/v1/backups/{}", task_id)))
                .respond_with(ResponseTemplate::new(200).set_body_json(&backup_response))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result = wait_for_done_backup(&client, &server_address, task_id, None, 10).await;

            if result.is_ok() {
                println!("Expected error but got Ok result");
            }
            assert!(result.is_err());
            assert!(result.unwrap_err().to_string().contains("Server error"));
        }

        #[tokio::test]
        async fn includes_auth_header_when_token_present() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let task_id = "test-task-auth";

            let backup_response = create_test_backup_response();

            Mock::given(method("GET"))
                .and(path(format!("/v1/backups/{}", task_id)))
                .and(header("Authorization", "Bearer test-token-123"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&backup_response))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result = wait_for_done_backup(
                &client,
                &server_address,
                task_id,
                Some("test-token-123"),
                10,
            )
            .await;

            assert!(result.is_ok());
        }
    }

    mod download_backup_tests {
        use super::*;

        #[tokio::test]
        async fn downloads_and_extracts_zip_archive() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let task_id = "test-task-123";

            // Create a temporary directory for extraction
            let temp_dir = TempDir::new().unwrap();
            let output_path = temp_dir.path();

            // Mock download token response
            let token_response = serde_json::json!({
                "token": "download-token-123"
            });

            Mock::given(method("POST"))
                .and(path(format!("/v1/backups/{}/download-tokens", task_id)))
                .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
                .mount(&mock_server)
                .await;

            // Create a simple zip file content
            let mut zip_data = Vec::new();
            {
                use std::io::Write;
                let mut zip = zip::ZipWriter::new(std::io::Cursor::new(&mut zip_data));
                zip.start_file("test.txt", zip::write::FileOptions::default())
                    .unwrap();
                zip.write_all(b"Hello, World!").unwrap();
                zip.finish().unwrap();
            }

            // Mock download response
            Mock::given(method("GET"))
                .and(path(format!("/v1/backups/{}/download", task_id)))
                .and(query_param("token", "download-token-123"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_data.clone()))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result = download_backup(
                &client,
                &server_address,
                task_id,
                Some(&output_path.to_path_buf()),
                None,
                "zip",
            )
            .await;

            assert!(result.is_ok());

            // Verify the file was extracted
            let extracted_file = output_path.join("test.txt");
            assert!(extracted_file.exists());
            let content = std::fs::read_to_string(&extracted_file).unwrap();
            assert_eq!(content, "Hello, World!");
        }

        #[tokio::test]
        async fn downloads_and_extracts_tar_gz_archive() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let task_id = "test-task-tar";

            // Create a temporary directory for extraction
            let temp_dir = TempDir::new().unwrap();
            let output_path = temp_dir.path();

            // Mock download token response
            let token_response = serde_json::json!({
                "token": "download-token-tar"
            });

            Mock::given(method("POST"))
                .and(path(format!("/v1/backups/{}/download-tokens", task_id)))
                .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
                .mount(&mock_server)
                .await;

            // Create a simple tar.gz file content
            let mut tar_data = Vec::new();
            {
                use flate2::write::GzEncoder;
                use flate2::Compression;
                use tar::Builder;

                let gz = GzEncoder::new(&mut tar_data, Compression::default());
                let mut tar = Builder::new(gz);
                let mut header = tar::Header::new_gnu();
                header.set_path("test.txt").unwrap();
                header.set_size(13);
                header.set_cksum();
                tar.append(&header, &b"Hello, World!"[..]).unwrap();
                tar.finish().unwrap();
            }

            // Mock download response
            Mock::given(method("GET"))
                .and(path(format!("/v1/backups/{}/download", task_id)))
                .and(query_param("token", "download-token-tar"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(tar_data.clone()))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result = download_backup(
                &client,
                &server_address,
                task_id,
                Some(&output_path.to_path_buf()),
                None,
                "tar.gz",
            )
            .await;

            assert!(result.is_ok());

            // Verify the file was extracted
            let extracted_file = output_path.join("test.txt");
            assert!(extracted_file.exists());
            let content = std::fs::read_to_string(&extracted_file).unwrap();
            assert_eq!(content, "Hello, World!");
        }

        #[tokio::test]
        async fn handles_download_token_error() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let task_id = "test-task-token-error";

            Mock::given(method("POST"))
                .and(path(format!("/v1/backups/{}/download-tokens", task_id)))
                .respond_with(ResponseTemplate::new(500).set_body_string("Token generation failed"))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result =
                download_backup(&client, &server_address, task_id, None, None, "zip").await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to get download token"));
        }

        #[tokio::test]
        async fn handles_download_error() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let task_id = "test-task-download-error";

            // Mock download token response
            let token_response = serde_json::json!({
                "token": "download-token-error"
            });

            Mock::given(method("POST"))
                .and(path(format!("/v1/backups/{}/download-tokens", task_id)))
                .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
                .mount(&mock_server)
                .await;

            // Mock download error
            Mock::given(method("GET"))
                .and(path(format!("/v1/backups/{}/download", task_id)))
                .respond_with(ResponseTemplate::new(500).set_body_string("Download failed"))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result =
                download_backup(&client, &server_address, task_id, None, None, "zip").await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to download archive"));
        }

        #[tokio::test]
        async fn handles_unknown_archive_format() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();
            let task_id = "test-task-unknown-format";

            // Mock download token response
            let token_response = serde_json::json!({
                "token": "download-token-unknown"
            });

            Mock::given(method("POST"))
                .and(path(format!("/v1/backups/{}/download-tokens", task_id)))
                .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
                .mount(&mock_server)
                .await;

            // Mock download response
            Mock::given(method("GET"))
                .and(path(format!("/v1/backups/{}/download", task_id)))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(b"some data"))
                .mount(&mock_server)
                .await;

            let client = Client::new();
            let result =
                download_backup(&client, &server_address, task_id, None, None, "unknown").await;

            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Unknown archive format"));
        }
    }

    mod run_tests {
        use super::*;
        use std::fs;

        #[tokio::test]
        async fn runs_successfully_with_valid_config() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            // Create a temporary tokens config file
            let temp_dir = TempDir::new().unwrap();
            let tokens_config_path = temp_dir.path().join("tokens.toml");
            fs::write(
                &tokens_config_path,
                r#"
ethereum = ["0x123:1"]
"#,
            )
            .unwrap();

            // Mock the backup creation
            let backup_response = create_test_backup_create_response();
            Mock::given(method("POST"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(201).set_body_json(&backup_response))
                .mount(&mock_server)
                .await;

            // Mock the status check
            let status_response = create_test_backup_response();
            Mock::given(method("GET"))
                .and(path("/v1/backups/test-task-123"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&status_response))
                .mount(&mock_server)
                .await;

            // Mock download token response
            let token_response = serde_json::json!({
                "token": "download-token-123"
            });
            Mock::given(method("POST"))
                .and(path("/v1/backups/test-task-123/download-tokens"))
                .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
                .mount(&mock_server)
                .await;

            // Create a simple tar.gz file content (Linux user agent maps to tar.gz)
            let mut tar_data = Vec::new();
            {
                use flate2::write::GzEncoder;
                use flate2::Compression;
                use tar::Builder;

                let gz = GzEncoder::new(&mut tar_data, Compression::default());
                let mut tar = Builder::new(gz);
                let mut header = tar::Header::new_gnu();
                header.set_path("test.txt").unwrap();
                header.set_size(13);
                header.set_cksum();
                tar.append(&header, &b"Hello, World!"[..]).unwrap();
                tar.finish().unwrap();
            }

            // Mock download response
            Mock::given(method("GET"))
                .and(path("/v1/backups/test-task-123/download"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(tar_data.clone()))
                .mount(&mock_server)
                .await;

            let result = run(
                tokens_config_path,
                server_address,
                Some(temp_dir.path().to_path_buf()),
                false,
                "Linux".to_string(),
                false,
                Some(10), // Very fast polling for tests
            )
            .await;

            if let Err(e) = &result {
                println!("Test failed with error: {}", e);
            }
            assert!(result.is_ok());
        }
    }
}
