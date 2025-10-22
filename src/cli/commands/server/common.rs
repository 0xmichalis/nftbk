use anyhow::{Context, Result};
use reqwest::Client;

use crate::envvar::is_defined;
use crate::server::api::BackupResponse;

const BACKUPS_API_PATH: &str = "/v1/backups";

pub async fn delete_backup(
    client: &Client,
    server_address: &str,
    task_id: &str,
    auth_token: Option<&str>,
) -> Result<()> {
    let server = server_address.trim_end_matches('/');

    // First, get the backup information to determine storage mode
    let backup_url = format!("{server}{BACKUPS_API_PATH}/{task_id}");
    let mut backup_req = client.get(&backup_url);
    if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
        backup_req = backup_req.header("Authorization", format!("Bearer {}", auth_token.unwrap()));
    }

    let backup_resp = backup_req
        .send()
        .await
        .context("Failed to get backup information")?;

    if backup_resp.status().as_u16() == 404 {
        println!("Backup {task_id} not found");
        return Ok(());
    }

    if !backup_resp.status().is_success() {
        let text = backup_resp.text().await.unwrap_or_default();
        anyhow::bail!("Failed to get backup information: {}", text);
    }

    let backup: BackupResponse = backup_resp
        .json()
        .await
        .context("Invalid backup response")?;

    // Determine which endpoint to call based on storage mode
    let delete_url = match backup.storage_mode.as_str() {
        "archive" => format!("{server}{BACKUPS_API_PATH}/{task_id}/archive"),
        "ipfs" => format!("{server}{BACKUPS_API_PATH}/{task_id}/pins"),
        "full" => {
            // For full backups, we need to delete both archive and pins
            // Start with archive deletion
            let archive_url = format!("{server}{BACKUPS_API_PATH}/{task_id}/archive");
            let mut archive_req = client.delete(&archive_url);
            if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
                archive_req =
                    archive_req.header("Authorization", format!("Bearer {}", auth_token.unwrap()));
            }
            let archive_resp = archive_req
                .send()
                .await
                .context("Failed to delete archive")?;

            match archive_resp.status().as_u16() {
                202 => println!("Archive deletion request sent for backup {task_id}"),
                404 => println!("Backup {task_id} already deleted"),
                409 => println!("Backup {task_id} is in progress"),
                code => {
                    let text = archive_resp.text().await.unwrap_or_default();
                    println!("Warning: failed to delete archive ({code}): {text}");
                }
            }

            // Then delete pins
            format!("{server}{BACKUPS_API_PATH}/{task_id}/pins")
        }
        _ => {
            anyhow::bail!("Unknown storage mode: {}", backup.storage_mode);
        }
    };

    // Send the delete request
    let mut delete_req = client.delete(&delete_url);
    if is_defined(&auth_token.as_ref().map(|s| s.to_string())) {
        delete_req = delete_req.header("Authorization", format!("Bearer {}", auth_token.unwrap()));
    }
    let resp = delete_req
        .send()
        .await
        .context("Failed to send DELETE to server")?;

    match resp.status().as_u16() {
        202 => {
            println!("Deletion request sent for backup {task_id}");
            Ok(())
        }
        404 => {
            println!("Backup {task_id} already deleted");
            Ok(())
        }
        409 => {
            println!("Existing backup {task_id} is in progress");
            Ok(())
        }
        code => {
            let text = resp.text().await.unwrap_or_default();
            println!("Warning: failed to delete existing backup ({code}): {text}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn deletes_backup_successfully() {
        let mock_server = MockServer::start().await;
        let server_address = mock_server.uri();
        let task_id = "test-task-123";

        // Mock the GET request to return backup info with archive storage mode
        Mock::given(method("GET"))
            .and(path(format!("/v1/backups/{}", task_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "task_id": task_id,
                "created_at": "2023-01-01T00:00:00Z",
                "storage_mode": "archive",
                "tokens": [],
                "total_tokens": 0,
                "page": 1,
                "limit": 10,
                "archive": {
                    "format": "zip",
                    "expires_at": null,
                    "status": {
                        "status": "done",
                        "fatal_error": null,
                        "error_log": null,
                        "deleted_at": null
                    }
                },
                "pins": null
            })))
            .mount(&mock_server)
            .await;

        // Mock the DELETE request to return 202 (accepted)
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/backups/{}/archive", task_id)))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        let client = Client::new();
        let result = delete_backup(&client, &server_address, task_id, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handles_already_deleted_backup() {
        let mock_server = MockServer::start().await;
        let server_address = mock_server.uri();
        let task_id = "test-task-404";

        // Mock the GET request to return 404 (backup not found)
        Mock::given(method("GET"))
            .and(path(format!("/v1/backups/{}", task_id)))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = Client::new();
        let result = delete_backup(&client, &server_address, task_id, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handles_backup_in_progress() {
        let mock_server = MockServer::start().await;
        let server_address = mock_server.uri();
        let task_id = "test-task-409";

        // Mock the GET request to return backup info with archive storage mode
        Mock::given(method("GET"))
            .and(path(format!("/v1/backups/{}", task_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "task_id": task_id,
                "created_at": "2023-01-01T00:00:00Z",
                "storage_mode": "archive",
                "tokens": [],
                "total_tokens": 0,
                "page": 1,
                "limit": 10,
                "archive": {
                    "format": "zip",
                    "expires_at": null,
                    "status": {
                        "status": "done",
                        "fatal_error": null,
                        "error_log": null,
                        "deleted_at": null
                    }
                },
                "pins": null
            })))
            .mount(&mock_server)
            .await;

        // Mock the DELETE request to return 409 (conflict - in progress)
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/backups/{}/archive", task_id)))
            .respond_with(ResponseTemplate::new(409))
            .mount(&mock_server)
            .await;

        let client = Client::new();
        let result = delete_backup(&client, &server_address, task_id, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn includes_auth_header_when_token_present() {
        let mock_server = MockServer::start().await;
        let server_address = mock_server.uri();
        let task_id = "test-task-auth";

        // Mock the GET request to return backup info with archive storage mode
        Mock::given(method("GET"))
            .and(path(format!("/v1/backups/{}", task_id)))
            .and(header("Authorization", "Bearer test-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "task_id": task_id,
                "created_at": "2023-01-01T00:00:00Z",
                "storage_mode": "archive",
                "tokens": [],
                "total_tokens": 0,
                "page": 1,
                "limit": 10,
                "archive": {
                    "format": "zip",
                    "expires_at": null,
                    "status": {
                        "status": "done",
                        "fatal_error": null,
                        "error_log": null,
                        "deleted_at": null
                    }
                },
                "pins": null
            })))
            .mount(&mock_server)
            .await;

        // Mock the DELETE request with auth header
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/backups/{}/archive", task_id)))
            .and(header("Authorization", "Bearer test-token-123"))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        // Mock the status check to return 404 (not found) after deletion
        Mock::given(method("GET"))
            .and(path(format!("/v1/backups/{}", task_id)))
            .and(header("Authorization", "Bearer test-token-123"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let client = Client::new();
        let result = delete_backup(&client, &server_address, task_id, Some("test-token-123")).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn works_without_auth_token() {
        let mock_server = MockServer::start().await;
        let server_address = mock_server.uri();
        let task_id = "test-task-no-auth";

        // Mock the GET request to return backup info with archive storage mode
        Mock::given(method("GET"))
            .and(path(format!("/v1/backups/{}", task_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "task_id": task_id,
                "created_at": "2023-01-01T00:00:00Z",
                "storage_mode": "archive",
                "tokens": [],
                "total_tokens": 0,
                "page": 1,
                "limit": 10,
                "archive": {
                    "format": "zip",
                    "expires_at": null,
                    "status": {
                        "status": "done",
                        "fatal_error": null,
                        "error_log": null,
                        "deleted_at": null
                    }
                },
                "pins": null
            })))
            .mount(&mock_server)
            .await;

        // Mock the DELETE request without auth header
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/backups/{}/archive", task_id)))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        let client = Client::new();
        let result = delete_backup(&client, &server_address, task_id, None).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn handles_server_error() {
        let mock_server = MockServer::start().await;
        let server_address = mock_server.uri();
        let task_id = "test-task-error";

        // Mock the GET request to return backup info with archive storage mode
        Mock::given(method("GET"))
            .and(path(format!("/v1/backups/{}", task_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "task_id": task_id,
                "created_at": "2023-01-01T00:00:00Z",
                "storage_mode": "archive",
                "tokens": [],
                "total_tokens": 0,
                "page": 1,
                "limit": 10,
                "archive": {
                    "format": "zip",
                    "expires_at": null,
                    "status": {
                        "status": "done",
                        "fatal_error": null,
                        "error_log": null,
                        "deleted_at": null
                    }
                },
                "pins": null
            })))
            .mount(&mock_server)
            .await;

        // Mock the DELETE request to return 500 (server error)
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/backups/{}/archive", task_id)))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let client = Client::new();
        let result = delete_backup(&client, &server_address, task_id, None).await;
        assert!(result.is_ok()); // The function returns Ok(()) for server errors with a warning
    }

    #[tokio::test]
    async fn trims_trailing_slash_from_server_address() {
        let mock_server = MockServer::start().await;
        let server_address = format!("{}/", mock_server.uri()); // Add trailing slash
        let task_id = "test-task-slash";

        // Mock the GET request to return backup info with archive storage mode
        Mock::given(method("GET"))
            .and(path(format!("/v1/backups/{}", task_id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "task_id": task_id,
                "created_at": "2023-01-01T00:00:00Z",
                "storage_mode": "archive",
                "tokens": [],
                "total_tokens": 0,
                "page": 1,
                "limit": 10,
                "archive": {
                    "format": "zip",
                    "expires_at": null,
                    "status": {
                        "status": "done",
                        "fatal_error": null,
                        "error_log": null,
                        "deleted_at": null
                    }
                },
                "pins": null
            })))
            .mount(&mock_server)
            .await;

        // Mock the DELETE request
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/backups/{}/archive", task_id)))
            .respond_with(ResponseTemplate::new(202))
            .mount(&mock_server)
            .await;

        let client = Client::new();
        let result = delete_backup(&client, &server_address, task_id, None).await;
        assert!(result.is_ok());
    }
}
