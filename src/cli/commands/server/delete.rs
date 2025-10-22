use std::env;

use anyhow::Result;
use reqwest::Client;

use super::common::delete_backup;

pub async fn run(server_address: String, task_id: String) -> Result<()> {
    let auth_token = env::var("NFTBK_AUTH_TOKEN").ok();
    let client = Client::new();

    delete_backup(&client, &server_address, &task_id, auth_token.as_deref()).await
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

        let result = run(server_address, task_id.to_string()).await;
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

        let result = run(server_address, task_id.to_string()).await;
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

        let result = run(server_address, task_id.to_string()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn includes_auth_header_when_token_present() {
        let mock_server = MockServer::start().await;
        let server_address = mock_server.uri();
        let task_id = "test-task-auth";

        std::env::set_var("NFTBK_AUTH_TOKEN", "test-token-123");

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

        let result = run(server_address, task_id.to_string()).await;
        assert!(result.is_ok());

        std::env::remove_var("NFTBK_AUTH_TOKEN");
    }

    #[tokio::test]
    async fn works_without_auth_token() {
        let mock_server = MockServer::start().await;
        let server_address = mock_server.uri();
        let task_id = "test-task-no-auth";

        // Ensure no auth token is set
        std::env::remove_var("NFTBK_AUTH_TOKEN");

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

        let result = run(server_address, task_id.to_string()).await;
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

        let result = run(server_address, task_id.to_string()).await;
        assert!(result.is_ok()); // The shared function returns Ok(()) for server errors with a warning
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

        let result = run(server_address, task_id.to_string()).await;
        assert!(result.is_ok());
    }
}
