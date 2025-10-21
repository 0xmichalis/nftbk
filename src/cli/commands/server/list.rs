use std::env;
use std::io::Write;

use anyhow::{Context, Result};
use prettytable::{row, Table};
use reqwest::Client;

use crate::envvar::is_defined;
use crate::server::api::BackupResponse;

const BACKUPS_API_PATH: &str = "/v1/backups";

/// Determines the overall backup status based on storage mode and subresource statuses
fn determine_backup_status(
    storage_mode: &str,
    archive_status: Option<&str>,
    pins_status: Option<&str>,
    archive_fatal_error: Option<&String>,
    pins_fatal_error: Option<&String>,
) -> &'static str {
    match storage_mode {
        "archive" => {
            // For archive-only backups, only check archive status
            if matches!(archive_status, Some("in_progress")) {
                "in_progress"
            } else if matches!(archive_status, Some("error")) || archive_fatal_error.is_some() {
                "error"
            } else if matches!(archive_status, Some("done")) {
                "done"
            } else {
                "unknown"
            }
        }
        "ipfs" => {
            // For IPFS-only backups, only check pins status
            if matches!(pins_status, Some("in_progress")) {
                "in_progress"
            } else if matches!(pins_status, Some("error")) || pins_fatal_error.is_some() {
                "error"
            } else if matches!(pins_status, Some("done")) {
                "done"
            } else {
                "unknown"
            }
        }
        "full" => {
            // For full backups, check both archive and pins statuses
            let any_in_progress = matches!(archive_status, Some("in_progress"))
                || matches!(pins_status, Some("in_progress"));
            let any_error = matches!(archive_status, Some("error"))
                || matches!(pins_status, Some("error"))
                || archive_fatal_error.is_some()
                || pins_fatal_error.is_some();

            if any_in_progress {
                "in_progress"
            } else if any_error {
                "error"
            } else {
                // Both archive and pins must be done for full backup to be done
                let archive_done = matches!(archive_status, Some("done"));
                let pins_done = matches!(pins_status, Some("done"));

                if archive_done && pins_done {
                    "done"
                } else {
                    "unknown"
                }
            }
        }
        _ => "unknown", // Unknown storage mode
    }
}

pub async fn run(server_address: String, show_errors: bool) -> Result<()> {
    run_inner(server_address, show_errors, None).await
}

pub async fn run_inner(
    server_address: String,
    show_errors: bool,
    writer: Option<Box<dyn Write + Send + Sync>>,
) -> Result<()> {
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
    if show_errors {
        table.add_row(row!["Task ID", "Status", "Error", "Error Log", "NFT Count"]);
    } else {
        table.add_row(row!["Task ID", "Status", "NFT Count"]);
    }
    for entry in arr {
        let task_id = entry.task_id.as_str();
        let archive_status = entry
            .archive
            .as_ref()
            .and_then(|a| a.status.status.as_deref());
        let pins_status = entry.pins.as_ref().and_then(|p| p.status.status.as_deref());

        // Determine overall status based on storage mode and relevant subresource statuses
        let status = determine_backup_status(
            entry.storage_mode.as_str(),
            archive_status,
            pins_status,
            entry
                .archive
                .as_ref()
                .and_then(|a| a.status.fatal_error.as_ref()),
            entry
                .pins
                .as_ref()
                .and_then(|p| p.status.fatal_error.as_ref()),
        );
        let error = entry
            .archive
            .as_ref()
            .and_then(|a| a.status.fatal_error.clone())
            .or(entry
                .pins
                .as_ref()
                .and_then(|p| p.status.fatal_error.clone()))
            .unwrap_or_default();
        let mut logs = Vec::new();
        if let Some(a) = entry
            .archive
            .as_ref()
            .and_then(|a| a.status.error_log.as_ref())
        {
            if !a.is_empty() {
                logs.push(a.as_str());
            }
        }
        if let Some(i) = entry
            .pins
            .as_ref()
            .and_then(|p| p.status.error_log.as_ref())
        {
            if !i.is_empty() {
                logs.push(i.as_str());
            }
        }
        let combined = logs.join(" | ");
        let nft_count = entry.total_tokens as u64;
        if show_errors {
            table.add_row(row![task_id, status, error, combined, nft_count]);
        } else {
            table.add_row(row![task_id, status, nft_count]);
        }
    }
    if let Some(mut w) = writer {
        table.print(&mut w)?;
    } else {
        table.printstd();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::api::{Archive, Pins, SubresourceStatus};
    use std::io::sink;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn test_determine_backup_status() {
        // Test archive-only backups
        assert_eq!(
            determine_backup_status("archive", Some("done"), None, None, None),
            "done"
        );
        assert_eq!(
            determine_backup_status("archive", Some("in_progress"), None, None, None),
            "in_progress"
        );
        assert_eq!(
            determine_backup_status("archive", Some("error"), None, None, None),
            "error"
        );
        assert_eq!(
            determine_backup_status("archive", None, None, None, None),
            "unknown"
        );

        // Test IPFS-only backups
        assert_eq!(
            determine_backup_status("ipfs", None, Some("done"), None, None),
            "done"
        );
        assert_eq!(
            determine_backup_status("ipfs", None, Some("in_progress"), None, None),
            "in_progress"
        );
        assert_eq!(
            determine_backup_status("ipfs", None, Some("error"), None, None),
            "error"
        );
        assert_eq!(
            determine_backup_status("ipfs", None, None, None, None),
            "unknown"
        );

        // Test full backups
        assert_eq!(
            determine_backup_status("full", Some("done"), Some("done"), None, None),
            "done"
        );
        assert_eq!(
            determine_backup_status("full", Some("in_progress"), Some("done"), None, None),
            "in_progress"
        );
        assert_eq!(
            determine_backup_status("full", Some("done"), Some("in_progress"), None, None),
            "in_progress"
        );
        assert_eq!(
            determine_backup_status("full", Some("error"), Some("done"), None, None),
            "error"
        );
        assert_eq!(
            determine_backup_status("full", Some("done"), Some("error"), None, None),
            "error"
        );
        assert_eq!(
            determine_backup_status("full", None, Some("done"), None, None),
            "unknown"
        );
        assert_eq!(
            determine_backup_status("full", Some("done"), None, None, None),
            "unknown"
        );

        // Test fatal errors
        let fatal_error = "Test fatal error".to_string();
        assert_eq!(
            determine_backup_status("archive", Some("done"), None, Some(&fatal_error), None),
            "error"
        );
        assert_eq!(
            determine_backup_status("ipfs", None, Some("done"), None, Some(&fatal_error)),
            "error"
        );
        assert_eq!(
            determine_backup_status("full", Some("done"), Some("done"), Some(&fatal_error), None),
            "error"
        );
        assert_eq!(
            determine_backup_status("full", Some("done"), Some("done"), None, Some(&fatal_error)),
            "error"
        );

        // Test unknown storage mode
        assert_eq!(
            determine_backup_status("unknown", Some("done"), Some("done"), None, None),
            "unknown"
        );
    }

    mod run_tests {
        use super::*;

        async fn create_mock_backup_response() -> BackupResponse {
            BackupResponse {
                task_id: "test-task-123".to_string(),
                created_at: "2023-01-01T00:00:00Z".to_string(),
                storage_mode: "full".to_string(),
                tokens: vec![],
                total_tokens: 5,
                page: 1,
                limit: 50,
                archive: Some(Archive {
                    status: SubresourceStatus {
                        status: Some("done".to_string()),
                        fatal_error: None,
                        error_log: None,
                        deleted_at: None,
                    },
                    format: Some("zip".to_string()),
                    expires_at: None,
                }),
                pins: Some(Pins {
                    status: SubresourceStatus {
                        status: Some("done".to_string()),
                        fatal_error: None,
                        error_log: None,
                        deleted_at: None,
                    },
                }),
            }
        }

        async fn create_mock_backup_response_with_errors() -> BackupResponse {
            BackupResponse {
                task_id: "test-task-error".to_string(),
                created_at: "2023-01-01T00:00:00Z".to_string(),
                storage_mode: "full".to_string(),
                tokens: vec![],
                total_tokens: 0,
                page: 1,
                limit: 50,
                archive: Some(Archive {
                    status: SubresourceStatus {
                        status: Some("error".to_string()),
                        fatal_error: Some("Archive creation failed".to_string()),
                        error_log: Some("Error: Connection timeout".to_string()),
                        deleted_at: None,
                    },
                    format: None,
                    expires_at: None,
                }),
                pins: Some(Pins {
                    status: SubresourceStatus {
                        status: Some("done".to_string()),
                        fatal_error: None,
                        error_log: None,
                        deleted_at: None,
                    },
                }),
            }
        }

        async fn create_mock_backup_response_in_progress() -> BackupResponse {
            BackupResponse {
                task_id: "test-task-progress".to_string(),
                created_at: "2023-01-01T00:00:00Z".to_string(),
                storage_mode: "full".to_string(),
                tokens: vec![],
                total_tokens: 10,
                page: 1,
                limit: 50,
                archive: Some(Archive {
                    status: SubresourceStatus {
                        status: Some("in_progress".to_string()),
                        fatal_error: None,
                        error_log: None,
                        deleted_at: None,
                    },
                    format: None,
                    expires_at: None,
                }),
                pins: Some(Pins {
                    status: SubresourceStatus {
                        status: Some("done".to_string()),
                        fatal_error: None,
                        error_log: None,
                        deleted_at: None,
                    },
                }),
            }
        }

        #[tokio::test]
        async fn runs_successfully_with_valid_response() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            let backup_response = create_mock_backup_response().await;

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![backup_response]))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn runs_successfully_with_empty_response() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(Vec::<BackupResponse>::new()),
                )
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn runs_successfully_with_multiple_backups() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            let backup1 = create_mock_backup_response().await;
            let backup2 = create_mock_backup_response_with_errors().await;
            let backup3 = create_mock_backup_response_in_progress().await;

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(vec![backup1, backup2, backup3]),
                )
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn includes_auth_header_when_token_present() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            std::env::set_var("NFTBK_AUTH_TOKEN", "test-token-123");

            let backup_response = create_mock_backup_response().await;

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .and(header("Authorization", "Bearer test-token-123"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![backup_response]))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());

            std::env::remove_var("NFTBK_AUTH_TOKEN");
        }

        #[tokio::test]
        async fn works_without_auth_token() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            // Ensure no auth token is set
            std::env::remove_var("NFTBK_AUTH_TOKEN");

            let backup_response = create_mock_backup_response().await;

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![backup_response]))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn handles_server_error_response() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Server error: Internal Server Error"));
        }

        #[tokio::test]
        async fn handles_invalid_json_response() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_string("invalid json"))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Invalid server response"));
        }

        #[tokio::test]
        async fn handles_network_error() {
            let invalid_server_address = "http://localhost:99999".to_string();

            let result = run_inner(invalid_server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_err());
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("Failed to fetch backups from server"));
        }

        #[tokio::test]
        async fn trims_trailing_slash_from_server_address() {
            let mock_server = MockServer::start().await;
            let server_address = format!("{}/", mock_server.uri()); // Add trailing slash

            let backup_response = create_mock_backup_response().await;

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![backup_response]))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn shows_errors_when_flag_is_true() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            let backup_response = create_mock_backup_response_with_errors().await;

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![backup_response]))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, true, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn hides_errors_when_flag_is_false() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            let backup_response = create_mock_backup_response_with_errors().await;

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![backup_response]))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn handles_archive_only_done() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            let backup_response = BackupResponse {
                task_id: "test-task-archive-only".to_string(),
                created_at: "2023-01-01T00:00:00Z".to_string(),
                storage_mode: "archive".to_string(),
                tokens: vec![],
                total_tokens: 3,
                page: 1,
                limit: 50,
                archive: Some(Archive {
                    status: SubresourceStatus {
                        status: Some("done".to_string()),
                        fatal_error: None,
                        error_log: None,
                        deleted_at: None,
                    },
                    format: Some("zip".to_string()),
                    expires_at: None,
                }),
                pins: None,
            };

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![backup_response]))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn handles_pins_only_done() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            let backup_response = BackupResponse {
                task_id: "test-task-pins-only".to_string(),
                created_at: "2023-01-01T00:00:00Z".to_string(),
                storage_mode: "ipfs".to_string(),
                tokens: vec![],
                total_tokens: 2,
                page: 1,
                limit: 50,
                archive: None,
                pins: Some(Pins {
                    status: SubresourceStatus {
                        status: Some("done".to_string()),
                        fatal_error: None,
                        error_log: None,
                        deleted_at: None,
                    },
                }),
            };

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![backup_response]))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn handles_mixed_statuses() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            let backup_response = BackupResponse {
                task_id: "test-task-mixed".to_string(),
                created_at: "2023-01-01T00:00:00Z".to_string(),
                storage_mode: "full".to_string(),
                tokens: vec![],
                total_tokens: 1,
                page: 1,
                limit: 50,
                archive: Some(Archive {
                    status: SubresourceStatus {
                        status: Some("done".to_string()),
                        fatal_error: None,
                        error_log: None,
                        deleted_at: None,
                    },
                    format: Some("zip".to_string()),
                    expires_at: None,
                }),
                pins: Some(Pins {
                    status: SubresourceStatus {
                        status: Some("in_progress".to_string()),
                        fatal_error: None,
                        error_log: None,
                        deleted_at: None,
                    },
                }),
            };

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![backup_response]))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn handles_unknown_status() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            let backup_response = BackupResponse {
                task_id: "test-task-unknown".to_string(),
                created_at: "2023-01-01T00:00:00Z".to_string(),
                storage_mode: "archive".to_string(),
                tokens: vec![],
                total_tokens: 0,
                page: 1,
                limit: 50,
                archive: Some(Archive {
                    status: SubresourceStatus {
                        status: None, // No status set yet - unknown
                        fatal_error: None,
                        error_log: None,
                        deleted_at: None,
                    },
                    format: None,
                    expires_at: None,
                }),
                pins: None,
            };

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![backup_response]))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn handles_backup_with_no_archive_or_pins() {
            let mock_server = MockServer::start().await;
            let server_address = mock_server.uri();

            let backup_response = BackupResponse {
                task_id: "test-task-no-subresources".to_string(),
                created_at: "2023-01-01T00:00:00Z".to_string(),
                storage_mode: "full".to_string(),
                tokens: vec![],
                total_tokens: 3,
                page: 1,
                limit: 50,
                archive: None,
                pins: None,
            };

            Mock::given(method("GET"))
                .and(path("/v1/backups"))
                .respond_with(ResponseTemplate::new(200).set_body_json(vec![backup_response]))
                .mount(&mock_server)
                .await;

            let result = run_inner(server_address, false, Some(Box::new(sink()))).await;
            assert!(result.is_ok());
        }
    }
}
