use axum::http::{header, HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct Tokens {
    /// The blockchain identifier (ethereum, polygon, tezos, base, arbitrum)
    #[schema(example = "ethereum")]
    pub chain: String,
    /// List of NFT token identifiers/contract addresses
    /// The tokens are formatted as `contract_address:token_id` (e.g., `0x1234567890123456789012345678901234567890:1`)
    #[schema(example = json!(["0x1234567890123456789012345678901234567890:1", "0x1234567890123456789012345678901234567890:2"]))]
    pub tokens: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct BackupRequest {
    /// List of tokens to backup, organized by blockchain
    pub tokens: Vec<Tokens>,
    /// When true, pin downloaded assets to configured IPFS provider(s)
    #[serde(default)]
    pub pin_on_ipfs: bool,
    /// When true, create an archive of downloaded assets; when false, skip archiving
    #[serde(default = "default_true")]
    pub create_archive: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BackupCreateResponse {
    /// Unique identifier for the backup task
    pub task_id: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct SubresourceStatus {
    /// Subresource status
    #[schema(example = "done")]
    pub status: Option<String>,
    /// Fatal error for the subresource
    pub fatal_error: Option<String>,
    /// Aggregated non-fatal error log for the subresource
    pub error_log: Option<String>,
    /// When deletion for this subresource was initiated (ISO 8601)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct Archive {
    /// Archive format (zip, tar.gz)
    pub format: Option<String>,
    /// When the archive expires (ISO 8601)
    pub expires_at: Option<String>,
    /// Archive status/errors
    pub status: SubresourceStatus,
}

#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct Pins {
    /// IPFS pins status/errors
    pub status: SubresourceStatus,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BackupResponse {
    /// Unique identifier for the backup task
    pub task_id: String,
    /// When the backup task was created (ISO 8601)
    pub created_at: String,
    /// Storage mode used for the backup (archive, ipfs, full)
    pub storage_mode: String,
    /// Paginated tokens for this task (current page)
    pub tokens: Vec<Tokens>,
    /// Total number of tokens for this task (for pagination)
    pub total_tokens: u32,
    /// Current page number
    pub page: u32,
    /// Page size
    pub limit: u32,
    /// Archive info (null when storage_mode does not include archive)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive: Option<Archive>,
    /// IPFS pins info (null when storage_mode does not include ipfs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pins: Option<Pins>,
}

impl BackupResponse {
    pub fn from_backup_task(
        task: &crate::server::database::BackupTask,
        tokens: Vec<Tokens>,
        total_tokens: u32,
        page: u32,
        limit: u32,
    ) -> Self {
        let archive_status = SubresourceStatus {
            status: task.archive_status.clone(),
            fatal_error: task.archive_fatal_error.clone(),
            error_log: task.archive_error_log.clone(),
            deleted_at: task
                .archive_deleted_at
                .as_ref()
                .map(|d: &DateTime<Utc>| d.to_rfc3339()),
        };
        let pins_status = SubresourceStatus {
            status: task.ipfs_status.clone(),
            fatal_error: task.ipfs_fatal_error.clone(),
            error_log: task.ipfs_error_log.clone(),
            deleted_at: task
                .pins_deleted_at
                .as_ref()
                .map(|d: &DateTime<Utc>| d.to_rfc3339()),
        };
        let archive = Archive {
            status: archive_status,
            format: task.archive_format.clone(),
            expires_at: task.expires_at.as_ref().map(|d| d.to_rfc3339()),
        };
        let pins = Pins {
            status: pins_status,
        };
        let (archive_opt, pins_opt) = match task.storage_mode.as_str() {
            "archive" => (Some(archive), None),
            "ipfs" => (None, Some(pins)),
            "full" => (Some(archive), Some(pins)),
            _ => (None, None),
        };
        BackupResponse {
            task_id: task.task_id.clone(),
            created_at: task.created_at.to_rfc3339(),
            storage_mode: task.storage_mode.clone(),
            tokens,
            total_tokens,
            page,
            limit,
            archive: archive_opt,
            pins: pins_opt,
        }
    }
}

#[cfg(test)]
mod from_backup_task_tests {
    use super::{BackupResponse, Tokens};
    use crate::server::database::BackupTask;
    use chrono::{TimeZone, Utc};

    fn sample_task() -> BackupTask {
        BackupTask {
            task_id: "task123".to_string(),
            created_at: Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            updated_at: Utc.timestamp_opt(1_700_000_500, 0).unwrap(),
            requestor: "did:privy:alice".to_string(),
            nft_count: 3,
            tokens: serde_json::json!([]),
            archive_status: Some("done".to_string()),
            ipfs_status: Some("in_progress".to_string()),
            archive_error_log: Some("arch warnings".to_string()),
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: Some("provider error".to_string()),
            storage_mode: "full".to_string(),
            archive_format: Some("zip".to_string()),
            expires_at: Some(Utc.timestamp_opt(1_700_086_400, 0).unwrap()), // +1 day
            archive_deleted_at: Some(Utc.timestamp_opt(1_700_000_800, 0).unwrap()),
            pins_deleted_at: Some(Utc.timestamp_opt(1_700_000_900, 0).unwrap()),
        }
    }

    #[test]
    fn maps_all_fields_with_some_values() {
        let task = sample_task();
        let tokens = vec![Tokens {
            chain: "ethereum".to_string(),
            tokens: vec!["0xabc:1".to_string(), "0xabc:2".to_string()],
        }];
        let resp = BackupResponse::from_backup_task(&task, tokens.clone(), 3, 2, 50);
        assert_eq!(resp.task_id, task.task_id);
        assert_eq!(resp.created_at, task.created_at.to_rfc3339());
        assert_eq!(resp.storage_mode, task.storage_mode);
        assert_eq!(resp.total_tokens, 3);
        assert_eq!(resp.page, 2);
        assert_eq!(resp.limit, 50);
        assert_eq!(resp.tokens.len(), 1);
        assert_eq!(resp.tokens[0].chain, "ethereum");
        let archive = resp.archive.as_ref().unwrap();
        assert_eq!(archive.format.as_deref(), Some("zip"));
        assert_eq!(
            archive.expires_at.as_deref(),
            Some(task.expires_at.unwrap().to_rfc3339().as_str())
        );
        // Archive status
        assert_eq!(archive.status.status.as_deref(), Some("done"));
        assert_eq!(archive.status.error_log.as_deref(), Some("arch warnings"));
        assert_eq!(archive.status.fatal_error, None);
        assert_eq!(
            archive.status.deleted_at.as_deref(),
            Some(task.archive_deleted_at.unwrap().to_rfc3339().as_str())
        );
        // Pins status
        let pins = resp.pins.as_ref().unwrap();
        assert_eq!(pins.status.status.as_deref(), Some("in_progress"));
        assert_eq!(pins.status.error_log, None);
        assert_eq!(pins.status.fatal_error.as_deref(), Some("provider error"));
        assert_eq!(
            pins.status.deleted_at.as_deref(),
            Some(task.pins_deleted_at.unwrap().to_rfc3339().as_str())
        );
    }

    #[test]
    fn maps_none_values_as_none() {
        let mut task = sample_task();
        task.archive_status = None;
        task.ipfs_status = None;
        task.archive_error_log = None;
        task.ipfs_error_log = None;
        task.archive_fatal_error = None;
        task.ipfs_fatal_error = None;
        task.archive_format = None;
        task.expires_at = None;
        task.archive_deleted_at = None;
        task.pins_deleted_at = None;
        task.storage_mode = "ipfs".to_string();

        let resp = BackupResponse::from_backup_task(&task, Vec::new(), 0, 1, 10);
        assert!(resp.archive.is_none());
        assert!(resp.pins.is_some());
        assert!(resp.tokens.is_empty());
        assert_eq!(resp.total_tokens, 0);
        assert_eq!(resp.page, 1);
        assert_eq!(resp.limit, 10);
    }
}

// RFC 7807 problem+json error shape
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiProblem {
    /// A URI reference that identifies the problem type
    #[serde(default = "default_problem_type")]
    #[schema(example = "about:blank")]
    pub r#type: String,
    /// A short, human-readable summary of the problem type
    #[schema(example = "Bad Request")]
    pub title: String,
    /// The HTTP status code generated by the origin server for this occurrence of the problem
    #[schema(example = 400, minimum = 100, maximum = 599)]
    pub status: u16,
    /// A human-readable explanation specific to this occurrence of the problem
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "The request body is invalid")]
    pub detail: Option<String>,
    /// A URI reference that identifies the specific occurrence of the problem
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schema(example = "/v1/backups")]
    pub instance: Option<String>,
}

fn default_problem_type() -> String {
    "about:blank".to_string()
}

impl ApiProblem {
    pub fn new(status: StatusCode, detail: Option<String>, instance: Option<String>) -> Self {
        let title = status.canonical_reason().unwrap_or("Error").to_string();
        Self {
            r#type: default_problem_type(),
            title,
            status: status.as_u16(),
            detail,
            instance,
        }
    }
    pub fn new_with_title(
        status: StatusCode,
        title: &str,
        detail: Option<String>,
        instance: Option<String>,
    ) -> Self {
        Self {
            r#type: default_problem_type(),
            title: title.to_string(),
            status: status.as_u16(),
            detail,
            instance,
        }
    }
}

/// Responder that serializes an `ApiProblem` with `application/problem+json` content type
pub struct ProblemJson(pub ApiProblem);

impl ProblemJson {
    pub fn from_status(
        status: StatusCode,
        detail: Option<String>,
        instance: Option<String>,
    ) -> Self {
        Self(ApiProblem::new(status, detail, instance))
    }
}

impl IntoResponse for ProblemJson {
    fn into_response(self) -> axum::response::Response {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/problem+json"),
        );
        let status =
            StatusCode::from_u16(self.0.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, headers, Json(self.0)).into_response()
    }
}

#[cfg(test)]
mod api_problem_tests {
    use super::ApiProblem;
    use axum::http::StatusCode;

    #[test]
    fn derives_title_from_status() {
        let p = ApiProblem::new(
            StatusCode::BAD_REQUEST,
            Some("detail".to_string()),
            Some("/v1/x".to_string()),
        );
        assert_eq!(p.title, "Bad Request");
        assert_eq!(p.status, 400);
        assert_eq!(p.r#type, "about:blank");
        assert_eq!(p.instance.as_deref(), Some("/v1/x"));
        assert_eq!(p.detail.as_deref(), Some("detail"));
    }

    #[test]
    fn allows_custom_title() {
        let p = ApiProblem::new_with_title(StatusCode::NOT_FOUND, "Resource Missing", None, None);
        assert_eq!(p.title, "Resource Missing");
        assert_eq!(p.status, 404);
    }

    #[test]
    fn serializes_and_deserializes() {
        let p = ApiProblem::new(
            StatusCode::UNAUTHORIZED,
            Some("auth missing".to_string()),
            Some("/v1/secure".to_string()),
        );
        let json = serde_json::to_string(&p).unwrap();
        let back: ApiProblem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title, p.title);
        assert_eq!(back.status, p.status);
        assert_eq!(back.instance, p.instance);
        assert_eq!(back.detail, p.detail);
    }
}
