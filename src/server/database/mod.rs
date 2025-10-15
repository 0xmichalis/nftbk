use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

use crate::server::database::r#trait::Database;

pub mod r#trait;

/// Combined view of backup_tasks + archive_requests
#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
#[schema(description = "Backup task information including metadata and status")]
pub struct BackupTask {
    /// Unique identifier for the backup task
    #[schema(example = "abc123def456")]
    pub task_id: String,
    /// When the backup task was created (ISO 8601 timestamp)
    #[schema(example = "2024-01-01T12:00:00Z")]
    pub created_at: DateTime<Utc>,
    /// When the backup task was last updated (ISO 8601 timestamp)
    #[schema(example = "2024-01-01T12:05:00Z")]
    pub updated_at: DateTime<Utc>,
    /// User who requested the backup
    #[schema(example = "user123")]
    pub requestor: String,
    /// Number of NFTs in this backup task
    #[schema(example = 42)]
    pub nft_count: i32,
    /// Token details (only included if include_tokens=true)
    pub tokens: serde_json::Value,
    /// Archive subresource status (in_progress, done, error, expired)
    pub archive_status: Option<String>,
    /// IPFS subresource status (in_progress, done, error)
    pub ipfs_status: Option<String>,
    /// Detailed archive error log if archive completed with some failures
    #[schema(example = "Failed to write archive checksum file")]
    pub archive_error_log: Option<String>,
    /// Detailed IPFS error log aggregated from pin requests
    #[schema(
        example = "Provider pinata failed: 401 Unauthorized\nProvider web3.storage failed: 429 Too Many Requests"
    )]
    pub ipfs_error_log: Option<String>,
    /// Archive subresource fatal error if backup failed completely at archive stage
    pub archive_fatal_error: Option<String>,
    /// IPFS subresource fatal error if backup failed completely at IPFS stage
    pub ipfs_fatal_error: Option<String>,
    /// Storage mode used for the backup (archive, ipfs, full)
    #[schema(example = "archive")]
    pub storage_mode: String,
    /// Archive format used for the backup (zip, tar.gz)
    #[schema(example = "zip")]
    pub archive_format: Option<String>,
    /// When the backup expires (if applicable, typically 7 days from creation)
    #[schema(example = "2024-01-08T12:00:00Z")]
    pub expires_at: Option<DateTime<Utc>>,
    /// When archive deletion was started (if applicable)
    #[schema(example = "2024-01-02T10:00:00Z")]
    pub archive_deleted_at: Option<DateTime<Utc>>,
    /// When IPFS pins deletion was started (if applicable)
    #[schema(example = "2024-01-02T10:00:00Z")]
    pub pins_deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
#[schema(description = "IPFS pin information for a specific CID")]
pub struct PinInfo {
    /// Content Identifier (CID) of the pinned content
    #[schema(example = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG")]
    pub cid: String,
    /// IPFS provider type where the content is pinned
    #[schema(example = "pinata")]
    pub provider_type: String,
    /// IPFS provider URL where the content is pinned
    #[schema(example = "https://api.pinata.cloud")]
    pub provider_url: String,
    /// Pin status (pinned, pinning, failed, queued)
    #[schema(example = "pinned")]
    pub status: String,
    /// When the pin was created (ISO 8601 timestamp)
    #[schema(example = "2024-01-01T12:00:00Z")]
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
#[schema(description = "Token information with associated pin requests")]
pub struct TokenWithPins {
    /// Blockchain identifier (e.g., ethereum, tezos)
    #[schema(example = "ethereum")]
    pub chain: String,
    /// NFT contract address
    #[schema(example = "0x1234567890123456789012345678901234567890")]
    pub contract_address: String,
    /// NFT token ID
    #[schema(example = "123")]
    pub token_id: String,
    /// List of IPFS pins for this token
    pub pins: Vec<PinInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PinRow {
    pub id: i64,
    pub task_id: String,
    pub provider_type: String,
    pub provider_url: Option<String>,
    pub cid: String,
    pub request_id: String,
    pub pin_status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct ExpiredBackup {
    pub task_id: String,
    pub archive_format: String,
}

#[derive(Clone)]
pub struct Db {
    pub pool: PgPool,
}

impl Db {
    pub async fn new(database_url: &str, max_connections: u32) -> Self {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await
            .expect("Failed to connect to Postgres");
        // Health check: run a simple query
        sqlx::query("SELECT 1")
            .execute(&pool)
            .await
            .expect("Postgres connection is not healthy");
        tracing::info!("Postgres connection is healthy");
        Db { pool }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn insert_backup_task(
        &self,
        task_id: &str,
        requestor: &str,
        nft_count: i32,
        tokens: &serde_json::Value,
        storage_mode: &str,
        archive_format: Option<&str>,
        retention_days: Option<u64>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // Insert into backup_tasks
        sqlx::query(
            r#"
            INSERT INTO backup_tasks (
                task_id, created_at, updated_at, requestor, nft_count, tokens, storage_mode
            ) VALUES (
                $1, NOW(), NOW(), $2, $3, $4, $5
            )
            ON CONFLICT (task_id) DO UPDATE SET
                updated_at = NOW(),
                nft_count = EXCLUDED.nft_count,
                tokens = EXCLUDED.tokens,
                storage_mode = EXCLUDED.storage_mode
            "#,
        )
        .bind(task_id)
        .bind(requestor)
        .bind(nft_count)
        .bind(tokens)
        .bind(storage_mode)
        .execute(&mut *tx)
        .await?;

        // Insert into archive_requests if storage mode includes archive
        if storage_mode == "archive" || storage_mode == "full" {
            let archive_fmt = archive_format.unwrap_or("zip");

            if let Some(days) = retention_days {
                sqlx::query(
                    r#"
                    INSERT INTO archive_requests (task_id, archive_format, expires_at, status)
                    VALUES ($1, $2, NOW() + make_interval(days => $3::int), 'in_progress')
                    ON CONFLICT (task_id) DO UPDATE SET
                        archive_format = EXCLUDED.archive_format,
                        expires_at = EXCLUDED.expires_at
                    "#,
                )
                .bind(task_id)
                .bind(archive_fmt)
                .bind(days as i64)
                .execute(&mut *tx)
                .await?;
            } else {
                sqlx::query(
                    r#"
                    INSERT INTO archive_requests (task_id, archive_format, expires_at, status)
                    VALUES ($1, $2, NULL, 'in_progress')
                    ON CONFLICT (task_id) DO UPDATE SET
                        archive_format = EXCLUDED.archive_format,
                        expires_at = EXCLUDED.expires_at
                    "#,
                )
                .bind(task_id)
                .bind(archive_fmt)
                .execute(&mut *tx)
                .await?;
            }
        }

        // Insert into pin_requests if storage mode includes IPFS
        if storage_mode == "ipfs" || storage_mode == "full" {
            sqlx::query(
                r#"
                INSERT INTO pin_requests (task_id, status)
                VALUES ($1, 'in_progress')
                ON CONFLICT (task_id) DO UPDATE SET
                    status = EXCLUDED.status
                "#,
            )
            .bind(task_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub async fn delete_backup_task(&self, task_id: &str) -> Result<(), sqlx::Error> {
        // CASCADE will delete associated archive_requests row if it exists
        sqlx::query!("DELETE FROM backup_tasks WHERE task_id = $1", task_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn set_error_logs(
        &self,
        task_id: &str,
        archive_error_log: Option<&str>,
        ipfs_error_log: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        if let Some(a) = archive_error_log {
            sqlx::query("UPDATE archive_requests SET error_log = $2 WHERE task_id = $1")
                .bind(task_id)
                .bind(a)
                .execute(&mut *tx)
                .await?;
        }
        if let Some(i) = ipfs_error_log {
            sqlx::query(
                r#"
                    UPDATE pin_requests
                    SET error_log = $2
                    WHERE task_id = $1
                    "#,
            )
            .bind(task_id)
            .bind(i)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn update_archive_request_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE archive_requests
            SET error_log = $2
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .bind(error_log)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_pin_request_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE pin_requests
            SET error_log = $2
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .bind(error_log)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_pin_request_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE pin_requests
            SET status = $2
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .bind(status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_archive_request_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE archive_requests
            SET status = $2
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .bind(status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_archive_request_statuses(
        &self,
        task_ids: &[String],
        status: &str,
    ) -> Result<(), sqlx::Error> {
        if task_ids.is_empty() {
            return Ok(());
        }

        // Use a transaction for atomicity
        let mut tx = self.pool.begin().await?;

        // Update each task_id individually with a prepared statement
        for task_id in task_ids {
            sqlx::query("UPDATE archive_requests SET status = $1 WHERE task_id = $2")
                .bind(status)
                .bind(task_id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub async fn retry_backup(
        &self,
        task_id: &str,
        scope: &str,
        retention_days: u64,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // Reset statuses per requested scope
        if scope == "archive" || scope == "full" {
            sqlx::query(
                r#"
                UPDATE archive_requests
                SET status = 'in_progress', fatal_error = NULL, error_log = NULL
                WHERE task_id = $1
                "#,
            )
            .bind(task_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                r#"
                UPDATE archive_requests
                SET expires_at = NOW() + make_interval(days => $2::int)
                WHERE task_id = $1
                "#,
            )
            .bind(task_id)
            .bind(retention_days as i64)
            .execute(&mut *tx)
            .await?;
        }
        if scope == "ipfs" || scope == "full" {
            sqlx::query(
                r#"
                UPDATE pin_requests
                SET status = 'in_progress', fatal_error = NULL, error_log = NULL
                WHERE task_id = $1
                "#,
            )
            .bind(task_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub async fn clear_backup_errors(&self, task_id: &str, scope: &str) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;
        // Clear archive errors if scope includes archive
        sqlx::query(
            r#"
            UPDATE archive_requests
            SET error_log = NULL, fatal_error = NULL
            WHERE task_id = $1 AND ($2 IN ('archive', 'full'))
            "#,
        )
        .bind(task_id)
        .bind(scope)
        .execute(&mut *tx)
        .await?;
        // Clear IPFS errors if scope includes ipfs
        sqlx::query(
            r#"
            UPDATE pin_requests
            SET error_log = NULL, fatal_error = NULL
            WHERE task_id = $1 AND ($2 IN ('ipfs', 'full'))
            "#,
        )
        .bind(task_id)
        .bind(scope)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_archive_request_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE archive_requests
            SET status = 'error', fatal_error = $2
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .bind(fatal_error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_pin_request_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE pin_requests
            SET status = 'error', fatal_error = $2
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .bind(fatal_error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn start_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // Touch parent row
        sqlx::query!(
            r#"UPDATE backup_tasks SET updated_at = NOW() WHERE task_id = $1"#,
            task_id
        )
        .execute(&mut *tx)
        .await?;

        // Mark archive subresource as being deleted
        sqlx::query!(
            r#"
            UPDATE archive_requests
            SET deleted_at = NOW()
            WHERE task_id = $1 AND deleted_at IS NULL
            "#,
            task_id
        )
        .execute(&mut *tx)
        .await?;

        // Mark IPFS subresource as being deleted
        sqlx::query!(
            r#"
            UPDATE pin_requests
            SET deleted_at = NOW()
            WHERE task_id = $1 AND deleted_at IS NULL
            "#,
            task_id
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Mark archive as being deleted (similar to start_deletion but for archive subresource)
    pub async fn start_archive_request_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE archive_requests 
            SET deleted_at = NOW() 
            WHERE task_id = $1 AND deleted_at IS NULL
            "#,
            task_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark IPFS pins as being deleted (similar to start_deletion but for IPFS pins subresource)
    pub async fn start_pin_request_deletions(&self, task_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE pin_requests 
            SET deleted_at = NOW() 
            WHERE task_id = $1 AND deleted_at IS NULL
            "#,
            task_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_backup_task(&self, task_id: &str) -> Result<Option<BackupTask>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT 
                b.task_id, b.created_at, b.updated_at, b.requestor, b.nft_count, 
                b.tokens, ar.status as archive_status, ar.fatal_error, b.storage_mode,
                ar.archive_format, ar.expires_at, ar.deleted_at as archive_deleted_at,
                ar.error_log as archive_error_log,
                pr.status as ipfs_status,
                pr.error_log as ipfs_error_log,
                pr.fatal_error as ipfs_fatal_error,
                pr.deleted_at as pins_deleted_at
            FROM backup_tasks b
            LEFT JOIN archive_requests ar ON b.task_id = ar.task_id
            LEFT JOIN pin_requests pr ON b.task_id = pr.task_id
            WHERE b.task_id = $1
            "#,
        )
        .bind(task_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| BackupTask {
            task_id: row.get("task_id"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            requestor: row.get("requestor"),
            nft_count: row.get("nft_count"),
            tokens: row.get("tokens"),
            archive_status: row
                .try_get::<Option<String>, _>("archive_status")
                .ok()
                .flatten(),
            ipfs_status: row
                .try_get::<Option<String>, _>("ipfs_status")
                .ok()
                .flatten(),
            archive_error_log: row.get("archive_error_log"),
            ipfs_error_log: row.get("ipfs_error_log"),
            archive_fatal_error: row.get("fatal_error"),
            ipfs_fatal_error: row
                .try_get::<Option<String>, _>("ipfs_fatal_error")
                .ok()
                .flatten(),
            storage_mode: row.get("storage_mode"),
            archive_format: row.get("archive_format"),
            expires_at: row.get("expires_at"),
            archive_deleted_at: row.get("archive_deleted_at"),
            pins_deleted_at: row.get("pins_deleted_at"),
        }))
    }

    pub async fn list_requestor_backup_tasks_paginated(
        &self,
        requestor: &str,
        include_tokens: bool,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<BackupTask>, u32), sqlx::Error> {
        let tokens_field = if include_tokens { "b.tokens," } else { "" };

        // Total count
        let total_row = sqlx::query!(
            r#"SELECT COUNT(*) as count FROM backup_tasks b WHERE b.requestor = $1"#,
            requestor
        )
        .fetch_one(&self.pool)
        .await?;
        let total: u32 = (total_row.count.unwrap_or(0) as i64).max(0) as u32;

        let query = format!(
            r#"
            SELECT 
                b.task_id, b.created_at, b.updated_at, b.requestor, b.nft_count, 
                {tokens_field} ar.status as archive_status, ar.fatal_error, b.storage_mode,
                ar.archive_format, ar.expires_at, ar.deleted_at as archive_deleted_at,
                ar.error_log as archive_error_log,
                pr.status as ipfs_status,
                pr.error_log as ipfs_error_log,
                pr.fatal_error as ipfs_fatal_error,
                pr.deleted_at as pins_deleted_at
            FROM backup_tasks b
            LEFT JOIN archive_requests ar ON b.task_id = ar.task_id
            LEFT JOIN pin_requests pr ON b.task_id = pr.task_id
            WHERE b.requestor = $1
            ORDER BY b.created_at DESC
            LIMIT $2 OFFSET $3
            "#,
        );

        let rows = sqlx::query(&query)
            .bind(requestor)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;

        let recs = rows
            .into_iter()
            .map(|row| {
                let tokens = if include_tokens {
                    row.try_get::<serde_json::Value, _>("tokens")
                        .unwrap_or(serde_json::Value::Null)
                } else {
                    serde_json::Value::Null
                };

                BackupTask {
                    task_id: row.get("task_id"),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                    requestor: row.get("requestor"),
                    nft_count: row.get("nft_count"),
                    tokens,
                    archive_status: row
                        .try_get::<Option<String>, _>("archive_status")
                        .ok()
                        .flatten(),
                    ipfs_status: row
                        .try_get::<Option<String>, _>("ipfs_status")
                        .ok()
                        .flatten(),
                    archive_error_log: row.get("archive_error_log"),
                    ipfs_error_log: row.get("ipfs_error_log"),
                    archive_fatal_error: row.get("fatal_error"),
                    ipfs_fatal_error: row
                        .try_get::<Option<String>, _>("ipfs_fatal_error")
                        .ok()
                        .flatten(),
                    storage_mode: row.get("storage_mode"),
                    archive_format: row.get("archive_format"),
                    expires_at: row.get("expires_at"),
                    archive_deleted_at: row.get("archive_deleted_at"),
                    pins_deleted_at: row.get("pins_deleted_at"),
                }
            })
            .collect();

        Ok((recs, total))
    }

    pub async fn list_unprocessed_expired_backups(
        &self,
    ) -> Result<Vec<ExpiredBackup>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT b.task_id, ar.archive_format 
            FROM backup_tasks b
            JOIN archive_requests ar ON b.task_id = ar.task_id
            WHERE ar.expires_at IS NOT NULL AND ar.expires_at < NOW() AND ar.status != 'expired'
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        let recs = rows
            .into_iter()
            .map(|row| ExpiredBackup {
                task_id: row.get("task_id"),
                archive_format: row.get("archive_format"),
            })
            .collect();
        Ok(recs)
    }

    /// Retrieve all backup tasks that are in 'in_progress' status
    /// This is used to recover incomplete tasks on server restart
    pub async fn get_incomplete_backup_tasks(&self) -> Result<Vec<BackupTask>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT 
                b.task_id, b.created_at, b.updated_at, b.requestor, b.nft_count, 
                b.tokens, ar.status as archive_status, ar.fatal_error, b.storage_mode,
                ar.archive_format, ar.expires_at, ar.deleted_at as archive_deleted_at,
                ar.error_log as archive_error_log,
                pr.status as ipfs_status,
                pr.error_log as ipfs_error_log,
                pr.deleted_at as pins_deleted_at
            FROM backup_tasks b
            LEFT JOIN archive_requests ar ON b.task_id = ar.task_id
            LEFT JOIN pin_requests pr ON b.task_id = pr.task_id
            WHERE (
                -- Archive-only mode: check archive status (record must exist and be in_progress)
                (b.storage_mode = 'archive' AND ar.status = 'in_progress')
                OR
                -- IPFS-only mode: check IPFS status (record must exist and be in_progress)
                (b.storage_mode = 'ipfs' AND pr.status = 'in_progress')
                OR
                -- Full mode: check both archive and IPFS status (task is incomplete if either is in_progress)
                (b.storage_mode = 'full' AND (ar.status = 'in_progress' OR pr.status = 'in_progress'))
            )
            ORDER BY b.created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let recs = rows
            .into_iter()
            .map(|row| BackupTask {
                task_id: row.get("task_id"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                requestor: row.get("requestor"),
                nft_count: row.get("nft_count"),
                tokens: row.get("tokens"),
                archive_status: row
                    .try_get::<Option<String>, _>("archive_status")
                    .ok()
                    .flatten(),
                ipfs_status: row
                    .try_get::<Option<String>, _>("ipfs_status")
                    .ok()
                    .flatten(),
                archive_error_log: row.get("archive_error_log"),
                ipfs_error_log: row.get("ipfs_error_log"),
                archive_fatal_error: row.get("fatal_error"),
                ipfs_fatal_error: None,
                storage_mode: row.get("storage_mode"),
                archive_format: row.get("archive_format"),
                expires_at: row.get("expires_at"),
                archive_deleted_at: row.get("archive_deleted_at"),
                pins_deleted_at: row.get("pins_deleted_at"),
            })
            .collect();

        Ok(recs)
    }

    /// Insert pins and their associated tokens in a single atomic transaction
    pub async fn insert_pins_with_tokens(
        &self,
        task_id: &str,
        token_pin_mappings: &[crate::TokenPinMapping],
    ) -> Result<(), sqlx::Error> {
        if token_pin_mappings.is_empty() {
            return Ok(());
        }

        // Collect all pin responses and prepare token data
        let mut all_pin_responses = Vec::new();
        let mut all_token_data = Vec::new(); // (index_in_pin_responses, chain, contract_address, token_id)

        for mapping in token_pin_mappings {
            for pin_response in &mapping.pin_responses {
                let index = all_pin_responses.len();
                all_pin_responses.push(pin_response);
                all_token_data.push((
                    index,
                    mapping.chain.clone(),
                    mapping.contract_address.clone(),
                    mapping.token_id.clone(),
                ));
            }
        }

        if all_pin_responses.is_empty() {
            return Ok(());
        }

        // Start a transaction for atomicity
        let mut tx = self.pool.begin().await?;

        // Insert pins one by one and collect generated IDs
        let mut pin_ids: Vec<i64> = Vec::new();
        for pin_response in &all_pin_responses {
            // Map status enum to lowercase string to satisfy CHECK constraint
            let status = match pin_response.status {
                crate::ipfs::PinResponseStatus::Queued => "queued",
                crate::ipfs::PinResponseStatus::Pinning => "pinning",
                crate::ipfs::PinResponseStatus::Pinned => "pinned",
                crate::ipfs::PinResponseStatus::Failed => "failed",
            };

            let row = sqlx::query(
                "INSERT INTO pins (task_id, provider_type, provider_url, cid, request_id, pin_status) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id"
            )
            .bind(task_id)
            .bind(&pin_response.provider_type)
            .bind(&pin_response.provider_url)
            .bind(&pin_response.cid)
            .bind(&pin_response.id)
            .bind(status)
            .fetch_one(&mut *tx)
            .await?;

            pin_ids.push(row.get("id"));
        }

        // Insert pinned tokens using the generated pin_ids
        for (index, chain, contract_address, token_id) in &all_token_data {
            sqlx::query(
                "INSERT INTO pinned_tokens (pin_id, chain, contract_address, token_id) VALUES ($1, $2, $3, $4)"
            )
            .bind(pin_ids[*index])
            .bind(chain)
            .bind(contract_address)
            .bind(token_id)
            .execute(&mut *tx)
            .await?;
        }

        // Commit the transaction
        tx.commit().await?;
        Ok(())
    }

    /// Get all pins for a specific backup task
    pub async fn get_pins_by_task_id(&self, task_id: &str) -> Result<Vec<PinRow>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, task_id, provider_type, provider_url, cid, request_id, pin_status, created_at
            FROM pins
            WHERE task_id = $1
            ORDER BY id
            "#,
        )
        .bind(task_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| PinRow {
                id: row.get("id"),
                task_id: row.get("task_id"),
                provider_type: row.get("provider_type"),
                provider_url: row
                    .try_get::<Option<String>, _>("provider_url")
                    .ok()
                    .flatten(),
                cid: row.get("cid"),
                request_id: row.get("request_id"),
                pin_status: row.get("pin_status"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    /// Paginated pinned tokens grouped by (chain, contract_address, token_id)
    pub async fn get_pinned_tokens_by_requestor(
        &self,
        requestor: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<TokenWithPins>, u32), sqlx::Error> {
        // Total distinct tokens for this requestor
        let total_row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM (
                SELECT DISTINCT pt.chain, pt.contract_address, pt.token_id
                FROM pinned_tokens pt
                JOIN pins p ON p.id = pt.pin_id
                JOIN backup_tasks bt ON bt.task_id = p.task_id
                WHERE bt.requestor = $1
            ) t
            "#,
        )
        .bind(requestor)
        .fetch_one(&self.pool)
        .await?;
        let total: u32 = (total_row.get::<i64, _>("count")).max(0) as u32;

        // Page of distinct tokens ordered by most recent pin time
        let rows = sqlx::query(
            r#"
            SELECT t.chain, t.contract_address, t.token_id
            FROM (
                SELECT pt.chain, pt.contract_address, pt.token_id, MAX(pt.created_at) AS last_created
                FROM pinned_tokens pt
                JOIN pins p ON p.id = pt.pin_id
                JOIN backup_tasks bt ON bt.task_id = p.task_id
                WHERE bt.requestor = $1
                GROUP BY pt.chain, pt.contract_address, pt.token_id
            ) t
            ORDER BY last_created DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(requestor)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        // For each token key, fetch pins (ordered by created_at desc)
        let mut result: Vec<TokenWithPins> = Vec::new();
        for r in rows {
            let token_rows = sqlx::query(
                r#"
                SELECT pt.chain, pt.contract_address, pt.token_id,
                       p.cid, p.provider_type, p.provider_url, p.pin_status, pt.created_at
                FROM pinned_tokens pt
                JOIN pins p ON p.id = pt.pin_id
                JOIN backup_tasks bt ON bt.task_id = p.task_id
                WHERE bt.requestor = $1
                  AND pt.chain = $2
                  AND pt.contract_address = $3
                  AND pt.token_id = $4
                ORDER BY pt.created_at DESC
                "#,
            )
            .bind(requestor)
            .bind(r.get::<String, _>("chain"))
            .bind(r.get::<String, _>("contract_address"))
            .bind(r.get::<String, _>("token_id"))
            .fetch_all(&self.pool)
            .await?;

            let mut pins: Vec<PinInfo> = Vec::new();
            let mut chain = String::new();
            let mut contract_address = String::new();
            let mut token_id = String::new();
            for row in token_rows {
                chain = row.get("chain");
                contract_address = row.get("contract_address");
                token_id = row.get("token_id");
                let cid: String = row.get("cid");
                let provider_type: String = row.get("provider_type");
                let provider_url: String = row
                    .try_get::<Option<String>, _>("provider_url")
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                let status: String = row.get("pin_status");
                let created_at: DateTime<Utc> = row.get("created_at");
                pins.push(PinInfo {
                    cid,
                    provider_type,
                    provider_url,
                    status,
                    created_at,
                });
            }
            result.push(TokenWithPins {
                chain,
                contract_address,
                token_id,
                pins,
            });
        }

        Ok((result, total))
    }

    /// Get a specific pinned token for a requestor
    pub async fn get_pinned_token_by_requestor(
        &self,
        requestor: &str,
        chain: &str,
        contract_address: &str,
        token_id: &str,
    ) -> Result<Option<TokenWithPins>, sqlx::Error> {
        let query = r#"
            SELECT pt.chain, pt.contract_address, pt.token_id,
                   p.cid, p.provider_type, p.provider_url, p.pin_status, pt.created_at
            FROM pinned_tokens pt
            JOIN pins p ON p.id = pt.pin_id
            JOIN backup_tasks bt ON bt.task_id = p.task_id
            WHERE bt.requestor = $1
              AND pt.chain = $2
              AND pt.contract_address = $3
              AND pt.token_id = $4
            ORDER BY pt.created_at DESC
        "#;

        let rows = sqlx::query(query)
            .bind(requestor)
            .bind(chain)
            .bind(contract_address)
            .bind(token_id)
            .fetch_all(&self.pool)
            .await?;

        if rows.is_empty() {
            return Ok(None);
        }

        let mut pins = Vec::new();
        let mut token_chain = String::new();
        let mut token_contract_address = String::new();
        let mut token_token_id = String::new();

        for row in rows {
            token_chain = row.get("chain");
            token_contract_address = row.get("contract_address");
            token_token_id = row.get("token_id");
            let cid: String = row.get("cid");
            let provider_type: String = row.get("provider_type");
            // provider_url may be NULL for legacy rows; default to empty string for API stability
            let provider_url: String = row
                .try_get::<Option<String>, _>("provider_url")
                .ok()
                .flatten()
                .unwrap_or_default();
            let status: String = row.get("pin_status");
            let created_at: DateTime<Utc> = row.get("created_at");

            pins.push(PinInfo {
                cid,
                provider_type,
                provider_url,
                status,
                created_at,
            });
        }

        Ok(Some(TokenWithPins {
            chain: token_chain,
            contract_address: token_contract_address,
            token_id: token_token_id,
            pins,
        }))
    }

    /// Get all pins that are in 'queued' or 'pinning' status
    /// This is used by the pin monitor to check for status updates
    pub async fn get_active_pins(&self) -> Result<Vec<PinRow>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, task_id, provider_type, provider_url, cid, request_id, pin_status, created_at
            FROM pins
            WHERE pin_status IN ('queued', 'pinning')
            ORDER BY id
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|row| PinRow {
                id: row.get("id"),
                task_id: row.get("task_id"),
                provider_type: row.get("provider_type"),
                provider_url: row
                    .try_get::<Option<String>, _>("provider_url")
                    .ok()
                    .flatten(),
                cid: row.get("cid"),
                request_id: row.get("request_id"),
                pin_status: row.get("pin_status"),
                created_at: row.get("created_at"),
            })
            .collect())
    }

    /// Set backup fatal error for relevant subresources in a single SQL statement.
    /// The update is based on the `storage_mode` value from the `backup_tasks` table for the given `task_id`:
    /// - If storage_mode is 'archive' or 'full': updates archive_requests.status and archive_requests.fatal_error
    /// - If storage_mode is 'ipfs' or 'full': updates pin_requests.status and pin_requests.fatal_error
    pub async fn set_backup_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = r#"
            WITH task_mode AS (
                SELECT storage_mode FROM backup_tasks WHERE task_id = $1
            ),
            upd_archive AS (
                UPDATE archive_requests ar
                SET status = 'error', fatal_error = $2
                WHERE ar.task_id = $1
                  AND EXISTS (
                      SELECT 1 FROM task_mode tm
                      WHERE tm.storage_mode IN ('archive', 'full')
                  )
                RETURNING 1
            ),
            upd_pins AS (
                UPDATE pin_requests pr
                SET status = 'error', fatal_error = $2
                WHERE pr.task_id = $1
                  AND EXISTS (
                      SELECT 1 FROM task_mode tm
                      WHERE tm.storage_mode IN ('ipfs', 'full')
                  )
                RETURNING 1
            )
            SELECT COALESCE((SELECT COUNT(*) FROM upd_archive), 0) AS archive_updates,
                   COALESCE((SELECT COUNT(*) FROM upd_pins), 0)     AS pin_updates
        "#;
        sqlx::query(sql)
            .bind(task_id)
            .bind(fatal_error)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Update backup subresource statuses for the task based on its storage mode
    /// - archive or full: updates archive_requests.status
    /// - ipfs or full: updates pin_requests.status
    pub async fn update_backup_statuses(
        &self,
        task_id: &str,
        scope: &str,
        archive_status: &str,
        ipfs_status: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = r#"
            WITH upd_archive AS (
                UPDATE archive_requests ar
                SET status = $2
                WHERE ar.task_id = $1
                  AND ($4 IN ('archive', 'full'))
                RETURNING 1
            ),
            upd_pins AS (
                UPDATE pin_requests pr
                SET status = $3
                WHERE pr.task_id = $1
                  AND ($4 IN ('ipfs', 'full'))
                RETURNING 1
            )
            SELECT COALESCE((SELECT COUNT(*) FROM upd_archive), 0) AS archive_updates,
                   COALESCE((SELECT COUNT(*) FROM upd_pins), 0)     AS pin_updates
        "#;
        sqlx::query(sql)
            .bind(task_id)
            .bind(archive_status)
            .bind(ipfs_status)
            .bind(scope)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_pin_statuses(&self, updates: &[(i64, String)]) -> Result<(), sqlx::Error> {
        if updates.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;

        for (id, status) in updates {
            sqlx::query(
                r#"
                UPDATE pins
                SET pin_status = $2
                WHERE id = $1
                "#,
            )
            .bind(id)
            .bind(status)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Ensure the missing subresource exists and upgrade the backup to full storage mode.
    /// If `add_archive` is true, create/ensure archive_requests row with provided format/retention.
    /// Otherwise, ensure pin_requests row exists. Always flips backup_tasks.storage_mode to 'full'.
    pub async fn upgrade_backup_to_full(
        &self,
        task_id: &str,
        add_archive: bool,
        archive_format: Option<&str>,
        retention_days: Option<u64>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // Upgrade storage mode to full
        sqlx::query(
            r#"
            UPDATE backup_tasks
            SET storage_mode = 'full', updated_at = NOW()
            WHERE task_id = $1
            "#,
        )
        .bind(task_id)
        .execute(&mut *tx)
        .await?;

        if add_archive {
            let fmt = archive_format.unwrap_or("zip");
            if let Some(days) = retention_days {
                sqlx::query(
                    r#"
                    INSERT INTO archive_requests (task_id, archive_format, expires_at, status)
                    VALUES ($1, $2, NOW() + make_interval(days => $3::int), 'in_progress')
                    ON CONFLICT (task_id) DO NOTHING
                    "#,
                )
                .bind(task_id)
                .bind(fmt)
                .bind(days as i64)
                .execute(&mut *tx)
                .await?;
            } else {
                sqlx::query(
                    r#"
                    INSERT INTO archive_requests (task_id, archive_format, expires_at, status)
                    VALUES ($1, $2, NULL, 'in_progress')
                    ON CONFLICT (task_id) DO NOTHING
                    "#,
                )
                .bind(task_id)
                .bind(fmt)
                .execute(&mut *tx)
                .await?;
            }
        } else {
            sqlx::query(
                r#"
                INSERT INTO pin_requests (task_id, status)
                VALUES ($1, 'in_progress')
                ON CONFLICT (task_id) DO NOTHING
                "#,
            )
            .bind(task_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Complete archive deletion:
    /// - If current storage_mode is 'archive', delete the whole backup (finalize deletion)
    /// - Else if current storage_mode is 'full', flip to 'ipfs' to reflect archive removed
    pub async fn complete_archive_request_deletion(
        &self,
        task_id: &str,
    ) -> Result<(), sqlx::Error> {
        // Atomically: delete when archive-only; else if full, flip to ipfs
        let sql = r#"
            WITH del AS (
                DELETE FROM backup_tasks
                WHERE task_id = $1 AND storage_mode = 'archive'
                RETURNING 1
            ), upd AS (
                UPDATE backup_tasks
                SET storage_mode = 'ipfs', updated_at = NOW()
                WHERE task_id = $1 AND storage_mode = 'full' AND NOT EXISTS (SELECT 1 FROM del)
                RETURNING 1
            )
            SELECT COALESCE((SELECT COUNT(*) FROM del), 0) AS deleted,
                   COALESCE((SELECT COUNT(*) FROM upd), 0) AS updated
        "#;
        let _ = sqlx::query(sql).bind(task_id).execute(&self.pool).await?;
        Ok(())
    }

    /// Complete IPFS pins deletion:
    /// - If current storage_mode is 'ipfs', delete the whole backup (finalize deletion)
    /// - Else if current storage_mode is 'full', flip to 'archive' to reflect pins removed
    pub async fn complete_pin_request_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        // Atomically: delete when ipfs-only; else if full, flip to archive
        let sql = r#"
            WITH del AS (
                DELETE FROM backup_tasks
                WHERE task_id = $1 AND storage_mode = 'ipfs'
                RETURNING 1
            ), upd AS (
                UPDATE backup_tasks
                SET storage_mode = 'archive', updated_at = NOW()
                WHERE task_id = $1 AND storage_mode = 'full' AND NOT EXISTS (SELECT 1 FROM del)
                RETURNING 1
            )
            SELECT COALESCE((SELECT COUNT(*) FROM del), 0) AS deleted,
                   COALESCE((SELECT COUNT(*) FROM upd), 0) AS updated
        "#;
        let _ = sqlx::query(sql).bind(task_id).execute(&self.pool).await?;
        Ok(())
    }
}

// Implement the unified Database trait for the real Db struct
#[async_trait::async_trait]
impl Database for Db {
    // Backup task operations

    async fn insert_backup_task(
        &self,
        task_id: &str,
        requestor: &str,
        nft_count: i32,
        tokens: &serde_json::Value,
        storage_mode: &str,
        archive_format: Option<&str>,
        retention_days: Option<u64>,
    ) -> Result<(), sqlx::Error> {
        Db::insert_backup_task(
            self,
            task_id,
            requestor,
            nft_count,
            tokens,
            storage_mode,
            archive_format,
            retention_days,
        )
        .await
    }

    async fn get_backup_task(&self, task_id: &str) -> Result<Option<BackupTask>, sqlx::Error> {
        Db::get_backup_task(self, task_id).await
    }

    async fn delete_backup_task(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::delete_backup_task(self, task_id).await
    }

    async fn get_incomplete_backup_tasks(&self) -> Result<Vec<BackupTask>, sqlx::Error> {
        Db::get_incomplete_backup_tasks(self).await
    }

    async fn list_requestor_backup_tasks_paginated(
        &self,
        requestor: &str,
        include_tokens: bool,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<BackupTask>, u32), sqlx::Error> {
        Db::list_requestor_backup_tasks_paginated(self, requestor, include_tokens, limit, offset)
            .await
    }

    async fn list_unprocessed_expired_backups(&self) -> Result<Vec<ExpiredBackup>, sqlx::Error> {
        Db::list_unprocessed_expired_backups(self).await
    }

    // Backup task status and error operations
    async fn clear_backup_errors(&self, task_id: &str, scope: &str) -> Result<(), sqlx::Error> {
        Db::clear_backup_errors(self, task_id, scope).await
    }

    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error> {
        Db::set_backup_error(self, task_id, error).await
    }

    async fn set_error_logs(
        &self,
        task_id: &str,
        archive_error_log: Option<&str>,
        ipfs_error_log: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        Db::set_error_logs(self, task_id, archive_error_log, ipfs_error_log).await
    }

    async fn update_archive_request_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_archive_request_error_log(self, task_id, error_log).await
    }

    async fn update_pin_request_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_pin_request_error_log(self, task_id, error_log).await
    }

    async fn set_archive_request_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error> {
        Db::set_archive_request_error(self, task_id, fatal_error).await
    }

    async fn set_pin_request_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error> {
        Db::set_pin_request_error(self, task_id, fatal_error).await
    }

    // Status update operations
    async fn update_archive_request_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_archive_request_status(self, task_id, status).await
    }

    async fn update_pin_request_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_pin_request_status(self, task_id, status).await
    }

    async fn update_backup_statuses(
        &self,
        task_id: &str,
        scope: &str,
        archive_status: &str,
        ipfs_status: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_backup_statuses(self, task_id, scope, archive_status, ipfs_status).await
    }

    async fn update_archive_request_statuses(
        &self,
        task_ids: &[String],
        status: &str,
    ) -> Result<(), sqlx::Error> {
        Db::update_archive_request_statuses(self, task_ids, status).await
    }

    async fn upgrade_backup_to_full(
        &self,
        task_id: &str,
        add_archive: bool,
        archive_format: Option<&str>,
        retention_days: Option<u64>,
    ) -> Result<(), sqlx::Error> {
        Db::upgrade_backup_to_full(self, task_id, add_archive, archive_format, retention_days).await
    }

    // Deletion operations
    async fn start_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::start_deletion(self, task_id).await
    }

    async fn start_archive_request_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::start_archive_request_deletion(self, task_id).await
    }

    async fn start_pin_request_deletions(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::start_pin_request_deletions(self, task_id).await
    }

    async fn complete_archive_request_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::complete_archive_request_deletion(self, task_id).await
    }

    async fn complete_pin_request_deletion(&self, task_id: &str) -> Result<(), sqlx::Error> {
        Db::complete_pin_request_deletion(self, task_id).await
    }

    // Retry operations
    async fn retry_backup(
        &self,
        task_id: &str,
        scope: &str,
        retention_days: u64,
    ) -> Result<(), sqlx::Error> {
        Db::retry_backup(self, task_id, scope, retention_days).await
    }

    // Pin operations
    async fn insert_pins_with_tokens(
        &self,
        task_id: &str,
        token_pin_mappings: &[crate::TokenPinMapping],
    ) -> Result<(), sqlx::Error> {
        Db::insert_pins_with_tokens(self, task_id, token_pin_mappings).await
    }

    async fn get_pins_by_task_id(&self, task_id: &str) -> Result<Vec<PinRow>, sqlx::Error> {
        Db::get_pins_by_task_id(self, task_id).await
    }

    async fn get_active_pins(&self) -> Result<Vec<PinRow>, sqlx::Error> {
        Db::get_active_pins(self).await
    }

    async fn update_pin_statuses(&self, updates: &[(i64, String)]) -> Result<(), sqlx::Error> {
        Db::update_pin_statuses(self, updates).await
    }

    // Pinned tokens operations
    async fn get_pinned_tokens_by_requestor(
        &self,
        requestor: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<TokenWithPins>, u32), sqlx::Error> {
        Db::get_pinned_tokens_by_requestor(self, requestor, limit, offset).await
    }

    async fn get_pinned_token_by_requestor(
        &self,
        requestor: &str,
        chain: &str,
        contract_address: &str,
        token_id: &str,
    ) -> Result<Option<TokenWithPins>, sqlx::Error> {
        Db::get_pinned_token_by_requestor(self, requestor, chain, contract_address, token_id).await
    }
}
