use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupMetadataRow {
    pub task_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub requestor: String,
    pub archive_format: String,
    pub nft_count: i32,
    pub tokens: serde_json::Value,
    pub status: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub error_log: Option<String>,
    pub fatal_error: Option<String>,
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

    pub async fn insert_backup_metadata(
        &self,
        task_id: &str,
        requestor: &str,
        archive_format: &str,
        nft_count: i32,
        tokens: &serde_json::Value,
        retention_days: Option<u64>,
    ) -> Result<(), sqlx::Error> {
        let (expires_at_sql, expires_at_arg) = if let Some(days) = retention_days {
            ("NOW() + ($6 || ' days')::interval", Some(days as i64))
        } else {
            ("NULL", None)
        };
        let query = format!(
            r#"
            INSERT INTO backup_metadata (
                task_id, created_at, updated_at, requestor, archive_format, nft_count, tokens, expires_at
            ) VALUES (
                $1, NOW(), NOW(), $2, $3, $4, $5, {expires_at_sql}
            )
            ON CONFLICT (task_id) DO UPDATE SET
                updated_at = NOW(),
                status = EXCLUDED.status,
                archive_format = EXCLUDED.archive_format,
                nft_count = EXCLUDED.nft_count,
                tokens = EXCLUDED.tokens,
                expires_at = {expires_at_sql},
                error_log = EXCLUDED.error_log
            "#,
        );
        if let Some(days) = expires_at_arg {
            sqlx::query(&query)
                .bind(task_id)
                .bind(requestor)
                .bind(archive_format)
                .bind(nft_count)
                .bind(tokens)
                .bind(days)
                .execute(&self.pool)
                .await?;
        } else {
            sqlx::query(&query)
                .bind(task_id)
                .bind(requestor)
                .bind(archive_format)
                .bind(nft_count)
                .bind(tokens)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    pub async fn delete_backup_metadata(&self, task_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query!("DELETE FROM backup_metadata WHERE task_id = $1", task_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_backup_metadata_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE backup_metadata
            SET error_log = $2, updated_at = NOW()
            WHERE task_id = $1
            "#,
            task_id,
            error_log
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn update_backup_metadata_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE backup_metadata
            SET status = $2, updated_at = NOW()
            WHERE task_id = $1
            "#,
            task_id,
            status
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn retry_backup(
        &self,
        task_id: &str,
        retention_days: u64,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE backup_metadata
            SET status = 'in_progress', updated_at = NOW(), expires_at = NOW() + ($2 || ' days')::interval, error_log = NULL, fatal_error = NULL
            WHERE task_id = $1
            "#,
            task_id,
            retention_days as i64
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Batch update: set status for multiple task_ids at once
    pub async fn batch_update_backup_status(
        &self,
        task_ids: &[String],
        status: &str,
    ) -> Result<(), sqlx::Error> {
        if task_ids.is_empty() {
            return Ok(());
        }
        // Build the query with a dynamic number of parameters
        let mut query = String::from(
            "UPDATE backup_metadata SET status = $1, updated_at = NOW() WHERE task_id IN (",
        );
        for (i, _) in task_ids.iter().enumerate() {
            if i > 0 {
                query.push_str(", ");
            }
            query.push_str(&format!("${}", i + 2));
        }
        query.push(')');
        let mut q = sqlx::query(&query).bind(status);
        for task_id in task_ids {
            q = q.bind(task_id);
        }
        q.execute(&self.pool).await?;
        Ok(())
    }

    pub async fn clear_backup_errors(&self, task_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE backup_metadata
            SET error_log = NULL, fatal_error = NULL
            WHERE task_id = $1
            "#,
            task_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn set_backup_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE backup_metadata
            SET status = 'error', fatal_error = $2, updated_at = NOW()
            WHERE task_id = $1
            "#,
            task_id,
            fatal_error
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_backup_metadata(
        &self,
        task_id: &str,
    ) -> Result<Option<BackupMetadataRow>, sqlx::Error> {
        let rec = sqlx::query_as!(
            BackupMetadataRow,
            r#"
            SELECT task_id, created_at, updated_at, requestor, archive_format, nft_count, tokens, status, expires_at, error_log, fatal_error
            FROM backup_metadata WHERE task_id = $1
            "#,
            task_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec)
    }

    pub async fn list_requestor_backups(
        &self,
        requestor: &str,
        include_tokens: bool,
    ) -> Result<Vec<BackupMetadataRow>, sqlx::Error> {
        let tokens_field = if include_tokens { "tokens," } else { "" };

        let query = format!(
            r#"
            SELECT task_id, created_at, updated_at, requestor, archive_format, nft_count, {tokens_field} status, expires_at, error_log, fatal_error
            FROM backup_metadata WHERE requestor = $1
            ORDER BY created_at DESC
            "#,
        );

        let rows = sqlx::query(&query)
            .bind(requestor)
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

                BackupMetadataRow {
                    task_id: row.get("task_id"),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                    requestor: row.get("requestor"),
                    archive_format: row.get("archive_format"),
                    nft_count: row.get("nft_count"),
                    tokens,
                    status: row.get("status"),
                    expires_at: row.get("expires_at"),
                    error_log: row.get("error_log"),
                    fatal_error: row.get("fatal_error"),
                }
            })
            .collect();

        Ok(recs)
    }

    pub async fn list_unprocessed_expired_backups(
        &self,
    ) -> Result<Vec<ExpiredBackup>, sqlx::Error> {
        let recs = sqlx::query_as!(
            ExpiredBackup,
            r#"
            SELECT task_id, archive_format FROM backup_metadata WHERE expires_at IS NOT NULL AND expires_at < NOW() AND status != 'expired'
            "#
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(recs)
    }

    pub async fn get_backup_status(&self, task_id: &str) -> Result<Option<String>, sqlx::Error> {
        let rec = sqlx::query!(
            r#"SELECT status FROM backup_metadata WHERE task_id = $1"#,
            task_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec.map(|r| r.status))
    }

    /// Retrieve all backup jobs that are in 'in_progress' status
    /// This is used to recover incomplete jobs on server restart
    pub async fn get_incomplete_backup_jobs(&self) -> Result<Vec<BackupMetadataRow>, sqlx::Error> {
        let rows = sqlx::query!(
            r#"
            SELECT task_id, created_at, updated_at, requestor, archive_format, nft_count, tokens, status, expires_at, error_log, fatal_error
            FROM backup_metadata 
            WHERE status = 'in_progress'
            ORDER BY created_at ASC
            "#
        )
        .fetch_all(&self.pool)
        .await?;

        let recs = rows
            .into_iter()
            .map(|row| BackupMetadataRow {
                task_id: row.task_id,
                created_at: row.created_at,
                updated_at: row.updated_at,
                requestor: row.requestor,
                archive_format: row.archive_format,
                nft_count: row.nft_count,
                tokens: row.tokens,
                status: row.status,
                expires_at: row.expires_at,
                error_log: row.error_log,
                fatal_error: row.fatal_error,
            })
            .collect();

        Ok(recs)
    }

    /// Insert pin request rows for a given requestor
    pub async fn insert_pin_requests(
        &self,
        requestor: &str,
        pins: &[crate::ipfs::PinResponse],
    ) -> Result<(), sqlx::Error> {
        if pins.is_empty() {
            return Ok(());
        }
        // Build a single multi-values INSERT for efficiency
        let mut query = String::from(
            "INSERT INTO pin_requests (provider, cid, request_id, status, requestor) VALUES ",
        );
        let mut bind_count = 0;
        for i in 0..pins.len() {
            if i > 0 {
                query.push_str(", ");
            }
            // 5 bind params per row
            let p1 = bind_count + 1;
            let p2 = bind_count + 2;
            let p3 = bind_count + 3;
            let p4 = bind_count + 4;
            let p5 = bind_count + 5;
            bind_count += 5;
            query.push_str(&format!("(${}, ${}, ${}, ${}, ${})", p1, p2, p3, p4, p5));
        }
        let mut q = sqlx::query(&query);
        for pin in pins {
            // Map status enum to lowercase string to satisfy CHECK constraint
            let status = match pin.status {
                crate::ipfs::PinResponseStatus::Queued => "queued",
                crate::ipfs::PinResponseStatus::Pinning => "pinning",
                crate::ipfs::PinResponseStatus::Pinned => "pinned",
                crate::ipfs::PinResponseStatus::Failed => "failed",
            };
            q = q
                .bind(&pin.provider)
                .bind(&pin.cid)
                .bind(&pin.id)
                .bind(status)
                .bind(requestor);
        }

        q.execute(&self.pool).await?;
        Ok(())
    }
}
