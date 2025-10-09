use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtectionJobRow {
    pub task_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub requestor: String,
    pub nft_count: i32,
    pub tokens: serde_json::Value,
    pub status: String,
    pub error_log: Option<String>,
    pub fatal_error: Option<String>,
    pub storage_mode: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupRequestRow {
    pub task_id: String,
    pub archive_format: String,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Combined view of protection_jobs + backup_requests for backwards compatibility
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProtectionJobWithBackup {
    pub task_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub requestor: String,
    pub nft_count: i32,
    pub tokens: serde_json::Value,
    pub status: String,
    pub error_log: Option<String>,
    pub fatal_error: Option<String>,
    pub storage_mode: String,
    pub archive_format: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PinRequestRow {
    pub id: i64,
    pub task_id: String,
    pub provider: String,
    pub cid: String,
    pub request_id: String,
    pub status: String,
    pub requestor: String,
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
    pub async fn insert_protection_job(
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

        // Insert into protection_jobs
        sqlx::query(
            r#"
            INSERT INTO protection_jobs (
                task_id, created_at, updated_at, requestor, nft_count, tokens, storage_mode
            ) VALUES (
                $1, NOW(), NOW(), $2, $3, $4, $5
            )
            ON CONFLICT (task_id) DO UPDATE SET
                updated_at = NOW(),
                status = EXCLUDED.status,
                nft_count = EXCLUDED.nft_count,
                tokens = EXCLUDED.tokens,
                storage_mode = EXCLUDED.storage_mode,
                error_log = EXCLUDED.error_log
            "#,
        )
        .bind(task_id)
        .bind(requestor)
        .bind(nft_count)
        .bind(tokens)
        .bind(storage_mode)
        .execute(&mut *tx)
        .await?;

        // Insert into backup_requests if storage mode includes filesystem
        if storage_mode == "filesystem" || storage_mode == "both" {
            let archive_fmt = archive_format.unwrap_or("zip");

            if let Some(days) = retention_days {
                sqlx::query(
                    r#"
                    INSERT INTO backup_requests (task_id, archive_format, expires_at)
                    VALUES ($1, $2, NOW() + ($3 || ' days')::interval)
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
                    INSERT INTO backup_requests (task_id, archive_format, expires_at)
                    VALUES ($1, $2, NULL)
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

        tx.commit().await?;
        Ok(())
    }

    pub async fn delete_protection_job(&self, task_id: &str) -> Result<(), sqlx::Error> {
        // CASCADE will delete associated backup_requests row if it exists
        sqlx::query!("DELETE FROM protection_jobs WHERE task_id = $1", task_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn update_protection_job_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE protection_jobs
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

    pub async fn update_protection_job_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE protection_jobs
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
        let mut tx = self.pool.begin().await?;

        // Update protection job
        sqlx::query!(
            r#"
            UPDATE protection_jobs
            SET status = 'in_progress', updated_at = NOW(), error_log = NULL, fatal_error = NULL
            WHERE task_id = $1
            "#,
            task_id
        )
        .execute(&mut *tx)
        .await?;

        // Update backup_requests expires_at if it exists
        sqlx::query!(
            r#"
            UPDATE backup_requests
            SET expires_at = NOW() + ($2 || ' days')::interval
            WHERE task_id = $1
            "#,
            task_id,
            retention_days as i64
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
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
            "UPDATE protection_jobs SET status = $1, updated_at = NOW() WHERE task_id IN (",
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
            UPDATE protection_jobs
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
            UPDATE protection_jobs
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

    pub async fn get_protection_job(
        &self,
        task_id: &str,
    ) -> Result<Option<ProtectionJobWithBackup>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT 
                pj.task_id, pj.created_at, pj.updated_at, pj.requestor, pj.nft_count, 
                pj.tokens, pj.status, pj.error_log, pj.fatal_error, pj.storage_mode,
                br.archive_format, br.expires_at
            FROM protection_jobs pj
            LEFT JOIN backup_requests br ON pj.task_id = br.task_id
            WHERE pj.task_id = $1
            "#,
        )
        .bind(task_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|row| ProtectionJobWithBackup {
            task_id: row.get("task_id"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            requestor: row.get("requestor"),
            nft_count: row.get("nft_count"),
            tokens: row.get("tokens"),
            status: row.get("status"),
            error_log: row.get("error_log"),
            fatal_error: row.get("fatal_error"),
            storage_mode: row.get("storage_mode"),
            archive_format: row.get("archive_format"),
            expires_at: row.get("expires_at"),
        }))
    }

    pub async fn list_requestor_protection_jobs(
        &self,
        requestor: &str,
        include_tokens: bool,
    ) -> Result<Vec<ProtectionJobWithBackup>, sqlx::Error> {
        let tokens_field = if include_tokens { "pj.tokens," } else { "" };

        let query = format!(
            r#"
            SELECT 
                pj.task_id, pj.created_at, pj.updated_at, pj.requestor, pj.nft_count, 
                {tokens_field} pj.status, pj.error_log, pj.fatal_error, pj.storage_mode,
                br.archive_format, br.expires_at
            FROM protection_jobs pj
            LEFT JOIN backup_requests br ON pj.task_id = br.task_id
            WHERE pj.requestor = $1
            ORDER BY pj.created_at DESC
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

                ProtectionJobWithBackup {
                    task_id: row.get("task_id"),
                    created_at: row.get("created_at"),
                    updated_at: row.get("updated_at"),
                    requestor: row.get("requestor"),
                    nft_count: row.get("nft_count"),
                    tokens,
                    status: row.get("status"),
                    error_log: row.get("error_log"),
                    fatal_error: row.get("fatal_error"),
                    storage_mode: row.get("storage_mode"),
                    archive_format: row.get("archive_format"),
                    expires_at: row.get("expires_at"),
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
            SELECT pj.task_id, br.archive_format 
            FROM protection_jobs pj
            JOIN backup_requests br ON pj.task_id = br.task_id
            WHERE br.expires_at IS NOT NULL AND br.expires_at < NOW() AND pj.status != 'expired'
            "#
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(recs)
    }

    pub async fn get_backup_status(&self, task_id: &str) -> Result<Option<String>, sqlx::Error> {
        let rec = sqlx::query!(
            r#"SELECT status FROM protection_jobs WHERE task_id = $1"#,
            task_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(rec.map(|r| r.status))
    }

    /// Retrieve all protection jobs that are in 'in_progress' status
    /// This is used to recover incomplete jobs on server restart
    pub async fn get_incomplete_protection_jobs(
        &self,
    ) -> Result<Vec<ProtectionJobWithBackup>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT 
                pj.task_id, pj.created_at, pj.updated_at, pj.requestor, pj.nft_count, 
                pj.tokens, pj.status, pj.error_log, pj.fatal_error, pj.storage_mode,
                br.archive_format, br.expires_at
            FROM protection_jobs pj
            LEFT JOIN backup_requests br ON pj.task_id = br.task_id
            WHERE pj.status = 'in_progress'
            ORDER BY pj.created_at ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        let recs = rows
            .into_iter()
            .map(|row| ProtectionJobWithBackup {
                task_id: row.get("task_id"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
                requestor: row.get("requestor"),
                nft_count: row.get("nft_count"),
                tokens: row.get("tokens"),
                status: row.get("status"),
                error_log: row.get("error_log"),
                fatal_error: row.get("fatal_error"),
                storage_mode: row.get("storage_mode"),
                archive_format: row.get("archive_format"),
                expires_at: row.get("expires_at"),
            })
            .collect();

        Ok(recs)
    }

    /// Insert pin requests and their associated tokens in a single atomic transaction
    pub async fn insert_pin_requests_with_tokens(
        &self,
        task_id: &str,
        requestor: &str,
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

        // Insert pin requests and return generated IDs
        let mut query = String::from(
            "INSERT INTO pin_requests (task_id, provider, cid, request_id, status, requestor) VALUES ",
        );
        let mut bind_count = 0;
        for i in 0..all_pin_responses.len() {
            if i > 0 {
                query.push_str(", ");
            }
            // 6 bind params per row
            let p1 = bind_count + 1;
            let p2 = bind_count + 2;
            let p3 = bind_count + 3;
            let p4 = bind_count + 4;
            let p5 = bind_count + 5;
            let p6 = bind_count + 6;
            bind_count += 6;
            query.push_str(&format!("(${p1}, ${p2}, ${p3}, ${p4}, ${p5}, ${p6})"));
        }
        query.push_str(" RETURNING id");

        let mut q = sqlx::query(&query);
        for pin_response in &all_pin_responses {
            // Map status enum to lowercase string to satisfy CHECK constraint
            let status = match pin_response.status {
                crate::ipfs::PinResponseStatus::Queued => "queued",
                crate::ipfs::PinResponseStatus::Pinning => "pinning",
                crate::ipfs::PinResponseStatus::Pinned => "pinned",
                crate::ipfs::PinResponseStatus::Failed => "failed",
            };
            q = q
                .bind(task_id)
                .bind(&pin_response.provider)
                .bind(&pin_response.cid)
                .bind(&pin_response.id)
                .bind(status)
                .bind(requestor);
        }
        let rows = q.fetch_all(&mut *tx).await?;

        // Extract generated IDs
        let pin_request_ids: Vec<i64> = rows.iter().map(|row| row.get("id")).collect();

        // Insert pinned tokens using the generated pin_request_ids
        if !all_token_data.is_empty() {
            let mut query = String::from(
                "INSERT INTO pinned_tokens (pin_request_id, chain, contract_address, token_id) VALUES ",
            );
            let mut bind_count = 0;
            for i in 0..all_token_data.len() {
                if i > 0 {
                    query.push_str(", ");
                }
                // 4 bind params per row
                let p1 = bind_count + 1;
                let p2 = bind_count + 2;
                let p3 = bind_count + 3;
                let p4 = bind_count + 4;
                bind_count += 4;
                query.push_str(&format!("(${p1}, ${p2}, ${p3}, ${p4})"));
            }
            let mut q = sqlx::query(&query);
            for (index, chain, contract_address, token_id) in &all_token_data {
                q = q
                    .bind(pin_request_ids[*index])
                    .bind(chain)
                    .bind(contract_address)
                    .bind(token_id);
            }
            q.execute(&mut *tx).await?;
        }

        // Commit the transaction
        tx.commit().await?;
        Ok(())
    }

    /// Get all pin requests for a specific protection job
    pub async fn get_pin_requests_by_task_id(
        &self,
        task_id: &str,
    ) -> Result<Vec<PinRequestRow>, sqlx::Error> {
        let rows = sqlx::query_as!(
            PinRequestRow,
            r#"
            SELECT id, task_id, provider, cid, request_id, status, requestor
            FROM pin_requests
            WHERE task_id = $1
            ORDER BY id
            "#,
            task_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    /// Get all pinned tokens for a requestor
    pub async fn get_pinned_tokens_by_requestor(
        &self,
        requestor: &str,
    ) -> Result<Vec<TokenWithPins>, sqlx::Error> {
        let query = r#"
            SELECT pt.chain, pt.contract_address, pt.token_id,
                   pr.cid, pr.provider, pr.status, pt.created_at
            FROM pinned_tokens pt
            JOIN pin_requests pr ON pr.id = pt.pin_request_id
            WHERE pr.requestor = $1
            ORDER BY pt.chain, pt.contract_address, pt.token_id, pt.created_at DESC
        "#;

        let rows = sqlx::query(query)
            .bind(requestor)
            .fetch_all(&self.pool)
            .await?;

        // Group pins by token
        let mut token_map: std::collections::HashMap<(String, String, String), TokenWithPins> =
            std::collections::HashMap::new();

        for row in rows {
            let chain: String = row.get("chain");
            let contract_address: String = row.get("contract_address");
            let token_id: String = row.get("token_id");
            let cid: String = row.get("cid");
            let provider: String = row.get("provider");
            let status: String = row.get("status");
            let created_at: DateTime<Utc> = row.get("created_at");

            let key = (chain.clone(), contract_address.clone(), token_id.clone());

            let pin_info = PinInfo {
                cid,
                provider,
                status,
                created_at,
            };

            token_map
                .entry(key)
                .or_insert_with(|| TokenWithPins {
                    chain,
                    contract_address,
                    token_id,
                    pins: Vec::new(),
                })
                .pins
                .push(pin_info);
        }

        let mut result: Vec<TokenWithPins> = token_map.into_values().collect();
        result.sort_by(|a, b| {
            a.chain
                .cmp(&b.chain)
                .then(a.contract_address.cmp(&b.contract_address))
                .then(a.token_id.cmp(&b.token_id))
        });

        Ok(result)
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
                   pr.cid, pr.provider, pr.status, pt.created_at
            FROM pinned_tokens pt
            JOIN pin_requests pr ON pr.id = pt.pin_request_id
            WHERE pr.requestor = $1
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
            let provider: String = row.get("provider");
            let status: String = row.get("status");
            let created_at: DateTime<Utc> = row.get("created_at");

            pins.push(PinInfo {
                cid,
                provider,
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
}

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct PinInfo {
    pub cid: String,
    pub provider: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone, utoipa::ToSchema)]
pub struct TokenWithPins {
    pub chain: String,
    pub contract_address: String,
    pub token_id: String,
    pub pins: Vec<PinInfo>,
}
