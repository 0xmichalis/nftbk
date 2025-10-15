use async_trait::async_trait;
use serde_json;
use sqlx;

use crate::server::database::{BackupTask, ExpiredBackup, PinRow, TokenWithPins};
use crate::TokenPinMapping;

/// Unified database trait that consolidates all database operations
#[async_trait]
pub trait Database {
    // Backup task operations
    #[allow(clippy::too_many_arguments)]
    async fn insert_backup_task(
        &self,
        task_id: &str,
        requestor: &str,
        nft_count: i32,
        tokens: &serde_json::Value,
        storage_mode: &str,
        archive_format: Option<&str>,
        retention_days: Option<u64>,
    ) -> Result<(), sqlx::Error>;

    async fn get_backup_task(&self, task_id: &str) -> Result<Option<BackupTask>, sqlx::Error>;

    async fn delete_backup_task(&self, task_id: &str) -> Result<(), sqlx::Error>;

    async fn get_incomplete_backup_tasks(&self) -> Result<Vec<BackupTask>, sqlx::Error>;

    async fn list_requestor_backup_tasks_paginated(
        &self,
        requestor: &str,
        include_tokens: bool,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<BackupTask>, u32), sqlx::Error>;

    async fn list_unprocessed_expired_backups(&self) -> Result<Vec<ExpiredBackup>, sqlx::Error>;

    // Backup task status and error operations
    async fn clear_backup_errors(&self, task_id: &str, scope: &str) -> Result<(), sqlx::Error>;

    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error>;

    async fn set_error_logs(
        &self,
        task_id: &str,
        archive_error_log: Option<&str>,
        ipfs_error_log: Option<&str>,
    ) -> Result<(), sqlx::Error>;

    async fn update_archive_request_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error>;

    async fn update_pin_request_error_log(
        &self,
        task_id: &str,
        error_log: &str,
    ) -> Result<(), sqlx::Error>;

    async fn set_archive_request_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error>;

    async fn set_pin_request_error(
        &self,
        task_id: &str,
        fatal_error: &str,
    ) -> Result<(), sqlx::Error>;

    // Status update operations
    async fn update_archive_request_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error>;

    async fn update_pin_request_status(
        &self,
        task_id: &str,
        status: &str,
    ) -> Result<(), sqlx::Error>;

    async fn update_backup_statuses(
        &self,
        task_id: &str,
        scope: &str,
        archive_status: &str,
        ipfs_status: &str,
    ) -> Result<(), sqlx::Error>;

    async fn update_archive_request_statuses(
        &self,
        task_ids: &[String],
        status: &str,
    ) -> Result<(), sqlx::Error>;

    // Deletion operations
    async fn start_deletion(&self, task_id: &str) -> Result<(), sqlx::Error>;

    async fn start_archive_request_deletion(&self, task_id: &str) -> Result<(), sqlx::Error>;

    async fn start_pin_request_deletions(&self, task_id: &str) -> Result<(), sqlx::Error>;

    async fn complete_archive_deletion(&self, task_id: &str) -> Result<(), sqlx::Error>;

    async fn complete_ipfs_pins_deletion(&self, task_id: &str) -> Result<(), sqlx::Error>;

    // Retry operations
    async fn retry_backup(&self, task_id: &str, retention_days: u64) -> Result<(), sqlx::Error>;

    // Pin operations
    async fn insert_pins_with_tokens(
        &self,
        task_id: &str,
        token_pin_mappings: &[TokenPinMapping],
    ) -> Result<(), sqlx::Error>;

    async fn get_pins_by_task_id(&self, task_id: &str) -> Result<Vec<PinRow>, sqlx::Error>;

    async fn get_active_pins(&self) -> Result<Vec<PinRow>, sqlx::Error>;

    async fn batch_update_pin_statuses(&self, updates: &[(i64, String)])
        -> Result<(), sqlx::Error>;

    // Pinned tokens operations
    async fn get_pinned_tokens_by_requestor(
        &self,
        requestor: &str,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<TokenWithPins>, u32), sqlx::Error>;

    async fn get_pinned_token_by_requestor(
        &self,
        requestor: &str,
        chain: &str,
        contract_address: &str,
        token_id: &str,
    ) -> Result<Option<TokenWithPins>, sqlx::Error>;
}

/// Configurable mock database implementation for testing
/// Each method can be configured to return specific responses or errors
#[derive(Default)]
pub struct MockDatabase {
    // Backup task operations
    pub insert_backup_task_error: Option<String>,
    pub get_backup_task_result: Option<BackupTask>,
    pub get_backup_task_error: Option<String>,
    pub delete_backup_task_error: Option<String>,
    pub get_incomplete_backup_tasks_result: Vec<BackupTask>,
    pub get_incomplete_backup_tasks_error: Option<String>,
    pub list_requestor_backup_tasks_paginated_result: (Vec<BackupTask>, u32),
    pub list_requestor_backup_tasks_paginated_error: Option<String>,
    pub list_unprocessed_expired_backups_result: Vec<ExpiredBackup>,
    pub list_unprocessed_expired_backups_error: Option<String>,

    // Backup task status and error operations
    pub clear_backup_errors_error: Option<String>,
    pub set_backup_error_error: Option<String>,
    pub set_error_logs_error: Option<String>,
    pub update_archive_request_error_log_error: Option<String>,
    pub update_pin_request_error_log_error: Option<String>,
    pub set_archive_request_error_error: Option<String>,
    pub set_pin_request_error_error: Option<String>,

    // Status update operations
    pub update_archive_request_status_error: Option<String>,
    pub update_pin_request_status_error: Option<String>,
    pub update_backup_statuses_error: Option<String>,
    pub update_archive_request_statuses_error: Option<String>,

    // Deletion operations
    pub start_deletion_error: Option<String>,
    pub start_archive_request_deletion_error: Option<String>,
    pub start_pin_request_deletions_error: Option<String>,
    pub complete_archive_deletion_error: Option<String>,
    pub complete_ipfs_pins_deletion_error: Option<String>,

    // Retry operations
    pub retry_backup_error: Option<String>,

    // Pin operations
    pub insert_pins_with_tokens_error: Option<String>,
    pub get_pins_by_task_id_result: Vec<PinRow>,
    pub get_pins_by_task_id_error: Option<String>,
    pub get_active_pins_result: Vec<PinRow>,
    pub get_active_pins_error: Option<String>,
    pub batch_update_pin_statuses_error: Option<String>,

    // Pinned tokens operations
    pub get_pinned_tokens_by_requestor_result: (Vec<TokenWithPins>, u32),
    pub get_pinned_tokens_by_requestor_error: Option<String>,
    pub get_pinned_token_by_requestor_result: Option<TokenWithPins>,
    pub get_pinned_token_by_requestor_error: Option<String>,
}

impl MockDatabase {
    // Configuration methods for backup task operations
    pub fn set_insert_backup_task_error(&mut self, error: Option<String>) {
        self.insert_backup_task_error = error;
    }

    pub fn set_get_backup_task_result(&mut self, result: Option<BackupTask>) {
        self.get_backup_task_result = result;
    }

    pub fn set_get_backup_task_error(&mut self, error: Option<String>) {
        self.get_backup_task_error = error;
    }

    pub fn set_delete_backup_task_error(&mut self, error: Option<String>) {
        self.delete_backup_task_error = error;
    }

    pub fn set_get_incomplete_backup_tasks_result(&mut self, result: Vec<BackupTask>) {
        self.get_incomplete_backup_tasks_result = result;
    }

    pub fn set_get_incomplete_backup_tasks_error(&mut self, error: Option<String>) {
        self.get_incomplete_backup_tasks_error = error;
    }

    pub fn set_list_requestor_backup_tasks_paginated_result(
        &mut self,
        result: (Vec<BackupTask>, u32),
    ) {
        self.list_requestor_backup_tasks_paginated_result = result;
    }

    pub fn set_list_requestor_backup_tasks_paginated_error(&mut self, error: Option<String>) {
        self.list_requestor_backup_tasks_paginated_error = error;
    }

    pub fn set_list_unprocessed_expired_backups_result(&mut self, result: Vec<ExpiredBackup>) {
        self.list_unprocessed_expired_backups_result = result;
    }

    pub fn set_list_unprocessed_expired_backups_error(&mut self, error: Option<String>) {
        self.list_unprocessed_expired_backups_error = error;
    }

    // Configuration methods for backup task status and error operations
    pub fn set_clear_backup_errors_error(&mut self, error: Option<String>) {
        self.clear_backup_errors_error = error;
    }

    pub fn set_set_backup_error_error(&mut self, error: Option<String>) {
        self.set_backup_error_error = error;
    }

    pub fn set_set_error_logs_error(&mut self, error: Option<String>) {
        self.set_error_logs_error = error;
    }

    pub fn set_update_archive_request_error_log_error(&mut self, error: Option<String>) {
        self.update_archive_request_error_log_error = error;
    }

    pub fn set_update_pin_request_error_log_error(&mut self, error: Option<String>) {
        self.update_pin_request_error_log_error = error;
    }

    pub fn set_set_archive_request_error_error(&mut self, error: Option<String>) {
        self.set_archive_request_error_error = error;
    }

    pub fn set_set_pin_request_error_error(&mut self, error: Option<String>) {
        self.set_pin_request_error_error = error;
    }

    // Configuration methods for status update operations
    pub fn set_update_archive_request_status_error(&mut self, error: Option<String>) {
        self.update_archive_request_status_error = error;
    }

    pub fn set_update_pin_request_status_error(&mut self, error: Option<String>) {
        self.update_pin_request_status_error = error;
    }

    pub fn set_update_backup_statuses_error(&mut self, error: Option<String>) {
        self.update_backup_statuses_error = error;
    }

    pub fn set_update_archive_request_statuses_error(&mut self, error: Option<String>) {
        self.update_archive_request_statuses_error = error;
    }

    // Configuration methods for deletion operations
    pub fn set_start_deletion_error(&mut self, error: Option<String>) {
        self.start_deletion_error = error;
    }

    pub fn set_start_archive_request_deletion_error(&mut self, error: Option<String>) {
        self.start_archive_request_deletion_error = error;
    }

    pub fn set_start_pin_request_deletions_error(&mut self, error: Option<String>) {
        self.start_pin_request_deletions_error = error;
    }

    pub fn set_complete_archive_deletion_error(&mut self, error: Option<String>) {
        self.complete_archive_deletion_error = error;
    }

    pub fn set_complete_ipfs_pins_deletion_error(&mut self, error: Option<String>) {
        self.complete_ipfs_pins_deletion_error = error;
    }

    // Configuration methods for retry operations
    pub fn set_retry_backup_error(&mut self, error: Option<String>) {
        self.retry_backup_error = error;
    }

    // Configuration methods for pin operations
    pub fn set_insert_pins_with_tokens_error(&mut self, error: Option<String>) {
        self.insert_pins_with_tokens_error = error;
    }

    pub fn set_get_pins_by_task_id_result(&mut self, result: Vec<PinRow>) {
        self.get_pins_by_task_id_result = result;
    }

    pub fn set_get_pins_by_task_id_error(&mut self, error: Option<String>) {
        self.get_pins_by_task_id_error = error;
    }

    pub fn set_get_active_pins_result(&mut self, result: Vec<PinRow>) {
        self.get_active_pins_result = result;
    }

    pub fn set_get_active_pins_error(&mut self, error: Option<String>) {
        self.get_active_pins_error = error;
    }

    pub fn set_batch_update_pin_statuses_error(&mut self, error: Option<String>) {
        self.batch_update_pin_statuses_error = error;
    }

    // Configuration methods for pinned tokens operations
    pub fn set_get_pinned_tokens_by_requestor_result(&mut self, result: (Vec<TokenWithPins>, u32)) {
        self.get_pinned_tokens_by_requestor_result = result;
    }

    pub fn set_get_pinned_tokens_by_requestor_error(&mut self, error: Option<String>) {
        self.get_pinned_tokens_by_requestor_error = error;
    }

    pub fn set_get_pinned_token_by_requestor_result(&mut self, result: Option<TokenWithPins>) {
        self.get_pinned_token_by_requestor_result = result;
    }

    pub fn set_get_pinned_token_by_requestor_error(&mut self, error: Option<String>) {
        self.get_pinned_token_by_requestor_error = error;
    }
}

#[async_trait]
impl Database for MockDatabase {
    // Backup task operations
    async fn insert_backup_task(
        &self,
        _task_id: &str,
        _requestor: &str,
        _nft_count: i32,
        _tokens: &serde_json::Value,
        _storage_mode: &str,
        _archive_format: Option<&str>,
        _retention_days: Option<u64>,
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.insert_backup_task_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn get_backup_task(&self, _task_id: &str) -> Result<Option<BackupTask>, sqlx::Error> {
        if let Some(error) = &self.get_backup_task_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(self.get_backup_task_result.clone())
        }
    }

    async fn delete_backup_task(&self, _task_id: &str) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.delete_backup_task_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn get_incomplete_backup_tasks(&self) -> Result<Vec<BackupTask>, sqlx::Error> {
        if let Some(error) = &self.get_incomplete_backup_tasks_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(self.get_incomplete_backup_tasks_result.clone())
        }
    }

    async fn list_requestor_backup_tasks_paginated(
        &self,
        _requestor: &str,
        _include_tokens: bool,
        limit: i64,
        offset: i64,
    ) -> Result<(Vec<BackupTask>, u32), sqlx::Error> {
        if let Some(error) = &self.list_requestor_backup_tasks_paginated_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            let (all_records, total_count) = &self.list_requestor_backup_tasks_paginated_result;
            let start = offset.max(0) as usize;
            let end = (start + limit.max(0) as usize).min(all_records.len());
            let page = if start < all_records.len() {
                all_records[start..end].to_vec()
            } else {
                Vec::new()
            };
            Ok((page, *total_count))
        }
    }

    async fn list_unprocessed_expired_backups(&self) -> Result<Vec<ExpiredBackup>, sqlx::Error> {
        if let Some(error) = &self.list_unprocessed_expired_backups_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(self.list_unprocessed_expired_backups_result.clone())
        }
    }

    // Backup task status and error operations
    async fn clear_backup_errors(&self, _task_id: &str, _scope: &str) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.clear_backup_errors_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn set_backup_error(&self, _task_id: &str, _error: &str) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.set_backup_error_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn set_error_logs(
        &self,
        _task_id: &str,
        _archive_error_log: Option<&str>,
        _ipfs_error_log: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.set_error_logs_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn update_archive_request_error_log(
        &self,
        _task_id: &str,
        _error_log: &str,
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.update_archive_request_error_log_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn update_pin_request_error_log(
        &self,
        _task_id: &str,
        _error_log: &str,
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.update_pin_request_error_log_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn set_archive_request_error(
        &self,
        _task_id: &str,
        _fatal_error: &str,
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.set_archive_request_error_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn set_pin_request_error(
        &self,
        _task_id: &str,
        _fatal_error: &str,
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.set_pin_request_error_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    // Status update operations
    async fn update_archive_request_status(
        &self,
        _task_id: &str,
        _status: &str,
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.update_archive_request_status_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn update_pin_request_status(
        &self,
        _task_id: &str,
        _status: &str,
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.update_pin_request_status_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn update_backup_statuses(
        &self,
        _task_id: &str,
        _scope: &str,
        _archive_status: &str,
        _ipfs_status: &str,
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.update_backup_statuses_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn update_archive_request_statuses(
        &self,
        _task_ids: &[String],
        _status: &str,
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.update_archive_request_statuses_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    // Deletion operations
    async fn start_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.start_deletion_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn start_archive_request_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.start_archive_request_deletion_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn start_pin_request_deletions(&self, _task_id: &str) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.start_pin_request_deletions_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn complete_archive_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.complete_archive_deletion_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn complete_ipfs_pins_deletion(&self, _task_id: &str) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.complete_ipfs_pins_deletion_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    // Retry operations
    async fn retry_backup(&self, _task_id: &str, _retention_days: u64) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.retry_backup_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    // Pin operations
    async fn insert_pins_with_tokens(
        &self,
        _task_id: &str,
        _token_pin_mappings: &[TokenPinMapping],
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.insert_pins_with_tokens_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    async fn get_pins_by_task_id(&self, _task_id: &str) -> Result<Vec<PinRow>, sqlx::Error> {
        if let Some(error) = &self.get_pins_by_task_id_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(self.get_pins_by_task_id_result.clone())
        }
    }

    async fn get_active_pins(&self) -> Result<Vec<PinRow>, sqlx::Error> {
        if let Some(error) = &self.get_active_pins_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(self.get_active_pins_result.clone())
        }
    }

    async fn batch_update_pin_statuses(
        &self,
        _updates: &[(i64, String)],
    ) -> Result<(), sqlx::Error> {
        if let Some(error) = &self.batch_update_pin_statuses_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(())
        }
    }

    // Pinned tokens operations
    async fn get_pinned_tokens_by_requestor(
        &self,
        _requestor: &str,
        _limit: i64,
        _offset: i64,
    ) -> Result<(Vec<TokenWithPins>, u32), sqlx::Error> {
        if let Some(error) = &self.get_pinned_tokens_by_requestor_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(self.get_pinned_tokens_by_requestor_result.clone())
        }
    }

    async fn get_pinned_token_by_requestor(
        &self,
        _requestor: &str,
        _chain: &str,
        _contract_address: &str,
        _token_id: &str,
    ) -> Result<Option<TokenWithPins>, sqlx::Error> {
        if let Some(error) = &self.get_pinned_token_by_requestor_error {
            Err(sqlx::Error::Configuration(error.clone().into()))
        } else {
            Ok(self.get_pinned_token_by_requestor_result.clone())
        }
    }
}
