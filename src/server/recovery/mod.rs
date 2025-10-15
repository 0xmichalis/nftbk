use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::server::api::Tokens;
use crate::server::database::r#trait::Database;
use crate::server::{BackupTask, BackupTaskOrShutdown, StorageMode, TaskType};

/// Recover incomplete backup tasks from the database and enqueue them for processing
/// This is called on server startup to handle tasks that were interrupted by server shutdown
pub async fn recover_incomplete_tasks<DB: Database + ?Sized>(
    db: &DB,
    backup_task_sender: &mpsc::Sender<BackupTaskOrShutdown>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    debug!("Recovering incomplete backup tasks from database...");

    let incomplete_tasks = db.get_incomplete_backup_tasks().await?;
    let task_count = incomplete_tasks.len();

    if task_count == 0 {
        debug!("No incomplete backup tasks found");
        return Ok(0);
    }

    debug!("Found {task_count} incomplete backup tasks, re-queueing...");

    for task_meta in incomplete_tasks {
        let task_id = task_meta.task_id.clone();
        let scope = task_meta.storage_mode.parse().unwrap_or(StorageMode::Full);

        // TODO: This could be batched
        let _ = db.clear_backup_errors(&task_id, scope.as_str()).await;

        // Parse the tokens JSON back to Vec<Tokens>
        let tokens: Vec<Tokens> = match serde_json::from_value(task_meta.tokens.clone()) {
            Ok(tokens) => tokens,
            Err(e) => {
                warn!("Failed to parse tokens for backup task {task_id}: {e}, skipping",);
                // Mark this task as error since we can't process it
                let _ = db
                    .set_backup_error(
                        &task_id,
                        &format!("Failed to parse tokens during recovery: {e}"),
                    )
                    .await;
                continue;
            }
        };

        let storage_mode = task_meta.storage_mode.parse().unwrap_or(StorageMode::Full);
        let pin_on_ipfs = storage_mode != StorageMode::Archive;
        let create_archive = storage_mode != StorageMode::Ipfs;

        let backup_task = BackupTask {
            task_id: task_meta.task_id.clone(),
            request: crate::server::api::BackupRequest {
                tokens,
                pin_on_ipfs,
                create_archive,
            },
            scope: storage_mode,
            archive_format: task_meta.archive_format,
            requestor: Some(task_meta.requestor),
        };

        // Try to enqueue the task
        if let Err(e) = backup_task_sender
            .send(BackupTaskOrShutdown::Task(TaskType::Creation(backup_task)))
            .await
        {
            warn!(
                "Failed to enqueue recovered task {}: {}",
                task_meta.task_id, e
            );
            // Mark as error if we can't enqueue it
            let _ = db
                .set_backup_error(
                    &task_meta.task_id,
                    &format!("Failed to enqueue during recovery: {e}"),
                )
                .await;
        } else {
            debug!("Re-queued backup task: {}", task_meta.task_id);
        }
    }

    Ok(task_count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::database::r#trait::MockDatabase;
    use crate::server::database::BackupTask as DbBackupTask;
    use chrono::Utc;
    use serde_json::json;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_recover_incomplete_tasks_no_tasks() {
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_incomplete_backup_tasks_result(vec![]);
        let (tx, _rx) = mpsc::channel(10);

        let result = recover_incomplete_tasks(&mock_db, &tx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_recover_incomplete_tasks_success() {
        let mut mock_db = MockDatabase::default();
        let tasks = vec![
            DbBackupTask {
                task_id: "task1".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                requestor: "user1".to_string(),
                nft_count: 0,
                tokens: json!([{ "chain": "ethereum", "tokens": ["0x123"] }]),
                archive_status: Some("in_progress".to_string()),
                ipfs_status: None,
                archive_error_log: None,
                ipfs_error_log: None,
                archive_fatal_error: None,
                ipfs_fatal_error: None,
                storage_mode: "archive".to_string(),
                archive_format: Some("zip".to_string()),
                expires_at: None,
                archive_deleted_at: None,
                pins_deleted_at: None,
            },
            DbBackupTask {
                task_id: "task2".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                requestor: "user2".to_string(),
                nft_count: 0,
                tokens: json!([{ "chain": "tezos", "tokens": ["KT1ABC"] }]),
                archive_status: Some("in_progress".to_string()),
                ipfs_status: Some("in_progress".to_string()),
                archive_error_log: None,
                ipfs_error_log: None,
                archive_fatal_error: None,
                ipfs_fatal_error: None,
                storage_mode: "full".to_string(),
                archive_format: None,
                expires_at: None,
                archive_deleted_at: None,
                pins_deleted_at: None,
            },
        ];
        mock_db.set_get_incomplete_backup_tasks_result(tasks);
        let (tx, mut rx) = mpsc::channel(10);

        let result = recover_incomplete_tasks(&mock_db, &tx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 2);

        // Check that tasks were enqueued (order-independent)
        let j1 = rx.recv().await.unwrap();
        let j2 = rx.recv().await.unwrap();
        let mut seen_task1 = false;
        let mut seen_task2 = false;
        for task in [j1, j2] {
            match task {
                BackupTaskOrShutdown::Task(TaskType::Creation(task)) => {
                    if task.task_id == "task1" {
                        seen_task1 = true;
                        assert_eq!(task.scope, StorageMode::Archive);
                        assert_eq!(task.archive_format, Some("zip".to_string()));
                        assert_eq!(task.requestor, Some("user1".to_string()));
                    } else if task.task_id == "task2" {
                        seen_task2 = true;
                        assert_eq!(task.scope, StorageMode::Full);
                        assert_eq!(task.archive_format, None);
                        assert_eq!(task.requestor, Some("user2".to_string()));
                    } else {
                        panic!("Unexpected task id");
                    }
                }
                _ => panic!("Expected backup task"),
            }
        }
        assert!(seen_task1 && seen_task2);
    }

    #[tokio::test]
    async fn test_recover_incomplete_tasks_invalid_tokens() {
        let mut mock_db = MockDatabase::default();
        let tasks = vec![DbBackupTask {
            task_id: "task1".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            requestor: "user1".to_string(),
            nft_count: 0,
            tokens: json!("invalid tokens"),
            archive_status: Some("in_progress".to_string()),
            ipfs_status: None,
            archive_error_log: None,
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: None,
            storage_mode: "archive".to_string(),
            archive_format: None,
            expires_at: None,
            archive_deleted_at: None,
            pins_deleted_at: None,
        }];
        mock_db.set_get_incomplete_backup_tasks_result(tasks);
        let (tx, mut rx) = mpsc::channel(10);

        let result = recover_incomplete_tasks(&mock_db, &tx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Should not enqueue any tasks
        assert!(rx.try_recv().is_err());

        // Cannot inspect MockDatabase calls; success and no enqueue is sufficient
    }

    #[tokio::test]
    async fn test_recover_incomplete_tasks_db_error() {
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_incomplete_backup_tasks_error(Some("Mock error".to_string()));
        let (tx, _rx) = mpsc::channel(10);

        let result = recover_incomplete_tasks(&mock_db, &tx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_recover_incomplete_tasks_storage_mode_parsing() {
        let mut mock_db = MockDatabase::default();
        let tasks = vec![DbBackupTask {
            task_id: "task1".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            requestor: "user1".to_string(),
            nft_count: 0,
            tokens: json!([{ "chain": "ethereum", "tokens": ["0x123"] }]),
            archive_status: Some("in_progress".to_string()),
            ipfs_status: None,
            archive_error_log: None,
            ipfs_error_log: None,
            archive_fatal_error: None,
            ipfs_fatal_error: None,
            storage_mode: "invalid_mode".to_string(),
            archive_format: None,
            expires_at: None,
            archive_deleted_at: None,
            pins_deleted_at: None,
        }];
        mock_db.set_get_incomplete_backup_tasks_result(tasks);
        let (tx, mut rx) = mpsc::channel(10);

        let result = recover_incomplete_tasks(&mock_db, &tx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Should default to StorageMode::Full for invalid mode
        let task = rx.recv().await.unwrap();
        match task {
            BackupTaskOrShutdown::Task(TaskType::Creation(task)) => {
                assert_eq!(task.scope, StorageMode::Full);
                assert!(task.request.pin_on_ipfs); // Both includes IPFS
            }
            _ => panic!("Expected backup task"),
        }
    }
}
