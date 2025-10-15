use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::server::api::Tokens;
use crate::server::database::Db;
use crate::server::{BackupTask, BackupTaskOrShutdown, StorageMode, TaskType};

// Recovery task struct that matches the database schema
#[derive(Debug, Clone)]
pub struct RecoveryTask {
    pub task_id: String,
    pub requestor: String,
    pub tokens: serde_json::Value,
    pub storage_mode: String,
    pub archive_format: Option<String>,
}

// Trait for database operations needed by recovery
#[async_trait::async_trait]
pub trait RecoveryDb {
    async fn get_incomplete_backup_tasks(&self) -> Result<Vec<RecoveryTask>, sqlx::Error>;
    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error>;
}

// Implement the trait for the real Db
#[async_trait::async_trait]
impl RecoveryDb for Db {
    async fn get_incomplete_backup_tasks(&self) -> Result<Vec<RecoveryTask>, sqlx::Error> {
        let tasks = Db::get_incomplete_backup_tasks(self).await?;
        Ok(tasks
            .into_iter()
            .map(|task| RecoveryTask {
                task_id: task.task_id,
                requestor: task.requestor,
                tokens: task.tokens,
                storage_mode: task.storage_mode,
                archive_format: task.archive_format,
            })
            .collect())
    }

    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error> {
        Db::set_backup_error(self, task_id, error).await
    }
}

// Implement the trait for Arc<Db> to support the AppState usage
#[async_trait::async_trait]
impl RecoveryDb for std::sync::Arc<Db> {
    async fn get_incomplete_backup_tasks(&self) -> Result<Vec<RecoveryTask>, sqlx::Error> {
        let tasks = self.as_ref().get_incomplete_backup_tasks().await?;
        Ok(tasks
            .into_iter()
            .map(|task| RecoveryTask {
                task_id: task.task_id,
                requestor: task.requestor,
                tokens: task.tokens,
                storage_mode: task.storage_mode,
                archive_format: task.archive_format,
            })
            .collect())
    }

    async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error> {
        self.as_ref().set_backup_error(task_id, error).await
    }
}

/// Recover incomplete backup tasks from the database and enqueue them for processing
/// This is called on server startup to handle tasks that were interrupted by server shutdown
pub async fn recover_incomplete_tasks<DB: RecoveryDb + ?Sized>(
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

    debug!(
        "Found {} incomplete backup tasks, re-queueing for processing",
        task_count
    );

    for task_meta in incomplete_tasks {
        // Parse the tokens JSON back to Vec<Tokens>
        let tokens: Vec<Tokens> = match serde_json::from_value(task_meta.tokens.clone()) {
            Ok(tokens) => tokens,
            Err(e) => {
                warn!(
                    "Failed to parse tokens for backup task {}: {}, skipping",
                    task_meta.task_id, e
                );
                // Mark this task as error since we can't process it
                let _ = db
                    .set_backup_error(
                        &task_meta.task_id,
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
            force: true, // Force recovery to ensure backup actually runs
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
    use serde_json::json;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    // Mock implementation of RecoveryDb for testing
    struct MockRecoveryDb {
        tasks: Vec<RecoveryTask>,
        should_fail_get_tasks: bool,
        should_fail_set_error: bool,
        set_error_calls: Arc<std::sync::Mutex<Vec<(String, String)>>>,
    }

    impl MockRecoveryDb {
        fn new(tasks: Vec<RecoveryTask>) -> Self {
            Self {
                tasks,
                should_fail_get_tasks: false,
                should_fail_set_error: false,
                set_error_calls: Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn with_get_tasks_failure(mut self) -> Self {
            self.should_fail_get_tasks = true;
            self
        }

        fn get_set_error_calls(&self) -> Vec<(String, String)> {
            self.set_error_calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl RecoveryDb for MockRecoveryDb {
        async fn get_incomplete_backup_tasks(&self) -> Result<Vec<RecoveryTask>, sqlx::Error> {
            if self.should_fail_get_tasks {
                return Err(sqlx::Error::Configuration("Mock error".into()));
            }
            Ok(self.tasks.clone())
        }

        async fn set_backup_error(&self, task_id: &str, error: &str) -> Result<(), sqlx::Error> {
            if self.should_fail_set_error {
                return Err(sqlx::Error::Configuration("Mock error".into()));
            }
            self.set_error_calls
                .lock()
                .unwrap()
                .push((task_id.to_string(), error.to_string()));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_recover_incomplete_tasks_no_tasks() {
        let mock_db = MockRecoveryDb::new(vec![]);
        let (tx, _rx) = mpsc::channel(10);

        let result = recover_incomplete_tasks(&mock_db, &tx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[tokio::test]
    async fn test_recover_incomplete_tasks_success() {
        let tasks = vec![
            RecoveryTask {
                task_id: "task1".to_string(),
                requestor: "user1".to_string(),
                tokens: json!([{"chain": "ethereum", "tokens": ["0x123"]}]),
                storage_mode: "archive".to_string(),
                archive_format: Some("zip".to_string()),
            },
            RecoveryTask {
                task_id: "task2".to_string(),
                requestor: "user2".to_string(),
                tokens: json!([{"chain": "tezos", "tokens": ["KT1ABC"]}]),
                storage_mode: "full".to_string(),
                archive_format: None,
            },
        ];
        let mock_db = MockRecoveryDb::new(tasks);
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
                        assert!(task.force);
                        assert_eq!(task.scope, StorageMode::Archive);
                        assert_eq!(task.archive_format, Some("zip".to_string()));
                        assert_eq!(task.requestor, Some("user1".to_string()));
                    } else if task.task_id == "task2" {
                        seen_task2 = true;
                        assert!(task.force);
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
        let tasks = vec![RecoveryTask {
            task_id: "task1".to_string(),
            requestor: "user1".to_string(),
            tokens: json!("invalid tokens"), // Invalid JSON for tokens
            storage_mode: "archive".to_string(),
            archive_format: None,
        }];
        let mock_db = MockRecoveryDb::new(tasks);
        let (tx, mut rx) = mpsc::channel(10);

        let result = recover_incomplete_tasks(&mock_db, &tx).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);

        // Should not enqueue any tasks
        assert!(rx.try_recv().is_err());

        // Should have called set_backup_error
        let error_calls = mock_db.get_set_error_calls();
        assert_eq!(error_calls.len(), 1);
        assert_eq!(error_calls[0].0, "task1");
        assert!(error_calls[0]
            .1
            .contains("Failed to parse tokens during recovery"));
    }

    #[tokio::test]
    async fn test_recover_incomplete_tasks_db_error() {
        let mock_db = MockRecoveryDb::new(vec![]).with_get_tasks_failure();
        let (tx, _rx) = mpsc::channel(10);

        let result = recover_incomplete_tasks(&mock_db, &tx).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_recover_incomplete_tasks_storage_mode_parsing() {
        let tasks = vec![RecoveryTask {
            task_id: "task1".to_string(),
            requestor: "user1".to_string(),
            tokens: json!([{"chain": "ethereum", "tokens": ["0x123"]}]),
            storage_mode: "invalid_mode".to_string(), // Invalid storage mode
            archive_format: None,
        }];
        let mock_db = MockRecoveryDb::new(tasks);
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
