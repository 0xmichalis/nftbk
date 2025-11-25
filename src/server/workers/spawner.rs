use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::info;

use super::creation::run_backup_task;
use super::deletion::run_deletion_task;
use super::quote::run_quote_task;
use crate::server::{AppState, BackupTaskOrShutdown, TaskType};

pub fn spawn_backup_workers(
    parallelism: usize,
    task_receiver: mpsc::Receiver<BackupTaskOrShutdown>,
    state: AppState,
) -> Vec<JoinHandle<()>> {
    let mut worker_handles = Vec::with_capacity(parallelism);
    let task_receiver = Arc::new(tokio::sync::Mutex::new(task_receiver));
    for i in 0..parallelism {
        let task_receiver = task_receiver.clone();
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            info!("Worker {} started", i);
            loop {
                let task_or_shutdown = {
                    let mut rx = task_receiver.lock().await;
                    rx.recv().await
                };
                match task_or_shutdown {
                    Some(BackupTaskOrShutdown::Task(task_type)) => match task_type {
                        TaskType::Creation(backup_task) => {
                            run_backup_task(state_clone.clone(), backup_task).await;
                        }
                        TaskType::Deletion(deletion_task) => {
                            run_deletion_task(state_clone.clone(), deletion_task).await;
                        }
                        TaskType::Quote(quote_task) => {
                            run_quote_task(state_clone.clone(), quote_task).await;
                        }
                    },
                    Some(BackupTaskOrShutdown::Shutdown) | None => break,
                }
            }
            info!("Worker {} stopped", i);
        });
        worker_handles.push(handle);
    }
    worker_handles
}
