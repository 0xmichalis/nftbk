use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::info;

use crate::server::{run_backup_job, AppState, BackupJobOrShutdown};

pub fn spawn_backup_workers(
    parallelism: usize,
    backup_job_receiver: mpsc::Receiver<BackupJobOrShutdown>,
    state: AppState,
) -> Vec<JoinHandle<()>> {
    let mut worker_handles = Vec::with_capacity(parallelism);
    let backup_job_receiver = Arc::new(tokio::sync::Mutex::new(backup_job_receiver));
    for i in 0..parallelism {
        let backup_job_receiver = backup_job_receiver.clone();
        let state_clone = state.clone();
        let handle = tokio::spawn(async move {
            info!("Worker {} started", i);
            loop {
                let job = {
                    let mut rx = backup_job_receiver.lock().await;
                    rx.recv().await
                };
                match job {
                    Some(BackupJobOrShutdown::Job(job)) => {
                        run_backup_job(
                            state_clone.clone(),
                            job.task_id,
                            job.tokens,
                            job.force,
                            job.archive_format,
                        )
                        .await;
                    }
                    Some(BackupJobOrShutdown::Shutdown) | None => break,
                }
            }
            info!("Worker {} stopped", i);
        });
        worker_handles.push(handle);
    }
    worker_handles
}
