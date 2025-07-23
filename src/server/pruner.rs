use std::fs::{remove_dir_all, remove_file};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration as TokioDuration};
use tracing::{info, warn};

use crate::server::archive::get_zipped_backup_paths;
use crate::server::db::{Db, ExpiredBackup};

pub async fn run_pruner(
    db: Arc<Db>,
    base_dir: String,
    interval_seconds: u64,
    running: Arc<AtomicBool>,
) {
    while running.load(Ordering::SeqCst) {
        info!("Running pruning process...");
        match db.list_expired_backups().await {
            Ok(expired) => {
                let mut pruned_task_ids = Vec::new();
                for ExpiredBackup {
                    task_id,
                    archive_format,
                } in &expired
                {
                    let (archive_path, archive_checksum_path) =
                        get_zipped_backup_paths(&base_dir, task_id, archive_format);
                    let backup_dir = format!("{}/nftbk-{}", base_dir, task_id);
                    let _ = remove_file(&archive_path);
                    let _ = remove_file(&archive_checksum_path);
                    let _ = remove_dir_all(&backup_dir);
                    info!("Pruned expired backup {}", task_id);
                    pruned_task_ids.push(task_id.clone());
                }
                if !pruned_task_ids.is_empty() {
                    if let Err(e) = db
                        .batch_update_backup_status(&pruned_task_ids, "expired")
                        .await
                    {
                        warn!("Failed to update status for pruned backups: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to query expired backups: {}", e);
            }
        }
        info!("Pruning process completed");
        let mut slept = 0;
        let sleep_step = 1;
        while slept < interval_seconds && running.load(Ordering::SeqCst) {
            sleep(TokioDuration::from_secs(sleep_step)).await;
            slept += sleep_step;
        }
    }
    info!("Pruner stopped");
}
