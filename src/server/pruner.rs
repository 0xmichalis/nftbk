use regex::Regex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{
    fs,
    path::Path,
    thread,
    time::{Duration, SystemTime},
};
use tracing::info;

#[derive(Debug, Clone)]
pub struct PrunerConfig {
    pub base_dir: String,
    pub retention_days: u64,
    pub interval_seconds: u64,
    pub pattern: String,
}

fn potentially_prune_file(path: &Path, now: SystemTime, retention: Duration, re: &Regex) {
    let metadata = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return,
    };
    let modified = match metadata.modified() {
        Ok(m) => m,
        Err(_) => return,
    };
    if now.duration_since(modified).unwrap_or(Duration::ZERO) <= retention {
        return;
    }
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return,
    };
    if !re.is_match(name) {
        return;
    }
    if name.ends_with("-metadata.json") {
        // Skip metadata files to continue displaying some amount of data
        // to end users about expired backups.
        return;
    }
    let res = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match res {
        Ok(_) => info!("Deleted {:?}", path),
        Err(e) => tracing::warn!("Failed to delete {:?}: {}", path, e),
    }
}

pub fn run_pruner(config: PrunerConfig, running: Arc<AtomicBool>) {
    let re = Regex::new(&config.pattern).expect("Invalid regex pattern");
    let run_once = || {
        info!("Running pruning process...");
        let now = SystemTime::now();
        let retention = Duration::from_secs(60 * 60 * 24 * config.retention_days);
        let base_dir = Path::new(&config.base_dir);
        let entries = match fs::read_dir(base_dir) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("Failed to read base dir {:?}: {}", base_dir, e);
                return;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            potentially_prune_file(&path, now, retention, &re);
        }
        info!("Pruning process completed");
    };
    while running.load(Ordering::SeqCst) {
        run_once();
        let sleep_step = 1; // seconds
        let mut slept = 0;
        while slept < config.interval_seconds && running.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_secs(sleep_step));
            slept += sleep_step;
        }
    }
    info!("Pruner shutting down");
}
