use clap::Parser;
use regex::Regex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{
    fs,
    path::Path,
    time::{Duration, SystemTime},
};
use tracing::info;

use nftbk::logging;
use nftbk::logging::LogLevel;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Directory to prune
    #[arg(long, default_value = "/tmp")]
    base_dir: String,

    /// Retention period in days
    #[arg(long, default_value_t = 7)]
    retention_days: u64,

    /// Prune interval in seconds
    #[arg(long, default_value_t = 3600)]
    interval_seconds: u64,

    /// Dry run (do not actually delete files)
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    dry_run: bool,

    /// Regex pattern for file names to prune
    #[arg(long, default_value = "^nftbk-")]
    pattern: String,

    /// Run in daemon mode (loop forever)
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    daemon: bool,

    /// Set the log level
    #[arg(short, long, value_enum, default_value = "info")]
    log_level: LogLevel,
}

fn potentially_prune_file(
    path: &Path,
    now: SystemTime,
    retention: Duration,
    re: &Regex,
    dry_run: bool,
) {
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
    if dry_run {
        println!("[dry-run] Would delete {:?}", path);
        return;
    }
    let res = if path.is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    match res {
        Ok(_) => println!("Deleted {:?}", path),
        Err(e) => eprintln!("Failed to delete {:?}: {}", path, e),
    }
}

fn main() {
    let args = Args::parse();
    logging::init(args.log_level.clone());

    info!("Starting pruner with config: {:?}", args);

    let re = Regex::new(&args.pattern).expect("Invalid regex pattern");
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
        info!("Received shutdown signal, shutting down pruner...");
    })
    .expect("Error setting Ctrl-C handler");

    let run_once = || {
        info!("Running pruning process...");
        let now = SystemTime::now();
        let retention = Duration::from_secs(60 * 60 * 24 * args.retention_days);
        let base_dir = Path::new(&args.base_dir);
        let entries = match fs::read_dir(base_dir) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Failed to read base dir {:?}: {}", base_dir, e);
                return;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            potentially_prune_file(&path, now, retention, &re, args.dry_run);
        }
        info!("Pruning process completed");
    };
    if args.daemon {
        while running.load(Ordering::SeqCst) {
            run_once();
            let sleep_step = 1; // seconds
            let mut slept = 0;
            while slept < args.interval_seconds && running.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_secs(sleep_step));
                slept += sleep_step;
            }
        }
        info!("Pruner shutting down gracefully");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        std::thread::sleep(std::time::Duration::from_millis(100));
    } else {
        run_once();
    }
}
