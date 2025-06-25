use clap::Parser;
use regex::Regex;
use std::{
    fs,
    path::Path,
    thread::sleep,
    time::{Duration, SystemTime},
};

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
    #[arg(long, default_value_t = false)]
    dry_run: bool,

    /// Regex pattern for file names to prune
    #[arg(long, default_value = "^nftbk-")]
    pattern: String,
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
    let re = Regex::new(&args.pattern).expect("Invalid regex pattern");
    println!("Starting pruner with config: {:?}", args);
    loop {
        let now = SystemTime::now();
        let retention = Duration::from_secs(60 * 60 * 24 * args.retention_days);
        let base_dir = Path::new(&args.base_dir);
        let entries = match fs::read_dir(base_dir) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("Failed to read base dir {:?}: {}", base_dir, e);
                sleep(Duration::from_secs(args.interval_seconds));
                continue;
            }
        };
        for entry in entries.flatten() {
            let path = entry.path();
            potentially_prune_file(&path, now, retention, &re, args.dry_run);
        }
        sleep(Duration::from_secs(args.interval_seconds));
    }
}
