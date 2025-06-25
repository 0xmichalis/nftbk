use clap::Parser;
use std::process::Command;
use std::thread;

/// Supervisor for running server and pruner together
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the server binary
    #[arg(long, default_value = "/app/nftbk-server")]
    server: String,

    /// Path to the pruner binary
    #[arg(long, default_value = "/app/nftbk-pruner")]
    pruner: String,

    /// Retention days for the pruner
    #[arg(long, default_value = "3")]
    retention_days: String,
}

fn main() {
    let args = Args::parse();

    // Start the main app
    let mut server = Command::new(&args.server)
        .args([
            "--listen-address",
            "0.0.0.0:8080",
            "--unsafe-skip-checksum-check",
            "true",
        ])
        .spawn()
        .expect("failed to start nftbk-server");

    // Start the pruner
    let mut pruner = Command::new(&args.pruner)
        .args([
            "--retention-days",
            &args.retention_days,
            "--dry-run",
            "false",
            "--daemon",
            "true",
        ])
        .spawn()
        .expect("failed to start nftbk-pruner");

    // Wait for either process to exit
    let server_handle = thread::spawn(move || server.wait());
    let pruner_handle = thread::spawn(move || pruner.wait());

    // Wait for either to finish
    let _ = server_handle.join();
    let _ = pruner_handle.join();
}
