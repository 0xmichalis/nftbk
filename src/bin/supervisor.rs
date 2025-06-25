use clap::Parser;
use std::process::Command;
use std::thread;
use tokio::signal as tokio_signal;
use tracing::info;

use nftbk::logging;
use nftbk::logging::LogLevel;

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

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Initialize logging at info level
    logging::init(LogLevel::Info);

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

    // Listen for Ctrl+C and forward to children
    let server_pid = server.id();
    let pruner_pid = pruner.id();
    let signal_handle = tokio::spawn(async move {
        tokio_signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("Supervisor received shutdown signal, forwarding to children...");
        let _ = unsafe { libc::kill(server_pid as i32, libc::SIGINT) };
        let _ = unsafe { libc::kill(pruner_pid as i32, libc::SIGINT) };

        // Wait for children to exit
        std::thread::sleep(std::time::Duration::from_secs(5));

        // Check if children are still running and send SIGKILL if needed
        if unsafe { libc::kill(server_pid as i32, 0) } == 0 {
            info!("Supervisor: server did not exit, sending SIGKILL");
            let _ = unsafe { libc::kill(server_pid as i32, libc::SIGKILL) };
        }
        if unsafe { libc::kill(pruner_pid as i32, 0) } == 0 {
            info!("Supervisor: pruner did not exit, sending SIGKILL");
            let _ = unsafe { libc::kill(pruner_pid as i32, libc::SIGKILL) };
        }
    });

    // Wait for children to exit
    let server_handle = thread::spawn(move || server.wait());
    let pruner_handle = thread::spawn(move || pruner.wait());

    let _ = server_handle.join();
    let _ = pruner_handle.join();
    let _ = signal_handle.await;
}
