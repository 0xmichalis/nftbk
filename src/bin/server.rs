use std::env;

use clap::Parser;
use dotenvy::dotenv;
use tracing::{error, info};

use nftbk::envvar::{is_defined, should_enable_color};
use nftbk::logging;
use nftbk::logging::LogLevel;
use nftbk::server::config::{load_and_validate_config, Config};
use nftbk::server::{run_server, ServerConfig};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The address to listen on
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen_address: String,

    /// The path to the configuration file
    #[arg(short = 'c', long, default_value = "config.toml")]
    config: String,

    /// The base directory to save the backup to
    #[arg(long, default_value = "/tmp")]
    base_dir: String,

    /// Set the log level
    #[arg(short, long, value_enum, default_value = "info")]
    log_level: LogLevel,

    /// Skip checksum verification
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    unsafe_skip_checksum_check: bool,

    /// Pruner retention period in days
    #[arg(long, default_value_t = 3)]
    pruner_retention_days: u64,

    /// Pruner interval in seconds
    #[arg(long, default_value_t = 3600)]
    pruner_interval_seconds: u64,

    /// Pruner regex pattern for file names to prune
    #[arg(long, default_value = "^nftbk-")]
    pruner_pattern: String,

    /// Pin monitor interval in seconds
    #[arg(long, default_value_t = 120)]
    pin_monitor_interval_seconds: u64,

    /// Number of backup worker threads to run in parallel
    #[arg(long, default_value_t = 4)]
    backup_parallelism: usize,

    /// Maximum number of backup tasks to queue before blocking
    #[arg(long, default_value_t = 10000)]
    backup_queue_size: usize,

    /// Disable colored log output. NO_COLOR and FORCE_COLOR environment variables take precedence.
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    no_color: bool,

    /// Maximum number of quotes to cache in memory for dynamic pricing.
    /// When the cache is full, the least recently used quotes are evicted.
    /// This cache stores quote IDs (UUID string, ~36 bytes) and their associated data
    /// (price string ~10 bytes + task_id SHA256 hex string ~64 bytes) for x402 dynamic pricing.
    /// Each entry uses approximately ~220 bytes including overhead, so:
    /// - 100 entries ≈ 22 KB
    /// - 1000 entries ≈ 220 KB (default)
    /// - 10000 entries ≈ 2.2 MB
    #[arg(long, default_value_t = 1000)]
    quote_cache_size: usize,
}

#[tokio::main]
async fn main() {
    // We are consuming config both from the environment and from the command line
    dotenv().ok();
    let args = Args::parse();
    let enable_color = should_enable_color(args.no_color);
    logging::init(args.log_level, enable_color);
    info!(
        "Version: {} {} (commit {})",
        env!("CARGO_BIN_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("GIT_COMMIT")
    );
    info!("Initializing server with options: {:?}", args);

    // Load configuration
    let auth_token = env::var("NFTBK_AUTH_TOKEN").ok();
    info!(
        "Symmetric authentication enabled: {}",
        is_defined(&auth_token)
    );

    let Config {
        chain_config,
        jwt_credentials,
        x402_config,
        ipfs_pinning_configs,
    } = match load_and_validate_config(&args.config) {
        Ok(config) => config,
        Err(e) => {
            error!("Failed to load and validate config: {}", e);
            std::process::exit(1);
        }
    };

    // Start the server
    let config = ServerConfig {
        listen_address: args.listen_address,
        base_dir: args.base_dir,
        unsafe_skip_checksum_check: args.unsafe_skip_checksum_check,
        auth_token,
        pruner_retention_days: args.pruner_retention_days,
        pruner_interval_seconds: args.pruner_interval_seconds,
        pin_monitor_interval_seconds: args.pin_monitor_interval_seconds,
        backup_parallelism: args.backup_parallelism,
        backup_queue_size: args.backup_queue_size,
        chain_config,
        jwt_credentials,
        x402_config,
        ipfs_pinning_configs,
        quote_cache_size: args.quote_cache_size,
    };

    if let Err(e) = run_server(config).await {
        error!("Server failed: {}", e);
        std::process::exit(1);
    }
}
