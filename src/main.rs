use anyhow::{Context, Result};
use clap::Parser;
use nftbk::backup::{backup_from_config, BackupConfig, ChainConfig, TokenConfig};
use nftbk::logging;
use nftbk::logging::LogLevel;
use std::path::PathBuf;
use tokio::fs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the NFT contracts configuration file (default: config.toml)
    #[arg(short, long, default_value = "config.toml")]
    config_path: PathBuf,

    /// Optional output directory path (defaults to current directory)
    #[arg(short, long)]
    output_path: Option<PathBuf>,

    #[arg(short, long, value_enum, default_value = "info")]
    log_level: LogLevel,

    /// Delete directories in the backup folder that are not part of the config
    #[arg(long, default_value = "false")]
    prune_missing: bool,
}

#[derive(serde::Deserialize)]
struct FileConfig {
    chains: std::collections::HashMap<String, String>,
    tokens: TokenConfig,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    logging::init(args.log_level);
    let config_content = fs::read_to_string(&args.config_path)
        .await
        .context("Failed to read config file")?;
    let file_config: FileConfig =
        toml::from_str(&config_content).context("Failed to parse config file")?;
    let chain_config = ChainConfig(file_config.chains);
    let token_config = file_config.tokens;
    let backup_config = BackupConfig {
        chain_config,
        token_config,
        output_path: args.output_path,
        prune_missing: args.prune_missing,
    };
    backup_from_config(backup_config).await
}
