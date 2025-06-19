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
    /// Path to the NFT chains configuration file (default: config_chains.toml)
    #[arg(short = 'c', long, default_value = "config_chains.toml")]
    chains_config_path: PathBuf,

    /// Path to the NFT tokens configuration file (default: config_tokens.toml)
    #[arg(short = 't', long, default_value = "config_tokens.toml")]
    tokens_config_path: PathBuf,

    /// Optional output directory path (defaults to current directory)
    #[arg(short, long)]
    output_path: Option<PathBuf>,

    #[arg(short, long, value_enum, default_value = "info")]
    log_level: LogLevel,

    /// Delete directories in the backup folder that are not part of the config
    #[arg(long, default_value = "false")]
    prune_missing: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    logging::init(args.log_level);

    let chains_content = fs::read_to_string(&args.chains_config_path)
        .await
        .context("Failed to read chains config file")?;
    let chain_config: ChainConfig =
        toml::from_str(&chains_content).context("Failed to parse chains config file")?;

    let tokens_content = fs::read_to_string(&args.tokens_config_path)
        .await
        .context("Failed to read tokens config file")?;
    let token_config: TokenConfig =
        toml::from_str(&tokens_content).context("Failed to parse tokens config file")?;

    let backup_config = BackupConfig {
        chain_config,
        token_config,
        output_path: args.output_path,
        prune_missing: args.prune_missing,
    };
    backup_from_config(backup_config).await
}
