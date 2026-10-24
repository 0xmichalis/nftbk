use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::logging::LogLevel;

pub mod commands;
pub mod config;
pub mod x402;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Set the log level
    #[arg(short, long, value_enum, default_value = "info")]
    pub log_level: LogLevel,

    /// Disable colored log output. NO_COLOR and FORCE_COLOR environment variables take precedence.
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a backup locally
    Create {
        /// The path to the unified configuration file
        #[arg(short = 'c', long, default_value = "config.toml")]
        config_path: PathBuf,

        /// The path to the tokens configuration file
        #[arg(short = 't', long, default_value = "config_tokens.toml")]
        tokens_config_path: PathBuf,

        /// The directory to save the backup to
        #[arg(short, long, default_value = "nft_backup")]
        output_path: Option<PathBuf>,

        /// Delete redundant files in the backup folder
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        prune_redundant: bool,

        /// Exit on the first error encountered
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        exit_on_error: bool,

        /// Pin content to IPFS using configured providers
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        pin_on_ipfs: bool,
    },
    /// Server-related operations
    Server {
        #[command(subcommand)]
        command: ServerCommands,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServerCommands {
    /// Create a backup on the server
    Create {
        /// The path to the tokens configuration file
        #[arg(short = 't', long, default_value = "config_tokens.toml")]
        tokens_config_path: PathBuf,

        /// The server address to request backups from
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server_address: String,

        /// The directory to save the backup to
        #[arg(short, long, default_value = "nft_backup")]
        output_path: Option<PathBuf>,

        /// Archive format to generate
        #[arg(long, default_value = "zip", value_parser = ["zip", "tar.gz"])]
        archive_format: String,

        /// Request server to pin downloaded assets on IPFS
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        pin_on_ipfs: bool,

        /// Polling interval in milliseconds for checking backup status
        #[arg(long, default_value = "10000")]
        polling_interval_ms: u64,
    },
    /// List existing backups on the server
    List {
        /// The server address to request backups from
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server_address: String,

        /// Show error details in the output table
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        show_errors: bool,
    },
    /// Delete a backup from the server
    Delete {
        /// The server address to request backups from
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        server_address: String,

        /// UUID of the backup to delete
        #[arg(short = 't', long)]
        backup_id: String,
    },
}

impl Cli {
    pub async fn run(self) -> Result<()> {
        match self.command {
            Commands::Create {
                config_path,
                tokens_config_path,
                output_path,
                prune_redundant,
                exit_on_error,
                pin_on_ipfs,
            } => {
                commands::create::run(
                    config_path,
                    tokens_config_path,
                    output_path,
                    prune_redundant,
                    exit_on_error,
                    pin_on_ipfs,
                )
                .await
            }
            Commands::Server { command } => match command {
                ServerCommands::Create {
                    tokens_config_path,
                    server_address,
                    output_path,
                    archive_format,
                    pin_on_ipfs,
                    polling_interval_ms,
                } => {
                    commands::server::create::run(
                        tokens_config_path,
                        server_address,
                        output_path,
                        archive_format,
                        pin_on_ipfs,
                        Some(polling_interval_ms),
                    )
                    .await
                }
                ServerCommands::List {
                    server_address,
                    show_errors,
                } => commands::server::list::run(server_address, show_errors).await,
                ServerCommands::Delete {
                    server_address,
                    backup_id,
                } => commands::server::delete::run(server_address, backup_id).await,
            },
        }
    }
}

#[cfg(test)]
mod cli_parsing_tests {
    use super::*;
    #[test]
    fn parses_explicit_archive_format() {
        let cli = Cli::try_parse_from([
            "nftbk-cli",
            "server",
            "create",
            "--archive-format",
            "tar.gz",
        ])
        .unwrap();
        match cli.command {
            Commands::Server {
                command: ServerCommands::Create { archive_format, .. },
            } => assert_eq!(archive_format, "tar.gz"),
            _ => panic!("wrong command"),
        }
        assert!(
            Cli::try_parse_from(["nftbk-cli", "server", "create", "--archive-format", "rar"])
                .is_err()
        );
    }
}
