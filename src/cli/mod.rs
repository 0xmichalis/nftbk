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

        /// Force rerunning a completed backup task
        #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
        force: bool,

        /// User-Agent to send to the server (affects archive format)
        #[arg(long, default_value = "Linux")]
        user_agent: String,

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

        /// The task ID of the backup to delete
        #[arg(short = 't', long)]
        task_id: String,

        /// Show what would be deleted without actually deleting
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        dry_run: bool,
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
            } => {
                commands::create::run(
                    config_path,
                    tokens_config_path,
                    output_path,
                    prune_redundant,
                    exit_on_error,
                )
                .await
            }
            Commands::Server { command } => match command {
                ServerCommands::Create {
                    tokens_config_path,
                    server_address,
                    output_path,
                    force,
                    user_agent,
                    pin_on_ipfs,
                    polling_interval_ms,
                } => {
                    commands::server::create::run(
                        tokens_config_path,
                        server_address,
                        output_path,
                        force,
                        user_agent,
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
                    task_id,
                    dry_run,
                } => commands::server::delete::run(server_address, task_id, dry_run).await,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    mod cli_parsing_tests {
        use super::*;

        #[test]
        fn parses_create_command_with_defaults() {
            let args = vec!["nftbk-cli", "create"];
            let cli = Cli::try_parse_from(args).unwrap();

            assert_eq!(cli.log_level, LogLevel::Info);
            assert!(!cli.no_color);
            match cli.command {
                Commands::Create {
                    config_path,
                    tokens_config_path,
                    output_path,
                    prune_redundant,
                    exit_on_error,
                } => {
                    assert_eq!(config_path, PathBuf::from("config.toml"));
                    assert_eq!(tokens_config_path, PathBuf::from("config_tokens.toml"));
                    assert_eq!(output_path, Some(PathBuf::from("nft_backup")));
                    assert!(!prune_redundant);
                    assert!(!exit_on_error);
                }
                _ => panic!("Expected Create command"),
            }
        }

        #[test]
        fn parses_create_command_with_custom_options() {
            let args = vec![
                "nftbk-cli",
                "--log-level",
                "debug",
                "--no-color",
                "true",
                "create",
                "--config-path",
                "custom_config.toml",
                "--tokens-config-path",
                "custom_tokens.toml",
                "--output-path",
                "/tmp/backup",
                "--prune-redundant",
                "true",
                "--exit-on-error",
                "true",
            ];
            let cli = Cli::try_parse_from(args).unwrap();

            assert_eq!(cli.log_level, LogLevel::Debug);
            assert!(cli.no_color);
            match cli.command {
                Commands::Create {
                    config_path,
                    tokens_config_path,
                    output_path,
                    prune_redundant,
                    exit_on_error,
                } => {
                    assert_eq!(config_path, PathBuf::from("custom_config.toml"));
                    assert_eq!(tokens_config_path, PathBuf::from("custom_tokens.toml"));
                    assert_eq!(output_path, Some(PathBuf::from("/tmp/backup")));
                    assert!(prune_redundant);
                    assert!(exit_on_error);
                }
                _ => panic!("Expected Create command"),
            }
        }

        #[test]
        fn parses_server_create_command_with_defaults() {
            let args = vec!["nftbk-cli", "server", "create"];
            let cli = Cli::try_parse_from(args).unwrap();

            match cli.command {
                Commands::Server { command } => match command {
                    ServerCommands::Create {
                        tokens_config_path,
                        server_address,
                        output_path,
                        force,
                        user_agent,
                        pin_on_ipfs,
                        polling_interval_ms,
                    } => {
                        assert_eq!(tokens_config_path, PathBuf::from("config_tokens.toml"));
                        assert_eq!(server_address, "http://127.0.0.1:8080");
                        assert_eq!(output_path, Some(PathBuf::from("nft_backup")));
                        assert!(!force);
                        assert_eq!(user_agent, "Linux");
                        assert!(!pin_on_ipfs);
                        assert_eq!(polling_interval_ms, 10000);
                    }
                    _ => panic!("Expected Server Create command"),
                },
                _ => panic!("Expected Server command"),
            }
        }

        #[test]
        fn parses_server_create_command_with_custom_options() {
            let args = vec![
                "nftbk-cli",
                "server",
                "create",
                "--tokens-config-path",
                "custom_tokens.toml",
                "--server-address",
                "https://api.example.com",
                "--output-path",
                "/tmp/server_backup",
                "--force",
                "true",
                "--user-agent",
                "CustomAgent/1.0",
                "--pin-on-ipfs",
                "true",
            ];
            let cli = Cli::try_parse_from(args).unwrap();

            match cli.command {
                Commands::Server { command } => match command {
                    ServerCommands::Create {
                        tokens_config_path,
                        server_address,
                        output_path,
                        force,
                        user_agent,
                        pin_on_ipfs,
                        polling_interval_ms,
                    } => {
                        assert_eq!(tokens_config_path, PathBuf::from("custom_tokens.toml"));
                        assert_eq!(server_address, "https://api.example.com");
                        assert_eq!(output_path, Some(PathBuf::from("/tmp/server_backup")));
                        assert!(force);
                        assert_eq!(user_agent, "CustomAgent/1.0");
                        assert!(pin_on_ipfs);
                        assert_eq!(polling_interval_ms, 10000); // Default value
                    }
                    _ => panic!("Expected Server Create command"),
                },
                _ => panic!("Expected Server command"),
            }
        }

        #[test]
        fn parses_server_list_command_with_defaults() {
            let args = vec!["nftbk-cli", "server", "list"];
            let cli = Cli::try_parse_from(args).unwrap();

            match cli.command {
                Commands::Server { command } => match command {
                    ServerCommands::List {
                        server_address,
                        show_errors,
                    } => {
                        assert_eq!(server_address, "http://127.0.0.1:8080");
                        assert!(!show_errors);
                    }
                    _ => panic!("Expected Server List command"),
                },
                _ => panic!("Expected Server command"),
            }
        }

        #[test]
        fn parses_server_list_command_with_custom_server() {
            let args = vec![
                "nftbk-cli",
                "server",
                "list",
                "--server-address",
                "https://api.example.com",
            ];
            let cli = Cli::try_parse_from(args).unwrap();

            match cli.command {
                Commands::Server { command } => match command {
                    ServerCommands::List {
                        server_address,
                        show_errors,
                    } => {
                        assert_eq!(server_address, "https://api.example.com");
                        assert!(!show_errors);
                    }
                    _ => panic!("Expected Server List command"),
                },
                _ => panic!("Expected Server command"),
            }
        }

        #[test]
        fn parses_server_list_command_with_show_errors() {
            let args = vec!["nftbk-cli", "server", "list", "--show-errors", "true"];
            let cli = Cli::try_parse_from(args).unwrap();

            match cli.command {
                Commands::Server { command } => match command {
                    ServerCommands::List {
                        server_address,
                        show_errors,
                    } => {
                        assert_eq!(server_address, "http://127.0.0.1:8080");
                        assert!(show_errors);
                    }
                    _ => panic!("Expected Server List command"),
                },
                _ => panic!("Expected Server command"),
            }
        }

        #[test]
        fn parses_server_delete_command_with_defaults() {
            let args = vec![
                "nftbk-cli",
                "server",
                "delete",
                "--task-id",
                "test-task-123",
            ];
            let cli = Cli::try_parse_from(args).unwrap();

            match cli.command {
                Commands::Server { command } => match command {
                    ServerCommands::Delete {
                        server_address,
                        task_id,
                        dry_run,
                    } => {
                        assert_eq!(server_address, "http://127.0.0.1:8080");
                        assert_eq!(task_id, "test-task-123");
                        assert!(dry_run);
                    }
                    _ => panic!("Expected Server Delete command"),
                },
                _ => panic!("Expected Server command"),
            }
        }

        #[test]
        fn parses_server_delete_command_with_custom_options() {
            let args = vec![
                "nftbk-cli",
                "server",
                "delete",
                "--server-address",
                "https://api.example.com",
                "--task-id",
                "custom-task-456",
                "--dry-run",
                "true",
            ];
            let cli = Cli::try_parse_from(args).unwrap();

            match cli.command {
                Commands::Server { command } => match command {
                    ServerCommands::Delete {
                        server_address,
                        task_id,
                        dry_run,
                    } => {
                        assert_eq!(server_address, "https://api.example.com");
                        assert_eq!(task_id, "custom-task-456");
                        assert!(dry_run);
                    }
                    _ => panic!("Expected Server Delete command"),
                },
                _ => panic!("Expected Server command"),
            }
        }

        #[test]
        fn parses_all_log_levels() {
            for (level_str, expected_level) in [
                ("debug", LogLevel::Debug),
                ("info", LogLevel::Info),
                ("warn", LogLevel::Warn),
                ("error", LogLevel::Error),
            ] {
                let args = vec!["nftbk-cli", "--log-level", level_str, "create"];
                let cli = Cli::try_parse_from(args).unwrap();
                assert_eq!(cli.log_level, expected_level);
            }
        }

        #[test]
        fn handles_no_color_flag() {
            let args = vec!["nftbk-cli", "--no-color", "true", "create"];
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(cli.no_color);

            let args = vec!["nftbk-cli", "--no-color", "false", "create"];
            let cli = Cli::try_parse_from(args).unwrap();
            assert!(!cli.no_color);
        }

        #[test]
        fn requires_subcommand() {
            let args = vec!["nftbk-cli"];
            let result = Cli::try_parse_from(args);
            assert!(result.is_err());
        }

        #[test]
        fn validates_log_level_enum() {
            let args = vec!["nftbk-cli", "--log-level", "invalid", "create"];
            let result = Cli::try_parse_from(args);
            assert!(result.is_err());
        }
    }
}
