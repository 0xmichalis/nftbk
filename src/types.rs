use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::envvar::resolve_env_placeholders;

/// Represents a token with its associated pin responses
#[derive(Debug, Clone)]
pub struct TokenPinMapping {
    pub chain: String,
    pub contract_address: String,
    pub token_id: String,
    pub pin_responses: Vec<crate::ipfs::PinResponse>,
}

#[derive(Debug)]
pub struct ArchiveOutcome {
    pub files: Vec<PathBuf>,
    pub errors: Vec<String>,
}

#[derive(Debug)]
pub struct IpfsOutcome {
    pub pin_requests: Vec<TokenPinMapping>,
    pub errors: Vec<String>,
}

pub const DEFAULT_MAX_CONTENT_REQUEST_RETRIES: u32 = 3;

#[derive(Debug, Deserialize, Clone)]
pub struct ChainConfig(pub HashMap<String, String>);

impl ChainConfig {
    /// Resolves environment variable references in the form ${VAR_NAME} in all values.
    /// Returns an error if any referenced environment variable is not set.
    pub fn resolve_env_vars(&mut self) -> Result<()> {
        for (key, value) in self.0.iter_mut() {
            let resolved = resolve_env_placeholders(value).with_context(|| {
                format!("Failed resolving env vars referenced in '{value}' for chain '{key}'")
            })?;
            *value = resolved;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenConfig {
    #[serde(flatten)]
    pub chains: HashMap<String, Vec<String>>,
}

/// Configuration for process management with shutdown and error handling options
#[derive(Clone)]
pub struct ProcessManagementConfig {
    pub exit_on_error: bool,
    pub shutdown_flag: Option<Arc<AtomicBool>>,
    pub max_content_request_retries: u32,
}

#[derive(Clone)]
pub struct StorageConfig {
    /// If Some, store content locally under this path
    pub output_path: Option<PathBuf>,
    pub prune_redundant: bool,
    /// IPFS pinning providers - content will be pinned to all configured providers
    pub ipfs_pinning_configs: Vec<crate::ipfs::IpfsPinningConfig>,
}

pub struct BackupConfig {
    pub chain_config: ChainConfig,
    pub token_config: TokenConfig,
    pub storage_config: StorageConfig,
    pub process_config: ProcessManagementConfig,
    pub task_id: Option<String>,
}
