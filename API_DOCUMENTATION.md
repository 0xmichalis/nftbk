# NFTBK - Comprehensive API Documentation

## Overview

NFTBK is a comprehensive Rust-based tool for backing up NFT metadata and content from EVM and Tezos blockchains. It provides three main components:

1. **Library (`nftbk`)** - Core functionality for programmatic use
2. **CLI Tool (`nftbk-cli`)** - Command-line interface for local backups
3. **HTTP Server (`nftbk-server`)** - Web service for remote backup requests

## Table of Contents

- [Library API](#library-api)
- [CLI Tool](#cli-tool)
- [HTTP Server API](#http-server-api)
- [Configuration](#configuration)
- [Data Structures](#data-structures)
- [Error Handling](#error-handling)
- [Examples](#examples)

---

## Library API

### Core Backup Module (`nftbk::backup`)

The main entry point for programmatic NFT backups.

#### `backup_from_config(cfg: BackupConfig) -> Result<Vec<PathBuf>>`

Performs NFT backup based on the provided configuration.

**Parameters:**
- `cfg: BackupConfig` - Configuration containing chain settings, tokens, and options

**Returns:**
- `Result<Vec<PathBuf>>` - List of saved file paths on success

**Example:**
```rust
use nftbk::backup::{backup_from_config, BackupConfig, ChainConfig, TokenConfig};
use std::path::PathBuf;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Configure chains
    let mut chain_config = ChainConfig(HashMap::from([
        ("ethereum".to_string(), "https://eth-mainnet.alchemyapi.io/v2/${EVM_RPC_API_KEY}".to_string()),
        ("polygon".to_string(), "https://polygon-mainnet.alchemyapi.io/v2/${EVM_RPC_API_KEY}".to_string()),
    ]));
    chain_config.resolve_env_vars()?;
    
    // Configure tokens to backup
    let token_config = TokenConfig {
        chains: HashMap::from([
            ("ethereum".to_string(), vec![
                "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:1".to_string(), // Bored Ape #1
                "0x60e4d786628fea6478f785a6d7e704777c86a7c6:1".to_string(), // Mutant Ape #1
            ]),
        ]),
    };
    
    let config = BackupConfig {
        chain_config,
        token_config,
        output_path: Some(PathBuf::from("./nft_backup")),
        prune_redundant: true,
        exit_on_error: false,
    };
    
    let saved_files = backup_from_config(config).await?;
    println!("Backup complete! Saved {} files", saved_files.len());
    Ok(())
}
```

### Configuration Structures

#### `ChainConfig`

Container for blockchain RPC URLs with environment variable resolution.

**Fields:**
- `0: HashMap<String, String>` - Maps chain names to RPC URLs

**Methods:**
- `resolve_env_vars(&mut self) -> Result<()>` - Resolves `${VAR_NAME}` patterns in URLs

**Example:**
```rust
use nftbk::ChainConfig;
use std::collections::HashMap;

let mut config = ChainConfig(HashMap::from([
    ("ethereum".to_string(), "https://eth-mainnet.alchemyapi.io/v2/${API_KEY}".to_string()),
]));

// Set environment variable
std::env::set_var("API_KEY", "your-api-key-here");

// Resolve environment variables
config.resolve_env_vars()?;
```

#### `TokenConfig`

Configuration for NFT tokens to backup.

**Fields:**
- `chains: HashMap<String, Vec<String>>` - Maps chain names to token lists

**Token Format:** `"contract_address:token_id"`

**Example:**
```rust
use nftbk::TokenConfig;
use std::collections::HashMap;

let config = TokenConfig {
    chains: HashMap::from([
        ("ethereum".to_string(), vec![
            "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:1".to_string(),
            "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:2".to_string(),
        ]),
        ("tezos".to_string(), vec![
            "KT1RJ6PbjHpwc3M5rw5s2Nbmefwbuwbdxton:123456".to_string(),
        ]),
    ]),
};
```

#### `BackupConfig`

Complete backup configuration structure.

**Fields:**
- `chain_config: ChainConfig` - Blockchain RPC configuration
- `token_config: TokenConfig` - NFT tokens to backup
- `output_path: Option<PathBuf>` - Backup destination directory
- `prune_redundant: bool` - Remove duplicate files after backup
- `exit_on_error: bool` - Stop on first error vs. continue and log errors

### Chain Processing API

#### `NFTChainProcessor` Trait

Core trait for implementing blockchain-specific NFT processing.

**Associated Types:**
- `Metadata` - Chain-specific metadata type
- `ContractWithToken` - Contract/token identifier type
- `RpcClient` - RPC client type

**Required Methods:**
```rust
async fn fetch_metadata(
    &self,
    token_uri: &str,
    contract: &Self::ContractWithToken,
    output_path: &std::path::Path,
    chain_name: &str,
) -> anyhow::Result<(Self::Metadata, std::path::PathBuf)>;

fn collect_urls_to_download(metadata: &Self::Metadata) -> Vec<(String, Option<String>)>;

async fn get_uri(
    &self,
    rpc: &Self::RpcClient,
    contract: &Self::ContractWithToken,
) -> anyhow::Result<String>;
```

#### `process_nfts<C, FExtraUri>(...) -> Result<Vec<PathBuf>>`

Generic function for processing NFTs across any blockchain.

**Parameters:**
- `processor: Arc<C>` - Chain processor implementation
- `provider: Arc<C::RpcClient>` - RPC client
- `contracts: Vec<C::ContractWithToken>` - Tokens to process
- `output_path: &Path` - Output directory
- `chain_name: &str` - Chain identifier
- `exit_on_error: bool` - Error handling mode
- `get_extra_content_uri: FExtraUri` - Extra content URI extractor

### Content Handling API

#### `fetch_and_save_content(...) -> Result<PathBuf>`

Downloads and saves content from URLs with automatic format detection.

**Parameters:**
- `url: &str` - Content URL (HTTP, IPFS, or data URL)
- `chain: &str` - Blockchain name
- `contract_address: &str` - NFT contract address
- `token_id: &str` - Token ID
- `output_path: &Path` - Base output directory
- `options: Options` - Download options

**Features:**
- Automatic file extension detection from content
- Data URL decoding
- JSON pretty-printing
- HTML resource extraction
- Duplicate prevention

**Example:**
```rust
use nftbk::content::{fetch_and_save_content, Options};
use std::path::Path;

let saved_path = fetch_and_save_content(
    "https://example.com/metadata.json",
    "ethereum",
    "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d",
    "1",
    Path::new("./backup"),
    Options {
        overriden_filename: None,
        fallback_filename: Some("metadata".to_string()),
    },
).await?;
```

---

## CLI Tool

### Installation and Usage

```bash
# Build the CLI tool
cargo build --release --bin nftbk-cli

# Run with default configuration
./target/release/nftbk-cli

# Run with custom configuration
./target/release/nftbk-cli \
  --chains-config-path custom_chains.toml \
  --tokens-config-path custom_tokens.toml \
  --output-path ./my_backup \
  --log-level debug \
  --prune-redundant true \
  --exit-on-error true
```

### Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--chains-config-path` | `-c` | `config_chains.toml` | Path to chains configuration file |
| `--tokens-config-path` | `-t` | `config_tokens.toml` | Path to tokens configuration file |
| `--output-path` | `-o` | `nft_backup` | Directory to save backup |
| `--log-level` | `-l` | `info` | Log level (error, warn, info, debug, trace) |
| `--prune-redundant` | | `false` | Delete redundant files in backup folder |
| `--server-mode` | | `false` | Request backup from server instead of running locally |
| `--server-address` | | `http://127.0.0.1:8080` | Server address for remote backups |
| `--exit-on-error` | | `false` | Exit on first error encountered |
| `--force` | | `false` | Force rerunning completed backup task |
| `--list` | | `false` | List existing backups on server |
| `--user-agent` | | `Linux` | User-Agent header (affects archive format) |

### Server Mode

The CLI can operate in server mode to request backups from a remote server:

```bash
# Request backup from server
nftbk-cli --server-mode true --server-address https://backup-server.com

# List existing backups on server
nftbk-cli --server-mode true --list true --server-address https://backup-server.com

# Force rerun completed backup
nftbk-cli --server-mode --force true
```

### Authentication

For server mode, set the authentication token:

```bash
export NFTBK_AUTH_TOKEN="your-auth-token"
nftbk-cli --server-mode true
```

---

## HTTP Server API

### Server Startup

```bash
# Build and run the server
cargo build --release --bin nftbk-server

# Run with default settings
./target/release/nftbk-server

# Run with custom configuration
./target/release/nftbk-server \
  --listen-address 0.0.0.0:8080 \
  --chain-config config_chains.toml \
  --base-dir /var/backups \
  --pruner-retention-days 7
```

### Server Configuration

| Argument | Default | Description |
|----------|---------|-------------|
| `--listen-address` | `127.0.0.1:8080` | Server bind address |
| `--chain-config` | `config_chains.toml` | Path to chains configuration |
| `--base-dir` | `/tmp` | Base directory for backups |
| `--log-level` | `info` | Log level |
| `--unsafe-skip-checksum-check` | `false` | Skip backup integrity checks |
| `--enable-pruner` | `true` | Enable automatic cleanup |
| `--pruner-retention-days` | `3` | Days to retain completed backups |
| `--pruner-interval-seconds` | `3600` | Cleanup interval |
| `--pruner-pattern` | `^nftbk-` | Filename pattern for cleanup |

### Authentication

The server supports two authentication methods:

#### 1. Symmetric Token Authentication
```bash
export NFTBK_AUTH_TOKEN="your-secret-token"
```

#### 2. Privy JWT Authentication
```bash
export PRIVY_APP_ID="your-privy-app-id"
export PRIVY_VERIFICATION_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
```

### API Endpoints

#### POST `/backup`

Creates a new backup task.

**Request Body:**
```json
{
  "tokens": [
    {
      "chain": "ethereum",
      "tokens": [
        "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:1",
        "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:2"
      ]
    },
    {
      "chain": "tezos",
      "tokens": [
        "KT1RJ6PbjHpwc3M5rw5s2Nbmefwbuwbdxton:123456"
      ]
    }
  ],
  "force": false
}
```

**Response:**
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Headers:**
- `Authorization: Bearer <token>` (required if auth enabled)
- `User-Agent: <platform>` (affects archive format)

#### GET `/backup/{task_id}/status`

Gets the current status of a backup task.

**Response:**
```json
{
  "status": "in_progress",
  "error": null
}
```

**Status Values:**
- `in_progress` - Backup is running
- `done` - Backup completed successfully
- `error` - Backup failed
- `expired` - Backup files have been cleaned up

#### GET `/backup/{task_id}/download_token`

Generates a temporary download token for the backup archive.

**Response:**
```json
{
  "token": "temp-download-token-12345",
  "expires_at": 1640995200
}
```

#### GET `/backup/{task_id}/download?token={download_token}`

Downloads the backup archive using a temporary token.

**Response:** Binary archive file (tar.gz or zip based on User-Agent)

#### GET `/backup/{task_id}/error_log`

Retrieves error logs for a backup task.

**Response:** Plain text error log

#### POST `/backup/{task_id}/retry`

Retries a failed backup task.

**Response:**
```json
{
  "task_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

#### DELETE `/backup/{task_id}`

Deletes a backup task and its files.

**Response:** HTTP 204 No Content

#### GET `/backups`

Lists all backup tasks for the authenticated user.

**Response:**
```json
[
  {
    "task_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "done",
    "error": null,
    "error_log": "",
    "nft_count": 2
  }
]
```

---

## Configuration

### Chain Configuration File (`config_chains.toml`)

```toml
ethereum = "https://eth-mainnet.alchemyapi.io/v2/${EVM_RPC_API_KEY}"
polygon = "https://polygon-mainnet.alchemyapi.io/v2/${EVM_RPC_API_KEY}"
arbitrum = "https://arb-mainnet.g.alchemy.com/v2/${EVM_RPC_API_KEY}"
optimism = "https://opt-mainnet.g.alchemy.com/v2/${EVM_RPC_API_KEY}"
base = "https://base-mainnet.g.alchemy.com/v2/${EVM_RPC_API_KEY}"
tezos = "https://mainnet-tezos.giganode.io"
```

### Token Configuration File (`config_tokens.toml`)

```toml
ethereum = [
    "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:1",    # Bored Ape #1
    "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:2",    # Bored Ape #2
    "0x60e4d786628fea6478f785a6d7e704777c86a7c6:1",    # Mutant Ape #1
]

polygon = [
    "0x2953399124f0cbb46d2cbacd8a89cf0599974963:1",    # OpenSea Shared Storefront
]

tezos = [
    "KT1RJ6PbjHpwc3M5rw5s2Nbmefwbuwbdxton:123456",   # Hic et Nunc NFT
]
```

### Environment Variables

```bash
# Required for EVM RPC endpoints that need an API key
export EVM_RPC_API_KEY="your-alchemy-api-key"

# Server authentication (optional)
export NFTBK_AUTH_TOKEN="your-secret-token"

# Privy JWT authentication (optional)
export PRIVY_APP_ID="your-privy-app-id"
export PRIVY_VERIFICATION_KEY="-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
```

---

## Data Structures

### API Request/Response Types

#### `Tokens`
```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Tokens {
    pub chain: String,
    pub tokens: Vec<String>,
}
```

#### `BackupRequest`
```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupRequest {
    pub tokens: Vec<Tokens>,
    pub force: Option<bool>,
}
```

#### `BackupResponse`
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupResponse {
    pub task_id: String,
}
```

#### `StatusResponse`
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
    pub error: Option<String>,
}
```

### Chain-Specific Types

#### `ContractWithToken`
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractWithToken {
    pub address: String,
    pub token_id: String,
}

impl ContractWithToken {
    pub fn parse_contracts(contracts: &[String]) -> Vec<Self> {
        // Parses "address:token_id" format
    }
}
```

#### `NFTAttribute`
```rust
#[derive(Debug, Serialize, Deserialize)]
pub struct NFTAttribute {
    pub trait_type: String,
    pub value: serde_json::Value,
}
```

---

## Error Handling

### Error Types

The library uses `anyhow::Result<T>` for error handling, providing rich error context and chaining.

Common error scenarios:
- Network connectivity issues
- Invalid RPC endpoints
- Missing environment variables
- File system permissions
- Invalid token formats
- Authentication failures

### Error Examples

```rust
// Environment variable resolution error
config.resolve_env_vars()
    .context("Failed to resolve environment variables in chain config")?;

// Network request error
let response = client.get(&url).send().await
    .context("Failed to fetch metadata from IPFS")?;

// File system error
fs::create_dir_all(&output_path).await
    .context("Failed to create output directory")?;
```

---

## Examples

### Example 1: Basic Library Usage

```rust
use nftbk::backup::{backup_from_config, BackupConfig, ChainConfig, TokenConfig};
use std::collections::HashMap;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Set up environment
    std::env::set_var("EVM_RPC_API_KEY", "your-api-key");
    
    // Configure chains
    let mut chain_config = ChainConfig(HashMap::from([
        ("ethereum".to_string(), "https://eth-mainnet.alchemyapi.io/v2/${EVM_RPC_API_KEY}".to_string()),
    ]));
    chain_config.resolve_env_vars()?;
    
    // Configure tokens
    let token_config = TokenConfig {
        chains: HashMap::from([
            ("ethereum".to_string(), vec![
                "0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:1".to_string(),
            ]),
        ]),
    };
    
    // Create backup configuration
    let config = BackupConfig {
        chain_config,
        token_config,
        output_path: Some(PathBuf::from("./nft_backup")),
        prune_redundant: true,
        exit_on_error: false,
    };
    
    // Perform backup
    let files = backup_from_config(config).await?;
    println!("Backup complete! {} files saved", files.len());
    
    Ok(())
}
```

### Example 2: Gallery.so Import

Generate configuration from an existing Gallery.so collection:

```bash
# Set Gallery credentials
export GALLERY_ID="2RgusW2IT1qkSPKE15S2xTnArN4"
export USERNAME="michalis"

# Generate token configuration
python3 scripts/extract_gallery_tokens.py > config_tokens.toml

# Run backup
nftbk-cli
```

### Example 3: Server API Client

```rust
use reqwest::Client;
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = Client::new();
    
    // Submit backup request
    let response = client
        .post("https://your-server.com/backup")
        .header("Authorization", "Bearer your-token")
        .json(&json!({
            "tokens": [{
                "chain": "ethereum",
                "tokens": ["0xbc4ca0eda7647a8ab7c2061c2e118a18a936f13d:1"]
            }],
            "force": false
        }))
        .send()
        .await?;
    
    let backup_response: serde_json::Value = response.json().await?;
    let task_id = backup_response["task_id"].as_str().unwrap();
    
    // Poll for completion
    loop {
        let status_response = client
            .get(&format!("https://your-server.com/backup/{}/status", task_id))
            .header("Authorization", "Bearer your-token")
            .send()
            .await?;
        
        let status: serde_json::Value = status_response.json().await?;
        match status["status"].as_str().unwrap() {
            "done" => break,
            "error" => panic!("Backup failed: {}", status["error"]),
            _ => tokio::time::sleep(std::time::Duration::from_secs(10)).await,
        }
    }
    
    // Get download token and download
    let token_response = client
        .get(&format!("https://your-server.com/backup/{}/download_token", task_id))
        .header("Authorization", "Bearer your-token")
        .send()
        .await?;
    
    let token_data: serde_json::Value = token_response.json().await?;
    let download_token = token_data["token"].as_str().unwrap();
    
    // Download the backup
    let download_response = client
        .get(&format!("https://your-server.com/backup/{}/download?token={}", task_id, download_token))
        .send()
        .await?;
    
    let backup_data = download_response.bytes().await?;
    tokio::fs::write("backup.tar.gz", backup_data).await?;
    
    println!("Backup downloaded successfully!");
    Ok(())
}
```

### Example 4: Custom Chain Processor

```rust
use nftbk::chain::{NFTChainProcessor, common::ContractTokenInfo};
use async_trait::async_trait;

struct CustomChainProcessor;

#[async_trait]
impl NFTChainProcessor for CustomChainProcessor {
    type Metadata = serde_json::Value;
    type ContractWithToken = nftbk::chain::common::ContractWithToken;
    type RpcClient = reqwest::Client;
    
    async fn fetch_metadata(
        &self,
        token_uri: &str,
        contract: &Self::ContractWithToken,
        output_path: &std::path::Path,
        chain_name: &str,
    ) -> anyhow::Result<(Self::Metadata, std::path::PathBuf)> {
        // Custom metadata fetching logic
        unimplemented!()
    }
    
    fn collect_urls_to_download(metadata: &Self::Metadata) -> Vec<(String, Option<String>)> {
        // Extract URLs from metadata
        vec![]
    }
    
    async fn get_uri(
        &self,
        rpc: &Self::RpcClient,
        contract: &Self::ContractWithToken,
    ) -> anyhow::Result<String> {
        // Get token URI from custom RPC
        unimplemented!()
    }
}
```

---

## Security Considerations

### Authentication
- Use strong, randomly generated tokens for symmetric authentication
- Properly configure Privy JWT verification keys
- Tokens are transmitted via Authorization headers only

### File System Security
- Backup filenames are sanitized
- Backups are cleaned up automatically
- Path traversal attacks are prevented through input validation

### Network Security
- HTTPS is recommended for production deployments
- Rate limiting should be implemented at the reverse proxy level
- Backup downloads use temporary tokens with expiration
