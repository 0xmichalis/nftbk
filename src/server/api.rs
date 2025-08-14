use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct Tokens {
    /// The blockchain identifier (e.g., "ethereum", "polygon", "tezos")
    pub chain: String,
    /// List of NFT token identifiers/contract addresses
    /// The tokens are formatted as `contract_address:token_id` (e.g., `0x1234567890123456789012345678901234567890:1`)
    pub tokens: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct BackupRequest {
    /// List of tokens to backup, organized by blockchain
    pub tokens: Vec<Tokens>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct BackupResponse {
    /// Unique identifier for the backup task
    pub task_id: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct StatusResponse {
    /// Current status of the backup (in_progress, done, error, expired)
    pub status: String,
    /// Error message if the backup failed
    pub error: Option<String>,
    /// This is a detailed error log of the backup process. It is only available if the backup completed
    /// successfully but some of the tokens failed to backup.
    pub error_log: Option<String>,
}
