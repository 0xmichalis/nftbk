use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChainTokens {
    pub chain: String,
    pub tokens: Vec<String>,
}

pub type BackupRequest = Vec<ChainTokens>;

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupResponse {
    pub task_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
    pub error: Option<String>,
}
