use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Tokens {
    pub chain: String,
    pub tokens: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BackupRequest {
    pub tokens: Vec<Tokens>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupResponse {
    pub task_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub status: String,
    pub error: Option<String>,
    pub error_log: Option<String>,
}
