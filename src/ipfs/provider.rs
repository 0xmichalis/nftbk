use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Unified pin request that all providers accept
#[derive(Debug, Clone)]
pub struct PinRequest {
    pub cid: String,
    pub name: Option<String>,
    pub metadata: Option<serde_json::Map<String, serde_json::Value>>,
}

/// Unified pin response that all providers return
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinResponse {
    /// Provider-specific request/pin ID
    pub id: String,
    /// The CID that was pinned
    pub cid: String,
    /// Status of the pin operation
    pub status: PinResponseStatus,
    /// Name of the provider (e.g., "pinning-service", "pinata")
    pub provider: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PinResponseStatus {
    Queued,
    Pinning,
    Pinned,
    Failed,
}

/// Trait for IPFS pinning providers
#[async_trait]
pub trait IpfsPinningProvider: Send + Sync {
    /// Get the name of the provider (e.g., "pinning-service", "pinata")
    fn provider_name(&self) -> &str;

    /// Pin a CID to the IPFS network
    async fn create_pin(&self, request: &PinRequest) -> Result<PinResponse>;

    /// Get the status of a pin by its ID
    async fn get_pin(&self, pin_id: &str) -> Result<PinResponse>;

    /// List all pins from the provider
    async fn list_pins(&self) -> Result<Vec<PinResponse>>;

    /// Delete a pin by its request ID
    async fn delete_pin(&self, request_id: &str) -> Result<()>;
}
