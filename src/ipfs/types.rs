use serde::{Deserialize, Serialize};

// Types adapted from the IPFS Pinning Service OpenAPI spec

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PinStatus {
    Queued,
    Pinning,
    Pinned,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinMeta(pub serde_json::Map<String, serde_json::Value>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PinOrigins(pub Vec<String>);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pin {
    pub cid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "is_pin_origins_empty")]
    pub origins: PinOrigins,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<PinMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinStatusResponse {
    pub requestid: String,
    pub status: PinStatus,
    pub created: String,
    pub pin: Pin,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegates: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PinsListResponse {
    pub count: u64,
    pub results: Vec<PinStatusResponse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PinsListQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Vec<PinStatus>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

fn is_pin_origins_empty(origins: &PinOrigins) -> bool {
    origins.0.is_empty()
}
