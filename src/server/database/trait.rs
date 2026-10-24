use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::server::model::*;

pub type Result<T> = std::result::Result<T, DatabaseError>;

#[derive(Debug)]
pub enum DatabaseError {
    NotFound,
    Conflict(String),
    Invalid(String),
    LostLease,
    Capacity,
    Storage(sqlx::Error),
}
impl From<sqlx::Error> for DatabaseError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(error)
    }
}
impl std::fmt::Display for DatabaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => write!(f, "Resource not found"),
            Self::Conflict(s) | Self::Invalid(s) => f.write_str(s),
            Self::Capacity => write!(f, "Work queue is at capacity; retry later"),
            Self::LostLease => write!(f, "Operation lease lost"),
            Self::Storage(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for DatabaseError {}

#[derive(Debug, Clone, Default, Deserialize, utoipa::IntoParams)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub cursor: Option<String>,
    pub limit: Option<u16>,
    pub state: Option<String>,
    pub chain_id: Option<String>,
    pub contract_address: Option<String>,
    pub token_id: Option<String>,
    pub cid: Option<String>,
    pub backup_id: Option<String>,
    pub pin_set_id: Option<String>,
    pub ipfs_only: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct QuoteTerms {
    pub asset_symbol: String,
    pub chain_id: String,
    pub asset_address: String,
    pub asset_decimals: u8,
    pub pricing_version: String,
    pub lifetime_seconds: u32,
}

#[derive(Debug, Clone)]
pub enum Creation {
    Backup {
        specification: Specification,
        quote_id: Option<String>,
        pricing_version: Option<String>,
        provider_ids: Vec<String>,
    },
    Quote {
        specification: Specification,
        terms: QuoteTerms,
        backup_id: Option<String>,
    },
    Output {
        backup_id: String,
        output: OutputRequest,
        provider_ids: Vec<String>,
        quote_id: Option<String>,
        pricing_version: Option<String>,
        specification_hash: String,
    },
}

#[derive(Debug, Clone)]
pub struct Create {
    pub owner_id: String,
    pub key: String,
    pub payload_hash: String,
    pub resource: Resource,
    pub creation: Creation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blob {
    pub sha256: String,
    pub size_bytes: u64,
    pub storage_key: String,
}

#[derive(Debug, Clone)]
pub enum Progress {
    Items(Vec<Item>),
    Captured {
        manifest_sha256: String,
        state: State,
    },
    Archived(Blob),
    Quoted {
        plan: Vec<Item>,
        amount_atomic: String,
        estimated_size_bytes: u64,
        lifetime_seconds: u32,
    },
    Pinned {
        state: State,
    },
    Deleted,
    Failed(Failure),
    Deferred,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedPin {
    pub id: String,
    pub provider_id: String,
    pub cid: String,
    pub request_id: Option<String>,
    pub submitted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub state: String,
    pub operation_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum PinUpdate {
    Submitting {
        pin_id: String,
    },
    Observed {
        pin_id: String,
        request_id: String,
        state: String,
    },
    Failed {
        pin_id: String,
        failure: Failure,
        ambiguous: bool,
    },
    Deleted {
        pin_id: String,
    },
}

#[derive(Debug, Clone)]
pub enum PaymentUpdate {
    Begin {
        proof_hash: String,
        settle_request: Document,
    },
    Settled(Document),
    Failed {
        detail: String,
        ambiguous: bool,
    },
}

#[async_trait]
pub trait Database: Send + Sync {
    async fn owner(&self, principal: &Principal) -> Result<String>;
    async fn archive_storage(&self, owner: &str, id: &str) -> Result<String>;
    async fn get(&self, resource: Resource, owner: &str, id: &str) -> Result<Option<Document>>;
    async fn list(
        &self,
        resource: Resource,
        owner: &str,
        page: &Page,
    ) -> Result<Collection<Document>>;
    async fn create(&self, request: Create) -> Result<Document>;
    async fn delete(&self, resource: Resource, owner: &str, id: &str) -> Result<Operation>;
    async fn retry(&self, owner: &str, id: &str) -> Result<Attempt>;
    async fn attempts(&self, owner: &str, id: &str) -> Result<Vec<Attempt>>;
    async fn claim(&self) -> Result<Option<Claim>>;
    async fn heartbeat(&self, claim: &Claim) -> Result<bool>;
    async fn context(&self, claim: &Claim) -> Result<Document>;
    async fn progress(&self, claim: &Claim, progress: Progress) -> Result<()>;
    async fn put_blob(&self, claim: &Claim, blob: &Blob) -> Result<()>;
    async fn reserve_pin(&self, claim: &Claim, asset: &Asset, provider: &str)
        -> Result<ManagedPin>;
    async fn update_pin(&self, claim: &Claim, update: PinUpdate) -> Result<()>;
    async fn release_pins(&self, claim: &Claim) -> Result<Vec<ManagedPin>>;
    async fn payment(
        &self,
        resource: Resource,
        owner: &str,
        target_id: &str,
        update: Option<PaymentUpdate>,
    ) -> Result<Option<Document>>;
    async fn maintenance(&self) -> Result<()>;
    async fn active_leases(&self) -> Result<Vec<(String, String)>>;
    async fn blob_deleting(&self, sha256: &str) -> Result<bool>;
    async fn garbage(&self, finished: Option<&str>) -> Result<Vec<Blob>>;
}
