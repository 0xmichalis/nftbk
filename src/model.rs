use std::collections::{BTreeMap, BTreeSet};

use anyhow::{ensure, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;

use crate::chain::id::validate_chain_id;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Nft {
    #[schema(example = "eip155:1")]
    pub chain_id: String,
    pub contract_address: String,
    /// Decimal string; NFT identifiers can exceed JSON's integer precision.
    pub token_id: String,
}

impl Nft {
    pub fn normalize(&mut self) -> Result<()> {
        validate_chain_id(&self.chain_id)?;
        ensure!(
            !self.token_id.is_empty()
                && self.token_id.len() <= 256
                && self.token_id.bytes().all(|b| b.is_ascii_digit()),
            "token_id must be a decimal string"
        );
        self.token_id = self.token_id.trim_start_matches('0').to_string();
        if self.token_id.is_empty() {
            self.token_id = "0".to_string();
        }
        if self.chain_id.starts_with("eip155:") {
            let address: alloy::primitives::Address = self.contract_address.parse()?;
            self.contract_address = format!("{address:#x}");
            alloy::primitives::U256::from_str_radix(&self.token_id, 10)?;
        } else {
            ensure!(
                self.contract_address.starts_with("KT1")
                    && self.contract_address.len() == 36
                    && tezos_core::types::encoded::ContractHash::try_from(
                        self.contract_address.as_str()
                    )
                    .is_ok(),
                "Invalid Tezos contract address"
            );
        }
        Ok(())
    }

    pub fn directory(&self) -> String {
        format!(
            "{}/{}/{}",
            self.chain_id, self.contract_address, self.token_id
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, ToSchema)]
pub enum ArchiveFormat {
    #[serde(rename = "zip")]
    Zip,
    #[serde(rename = "tar.gz")]
    TarGz,
}

impl ArchiveFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::TarGz => "tar.gz",
        }
    }
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Zip => "application/zip",
            Self::TarGz => "application/gzip",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutputRequest {
    Archive {
        format: ArchiveFormat,
        #[serde(default)]
        retention_days: Option<u32>,
    },
    Ipfs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct Specification {
    pub nfts: Vec<Nft>,
    pub outputs: Vec<OutputRequest>,
}

impl Specification {
    pub fn normalize(&mut self, retention_days: u32) -> Result<()> {
        ensure!(
            !self.nfts.is_empty() && self.nfts.len() <= 1000,
            "Provide between 1 and 1000 NFTs"
        );
        ensure!(
            !self.outputs.is_empty() && self.outputs.len() <= 3,
            "Provide between 1 and 3 outputs"
        );
        for nft in &mut self.nfts {
            nft.normalize()?;
        }
        self.nfts.sort();
        self.nfts.dedup();
        for output in &mut self.outputs {
            if let OutputRequest::Archive {
                retention_days: days,
                ..
            } = output
            {
                let days = days.get_or_insert(retention_days);
                ensure!(
                    (1..=365).contains(days),
                    "retention_days must be between 1 and 365"
                );
            }
        }
        self.outputs.sort();
        self.outputs.dedup();
        Ok(())
    }

    pub fn hash(&self) -> String {
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).expect("Specification serialization"))
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateBackup {
    pub nfts: Vec<Nft>,
    pub outputs: Vec<OutputRequest>,
    pub quote_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum State {
    AwaitingPayment,
    Queued,
    Running,
    Ready,
    Partial,
    Failed,
    Deleting,
    Deleted,
    Expired,
    Unsupported,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, ToSchema)]
pub struct Failure {
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Backup {
    #[serde(default)]
    pub links: BTreeMap<String, String>,
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub state: State,
    pub nft_count: u32,
    pub captured_count: u32,
    pub failed_count: u32,
    pub archives: Vec<Archive>,
    pub pin_sets: Vec<PinSet>,
    pub operation_id: Option<String>,
    pub manifest_sha256: Option<String>,
    pub provenance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Archive {
    #[serde(default)]
    pub links: BTreeMap<String, String>,
    pub id: String,
    pub backup_id: String,
    pub created_at: DateTime<Utc>,
    pub state: State,
    pub format: ArchiveFormat,
    pub expires_at: Option<DateTime<Utc>>,
    pub sha256: Option<String>,
    pub size_bytes: Option<u64>,
    pub operation_id: Option<String>,
    pub error: Option<Failure>,
    pub deletion_requested_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PinSet {
    #[serde(default)]
    pub links: BTreeMap<String, String>,
    pub id: String,
    pub backup_id: String,
    pub created_at: DateTime<Utc>,
    pub state: State,
    pub requested_nft_count: u32,
    pub eligible_nft_count: u32,
    pub protected_nft_count: u32,
    pub skipped_nft_count: u32,
    pub operation_id: Option<String>,
    pub error: Option<Failure>,
    pub deletion_requested_at: Option<DateTime<Utc>>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Asset {
    pub id: String,
    pub item_id: String,
    pub role: String,
    pub source_uri: Option<String>,
    pub filename: Option<String>,
    pub fallback_filename: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    pub path: String,
    pub sha256: Option<String>,
    pub cid: Option<String>,
    pub size_bytes: Option<u64>,
    pub state: State,
    pub error: Option<Failure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Item {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, String>,
    pub id: String,
    pub backup_id: String,
    #[serde(flatten)]
    pub nft: Nft,
    pub state: State,
    pub metadata_uri: Option<String>,
    pub metadata_sha256: Option<String>,
    pub observed_at: Option<DateTime<Utc>>,
    pub block_reference: Option<String>,
    pub error: Option<Failure>,
    pub assets: Vec<Asset>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Pin {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub links: BTreeMap<String, String>,
    #[serde(default)]
    pub nfts: Vec<Nft>,
    pub id: String,
    pub provider_id: String,
    pub cid: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub error: Option<Failure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Operation {
    #[serde(default)]
    pub links: BTreeMap<String, String>,
    pub id: String,
    pub kind: String,
    pub target_id: String,
    pub state: String,
    pub attempts: u32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub error: Option<Failure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Attempt {
    pub number: u32,
    pub requested_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub error: Option<Failure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Quote {
    #[serde(default)]
    pub links: BTreeMap<String, String>,
    pub id: String,
    pub state: String,
    pub amount_atomic: Option<String>,
    pub asset_symbol: String,
    pub chain_id: String,
    pub asset_address: String,
    pub asset_decimals: u8,
    pub estimated_size_bytes: Option<u64>,
    pub expires_at: DateTime<Utc>,
    pub pricing_version: String,
    pub operation_id: Option<String>,
    pub error: Option<Failure>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Collection<T> {
    pub data: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Manifest {
    pub version: u32,
    pub backup_id: String,
    pub created_at: DateTime<Utc>,
    pub provenance: String,
    pub items: Vec<Item>,
}

impl Manifest {
    pub fn coverage(&self) -> (u32, u32) {
        let ready = self
            .items
            .iter()
            .filter(|i| i.state == State::Ready)
            .count() as u32;
        (ready, self.items.len() as u32 - ready)
    }

    pub fn ipfs_items(&self) -> BTreeSet<&str> {
        self.items
            .iter()
            .filter(|i| i.assets.iter().any(|a| a.cid.is_some()))
            .map(|i| i.id.as_str())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    pub issuer: String,
    pub subject: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claim {
    pub operation: Operation,
    pub owner_id: String,
    pub lease_token: String,
    pub specification: Option<Specification>,
    pub plan: Vec<Item>,
}

#[derive(Debug, Clone, Copy)]
pub enum Resource {
    Backup,
    Archive,
    PinSet,
    Quote,
    Operation,
    Item,
    Pin,
}

impl Resource {
    pub fn table(self) -> &'static str {
        match self {
            Self::Backup => "backups",
            Self::Archive => "archives",
            Self::PinSet => "pin_sets",
            Self::Quote => "quotes",
            Self::Operation => "operations",
            Self::Item => "backup_items",
            Self::Pin => "provider_pins",
        }
    }
    pub fn collection(self) -> &'static str {
        match self {
            Self::PinSet => "pin-sets",
            Self::Pin => "pins",
            Self::Item => "items",
            other => other.table(),
        }
    }
}

pub type Document = serde_json::Value;
pub type ProviderMap = BTreeMap<String, std::sync::Arc<dyn crate::ipfs::IpfsPinningProvider>>;

#[cfg(test)]
mod normalize_tests {
    use super::*;

    fn nft(token_id: &str) -> Nft {
        Nft {
            chain_id: "eip155:1".into(),
            contract_address: "0x00000000000000000000000000000000000000aB".into(),
            token_id: token_id.into(),
        }
    }

    #[test]
    fn canonicalizes_identity_deduplicates_and_resolves_defaults() {
        let mut specification = Specification {
            nfts: vec![nft("042"), nft("42")],
            outputs: vec![OutputRequest::Archive {
                format: ArchiveFormat::Zip,
                retention_days: None,
            }],
        };
        specification.normalize(3).unwrap();
        assert_eq!(specification.nfts.len(), 1);
        assert_eq!(specification.nfts[0].token_id, "42");
        assert_eq!(
            specification.nfts[0].contract_address,
            "0x00000000000000000000000000000000000000ab"
        );
        assert_eq!(
            specification.outputs,
            vec![OutputRequest::Archive {
                format: ArchiveFormat::Zip,
                retention_days: Some(3)
            }]
        );
    }

    #[test]
    fn rejects_paths_and_invalid_numbers() {
        for token_id in ["", "../1", "-1", "0x1"] {
            assert!(nft(token_id).normalize().is_err());
        }
        let mut invalid = nft("1");
        invalid.chain_id = "ethereum".into();
        assert!(invalid.normalize().is_err());
    }
}

#[cfg(test)]
mod hash_tests {
    use super::*;

    #[test]
    fn output_and_retention_changes_affect_the_quote_binding() {
        let mut specification = Specification {
            nfts: vec![],
            outputs: vec![OutputRequest::Ipfs],
        };
        let pins = specification.hash();
        specification.outputs.push(OutputRequest::Archive {
            format: ArchiveFormat::Zip,
            retention_days: Some(3),
        });
        assert_ne!(pins, specification.hash());
        let short_retention = specification.hash();
        specification.outputs[1] = OutputRequest::Archive {
            format: ArchiveFormat::Zip,
            retention_days: Some(30),
        };
        assert_ne!(short_retention, specification.hash());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateArchive {
    pub backup_id: String,
    pub format: ArchiveFormat,
    pub retention_days: Option<u32>,
    pub quote_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct CreatePinSet {
    pub backup_id: String,
    pub quote_id: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct QuoteOutput {
    pub backup_id: String,
    pub outputs: Vec<OutputRequest>,
}
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum QuoteRequest {
    Capture(Specification),
    Output(QuoteOutput),
}
