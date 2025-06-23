use alloy::{
    contract::Error,
    sol,
    transports::http::{Client, Http},
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

use crate::chain::common::{ContractWithToken, NFTAttribute};
use crate::chain::ContractTokenInfo;
use crate::content::{fetch_and_save_content, Options};

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    #[serde(alias = "imageUrl")]
    pub image_url: Option<String>,
    pub animation_url: Option<String>,
    pub external_url: Option<String>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_attributes")]
    pub attributes: Option<Vec<NFTAttribute>>,
    pub media: Option<Media>,
    pub content: Option<Media>,
    pub assets: Option<Assets>,
}

// Helper enum to deserialize both formats
#[derive(Deserialize)]
#[serde(untagged)]
enum AttributesFormat {
    Array(Vec<NFTAttribute>),
    // Used by KnownOrigin
    Map(std::collections::HashMap<String, serde_json::Value>),
}

fn deserialize_attributes<'de, D>(deserializer: D) -> Result<Option<Vec<NFTAttribute>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<AttributesFormat>::deserialize(deserializer)? {
        Some(AttributesFormat::Map(map)) => {
            // Convert map to Vec<NFTAttribute>
            Ok(Some(
                map.into_iter()
                    .map(|(trait_type, value)| NFTAttribute { trait_type, value })
                    .collect(),
            ))
        }
        Some(AttributesFormat::Array(attrs)) => Ok(Some(attrs)),
        None => Ok(None),
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Media {
    pub uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Assets {
    pub glb: Option<String>,
}

// ERC721/ERC1155 minimal ABI to get the token URI
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface INFT {
        function tokenURI(uint256 tokenId) external view returns (string);
        function uri(uint256 id) external view returns (string);
    }
}

fn is_rate_limited(e: &Error) -> bool {
    e.to_string().contains("429")
}

// Helper function to handle contract calls with retries
async fn try_call_contract<Fut, T>(mut f: impl FnMut() -> Fut) -> Result<T, Error>
where
    Fut: Future<Output = Result<T, Error>> + Send,
{
    const MAX_RETRIES: u32 = 5;
    const RETRY_DELAY_MS: u64 = 1000;

    let mut attempts = 0;
    loop {
        match f().await {
            Ok(uri) => return Ok(uri),
            Err(e) if is_rate_limited(&e) && attempts < MAX_RETRIES => {
                attempts += 1;
                sleep(Duration::from_millis(RETRY_DELAY_MS * attempts as u64)).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

pub struct EvmChainProcessor;

#[async_trait::async_trait]
impl crate::chain::NFTChainProcessor for EvmChainProcessor {
    type Metadata = NFTMetadata;
    type ContractWithToken = ContractWithToken;
    type RpcClient = alloy::providers::RootProvider<Http<Client>>;

    async fn fetch_metadata(
        &self,
        token_uri: &str,
        contract: &Self::ContractWithToken,
        output_path: &std::path::Path,
        chain_name: &str,
    ) -> anyhow::Result<(Self::Metadata, std::path::PathBuf)> {
        debug!(
            "Fetching metadata from {} for contract {}",
            token_uri,
            contract.address()
        );
        let metadata_content = fetch_and_save_content(
            token_uri,
            chain_name,
            &contract.address,
            &contract.token_id,
            output_path,
            Options {
                overriden_filename: Some("metadata.json".to_string()),
                fallback_filename: None,
            },
        )
        .await?;
        let metadata_content_str = tokio::fs::read_to_string(&metadata_content).await?;
        let metadata: NFTMetadata = serde_json::from_str(&metadata_content_str)?;
        Ok((metadata, metadata_content))
    }

    fn collect_urls_to_download(metadata: &Self::Metadata) -> Vec<(String, Option<String>)> {
        let mut urls_to_download = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let mut add_if_not_empty = |url: &str, name: Option<&str>| {
            if !url.is_empty() && seen.insert(url.to_string()) {
                urls_to_download.push((url.to_string(), name.map(|s| s.to_string())));
            }
        };

        if let Some(media) = &metadata.media {
            add_if_not_empty(&media.uri, Some("media"));
        }
        if let Some(content) = &metadata.content {
            add_if_not_empty(&content.uri, Some("content"));
        }
        if let Some(assets) = &metadata.assets {
            if let Some(glb) = &assets.glb {
                add_if_not_empty(glb, Some("glb"));
            }
        }
        if let Some(image) = &metadata.image {
            add_if_not_empty(image, Some("image"));
        }
        if let Some(image_url) = &metadata.image_url {
            add_if_not_empty(image_url, Some("image"));
        }
        if let Some(animation_url) = &metadata.animation_url {
            add_if_not_empty(animation_url, Some("animation"));
        }

        urls_to_download
    }

    async fn get_uri(
        &self,
        rpc: &Self::RpcClient,
        contract: &Self::ContractWithToken,
    ) -> anyhow::Result<String> {
        use alloy::primitives::{Address, U256};
        let contract_addr = contract.address().parse::<Address>()?;
        let token_id = U256::from_str_radix(contract.token_id(), 10)?;
        let nft = INFT::new(contract_addr, rpc);

        let uri = match try_call_contract(|| {
            let nft = nft.clone();
            async move { nft.tokenURI(token_id).call().await }
        })
        .await
        {
            Ok(uri) => Ok(uri._0),
            Err(e) if !is_rate_limited(&e) => {
                let uri = try_call_contract(|| {
                    let nft = nft.clone();
                    async move { nft.uri(token_id).call().await }
                })
                .await?;
                Ok(uri._0)
            }
            Err(e) => Err(e),
        }?;

        // Handle OpenSea's URI pattern
        if uri.contains("/api.opensea.io/") && uri.contains("{id}") {
            let hex_token_id = format!("{:x}", token_id);
            return Ok(uri.replace("{id}", &hex_token_id));
        }

        Ok(uri)
    }
}
