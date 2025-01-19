use alloy::{
    primitives::{Address, U256},
    providers::{ProviderBuilder, RootProvider},
    sol,
    transports::http::{Client, Http},
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::{future::Future, path::Path};
use tokio::fs;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::content::fetch_and_save_content;

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub animation_url: Option<String>,
    pub external_url: Option<String>,
    pub attributes: Option<Vec<NFTAttribute>>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTAttribute {
    pub trait_type: String,
    pub value: serde_json::Value,
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

#[derive(Debug)]
struct ContractWithToken {
    address: String,
    token_id: String,
}

// Helper function to handle contract calls with retries
async fn try_call_contract<F, T>(mut f: F) -> Result<T>
where
    F: FnMut() -> std::pin::Pin<Box<dyn Future<Output = Result<T, alloy::contract::Error>> + Send>>,
{
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_MS: u64 = 1000;

    let mut attempts = 0;
    loop {
        match f().await {
            Ok(uri) => return Ok(uri),
            Err(e) if e.to_string().contains("429") && attempts < MAX_RETRIES => {
                attempts += 1;
                sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

async fn get_token_uri(
    contract_addr: Address,
    provider: RootProvider<Http<Client>>,
    token_id: U256,
) -> Result<String> {
    let nft = INFT::new(contract_addr, provider);

    match try_call_contract(|| {
        let nft = nft.clone();
        Box::pin(async move { nft.tokenURI(token_id).call().await })
    })
    .await
    {
        Ok(uri) => Ok(uri._0),
        Err(e) if !e.to_string().contains("429") => {
            let uri = try_call_contract(|| {
                let nft = nft.clone();
                Box::pin(async move { nft.uri(token_id).call().await })
            })
            .await?;
            Ok(uri._0)
        }
        Err(e) => Err(e),
    }
}

pub async fn process_nfts(
    chain_name: &str,
    rpc_url: &str,
    contracts: Vec<String>,
    output_path: &Path,
) -> Result<()> {
    let rpc_url = rpc_url.parse::<url::Url>()?;
    let provider = ProviderBuilder::new().on_http(rpc_url);

    let contracts = contracts
        .into_iter()
        .map(|s| {
            let parts: Vec<&str> = s.split(':').collect();
            ContractWithToken {
                address: parts[0].to_string(),
                token_id: parts[1].to_string(),
            }
        })
        .collect::<Vec<_>>();

    for contract in contracts {
        info!("Processing contract {} on {}", contract.address, chain_name);
        let contract_addr = match contract.address.parse::<Address>() {
            Ok(addr) => addr,
            Err(e) => {
                warn!("Failed to parse contract address on {}: {}", chain_name, e);
                continue;
            }
        };

        // Parse token ID into U256
        let token_id = match U256::from_str_radix(&contract.token_id, 10) {
            Ok(id) => id,
            Err(e) => {
                warn!("Failed to parse token ID: {}", e);
                continue;
            }
        };

        // Get token URI
        let token_uri = match get_token_uri(contract_addr, provider.clone(), token_id).await {
            Ok(uri) => uri,
            Err(e) => {
                error!("Failed to get token URI: {}, skipping token", e);
                continue;
            }
        };

        // Save metadata
        info!("Fetching metadata from {}", token_uri);
        let contract_address = format!("{:#x}", contract_addr);
        let token_id_str = token_id.to_string();
        let metadata_content = fetch_and_save_content(
            &token_uri,
            chain_name,
            &contract_address,
            &token_id_str,
            output_path,
            Some("metadata.json"),
        )
        .await?;
        let metadata_content_str = fs::read_to_string(metadata_content).await?;
        let metadata: NFTMetadata = serde_json::from_str(&metadata_content_str)?;

        // Save linked content
        if let Some(image_url) = &metadata.image {
            info!("Downloading image from {}", image_url);
            fetch_and_save_content(
                image_url,
                chain_name,
                &contract_address,
                &token_id_str,
                output_path,
                Some("image"),
            )
            .await?;
        }

        if let Some(animation_url) = &metadata.animation_url {
            info!("Downloading animation from {}", animation_url);
            fetch_and_save_content(
                animation_url,
                chain_name,
                &contract_address,
                &token_id_str,
                output_path,
                Some("animation"),
            )
            .await?;
        }

        // Process any additional content after downloading all files
        crate::content::extensions::fetch_and_save_additional_content(
            chain_name,
            &format!("{:#x}", contract_addr),
            &token_id.to_string(),
            output_path,
        )
        .await?;
    }

    Ok(())
}
