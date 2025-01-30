use alloy::{
    contract::Error,
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
use tracing::{debug, error};

use crate::content::{
    extensions::fetch_and_save_additional_content, fetch_and_save_content, Options,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub animation_url: Option<String>,
    pub external_url: Option<String>,
    pub attributes: Option<Vec<NFTAttribute>>,
    pub media: Option<Media>,
    pub content: Option<Media>,
    pub assets: Option<Assets>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTAttribute {
    pub trait_type: String,
    pub value: serde_json::Value,
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

#[derive(Debug)]
struct ContractWithToken {
    address: String,
    token_id: String,
}

fn is_rate_limited(e: &Error) -> bool {
    e.to_string().contains("429")
}

// Helper function to handle contract calls with retries
async fn try_call_contract<Fut, T>(mut f: impl FnMut() -> Fut) -> Result<T, Error>
where
    Fut: Future<Output = Result<T, Error>> + Send,
{
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_MS: u64 = 1000;

    let mut attempts = 0;
    loop {
        match f().await {
            Ok(uri) => return Ok(uri),
            Err(e) if is_rate_limited(&e) && attempts < MAX_RETRIES => {
                attempts += 1;
                sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

async fn get_token_uri(
    contract_addr: Address,
    provider: RootProvider<Http<Client>>,
    token_id: U256,
) -> Result<String, Error> {
    let nft = INFT::new(contract_addr, provider);

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

fn get_uri_from_media(media: &Media, fallback_uri: &str) -> String {
    let mut uri = media.uri.to_string();
    if uri.is_empty() {
        uri = fallback_uri.to_string();
    }
    uri
}

fn get_uri_from_metadata(
    metadata: &NFTMetadata,
    fallback_uri: &str,
    check_image_details: bool,
    check_animation_details: bool,
) -> String {
    if !check_image_details && !check_animation_details {
        panic!("Need to check the extension of either an image or animation");
    }
    if let Some(media) = &metadata.media {
        return get_uri_from_media(media, fallback_uri);
    }
    if let Some(content) = &metadata.content {
        return get_uri_from_media(content, fallback_uri);
    }
    if let Some(assets) = &metadata.assets {
        if let Some(glb) = &assets.glb {
            return glb.to_string();
        }
    }
    fallback_uri.to_string()
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
        debug!("Processing contract {} on {}", contract.address, chain_name);
        let contract_addr = match contract.address.parse::<Address>() {
            Ok(addr) => addr,
            Err(e) => {
                error!("Failed to parse contract address on {}: {}", chain_name, e);
                continue;
            }
        };

        // Parse token ID into U256
        let token_id = match U256::from_str_radix(&contract.token_id, 10) {
            Ok(id) => id,
            Err(e) => {
                error!("Failed to parse token ID: {}", e);
                continue;
            }
        };

        // Get token URI
        let token_uri = match get_token_uri(contract_addr, provider.clone(), token_id).await {
            Ok(uri) => uri,
            Err(e) => {
                error!("Failed to get token URI: {}", e);
                continue;
            }
        };

        // Save metadata
        debug!("Fetching metadata from {}", token_uri);
        let contract_address = format!("{:#x}", contract_addr);
        let token_id_str = token_id.to_string();
        let metadata_content = match fetch_and_save_content(
            &token_uri,
            chain_name,
            &contract_address,
            &token_id_str,
            output_path,
            Options {
                overriden_filename: Some("metadata.json".to_string()),
                fallback_filename: None,
            },
        )
        .await
        {
            Ok(content) => content,
            Err(e) => {
                error!("Failed to fetch metadata: {}", e);
                continue;
            }
        };

        let metadata_content_str = fs::read_to_string(metadata_content).await?;
        let metadata: NFTMetadata = serde_json::from_str(&metadata_content_str)?;

        // Save linked content
        if let Some(image_url) = &metadata.image {
            let image_url = get_uri_from_metadata(&metadata, image_url, true, false);
            debug!("Downloading image from {}", image_url);
            fetch_and_save_content(
                &image_url,
                chain_name,
                &contract_address,
                &token_id_str,
                output_path,
                Options {
                    overriden_filename: None,
                    fallback_filename: Some("image".to_string()),
                },
            )
            .await?;
        }

        if let Some(animation_url) = &metadata.animation_url {
            let animation_url = get_uri_from_metadata(&metadata, animation_url, false, true);
            debug!("Downloading animation from {}", animation_url);
            fetch_and_save_content(
                &animation_url,
                chain_name,
                &contract_address,
                &token_id_str,
                output_path,
                Options {
                    overriden_filename: None,
                    fallback_filename: Some("animation".to_string()),
                },
            )
            .await?;
        }

        // Process any additional content after downloading all files
        fetch_and_save_additional_content(
            chain_name,
            &format!("{:#x}", contract_addr),
            &token_id.to_string(),
            output_path,
        )
        .await?;
    }

    Ok(())
}
