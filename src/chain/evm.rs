use anyhow::{Context, Result};
use ethers::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;

use crate::content::{fetch_and_save_content, url::get_url};

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

// ERC721/ERC1155 minimal ABI for token URI and balance
const NFT_ABI: &str = r#"[
    {
        "inputs": [{"name": "tokenId", "type": "uint256"}],
        "name": "tokenURI",
        "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"name": "owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"name": "id", "type": "uint256"}],
        "name": "uri",
        "outputs": [{"name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    }
]"#;

#[derive(Debug)]
struct ContractWithToken {
    address: String,
    token_id: String,
}

pub async fn process_nfts(
    chain_name: &str,
    rpc_url: &str,
    contracts: Vec<String>,
    output_path: &Path,
) -> Result<()> {
    let provider = Provider::<Http>::try_from(rpc_url)
        .context(format!("Failed to connect to {} RPC", chain_name))?;

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
        println!("Processing contract {} on {}", contract.address, chain_name);
        let contract_addr = match contract.address.parse::<Address>() {
            Ok(addr) => addr,
            Err(e) => {
                println!("Failed to parse contract address on {}: {}", chain_name, e);
                continue;
            }
        };
        let abi: ethers::abi::Abi = serde_json::from_str(NFT_ABI)?;
        let contract_instance = Contract::new(contract_addr, abi, provider.clone().into());

        // Parse token ID into U256
        let token_id = match ethers::types::U256::from_dec_str(&contract.token_id) {
            Ok(id) => id,
            Err(e) => {
                println!("Failed to parse token ID: {}", e);
                continue;
            }
        };

        // Try both tokenURI and uri functions
        let token_uri = match contract_instance
            .method::<_, String>("tokenURI", token_id)?
            .call()
            .await
        {
            Ok(uri) => uri,
            Err(e) => {
                println!("tokenURI failed: {}, trying uri...", e);
                match contract_instance
                    .method::<_, String>("uri", token_id)?
                    .call()
                    .await
                {
                    Ok(uri) => uri,
                    Err(e) => {
                        println!("uri failed: {}, skipping token", e);
                        continue;
                    }
                }
            }
        };

        println!("Fetching token {} metadata from {}", &token_id, token_uri);

        // Convert IPFS URLs to gateway URL if needed
        let metadata_url = get_url(&token_uri);

        // Fetch and save metadata
        let client = reqwest::Client::new();
        let metadata: NFTMetadata = client.get(&metadata_url).send().await?.json().await?;

        // Save metadata
        let dir_path = output_path
            .join(chain_name)
            .join(format!("{:#x}", contract_addr))
            .join(token_id.to_string());
        fs::create_dir_all(&dir_path).await?;
        fs::write(
            dir_path.join("metadata.json"),
            serde_json::to_string_pretty(&metadata)?,
        )
        .await?;

        // Save linked content
        if let Some(image_url) = &metadata.image {
            println!("Downloading image from {}", image_url);
            fetch_and_save_content(
                image_url,
                chain_name,
                &format!("{:#x}", contract_addr),
                &token_id.to_string(),
                output_path,
                Some("image"),
            )
            .await?;
        }

        if let Some(animation_url) = &metadata.animation_url {
            println!("Downloading animation from {}", animation_url);
            fetch_and_save_content(
                animation_url,
                chain_name,
                &format!("{:#x}", contract_addr),
                &token_id.to_string(),
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
