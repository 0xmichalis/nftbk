use anyhow::{Context, Result};
use ethers::{
    contract::Contract,
    providers::{Http, Provider},
    types::Address,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use url::Url;

use crate::url::get_url;

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

pub async fn fetch_and_save_content(
    url: &str,
    output_path: &Path,
    chain: &str,
    token_id: &str,
    contract: &str,
    content_type: &str,
) -> Result<PathBuf> {
    let content_url = get_url(url);
    let client = reqwest::Client::new();
    let response = client.get(&content_url).send().await?;
    let content = response.bytes().await?;

    let url = Url::parse(url)?;
    let file_name = url
        .path_segments()
        .and_then(|segments| segments.last())
        .unwrap_or(content_type);

    let dir_path = output_path.join(chain).join(contract).join(token_id);
    fs::create_dir_all(&dir_path).await?;

    let file_path = dir_path.join(file_name);
    fs::write(&file_path, content).await?;

    Ok(file_path)
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

#[derive(Debug, Deserialize)]
pub struct ContractsConfig {
    pub contracts: Contracts,
}

#[derive(Debug, Deserialize)]
pub struct Contracts {
    ethereum: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ContractWithToken {
    pub address: String,
    pub token_id: u64,
}

pub async fn process_nfts(config_path: &Path, output_path: &Path) -> Result<()> {
    let provider =
        Provider::<Http>::try_from(std::env::var("ETH_RPC_URL").context("ETH_RPC_URL not set")?)?;

    let config = fs::read_to_string(config_path).await?;
    let contracts_config = toml::from_str::<ContractsConfig>(&config)?;

    let contracts = contracts_config
        .contracts
        .ethereum
        .into_iter()
        .map(|s| {
            let parts: Vec<&str> = s.split(':').collect();
            ContractWithToken {
                address: parts[0].to_string(),
                token_id: parts[1].parse().unwrap(),
            }
        })
        .collect::<Vec<_>>();

    for contract in contracts {
        let contract_addr = contract.address.parse::<Address>()?;
        let abi: ethers::abi::Abi = serde_json::from_str(NFT_ABI)?;
        let contract_instance = Contract::new(contract_addr, abi, provider.clone().into());

        println!("Processing contract {}", contract_addr);

        let token_id = contract.token_id;

        // Try both tokenURI and uri functions
        let token_uri = match contract_instance
            .method::<_, String>("tokenURI", token_id)?
            .call()
            .await
        {
            Ok(uri) => uri,
            Err(_) => match contract_instance
                .method::<_, String>("uri", token_id)?
                .call()
                .await
            {
                Ok(uri) => uri,
                Err(_) => continue, // Skip if we can't get URI
            },
        };

        println!("Fetching token {} metadata from {}", token_id, token_uri);

        // Convert IPFS URLs to gateway URL if needed
        let metadata_url = get_url(&token_uri);

        // Fetch and save metadata
        let client = reqwest::Client::new();
        let metadata: NFTMetadata = client.get(&metadata_url).send().await?.json().await?;

        // Save metadata
        let dir_path = output_path
            .join("ethereum")
            .join(contract_addr.to_string())
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
                output_path,
                "ethereum",
                &token_id.to_string(),
                &contract_addr.to_string(),
                "image",
            )
            .await?;
        }

        if let Some(animation_url) = &metadata.animation_url {
            println!("Downloading animation from {}", animation_url);
            fetch_and_save_content(
                animation_url,
                output_path,
                "ethereum",
                &token_id.to_string(),
                &contract_addr.to_string(),
                "animation",
            )
            .await?;
        }
    }

    Ok(())
}
