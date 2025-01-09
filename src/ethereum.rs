use anyhow::{Context, Result};
use ethers::{
    prelude::*,
    providers::{Http, Provider},
    types::Address,
};
use serde::Deserialize;
use std::path::Path;
use tokio::fs;

use crate::{fetch_and_save_content, NFTMetadata};

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
pub struct ContractWithToken {
    pub address: String,
    pub token_id: u64,
}

pub async fn process_nfts(config_path: &Path, output_path: &Path) -> Result<()> {
    let provider =
        Provider::<Http>::try_from(std::env::var("ETH_RPC_URL").context("ETH_RPC_URL not set")?)?;

    let config = fs::read_to_string(config_path).await?;
    let contracts = toml::from_str::<Vec<ContractWithToken>>(&config)?;

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

        // Fetch and save metadata
        let client = reqwest::Client::new();
        let metadata: NFTMetadata = client.get(&token_uri).send().await?.json().await?;

        // Save metadata
        let dir_path = output_path
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
                &token_id.to_string(),
                &contract_addr.to_string(),
                "animation",
            )
            .await?;
        }
    }

    Ok(())
}
