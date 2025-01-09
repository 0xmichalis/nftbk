use anyhow::{Context, Result};
use clap::Parser;
use ethers::{
    prelude::*,
    providers::{Http, Provider},
    types::Address as EthAddress,
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};
use tokio::fs;
use url::Url;

// CLI Arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// List of Ethereum or Tezos addresses to fetch NFTs from
    #[arg(required = true)]
    addresses: Vec<String>,

    /// Path to the NFT contracts configuration file
    #[arg(short, long)]
    config_path: PathBuf,

    /// Optional backup directory path (defaults to current directory)
    #[arg(short, long)]
    path: Option<PathBuf>,
}

// TOML Config structure
#[derive(Debug, Deserialize)]
struct ContractsConfig {
    contracts: Contracts,
}

#[derive(Debug, Deserialize)]
struct Contracts {
    ethereum: Vec<ContractWithToken>,
    tezos: Vec<ContractWithToken>,
}

#[derive(Debug, Deserialize)]
struct ContractWithToken {
    address: String,
    token_id: u64,
}

// NFT Metadata structure
#[derive(Debug, Serialize, Deserialize)]
struct NFTMetadata {
    name: Option<String>,
    description: Option<String>,
    image: Option<String>,
    animation_url: Option<String>,
    external_url: Option<String>,
    attributes: Option<Vec<NFTAttribute>>,
    #[serde(flatten)]
    extra: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct NFTAttribute {
    trait_type: String,
    value: serde_json::Value,
}

#[derive(Debug)]
enum ChainAddress {
    Ethereum(EthAddress),
    Tezos(String),
}

impl FromStr for ChainAddress {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.starts_with("KT1") {
            Ok(ChainAddress::Tezos(s.to_string()))
        } else {
            Ok(ChainAddress::Ethereum(
                s.parse().context("Failed to parse Ethereum address")?,
            ))
        }
    }
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

async fn fetch_and_save_content(
    url: &str,
    base_path: &Path,
    token_id: &str,
    contract: &str,
    content_type: &str,
) -> Result<PathBuf> {
    let client = reqwest::Client::new();
    let response = client.get(url).send().await?;
    let content = response.bytes().await?;

    let url = Url::parse(url)?;
    let file_name = url
        .path_segments()
        .and_then(|segments| segments.last())
        .unwrap_or(content_type);

    let dir_path = base_path.join(contract).join(token_id);
    fs::create_dir_all(&dir_path).await?;

    let file_path = dir_path.join(file_name);
    fs::write(&file_path, content).await?;

    Ok(file_path)
}

async fn process_ethereum_nfts(config_path: &Path, base_path: &Path) -> Result<()> {
    let provider =
        Provider::<Http>::try_from(std::env::var("ETH_RPC_URL").context("ETH_RPC_URL not set")?)?;

    let config = fs::read_to_string(config_path).await?;
    let contracts = toml::from_str::<ContractsConfig>(&config)?
        .contracts
        .ethereum;

    for contract in contracts {
        let contract_addr = contract.address.parse::<EthAddress>()?;
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
        let dir_path = base_path
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
                base_path,
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
                base_path,
                &token_id.to_string(),
                &contract_addr.to_string(),
                "animation",
            )
            .await?;
        }
    }

    Ok(())
}

async fn process_tezos_nfts(config_path: &Path, base_path: &Path) -> Result<()> {
    println!("Tezos support is not yet implemented");
    let config = fs::read_to_string(config_path).await?;
    let contracts = toml::from_str::<ContractsConfig>(&config)?.contracts.tezos;
    println!("Contracts: {:?}", contracts);
    println!("Backup path: {}", base_path.display());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Parse command line arguments
    let args = Args::parse();

    // Use provided path or current directory
    let base_path = args.path.unwrap_or_else(|| PathBuf::from("."));

    // Create base directory if it doesn't exist
    fs::create_dir_all(&base_path).await?;

    // Process each address
    for addr_str in args.addresses {
        let chain_address = addr_str.parse::<ChainAddress>()?;

        match chain_address {
            ChainAddress::Ethereum(_) => {
                process_ethereum_nfts(&args.config_path, &base_path).await?;
            }
            ChainAddress::Tezos(_) => {
                process_tezos_nfts(&args.config_path, &base_path).await?;
            }
        }
    }

    Ok(())
}
