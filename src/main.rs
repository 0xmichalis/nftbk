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

    /// Optional list of specific NFT contract addresses to filter by
    #[arg(short, long, value_delimiter = ',')]
    nft_contracts: Option<Vec<String>>,

    /// Optional backup directory path (defaults to current directory)
    #[arg(short, long)]
    path: Option<PathBuf>,
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
        if s.starts_with("tz") {
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

async fn process_ethereum_nfts(
    address: EthAddress,
    nft_contracts: &Option<Vec<String>>,
    base_path: &Path,
) -> Result<()> {
    let provider =
        Provider::<Http>::try_from(std::env::var("ETH_RPC_URL").context("ETH_RPC_URL not set")?)?;

    let Some(contracts) = nft_contracts else {
        println!("No specific contracts provided. To fetch all NFTs, you need to specify contract addresses.");
        println!("Use --nft-contracts option with comma-separated contract addresses.");
        return Ok(());
    };

    for contract in contracts {
        let contract_addr = contract.parse::<EthAddress>()?;
        let abi: ethers::abi::Abi = serde_json::from_str(NFT_ABI)?;
        let contract = Contract::new(contract_addr, abi, provider.clone().into());

        // Try both ERC721 and ERC1155 balance checks
        let balance: U256 = match contract
            .method::<_, U256>("balanceOf", address)?
            .call()
            .await
        {
            Ok(bal) => bal,
            Err(_) => continue, // Skip if contract doesn't implement balanceOf
        };

        println!(
            "Processing contract {} (balance: {})",
            contract_addr, balance
        );

        for token_id in 0..balance.as_u64() {
            // Try both tokenURI and uri functions
            let token_uri = match contract
                .method::<_, String>("tokenURI", token_id)?
                .call()
                .await
            {
                Ok(uri) => uri,
                Err(_) => match contract.method::<_, String>("uri", token_id)?.call().await {
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
    }

    Ok(())
}

async fn process_tezos_nfts(
    address: &str,
    nft_contracts: &Option<Vec<String>>,
    base_path: &Path,
) -> Result<()> {
    println!("Tezos support is not yet implemented");
    println!("Address: {}", address);
    if let Some(contracts) = nft_contracts {
        println!("Contracts: {:?}", contracts);
    }
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
            ChainAddress::Ethereum(addr) => {
                process_ethereum_nfts(addr, &args.nft_contracts, &base_path).await?;
            }
            ChainAddress::Tezos(addr) => {
                process_tezos_nfts(&addr, &args.nft_contracts, &base_path).await?;
            }
        }
    }

    Ok(())
}
