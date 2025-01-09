use anyhow::Result;
use serde::Deserialize;
use std::path::Path;
use tokio::fs;

#[derive(Debug, Deserialize)]
pub struct ContractWithToken {
    pub address: String,
    pub token_id: u64,
}

pub async fn process_nfts(config_path: &Path, output_path: &Path) -> Result<()> {
    println!("Tezos support is not yet implemented");
    let config = fs::read_to_string(config_path).await?;
    let contracts = toml::from_str::<Vec<ContractWithToken>>(&config)?;
    for contract in contracts {
        println!("Contract {} (token id={})", contract.address, contract.token_id);
    }
    println!("Backup path: {}", output_path.display());
    Ok(())
}
