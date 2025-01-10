use anyhow::Result;

pub async fn process_nfts(contracts: Vec<String>, output_path: &std::path::Path) -> Result<()> {
    println!("Tezos support is not yet implemented");
    for contract in contracts {
        let parts: Vec<&str> = contract.split(':').collect();
        println!("Contract {} (token id={})", parts[0], parts[1]);
    }
    println!("Backup path: {}", output_path.display());
    Ok(())
}
