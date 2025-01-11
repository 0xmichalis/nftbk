use anyhow::Result;
use std::path::Path;
use tokio::fs;

async fn extend_crocket_challenge_content(
    output_path: &Path,
    contract: &str,
    token_id: &str,
) -> Result<()> {
    // Create Build directory
    let build_dir = output_path
        .join("ethereum")
        .join(contract)
        .join(token_id)
        .join("Build");
    fs::create_dir_all(&build_dir).await?;

    // Files to download with their target names
    let files = [
        ("bb0101.data.gz", "bb0101_uncompressed.data"),
        ("bb0101.framework.js.gz", "bb0101_uncompressed.framework.js"),
        ("bb0101.loader.js", "bb0101_uncompressed.loader.js"),
        ("bb0101.wasm.gz", "bb0101_uncompressed.wasm"),
    ];

    // Download each file
    let client = reqwest::Client::new();
    for (source_file, target_file) in files {
        let url = format!("https://chan.gallery/bb0101/Build/{}", source_file);
        let file_path = build_dir.join(target_file);

        // Skip if file already exists
        if fs::try_exists(&file_path).await? {
            println!("File already exists at {}", file_path.display());
            continue;
        }

        println!("Downloading {} as {}", url, target_file);
        let response = client.get(&url).send().await?;
        let content = response.bytes().await?;
        fs::write(file_path, content).await?;
    }

    Ok(())
}

/// Extends content handling based on chain, contract address, and token ID.
/// This function is called after the main content has been downloaded and saved.
pub async fn extend_content(
    chain: &str,
    contract: &str,
    token_id: &str,
    _output_path: &Path,
) -> Result<()> {
    match (chain, contract, token_id) {
        (
            "ethereum",
            "0x2A86C5466f088caEbf94e071a77669BAe371CD87",
            "25811853076941608055270457512038717433705462539422789705262203111341130500780",
        ) => extend_crocket_challenge_content(_output_path, contract, token_id).await,
        // Default case - no extension needed
        _ => Ok(()),
    }
}
