use anyhow::Result;
use flate2::read::GzDecoder;
use std::io::Read;
use std::path::Path;
use tokio::fs;
use tracing::{debug, info, warn};

use crate::url::get_url;

async fn fetch_croquet_challenge_content(
    output_path: &Path,
    contract: &str,
    token_id: &str,
) -> Result<()> {
    debug!(
        "Fetching additional content for Ethereum contract {} token {}",
        contract, token_id
    );

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
            debug!("File already exists at {}", file_path.display());
            continue;
        }

        let response = client.get(&url).send().await?;
        let content = response.bytes().await?;

        // Decompress if it's a gzipped file
        let final_content = if source_file.ends_with(".gz") {
            let mut decoder = GzDecoder::new(&content[..]);
            let mut decompressed = Vec::new();
            decoder.read_to_end(&mut decompressed)?;
            decompressed
        } else {
            content.to_vec()
        };

        fs::write(file_path, final_content).await?;
        info!("Saved {} from {}", target_file, url);
    }

    Ok(())
}

async fn fetch_the_fisherman_content(
    output_path: &Path,
    contract: &str,
    token_id: &str,
    artifact_url: &str,
) -> Result<()> {
    debug!(
        "Fetching additional content for Tezos contract {} token {}",
        contract, token_id
    );

    // Create token directory
    let token_dir = output_path.join("tezos").join(contract).join(token_id);
    fs::create_dir_all(&token_dir).await?;

    // Files to download
    let files = [
        "0.png",
        "1.png",
        "2.png",
        "4.png",
        "5.png",
        "6.png",
        "7.png",
        "8.png",
        "10.png",
        "11.png",
        "13.png",
        "14.png",
        "sound1.mp3",
        "sound2.mp3",
        "IBMCGAthin.ttf",
    ];

    // Download each file
    let client = reqwest::Client::new();
    for file in files {
        let url = format!("{}/{}", artifact_url.trim_end_matches('/'), file);
        let file_path = token_dir.join(file);

        // Skip if file already exists
        if fs::try_exists(&file_path).await? {
            debug!("File already exists at {}", file_path.display());
            continue;
        }

        match client.get(&url).send().await {
            Ok(response) => {
                let content = response.bytes().await?;
                fs::write(&file_path, content).await?;
                info!("Saved {} from {}", file, url);
            }
            Err(e) => {
                warn!("Failed to download {}: {}", file, e);
            }
        }
    }

    Ok(())
}

/// Extends content handling based on chain, contract address, and token ID.
/// This function is called after the main content has been downloaded and saved.
pub async fn fetch_and_save_extra_content(
    chain: &str,
    contract: &str,
    token_id: &str,
    output_path: &Path,
    artifact_url: Option<&str>,
) -> Result<()> {
    match (chain, contract, token_id) {
        (
            "ethereum",
            "0x2a86c5466f088caebf94e071a77669bae371cd87",
            "25811853076941608055270457512038717433705462539422789705262203111341130500780",
        ) => fetch_croquet_challenge_content(output_path, contract, token_id).await,
        ("tezos", "KT1UcASzQxiWprSmsvpStsxtAZzaRJWR78gz", "4") if artifact_url.is_some() => {
            fetch_the_fisherman_content(
                output_path,
                contract,
                token_id,
                &get_url(artifact_url.unwrap()),
            )
            .await
        }
        // Default case - no extension needed
        _ => Ok(()),
    }
}
