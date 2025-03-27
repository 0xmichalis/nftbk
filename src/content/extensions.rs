use anyhow::Result;
use flate2::read::GzDecoder;
use std::ffi::OsStr;
use std::io::Read;
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, info};

/// List of known media file extensions that we handle
const KNOWN_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "mp3", "mp4", "mov", "mpg", "html", "json", "glb",
];

/// Checks if a path has a known media file extension
pub fn has_known_extension(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(OsStr::to_str) {
        KNOWN_EXTENSIONS.contains(&ext.to_lowercase().as_str())
    } else {
        false
    }
}

/// Gets a path with a known extension in the same directory, if one exists
pub async fn find_path_with_known_extension(path: &Path) -> Result<Option<PathBuf>> {
    if let Some(parent) = path.parent() {
        // Get the appropriate stem based on whether the path has a known extension
        let search_stem = if has_known_extension(path) {
            path.file_stem().map(|s| s.to_string_lossy().to_string())
        } else {
            // If path doesn't have a known extension, use the whole filename as stem
            path.file_name().map(|s| s.to_string_lossy().to_string())
        };

        if let Some(stem) = search_stem {
            if fs::try_exists(parent).await? {
                let mut dir = fs::read_dir(parent).await?;
                while let Some(entry) = dir.next_entry().await? {
                    let entry_path = entry.path();
                    if entry_path
                        .file_stem()
                        .map_or(false, |s| s.to_string_lossy() == stem)
                        && has_known_extension(&entry_path)
                    {
                        return Ok(Some(entry_path));
                    }
                }
            }
        }
    }
    Ok(None)
}

async fn extend_croquet_challenge_content(
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

        info!("Saving {} as {}", url, target_file);
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
    }

    Ok(())
}

/// Extends content handling based on chain, contract address, and token ID.
/// This function is called after the main content has been downloaded and saved.
pub async fn fetch_and_save_additional_content(
    chain: &str,
    contract: &str,
    token_id: &str,
    _output_path: &Path,
) -> Result<()> {
    match (chain, contract, token_id) {
        (
            "ethereum",
            "0x2a86c5466f088caebf94e071a77669bae371cd87",
            "25811853076941608055270457512038717433705462539422789705262203111341130500780",
        ) => extend_croquet_challenge_content(_output_path, contract, token_id).await,
        // Default case - no extension needed
        _ => Ok(()),
    }
}
