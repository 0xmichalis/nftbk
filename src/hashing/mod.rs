use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs::read;

pub fn compute_array_sha256(array: &[String]) -> String {
    let mut hasher = Sha256::new();
    let mut sorted = array.to_vec();
    sorted.sort();
    for token in &sorted {
        hasher.update(token.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

pub async fn compute_file_sha256(path: &Path) -> anyhow::Result<String> {
    let contents = read(path).await?;
    let hash = Sha256::digest(&contents);
    Ok(format!("{:x}", hash))
}
