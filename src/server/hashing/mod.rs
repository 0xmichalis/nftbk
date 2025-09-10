use crate::server::api::Tokens;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

/// Compute a stable task id for a backup request, including the requestor (tenant)
/// to avoid cross-tenant collisions. The hashing of tokens remains order-independent
/// across chains and within each chain.
pub fn compute_task_id(tokens: &[Tokens], requestor: Option<&str>) -> String {
    let mut chain_token_pairs = Vec::new();
    let mut sorted_tokens = tokens.to_vec();
    // Sort by chain name to ensure deterministic order
    sorted_tokens.sort_by(|a, b| a.chain.cmp(&b.chain));
    for entry in &mut sorted_tokens {
        // Sort tokens within each chain
        entry.tokens.sort();
        for token in &entry.tokens {
            // Combine chain and token for uniqueness
            chain_token_pairs.push(format!("{}:{}", entry.chain, token));
        }
    }
    let mut hasher = Sha256::new();
    // Mix requestor first so same tokens under different tenants diverge
    let req = requestor.unwrap_or("");
    hasher.update(req.as_bytes());
    hasher.update([0u8]); // separator
    for pair in &chain_token_pairs {
        hasher.update(pair.as_bytes());
        hasher.update([0u8]); // separator between entries
    }
    format!("{:x}", hasher.finalize())
}

pub async fn compute_file_sha256(path: &Path) -> anyhow::Result<String> {
    let mut file = File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::api::Tokens;

    #[test]
    fn test_deterministic_hashing_order_independence() {
        let t1 = Tokens {
            chain: "eth".to_string(),
            tokens: vec!["a".to_string(), "b".to_string()],
        };
        let t2 = Tokens {
            chain: "tezos".to_string(),
            tokens: vec!["c".to_string()],
        };
        let req1 = vec![t1.clone(), t2.clone()];
        let req2 = vec![t2, t1]; // different order
        let hash1 = compute_task_id(&req1, Some("tenant"));
        let hash2 = compute_task_id(&req2, Some("tenant"));
        assert_eq!(hash1, hash2, "Hash should be order-independent");
    }

    #[test]
    fn test_chain_token_uniqueness() {
        let t1 = Tokens {
            chain: "eth".to_string(),
            tokens: vec!["a".to_string()],
        };
        let t2 = Tokens {
            chain: "tezos".to_string(),
            tokens: vec!["a".to_string()],
        };
        let hash1 = compute_task_id(&[t1.clone()], Some("tenant"));
        let hash2 = compute_task_id(&[t2.clone()], Some("tenant"));
        assert_ne!(
            hash1, hash2,
            "Same token on different chains should have different hashes"
        );
    }

    #[test]
    fn test_token_order_within_chain() {
        let t1 = Tokens {
            chain: "eth".to_string(),
            tokens: vec!["b".to_string(), "a".to_string()],
        };
        let t2 = Tokens {
            chain: "eth".to_string(),
            tokens: vec!["a".to_string(), "b".to_string()],
        };
        let hash1 = compute_task_id(&[t1], Some("tenant"));
        let hash2 = compute_task_id(&[t2], Some("tenant"));
        assert_eq!(
            hash1, hash2,
            "Token order within chain should not affect hash"
        );
    }

    #[test]
    fn test_requestor_affects_hash() {
        let t = Tokens {
            chain: "eth".to_string(),
            tokens: vec!["a".to_string()],
        };
        let h1 = compute_task_id(&[t.clone()], Some("tenant-a"));
        let h2 = compute_task_id(&[t], Some("tenant-b"));
        assert_ne!(
            h1, h2,
            "Different requestors should yield different task ids"
        );
    }

    #[test]
    fn test_requestor_optional_doesnt_panic() {
        let t = Tokens {
            chain: "eth".to_string(),
            tokens: vec!["a".to_string()],
        };
        let _ = compute_task_id(&[t], None);
    }
}
