use crate::server::api::Tokens;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::fs::read;

pub fn compute_array_sha256(tokens: &[Tokens]) -> String {
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
    for pair in &chain_token_pairs {
        hasher.update(pair.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

pub async fn compute_file_sha256(path: &Path) -> anyhow::Result<String> {
    let contents = read(path).await?;
    let hash = Sha256::digest(&contents);
    Ok(format!("{hash:x}"))
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
        let hash1 = compute_array_sha256(&req1);
        let hash2 = compute_array_sha256(&req2);
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
        let hash1 = compute_array_sha256(&[t1.clone()]);
        let hash2 = compute_array_sha256(&[t2.clone()]);
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
        let hash1 = compute_array_sha256(&[t1]);
        let hash2 = compute_array_sha256(&[t2]);
        assert_eq!(
            hash1, hash2,
            "Token order within chain should not affect hash"
        );
    }
}
