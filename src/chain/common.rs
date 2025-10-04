use serde::{Deserialize, Serialize};
use std::fmt;

pub trait ContractTokenInfo {
    fn address(&self) -> &str;
    fn token_id(&self) -> &str;
    fn chain_name(&self) -> &str;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractTokenId {
    pub address: String,
    pub token_id: String,
    pub chain_name: String,
}

impl ContractTokenInfo for ContractTokenId {
    fn address(&self) -> &str {
        &self.address
    }
    fn token_id(&self) -> &str {
        &self.token_id
    }
    fn chain_name(&self) -> &str {
        &self.chain_name
    }
}

impl ContractTokenId {
    pub fn parse_tokens(tokens: &[String], chain_name: &str) -> Vec<Self> {
        tokens
            .iter()
            .map(|s| {
                let parts: Vec<&str> = s.split(':').collect();
                ContractTokenId {
                    address: parts[0].to_string(),
                    token_id: parts[1].to_string(),
                    chain_name: chain_name.to_string(),
                }
            })
            .collect()
    }
}

impl fmt::Display for ContractTokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} contract {} (token ID {})",
            self.chain_name, self.address, self.token_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_contract_token_id() {
        let token = ContractTokenId {
            address: "0x1234567890123456789012345678901234567890".to_string(),
            token_id: "42".to_string(),
            chain_name: "ethereum".to_string(),
        };

        let formatted = format!("{}", token);
        assert_eq!(
            formatted,
            "ethereum contract 0x1234567890123456789012345678901234567890 (token ID 42)"
        );
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTAttribute {
    pub trait_type: String,
    pub value: serde_json::Value,
}
