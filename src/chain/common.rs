use serde::{Deserialize, Serialize};

pub trait ContractTokenInfo {
    fn address(&self) -> &str;
    fn token_id(&self) -> &str;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractTokenId {
    pub address: String,
    pub token_id: String,
}

impl ContractTokenInfo for ContractTokenId {
    fn address(&self) -> &str {
        &self.address
    }
    fn token_id(&self) -> &str {
        &self.token_id
    }
}

impl ContractTokenId {
    pub fn parse_tokens(tokens: &[String]) -> Vec<Self> {
        tokens
            .iter()
            .map(|s| {
                let parts: Vec<&str> = s.split(':').collect();
                ContractTokenId {
                    address: parts[0].to_string(),
                    token_id: parts[1].to_string(),
                }
            })
            .collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTAttribute {
    pub trait_type: String,
    pub value: serde_json::Value,
}
