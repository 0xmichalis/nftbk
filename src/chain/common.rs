use serde::{Deserialize, Serialize};

pub trait ContractTokenInfo {
    fn address(&self) -> &str;
    fn token_id(&self) -> &str;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractWithToken {
    pub address: String,
    pub token_id: String,
}

impl ContractTokenInfo for ContractWithToken {
    fn address(&self) -> &str {
        &self.address
    }
    fn token_id(&self) -> &str {
        &self.token_id
    }
}

impl ContractWithToken {
    pub fn parse_contracts(contracts: &[String]) -> Vec<Self> {
        contracts
            .iter()
            .map(|s| {
                let parts: Vec<&str> = s.split(':').collect();
                ContractWithToken {
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
