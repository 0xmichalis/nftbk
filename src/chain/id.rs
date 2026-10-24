use anyhow::{bail, ensure, Result};

/// Validate a case-sensitive CAIP-2 identifier for a supported chain family.
pub fn validate_chain_id(id: &str) -> Result<()> {
    let Some((namespace, reference)) = id.split_once(':') else {
        bail!("Expected a CAIP-2 chain ID, for example eip155:1 or tezos:NetXdQprcVkpaWU");
    };
    ensure!(
        (3..=8).contains(&namespace.len())
            && namespace
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && (1..=32).contains(&reference.len())
            && reference
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "Invalid CAIP-2 chain ID"
    );
    match namespace {
        "eip155" => ensure!(
            reference.bytes().all(|b| b.is_ascii_digit()) && !reference.starts_with('0'),
            "EIP-155 references must be positive decimal integers without leading zeros"
        ),
        "tezos" => ensure!(
            reference.len() == 15
                && reference.starts_with("Net")
                && tezos_core::types::encoded::ChainId::try_from(reference).is_ok(),
            "Tezos references must be case-sensitive network IDs, for example NetXdQprcVkpaWU"
        ),
        _ => bail!("Unsupported CAIP-2 namespace: {namespace}"),
    }
    Ok(())
}

/// Map legacy configuration names during the 1.x to 2.x transition.
pub fn canonical_chain_id(id: &str) -> &str {
    match id {
        "ethereum" => "eip155:1",
        "polygon" => "eip155:137",
        "base" => "eip155:8453",
        "base-sepolia" => "eip155:84532",
        "arbitrum" => "eip155:42161",
        "optimism" => "eip155:10",
        "shape" => "eip155:360",
        "zora" => "eip155:7777777",
        "tezos" => "tezos:NetXdQprcVkpaWU",
        "ghostnet" => "tezos:NetXnHfVqm9iesp",
        _ => id,
    }
}

#[cfg(test)]
mod validate_chain_id_tests {
    use super::*;

    #[test]
    fn accepts_supported_networks_and_rejects_aliases_and_malformed_ids() {
        for id in [
            "eip155:1",
            "eip155:84532",
            "tezos:NetXdQprcVkpaWU",
            "tezos:NetXnHfVqm9iesp",
        ] {
            assert_eq!(validate_chain_id(id).map_err(|e| e.to_string()), Ok(()));
        }
        for id in [
            "ethereum",
            "eip155:01",
            "eip155:0",
            "eip155:-1",
            "EIP155:1",
            "tezos:mainnet",
            "tezos:netxdqprcvkpawu",
            "eip155:1:2",
            "eip155:../1",
        ] {
            assert!(validate_chain_id(id).is_err(), "{id}");
        }
    }
}

#[cfg(test)]
mod canonical_chain_id_tests {
    use super::*;

    #[test]
    fn maps_only_known_legacy_names() {
        assert_eq!(canonical_chain_id("ethereum"), "eip155:1");
        assert_eq!(canonical_chain_id("tezos"), "tezos:NetXdQprcVkpaWU");
        assert_eq!(canonical_chain_id("eip155:84532"), "eip155:84532");
        assert_eq!(canonical_chain_id("unknown"), "unknown");
    }
}
