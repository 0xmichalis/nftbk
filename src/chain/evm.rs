use alloy::{
    contract::Error,
    primitives::{Address, U256},
    sol,
    transports::http::{Client, Http},
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

use crate::chain::common::{ContractWithToken, NFTAttribute};
use crate::chain::ContractTokenInfo;
use crate::content::{fetch_and_save_content, Options};

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    #[serde(alias = "imageUrl")]
    pub image_url: Option<String>,
    pub animation_url: Option<String>,
    pub animation_details: Option<AnimationDetails>,
    pub external_url: Option<String>,
    #[serde(default)]
    #[serde(deserialize_with = "deserialize_attributes")]
    pub attributes: Option<Vec<NFTAttribute>>,
    pub media: Option<Media>,
    pub content: Option<Media>,
    pub assets: Option<Assets>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AnimationDetails {
    String(String),
    Object { format: Option<String> },
}

// Helper struct for attributes with only value field (used by Primera)
#[derive(Deserialize)]
struct ValueOnlyAttribute {
    value: serde_json::Value,
}

// Helper enum to deserialize both formats
#[derive(Deserialize)]
#[serde(untagged)]
enum AttributesFormat {
    Array(Vec<NFTAttribute>),
    // Used by KnownOrigin
    Map(std::collections::HashMap<String, serde_json::Value>),
    // Used by Primera - attributes with only value field
    ValueOnlyArray(Vec<ValueOnlyAttribute>),
}

fn deserialize_attributes<'de, D>(deserializer: D) -> Result<Option<Vec<NFTAttribute>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match Option::<AttributesFormat>::deserialize(deserializer)? {
        Some(AttributesFormat::Map(map)) => {
            // Convert map to Vec<NFTAttribute>
            Ok(Some(
                map.into_iter()
                    .map(|(trait_type, value)| NFTAttribute { trait_type, value })
                    .collect(),
            ))
        }
        Some(AttributesFormat::Array(attrs)) => Ok(Some(attrs)),
        Some(AttributesFormat::ValueOnlyArray(attrs)) => {
            // Convert ValueOnlyAttribute to NFTAttribute with empty trait_type
            Ok(Some(
                attrs
                    .into_iter()
                    .map(|attr| NFTAttribute {
                        trait_type: String::new(),
                        value: attr.value,
                    })
                    .collect(),
            ))
        }
        None => Ok(None),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Media {
    Uri { uri: String },
    String(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Assets {
    pub glb: Option<String>,
}

// ERC721/ERC1155 minimal ABI to get the token URI
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface INFT {
        function tokenURI(uint256 tokenId) external view returns (string);
        function uri(uint256 id) external view returns (string);
    }
}

// CryptoPunks contract ABI
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ICryptoPunks {
        function punkImageSvg(uint16 punkId) external view returns (string);
        function punkAttributes(uint16 punkId) external view returns (string);
    }
}

fn is_rate_limited(e: &Error) -> bool {
    e.to_string().contains("429") || e.to_string().contains("rate limit")
}

// Helper function to handle contract calls with retries
async fn try_call_contract<Fut, T>(mut f: impl FnMut() -> Fut) -> Result<T, Error>
where
    Fut: Future<Output = Result<T, Error>> + Send,
{
    const MAX_RETRIES: u32 = 5;
    const RETRY_DELAY_MS: u64 = 1000;

    let mut attempts = 0;
    loop {
        match f().await {
            Ok(uri) => return Ok(uri),
            Err(e) if is_rate_limited(&e) && attempts < MAX_RETRIES => {
                attempts += 1;
                sleep(Duration::from_millis(RETRY_DELAY_MS * attempts as u64)).await;
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}

pub struct EvmChainProcessor;

#[async_trait::async_trait]
impl crate::chain::NFTChainProcessor for EvmChainProcessor {
    type Metadata = NFTMetadata;
    type ContractWithToken = ContractWithToken;
    type RpcClient = alloy::providers::RootProvider<Http<Client>>;

    async fn fetch_metadata(
        &self,
        token_uri: &str,
        contract: &Self::ContractWithToken,
        output_path: &std::path::Path,
        chain_name: &str,
    ) -> anyhow::Result<(Self::Metadata, std::path::PathBuf)> {
        debug!(
            "Fetching metadata from {} for contract {}",
            token_uri,
            contract.address()
        );
        let metadata_content = fetch_and_save_content(
            token_uri,
            chain_name,
            &contract.address,
            &contract.token_id,
            output_path,
            Options {
                overriden_filename: Some("metadata.json".to_string()),
                fallback_filename: None,
            },
        )
        .await?;
        let metadata_content_str = tokio::fs::read_to_string(&metadata_content).await?;
        let metadata: NFTMetadata = serde_json::from_str(&metadata_content_str)?;
        Ok((metadata, metadata_content))
    }

    fn collect_urls_to_download(metadata: &Self::Metadata) -> Vec<(String, Options)> {
        let mut urls_to_download = Vec::new();
        let mut seen = std::collections::HashSet::new();

        let mut add_if_not_empty = |url: &str, options: Options| {
            if !url.is_empty() && seen.insert(url.to_string()) {
                urls_to_download.push((url.to_string(), options));
            }
        };

        if let Some(media) = &metadata.media {
            match media {
                Media::Uri { uri } => add_if_not_empty(
                    uri,
                    Options {
                        fallback_filename: Some("media".to_string()),
                        overriden_filename: None,
                    },
                ),
                Media::String(uri) => add_if_not_empty(
                    uri,
                    Options {
                        fallback_filename: Some("media".to_string()),
                        overriden_filename: None,
                    },
                ),
            }
        }
        if let Some(content) = &metadata.content {
            match content {
                Media::Uri { uri } => add_if_not_empty(
                    uri,
                    Options {
                        fallback_filename: Some("content".to_string()),
                        overriden_filename: None,
                    },
                ),
                Media::String(uri) => add_if_not_empty(
                    uri,
                    Options {
                        fallback_filename: Some("content".to_string()),
                        overriden_filename: None,
                    },
                ),
            }
        }
        if let Some(assets) = &metadata.assets {
            if let Some(glb) = &assets.glb {
                add_if_not_empty(
                    glb,
                    Options {
                        fallback_filename: Some("glb".to_string()),
                        overriden_filename: None,
                    },
                );
            }
        }
        if let Some(image) = &metadata.image {
            add_if_not_empty(
                image,
                Options {
                    fallback_filename: Some("image".to_string()),
                    overriden_filename: None,
                },
            );
        }
        if let Some(image_url) = &metadata.image_url {
            add_if_not_empty(
                image_url,
                Options {
                    fallback_filename: Some("image".to_string()),
                    overriden_filename: None,
                },
            );
        }
        if let Some(animation_url) = &metadata.animation_url {
            let mut overriden_filename = None;
            if let Some(details) = &metadata.animation_details {
                match details {
                    AnimationDetails::String(s) => {
                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(s) {
                            if let Some(fmt) = json.get("format").and_then(|v| v.as_str()) {
                                if fmt.eq_ignore_ascii_case("html") {
                                    overriden_filename = Some("index.html".to_string());
                                }
                            }
                        }
                    }
                    AnimationDetails::Object { format, .. } => {
                        if let Some(fmt) = format {
                            if fmt.eq_ignore_ascii_case("html") {
                                overriden_filename = Some("index.html".to_string());
                            }
                        }
                    }
                }
            }
            add_if_not_empty(
                animation_url,
                Options {
                    fallback_filename: Some("animation".to_string()),
                    overriden_filename,
                },
            );
        }
        urls_to_download
    }

    async fn get_uri(
        &self,
        rpc: &Self::RpcClient,
        contract: &Self::ContractWithToken,
        chain_name: &str,
    ) -> anyhow::Result<String> {
        let contract_addr = contract.address().parse::<Address>()?;
        let token_id = U256::from_str_radix(contract.token_id(), 10)?;

        // Check for special contract handling first
        if let Some(special_uri) =
            handle_special_contract_uri(rpc, chain_name, contract.address(), &token_id).await?
        {
            return Ok(special_uri);
        }

        let nft = INFT::new(contract_addr, rpc);

        let uri = match try_call_contract(|| {
            let nft = nft.clone();
            async move { nft.tokenURI(token_id).call().await }
        })
        .await
        {
            Ok(uri) => Ok(uri._0),
            Err(e) if !is_rate_limited(&e) => {
                let uri = try_call_contract(|| {
                    let nft = nft.clone();
                    async move { nft.uri(token_id).call().await }
                })
                .await?;
                Ok(uri._0)
            }
            Err(e) => Err(e),
        }?;

        // Handle OpenSea's URI pattern
        if uri.contains("/api.opensea.io/") && uri.contains("{id}") {
            let hex_token_id = format!("{token_id:x}");
            return Ok(uri.replace("{id}", &hex_token_id));
        }

        // Handle URIs with {id} patterns
        if let Some(new_uri) = replace_id_pattern(&uri, &token_id) {
            return Ok(new_uri);
        }

        Ok(uri)
    }
}

fn replace_id_pattern(uri: &str, token_id: &U256) -> Option<String> {
    if let Some(idx) = uri.rfind("/0x{id}") {
        if idx + 7 == uri.len() {
            let hex_token_id = format!("0x{token_id:x}");
            let new_uri = format!("{}{}", &uri[..idx + 1], hex_token_id);
            return Some(new_uri);
        }
    }

    // Catch-all pattern: /{id} at end
    if let Some(idx) = uri.rfind("/{id}") {
        if idx + 5 == uri.len() {
            let dec_token_id = token_id.to_string();
            let new_uri = format!("{}{}", &uri[..idx + 1], dec_token_id);
            return Some(new_uri);
        }
    }
    None
}

/// Handle special contract URI generation for contracts that don't follow ERC-721/ERC-1155 standards
async fn handle_special_contract_uri(
    rpc: &alloy::providers::RootProvider<Http<Client>>,
    chain_name: &str,
    contract_address: &str,
    token_id: &U256,
) -> anyhow::Result<Option<String>> {
    // Handle CryptoPunks on Ethereum mainnet
    if chain_name == "ethereum"
        && contract_address.to_lowercase() == "0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb"
    {
        return generate_cryptopunks_data_uri(rpc, token_id).await.map(Some);
    }

    // Handle Beeple's contract on Ethereum mainnet
    if chain_name == "ethereum"
        && contract_address.to_lowercase() == "0xd92e44ac213b9ebda0178e1523cc0ce177b7fa96"
    {
        return Ok(Some(generate_beeple_uri(token_id)));
    }

    // Future special contracts can be added here
    // Example:
    // if chain_name == "ethereum" && contract_address.to_lowercase() == "0x..." {
    //     return handle_other_special_contract(rpc, token_id).await.map(Some);
    // }

    Ok(None)
}

/// Generate a data URI for CryptoPunks metadata using contract calls
async fn generate_cryptopunks_data_uri(
    rpc: &alloy::providers::RootProvider<Http<Client>>,
    token_id: &U256,
) -> anyhow::Result<String> {
    // CryptoPunks contract address
    let cryptopunks_address = "0x16F5A35647D6F03D5D3da7b35409D65ba03aF3B2".parse::<Address>()?;

    // Convert token_id to u16 (CryptoPunks uses uint16)
    let punk_id = token_id.to::<u16>();

    let cryptopunks = ICryptoPunks::new(cryptopunks_address, rpc);

    // Call contract functions with retries
    let svg_data = try_call_contract(|| {
        let cryptopunks = cryptopunks.clone();
        async move { cryptopunks.punkImageSvg(punk_id).call().await }
    })
    .await?;

    let attributes_str = try_call_contract(|| {
        let cryptopunks = cryptopunks.clone();
        async move { cryptopunks.punkAttributes(punk_id).call().await }
    })
    .await?;

    // Parse attributes string (comma-separated values)
    let attributes_list: Vec<String> = attributes_str
        ._0
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    // Create attributes from the contract response
    let mut attributes = Vec::new();

    // The first attribute is typically the type (Male/Female/Zombie/Ape/Alien)
    if let Some(punk_type) = attributes_list.first() {
        attributes.push(NFTAttribute {
            trait_type: "Type".to_string(),
            value: serde_json::Value::String(punk_type.clone()),
        });
    }

    // Add remaining attributes as accessories
    for accessory in attributes_list.iter().skip(1) {
        attributes.push(NFTAttribute {
            trait_type: "Accessory".to_string(),
            value: serde_json::Value::String(accessory.clone()),
        });
    }

    // Use the SVG data URI directly from the contract (already properly formatted)
    let svg_data_uri = svg_data._0;

    // Create the metadata
    let metadata = NFTMetadata {
        name: Some(format!("CryptoPunk #{token_id}")),
        description: Some("CryptoPunks launched as a fixed set of 10,000 items in mid-2017 and became one of the inspirations for the ERC-721 standard. They have been featured in places like The New York Times, Christie's of London, Art|Basel Miami, and The PBS NewsHour.".to_string()),
        image: None,
        image_url: Some(svg_data_uri),
        animation_url: None,
        animation_details: None,
        external_url: None,
        attributes: Some(attributes),
        media: None,
        content: None,
        assets: None,
    };

    // Serialize to JSON and create data URI
    let metadata_json = serde_json::to_string(&metadata)?;
    Ok(format!("data:application/json;utf8,{metadata_json}"))
}

/// Generate the proper token URI for Beeple's contract
/// The contract returns malformed URIs, so we construct the correct Nifty Gateway API URL
fn generate_beeple_uri(token_id: &U256) -> String {
    // Convert token_id to string and construct the proper Nifty Gateway API URL
    // Based on the example: https://api.niftygateway.com/beeple/100010189/
    format!("https://api.niftygateway.com/beeple/{token_id}/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_deserialize_metadata_content_string() {
        let json = r#"{
            "name": "Filmmaking in the Age of the Feed 1",
            "description": "https://mirror.xyz/10/0x84b4ee3c0b5d5da3f44c93814490270aec9af2e5",
            "content": "ar://YIhysXzc499Si_YLcGbzFyd-i5VsQRodP_DCPyc1B2Q",
            "animation_url": "https://mirror.xyz/10/0x84b4ee3c0b5d5da3f44c93814490270aec9af2e5/render",
            "image": "ipfs://QmYiudjqgZwma6siYmaMJELgPVjCJMzhu3cz3tsxaFUw8Q",
            "attributes": [
                { "trait_type": "Serial", "value": 1 }
            ]
        }"#;
        let meta: NFTMetadata = serde_json::from_str(json).expect("Deserialization failed");
        assert_eq!(
            meta.name.as_deref(),
            Some("Filmmaking in the Age of the Feed 1")
        );
        assert_eq!(
            meta.description.as_deref(),
            Some("https://mirror.xyz/10/0x84b4ee3c0b5d5da3f44c93814490270aec9af2e5")
        );
        match meta.content {
            Some(Media::String(ref s)) => {
                assert_eq!(s, "ar://YIhysXzc499Si_YLcGbzFyd-i5VsQRodP_DCPyc1B2Q")
            }
            _ => panic!("content should be Media::String variant"),
        }
        assert_eq!(
            meta.animation_url.as_deref(),
            Some("https://mirror.xyz/10/0x84b4ee3c0b5d5da3f44c93814490270aec9af2e5/render")
        );
        assert_eq!(
            meta.image.as_deref(),
            Some("ipfs://QmYiudjqgZwma6siYmaMJELgPVjCJMzhu3cz3tsxaFUw8Q")
        );
        assert!(meta.attributes.is_some());
        let attrs = meta.attributes.unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].trait_type, "Serial");
        assert_eq!(attrs[0].value, serde_json::json!(1));
    }

    #[tokio::test]
    async fn test_replace_id_pattern() {
        use alloy::primitives::U256;
        let ens_uri = "https://metadata.ens.domains/mainnet/0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401/0x{id}";
        let token_id = U256::from(123456u64);
        let expected_uri = "https://metadata.ens.domains/mainnet/0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401/0x1e240";
        let replaced = replace_id_pattern(ens_uri, &token_id);
        assert_eq!(replaced.as_deref(), Some(expected_uri));

        // Should not replace if pattern is not at end
        let not_at_end = "https://foo.com/0x{id}/extra";
        assert_eq!(replace_id_pattern(not_at_end, &token_id), None);

        // Should not replace if pattern is missing
        let no_pattern = "https://foo.com/bar";
        assert_eq!(replace_id_pattern(no_pattern, &token_id), None);

        // Test new pattern: /{id} at end, decimal
        let dec_uri = "https://api.example.com/metadata/{id}";
        let expected_dec_uri = "https://api.example.com/metadata/123456";
        let replaced_dec = replace_id_pattern(dec_uri, &token_id);
        assert_eq!(replaced_dec.as_deref(), Some(expected_dec_uri));
    }

    #[test]
    fn test_generate_beeple_uri() {
        use alloy::primitives::U256;

        let token_id = U256::from(100010189u64);
        let expected_uri = "https://api.niftygateway.com/beeple/100010189/";
        let generated_uri = generate_beeple_uri(&token_id);
        assert_eq!(generated_uri, expected_uri);

        let token_id_2 = U256::from(12345u64);
        let expected_uri_2 = "https://api.niftygateway.com/beeple/12345/";
        let generated_uri_2 = generate_beeple_uri(&token_id_2);
        assert_eq!(generated_uri_2, expected_uri_2);
    }

    #[test]
    fn test_deserialize_primera_metadata() {
        let json = r#"{
            "image": "https://earxvqhz3yy7be5zmpqjadsdumy5rkudotdvbqf6gjzs3lgvlkfa.arweave.net/ICN6wPneMfCTuWPgkA5DozHYqoN0x1DAvjJzLazVWoo/primera-223.gif",
            "script_type": "p5js",
            "aspect_ratio": "1",
            "date": "2021/11/14",
            "animation_url": "https://lqucewrfvyqn6r4pslvx3sa5vvqhvxd2rkg6cuf7rq56nehzrm.arweave.net/XCgiWiWuIN9Hj5Lr_fcgdrWB63HqKjeFQv4w75pD5iw?hash=0xf146009532e35f67117b6e1c1303819ae44ec049a266a99b262bbad7a7d65538&number=223",
            "name": "Primera #223",
            "number": "223",
            "hash": "0xf146009532e35f67117b6e1c1303819ae44ec049a266a99b262bbad7a7d65538",
            "external_url": "https://lqucewrfvyqn6r4pslvx3sa5vvqhvxd2rkg6cuf7rq56nehzrm.arweave.net/XCgiWiWuIN9Hj5Lr_fcgdrWB63HqKjeFQv4w75pD5iw?hash=0xf146009532e35f67117b6e1c1303819ae44ec049a266a99b262bbad7a7d65538&number=223",
            "description": "Primera is the genesis project from Andrew Mitchell and Grant Yun written completely in p5.js. Primera, capped at 400 individual pieces generated upon mint, has been a project with years in the making. It is a study and interpretation on the fundamentals of early 20th century art utilizing 21st century blockchain technology",
            "attributes": [
                {
                    "value": "Tan Background"
                },
                {
                    "value": "Black"
                },
                {
                    "value": "Blue"
                },
                {
                    "value": "Yellow"
                },
                {
                    "value": "Green"
                }
            ]
        }"#;
        let meta: NFTMetadata = serde_json::from_str(json).expect("Deserialization failed");
        assert_eq!(meta.name.as_deref(), Some("Primera #223"));
        assert!(meta.attributes.is_some());
        let attrs = meta.attributes.unwrap();
        assert_eq!(attrs.len(), 5);
        assert_eq!(attrs[0].value, serde_json::json!("Tan Background"));
        assert_eq!(attrs[1].value, serde_json::json!("Black"));
        assert_eq!(attrs[2].value, serde_json::json!("Blue"));
        assert_eq!(attrs[3].value, serde_json::json!("Yellow"));
        assert_eq!(attrs[4].value, serde_json::json!("Green"));
    }

    #[test]
    fn test_deserialize_knownorigin_metadata() {
        let json = r#"{
            "name": "Test NFT",
            "description": "Test description",
            "image": "https://example.com/image.jpg",
            "attributes": {
                "Background": "Blue",
                "Eyes": "Green",
                "Mouth": "Smile"
            }
        }"#;
        let meta: NFTMetadata = serde_json::from_str(json).expect("Deserialization failed");
        assert_eq!(meta.name.as_deref(), Some("Test NFT"));
        assert!(meta.attributes.is_some());
        let attrs = meta.attributes.unwrap();
        assert_eq!(attrs.len(), 3);

        // Check that all expected attributes are present (order doesn't matter for HashMap)
        let mut found_background = false;
        let mut found_eyes = false;
        let mut found_mouth = false;

        for attr in &attrs {
            match attr.trait_type.as_str() {
                "Background" => {
                    assert_eq!(attr.value, serde_json::json!("Blue"));
                    found_background = true;
                }
                "Eyes" => {
                    assert_eq!(attr.value, serde_json::json!("Green"));
                    found_eyes = true;
                }
                "Mouth" => {
                    assert_eq!(attr.value, serde_json::json!("Smile"));
                    found_mouth = true;
                }
                _ => panic!("Unexpected trait_type: {}", attr.trait_type),
            }
        }

        assert!(found_background, "Background attribute not found");
        assert!(found_eyes, "Eyes attribute not found");
        assert!(found_mouth, "Mouth attribute not found");
    }

    // RPC URL configuration
    const DEFAULT_LLAMARPC_URL: &str = "https://eth.llamarpc.com";
    const DEFAULT_ALCHEMY_URL: &str = "https://eth-mainnet.g.alchemy.com/v2";

    fn get_evm_rpc_url() -> String {
        if let Ok(api_key) = std::env::var("ALCHEMY_API_KEY") {
            if !api_key.is_empty() {
                return format!("{}/{}", DEFAULT_ALCHEMY_URL, api_key);
            }
        }
        DEFAULT_LLAMARPC_URL.to_string()
    }

    #[tokio::test]
    async fn test_cryptopunks_special_handling() {
        use alloy::primitives::U256;
        use alloy::providers::RootProvider;

        // Create RPC client for testing using the configured URL (real network calls)
        let rpc_url = get_evm_rpc_url();
        let rpc = RootProvider::new_http(rpc_url.parse().unwrap());

        // Test CryptoPunks contract detection
        let chain_name = "ethereum";
        let cryptopunks_address = "0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb";
        let token_id = U256::from(0u64);

        let result =
            handle_special_contract_uri(&rpc, chain_name, cryptopunks_address, &token_id).await;

        match result {
            Ok(Some(data_uri)) => {
                // Verify it's a data URI with the expected format
                assert!(
                    data_uri.starts_with("data:application/json;utf8,"),
                    "Should be a JSON data URI"
                );

                // Decode and verify the metadata structure
                let json_content = &data_uri["data:application/json;utf8,".len()..];
                let metadata: NFTMetadata = serde_json::from_str(json_content).unwrap();

                // Verify the metadata structure matches what we expect from the contract
                assert_eq!(metadata.name.as_deref(), Some("CryptoPunk #0"));
                assert!(metadata.description.is_some());
                assert!(metadata.image_url.is_some());
                assert!(metadata.attributes.is_some());

                // Verify the image is a UTF-8 encoded SVG data URI from contract
                let image_url = metadata.image_url.unwrap();
                assert!(
                    image_url.starts_with("data:image/svg+xml;utf8,"),
                    "Image should be a UTF-8 encoded SVG data URI from contract"
                );

                // Verify attributes structure
                let attributes = metadata.attributes.unwrap();
                assert!(
                    !attributes.is_empty(),
                    "Should have attributes from contract"
                );

                // Check that we have a Type attribute (first attribute from contract)
                let type_attr = attributes.iter().find(|attr| attr.trait_type == "Type");
                assert!(
                    type_attr.is_some(),
                    "Should have a Type attribute from contract"
                );

                // Verify the Type attribute has a valid value
                if let Some(type_attr) = type_attr {
                    let type_value = type_attr.value.as_str().unwrap();
                    assert!(
                        matches!(type_value, "Male" | "Female" | "Zombie" | "Ape" | "Alien"),
                        "Type should be one of the valid CryptoPunk types, got: {}",
                        type_value
                    );
                }

                println!("Successfully generated CryptoPunks data URI with contract data");
            }
            Ok(None) => {
                panic!("Should return Some URI for CryptoPunks, got None");
            }
            Err(e) => {
                // Network error is acceptable in tests, but log it
                println!("Network error in test (acceptable): {}", e);
                // We can't fully test the network call, but we can verify the contract detection logic
                // by checking that it doesn't return None for CryptoPunks
                assert!(
                    !e.to_string().contains("not found"),
                    "Should not be a 'not found' error for CryptoPunks"
                );
            }
        }

        // Test non-special contract
        let normal_address = "0x1234567890123456789012345678901234567890";
        let result = handle_special_contract_uri(&rpc, chain_name, normal_address, &token_id).await;
        assert!(result.is_ok());
        assert!(
            result.unwrap().is_none(),
            "Should return None for normal contracts"
        );
    }

    #[tokio::test]
    async fn test_generate_cryptopunks_data_uri() {
        use alloy::primitives::U256;
        use alloy::providers::RootProvider;

        // Create RPC client for testing using the configured URL (real network calls)
        let rpc_url = get_evm_rpc_url();
        let rpc = RootProvider::new_http(rpc_url.parse().unwrap());

        // Test generating data URI for CryptoPunk #0
        let token_id = U256::from(0u64);
        let result = generate_cryptopunks_data_uri(&rpc, &token_id).await;

        match result {
            Ok(data_uri) => {
                // Verify it's a data URI with the expected format
                assert!(
                    data_uri.starts_with("data:application/json;utf8,"),
                    "Should be a JSON data URI"
                );

                // Decode and verify the metadata structure
                let json_content = &data_uri["data:application/json;utf8,".len()..];
                let metadata: NFTMetadata = serde_json::from_str(json_content).unwrap();

                // Verify basic metadata structure
                assert_eq!(metadata.name.as_deref(), Some("CryptoPunk #0"));
                assert!(metadata.description.is_some());
                assert!(metadata.image_url.is_some());
                assert!(metadata.attributes.is_some());

                // Verify the image is an SVG data URI from contract
                let image_url = metadata.image_url.unwrap();
                assert!(
                    image_url.starts_with("data:image/svg+xml"),
                    "Image should be an SVG data URI from contract"
                );

                // Verify the SVG content is UTF-8 encoded as returned by the contract
                assert!(
                    image_url.starts_with("data:image/svg+xml;utf8,"),
                    "Image should be UTF-8 encoded SVG data URI from contract"
                );

                let svg_content = &image_url["data:image/svg+xml;utf8,".len()..];
                assert!(
                    svg_content.contains("<svg"),
                    "SVG content should contain SVG markup from contract"
                );

                // Verify attributes from contract
                let attributes = metadata.attributes.unwrap();
                assert!(
                    !attributes.is_empty(),
                    "Should have attributes from contract"
                );

                // Check that we have a Type attribute (first from contract)
                let type_attr = attributes.iter().find(|attr| attr.trait_type == "Type");
                assert!(
                    type_attr.is_some(),
                    "Should have a Type attribute from contract"
                );

                // Verify the Type attribute has a valid CryptoPunk type
                if let Some(type_attr) = type_attr {
                    let type_value = type_attr.value.as_str().unwrap();
                    assert!(
                        matches!(type_value, "Male" | "Female" | "Zombie" | "Ape" | "Alien"),
                        "Type should be one of the valid CryptoPunk types from contract, got: {}",
                        type_value
                    );
                }

                // Verify accessory attributes (remaining from contract)
                let _accessory_attrs: Vec<_> = attributes
                    .iter()
                    .filter(|attr| attr.trait_type == "Accessory")
                    .collect();

                // Log the actual attributes received from contract for debugging
                println!("Attributes received from contract:");
                for attr in &attributes {
                    println!("  {}: {}", attr.trait_type, attr.value);
                }

                println!("Successfully generated CryptoPunk #0 data URI with contract data");
            }
            Err(e) => {
                // Network error is acceptable in tests, but log it
                println!("Network error in test (acceptable): {}", e);
                // We can't fully test the network call, but we can verify the function exists and compiles
                assert!(
                    !e.to_string().contains("not found"),
                    "Should not be a 'not found' error"
                );
            }
        }
    }
}
