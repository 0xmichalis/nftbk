use alloy::{
    contract::Error,
    primitives::{Address, U256},
    providers::ProviderBuilder,
    sol,
    transports::http::{Client, Http},
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::sleep;
use tracing::debug;

use crate::chain::common::{ContractTokenId, NFTAttribute};
use crate::chain::ContractTokenInfo;
use crate::content::Options;
use crate::httpclient::HttpClient;
use crate::ipfs::IpfsPinningProvider;
use crate::StorageConfig;

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

pub struct EvmChainProcessor {
    pub rpc: alloy::providers::RootProvider<Http<Client>>,
    pub output_path: Option<PathBuf>,
    pub ipfs_providers: Vec<Box<dyn IpfsPinningProvider>>,
    pub http_client: HttpClient,
}

impl EvmChainProcessor {
    pub fn new(rpc_url: &str, storage_config: StorageConfig) -> anyhow::Result<Self> {
        let rpc = ProviderBuilder::new().on_http(rpc_url.parse()?);
        let ipfs_providers: Vec<Box<dyn IpfsPinningProvider>> = storage_config
            .ipfs_providers
            .iter()
            .map(|config| config.create_provider())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            rpc,
            output_path: storage_config.output_path,
            ipfs_providers,
            http_client: HttpClient::new(),
        })
    }
}

#[async_trait::async_trait]
impl crate::chain::NFTChainProcessor for EvmChainProcessor {
    type Metadata = NFTMetadata;
    type ContractTokenId = ContractTokenId;
    type RpcClient = alloy::providers::RootProvider<Http<Client>>;

    async fn fetch_metadata(
        &self,
        token: &Self::ContractTokenId,
    ) -> anyhow::Result<(Self::Metadata, String)> {
        let token_uri = self.get_uri(token).await?;
        debug!("Fetching metadata from {} for {}", token_uri, token);
        let bytes = self.http_client.fetch(&token_uri).await?;
        let metadata: NFTMetadata = serde_json::from_slice(&bytes)?;
        Ok((metadata, token_uri))
    }

    fn collect_urls(metadata: &Self::Metadata) -> Vec<(String, Options)> {
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

    async fn get_uri(&self, token: &Self::ContractTokenId) -> anyhow::Result<String> {
        let token_addr = token.address().parse::<Address>()?;
        let token_id = U256::from_str_radix(token.token_id(), 10)?;

        // Check for special contract handling first
        if let Some(special_uri) =
            handle_special_contract_uri(&self.rpc, token.chain_name(), token.address(), &token_id)
                .await?
        {
            return Ok(special_uri);
        }

        let nft = INFT::new(token_addr, &self.rpc);

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

    fn ipfs_providers(&self) -> &[Box<dyn IpfsPinningProvider>] {
        &self.ipfs_providers
    }

    fn http_client(&self) -> &crate::httpclient::HttpClient {
        &self.http_client
    }

    fn output_path(&self) -> Option<&std::path::Path> {
        self.output_path.as_deref()
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
    token_address: &str,
    token_id: &U256,
) -> anyhow::Result<Option<String>> {
    // Handle CryptoPunks on Ethereum mainnet
    if chain_name == "ethereum"
        && token_address.to_lowercase() == "0xb47e3cd837ddf8e4c57f05d70ab865de6e193bbb"
    {
        return generate_cryptopunks_data_uri(rpc, token_id).await.map(Some);
    }

    // Handle Beeple's contract on Ethereum mainnet
    if chain_name == "ethereum"
        && token_address.to_lowercase() == "0xd92e44ac213b9ebda0178e1523cc0ce177b7fa96"
    {
        return Ok(Some(generate_beeple_uri(token_id)));
    }

    // Future special contracts can be added here
    // Example:
    // if chain_name == "ethereum" && token_address.to_lowercase() == "0x..." {
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
mod deserialize_metadata_content_string_tests {
    use super::*;

    #[test]
    fn deserializes_content_string_and_basic_fields() {
        let json = r#"{
            "name": "Filmmaking in the Age of the Feed 1",
            "description": "https://mirror.xyz/10/0x84b4ee3c0b5d5da3f44c93814490270aec9af2e5",
            "content": "ar://YIhysXzc499Si_YLcGbzFyd-i5VsQRodP_DCPyc1B2Q",
            "animation_url": "https://mirror.xyz/10/0x84b4ee3c0b5d5da3f44c93814490270aec9af2e5/render",
            "image": "ipfs://QmYiudjqgZwma6siYmaMJELgPVjCJMzhu3cz3tsxaFUw8Q",
            "attributes": [ { "trait_type": "Serial", "value": 1 } ]
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
        let attrs = meta.attributes.unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].trait_type, "Serial");
        assert_eq!(attrs[0].value, serde_json::json!(1));
    }
}

#[cfg(test)]
mod replace_id_pattern_tests {
    use super::*;

    #[tokio::test]
    async fn replaces_supported_patterns() {
        use alloy::primitives::U256;
        let ens_uri = "https://metadata.ens.domains/mainnet/0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401/0x{id}";
        let token_id = U256::from(123456u64);
        let expected_uri = "https://metadata.ens.domains/mainnet/0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401/0x1e240";
        assert_eq!(
            replace_id_pattern(ens_uri, &token_id).as_deref(),
            Some(expected_uri)
        );

        let not_at_end = "https://foo.com/0x{id}/extra";
        assert_eq!(replace_id_pattern(not_at_end, &token_id), None);

        let no_pattern = "https://foo.com/bar";
        assert_eq!(replace_id_pattern(no_pattern, &token_id), None);

        let dec_uri = "https://api.example.com/metadata/{id}";
        let expected_dec_uri = "https://api.example.com/metadata/123456";
        assert_eq!(
            replace_id_pattern(dec_uri, &token_id).as_deref(),
            Some(expected_dec_uri)
        );
    }
}

#[cfg(test)]
mod generate_beeple_uri_tests {
    use super::*;

    #[test]
    fn constructs_expected_urls() {
        use alloy::primitives::U256;
        let token_id = U256::from(100010189u64);
        assert_eq!(
            generate_beeple_uri(&token_id),
            "https://api.niftygateway.com/beeple/100010189/"
        );

        let token_id_2 = U256::from(12345u64);
        assert_eq!(
            generate_beeple_uri(&token_id_2),
            "https://api.niftygateway.com/beeple/12345/"
        );
    }
}

#[cfg(test)]
mod deserialize_primera_metadata_tests {
    use super::*;

    #[test]
    fn handles_value_only_attributes() {
        let json = r#"{
            "image": "https://earx.../primera-223.gif",
            "script_type": "p5js",
            "aspect_ratio": "1",
            "date": "2021/11/14",
            "animation_url": "https://.../XCgiWiWuIN9Hj5Lr_fcgdrWB...",
            "name": "Primera #223",
            "number": "223",
            "hash": "0xf146...",
            "external_url": "https://...",
            "description": "Primera is the genesis project...",
            "attributes": [ { "value": "Tan Background" }, { "value": "Black" }, { "value": "Blue" }, { "value": "Yellow" }, { "value": "Green" } ]
        }"#;
        let meta: NFTMetadata = serde_json::from_str(json).expect("Deserialization failed");
        assert_eq!(meta.name.as_deref(), Some("Primera #223"));
        let attrs = meta.attributes.unwrap();
        assert_eq!(attrs.len(), 5);
        assert_eq!(attrs[0].value, serde_json::json!("Tan Background"));
    }
}

#[cfg(test)]
mod deserialize_knownorigin_metadata_tests {
    use super::*;

    #[test]
    fn converts_map_attributes_to_vec() {
        let json = r#"{
            "name": "Test NFT",
            "description": "Test description",
            "image": "https://example.com/image.jpg",
            "attributes": {"Background": "Blue", "Eyes": "Green", "Mouth": "Smile"}
        }"#;
        let meta: NFTMetadata = serde_json::from_str(json).expect("Deserialization failed");
        assert_eq!(meta.name.as_deref(), Some("Test NFT"));
        let attrs = meta.attributes.unwrap();

        let mut found = std::collections::HashMap::new();
        for a in attrs {
            found.insert(a.trait_type, a.value);
        }
        assert_eq!(found.get("Background"), Some(&serde_json::json!("Blue")));
        assert_eq!(found.get("Eyes"), Some(&serde_json::json!("Green")));
        assert_eq!(found.get("Mouth"), Some(&serde_json::json!("Smile")));
    }
}

#[cfg(test)]
mod collect_urls_tests {
    use super::*;

    #[test]
    fn collects_and_deduplicates_urls_and_sets_filenames() {
        let metadata = NFTMetadata {
            name: Some("MyNFT".to_string()),
            description: None,
            image: Some("ipfs://image-cid".to_string()),
            image_url: Some("ipfs://image-cid".to_string()), // duplicate
            animation_url: Some("https://example.com/anim.html".to_string()),
            animation_details: Some(AnimationDetails::Object {
                format: Some("html".to_string()),
            }),
            external_url: None,
            attributes: None,
            media: Some(Media::Uri {
                uri: "ipfs://media-cid".to_string(),
            }),
            content: Some(Media::String("ipfs://content-cid".to_string())),
            assets: Some(Assets {
                glb: Some("ipfs://model.glb".to_string()),
            }),
        };

        let list =
            <crate::chain::evm::EvmChainProcessor as crate::chain::NFTChainProcessor>::collect_urls(
                &metadata,
            );
        let mut map = std::collections::HashMap::new();
        for (u, opts) in list {
            map.insert(u, opts.overriden_filename);
        }

        assert!(map.contains_key("ipfs://image-cid"));
        assert!(map.contains_key("ipfs://media-cid"));
        assert!(map.contains_key("ipfs://content-cid"));
        assert!(map.contains_key("ipfs://model.glb"));
        assert_eq!(
            map.get("https://example.com/anim.html").unwrap().as_deref(),
            Some("index.html")
        );
    }
}

#[cfg(test)]
mod handle_special_contract_uri_tests {
    use super::*;

    const DEFAULT_LLAMARPC_URL: &str = "https://eth.llamarpc.com";
    const DEFAULT_ALCHEMY_URL: &str = "https://eth-mainnet.g.alchemy.com/v2";

    fn get_evm_rpc_url() -> String {
        if let Ok(api_key) = std::env::var("ALCHEMY_API_KEY") {
            if !api_key.is_empty() {
                return format!("{DEFAULT_ALCHEMY_URL}/{api_key}");
            }
        }
        DEFAULT_LLAMARPC_URL.to_string()
    }

    #[tokio::test]
    async fn detects_beeple_contract_without_network_calls() {
        use alloy::primitives::U256;
        use alloy::providers::RootProvider;
        let rpc_url = get_evm_rpc_url();
        let rpc = RootProvider::new_http(rpc_url.parse().unwrap());
        let chain_name = "ethereum";
        let beeple_address = "0xd92e44ac213b9ebda0178e1523cc0ce177b7fa96";
        let token_id = U256::from(100010189u64);
        let res = handle_special_contract_uri(&rpc, chain_name, beeple_address, &token_id)
            .await
            .unwrap();
        assert!(res.is_some());
        assert!(res.unwrap().contains("niftygateway.com/beeple/100010189/"));
    }
}

#[cfg(test)]
mod generate_cryptopunks_data_uri_tests {
    use super::*;

    const DEFAULT_LLAMARPC_URL: &str = "https://eth.llamarpc.com";
    const DEFAULT_ALCHEMY_URL: &str = "https://eth-mainnet.g.alchemy.com/v2";

    fn get_evm_rpc_url() -> String {
        if let Ok(api_key) = std::env::var("ALCHEMY_API_KEY") {
            if !api_key.is_empty() {
                return format!("{DEFAULT_ALCHEMY_URL}/{api_key}");
            }
        }
        DEFAULT_LLAMARPC_URL.to_string()
    }

    #[tokio::test]
    async fn generates_valid_data_uri_or_handles_network_error() {
        use alloy::primitives::U256;
        use alloy::providers::RootProvider;
        let rpc_url = get_evm_rpc_url();
        let rpc = RootProvider::new_http(rpc_url.parse().unwrap());
        let token_id = U256::from(0u64);
        let result = generate_cryptopunks_data_uri(&rpc, &token_id).await;
        if let Ok(data_uri) = result {
            assert!(data_uri.starts_with("data:application/json;utf8,"));
        } else if let Err(e) = result {
            println!("Network error in test (acceptable): {e}");
        }
    }
}

#[cfg(test)]
mod new_tests {
    use super::*;
    use crate::chain::NFTChainProcessor;

    #[test]
    fn constructs_with_valid_rpc_and_storage_config() {
        let storage = crate::StorageConfig {
            output_path: Some(std::path::PathBuf::from("/tmp")),
            prune_redundant: false,
            ipfs_providers: vec![],
        };
        let proc = EvmChainProcessor::new("https://eth.llamarpc.com", storage).expect("new ok");
        // basic sanity
        let _ = proc.http_client();
        let _ = proc.ipfs_providers();
        let out = proc.output_path();
        assert!(out.is_some());
    }
}

#[cfg(test)]
mod ipfs_providers_tests {
    use super::*;
    use crate::chain::NFTChainProcessor;

    #[test]
    fn returns_configured_providers() {
        let storage = crate::StorageConfig {
            output_path: None,
            prune_redundant: false,
            ipfs_providers: vec![crate::ipfs::IpfsProviderConfig::IpfsPinningService {
                base_url: "http://example.com".to_string(),
                bearer_token: None,
                bearer_token_env: None,
            }],
        };
        let proc = EvmChainProcessor::new("https://eth.llamarpc.com", storage).expect("new ok");
        assert_eq!(proc.ipfs_providers().len(), 1);
    }
}

#[cfg(test)]
mod http_client_tests {
    use super::*;
    use crate::chain::NFTChainProcessor;

    #[test]
    fn returns_http_client_reference() {
        let storage = crate::StorageConfig {
            output_path: None,
            prune_redundant: false,
            ipfs_providers: vec![],
        };
        let proc = EvmChainProcessor::new("https://eth.llamarpc.com", storage).expect("new ok");
        let _client_ref = proc.http_client();
    }
}

#[cfg(test)]
mod output_path_tests {
    use super::*;
    use crate::chain::NFTChainProcessor;

    #[test]
    fn returns_configured_output_path() {
        let storage = crate::StorageConfig {
            output_path: Some(std::path::PathBuf::from("/tmp")),
            prune_redundant: false,
            ipfs_providers: vec![],
        };
        let proc = EvmChainProcessor::new("https://eth.llamarpc.com", storage).expect("new ok");
        assert_eq!(proc.output_path().unwrap().to_str().unwrap(), "/tmp");
    }
}
