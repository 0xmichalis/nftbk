use base64::Engine;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use std::path::PathBuf;
use tezos_contract::ContractFetcher;
use tezos_core::types::number::Int;
use tezos_michelson::michelson::data;
use tezos_rpc::client::TezosRpc;
use tezos_rpc::http::default::HttpClient as TezosHttpClient;
use tracing::debug;

use crate::chain::common::ContractTokenId;
use crate::content::Options;
use crate::ipfs::IpfsPinningProvider;
use crate::types::StorageConfig;

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTMetadata {
    pub name: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub tags: Option<Vec<String>>,
    #[serde(rename = "artifactUri")]
    pub artifact_uri: Option<String>,
    #[serde(rename = "displayUri")]
    pub display_uri: Option<String>,
    #[serde(rename = "thumbnailUri")]
    pub thumbnail_uri: Option<String>,
    pub formats: Option<Vec<NFTFormat>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTFormat {
    pub uri: String,
    #[serde(rename = "fileName", default)]
    pub file_name: String,
}

pub struct TezosChainProcessor {
    pub rpc: TezosRpc<TezosHttpClient>,
    pub output_path: Option<PathBuf>,
    pub ipfs_pinning_providers: Vec<Box<dyn IpfsPinningProvider>>,
    pub http_client: crate::httpclient::HttpClient,
}

impl TezosChainProcessor {
    pub fn new(
        rpc_url: &str,
        storage_config: StorageConfig,
        max_content_request_retries: u32,
    ) -> anyhow::Result<Self> {
        let rpc = TezosRpc::<TezosHttpClient>::new(rpc_url.to_string());
        let ipfs_pinning_providers: Vec<Box<dyn IpfsPinningProvider>> = storage_config
            .ipfs_pinning_configs
            .iter()
            .map(|config| config.create_provider())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            rpc,
            output_path: storage_config.output_path,
            ipfs_pinning_providers,
            http_client: crate::httpclient::HttpClient::new()
                .with_max_retries(max_content_request_retries),
        })
    }
}

#[async_trait::async_trait]
impl crate::chain::NFTChainProcessor for TezosChainProcessor {
    type Metadata = NFTMetadata;
    type ContractTokenId = ContractTokenId;
    type RpcClient = tezos_rpc::client::TezosRpc<TezosHttpClient>;

    async fn fetch_metadata(&self, token_uri: &str) -> anyhow::Result<Self::Metadata> {
        debug!("Fetching metadata from {}", token_uri);
        let bytes = self.http_client.fetch(token_uri).await?;
        let metadata: NFTMetadata = serde_json::from_slice(&bytes)?;
        Ok(metadata)
    }

    fn collect_urls(metadata: &Self::Metadata) -> Vec<(String, Options)> {
        let mut urls_to_download = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let nft_name = metadata.name.as_deref().unwrap_or("untitled");

        // Add URIs from formats array with their filenames
        if let Some(formats) = &metadata.formats {
            for format in formats {
                if format.uri.is_empty() {
                    continue;
                }
                let file_name = if format.file_name.is_empty() {
                    nft_name.to_string()
                } else {
                    format.file_name.clone()
                };
                if seen.insert(format.uri.clone()) {
                    urls_to_download.push((
                        format.uri.clone(),
                        Options {
                            fallback_filename: Some(file_name),
                            overriden_filename: None,
                        },
                    ));
                }
            }
        }

        // Helper function to add non-empty URLs
        let mut add_if_not_empty = |url: &Option<String>, name: &str| {
            if let Some(url) = url {
                if !url.is_empty() && seen.insert(url.clone()) {
                    urls_to_download.push((
                        url.clone(),
                        Options {
                            fallback_filename: Some(name.to_string()),
                            overriden_filename: None,
                        },
                    ));
                }
            }
        };

        add_if_not_empty(&metadata.image, "image");
        add_if_not_empty(&metadata.artifact_uri, "artifact");
        add_if_not_empty(&metadata.display_uri, "display");
        add_if_not_empty(&metadata.thumbnail_uri, "thumbnail");

        urls_to_download
    }

    async fn get_uri(&self, token: &Self::ContractTokenId) -> anyhow::Result<String> {
        let nft_contract = self
            .rpc
            .contract_at(token.address.clone().try_into()?, None)
            .await?;
        let token_metadata = nft_contract
            .storage()
            .big_maps()
            .get_by_name("token_metadata")
            .ok_or_else(|| anyhow::anyhow!("Contract does not have token_metadata big map"))?;
        let token_id = Int::from(&token.token_id)?;
        let token_id_michelson = data::int(token_id);
        let value = token_metadata
            .get_value(&self.rpc, token_id_michelson, None)
            .await?;

        // Convert to JSON to access the raw hex string
        let json_value = serde_json::to_value(value)?;

        Ok(get_uri_from_token_metadata(&json_value).unwrap_or_default())
    }

    fn ipfs_pinning_providers(&self) -> &[Box<dyn IpfsPinningProvider>] {
        &self.ipfs_pinning_providers
    }

    fn http_client(&self) -> &crate::httpclient::HttpClient {
        &self.http_client
    }

    fn output_path(&self) -> Option<&std::path::Path> {
        self.output_path.as_deref()
    }
}

fn get_uri_from_token_metadata(json_value: &serde_json::Value) -> Option<String> {
    // Navigate to the seq_arr
    let seq_arr = json_value
        .as_object()
        .and_then(|obj| obj.get("args"))
        .and_then(|args| args.as_array())
        .and_then(|arr| arr.get(1))
        .and_then(|seq| seq.as_array())?;

    match seq_arr.len().cmp(&1) {
        std::cmp::Ordering::Equal => {
            // Standard case: single item, extract bytes
            seq_arr
                .first()
                .and_then(|elt| elt.as_object())
                .and_then(|elt_obj| elt_obj.get("args"))
                .and_then(|elt_args| elt_args.as_array())
                .and_then(|elt_arr| elt_arr.get(1))
                .and_then(|bytes_obj| bytes_obj.as_object())
                .and_then(|bytes_map| bytes_map.get("bytes"))
                .and_then(|bytes_val| bytes_val.as_str())
                .and_then(|hex_str| {
                    let bytes = hex::decode(hex_str).ok()?;
                    String::from_utf8(bytes).ok()
                })
        }
        std::cmp::Ordering::Greater => {
            // Multiple items: treat as key-value pairs
            let mut map = serde_json::Map::new();
            for elt in seq_arr {
                if let Some(obj) = elt.as_object() {
                    let args = obj.get("args").and_then(|a| a.as_array());
                    if let Some(args) = args {
                        if args.len() == 2 {
                            let key = args[0].as_object().and_then(|b| {
                                if let Some(s) = b.get("string").and_then(|v| v.as_str()) {
                                    Some(s.to_string())
                                } else if let Some(bytes) = b.get("bytes").and_then(|v| v.as_str())
                                {
                                    hex::decode(bytes)
                                        .ok()
                                        .and_then(|bytes| String::from_utf8(bytes).ok())
                                } else {
                                    None
                                }
                            });
                            let value = args[1]
                                .as_object()
                                .and_then(|b| b.get("bytes"))
                                .and_then(|v| v.as_str())
                                .and_then(|hex_str| hex::decode(hex_str).ok())
                                .and_then(|bytes| String::from_utf8(bytes).ok());
                            if let (Some(key), Some(value)) = (key, value) {
                                // Try to parse as JSON, otherwise store as string
                                if let Ok(json_val) =
                                    serde_json::from_str::<serde_json::Value>(&value)
                                {
                                    map.insert(key, json_val);
                                } else {
                                    map.insert(key, serde_json::Value::String(value));
                                }
                            }
                        }
                    }
                }
            }
            let json = serde_json::to_string(&map).ok()?;
            let base64 = base64::engine::general_purpose::STANDARD.encode(json);
            Some(format!("data:application/json;base64,{base64}"))
        }
        std::cmp::Ordering::Less => None,
    }
}

#[cfg(test)]
mod get_uri_from_token_metadata_tests {
    use super::get_uri_from_token_metadata;
    use base64::Engine;

    #[test]
    fn extracts_single_item_bytes_uri() {
        // Michelson-like JSON structure with a single seq element containing bytes
        // bytes hex decodes to "ipfs://QmFoo"
        let json = serde_json::json!({
            "args": [
                { "prim": "pair" },
                [
                    {
                        "args": [ {"int": "0"}, {"bytes": "697066733a2f2f516d466f6f"} ]
                    }
                ]
            ]
        });

        let uri = get_uri_from_token_metadata(&json);
        assert_eq!(uri.as_deref(), Some("ipfs://QmFoo"));
    }

    #[test]
    fn builds_base64_data_uri_from_multiple_items() {
        // Two kv pairs: name => "Hello", attributes => JSON array
        // value bytes are hex-encoded strings
        let name_hex = hex::encode("Hello");
        let attrs_json = serde_json::json!([
            {"trait_type": "A", "value": "B"}
        ]);
        let attrs_hex = hex::encode(attrs_json.to_string());

        let json = serde_json::json!({
            "args": [
                { "prim": "pair" },
                [
                    { "args": [ {"string": "name"}, {"bytes": name_hex} ] },
                    { "args": [ {"string": "attributes"}, {"bytes": attrs_hex} ] }
                ]
            ]
        });

        let data_uri = get_uri_from_token_metadata(&json).expect("expected data uri");
        assert!(data_uri.starts_with("data:application/json;base64,"));
        let b64 = &data_uri["data:application/json;base64,".len()..];
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64");
        let decoded_json: serde_json::Value = serde_json::from_slice(&decoded).expect("json");

        assert_eq!(
            decoded_json.get("name").and_then(|v| v.as_str()),
            Some("Hello")
        );
        let attrs = decoded_json
            .get("attributes")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0]["trait_type"], "A");
        assert_eq!(attrs[0]["value"], "B");
    }
}

#[cfg(test)]
mod collect_urls_tests {
    use super::{NFTFormat, NFTMetadata, TezosChainProcessor};

    #[test]
    fn collects_urls_with_filenames_and_deduplicates() {
        let metadata = NFTMetadata {
            name: Some("MyNFT".to_string()),
            description: None,
            image: Some("ipfs://image-cid".to_string()),
            tags: None,
            artifact_uri: Some("ipfs://artifact-cid".to_string()),
            display_uri: Some("ipfs://display-cid".to_string()),
            thumbnail_uri: Some("ipfs://thumb-cid".to_string()),
            formats: Some(vec![
                NFTFormat {
                    uri: "ipfs://artifact-cid".to_string(),
                    file_name: "".to_string(),
                },
                NFTFormat {
                    uri: "ipfs://extra-cid".to_string(),
                    file_name: "file.mp4".to_string(),
                },
            ]),
        };

        let urls =
            <TezosChainProcessor as crate::chain::NFTChainProcessor>::collect_urls(&metadata);

        // Expect unique entries and proper filenames assigned
        // We don't assert order; collect into map for checks
        let mut map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for (u, opts) in urls {
            map.insert(u, opts.fallback_filename.unwrap());
        }

        assert_eq!(
            map.get("ipfs://image-cid").map(|s| s.as_str()),
            Some("image")
        );
        assert_eq!(
            map.get("ipfs://artifact-cid").map(|s| s.as_str()),
            Some("MyNFT")
        );
        assert_eq!(
            map.get("ipfs://display-cid").map(|s| s.as_str()),
            Some("display")
        );
        assert_eq!(
            map.get("ipfs://thumb-cid").map(|s| s.as_str()),
            Some("thumbnail")
        );
        assert_eq!(
            map.get("ipfs://extra-cid").map(|s| s.as_str()),
            Some("file.mp4")
        );
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
            ipfs_pinning_configs: vec![],
        };
        let proc = TezosChainProcessor::new(
            "https://mainnet.tezos.marigold.dev",
            storage,
            crate::types::DEFAULT_MAX_CONTENT_REQUEST_RETRIES,
        )
        .expect("new ok");
        let _ = proc.http_client();
        let _ = proc.ipfs_pinning_providers();
        assert!(proc.output_path().is_some());
    }
}

#[cfg(test)]
mod ipfs_pinning_providers_tests {
    use super::*;
    use crate::chain::NFTChainProcessor;

    #[test]
    fn returns_configured_providers() {
        let storage = crate::StorageConfig {
            output_path: None,
            prune_redundant: false,
            ipfs_pinning_configs: vec![crate::ipfs::IpfsPinningConfig::IpfsPinningService {
                base_url: "http://example.com".to_string(),
                bearer_token_env: None,
            }],
        };
        let proc = TezosChainProcessor::new(
            "https://mainnet.tezos.marigold.dev",
            storage,
            crate::types::DEFAULT_MAX_CONTENT_REQUEST_RETRIES,
        )
        .expect("new ok");
        assert_eq!(proc.ipfs_pinning_providers().len(), 1);
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
            ipfs_pinning_configs: vec![],
        };
        let proc = TezosChainProcessor::new(
            "https://mainnet.tezos.marigold.dev",
            storage,
            crate::types::DEFAULT_MAX_CONTENT_REQUEST_RETRIES,
        )
        .expect("new ok");
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
            ipfs_pinning_configs: vec![],
        };
        let proc = TezosChainProcessor::new(
            "https://mainnet.tezos.marigold.dev",
            storage,
            crate::types::DEFAULT_MAX_CONTENT_REQUEST_RETRIES,
        )
        .expect("new ok");
        assert_eq!(proc.output_path().unwrap().to_str().unwrap(), "/tmp");
    }
}
