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
use crate::StorageConfig;

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
    pub ipfs_providers: Vec<Box<dyn IpfsPinningProvider>>,
    pub http_client: crate::httpclient::HttpClient,
}

impl TezosChainProcessor {
    pub fn new(rpc_url: &str, storage_config: StorageConfig) -> anyhow::Result<Self> {
        let rpc = TezosRpc::<TezosHttpClient>::new(rpc_url.to_string());
        let ipfs_providers: Vec<Box<dyn IpfsPinningProvider>> = storage_config
            .ipfs_providers
            .iter()
            .map(|config| config.create_provider())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            rpc,
            output_path: storage_config.output_path,
            ipfs_providers,
            http_client: crate::httpclient::HttpClient::new(),
        })
    }
}

#[async_trait::async_trait]
impl crate::chain::NFTChainProcessor for TezosChainProcessor {
    type Metadata = NFTMetadata;
    type ContractTokenId = ContractTokenId;
    type RpcClient = tezos_rpc::client::TezosRpc<TezosHttpClient>;

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
