use anyhow::Result;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use tezos_contract::ContractFetcher;
use tezos_core::types::number::Int;
use tezos_michelson::michelson::data;
use tezos_rpc::client::TezosRpc;
use tezos_rpc::http::default::HttpClient;
use tracing::{debug, error};

use crate::content::{extra::fetch_and_save_extra_content, fetch_and_save_content};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct NFTAttribute {
    pub trait_type: String,
    pub value: serde_json::Value,
}

#[derive(Debug)]
struct ContractWithToken {
    address: String,
    token_id: String,
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
            Some(format!("data:application/json;base64,{}", base64))
        }
        std::cmp::Ordering::Less => None,
    }
}

async fn get_uri(
    rpc: &TezosRpc<HttpClient>,
    contract: &ContractWithToken,
) -> Result<Option<String>> {
    let nft_contract = rpc
        .contract_at(contract.address.clone().try_into()?, None)
        .await?;
    let token_metadata = nft_contract
        .storage()
        .big_maps()
        .get_by_name("token_metadata")
        .unwrap();
    let token_id = Int::from(&contract.token_id)?;
    let token_id_michelson = data::int(token_id);
    let value = token_metadata
        .get_value(rpc, token_id_michelson, None)
        .await?;

    // Convert to JSON to access the raw hex string
    let json_value = serde_json::to_value(value)?;

    Ok(get_uri_from_token_metadata(&json_value))
}

async fn fetch_nft_metadata(
    token_uri: &str,
    contract: &ContractWithToken,
    output_path: &std::path::Path,
) -> Result<()> {
    use crate::content::Options;
    use tokio::fs;
    use tracing::debug;

    debug!("Fetching metadata from {}", token_uri);
    let metadata_content_result = fetch_and_save_content(
        token_uri,
        "tezos",
        &contract.address,
        &contract.token_id,
        output_path,
        Options {
            overriden_filename: Some("metadata.json".to_string()),
            fallback_filename: None,
        },
    )
    .await;

    let metadata_content = match metadata_content_result {
        Ok(path) => path,
        Err(e) => {
            error!(
                "Failed to fetch metadata for contract {} (token ID {}): {}",
                contract.address, contract.token_id, e
            );
            return Err(e);
        }
    };

    let metadata_content_str = fs::read_to_string(metadata_content).await?;
    let metadata: NFTMetadata = serde_json::from_str(&metadata_content_str)?;

    // Get NFT name to use as fallback filename
    let nft_name = metadata.name.as_deref().unwrap_or("untitled");

    // Collect all URIs that need to be downloaded
    let mut urls_to_download = Vec::new();

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
            urls_to_download.push((format.uri.clone(), file_name));
        }
    }

    // Helper function to add non-empty URLs
    let mut add_if_not_empty = |url: &Option<String>, name: &str| {
        if let Some(url) = url {
            if !url.is_empty() {
                urls_to_download.push((url.clone(), name.to_string()));
            }
        }
    };

    add_if_not_empty(&metadata.image, "image");
    add_if_not_empty(&metadata.artifact_uri, "artifact");
    add_if_not_empty(&metadata.display_uri, "display");
    add_if_not_empty(&metadata.thumbnail_uri, "thumbnail");

    // Download all URLs, keeping track of what we've downloaded to avoid duplicates
    let mut downloaded = std::collections::HashSet::new();
    for (url, file_name) in urls_to_download {
        // Only download if we haven't seen this URL before
        let inserted = downloaded.insert(url.clone());
        if !inserted {
            debug!("Skipping duplicate {} from {}", file_name, url);
            continue;
        }

        debug!("Downloading {} from {}", file_name, url);
        if let Err(e) = fetch_and_save_content(
            &url,
            "tezos",
            &contract.address,
            &contract.token_id,
            output_path,
            Options {
                overriden_filename: Some(file_name),
                fallback_filename: None,
            },
        )
        .await
        {
            error!(
                "Failed to fetch content from {} for contract {} (token ID {}): {}",
                url, contract.address, contract.token_id, e
            );
            return Err(e);
        }
    }

    // Process any additional content after downloading all files
    if let Err(e) = fetch_and_save_extra_content(
        "tezos",
        &contract.address,
        &contract.token_id,
        output_path,
        metadata.artifact_uri.as_deref(),
    )
    .await
    {
        error!(
            "Failed to fetch extra content for contract {} (token ID {}): {}",
            contract.address, contract.token_id, e
        );
        return Err(e);
    }

    Ok(())
}

pub async fn process_nfts(
    rpc_url: &str,
    contracts: Vec<String>,
    output_path: &std::path::Path,
    exit_on_error: bool,
) -> Result<()> {
    // Initialize Tezos RPC client
    let rpc: TezosRpc<HttpClient> = TezosRpc::new(rpc_url.to_string());

    let contracts = contracts
        .into_iter()
        .map(|s| {
            let parts: Vec<&str> = s.split(':').collect();
            ContractWithToken {
                address: parts[0].to_string(),
                token_id: parts[1].parse().unwrap(),
            }
        })
        .collect::<Vec<_>>();

    for contract in contracts {
        debug!(
            "Processing contract {} on tezos (token ID {})",
            contract.address, contract.token_id
        );
        let token_uri = match get_uri(&rpc, &contract).await? {
            None => {
                error!(
                    "Failed to get token URI for contract {} (token ID {})",
                    contract.address, contract.token_id
                );
                continue;
            }
            Some(uri) => uri,
        };

        if let Err(e) = fetch_nft_metadata(&token_uri, &contract, output_path).await {
            error!(
                "Failed to process contract {} (token ID {}): {}",
                contract.address, contract.token_id, e
            );
            if exit_on_error {
                return Err(e);
            }
        }
    }

    Ok(())
}
