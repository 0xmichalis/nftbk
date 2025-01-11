use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::convert::TryInto;
use tezos_contract::ContractFetcher;
use tezos_core::types::number::Int;
use tezos_michelson::michelson::data;
use tezos_rpc::client::TezosRpc;
use tezos_rpc::http::default::HttpClient;
use tokio::fs;

use crate::{content::fetch_and_save_content, url::get_url};

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
    #[serde(rename = "fileName")]
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

async fn get_ipfs_uri(
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

    // Extract the hex string from the JSON structure
    let hex_str = json_value
        .as_object()
        .and_then(|obj| obj.get("args"))
        .and_then(|args| args.as_array())
        .and_then(|arr| arr.get(1))
        .and_then(|seq| seq.as_array())
        .and_then(|seq_arr| seq_arr.first())
        .and_then(|elt| elt.as_object())
        .and_then(|elt_obj| elt_obj.get("args"))
        .and_then(|elt_args| elt_args.as_array())
        .and_then(|elt_arr| elt_arr.get(1))
        .and_then(|bytes_obj| bytes_obj.as_object())
        .and_then(|bytes_map| bytes_map.get("bytes"))
        .and_then(|bytes_val| bytes_val.as_str());

    if let Some(hex_str) = hex_str {
        let bytes = hex::decode(hex_str)?;
        let decoded = String::from_utf8(bytes)?;
        Ok(Some(decoded))
    } else {
        Ok(None)
    }
}

pub async fn process_nfts(contracts: Vec<String>, output_path: &std::path::Path) -> Result<()> {
    // Initialize Tezos RPC client
    let rpc_url = std::env::var("TEZOS_RPC_URL").context("TEZOS_RPC_URL not set")?;
    let rpc: TezosRpc<HttpClient> = TezosRpc::new(rpc_url);

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
        println!("Processing contract {}", contract.address);

        if let Some(uri) = get_ipfs_uri(&rpc, &contract).await? {
            println!("Fetching metadata from {}", uri);

            // Convert IPFS URLs to gateway URL if needed
            let metadata_url = get_url(&uri);

            // Fetch metadata
            let client = reqwest::Client::new();
            let metadata: NFTMetadata = client.get(&metadata_url).send().await?.json().await?;

            // Save metadata
            let dir_path = output_path
                .join("tezos")
                .join(&contract.address)
                .join(&contract.token_id);
            let metadata_filename = dir_path.join("metadata.json");
            fs::create_dir_all(&dir_path).await?;
            fs::write(&metadata_filename, serde_json::to_string_pretty(&metadata)?).await?;
            println!("Saved metadata to {}", metadata_filename.display());

            // Collect all URIs that need to be downloaded
            let mut urls_to_download = Vec::new();

            // Add URIs from formats array with their filenames
            if let Some(formats) = &metadata.formats {
                for format in formats {
                    urls_to_download.push((format.uri.clone(), format.file_name.clone()));
                }
            }

            if let Some(url) = &metadata.image {
                urls_to_download.push((url.clone(), "image".to_string()));
            }
            if let Some(url) = &metadata.artifact_uri {
                urls_to_download.push((url.clone(), "artifact".to_string()));
            }
            if let Some(url) = &metadata.display_uri {
                urls_to_download.push((url.clone(), "display".to_string()));
            }
            if let Some(url) = &metadata.thumbnail_uri {
                urls_to_download.push((url.clone(), "thumbnail".to_string()));
            }

            // Download all URLs, keeping track of what we've downloaded to avoid duplicates
            let mut downloaded = std::collections::HashSet::new();
            for (url, file_name) in urls_to_download {
                // Only download if we haven't seen this exact URL + file_name combination
                if downloaded.insert((url.clone(), file_name.clone())) {
                    println!("Downloading content from {}", url);
                    fetch_and_save_content(
                        &url,
                        output_path,
                        "tezos",
                        &contract.token_id,
                        &contract.address,
                        Some(&file_name),
                    )
                    .await?;
                }
            }
        }
    }

    Ok(())
}
