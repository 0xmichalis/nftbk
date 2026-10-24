use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use tokio::fs;
use uuid::Uuid;

use crate::chain::common::ContractTokenId;
use crate::chain::evm::EvmChainProcessor;
use crate::chain::tezos::TezosChainProcessor;
use crate::chain::NFTChainProcessor;
use crate::ipfs::url::extract_ipfs_cid;
use crate::server::database::r#trait::Progress;
use crate::server::model::*;
use crate::server::AppState;
use crate::StorageConfig;

pub fn failure(code: &str, message: &str) -> Failure {
    Failure {
        code: code.into(),
        message: crate::errors::redact_urls(message),
        retryable: true,
    }
}

fn token(nft: &Nft) -> ContractTokenId {
    ContractTokenId {
        address: nft.contract_address.clone(),
        token_id: nft.token_id.clone(),
        chain_name: nft.chain_id.clone(),
    }
}

pub fn new_item(backup_id: &str, nft: Nft) -> Item {
    Item {
        links: Default::default(),
        id: Uuid::new_v4().to_string(),
        backup_id: backup_id.into(),
        nft,
        state: State::Queued,
        metadata_uri: None,
        metadata_sha256: None,
        observed_at: None,
        block_reference: None,
        error: None,
        assets: vec![],
    }
}

pub async fn observe(state: &AppState, claim: &Claim, item: &mut Item) -> Result<()> {
    let rpc = state
        .chain_config
        .0
        .get(&item.nft.chain_id)
        .context("Chain is not configured")?;
    let storage = StorageConfig {
        output_path: None,
        prune_redundant: false,
        ipfs_pinning_configs: vec![],
    };
    if item.nft.chain_id.starts_with("tezos:") {
        let processor = TezosChainProcessor::new(rpc, storage, state.max_content_request_retries)?;
        observe_with(state, claim, item, &processor).await
    } else {
        let processor =
            EvmChainProcessor::new(rpc, storage, state.max_content_request_retries).await?;
        observe_with(state, claim, item, &processor).await
    }
}

async fn observe_with<C>(
    state: &AppState,
    claim: &Claim,
    item: &mut Item,
    processor: &C,
) -> Result<()>
where
    C: NFTChainProcessor<ContractTokenId = ContractTokenId>,
    C::Metadata: serde::de::DeserializeOwned,
{
    let uri = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        processor.get_uri(&token(&item.nft)),
    )
    .await
    .context("NFT RPC observation timed out")??;
    let raw = processor.http_client().fetch(&uri).await?;
    let blob = state.storage.put(state.db.as_ref(), claim, &raw).await?;
    item.metadata_uri = Some(uri.clone());
    item.metadata_sha256 = Some(blob.sha256.clone());
    item.observed_at = Some(Utc::now());
    item.assets.push(Asset {
        id: Uuid::new_v4().to_string(),
        item_id: item.id.clone(),
        role: "metadata".into(),
        source_uri: Some(uri.clone()),
        filename: None,
        fallback_filename: None,
        observed_at: item.observed_at,
        path: format!("{}/metadata.json", item.nft.directory()),
        sha256: Some(blob.sha256),
        cid: extract_ipfs_cid(&uri),
        size_bytes: Some(blob.size_bytes),
        state: State::Ready,
        error: None,
    });
    let metadata: C::Metadata = serde_json::from_slice(&raw)?;
    let mut seen = HashSet::new();
    for (uri, options) in C::collect_urls(&metadata) {
        if !seen.insert(uri.clone()) {
            continue;
        }
        item.assets.push(Asset {
            id: Uuid::new_v4().to_string(),
            item_id: item.id.clone(),
            role: options
                .fallback_filename
                .clone()
                .unwrap_or_else(|| "content".into()),
            source_uri: Some(uri.clone()),
            filename: options.overriden_filename,
            fallback_filename: options.fallback_filename,
            observed_at: None,
            path: format!(
                "{}/assets/{}/content",
                item.nft.directory(),
                item.assets.len()
            ),
            sha256: None,
            cid: extract_ipfs_cid(&uri),
            size_bytes: None,
            state: State::Queued,
            error: None,
        });
    }
    Ok(())
}

pub async fn capture(state: &AppState, claim: &Claim) -> Result<()> {
    let context = state.db.context(claim).await?;
    let mut items: Vec<Item> = serde_json::from_value(context["items"].clone())?;
    let download = claim
        .specification
        .as_ref()
        .context("Missing specification")?
        .outputs
        .iter()
        .any(|o| matches!(o, OutputRequest::Archive { .. }));
    let staging = state.storage.stage(claim).await?;
    for item in &mut items {
        if state.shutdown_flag.load(Ordering::SeqCst) {
            bail!("Server is shutting down");
        }
        if item.state == State::Ready {
            continue;
        }
        if item.metadata_sha256.is_none() {
            if observe(state, claim, item).await.is_err() {
                item.state = State::Failed;
                item.error = Some(failure(
                    "metadata_capture_failed",
                    "NFT metadata could not be captured",
                ));
                state
                    .db
                    .progress(claim, Progress::Items(vec![item.clone()]))
                    .await?;
                continue;
            }
            state
                .db
                .progress(claim, Progress::Items(vec![item.clone()]))
                .await?;
        }
        let mut additions = vec![];
        for (index, asset) in item.assets.iter_mut().enumerate() {
            if asset.sha256.is_some() || asset.role == "dependency" {
                continue;
            }
            if !download {
                asset.state = if asset.cid.is_some() {
                    State::Ready
                } else {
                    State::Unsupported
                };
                continue;
            }
            let Some(uri) = asset.source_uri.as_deref() else {
                continue;
            };
            let root = staging.join(&item.id).join(index.to_string());
            let result = download_asset(
                state,
                claim,
                &item.nft,
                asset,
                uri.to_string(),
                &root,
                index,
            )
            .await;
            match result {
                Ok((primary, dependencies)) => {
                    *asset = primary;
                    additions.extend(dependencies);
                }
                Err(_) => {
                    asset.state = State::Failed;
                    asset.error = Some(failure(
                        "asset_capture_failed",
                        "Asset could not be captured",
                    ));
                }
            }
        }
        item.assets.extend(additions);
        item.state = if item.assets.iter().any(|a| a.state == State::Failed) {
            State::Partial
        } else {
            State::Ready
        };
        item.error = None;
        state
            .db
            .progress(claim, Progress::Items(vec![item.clone()]))
            .await?;
    }
    // Read persisted IDs so the manifest and subsequent pin memberships agree.
    let context = state.db.context(claim).await?;
    let items: Vec<Item> = serde_json::from_value(context["items"].clone())?;
    let backup: Backup = serde_json::from_value(
        state
            .db
            .get(
                Resource::Backup,
                &claim.owner_id,
                &claim.operation.target_id,
            )
            .await?
            .context("Backup missing")?,
    )?;
    let manifest = Manifest {
        version: 2,
        backup_id: backup.id,
        created_at: backup.created_at,
        provenance: backup.provenance,
        items,
    };
    let (_, failed) = manifest.coverage();
    if manifest.items.iter().all(|i| i.metadata_sha256.is_none()) {
        bail!("No NFT metadata could be captured");
    }
    let blob = state
        .storage
        .put(
            state.db.as_ref(),
            claim,
            &serde_json::to_vec_pretty(&manifest)?,
        )
        .await?;
    state
        .db
        .progress(
            claim,
            Progress::Captured {
                manifest_sha256: blob.sha256,
                state: if failed == 0 {
                    State::Ready
                } else {
                    State::Partial
                },
            },
        )
        .await?;
    fs::remove_dir_all(staging).await.ok();
    Ok(())
}

async fn download_asset(
    state: &AppState,
    claim: &Claim,
    nft: &Nft,
    asset: &Asset,
    uri: String,
    root: &Path,
    index: usize,
) -> Result<(Asset, Vec<Asset>)> {
    let client =
        crate::httpclient::HttpClient::new().with_max_retries(state.max_content_request_retries);
    let primary = client
        .fetch_and_write(
            &uri,
            &token(nft),
            root,
            crate::content::Options {
                overriden_filename: asset.filename.clone(),
                fallback_filename: asset
                    .fallback_filename
                    .clone()
                    .or_else(|| Some("content".into())),
            },
        )
        .await?;
    if matches!(asset.role.as_str(), "animation" | "artifact") {
        crate::content::extra::fetch_and_write_extra(&token(nft), root, Some(&uri)).await?;
    }
    let content_root = root.join(nft.directory());
    let mut paths = files(&content_root).await?;
    paths.sort();
    let mut retained = asset.clone();
    let mut dependencies = vec![];
    for path in paths {
        let blob = state
            .storage
            .import(state.db.as_ref(), claim, &path)
            .await?;
        let relative = path
            .strip_prefix(&content_root)?
            .to_string_lossy()
            .to_string();
        let mut entry = if path == primary {
            asset.clone()
        } else {
            Asset {
                id: Uuid::new_v4().to_string(),
                item_id: asset.item_id.clone(),
                role: "dependency".into(),
                source_uri: None,
                filename: None,
                fallback_filename: None,
                observed_at: None,
                path: String::new(),
                sha256: None,
                cid: None,
                size_bytes: None,
                state: State::Queued,
                error: None,
            }
        };
        entry.observed_at = Some(Utc::now());
        entry.path = format!("{}/assets/{index}/{relative}", nft.directory());
        entry.sha256 = Some(blob.sha256);
        entry.size_bytes = Some(blob.size_bytes);
        entry.state = State::Ready;
        entry.error = None;
        if path == primary {
            retained = entry;
        } else {
            dependencies.push(entry);
        }
    }
    Ok((retained, dependencies))
}

pub async fn files(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut pending = vec![directory.to_path_buf()];
    let mut result = vec![];
    while let Some(path) = pending.pop() {
        let mut entries = fs::read_dir(path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let kind = entry.file_type().await?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                result.push(entry.path());
            }
        }
    }
    Ok(result)
}

pub async fn quote(state: &AppState, claim: &Claim) -> Result<()> {
    let specification = claim
        .specification
        .as_ref()
        .context("Missing quote specification")?;
    let context = state.db.context(claim).await?;
    let existing: Vec<Item> = serde_json::from_value(context["items"].clone())?;
    let mut plan = vec![];
    let client =
        crate::httpclient::HttpClient::new().with_max_retries(state.max_content_request_retries);
    for nft in &specification.nfts {
        let mut item = if let Some(item) = existing.iter().find(|i| i.nft == *nft) {
            item.clone()
        } else {
            let mut item = new_item("", nft.clone());
            observe(state, claim, &mut item).await?;
            item
        };
        for asset in &mut item.assets {
            if asset.size_bytes.is_none() {
                if asset.cid.is_none()
                    && !specification
                        .outputs
                        .iter()
                        .any(|o| matches!(o, OutputRequest::Archive { .. }))
                {
                    asset.size_bytes = Some(0);
                    continue;
                }
                let uri = asset.source_uri.as_deref().context("Asset URI missing")?;
                asset.size_bytes = Some(client.head_content_length(uri).await?);
            }
        }
        plan.push(item);
    }
    let pricing = state.x402_config.as_ref().context("Pricing is disabled")?;
    let (amount, bytes) = estimate_price(&pricing.pricing, specification, &plan)?;
    state
        .db
        .progress(
            claim,
            Progress::Quoted {
                plan,
                amount_atomic: amount.to_string(),
                estimated_size_bytes: bytes,
                lifetime_seconds: u32::try_from(pricing.max_timeout_seconds)?,
            },
        )
        .await?;
    Ok(())
}

pub fn estimate_price(
    pricing: &crate::server::x402::PricingConfig,
    specification: &Specification,
    plan: &[Item],
) -> Result<(u64, u64)> {
    let mut archive_bytes = 0u64;
    let mut pin_bytes = 0u64;
    let mut seen_archive = BTreeSet::new();
    let mut seen_pins = BTreeSet::new();
    for asset in plan.iter().flat_map(|i| &i.assets) {
        let size = asset.size_bytes.context("Asset size is unavailable")?;
        let key = asset
            .sha256
            .as_deref()
            .or(asset.source_uri.as_deref())
            .context("Asset identity unavailable")?;
        if seen_archive.insert(key) {
            archive_bytes = archive_bytes.checked_add(size).context("Size overflow")?;
        }
        if let Some(cid) = &asset.cid {
            if seen_pins.insert(cid) {
                pin_bytes = pin_bytes.checked_add(size).context("Size overflow")?;
            }
        }
    }
    let mut total = 0u128;
    for output in &specification.outputs {
        let (rate, bytes) = match output {
            OutputRequest::Archive { .. } => (
                pricing
                    .archive_price_per_gb
                    .context("Archive pricing is unavailable")?,
                archive_bytes,
            ),
            OutputRequest::Ipfs => (
                pricing
                    .pin_price_per_gb
                    .context("IPFS pricing is unavailable")?,
                pin_bytes,
            ),
        };
        total = total
            .checked_add((u128::from(rate) * u128::from(bytes)).div_ceil(1024 * 1024 * 1024))
            .context("Price overflow")?;
    }
    Ok((
        u64::try_from(total)?,
        if specification
            .outputs
            .iter()
            .any(|o| matches!(o, OutputRequest::Archive { .. }))
        {
            archive_bytes
        } else {
            pin_bytes
        },
    ))
}

pub async fn build_archive(state: &AppState, claim: &Claim) -> Result<()> {
    let context = state.db.context(claim).await?;
    let archive: Archive = serde_json::from_value(context["archive"].clone())?;
    let backup: Backup = serde_json::from_value(
        state
            .db
            .get(Resource::Backup, &claim.owner_id, &archive.backup_id)
            .await?
            .context("Backup missing")?,
    )?;
    let digest = backup.manifest_sha256.as_deref().context(
        "Legacy backup has no captured manifest; create a fresh snapshot to generate an archive",
    )?;
    let raw = state.storage.read(digest).await?;
    let manifest: Manifest = serde_json::from_slice(&raw)?;
    let staging = state.storage.stage(claim).await?;
    let contents = staging.join("contents");
    fs::create_dir_all(&contents).await?;
    for asset in manifest.items.iter().flat_map(|i| &i.assets) {
        let Some(digest) = asset.sha256.as_deref() else {
            continue;
        };
        let target = contents.join(&asset.path);
        anyhow::ensure!(
            Path::new(&asset.path)
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_))),
            "Invalid manifest path"
        );
        fs::create_dir_all(target.parent().context("Missing parent")?).await?;
        fs::copy(state.storage.blob_path(digest)?, target).await?;
    }
    fs::write(contents.join("manifest.json"), &raw).await?;
    let path = staging.join(format!("archive.{}", archive.format.as_str()));
    let output = path.clone();
    let format = archive.format.as_str().to_string();
    let shutdown = state.shutdown_flag.clone();
    tokio::task::spawn_blocking(move || {
        crate::server::archive::zip_backup(&contents, &output, format, Some(shutdown))
    })
    .await?
    .map_err(anyhow::Error::msg)?;
    let blob = state
        .storage
        .import(state.db.as_ref(), claim, &path)
        .await?;
    state.db.progress(claim, Progress::Archived(blob)).await?;
    fs::remove_dir_all(staging).await.ok();
    Ok(())
}

#[cfg(test)]
mod estimate_price_tests {
    use super::*;
    #[test]
    fn charges_atomic_units_proportionally_and_excludes_non_ipfs_assets_from_pinning() {
        let pricing = crate::server::x402::PricingConfig {
            archive_price_per_gb: Some(1_000_000),
            pin_price_per_gb: Some(2_000_000),
        };
        let mut specification = Specification {
            nfts: vec![],
            outputs: vec![OutputRequest::Ipfs],
        };
        let mut item = new_item(
            "",
            Nft {
                chain_id: "eip155:1".into(),
                contract_address: String::new(),
                token_id: "1".into(),
            },
        );
        item.assets.push(Asset {
            id: String::new(),
            item_id: String::new(),
            role: "content".into(),
            source_uri: Some("https://example.com/a".into()),
            filename: None,
            fallback_filename: None,
            observed_at: None,
            path: String::new(),
            sha256: None,
            cid: None,
            size_bytes: Some(1024 * 1024 * 1024),
            state: State::Queued,
            error: None,
        });
        item.assets.push(Asset {
            id: String::new(),
            item_id: String::new(),
            role: "content".into(),
            source_uri: Some("ipfs://cid".into()),
            filename: None,
            fallback_filename: None,
            observed_at: None,
            path: String::new(),
            sha256: None,
            cid: Some("cid".into()),
            size_bytes: Some(1024),
            state: State::Queued,
            error: None,
        });
        assert_eq!(
            estimate_price(&pricing, &specification, &[item.clone()]).unwrap(),
            (2, 1024)
        );
        specification.outputs.push(OutputRequest::Archive {
            format: ArchiveFormat::Zip,
            retention_days: Some(3),
        });
        assert_eq!(
            estimate_price(&pricing, &specification, &[item]).unwrap(),
            (1_000_003, 1024 * 1024 * 1024 + 1024)
        );
    }
}

#[cfg(test)]
mod observe_tests {
    use std::sync::Arc;

    use alloy::sol_types::SolValue;
    use serde_json::json;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    use crate::server::database::mock::{state, MockDatabase};

    #[tokio::test]
    async fn retains_original_metadata_and_html_filename_instructions() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(MockDatabase::default());
        let mut state = state(db.clone(), directory.path());
        let server = MockServer::start().await;
        let uri = format!("{}/metadata", server.uri());
        Mock::given(method("POST")).and(path("/rpc")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"jsonrpc":"2.0","id":0,"result":format!("0x{}",hex::encode(uri.abi_encode()))}))).mount(&server).await;
        let original=br#"{ "unknown": {"must":"survive"}, "animation_url":"https://example.com/art", "animation_details":{"format":"html"} }"#;
        Mock::given(method("GET"))
            .and(path("/metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(original.as_slice()))
            .expect(1)
            .mount(&server)
            .await;
        Arc::make_mut(&mut state.chain_config)
            .0
            .insert("eip155:1".into(), format!("{}/rpc", server.uri()));
        let mut item = new_item(
            "snapshot",
            Nft {
                chain_id: "eip155:1".into(),
                contract_address: "0x00000000000000000000000000000000000000ab".into(),
                token_id: "42".into(),
            },
        );
        let claim:Claim=serde_json::from_value(json!({"operation":{"id":"op","kind":"capture","target_id":"snapshot","state":"running","attempts":1,"created_at":Utc::now(),"updated_at":Utc::now(),"error":null},"owner_id":"owner","lease_token":"lease","specification":null,"plan":[]})).unwrap();
        observe(&state, &claim, &mut item).await.unwrap();
        let raw = state
            .storage
            .read(item.metadata_sha256.as_deref().unwrap())
            .await
            .unwrap();
        assert_eq!(raw, original);
        assert_eq!(item.assets.len(), 2);
        assert_eq!(item.assets[1].filename.as_deref(), Some("index.html"));
        assert_eq!(item.assets[1].role, "animation");
        assert_eq!(db.blobs.lock().unwrap().len(), 1);
    }
}
