use std::sync::atomic::Ordering;

use anyhow::{bail, Context, Result};
use futures_util::FutureExt;
use serde_json::json;
use tokio::task::JoinHandle;
use tracing::{error, warn};

use crate::ipfs::PinRequest;
use crate::server::database::r#trait::{ManagedPin, PinUpdate, Progress};
use crate::server::model::*;
use crate::server::snapshot::{build_archive, capture, failure, quote};
use crate::server::AppState;

pub fn spawn_workers(parallelism: usize, state: AppState) -> Vec<JoinHandle<()>> {
    (0..parallelism.max(1))
        .map(|_| {
            let state = state.clone();
            tokio::spawn(async move {
                while !state.shutdown_flag.load(Ordering::SeqCst) {
                    match state.db.claim().await {
                        Ok(Some(claim)) => run(state.clone(), claim).await,
                        Ok(None) => tokio::time::sleep(std::time::Duration::from_millis(500)).await,
                        Err(error) => {
                            error!(%error,"Could not claim operation");
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }
                    }
                }
            })
        })
        .collect()
}

async fn run(state: AppState, claim: Claim) {
    let heartbeat = async {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(20)).await;
            if state.shutdown_flag.load(Ordering::SeqCst)
                || !state.db.heartbeat(&claim).await.unwrap_or(false)
            {
                break;
            }
        }
    };
    let execute = execute(&state, &claim);
    let result = tokio::select! {
        result=std::panic::AssertUnwindSafe(execute).catch_unwind()=>Some(result),
        ()=heartbeat=>None,
    };
    if state.shutdown_flag.load(Ordering::SeqCst) {
        return;
    }
    match result {
        Some(Ok(Ok(()))) | None => {}
        Some(Ok(Err(error))) => {
            let message = crate::errors::redact_urls(&error.to_string());
            warn!(operation_id=%claim.operation.id,error=%message,"Operation failed");
            let _ = state
                .db
                .progress(
                    &claim,
                    Progress::Failed(failure("operation_failed", &message)),
                )
                .await;
        }
        Some(Err(_)) => {
            let _ = state
                .db
                .progress(
                    &claim,
                    Progress::Failed(failure(
                        "worker_panic",
                        "Operation interrupted by a worker panic",
                    )),
                )
                .await;
        }
    }
}

pub async fn execute(state: &AppState, claim: &Claim) -> Result<()> {
    match claim.operation.kind.as_str() {
        "capture" => capture(state, claim).await,
        "archive" => build_archive(state, claim).await,
        "quote" => quote(state, claim).await,
        "pin" => pin(state, claim).await,
        "delete_archive" => delete_archive(state, claim).await,
        "delete_pin_set" => delete_pin_set(state, claim).await,
        "delete_backup" => delete_backup(state, claim).await,
        _ => bail!("Unknown operation kind"),
    }
}

async fn reconcile(state: &AppState, claim: &Claim, pin: &ManagedPin) -> Result<bool> {
    let provider = state
        .providers
        .get(&pin.provider_id)
        .context("Configured provider account is unavailable")?;
    if let Some(observed) = provider.find_pin(&pin.cid, &pin.id).await? {
        state
            .db
            .update_pin(
                claim,
                PinUpdate::Observed {
                    pin_id: pin.id.clone(),
                    request_id: observed.id,
                    state: observed.status.as_str().into(),
                },
            )
            .await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn pin(state: &AppState, claim: &Claim) -> Result<()> {
    let context = state.db.context(claim).await?;
    let items: Vec<Item> = serde_json::from_value(context["items"].clone())?;
    let providers: Vec<String> = serde_json::from_value(context["provider_ids"].clone())?;
    if providers.is_empty() {
        bail!("No provider accounts are associated with this pin set");
    }
    let mut eligible = false;
    let mut pending = false;
    let mut failed = false;
    for asset in items
        .iter()
        .flat_map(|i| &i.assets)
        .filter(|a| a.cid.is_some())
    {
        eligible = true;
        for provider_id in &providers {
            let managed = state.db.reserve_pin(claim, asset, provider_id).await?;
            let provider = state
                .providers
                .get(provider_id)
                .context("Configured provider account is unavailable")?;
            if let Some(request_id) = &managed.request_id {
                match provider.get_pin(request_id).await {
                    Ok(observed) => {
                        anyhow::ensure!(
                            observed.cid == managed.cid,
                            "Provider returned a pin for another CID"
                        );
                        pending |= matches!(
                            observed.status,
                            crate::ipfs::PinResponseStatus::Queued
                                | crate::ipfs::PinResponseStatus::Pinning
                        );
                        failed |= observed.status == crate::ipfs::PinResponseStatus::Failed;
                        state
                            .db
                            .update_pin(
                                claim,
                                PinUpdate::Observed {
                                    pin_id: managed.id,
                                    request_id: observed.id,
                                    state: observed.status.as_str().into(),
                                },
                            )
                            .await?;
                    }
                    Err(_) => {
                        state
                            .db
                            .update_pin(
                                claim,
                                PinUpdate::Failed {
                                    pin_id: managed.id,
                                    failure: failure(
                                        "pin_observation_failed",
                                        "Provider pin state could not be confirmed",
                                    ),
                                    ambiguous: true,
                                },
                            )
                            .await?;
                        pending = true;
                    }
                }
            } else if managed.submitted_at.is_some()
                || managed.operation_id.as_deref() != Some(&claim.operation.id)
            {
                if !reconcile(state, claim, &managed).await?
                    && managed
                        .submitted_at
                        .is_some_and(|at| chrono::Utc::now() - at > chrono::Duration::minutes(15))
                {
                    let error = failure("pin_reconciliation_required", "The provider has not confirmed this submission; reconcile the remote request before retrying");
                    state
                        .db
                        .update_pin(
                            claim,
                            PinUpdate::Failed {
                                pin_id: managed.id,
                                failure: error.clone(),
                                ambiguous: true,
                            },
                        )
                        .await?;
                    state.db.progress(claim, Progress::Failed(error)).await?;
                    return Ok(());
                }
                pending = true;
            } else {
                let request = PinRequest {
                    cid: managed.cid.clone(),
                    name: Some(format!("nftbk-{}", managed.id)),
                    metadata: Some(serde_json::from_value(json!({"nftbk_pin_id":managed.id} ))?),
                };
                state
                    .db
                    .update_pin(
                        claim,
                        PinUpdate::Submitting {
                            pin_id: managed.id.clone(),
                        },
                    )
                    .await?;
                match provider.create_pin(&request).await {
                    Ok(observed) => {
                        anyhow::ensure!(
                            observed.cid == managed.cid,
                            "Provider returned a pin for another CID"
                        );
                        pending |= matches!(
                            observed.status,
                            crate::ipfs::PinResponseStatus::Queued
                                | crate::ipfs::PinResponseStatus::Pinning
                        );
                        failed |= observed.status == crate::ipfs::PinResponseStatus::Failed;
                        state
                            .db
                            .update_pin(
                                claim,
                                PinUpdate::Observed {
                                    pin_id: managed.id,
                                    request_id: observed.id,
                                    state: observed.status.as_str().into(),
                                },
                            )
                            .await?;
                    }
                    Err(_) => {
                        state.db.update_pin(claim,PinUpdate::Failed {pin_id:managed.id,failure:failure("pin_submission_unknown","Provider response was interrupted; reconciling the submitted request"),ambiguous:true}).await?;
                        pending = true;
                    }
                }
            }
        }
    }
    if !eligible {
        bail!("This snapshot has no IPFS assets; all requested NFTs were skipped");
    }
    if pending {
        state.db.progress(claim, Progress::Deferred).await?;
        return Ok(());
    }
    if failed {
        bail!("One or more provider pins failed");
    }
    let pin_set: PinSet = serde_json::from_value(
        state
            .db
            .get(
                Resource::PinSet,
                &claim.owner_id,
                &claim.operation.target_id,
            )
            .await?
            .context("Pin set missing")?,
    )?;
    state
        .db
        .progress(
            claim,
            Progress::Pinned {
                state: if pin_set.skipped_nft_count > 0 {
                    State::Partial
                } else {
                    State::Ready
                },
            },
        )
        .await?;
    Ok(())
}

async fn delete_archive(state: &AppState, claim: &Claim) -> Result<()> {
    let context = state.db.context(claim).await?;
    if let Some(key) = context["storage_key"].as_str() {
        if !key.starts_with("blobs/") {
            state.storage.remove(key).await?;
            state.storage.remove(&format!("{key}.sha256")).await?;
        }
    }
    state.db.progress(claim, Progress::Deleted).await?;
    Ok(())
}

async fn delete_pin_set(state: &AppState, claim: &Claim) -> Result<()> {
    for managed in state.db.release_pins(claim).await? {
        let provider = state
            .providers
            .get(&managed.provider_id)
            .context("Configured provider account is unavailable; pin removal remains pending")?;
        if let Some(request_id) = &managed.request_id {
            provider.delete_pin(request_id).await?;
        } else if managed.submitted_at.is_some() {
            if reconcile(state, claim, &managed).await? {
                state.db.progress(claim, Progress::Deferred).await?;
                return Ok(());
            }
            bail!("Unconfirmed pin submission must be reconciled before deletion");
        }
        state
            .db
            .update_pin(claim, PinUpdate::Deleted { pin_id: managed.id })
            .await?;
    }
    state.db.progress(claim, Progress::Deleted).await?;
    Ok(())
}

async fn delete_backup(state: &AppState, claim: &Claim) -> Result<()> {
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
    let mut pending = false;
    for archive in backup.archives {
        if !matches!(archive.state, State::Deleted | State::Expired) {
            let operation = state
                .db
                .delete(Resource::Archive, &claim.owner_id, &archive.id)
                .await?;
            if operation.state == "failed" {
                bail!("Archive deletion failed; retry its operation before completing backup deletion");
            }
            pending = true;
        }
    }
    for pin_set in backup.pin_sets {
        if pin_set.state != State::Deleted {
            let operation = state
                .db
                .delete(Resource::PinSet, &claim.owner_id, &pin_set.id)
                .await?;
            if operation.state == "failed" {
                bail!("Pin removal failed; retry its operation before completing backup deletion");
            }
            pending = true;
        }
    }
    state
        .db
        .progress(
            claim,
            if pending {
                Progress::Deferred
            } else {
                Progress::Deleted
            },
        )
        .await?;
    Ok(())
}

pub fn spawn_maintenance(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_staging_cleanup =
            tokio::time::Instant::now() - std::time::Duration::from_secs(60);
        while !state.shutdown_flag.load(Ordering::SeqCst) {
            if let Err(error) = state.db.maintenance().await {
                error!(%error,"Operation recovery failed");
            }
            if last_staging_cleanup.elapsed() >= std::time::Duration::from_secs(60) {
                if let Err(error) = state.storage.cleanup_staging(state.db.as_ref()).await {
                    error!(%error,"Staging cleanup remains pending");
                }
                last_staging_cleanup = tokio::time::Instant::now();
            }
            match state.db.garbage(None).await {
                Ok(blobs) => {
                    for blob in blobs {
                        if let Err(error) = state.storage.collect(state.db.as_ref(), &blob).await {
                            error!(%error,"Blob cleanup remains pending");
                        }
                    }
                }
                Err(error) => error!(%error,"Could not schedule blob cleanup"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    })
}
