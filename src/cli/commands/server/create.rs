use std::env;
use std::io::Cursor;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use reqwest::Method;
use uuid::Uuid;

use crate::cli::config::load_token_config;
use crate::client::Client;
use crate::model::*;

pub async fn run(
    tokens_config_path: PathBuf,
    server_address: String,
    output_path: Option<PathBuf>,
    archive_format: String,
    pin_on_ipfs: bool,
    polling_interval_ms: Option<u64>,
) -> Result<()> {
    let tokens = load_token_config(&tokens_config_path).await?;
    let mut nfts = vec![];
    for (chain_id, tokens) in tokens.chains {
        for token in tokens {
            let (contract_address, token_id) = token
                .split_once(':')
                .context("Tokens must use contract_address:token_id")?;
            nfts.push(Nft {
                chain_id: chain_id.clone(),
                contract_address: contract_address.into(),
                token_id: token_id.into(),
            });
        }
    }
    let mut outputs = vec![];
    if output_path.is_some() {
        outputs.push(OutputRequest::Archive {
            format: if archive_format == "tar.gz" {
                ArchiveFormat::TarGz
            } else {
                ArchiveFormat::Zip
            },
            retention_days: None,
        });
    }
    if pin_on_ipfs {
        outputs.push(OutputRequest::Ipfs);
    }
    let mut specification = Specification { nfts, outputs };
    let mut validated = specification.clone();
    validated.normalize(1)?;
    specification.nfts = validated.nfts;
    let client = Client::new(&server_address, env::var("NFTBK_AUTH_TOKEN").ok());
    let interval = std::time::Duration::from_millis(polling_interval_ms.unwrap_or(1000).max(100));
    let response = client
        .request(Method::POST, "/quotes")
        .json(&specification)
        .send()
        .await?;
    let quote_id = if response.status() == reqwest::StatusCode::CONFLICT {
        let error: serde_json::Value = response.json().await?;
        if error["type"] != "urn:nftbk:problem:pricing_unavailable" {
            bail!(
                "{}",
                error["detail"].as_str().unwrap_or("Quote request failed")
            );
        }
        None
    } else {
        let mut quote: Quote = Client::check(response).await?.json().await?;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(360);
        loop {
            match quote.state.as_str() {
                "ready" => break,
                "failed" | "expired" => bail!("Quote {}: {:?}", quote.state, quote.error),
                _ => {}
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("Quote calculation timed out");
            }
            tokio::time::sleep(interval).await;
            quote = client.get_quote(&quote.id).await?;
        }
        println!(
            "Quote: {} {} atomic units",
            quote.amount_atomic.as_deref().unwrap_or("0"),
            quote.asset_symbol
        );
        Some(quote.id)
    };
    let request = CreateBackup {
        nfts: specification.nfts,
        outputs: specification.outputs,
        quote_id,
    };
    let original = client
        .request(Method::POST, "/backups")
        .header("idempotency-key", Uuid::new_v4().to_string())
        .json(&request)
        .build()?;
    let mut response = client
        .http()
        .execute(original.try_clone().context("Request cannot be retried")?)
        .await?;
    if response.status() == reqwest::StatusCode::PAYMENT_REQUIRED {
        let payment: x402_rs::types::PaymentRequiredResponse = response.json().await?;
        let requirement = payment
            .accepts
            .into_iter()
            .next()
            .context("No payment option was offered")?;
        let private_key = env::var("NFTBK_X402_PRIVATE_KEY").ok();
        let handler = crate::cli::x402::X402PaymentHandler::new(private_key.as_deref())?;
        response = handler
            .handle_402_response(client.http(), &original, requirement)
            .await?;
    }
    let mut backup: Backup = Client::check(response).await?.json().await?;
    println!("Backup: {}", backup.id);
    loop {
        if backup.state == State::Failed {
            bail!(
                "Snapshot capture failed; inspect operation {}",
                backup.operation_id.as_deref().unwrap_or("")
            );
        }
        let pending = backup.archives.iter().any(|a| {
            matches!(
                a.state,
                State::Queued | State::Running | State::AwaitingPayment
            )
        }) || backup.pin_sets.iter().any(|p| {
            matches!(
                p.state,
                State::Queued | State::Running | State::AwaitingPayment
            )
        });
        if !pending && matches!(backup.state, State::Ready | State::Partial) {
            break;
        }
        tokio::time::sleep(interval).await;
        backup = client.get(&backup.id).await?;
    }
    if let Some(output) = output_path {
        let archive = backup.archives.first().context("No archive was created")?;
        if !matches!(archive.state, State::Ready | State::Partial) {
            bail!("Archive failed: {:?}", archive.error);
        }
        let bytes = client.download(archive).await?;
        let format = archive.format;
        tokio::task::spawn_blocking(move || -> Result<()> {
            std::fs::create_dir_all(&output)?;
            match format {
                ArchiveFormat::Zip => zip::ZipArchive::new(Cursor::new(bytes))?.extract(&output)?,
                ArchiveFormat::TarGz => {
                    tar::Archive::new(flate2::read::GzDecoder::new(Cursor::new(bytes)))
                        .unpack(&output)?
                }
            }
            Ok(())
        })
        .await??;
    }
    for pins in backup.pin_sets {
        println!(
            "IPFS: {} protected, {} eligible, {} skipped",
            pins.protected_nft_count, pins.eligible_nft_count, pins.skipped_nft_count
        );
        if pins.state == State::Failed {
            bail!("Pin set failed: {:?}", pins.error);
        }
    }
    Ok(())
}
