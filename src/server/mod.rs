use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tracing::info;

use crate::ipfs::IpfsPinningConfig;
use crate::server::auth::jwt::JwtCredential;
use crate::server::database::r#trait::Database;
use crate::server::database::Db;
use crate::server::model::ProviderMap;
use crate::server::storage::BlobStore;
use crate::server::x402::X402Config;
use crate::types::ChainConfig;

pub mod api;
pub mod archive;
pub mod auth;
pub mod billing;
pub mod config;
pub mod database;
pub mod handlers;
pub mod hashing;
pub use crate::model;
pub mod router;
pub mod snapshot;
pub mod storage;
pub mod workers;
pub mod x402;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn Database>,
    pub chain_config: Arc<ChainConfig>,
    pub storage: BlobStore,
    pub providers: Arc<ProviderMap>,
    pub jwt_credentials: Arc<Vec<JwtCredential>>,
    pub auth_token: Option<String>,
    pub download_key: Arc<[u8; 32]>,
    pub shutdown_flag: Arc<AtomicBool>,
    pub x402_config: Option<X402Config>,
    pub retention_days: u32,
    pub max_content_request_retries: u32,
    pub unsafe_skip_checksum_check: bool,
    pub pricing_version: String,
}

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen_address: String,
    pub base_dir: String,
    pub unsafe_skip_checksum_check: bool,
    pub auth_token: Option<String>,
    pub pruner_retention_days: u64,
    pub pin_monitor_interval_seconds: u64,
    pub backup_parallelism: usize,
    pub backup_queue_size: usize,
    pub chain_config: ChainConfig,
    pub jwt_credentials: Vec<JwtCredential>,
    pub x402_config: Option<X402Config>,
    pub ipfs_pinning_configs: Vec<IpfsPinningConfig>,
    pub max_content_request_retries: u32,
}

pub async fn run_server(config: ServerConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.backup_parallelism > 0,
        "At least one worker is required"
    );
    anyhow::ensure!(
        (1..=365).contains(&config.pruner_retention_days),
        "Retention must be between 1 and 365 days"
    );
    let database_url = std::env::var("DATABASE_URL")?;
    let db = Db::new(
        &database_url,
        (config.backup_parallelism.saturating_mul(2) + 4).min(64) as u32,
    )
    .await?
    .configure(
        config.backup_queue_size,
        config.pin_monitor_interval_seconds,
    );
    let issuers: BTreeSet<&str> = config
        .jwt_credentials
        .iter()
        .map(|c| c.issuer.as_str())
        .collect();
    if issuers.len() == 1 {
        db.adopt_legacy_issuer(issuers.first().expect("one issuer"))
            .await?;
    }
    let mut providers = ProviderMap::new();
    for provider in &config.ipfs_pinning_configs {
        let (reference, key) = match provider {
            IpfsPinningConfig::IpfsPinningService {
                base_url,
                bearer_token_env,
            }
            | IpfsPinningConfig::Pinata {
                base_url,
                bearer_token_env,
            } => (
                bearer_token_env.as_deref(),
                format!(
                    "{}\0{}\0{}",
                    provider.provider_type(),
                    base_url,
                    bearer_token_env.as_deref().unwrap_or("")
                ),
            ),
        };
        let identity = format!("{:x}", Sha256::digest(key.as_bytes()));
        let unique_url = config
            .ipfs_pinning_configs
            .iter()
            .filter(|p| {
                p.base_url() == provider.base_url() && p.provider_type() == provider.provider_type()
            })
            .count()
            == 1;
        let id = db
            .register_provider(
                &identity,
                provider.provider_type(),
                provider.base_url(),
                reference,
                unique_url,
            )
            .await?;
        providers.insert(id, Arc::from(provider.create_provider()?));
    }
    let download_key: [u8; 32] = db
        .signing_key()
        .await?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Invalid download signing key"))?;
    let pricing_version = billing::pricing_version(
        config.x402_config.as_ref(),
        &providers,
        config.pruner_retention_days,
    );
    let state = AppState {
        db: Arc::new(db),
        chain_config: Arc::new(config.chain_config),
        storage: BlobStore::new(&config.base_dir),
        providers: Arc::new(providers),
        jwt_credentials: Arc::new(config.jwt_credentials),
        auth_token: config.auth_token,
        download_key: Arc::new(download_key),
        shutdown_flag: Arc::new(AtomicBool::new(false)),
        x402_config: config.x402_config,
        retention_days: config.pruner_retention_days as u32,
        max_content_request_retries: config.max_content_request_retries,
        unsafe_skip_checksum_check: config.unsafe_skip_checksum_check,
        pricing_version,
    };
    let workers = workers::spawn_workers(config.backup_parallelism, state.clone());
    let maintenance = workers::spawn_maintenance(state.clone());
    let listener = tokio::net::TcpListener::bind(&config.listen_address).await?;
    info!(address=%config.listen_address,version=env!("CARGO_PKG_VERSION"),"Serving nftbk API v2");
    let shutdown = state.shutdown_flag.clone();
    let app = router::build_router(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("SIGTERM handler");
            tokio::select! {_ = tokio::signal::ctrl_c()=>{},_=sigterm.recv()=>{}}
            shutdown.store(true, Ordering::SeqCst);
        })
        .await?;
    for worker in workers {
        worker.await?;
    }
    maintenance.await?;
    Ok(())
}
