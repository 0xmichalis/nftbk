use axum::{
    extract::{Extension, Json, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use tracing::info;
use uuid::Uuid;

use crate::server::api::{
    ApiProblem, BackupRequest, ProblemJson, QuoteCreateResponse, QuoteResponse,
};
use crate::server::hashing::compute_task_id;
use crate::server::x402::parse_usdc_price_to_wei;
use crate::server::AppState;

/// Request a quote for creating a backup. Returns a quote_id that can be used to retrieve the quote
/// via GET /v1/backups/quote/{quote_id} once it's ready.
#[utoipa::path(
    post,
    path = "/v1/backups/quote",
    request_body = BackupRequest,
    responses(
        (status = 202, description = "Quote request accepted", body = QuoteCreateResponse),
        (status = 400, description = "Invalid request", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup_quote(
    State(state): State<AppState>,
    Extension(_requestor): Extension<Option<String>>,
    Json(req): Json<BackupRequest>,
) -> axum::response::Response {
    // Validate the request (same validation as backup creation)
    if let Err(msg) =
        crate::server::handlers::handle_backup_create::validate_backup_request(&state, &req)
    {
        let problem = ProblemJson::from_status(
            StatusCode::BAD_REQUEST,
            Some(msg),
            Some("/v1/backups/quote".to_string()),
        );
        return problem.into_response();
    }

    // Generate a unique quote ID
    let quote_id = Uuid::new_v4().to_string();

    // Compute the task_id for this request (same as backup creation)
    let requestor_str = _requestor.as_deref().unwrap_or("");
    let task_id = compute_task_id(&req.tokens, Some(requestor_str));

    // Store the quote in the cache with None price (pending) and task_id for validation
    {
        let mut cache = state.quote_cache.lock().await;
        cache.put(quote_id.clone(), (None, task_id));
    }

    // Get price from x402 config if available, otherwise return error
    // TODO: Implement actual price computation asynchronously.
    let price = if let Some(cfg) = state.x402_config.as_ref() {
        cfg.price.clone()
    } else {
        let problem = ProblemJson::from_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("x402 configuration not available".to_string()),
            Some("/v1/backups/quote".to_string()),
        );
        return problem.into_response();
    };
    {
        let mut cache = state.quote_cache.lock().await;
        if let Some((cached_price, _task_id)) = cache.get_mut(&quote_id) {
            *cached_price = Some(price.clone());
        }
    }

    info!("Created quote {} with price {}", quote_id, price);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        format!("/v1/backups/quote/{}", quote_id).parse().unwrap(),
    );

    (
        StatusCode::ACCEPTED,
        headers,
        Json(QuoteCreateResponse { quote_id }),
    )
        .into_response()
}

/// Get a quote by quote_id. Returns the quote with price if ready, or 202 Accepted if still being computed.
#[utoipa::path(
    get,
    path = "/v1/backups/quote/{quote_id}",
    params(
        ("quote_id" = String, Path, description = "Unique identifier for the quote")
    ),
    responses(
        (status = 200, description = "Quote retrieved successfully with price", body = QuoteResponse),
        (status = 202, description = "Quote request is still being processed", body = QuoteResponse),
        (status = 404, description = "Quote not found", body = ApiProblem, content_type = "application/problem+json"),
    ),
    tag = "backups",
    security(("bearer_auth" = []))
)]
pub async fn handle_backup_quote_get(
    State(state): State<AppState>,
    Path(quote_id): Path<String>,
) -> axum::response::Response {
    let mut cache = state.quote_cache.lock().await;
    if let Some((price, _task_id)) = cache.get(&quote_id) {
        let status = if price.is_some() {
            StatusCode::OK
        } else {
            StatusCode::ACCEPTED
        };
        let (asset_symbol, network, price_decimal) = if let Some(cfg) = state.x402_config.as_ref() {
            let price_decimal = price.as_ref().and_then(|p| {
                parse_usdc_price_to_wei(p)
                    .map(|microdollars| microdollars.to_string())
                    .ok()
            });
            (
                Some(cfg.asset_symbol.clone()),
                Some(cfg.facilitator.network.to_string()),
                price_decimal,
            )
        } else {
            (None, None, None)
        };
        (
            status,
            Json(QuoteResponse {
                quote_id,
                price: price_decimal,
                asset_symbol,
                network,
            }),
        )
            .into_response()
    } else {
        let problem = ProblemJson::from_status(
            StatusCode::NOT_FOUND,
            Some("Quote not found".to_string()),
            Some(format!("/v1/backups/quote/{}", quote_id)),
        );
        problem.into_response()
    }
}

#[cfg(test)]
mod handle_backup_quote_tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::{Request, StatusCode};
    use axum::{routing::get, routing::post, Extension, Router};
    use serde_json::json;
    use std::collections::HashMap;
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use tokio::sync::{mpsc, Mutex};
    use tower::Service;

    use crate::ipfs::IpfsPinningConfig;
    use crate::server::database::Db;
    use crate::server::x402::{X402Config, X402ConfigRaw, X402FacilitatorConfigRaw};
    use crate::server::AppState;

    fn make_state_with_x402(ipfs_pinning_configs: Vec<IpfsPinningConfig>) -> AppState {
        let mut chains = HashMap::new();
        chains.insert("ethereum".to_string(), "rpc://dummy".to_string());
        let chain_config = crate::ChainConfig(chains);
        let (tx, _rx) = mpsc::channel(1);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@localhost/db")
            .unwrap();
        let db = Arc::new(Db { pool });

        let x402_config_raw = X402ConfigRaw {
            asset_symbol: "USDC".to_string(),
            base_url: "http://localhost:8080/".to_string(),
            recipient_address: "0x1234567890123456789012345678901234567890".to_string(),
            max_timeout_seconds: 300,
            price: "0.1".to_string(),
            facilitator: X402FacilitatorConfigRaw {
                url: "https://x402.org/facilitator".to_string(),
                network: "base-sepolia".to_string(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
        };
        let x402_config = X402Config::compile(x402_config_raw).unwrap();

        AppState {
            chain_config: Arc::new(chain_config),
            base_dir: Arc::new("/tmp".to_string()),
            unsafe_skip_checksum_check: true,
            auth_token: None,
            pruner_retention_days: 7,
            download_tokens: Arc::new(Mutex::new(HashMap::new())),
            quote_cache: Arc::new(Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(1000).unwrap(),
            ))),
            backup_task_sender: tx,
            db,
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ipfs_pinning_configs,
            ipfs_pinning_instances: Arc::new(Vec::new()),
            x402_config: Some(x402_config),
        }
    }

    fn make_state_without_x402(ipfs_pinning_configs: Vec<IpfsPinningConfig>) -> AppState {
        let mut chains = HashMap::new();
        chains.insert("ethereum".to_string(), "rpc://dummy".to_string());
        let chain_config = crate::ChainConfig(chains);
        let (tx, _rx) = mpsc::channel(1);
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://user:pass@localhost/db")
            .unwrap();
        let db = Arc::new(Db { pool });
        AppState {
            chain_config: Arc::new(chain_config),
            base_dir: Arc::new("/tmp".to_string()),
            unsafe_skip_checksum_check: true,
            auth_token: None,
            pruner_retention_days: 7,
            download_tokens: Arc::new(Mutex::new(HashMap::new())),
            quote_cache: Arc::new(Mutex::new(lru::LruCache::new(
                NonZeroUsize::new(1000).unwrap(),
            ))),
            backup_task_sender: tx,
            db,
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ipfs_pinning_configs,
            ipfs_pinning_instances: Arc::new(Vec::new()),
            x402_config: None,
        }
    }

    #[tokio::test]
    async fn creates_quote_successfully() {
        let state = make_state_with_x402(Vec::new());
        let mut app = Router::new()
            .route("/quote", post(handle_backup_quote))
            .with_state(state)
            .layer(Extension::<Option<String>>(None));

        let req_body = json!({
            "tokens": [
                {
                    "chain": "ethereum",
                    "tokens": ["0x123:1"]
                }
            ],
            "pin_on_ipfs": false,
            "create_archive": true
        });

        let req = Request::builder()
            .method("POST")
            .uri("/quote")
            .header("content-type", "application/json")
            .body(serde_json::to_string(&req_body).unwrap())
            .unwrap();

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let quote_resp: QuoteCreateResponse = serde_json::from_slice(&body).unwrap();
        assert!(!quote_resp.quote_id.is_empty());
    }

    #[tokio::test]
    async fn returns_500_when_x402_config_missing() {
        let state = make_state_without_x402(Vec::new());
        let mut app = Router::new()
            .route("/quote", post(handle_backup_quote))
            .with_state(state)
            .layer(Extension::<Option<String>>(None));

        let req_body = json!({
            "tokens": [
                {
                    "chain": "ethereum",
                    "tokens": ["0x123:1"]
                }
            ],
            "pin_on_ipfs": false,
            "create_archive": true
        });

        let req = Request::builder()
            .method("POST")
            .uri("/quote")
            .header("content-type", "application/json")
            .body(serde_json::to_string(&req_body).unwrap())
            .unwrap();

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn returns_400_for_invalid_request() {
        let state = make_state_with_x402(Vec::new());
        let mut app = Router::new()
            .route("/quote", post(handle_backup_quote))
            .with_state(state)
            .layer(Extension::<Option<String>>(None));

        let req_body = json!({
            "tokens": [
                {
                    "chain": "unknown_chain",
                    "tokens": ["0x123:1"]
                }
            ],
            "pin_on_ipfs": false,
            "create_archive": true
        });

        let req = Request::builder()
            .method("POST")
            .uri("/quote")
            .header("content-type", "application/json")
            .body(serde_json::to_string(&req_body).unwrap())
            .unwrap();

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn gets_quote_successfully() {
        let state = make_state_with_x402(Vec::new());
        let mut app = Router::new()
            .route("/quote", post(handle_backup_quote))
            .route("/quote/{quote_id}", get(handle_backup_quote_get))
            .with_state(state.clone())
            .layer(Extension::<Option<String>>(None));

        // First create a quote
        let req_body = json!({
            "tokens": [
                {
                    "chain": "ethereum",
                    "tokens": ["0x123:1"]
                }
            ],
            "pin_on_ipfs": false,
            "create_archive": true
        });

        let req = Request::builder()
            .method("POST")
            .uri("/quote")
            .header("content-type", "application/json")
            .body(serde_json::to_string(&req_body).unwrap())
            .unwrap();

        let resp = app.call(req).await.unwrap();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let quote_resp: QuoteCreateResponse = serde_json::from_slice(&body).unwrap();
        let quote_id = quote_resp.quote_id;

        // Now get the quote
        let req = Request::builder()
            .method("GET")
            .uri(format!("/quote/{}", quote_id))
            .body(String::new())
            .unwrap();

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let quote: QuoteResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(quote.quote_id, quote_id);
        assert_eq!(quote.price, Some("100000".to_string()));
        assert_eq!(quote.asset_symbol, Some("USDC".to_string()));
        assert_eq!(quote.network, Some("base-sepolia".to_string()));
    }

    #[tokio::test]
    async fn returns_404_for_nonexistent_quote() {
        let state = make_state_with_x402(Vec::new());
        let mut app = Router::new()
            .route("/quote/{quote_id}", get(handle_backup_quote_get))
            .with_state(state)
            .layer(Extension::<Option<String>>(None));

        let req = Request::builder()
            .method("GET")
            .uri("/quote/nonexistent-id")
            .body(String::new())
            .unwrap();

        let resp = app.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
