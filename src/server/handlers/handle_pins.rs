use axum::{
    extract::{Extension, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use tracing::{debug, error, info};

use crate::server::api::{ApiProblem, ProblemJson};
use crate::server::database::r#trait::Database;
use crate::server::database::TokenWithPins;
use crate::server::AppState;

pub type PinsResponse = Vec<TokenWithPins>;

#[derive(serde::Deserialize, utoipa::IntoParams, Debug, Clone, Default)]
#[into_params(parameter_in = Query)]
pub struct PinsQuery {
    /// E.g. "ethereum"
    pub chain: Option<String>,
    /// Contract address (checksum or lowercase)
    pub contract_address: Option<String>,
    /// Token id as string
    pub token_id: Option<String>,
    /// Filter by pin status (e.g. pinned, pinning)
    pub status: Option<String>,
    /// Page number starting at 1
    #[serde(default = "default_page")]
    pub page: u32,
    /// Items per page (max 100)
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_page() -> u32 {
    1
}
fn default_limit() -> u32 {
    50
}

fn filter_tokens_for_query(tokens: Vec<TokenWithPins>, q: &PinsQuery) -> Vec<TokenWithPins> {
    let mut filtered: Vec<TokenWithPins> = tokens
        .into_iter()
        .filter(|t| match (&q.chain, &q.contract_address, &q.token_id) {
            (Some(chain), Some(contract), Some(token_id)) => {
                t.chain.eq_ignore_ascii_case(chain)
                    && t.contract_address.eq_ignore_ascii_case(contract)
                    && t.token_id == *token_id
            }
            (Some(chain), Some(contract), None) => {
                t.chain.eq_ignore_ascii_case(chain)
                    && t.contract_address.eq_ignore_ascii_case(contract)
            }
            (Some(chain), None, None) => t.chain.eq_ignore_ascii_case(chain),
            _ => true,
        })
        .collect();

    if q.status.is_some() {
        for token in &mut filtered {
            token.pins.retain(|p| {
                let status_ok = q
                    .status
                    .as_ref()
                    .map(|s| p.status.eq_ignore_ascii_case(s))
                    .unwrap_or(true);
                status_ok
            });
        }
        // Remove tokens that ended up with no pins after filtering by pin-level criteria
        filtered.retain(|t| !t.pins.is_empty());
    }

    filtered
}

/// Get all IPFS pin requests for the tokens and the authenticated user
#[utoipa::path(
    get,
    path = "/v1/pins",
    params(PinsQuery),
    responses(
        (status = 200, description = "List pinned tokens for the authenticated user. Supports filters by NFT info and pin status.", 
         body = PinsResponse,
         headers(
             ("Link" = String, description = "Pagination links per RFC 5988: rel=prev,next"),
             ("X-Total-Count" = u32, description = "Total number of items before pagination")
         ),
         example = json!([
             {
                 "chain": "ethereum",
                 "contract_address": "0x1234567890123456789012345678901234567890",
                 "token_id": "1",
                 "pins": [
                     {
                         "cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
                         "provider_type": "pinata",
                         "provider_url": "https://api.pinata.cloud",
                         "status": "pinned",
                         "created_at": "2024-01-01T00:00:00Z"
                     }
                 ]
             }
         ])
        ),
        (status = 401, description = "Unauthorized", body = ApiProblem, content_type = "application/problem+json"),
        (status = 500, description = "Internal server error", body = ApiProblem, content_type = "application/problem+json")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "pins"
)]
pub async fn handle_pins(
    State(state): State<AppState>,
    Extension(requestor): Extension<Option<String>>,
    Query(query): Query<PinsQuery>,
) -> impl IntoResponse {
    let requestor = match requestor {
        Some(req) => req,
        None => {
            error!("No requestor found in request extensions");
            return (
                StatusCode::UNAUTHORIZED,
                ProblemJson::from_status(
                    StatusCode::UNAUTHORIZED,
                    Some("Missing requestor".to_string()),
                    Some("/v1/pins".to_string()),
                ),
            )
                .into_response();
        }
    };

    debug!(
        "Getting pinned tokens for requestor: {} with query: {:?}",
        requestor, query
    );

    handle_pins_core(&*state.db, &requestor, query).await
}

async fn handle_pins_core<DB: Database + ?Sized>(
    db: &DB,
    requestor: &str,
    query: PinsQuery,
) -> axum::response::Response {
    let limit = query.limit.clamp(1, 100);
    let page = query.page.max(1);
    let offset = ((page - 1) * limit) as i64;
    match db
        .get_pinned_tokens_by_requestor(requestor, limit as i64, offset)
        .await
    {
        Ok((tokens, total)) => {
            let filtered = filter_tokens_for_query(tokens, &query);
            let mut headers = HeaderMap::new();
            headers.insert("X-Total-Count", total.to_string().parse().unwrap());
            let mut links: Vec<String> = Vec::new();
            let last_page = total.div_ceil(limit).max(1);
            if page > 1 {
                links.push(format!(
                    "</v1/pins?page={}&limit={}>; rel=\"prev\"",
                    page - 1,
                    limit
                ));
            }
            if page < last_page {
                links.push(format!(
                    "</v1/pins?page={}&limit={}>; rel=\"next\"",
                    page + 1,
                    limit
                ));
            }
            if !links.is_empty() {
                headers.insert("Link", links.join(", ").parse().unwrap());
            }
            info!(
                "Retrieved {} pinned tokens for requestor: {} (page {}, limit {})",
                filtered.len(),
                requestor,
                page,
                limit
            );
            (StatusCode::OK, headers, Json(filtered)).into_response()
        }
        Err(e) => {
            error!(
                "Failed to get pinned tokens for requestor {}: {}",
                requestor, e
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                ProblemJson::from_status(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Some("Failed to get pinned tokens".to_string()),
                    Some("/v1/pins".to_string()),
                ),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod filter_tokens_for_query_tests {
    use super::*;
    use crate::server::database::PinInfo;
    use chrono::{DateTime, Utc};

    fn create_test_tokens() -> Vec<TokenWithPins> {
        vec![
            TokenWithPins {
                chain: "ethereum".to_string(),
                contract_address: "0x1234567890123456789012345678901234567890".to_string(),
                token_id: "1".to_string(),
                pins: vec![
                    PinInfo {
                        cid: "QmTestHash1".to_string(),
                        provider_type: "pinata".to_string(),
                        provider_url: "https://api.pinata.cloud".to_string(),
                        status: "pinned".to_string(),
                        created_at: DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    },
                    PinInfo {
                        cid: "QmTestHash2".to_string(),
                        provider_type: "web3storage".to_string(),
                        provider_url: "https://api.web3.storage".to_string(),
                        status: "pinning".to_string(),
                        created_at: DateTime::parse_from_rfc3339("2023-01-01T01:00:00Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    },
                ],
            },
            TokenWithPins {
                chain: "ethereum".to_string(),
                contract_address: "0x1234567890123456789012345678901234567890".to_string(),
                token_id: "2".to_string(),
                pins: vec![PinInfo {
                    cid: "QmTestHash3".to_string(),
                    provider_type: "pinata".to_string(),
                    provider_url: "https://api.pinata.cloud".to_string(),
                    status: "pinned".to_string(),
                    created_at: DateTime::parse_from_rfc3339("2023-01-02T00:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                }],
            },
        ]
    }

    #[test]
    fn filters_by_chain_contract_token() {
        let tokens = create_test_tokens();
        let q = PinsQuery {
            chain: Some("ethereum".to_string()),
            contract_address: Some("0x1234567890123456789012345678901234567890".to_string()),
            token_id: Some("1".to_string()),
            ..Default::default()
        };
        let filtered = filter_tokens_for_query(tokens, &q);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].token_id, "1");
    }

    #[test]
    fn filters_by_status() {
        let tokens = create_test_tokens();
        let q = PinsQuery {
            status: Some("pinned".to_string()),
            ..Default::default()
        };
        let filtered = filter_tokens_for_query(tokens, &q);
        // token 1 retains only pinned entries (1 pin), token 2 is pinned (1 pin)
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].pins.len(), 1);
        assert_eq!(filtered[1].pins.len(), 1);
    }

    #[test]
    fn removes_tokens_without_matching_pins() {
        let tokens = create_test_tokens();
        let q = PinsQuery {
            status: Some("pinning".to_string()),
            ..Default::default()
        };
        let filtered = filter_tokens_for_query(tokens, &q);
        // token 1 has a pinning entry; token 2 is pinned only and gets removed
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].token_id, "1");
    }
}

#[cfg(test)]
mod handle_pins_core_mockdb_tests {
    use super::{handle_pins_core, PinsQuery};
    use crate::server::database::r#trait::MockDatabase;
    use crate::server::database::{PinInfo, TokenWithPins};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use chrono::{DateTime, Utc};

    fn create_test_tokens() -> Vec<TokenWithPins> {
        vec![
            TokenWithPins {
                chain: "ethereum".to_string(),
                contract_address: "0x1234567890123456789012345678901234567890".to_string(),
                token_id: "1".to_string(),
                pins: vec![
                    PinInfo {
                        cid: "QmTestHash1".to_string(),
                        provider_type: "pinata".to_string(),
                        provider_url: "https://api.pinata.cloud".to_string(),
                        status: "pinned".to_string(),
                        created_at: DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    },
                    PinInfo {
                        cid: "QmTestHash2".to_string(),
                        provider_type: "web3storage".to_string(),
                        provider_url: "https://api.web3.storage".to_string(),
                        status: "pinning".to_string(),
                        created_at: DateTime::parse_from_rfc3339("2023-01-01T01:00:00Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    },
                ],
            },
            TokenWithPins {
                chain: "ethereum".to_string(),
                contract_address: "0x1234567890123456789012345678901234567890".to_string(),
                token_id: "2".to_string(),
                pins: vec![PinInfo {
                    cid: "QmTestHash3".to_string(),
                    provider_type: "pinata".to_string(),
                    provider_url: "https://api.pinata.cloud".to_string(),
                    status: "pinned".to_string(),
                    created_at: DateTime::parse_from_rfc3339("2023-01-02T00:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                }],
            },
        ]
    }

    #[tokio::test]
    async fn returns_200_with_all_tokens_for_requestor() {
        let mut db = MockDatabase::default();
        let tokens = create_test_tokens();
        db.set_get_pinned_tokens_by_requestor_result((tokens, 2));
        let q = PinsQuery {
            page: 1,
            limit: 50,
            ..Default::default()
        };
        let resp = handle_pins_core(&db, "did:privy:subject", q)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn returns_200_and_filters_by_status() {
        let mut db = MockDatabase::default();
        let tokens = create_test_tokens();
        db.set_get_pinned_tokens_by_requestor_result((tokens, 2));
        let q = PinsQuery {
            status: Some("pinned".to_string()),
            page: 1,
            limit: 50,
            ..Default::default()
        };
        let resp = handle_pins_core(&db, "did:privy:subject", q)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let mut db = MockDatabase::default();
        db.set_get_pinned_tokens_by_requestor_error(Some("Database error".to_string()));
        let q = PinsQuery {
            page: 1,
            limit: 50,
            ..Default::default()
        };
        let resp = handle_pins_core(&db, "did:privy:subject", q)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        // Parse problem+json
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let problem: crate::server::api::ApiProblem = serde_json::from_slice(&body).unwrap();
        assert_eq!(problem.status, StatusCode::INTERNAL_SERVER_ERROR.as_u16());
    }
}

#[cfg(test)]
mod handle_pins_endpoint_tests {
    use super::handle_pins;
    use axum::http::StatusCode;
    use axum::{routing::get, Extension, Router};
    use hyper::Request;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tower::Service;

    use crate::ipfs::IpfsPinningConfig;
    use crate::server::database::Db;
    use crate::server::AppState;

    fn make_state(ipfs_pinning_configs: Vec<IpfsPinningConfig>) -> AppState {
        let mut chains = HashMap::new();
        chains.insert("ethereum".to_string(), "rpc://dummy".to_string());
        let chain_config = crate::backup::ChainConfig(chains);
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
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
            backup_task_sender: tx,
            db,
            shutdown_flag: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            ipfs_pinning_configs,
            ipfs_pinning_instances: Arc::new(Vec::new()),
        }
    }

    #[tokio::test]
    async fn returns_401_when_missing_requestor() {
        let state = make_state(Vec::new());
        let app = Router::new()
            .route("/pins", get(handle_pins))
            .with_state(state)
            .layer(Extension::<Option<String>>(None));

        let request = Request::builder()
            .method("GET")
            .uri("/pins")
            .body(axum::body::Body::empty())
            .unwrap();

        let mut app = app;
        let response = app.call(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
