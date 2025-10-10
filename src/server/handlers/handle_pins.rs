use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tracing::{debug, error, info};

use crate::server::api::{ApiProblem, ProblemJson};
use crate::server::db::{Db, TokenWithPins};
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
         example = json!([
             {
                 "chain": "ethereum",
                 "contract_address": "0x1234567890123456789012345678901234567890",
                 "token_id": "1",
                 "pins": [
                     {
                         "cid": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
                         "provider": "pinata",
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
    let subject = match requestor {
        Some(req) => req,
        None => {
            error!("No requestor found in request extensions");
            return (
                StatusCode::UNAUTHORIZED,
                ProblemJson::from_status(
                    StatusCode::UNAUTHORIZED,
                    Some("Missing authentication subject".to_string()),
                    Some("/v1/pins".to_string()),
                ),
            )
                .into_response();
        }
    };

    debug!(
        "Getting pinned tokens for requestor: {} with query: {:?}",
        subject, query
    );

    handle_pins_core(&*state.db, &subject, query).await
}

// A minimal trait to enable mocking DB calls for unit tests of this handler
pub trait PinsDb {
    fn get_pinned_tokens_by_requestor<'a>(
        &'a self,
        requestor: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<TokenWithPins>, sqlx::Error>> + Send + 'a>,
    >;
}

impl PinsDb for Db {
    fn get_pinned_tokens_by_requestor<'a>(
        &'a self,
        requestor: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<TokenWithPins>, sqlx::Error>> + Send + 'a>,
    > {
        Box::pin(async move { Db::get_pinned_tokens_by_requestor(self, requestor).await })
    }
}

async fn handle_pins_core<DB: PinsDb + ?Sized>(
    db: &DB,
    subject: &str,
    query: PinsQuery,
) -> axum::response::Response {
    match db.get_pinned_tokens_by_requestor(subject).await {
        Ok(tokens) => {
            let filtered = filter_tokens_for_query(tokens, &query);
            info!(
                "Retrieved {} pinned tokens for requestor: {}",
                filtered.len(),
                subject
            );
            (StatusCode::OK, Json(filtered)).into_response()
        }
        Err(e) => {
            error!(
                "Failed to get pinned tokens for requestor {}: {}",
                subject, e
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
    use crate::server::db::PinInfo;
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
                        provider: "pinata".to_string(),
                        status: "pinned".to_string(),
                        created_at: DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    },
                    PinInfo {
                        cid: "QmTestHash2".to_string(),
                        provider: "web3storage".to_string(),
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
                    provider: "pinata".to_string(),
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
    use super::{handle_pins_core, PinsDb, PinsQuery};
    use crate::server::db::{PinInfo, TokenWithPins};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use chrono::{DateTime, Utc};

    #[derive(Clone, Default)]
    struct MockDb {
        tokens: Vec<TokenWithPins>,
        error: bool,
    }

    impl PinsDb for MockDb {
        fn get_pinned_tokens_by_requestor<'a>(
            &'a self,
            _requestor: &'a str,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<Vec<TokenWithPins>, sqlx::Error>>
                    + Send
                    + 'a,
            >,
        > {
            let tokens = self.tokens.clone();
            let error = self.error;
            Box::pin(async move {
                if error {
                    Err(sqlx::Error::PoolTimedOut)
                } else {
                    Ok(tokens)
                }
            })
        }
    }

    fn create_test_tokens() -> Vec<TokenWithPins> {
        vec![
            TokenWithPins {
                chain: "ethereum".to_string(),
                contract_address: "0x1234567890123456789012345678901234567890".to_string(),
                token_id: "1".to_string(),
                pins: vec![
                    PinInfo {
                        cid: "QmTestHash1".to_string(),
                        provider: "pinata".to_string(),
                        status: "pinned".to_string(),
                        created_at: DateTime::parse_from_rfc3339("2023-01-01T00:00:00Z")
                            .unwrap()
                            .with_timezone(&Utc),
                    },
                    PinInfo {
                        cid: "QmTestHash2".to_string(),
                        provider: "web3storage".to_string(),
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
                    provider: "pinata".to_string(),
                    status: "pinned".to_string(),
                    created_at: DateTime::parse_from_rfc3339("2023-01-02T00:00:00Z")
                        .unwrap()
                        .with_timezone(&Utc),
                }],
            },
        ]
    }

    #[tokio::test]
    async fn returns_200_with_all_tokens_for_subject() {
        let db = MockDb {
            tokens: create_test_tokens(),
            error: false,
        };
        let q = PinsQuery::default();
        let resp = handle_pins_core(&db, "did:privy:subject", q)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn returns_200_and_filters_by_status() {
        let db = MockDb {
            tokens: create_test_tokens(),
            error: false,
        };
        let q = PinsQuery {
            status: Some("pinned".to_string()),
            ..Default::default()
        };
        let resp = handle_pins_core(&db, "did:privy:subject", q)
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn returns_500_on_db_error() {
        let db = MockDb {
            tokens: Vec::new(),
            error: true,
        };
        let q = PinsQuery::default();
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
