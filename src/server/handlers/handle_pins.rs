use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tracing::{debug, error, info};

use crate::server::db::TokenWithPins;
use crate::server::AppState;

pub type PinsResponse = Vec<TokenWithPins>;

/// Get all pinned tokens for the authenticated user
#[utoipa::path(
    get,
    path = "/pins",
    responses(
        (status = 200, description = "List of all pinned tokens for the user. Returns token metadata with IPFS pin information including CIDs, providers, and pin status.", 
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
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "pins"
)]
pub async fn handle_pins(
    State(state): State<AppState>,
    Extension(requestor): Extension<Option<String>>,
) -> impl IntoResponse {
    let requestor = match requestor {
        Some(req) => req,
        None => {
            error!("No requestor found in request extensions");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };

    debug!("Getting all pinned tokens for requestor: {}", requestor);

    match state.db.get_pinned_tokens_by_requestor(&requestor).await {
        Ok(tokens) => {
            info!(
                "Retrieved {} pinned tokens for requestor: {}",
                tokens.len(),
                requestor
            );
            (StatusCode::OK, Json(tokens)).into_response()
        }
        Err(e) => {
            error!(
                "Failed to get pinned tokens for requestor {}: {}",
                requestor, e
            );
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::db::{PinInfo, TokenWithPins};
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
                        status: "pinned".to_string(),
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
    fn test_pins_response_serialization() {
        let tokens = create_test_tokens();
        let response: PinsResponse = tokens.clone();
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: PinsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.len(), 2);
        assert_eq!(deserialized[0].chain, "ethereum");
        assert_eq!(deserialized[0].token_id, "1");
        assert_eq!(deserialized[0].pins.len(), 2);
        assert_eq!(deserialized[0].pins[0].cid, "QmTestHash1");
        assert_eq!(deserialized[0].pins[1].cid, "QmTestHash2");
    }
}
