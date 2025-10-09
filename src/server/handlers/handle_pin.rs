use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tracing::{debug, error, info};

use crate::server::db::TokenWithPins;
use crate::server::AppState;

pub type PinResponse = Option<TokenWithPins>;

/// Get a specific pinned token for the authenticated user
#[utoipa::path(
    get,
    path = "/pin/{chain}/{contract_address}/{token_id}",
    responses(
        (status = 200, description = "All pinned tokens for the specified token", body = PinResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    params(
        ("chain" = String, Path, description = "Blockchain identifier (e.g., ethereum, tezos)"),
        ("contract_address" = String, Path, description = "NFT contract address"),
        ("token_id" = String, Path, description = "NFT token ID")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "pins"
)]
pub async fn handle_pin(
    State(state): State<AppState>,
    Extension(requestor): Extension<Option<String>>,
    Path((chain, contract_address, token_id)): Path<(String, String, String)>,
) -> impl IntoResponse {
    let requestor = match requestor {
        Some(req) => req,
        None => {
            error!("No requestor found in request extensions");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };

    debug!(
        "Getting pinned token for requestor: {}, chain: {}, contract: {}, token_id: {}",
        requestor, chain, contract_address, token_id
    );

    match state
        .db
        .get_pinned_token_by_requestor(&requestor, &chain, &contract_address, &token_id)
        .await
    {
        Ok(token) => {
            if let Some(token) = token {
                info!(
                    "Retrieved token with {} pins for requestor: {}, chain: {}, contract: {}, token_id: {}",
                    token.pins.len(), requestor, chain, contract_address, token_id
                );
                (StatusCode::OK, Json(Some(token))).into_response()
            } else {
                info!(
                    "No pinned token found for requestor: {}, chain: {}, contract: {}, token_id: {}",
                    requestor, chain, contract_address, token_id
                );
                (StatusCode::OK, Json(None::<TokenWithPins>)).into_response()
            }
        }
        Err(e) => {
            error!(
                "Failed to get pinned token for requestor: {}, chain: {}, contract: {}, token_id: {}: {}",
                requestor, chain, contract_address, token_id, e
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

    fn create_test_token() -> TokenWithPins {
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
        }
    }

    #[test]
    fn test_pin_response_serialization() {
        let token = create_test_token();
        let response: PinResponse = Some(token.clone());
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: PinResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_some());
        let retrieved_token = deserialized.unwrap();
        assert_eq!(retrieved_token.chain, "ethereum");
        assert_eq!(retrieved_token.token_id, "1");
        assert_eq!(retrieved_token.pins.len(), 2);
        assert_eq!(retrieved_token.pins[0].cid, "QmTestHash1");
        assert_eq!(retrieved_token.pins[1].cid, "QmTestHash2");
    }

    #[test]
    fn test_pin_response_no_token() {
        let response: PinResponse = None;
        let json = serde_json::to_string(&response).unwrap();
        let deserialized: PinResponse = serde_json::from_str(&json).unwrap();
        assert!(deserialized.is_none());
    }
}
