use std::sync::Arc;

use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use serde_json::json;
use sha2::{Digest, Sha256};
use x402_axum::layer::{X402Error, X402Paygate};
use x402_rs::facilitator::Facilitator;
use x402_rs::types::{PaymentRequirements, Scheme, SettleRequest};

use crate::server::database::r#trait::{PaymentUpdate, QuoteTerms};
use crate::server::handlers::{problem, ApiError};
use crate::server::model::*;
use crate::server::AppState;

pub fn pricing_version(
    config: Option<&crate::server::x402::X402Config>,
    providers: &ProviderMap,
    retention_days: u64,
) -> String {
    let configuration=config.map(|c|json!({"archive":c.pricing.archive_price_per_gb,"ipfs":c.pricing.pin_price_per_gb,"network":c.facilitator.network.to_string(),"recipient":c.recipient.to_string(),"symbol":c.asset_symbol}));
    format!("{:x}",Sha256::digest(json!({"version":2,"pricing":configuration,"providers":providers.keys().collect::<Vec<_>>(),"retention_days":retention_days}).to_string().as_bytes()))
}

pub fn terms(state: &AppState) -> Result<QuoteTerms, ApiError> {
    let config = state.x402_config.as_ref().ok_or_else(|| {
        problem(
            409,
            "pricing_unavailable",
            "This server does not require payment",
        )
    })?;
    let tag = config
        .usdc_price_tag_for_token_amount(1)
        .map_err(ApiError::internal)?;
    let chain_id = match config.facilitator.network {
        x402_rs::network::Network::Base => "eip155:8453",
        x402_rs::network::Network::BaseSepolia => "eip155:84532",
        _ => {
            return Err(problem(
                500,
                "pricing_unavailable",
                "Unsupported payment network",
            ))
        }
    };
    Ok(QuoteTerms {
        asset_symbol: config.asset_symbol.clone(),
        chain_id: chain_id.into(),
        asset_address: tag.token.address().to_string(),
        asset_decimals: 6,
        pricing_version: state.pricing_version.clone(),
        lifetime_seconds: config.max_timeout_seconds.min(u64::from(u32::MAX)) as u32,
    })
}

pub async fn pay(
    state: &AppState,
    resource: Resource,
    owner: &str,
    id: &str,
    headers: &HeaderMap,
) -> Result<Option<String>, Response> {
    let Some(config) = &state.x402_config else {
        return Ok(None);
    };
    let payment = state
        .db
        .payment(resource, owner, id, None)
        .await
        .map_err(|e| ApiError::from(e).into_response())?
        .ok_or_else(|| {
            problem(500, "payment_missing", "Payment intent is missing").into_response()
        })?;
    let payment_state = payment["state"].as_str().unwrap_or("");
    if payment_state == "paid" {
        return Ok(Some(encode_settlement(&payment["settlement"])));
    }
    if matches!(payment_state, "settling" | "reconciliation_required") {
        return Err(problem(
            409,
            "settlement_pending",
            "Payment settlement is pending reconciliation; do not submit a new payment",
        )
        .into_response());
    }
    let quote_id = payment["quote_id"].as_str().ok_or_else(|| {
        problem(500, "payment_missing", "Quote reference is missing").into_response()
    })?;
    let quote: Quote = serde_json::from_value(
        state
            .db
            .get(Resource::Quote, owner, quote_id)
            .await
            .map_err(|e| ApiError::from(e).into_response())?
            .ok_or_else(|| problem(404, "quote_not_found", "Quote not found").into_response())?,
    )
    .map_err(|e| ApiError::internal(e).into_response())?;
    if quote.state != "ready" {
        return Err(problem(
            409,
            "quote_expired",
            "Quote is no longer payable; request a fresh quote and use a new idempotency key",
        )
        .into_response());
    }
    let amount = quote
        .amount_atomic
        .as_deref()
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| {
            problem(500, "invalid_quote", "Quote amount is unavailable").into_response()
        })?;
    if amount == 0 {
        let settlement = json!({"success":true,"zero_charge":true});
        state
            .db
            .payment(
                resource,
                owner,
                id,
                Some(PaymentUpdate::Settled(settlement.clone())),
            )
            .await
            .map_err(|e| ApiError::from(e).into_response())?;
        return Ok(Some(encode_settlement(&settlement)));
    }
    let tag = config
        .usdc_price_tag_for_token_amount(amount)
        .map_err(|e| ApiError::internal(e).into_response())?;
    let extra = tag
        .token
        .eip712
        .as_ref()
        .map(|e| json!({"name":e.name,"version":e.version}));
    let requirements = PaymentRequirements {
        scheme: Scheme::Exact,
        network: tag.token.network(),
        max_amount_required: tag.amount,
        resource: url::Url::parse(&format!(
            "{}/v2/{}",
            config.base_url.trim_end_matches('/'),
            resource.collection()
        ))
        .map_err(|e| ApiError::internal(e).into_response())?,
        description: "NFT snapshot retention".into(),
        mime_type: "application/json".into(),
        output_schema: None,
        pay_to: tag.pay_to,
        max_timeout_seconds: config.max_timeout_seconds,
        asset: tag.token.address(),
        extra,
    };
    let offers = vec![requirements];
    if !headers.contains_key("x-payment") {
        return Err(X402Error::payment_header_required(offers).into_response());
    }
    let facilitator = Arc::new(
        config
            .facilitator_client()
            .map_err(|e| ApiError::internal(e).into_response())?,
    );
    let gate = X402Paygate {
        facilitator: facilitator.clone(),
        payment_requirements: Arc::new(offers.clone()),
        settle_before_execution: true,
    };
    let payload = gate
        .extract_payment_payload(headers)
        .await
        .map_err(IntoResponse::into_response)?;
    let verified = gate
        .verify_payment(payload)
        .await
        .map_err(IntoResponse::into_response)?;
    let settle = SettleRequest {
        x402_version: verified.x402_version,
        payment_payload: verified.payment_payload,
        payment_requirements: verified.payment_requirements,
    };
    let encoded = serde_json::to_vec(&settle.payment_payload)
        .map_err(|e| ApiError::internal(e).into_response())?;
    let proof_hash = format!("{:x}", Sha256::digest(encoded));
    state
        .db
        .payment(
            resource,
            owner,
            id,
            Some(PaymentUpdate::Begin {
                proof_hash,
                settle_request: json!(settle),
            }),
        )
        .await
        .map_err(|e| ApiError::from(e).into_response())?;
    match facilitator.settle(&settle).await {
        Ok(reply) if reply.success => {
            let settlement = json!(reply);
            state
                .db
                .payment(
                    resource,
                    owner,
                    id,
                    Some(PaymentUpdate::Settled(settlement.clone())),
                )
                .await
                .map_err(|e| ApiError::from(e).into_response())?;
            Ok(Some(encode_settlement(&settlement)))
        }
        Ok(reply) => {
            state
                .db
                .payment(
                    resource,
                    owner,
                    id,
                    Some(PaymentUpdate::Failed {
                        detail: "Facilitator rejected settlement".into(),
                        ambiguous: false,
                    }),
                )
                .await
                .map_err(|e| ApiError::from(e).into_response())?;
            Err(
                X402Error::settlement_failed(format!("{:?}", reply.error_reason), offers)
                    .into_response(),
            )
        }
        Err(_) => {
            state
                .db
                .payment(
                    resource,
                    owner,
                    id,
                    Some(PaymentUpdate::Failed {
                        detail: "Facilitator response was interrupted".into(),
                        ambiguous: true,
                    }),
                )
                .await
                .map_err(|e| ApiError::from(e).into_response())?;
            Err(problem(
                503,
                "settlement_unknown",
                "Payment outcome requires reconciliation; do not submit another payment",
            )
            .into_response())
        }
    }
}
fn encode_settlement(value: &Document) -> String {
    base64::engine::general_purpose::STANDARD.encode(value.to_string())
}

#[cfg(test)]
mod pay_tests {
    use std::sync::{Arc, Mutex};

    use axum::body::to_bytes;
    use chrono::Utc;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    use crate::server::database::mock::{state, MockDatabase, OWNER};
    use crate::server::x402::{PricingRaw, X402Config, X402ConfigRaw, X402FacilitatorConfigRaw};

    fn config(url: &str) -> X402Config {
        X402Config::compile(X402ConfigRaw {
            asset_symbol: "USDC".into(),
            base_url: "https://nftbk.example".into(),
            recipient_address: "0x0000000000000000000000000000000000000002".into(),
            max_timeout_seconds: 300,
            facilitator: X402FacilitatorConfigRaw {
                url: url.into(),
                network: "eip155:84532".into(),
                api_key_id_env: None,
                api_key_secret_env: None,
            },
            pricing: PricingRaw {
                archive_price_per_gb: Some("0.1".into()),
                pin_price_per_gb: None,
            },
        })
        .unwrap()
    }
    fn quote() -> Document {
        json!({"id":OWNER,"state":"ready","amount_atomic":"123","asset_symbol":"USDC","chain_id":"eip155:84532","asset_address":"0xasset","asset_decimals":6,"estimated_size_bytes":100,"expires_at":Utc::now()+chrono::Duration::minutes(5),"pricing_version":"test","operation_id":null,"error":null})
    }
    #[tokio::test]
    async fn challenges_without_calling_the_facilitator_or_starting_settlement() {
        let server = MockServer::start().await;
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(MockDatabase {
            document: Some(quote()),
            payment: Mutex::new(Some(json!({"state":"pending","quote_id":OWNER}))),
            ..Default::default()
        });
        let mut state = state(db.clone(), directory.path());
        state.x402_config = Some(config(&server.uri()));
        let response = pay(&state, Resource::Backup, OWNER, OWNER, &HeaderMap::new())
            .await
            .unwrap_err();
        assert_eq!(response.status(), 402);
        let body: Document =
            serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(body["accepts"][0]["maxAmountRequired"], "123");
        assert_eq!(body["accepts"][0]["network"], "base-sepolia");
        assert_eq!(server.received_requests().await.unwrap().len(), 0);
        assert_eq!(db.payment_updates.lock().unwrap().len(), 0);
    }
    #[tokio::test]
    async fn settles_only_after_recording_intent_and_preserves_an_uncertain_outcome() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/supported"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"kinds":[{"network":"base-sepolia","scheme":"exact","x402Version":1}]}),
            ))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"isValid":true,"payer":"0x0000000000000000000000000000000000000001"}),
            ))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/settle"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&server)
            .await;
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(MockDatabase {
            document: Some(quote()),
            payment: Mutex::new(Some(json!({"state":"pending","quote_id":OWNER}))),
            ..Default::default()
        });
        let mut state = state(db.clone(), directory.path());
        state.x402_config = Some(config(&server.uri()));
        let payload = json!({"x402Version":1,"scheme":"exact","network":"base-sepolia","payload":{"signature":format!("0x{}","11".repeat(65)),"authorization":{"from":"0x0000000000000000000000000000000000000001","to":"0x0000000000000000000000000000000000000002","value":"123","validAfter":"0","validBefore":"9999999999","nonce":format!("0x{}","22".repeat(32))}}});
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-payment",
            base64::engine::general_purpose::STANDARD
                .encode(payload.to_string())
                .parse()
                .unwrap(),
        );
        let response = pay(&state, Resource::Backup, OWNER, OWNER, &headers)
            .await
            .unwrap_err();
        assert_eq!(response.status(), 503);
        {
            let updates = db.payment_updates.lock().unwrap();
            assert_eq!(updates.len(), 2);
            assert!(
                matches!(&updates[0],PaymentUpdate::Begin {proof_hash,settle_request} if proof_hash.len()==64 && settle_request["paymentPayload"]==payload)
            );
            assert!(matches!(
                updates[1],
                PaymentUpdate::Failed {
                    ambiguous: true,
                    ..
                }
            ));
        }
        *db.payment.lock().unwrap() =
            Some(json!({"state":"reconciliation_required","quote_id":OWNER}));
        assert_eq!(
            pay(&state, Resource::Backup, OWNER, OWNER, &headers)
                .await
                .unwrap_err()
                .status(),
            409
        );
        assert_eq!(db.payment_updates.lock().unwrap().len(), 2);
    }
}
