use axum::extract::{Request, State};
use axum::http::{header, HeaderMap};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use subtle::ConstantTimeEq;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::server::api::ApiProblem;
use crate::server::auth::jwt::verify_jwt;
use crate::server::handlers::*;
use crate::server::model::*;
use crate::server::AppState;

#[derive(OpenApi)]
#[openapi(
    paths(create_backup,list_backups,get_backup,delete_backup,list_items,get_item,manifest,
        create_archive,list_archives,get_archive,delete_archive,download_link,content,
        create_pin_set,list_pin_sets,get_pin_set,delete_pin_set,list_pins,get_pin,
        create_quote,list_quotes,get_quote,list_operations,get_operation,attempts,get_attempt,retry),
    components(schemas(Nft,Specification,CreateBackup,CreateArchive,CreatePinSet,QuoteRequest,QuoteOutput,OutputRequest,Backup,Archive,PinSet,Pin,Item,Asset,Manifest,Quote,Operation,Attempt,Failure,ApiProblem)),
    info(title="nftbk API",version="2.0.0",description="Immutable NFT snapshots, independent archives and IPFS retention, and durable operations."),
    modifiers(&Security)
)]
pub struct ApiDoc;
struct Security;
impl utoipa::Modify for Security {
    fn modify(&self, api: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = &mut api.components {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .build(),
                ),
            );
        }
    }
}

pub async fn authenticate(state: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok());
    let principal = if state.auth_token.is_none() && state.jwt_credentials.is_empty() {
        Principal {
            issuer: "nftbk:local".into(),
            subject: "local".into(),
        }
    } else if state.auth_token.as_ref().is_some_and(|token| {
        authorization.is_some_and(|header| {
            bool::from(
                header
                    .as_bytes()
                    .ct_eq(format!("Bearer {token}").as_bytes()),
            )
        })
    }) {
        Principal {
            issuer: "nftbk:local".into(),
            subject: "admin".into(),
        }
    } else {
        let jwt = authorization
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or_else(|| problem(401, "unauthorized", "Bearer authentication is required"))?;
        let mut principal = None;
        for credential in state.jwt_credentials.iter() {
            if let Ok(claims) = verify_jwt(
                jwt,
                &credential.verification_key,
                &credential.issuer,
                &credential.audience,
            )
            .await
            {
                if !claims.sub.is_empty() {
                    principal = Some(Principal {
                        issuer: claims.iss,
                        subject: claims.sub,
                    });
                    break;
                }
            }
        }
        principal.ok_or_else(|| problem(401, "unauthorized", "Bearer authentication failed"))?
    };
    Ok(state.db.owner(&principal).await?)
}
async fn auth(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    match authenticate(&state, request.headers()).await {
        Ok(owner) => {
            request.extensions_mut().insert(owner);
            next.run(request).await
        }
        Err(error) => error.into_response(),
    }
}

pub fn build_router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/v2/backups", get(list_backups).post(create_backup))
        .route("/v2/backups/{id}", get(get_backup).delete(delete_backup))
        .route("/v2/backups/{id}/items", get(list_items))
        .route("/v2/backups/{id}/items/{item_id}", get(get_item))
        .route("/v2/backups/{id}/manifest", get(manifest))
        .route("/v2/archives", get(list_archives).post(create_archive))
        .route("/v2/archives/{id}", get(get_archive).delete(delete_archive))
        .route("/v2/archives/{id}/download-links", post(download_link))
        .route("/v2/pin-sets", get(list_pin_sets).post(create_pin_set))
        .route("/v2/pin-sets/{id}", get(get_pin_set).delete(delete_pin_set))
        .route("/v2/pins", get(list_pins))
        .route("/v2/pins/{id}", get(get_pin))
        .route("/v2/quotes", get(list_quotes).post(create_quote))
        .route("/v2/quotes/{id}", get(get_quote))
        .route("/v2/operations", get(list_operations))
        .route("/v2/operations/{id}", get(get_operation))
        .route("/v2/operations/{id}/attempts", get(attempts).post(retry))
        .route("/v2/operations/{id}/attempts/{number}", get(get_attempt))
        .layer(middleware::from_fn_with_state(state.clone(), auth));
    protected
        .route("/v2/archives/{id}/content", get(content))
        .merge(SwaggerUi::new("/v2/swagger-ui").url("/v2/openapi.json", ApiDoc::openapi()))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
}

#[cfg(test)]
mod build_router_tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{Method, Request, StatusCode};
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::server::database::mock::{state, MockDatabase, OWNER};
    use crate::server::database::r#trait::Creation;

    #[tokio::test]
    async fn normalizes_the_creation_contract_and_returns_a_resource_location() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(MockDatabase {
            document: Some(json!({"id":OWNER})),
            ..Default::default()
        });
        let mut state = state(db.clone(), directory.path());
        Arc::make_mut(&mut state.chain_config)
            .0
            .insert("eip155:1".into(), "https://rpc.example".into());
        let app = build_router(state);
        let response = app.oneshot(Request::builder().method(Method::POST).uri("/v2/backups").header("content-type","application/json").header("idempotency-key","request-1").body(Body::from(json!({"nfts":[{"chain_id":"eip155:1","contract_address":"0x00000000000000000000000000000000000000AB","token_id":"00042"}],"outputs":[{"type":"archive","format":"zip"}]}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            response.headers()[header::LOCATION],
            format!("/v2/backups/{OWNER}")
        );
        let creates = db.creates.lock().unwrap();
        assert_eq!(creates.len(), 1);
        assert_eq!(creates[0].key, "request-1");
        assert_eq!(creates[0].owner_id, OWNER);
        let Creation::Backup { specification, .. } = &creates[0].creation else {
            panic!("Wrong creation")
        };
        assert_eq!(specification.nfts[0].token_id, "42");
        assert_eq!(
            specification.nfts[0].contract_address,
            "0x00000000000000000000000000000000000000ab"
        );
        assert_eq!(
            specification.outputs,
            vec![OutputRequest::Archive {
                format: ArchiveFormat::Zip,
                retention_days: Some(3)
            }]
        );
    }

    #[tokio::test]
    async fn rejects_invalid_requests_and_returns_problem_details_for_routing_errors() {
        let directory = tempfile::tempdir().unwrap();
        let app = build_router(state(Arc::new(MockDatabase::default()), directory.path()));
        for (method, path, body, status) in [
            (Method::POST, "/v2/backups", "{", StatusCode::BAD_REQUEST),
            (
                Method::POST,
                "/v2/backups",
                r#"{"tokens":[],"force":true}"#,
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                Method::GET,
                "/v2/backups?limit=101",
                "",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                Method::GET,
                "/v2/backups?page=1",
                "",
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                "/v2/backups/not-an-id",
                "",
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::GET,
                "/v2/backups/11111111-1111-4111-8111-111111111111",
                "",
                StatusCode::NOT_FOUND,
            ),
            (
                Method::PUT,
                "/v2/backups",
                "{}",
                StatusCode::METHOD_NOT_ALLOWED,
            ),
            (Method::GET, "/v1/backups", "", StatusCode::NOT_FOUND),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status, "{path}");
            assert_eq!(
                response.headers()[header::CONTENT_TYPE],
                "application/problem+json"
            );
            let problem: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap())
                    .unwrap();
            assert_eq!(problem["status"], status.as_u16());
            assert!(problem["type"]
                .as_str()
                .unwrap()
                .starts_with("urn:nftbk:problem:"));
        }
    }

    #[tokio::test]
    async fn exposes_item_and_pin_self_links_at_readable_uris() {
        let directory = tempfile::tempdir().unwrap();
        let db = Arc::new(MockDatabase {
            document: Some(json!({"id":OWNER,"backup_id":OWNER})),
            ..Default::default()
        });
        let app = build_router(state(db, directory.path()));
        for uri in [
            format!("/v2/backups/{OWNER}/items/{OWNER}"),
            format!("/v2/pins/{OWNER}"),
        ] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(&uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap())
                    .unwrap();
            assert_eq!(body["links"]["self"], uri);
        }
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!(
                        "/v2/backups/22222222-2222-4222-8222-222222222222/items/{OWNER}"
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn requires_authentication_before_owner_scoped_reads() {
        let directory = tempfile::tempdir().unwrap();
        let mut state = state(Arc::new(MockDatabase::default()), directory.path());
        state.auth_token = Some("a-private-token".into());
        let response = build_router(state)
            .oneshot(
                Request::builder()
                    .uri("/v2/backups")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(response.headers()[header::WWW_AUTHENTICATE], "Bearer");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}

#[cfg(test)]
mod openapi_tests {
    use super::*;
    use serde_json::Value;

    fn check_refs(value: &Value, root: &Value) {
        if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
            assert!(
                root.pointer(reference.strip_prefix('#').unwrap()).is_some(),
                "Unresolved {reference}"
            );
        }
        match value {
            Value::Object(object) => {
                for value in object.values() {
                    check_refs(value, root)
                }
            }
            Value::Array(values) => {
                for value in values {
                    check_refs(value, root)
                }
            }
            _ => {}
        }
    }
    #[test]
    fn publishes_resolvable_schemas_and_declares_every_path_parameter() {
        let api = serde_json::to_value(ApiDoc::openapi()).unwrap();
        check_refs(&api, &api);
        for (path, item) in api["paths"].as_object().unwrap() {
            for operation in item.as_object().unwrap().values() {
                for parameter in path
                    .split('{')
                    .skip(1)
                    .filter_map(|s| s.split_once('}').map(|(p, _)| p))
                {
                    if path.contains(&format!("{{{parameter}}}")) {
                        assert!(
                            operation["parameters"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|p| p["in"] == "path"
                                    && p["name"] == parameter
                                    && p["required"] == true),
                            "{path}: missing {parameter}"
                        );
                    }
                }
            }
        }
    }
}
