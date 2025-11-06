use axum::http::{header, StatusCode};
use axum::middleware;
use axum::middleware::Next;
use axum::{
    extract::Request,
    response::IntoResponse,
    routing::{delete, get, post},
    Router,
};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::envvar::is_defined;
use crate::server::api::{
    ApiProblem, BackupCreateResponse, BackupRequest, BackupResponse, ProblemJson, Tokens,
};
use crate::server::auth::jwt::{verify_jwt, JwtCredential};
use crate::server::database::{PinInfo, TokenWithPins};
use crate::server::handlers::handle_archive_download::{DownloadQuery, DownloadTokenResponse};
use crate::server::handlers::handle_archive_download::{
    __path_handle_archive_download as __path_handle_download,
    __path_handle_archive_download_token as __path_handle_download_token,
    handle_archive_download as handle_download,
    handle_archive_download_token as handle_download_token,
};
use crate::server::handlers::handle_backup::{__path_handle_backup, handle_backup};
use crate::server::handlers::handle_backup_create::{
    __path_handle_backup_create, handle_backup_create,
};
use crate::server::handlers::handle_backup_delete_archive::{
    __path_handle_backup_delete_archive, handle_backup_delete_archive,
};
use crate::server::handlers::handle_backup_delete_pins::{
    __path_handle_backup_delete_pins, handle_backup_delete_pins,
};
use crate::server::handlers::handle_backup_retries::{
    __path_handle_backup_retries, handle_backup_retries,
};
use crate::server::handlers::handle_backups::BackupsQuery;
use crate::server::handlers::handle_backups::{__path_handle_backups, handle_backups};
use crate::server::handlers::handle_pins::{__path_handle_pins, handle_pins, PinsResponse};
use crate::server::x402::X402Config;
use crate::server::AppState;

#[derive(OpenApi)]
#[openapi(
    paths(
        handle_backup_create,
        handle_backup,
        handle_download_token,
        handle_download,
        handle_backup_retries,
        handle_backup_delete_archive,
        handle_backup_delete_pins,
        handle_backups,
        handle_pins,
    ),
    components(
        schemas(BackupRequest, BackupCreateResponse, BackupResponse, Tokens, DownloadQuery, DownloadTokenResponse, BackupsQuery, PinsResponse, TokenWithPins, PinInfo, ApiProblem)
    ),
    tags(
        (name = "backups", description = "General backup operations"),
        (name = "pins", description = "IPFS pinning operations")
    ),
    info(
        title = "NFT Protection API",
        version = env!("CARGO_PKG_VERSION"),
        description = "API for protecting NFT metadata and content from EVM and Tezos NFT contracts.

## Key APIs:

### Backup Management (`/backups`)
- **Purpose**: Enable users to request NFT backups and either download them to their local filesystem or pin them to IPFS
- **Use Case**: Request a backup, track backup progress, view backup history, monitor failures

### Pin Management (`/pins`)
- **Purpose**: Enable users to manage IPFS pins
- **Use Case**: Check pin status and verify content is pinned",
        contact(
            name = "nftbk",
            url = "https://github.com/0xmichalis/nftbk"
        ),
        license(
            name = "Apache License 2.0",
            identifier = "Apache-2.0"
        )
    ),
    security(
        ("bearer_auth" = [])
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("Bearer token authentication (JWT or symmetric token)"))
                        .build(),
                ),
            );
        }
    }
}

#[derive(Clone)]
pub struct AuthState {
    pub app_state: AppState,
    pub jwt_credentials: Vec<JwtCredential>,
}

async fn auth_middleware(
    axum::extract::State(auth_state): axum::extract::State<AuthState>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    let state = &auth_state.app_state;
    let jwt_credentials = &auth_state.jwt_credentials;

    // 1. Try symmetric token auth
    if let Some(ref token) = state.auth_token {
        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let expected = format!("Bearer {token}");
        if let Some(auth_header) = auth_header {
            if auth_header
                .as_bytes()
                .ct_eq(expected.as_bytes())
                .unwrap_u8()
                == 1
            {
                req.extensions_mut().insert(Some("admin".to_string()));
                return next.run(req).await;
            }
        }
    }

    // 2. Try JWT auth (multiple credential sets)
    if !jwt_credentials.is_empty() {
        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        if let Some(header_value) = auth_header {
            if let Some(jwt) = header_value.strip_prefix("Bearer ") {
                for cred in jwt_credentials.iter() {
                    match verify_jwt(jwt, &cred.verification_key, &cred.issuer, &cred.audience)
                        .await
                    {
                        Ok(claims) => {
                            req.extensions_mut().insert(Some(claims.sub.clone()));
                            return next.run(req).await;
                        }
                        Err(e) => {
                            debug!("JWT verification failed for issuer {}: {e}", cred.issuer);
                        }
                    }
                }
                warn!("JWT verification failed for all configured credentials");
            }
        }
    }

    // 3. If both fail, return 401
    (
        [(header::WWW_AUTHENTICATE, "Bearer")],
        ProblemJson::from_status(
            StatusCode::UNAUTHORIZED,
            Some("Unauthorized".to_string()),
            Some(req.uri().to_string()),
        ),
    )
        .into_response()
}

pub fn build_router(
    state: AppState,
    jwt_credentials: Vec<JwtCredential>,
    x402_config: Option<X402Config>,
) -> Router {
    // Public router (no auth middleware)
    let public_router = Router::new()
        .route("/v1/backups/{task_id}/download", get(handle_download))
        .merge(SwaggerUi::new("/v1/swagger-ui").url("/v1/openapi.json", ApiDoc::openapi()))
        .with_state(state.clone());

    // Authenticated router
    let mut authed_router = Router::new()
        .route("/v1/backups", get(handle_backups))
        .route("/v1/backups/{task_id}", get(handle_backup))
        .route(
            "/v1/backups/{task_id}/download-tokens",
            post(handle_download_token),
        )
        .route("/v1/backups/{task_id}/retries", post(handle_backup_retries))
        .route(
            "/v1/backups/{task_id}/archive",
            delete(handle_backup_delete_archive),
        )
        .route(
            "/v1/backups/{task_id}/pins",
            delete(handle_backup_delete_pins),
        )
        .route("/v1/pins", get(handle_pins))
        .with_state(state.clone());

    // Add POST /v1/backups route with optional x402 middleware
    let post_backups_route = match x402_config {
        None => Router::new()
            .route("/v1/backups", post(handle_backup_create))
            .with_state(state.clone()),
        Some(config) => {
            let x402 = config
                .to_middleware()
                .expect("invalid x402 middleware config")
                .settle_before_execution()
                .with_description("Backup creation API");

            let price_tag = config
                .usdc_price_tag_for_amount(&config.price)
                .expect("invalid x402 price");

            Router::new()
                .route("/v1/backups", post(handle_backup_create))
                .layer(x402.with_price_tag(price_tag))
                .with_state(state.clone())
        }
    };

    authed_router = authed_router.merge(post_backups_route);

    let auth_state = AuthState {
        app_state: state.clone(),
        jwt_credentials,
    };
    if is_defined(&state.auth_token) || !auth_state.jwt_credentials.is_empty() {
        authed_router =
            authed_router.layer(middleware::from_fn_with_state(auth_state, auth_middleware));
    }

    public_router.merge(authed_router)
}
