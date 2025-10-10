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
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::envvar::is_defined;
use crate::server::api::{BackupRequest, BackupResponse, StatusResponse, Tokens};
use crate::server::db::{PinInfo, ProtectionJobWithBackup, TokenWithPins};
use crate::server::handlers::handle_backup::{__path_handle_backup, handle_backup};
use crate::server::handlers::handle_backup_delete::{
    __path_handle_backup_delete, handle_backup_delete,
};
use crate::server::handlers::handle_backup_retry::{
    __path_handle_backup_retry, handle_backup_retry,
};
use crate::server::handlers::handle_backups::BackupsQuery;
use crate::server::handlers::handle_backups::{__path_handle_backups, handle_backups};
use crate::server::handlers::handle_create_pins::{
    __path_handle_create_pins, handle_create_pins, PinRequest,
};
use crate::server::handlers::handle_download::{DownloadQuery, DownloadTokenResponse};
use crate::server::handlers::handle_download::{
    __path_handle_download, __path_handle_download_token, handle_download, handle_download_token,
};
use crate::server::handlers::handle_pins::{__path_handle_pins, handle_pins, PinsResponse};
use crate::server::handlers::handle_status::{__path_handle_status, handle_status};
use crate::server::privy::verify_privy_jwt;
use crate::server::AppState;

#[derive(OpenApi)]
#[openapi(
    paths(
        handle_backup,
        handle_status,
        handle_download_token,
        handle_download,
        handle_backup_retry,
        handle_backup_delete,
        handle_backups,
        handle_create_pins,
        handle_pins,
    ),
    components(
        schemas(BackupRequest, BackupResponse, StatusResponse, Tokens, DownloadQuery, DownloadTokenResponse, BackupsQuery, PinRequest, PinsResponse, ProtectionJobWithBackup, TokenWithPins, PinInfo)
    ),
    tags(
        (name = "backup", description = "Filesystem backup operations"),
        (name = "pins", description = "IPFS pinning operations")
    ),
    info(
        title = "NFT Protection API",
        version = env!("CARGO_PKG_VERSION"),
        description = "API for protecting NFT metadata and content from EVM and Tezos NFT contracts.

## Key APIs:

### Filesystem Backup Management (`/backups`)
- **Purpose**: Enable users to request and download NFT backups to their local filesystem
- **Use Case**: Request a backup, track backup progress, view backup history, monitor failures

### Pin Management (`/pins`) 
- **Purpose**: Enable users to request and manage IPFS pinning of NFTs
- **Use Case**: Request a pin, check pin status, verify content is pinned",
        contact(
            name = "nftbk",
            url = "https://github.com/0xmichalis/nftbk"
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
    pub privy_credentials: Vec<(String, String)>, // (app_id, verification_key)
}

async fn auth_middleware(
    axum::extract::State(auth_state): axum::extract::State<AuthState>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    let state = &auth_state.app_state;
    let privy_credentials = &auth_state.privy_credentials;

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

    // 2. Try Privy JWT auth (multiple credential sets)
    if !privy_credentials.is_empty() {
        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        if let Some(header_value) = auth_header {
            if let Some(jwt) = header_value.strip_prefix("Bearer ") {
                for (app_id, verification_key) in privy_credentials.iter() {
                    match verify_privy_jwt(jwt, verification_key, app_id).await {
                        Ok(claims) => {
                            req.extensions_mut().insert(Some(claims.sub.clone()));
                            return next.run(req).await;
                        }
                        Err(e) => {
                            tracing::debug!(
                                "Privy JWT verification failed for app_id {}: {}",
                                app_id,
                                e
                            );
                        }
                    }
                }
                tracing::warn!("Privy JWT verification failed for all configured credentials");
            }
        }
    }

    // 3. If both fail, return 401
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        "Unauthorized",
    )
        .into_response()
}

pub fn build_router(state: AppState, privy_credentials: Vec<(String, String)>) -> Router {
    // Public router (no auth middleware)
    let public_router = Router::new()
        .route("/backup/:task_id/download", get(handle_download))
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .with_state(state.clone());

    // Authenticated router
    let mut authed_router = Router::new()
        .route("/backup", post(handle_backup))
        .route("/backup/:task_id/status", get(handle_status))
        .route(
            "/backup/:task_id/download_token",
            get(handle_download_token),
        )
        .route("/backup/:task_id/retry", post(handle_backup_retry))
        .route("/backup/:task_id", delete(handle_backup_delete))
        .route("/backups", get(handle_backups))
        .route("/pins", get(handle_pins).post(handle_create_pins))
        .with_state(state.clone());

    let auth_state = AuthState {
        app_state: state.clone(),
        privy_credentials,
    };
    if is_defined(&state.auth_token) || !auth_state.privy_credentials.is_empty() {
        authed_router =
            authed_router.layer(middleware::from_fn_with_state(auth_state, auth_middleware));
    }

    public_router.merge(authed_router)
}
