use axum::http::{header, StatusCode};
use axum::middleware;
use axum::middleware::Next;
use axum::{
    extract::{Request, State},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use clap::Parser;
use dotenv::dotenv;
use std::env;
use std::io::Write;
use std::net::SocketAddr;
use tokio::signal;
use tracing::info;

use nftbk::envvar::is_defined;
use nftbk::logging;
use nftbk::logging::LogLevel;
use nftbk::server::privy::verify_privy_jwt;
use nftbk::server::{handle_backup, handle_download, handle_error_log, handle_status, AppState};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The address to listen on
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen_address: String,

    /// The path to the chains configuration file
    #[arg(short = 'c', long, default_value = "config_chains.toml")]
    chain_config: String,

    /// The base directory to save the backup to
    #[arg(long, default_value = "/tmp")]
    base_dir: String,

    /// Set the log level
    #[arg(short, long, value_enum, default_value = "info")]
    log_level: LogLevel,

    /// Skip checksum verification
    #[arg(long, default_value_t = false, action = clap::ArgAction::Set)]
    unsafe_skip_checksum_check: bool,
}

#[derive(Clone)]
struct AuthState {
    app_state: AppState,
    privy_verification_key: Option<String>,
    privy_app_id: Option<String>,
}

#[tokio::main]
async fn main() {
    // We are consuming config both from the environment and from the command line
    dotenv().ok();
    let args = Args::parse();
    logging::init(args.log_level.clone());
    let auth_token = env::var("NFTBK_AUTH_TOKEN").ok();
    let privy_app_id = env::var("PRIVY_APP_ID").ok();
    let privy_verification_key = env::var("PRIVY_VERIFICATION_KEY")
        .ok()
        .map(|s| s.replace("\\n", "\n"));

    let state = AppState::new(
        &args.chain_config,
        &args.base_dir,
        args.unsafe_skip_checksum_check,
        auth_token.clone(),
    )
    .await;

    info!("Starting server with options: {:?}", args);
    info!(
        "Symmetric authentication enabled: {}",
        is_defined(&auth_token)
    );
    info!(
        "Privy JWT authentication enabled: {}",
        is_defined(&privy_app_id) && is_defined(&privy_verification_key)
    );

    // Create the router
    let mut app = Router::new()
        .route("/backup", post(handle_backup))
        .route("/backup/:task_id/status", get(handle_status))
        .route("/backup/:task_id/download", get(handle_download))
        .route("/backup/:task_id/error_log", get(handle_error_log))
        .with_state(state.clone());

    // Add auth middleware
    let auth_state = AuthState {
        app_state: state.clone(),
        privy_verification_key,
        privy_app_id,
    };
    if is_defined(&auth_token) || is_defined(&auth_state.privy_verification_key) {
        app = app.layer(middleware::from_fn_with_state(auth_state, auth_middleware));
    }

    // Add graceful shutdown
    let shutdown_signal = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
        info!("Received shutdown signal, shutting down server...");
        let _ = std::io::stdout().flush();
        std::thread::sleep(std::time::Duration::from_millis(100));
    };

    // Start the server
    let addr: SocketAddr = args.listen_address.parse().expect("Invalid listen address");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!("Listening on {}", addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await
        .unwrap();
}

async fn auth_middleware(
    State(auth_state): State<AuthState>,
    mut req: Request,
    next: Next,
) -> impl IntoResponse {
    let state = &auth_state.app_state;
    let privy_app_id = &auth_state.privy_app_id;
    let privy_verification_key = &auth_state.privy_verification_key;

    // 1. Try symmetric token auth
    if let Some(ref token) = state.auth_token {
        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        let expected = format!("Bearer {}", token);
        if auth_header == Some(expected.as_str()) {
            req.extensions_mut().insert::<Option<String>>(None);
            return next.run(req).await;
        }
    }

    // 2. Try Privy JWT auth
    if let (Some(app_id), Some(verification_key)) =
        (privy_app_id.as_ref(), privy_verification_key.as_ref())
    {
        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());
        if let Some(header_value) = auth_header {
            if let Some(jwt) = header_value.strip_prefix("Bearer ") {
                match verify_privy_jwt(jwt, verification_key, app_id).await {
                    Ok(claims) => {
                        req.extensions_mut().insert(Some(claims.sub.clone()));
                        return next.run(req).await;
                    }
                    Err(e) => {
                        tracing::warn!("Privy JWT verification failed: {}", e);
                    }
                }
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
