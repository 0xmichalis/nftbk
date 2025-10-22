use axum::{
    extract::{Request, State},
    response::Response,
};
use tower::Service;
use tracing::{error, info, warn};

use crate::server::database::r#trait::Database;
use crate::server::hashing::compute_task_id;
use crate::server::api::BackupRequest;

/// Custom handler that wraps the backup creation with settlement failure handling
pub async fn handle_backup_create_with_settlement_hook<DB: Database + Send + Sync + 'static>(
    State(db): State<DB>,
    request: Request,
    next: impl Service<Request, Response = Response>,
) -> Response {
    // Extract the backup request to compute task_id
    let task_id = if let Some(body) = request.extensions().get::<BackupRequest>() {
        Some(compute_task_id(&body.tokens, None))
    } else {
        None
    };

    // Call the next handler (which includes x402 middleware)
    let response = next.call(request).await;

    // Check if this was a settlement failure (402 status)
    if response.status() == 402 {
        warn!("x402 settlement failed, marking backup as unpaid");
        
        if let Some(task_id) = task_id {
            if let Err(e) = db.mark_backup_as_unpaid(&task_id).await {
                error!("Failed to mark backup {} as unpaid: {}", task_id, e);
            } else {
                info!("Successfully marked backup {} as unpaid due to settlement failure", task_id);
            }
        }
    }

    response
}
