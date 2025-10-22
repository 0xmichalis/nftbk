use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::response::Response;
use tower::Service;
use tracing::{error, info, warn};
use x402_axum::X402Middleware;

use crate::server::database::r#trait::Database;

/// A wrapper around X402Middleware that provides settlement failure hooks
pub struct X402MiddlewareWithSettlementHook<F, DB> {
    inner: X402Middleware<F>,
    db: DB,
}

impl<F, DB> X402MiddlewareWithSettlementHook<F, DB> {
    pub fn new(inner: X402Middleware<F>, db: DB) -> Self {
        Self { inner, db }
    }
}

impl<F, DB> Clone for X402MiddlewareWithSettlementHook<F, DB>
where
    F: Clone,
    DB: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            db: self.db.clone(),
        }
    }
}

impl<F, DB> Service<Request> for X402MiddlewareWithSettlementHook<F, DB>
where
    F: Service<Request, Response = Response> + Send + 'static,
    F::Future: Send + 'static,
    F::Error: Send + 'static,
    DB: Database + Send + Sync + 'static,
{
    type Response = Response;
    type Error = F::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request) -> Self::Future {
        let mut inner = self.inner.clone();
        let db = self.db.clone();

        Box::pin(async move {
            // Extract task_id from the request if it's a backup creation request
            let task_id = extract_task_id_from_request(&req);

            // Call the inner middleware
            let result = inner.call(req).await;

            // Check if this was a settlement failure
            if let Err(ref error) = result {
                if is_settlement_failure(error) {
                    warn!("x402 settlement failed, marking backup as unpaid");
                    
                    if let Some(task_id) = task_id {
                        if let Err(e) = mark_backup_as_unpaid(&db, &task_id).await {
                            error!("Failed to mark backup {} as unpaid: {}", task_id, e);
                        } else {
                            info!("Successfully marked backup {} as unpaid due to settlement failure", task_id);
                        }
                    }
                }
            }

            result
        })
    }
}

/// Extract task_id from a backup creation request
fn extract_task_id_from_request(req: &Request) -> Option<String> {
    // Check if this is a POST to /v1/backups
    if req.method() != "POST" {
        return None;
    }

    if !req.uri().path().starts_with("/v1/backups") {
        return None;
    }

    // For backup creation, we need to compute the task_id from the request body
    // This is a simplified approach - in practice, you might want to parse the body
    // or use a different method to identify the backup task
    None // We'll need to implement this based on the actual request structure
}

/// Check if an error represents a settlement failure
fn is_settlement_failure(error: &F::Error) -> bool {
    // This is a placeholder - you'll need to implement this based on the actual error types
    // from the x402 middleware
    false
}

/// Mark a backup as unpaid in the database
async fn mark_backup_as_unpaid<DB: Database>(db: &DB, task_id: &str) -> Result<(), sqlx::Error> {
    // Update the backup status to "unpaid" to make it inaccessible
    // We'll need to add this method to the Database trait
    db.mark_backup_as_unpaid(task_id).await
}
