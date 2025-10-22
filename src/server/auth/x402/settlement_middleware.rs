use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::extract::Request;
use axum::response::Response;
use tower::Service;
use tracing::{error, info, warn};

use crate::server::database::r#trait::Database;
use crate::server::hashing::compute_task_id;
use crate::server::api::BackupRequest;

/// Middleware that wraps x402 middleware and handles settlement failures
pub struct SettlementFailureMiddleware<S, DB> {
    inner: S,
    db: DB,
}

impl<S, DB> SettlementFailureMiddleware<S, DB> {
    pub fn new(inner: S, db: DB) -> Self {
        Self { inner, db }
    }
}

impl<S, DB> Clone for SettlementFailureMiddleware<S, DB>
where
    S: Clone,
    DB: Clone,
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            db: self.db.clone(),
        }
    }
}

impl<S, DB> Service<Request> for SettlementFailureMiddleware<S, DB>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    DB: Database + Send + Sync + 'static,
{
    type Response = Response;
    type Error = S::Error;
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

            // Call the inner service (x402 middleware)
            let response = inner.call(req).await?;

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

            Ok(response)
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

    // Try to extract the backup request from the request body
    // This is a simplified approach - in practice, you might want to parse the body
    // or use a different method to identify the backup task
    None // We'll need to implement this based on the actual request structure
}
