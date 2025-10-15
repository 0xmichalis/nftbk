use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::time::{sleep, Duration as TokioDuration};
use tracing::{error, info, warn};

use crate::ipfs::{IpfsPinningProvider, PinResponseStatus};
use crate::server::database::{r#trait::Database, Db};

/// Monitor and update the status of queued or pinning pin requests
pub async fn monitor_pin_requests<DB: Database + ?Sized>(
    db: &DB,
    providers: &[Arc<dyn IpfsPinningProvider>],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let active_pins = db.get_active_pins().await?;

    if active_pins.is_empty() {
        return Ok(());
    }

    info!("Monitoring {} active pins", active_pins.len());

    let mut status_updates = Vec::new();

    for pin in active_pins {
        // Find the appropriate provider for this pin
        let provider = providers
            .iter()
            .find(|p| pin.provider_url.as_deref() == Some(p.provider_url()));

        let Some(provider) = provider else {
            warn!(
                "No provider found for pin {} (provider_url: {})",
                pin.id,
                pin.provider_url.as_deref().unwrap_or("")
            );
            continue;
        };

        // Get the current status from the provider
        match provider.get_pin(&pin.request_id).await {
            Ok(pin_response) => {
                let new_status = match pin_response.status {
                    PinResponseStatus::Queued => "queued",
                    PinResponseStatus::Pinning => "pinning",
                    PinResponseStatus::Pinned => "pinned",
                    PinResponseStatus::Failed => "failed",
                };

                // Only update if the status has changed
                if new_status != pin.pin_status {
                    status_updates.push((pin.id, new_status.to_string()));
                    info!(
                        "Queued status update for pin {}: {} -> {}",
                        pin.id, pin.pin_status, new_status
                    );
                }
            }
            Err(e) => {
                warn!(
                    "Failed to get pin status for request {} ({}): {}",
                    pin.id, pin.request_id, e
                );
            }
        }
    }

    // Batch update all status changes
    if !status_updates.is_empty() {
        match db.update_pin_statuses(&status_updates).await {
            Ok(()) => {
                info!("Successfully updated {} pin statuses", status_updates.len());
            }
            Err(e) => {
                error!("Failed to batch update pin statuses: {}", e);
            }
        }
    }

    Ok(())
}

pub async fn run_pin_monitor(
    db: Arc<Db>,
    providers: Vec<Arc<dyn IpfsPinningProvider>>,
    interval_seconds: u64,
    shutdown_flag: Arc<AtomicBool>,
) {
    while !shutdown_flag.load(Ordering::SeqCst) {
        info!("Running pin monitoring process...");

        match monitor_pin_requests(&*db, &providers).await {
            Ok(()) => {
                info!("Pin monitoring process completed successfully");
            }
            Err(e) => {
                error!("Pin monitoring process failed: {}", e);
            }
        }

        // Sleep with periodic shutdown checks
        let mut slept = 0;
        let sleep_step = 1;
        while slept < interval_seconds && !shutdown_flag.load(Ordering::SeqCst) {
            sleep(TokioDuration::from_secs(sleep_step)).await;
            slept += sleep_step;
        }
    }

    info!("Pin monitor stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipfs::provider::{PinRequest, PinResponse, PinResponseStatus};
    use crate::server::database::r#trait::MockDatabase;
    use crate::server::database::PinRow;
    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};

    // Mock IPFS provider for testing
    #[derive(Clone)]
    struct TestIpfsProvider {
        name: String,
        get_pin_results: Arc<Mutex<Vec<anyhow::Result<PinResponse>>>>,
        get_pin_calls: Arc<Mutex<Vec<String>>>,
    }

    impl TestIpfsProvider {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                get_pin_results: Arc::new(Mutex::new(Vec::new())),
                get_pin_calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn set_get_pin_result(&self, result: anyhow::Result<PinResponse>) {
            *self.get_pin_results.lock().unwrap() = vec![result];
        }

        fn set_get_pin_results(&self, results: Vec<anyhow::Result<PinResponse>>) {
            *self.get_pin_results.lock().unwrap() = results;
        }

        fn get_pin_calls(&self) -> Vec<String> {
            self.get_pin_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl IpfsPinningProvider for TestIpfsProvider {
        fn provider_type(&self) -> &str {
            &self.name
        }

        fn provider_url(&self) -> &str {
            &self.name
        }

        async fn create_pin(&self, _request: &PinRequest) -> anyhow::Result<PinResponse> {
            Err(anyhow::anyhow!("Not implemented in test"))
        }

        async fn get_pin(&self, pin_id: &str) -> anyhow::Result<PinResponse> {
            self.get_pin_calls.lock().unwrap().push(pin_id.to_string());
            let mut results = self.get_pin_results.lock().unwrap();
            if results.is_empty() {
                return Err(anyhow::anyhow!("No mock result set"));
            }
            results.remove(0)
        }

        async fn list_pins(&self) -> anyhow::Result<Vec<PinResponse>> {
            Err(anyhow::anyhow!("Not implemented in test"))
        }

        async fn delete_pin(&self, _request_id: &str) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("Not implemented in test"))
        }
    }

    fn create_test_pin_row(id: i64, provider_url: &str, request_id: &str, status: &str) -> PinRow {
        PinRow {
            id,
            task_id: "test-task".to_string(),
            provider_type: "test-type".to_string(),
            provider_url: Some(provider_url.to_string()),
            cid: "QmTestCid".to_string(),
            request_id: request_id.to_string(),
            pin_status: status.to_string(),
            created_at: chrono::Utc::now(),
        }
    }

    fn create_test_pin_response(id: &str, status: PinResponseStatus) -> PinResponse {
        PinResponse {
            id: id.to_string(),
            cid: "QmTestCid".to_string(),
            status,
            provider_type: "test-provider".to_string(),
            provider_url: "test-provider".to_string(),
            metadata: None,
        }
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_empty_list() {
        // Setup: DB returns empty list of active pin requests
        let mock_db = MockDatabase::default(); // No active requests by default

        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_ok());

        // DB queried once, no updates attempted
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 0);
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_db_error() {
        // Setup: DB fails when trying to get active pin requests
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_active_pins_error(Some("Database error".to_string()));

        // Setup: Provider is available but won't be called due to DB error
        let mock_provider = TestIpfsProvider::new("test-provider");
        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![Arc::new(mock_provider.clone())];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Database error"));

        // Verify: No provider calls were made due to DB error; DB queried once
        let calls = mock_provider.get_pin_calls();
        assert!(calls.is_empty());
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 0);
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_no_provider_found() {
        // Setup: DB has a pin request for a provider that doesn't exist
        let pin_request = create_test_pin_row(1, "unknown-provider", "req-1", "queued");
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_active_pins_result(vec![pin_request]);

        // Setup: No providers configured (or different provider names)
        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_ok());

        // Verify: DB queried once, no updates attempted
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 0);
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_provider_name_mismatch() {
        // Setup: DB has a pin request for a provider that doesn't match any configured providers
        let pin_request = create_test_pin_row(1, "unknown-provider", "req-1", "queued");
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_active_pins_result(vec![pin_request]);

        // Setup: Different providers are configured (name mismatch)
        let mock_provider1 = TestIpfsProvider::new("provider-1");
        let mock_provider2 = TestIpfsProvider::new("provider-2");
        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![
            Arc::new(mock_provider1.clone()),
            Arc::new(mock_provider2.clone()),
        ];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_ok());

        // Verify: DB queried once, no updates attempted
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 0);

        // Verify: No provider calls were made since no matching provider was found
        let calls1 = mock_provider1.get_pin_calls();
        assert!(calls1.is_empty());

        let calls2 = mock_provider2.get_pin_calls();
        assert!(calls2.is_empty());
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_provider_error() {
        // Setup: DB has a pin request for a valid provider
        let pin_request = create_test_pin_row(1, "test-provider", "req-1", "queued");
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_active_pins_result(vec![pin_request]);

        // Setup: Provider will return an error when called
        let mock_provider = TestIpfsProvider::new("test-provider");
        mock_provider.set_get_pin_result(Err(anyhow::anyhow!("Provider error")));

        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![Arc::new(mock_provider.clone())];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_ok()); // Should continue despite provider error

        // Verify: DB queried once; provider was called with the correct request ID
        let calls = mock_provider.get_pin_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], "req-1");
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 0);
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_status_unchanged() {
        // Setup: DB has a pin request with queued status
        let pin_request = create_test_pin_row(1, "test-provider", "req-1", "queued");
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_active_pins_result(vec![pin_request]);

        // Setup: Provider returns the same status (no change)
        let mock_provider = TestIpfsProvider::new("test-provider");
        mock_provider.set_get_pin_result(Ok(create_test_pin_response(
            "req-1",
            PinResponseStatus::Queued,
        )));

        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![Arc::new(mock_provider.clone())];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_ok());

        // Verify: DB queried once; provider was called with the correct request ID
        let calls = mock_provider.get_pin_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], "req-1");
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 0);
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_status_changed() {
        // Setup: DB has a pin request with queued status
        let pin_request = create_test_pin_row(1, "test-provider", "req-1", "queued");
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_active_pins_result(vec![pin_request]);

        // Setup: Provider returns a different status (status change)
        let mock_provider = TestIpfsProvider::new("test-provider");
        mock_provider.set_get_pin_result(Ok(create_test_pin_response(
            "req-1",
            PinResponseStatus::Pinned,
        )));

        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![Arc::new(mock_provider.clone())];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_ok());

        // Verify: DB queried once; provider was called with the correct request ID
        let calls = mock_provider.get_pin_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], "req-1");
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 1);
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_multiple_status_changes() {
        // Setup: DB has 2 pin requests with different initial statuses
        let pin_request1 = create_test_pin_row(1, "test-provider", "req-1", "queued");
        let pin_request2 = create_test_pin_row(2, "test-provider", "req-2", "pinning");
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_active_pins_result(vec![pin_request1, pin_request2]);

        // Setup: Provider will return different statuses for each request
        let mock_provider = TestIpfsProvider::new("test-provider");
        mock_provider.set_get_pin_results(vec![
            Ok(create_test_pin_response("req-1", PinResponseStatus::Pinned)), // queued -> pinned
            Ok(create_test_pin_response("req-2", PinResponseStatus::Failed)), // pinning -> failed
        ]);

        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![Arc::new(mock_provider.clone())];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_ok());

        // Verify: DB queried once; Provider was called for both requests
        let calls = mock_provider.get_pin_calls();
        assert_eq!(calls.len(), 2);
        assert!(calls.contains(&"req-1".to_string()));
        assert!(calls.contains(&"req-2".to_string()));
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 1);
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_batch_update_error() {
        // Setup: DB has a pin request and will fail on batch update
        let pin_request = create_test_pin_row(1, "test-provider", "req-1", "queued");
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_active_pins_result(vec![pin_request]);
        mock_db.set_update_pin_statuses_error(Some("Batch update error".to_string()));

        // Setup: Provider returns a status change
        let mock_provider = TestIpfsProvider::new("test-provider");
        mock_provider.set_get_pin_result(Ok(create_test_pin_response(
            "req-1",
            PinResponseStatus::Pinned,
        )));

        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![Arc::new(mock_provider.clone())];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_ok()); // Should continue despite batch update error

        // Verify: DB queried once; The provider was called with the correct request ID
        let calls = mock_provider.get_pin_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], "req-1");
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 1);
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_mixed_providers() {
        // Setup: DB has 2 pin requests for different providers
        let pin_request1 = create_test_pin_row(1, "provider-1", "req-1", "queued");
        let pin_request2 = create_test_pin_row(2, "provider-2", "req-2", "pinning");
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_active_pins_result(vec![pin_request1, pin_request2]);

        // Setup: Each provider returns different statuses
        let mock_provider1 = TestIpfsProvider::new("provider-1");
        mock_provider1.set_get_pin_result(Ok(create_test_pin_response(
            "req-1",
            PinResponseStatus::Pinned,
        ))); // queued -> pinned

        let mock_provider2 = TestIpfsProvider::new("provider-2");
        mock_provider2.set_get_pin_result(Ok(create_test_pin_response(
            "req-2",
            PinResponseStatus::Failed,
        ))); // pinning -> failed

        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![
            Arc::new(mock_provider1.clone()),
            Arc::new(mock_provider2.clone()),
        ];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_ok());

        // Verify: DB queried once; Each provider was called with the correct request
        let calls1 = mock_provider1.get_pin_calls();
        assert_eq!(calls1.len(), 1);
        assert!(calls1.contains(&"req-1".to_string()));

        let calls2 = mock_provider2.get_pin_calls();
        assert_eq!(calls2.len(), 1);
        assert!(calls2.contains(&"req-2".to_string()));
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 1);
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_queued_to_pinned_transition() {
        // Setup: DB has a queued pin request
        let pin_request = create_test_pin_row(1, "test-provider", "req-1", "queued");
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_active_pins_result(vec![pin_request]);

        // Setup: Provider API returns that the pin is now pinned
        let mock_provider = TestIpfsProvider::new("test-provider");
        mock_provider.set_get_pin_result(Ok(create_test_pin_response(
            "req-1",
            PinResponseStatus::Pinned,
        )));

        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![Arc::new(mock_provider.clone())];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_ok());

        // Verify: DB queried once; The monitor called the provider API for the request
        let calls = mock_provider.get_pin_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], "req-1");
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 1);
    }

    #[tokio::test]
    async fn test_monitor_pin_requests_all_status_types() {
        // Setup: DB has 4 pin requests with different initial statuses
        let pin_request1 = create_test_pin_row(1, "test-provider", "req-1", "queued");
        let pin_request2 = create_test_pin_row(2, "test-provider", "req-2", "pinning");
        let pin_request3 = create_test_pin_row(3, "test-provider", "req-3", "pinned");
        let pin_request4 = create_test_pin_row(4, "test-provider", "req-4", "failed");
        let mut mock_db = MockDatabase::default();
        mock_db.set_get_active_pins_result(vec![
            pin_request1,
            pin_request2,
            pin_request3,
            pin_request4,
        ]);

        // Setup: Provider returns different statuses for each request
        let mock_provider = TestIpfsProvider::new("test-provider");
        mock_provider.set_get_pin_results(vec![
            Ok(create_test_pin_response(
                "req-1",
                PinResponseStatus::Pinning,
            )), // queued -> pinning
            Ok(create_test_pin_response("req-2", PinResponseStatus::Pinned)), // pinning -> pinned
            Ok(create_test_pin_response("req-3", PinResponseStatus::Failed)), // pinned -> failed
            Ok(create_test_pin_response("req-4", PinResponseStatus::Queued)), // failed -> queued
        ]);

        let providers: Vec<Arc<dyn IpfsPinningProvider>> = vec![Arc::new(mock_provider.clone())];

        // Execute: Run the monitor
        let result = monitor_pin_requests(&mock_db, &providers).await;
        assert!(result.is_ok());

        // Verify: DB queried once; Provider was called for all 4 requests
        let calls = mock_provider.get_pin_calls();
        assert_eq!(calls.len(), 4);
        assert!(calls.contains(&"req-1".to_string()));
        assert!(calls.contains(&"req-2".to_string()));
        assert!(calls.contains(&"req-3".to_string()));
        assert!(calls.contains(&"req-4".to_string()));
        assert_eq!(mock_db.get_active_pins_calls(), 1);
        assert_eq!(mock_db.get_update_pin_statuses_calls(), 1);
    }
}
