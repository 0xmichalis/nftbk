use std::path::Path;
use std::sync::{atomic::AtomicBool, Arc, Mutex};

use async_trait::async_trait;

use super::r#trait::*;
use crate::server::model::*;
use crate::server::{storage::BlobStore, AppState};

pub const OWNER: &str = "11111111-1111-4111-8111-111111111111";

#[derive(Default)]
pub struct MockDatabase {
    pub document: Option<Document>,
    pub payment: Mutex<Option<Document>>,
    pub payment_updates: Mutex<Vec<PaymentUpdate>>,
    pub creates: Mutex<Vec<Create>>,
    pub blobs: Mutex<Vec<Blob>>,
    pub operation_context: Mutex<Option<Document>>,
}
#[async_trait]
impl Database for MockDatabase {
    async fn owner(&self, _principal: &Principal) -> Result<String> {
        Ok(OWNER.into())
    }
    async fn archive_storage(&self, _owner: &str, _id: &str) -> Result<String> {
        panic!("Unexpected database call: archive_storage")
    }
    async fn get(&self, _resource: Resource, _owner: &str, _id: &str) -> Result<Option<Document>> {
        Ok(self.document.clone())
    }
    async fn list(
        &self,
        _resource: Resource,
        _owner: &str,
        _page: &Page,
    ) -> Result<Collection<Document>> {
        Ok(Collection {
            data: self.document.clone().into_iter().collect(),
            next_cursor: None,
        })
    }
    async fn create(&self, request: Create) -> Result<Document> {
        self.creates.lock().unwrap().push(request);
        Ok(self.document.clone().expect("Configure create response"))
    }
    async fn delete(&self, _resource: Resource, _owner: &str, _id: &str) -> Result<Operation> {
        panic!("Unexpected database call: delete")
    }
    async fn retry(&self, _owner: &str, _id: &str) -> Result<Attempt> {
        panic!("Unexpected database call: retry")
    }
    async fn attempts(&self, _owner: &str, _id: &str) -> Result<Vec<Attempt>> {
        panic!("Unexpected database call: attempts")
    }
    async fn claim(&self) -> Result<Option<Claim>> {
        panic!("Unexpected database call: claim")
    }
    async fn heartbeat(&self, _claim: &Claim) -> Result<bool> {
        panic!("Unexpected database call: heartbeat")
    }
    async fn context(&self, _claim: &Claim) -> Result<Document> {
        Ok(self
            .operation_context
            .lock()
            .unwrap()
            .clone()
            .expect("Configure operation context"))
    }
    async fn progress(&self, _claim: &Claim, progress: Progress) -> Result<()> {
        let mut context = self.operation_context.lock().unwrap();
        let context = context.as_mut().expect("Configure operation context");
        if let Progress::Items(items) = &progress {
            context["items"] = serde_json::to_value(items).unwrap();
        }
        Ok(())
    }
    async fn put_blob(&self, _claim: &Claim, blob: &Blob) -> Result<()> {
        self.blobs.lock().unwrap().push(blob.clone());
        Ok(())
    }
    async fn reserve_pin(
        &self,
        _claim: &Claim,
        _asset: &Asset,
        _provider: &str,
    ) -> Result<ManagedPin> {
        panic!("Unexpected database call: reserve_pin")
    }
    async fn update_pin(&self, _claim: &Claim, _update: PinUpdate) -> Result<()> {
        panic!("Unexpected database call: update_pin")
    }
    async fn release_pins(&self, _claim: &Claim) -> Result<Vec<ManagedPin>> {
        panic!("Unexpected database call: release_pins")
    }
    async fn payment(
        &self,
        _resource: Resource,
        _owner: &str,
        _target_id: &str,
        update: Option<PaymentUpdate>,
    ) -> Result<Option<Document>> {
        if let Some(update) = update {
            self.payment_updates.lock().unwrap().push(update);
        }
        Ok(self.payment.lock().unwrap().clone())
    }
    async fn maintenance(&self) -> Result<()> {
        panic!("Unexpected database call: maintenance")
    }
    async fn active_leases(&self) -> Result<Vec<(String, String)>> {
        panic!("Unexpected database call: active_leases")
    }
    async fn blob_deleting(&self, _sha256: &str) -> Result<bool> {
        panic!("Unexpected database call: blob_deleting")
    }
    async fn garbage(&self, _finished: Option<&str>) -> Result<Vec<Blob>> {
        panic!("Unexpected database call: garbage")
    }
}

pub fn state(db: Arc<dyn Database>, directory: &Path) -> AppState {
    AppState {
        db,
        chain_config: Arc::new(crate::ChainConfig(Default::default())),
        storage: BlobStore::new(directory),
        providers: Arc::new(ProviderMap::new()),
        jwt_credentials: Arc::new(vec![]),
        auth_token: None,
        download_key: Arc::new([7u8; 32]),
        shutdown_flag: Arc::new(AtomicBool::new(false)),
        x402_config: None,
        retention_days: 3,
        max_content_request_retries: 0,
        unsafe_skip_checksum_check: false,
        pricing_version: "test".into(),
    }
}
