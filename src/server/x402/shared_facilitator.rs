use std::future::Future;

use x402_axum::facilitator_client::{FacilitatorClient, FacilitatorClientError};
use x402_rs::facilitator::Facilitator;
use x402_rs::types::{
    SettleRequest, SettleResponse, SupportedPaymentKindsResponse, VerifyRequest, VerifyResponse,
};

use super::error_handling::{
    handle_result, tolerant_parse_supported, tolerant_recover_payment_required,
    tolerant_recover_verify,
};

/// A wrapper around FacilitatorClient that adds robust error handling
#[derive(Clone, Debug)]
pub struct SharedFacilitator {
    client: FacilitatorClient,
}

impl SharedFacilitator {
    pub fn new(client: FacilitatorClient) -> Self {
        Self { client }
    }
}

impl Facilitator for SharedFacilitator {
    type Error = FacilitatorClientError;

    fn verify(
        &self,
        request: &VerifyRequest,
    ) -> impl Future<Output = Result<VerifyResponse, Self::Error>> + Send {
        let this = self.clone();
        let req = request.clone();
        async move {
            handle_result(
                &this.client,
                "POST /verify",
                {
                    let client = this.client.clone();
                    let req = req.clone();
                    move || {
                        reqwest::Client::new()
                            .post(client.verify_url().clone())
                            .json(&req)
                    }
                },
                tolerant_recover_verify,
                this.client.verify(&req).await,
            )
            .await
        }
    }

    fn settle(
        &self,
        request: &SettleRequest,
    ) -> impl Future<Output = Result<SettleResponse, Self::Error>> + Send {
        let this = self.clone();
        let req = request.clone();
        async move {
            handle_result(
                &this.client,
                "POST /settle",
                {
                    let client = this.client.clone();
                    let req = req.clone();
                    move || {
                        reqwest::Client::new()
                            .post(client.settle_url().clone())
                            .json(&req)
                    }
                },
                |body| tolerant_recover_payment_required::<SettleResponse>("POST /settle", body),
                this.client.settle(&req).await,
            )
            .await
        }
    }

    fn supported(
        &self,
    ) -> impl Future<Output = Result<SupportedPaymentKindsResponse, Self::Error>> + Send {
        let this = self.clone();
        async move {
            handle_result(
                &this.client,
                "GET /supported",
                {
                    let client = this.client.clone();
                    move || reqwest::Client::new().get(client.supported_url().clone())
                },
                |body| tolerant_parse_supported(body).map(Ok),
                this.client.supported().await,
            )
            .await
        }
    }
}
