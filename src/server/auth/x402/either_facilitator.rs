use x402_axum::facilitator_client::FacilitatorClient;
use x402_rs::facilitator::Facilitator;
use x402_rs::types::{
    SettleRequest, SettleResponse, SupportedPaymentKindsResponse, VerifyRequest, VerifyResponse,
};

use super::coinbase_facilitator::CoinbaseFacilitator;
use super::shared_facilitator::SharedFacilitator;

#[derive(Clone, Debug)]
pub enum EitherFacilitator {
    Simple(SharedFacilitator),
    Coinbase(CoinbaseFacilitator),
}

impl From<FacilitatorClient> for EitherFacilitator {
    fn from(value: FacilitatorClient) -> Self {
        EitherFacilitator::Simple(SharedFacilitator::new(value))
    }
}

impl From<CoinbaseFacilitator> for EitherFacilitator {
    fn from(value: CoinbaseFacilitator) -> Self {
        EitherFacilitator::Coinbase(value)
    }
}

impl Facilitator for EitherFacilitator {
    type Error = x402_axum::facilitator_client::FacilitatorClientError;

    fn verify(
        &self,
        request: &VerifyRequest,
    ) -> impl std::future::Future<Output = Result<VerifyResponse, Self::Error>> + Send {
        let this = self.clone();
        let req = request.clone();
        async move {
            match this {
                EitherFacilitator::Simple(inner) => inner.verify(&req).await,
                EitherFacilitator::Coinbase(inner) => inner.verify(&req).await,
            }
        }
    }

    fn settle(
        &self,
        request: &SettleRequest,
    ) -> impl std::future::Future<Output = Result<SettleResponse, Self::Error>> + Send {
        let this = self.clone();
        let req = request.clone();
        async move {
            match this {
                EitherFacilitator::Simple(inner) => inner.settle(&req).await,
                EitherFacilitator::Coinbase(inner) => inner.settle(&req).await,
            }
        }
    }

    fn supported(
        &self,
    ) -> impl std::future::Future<Output = Result<SupportedPaymentKindsResponse, Self::Error>> + Send
    {
        let this = self.clone();
        async move {
            match this {
                EitherFacilitator::Simple(inner) => inner.supported().await,
                EitherFacilitator::Coinbase(inner) => inner.supported().await,
            }
        }
    }
}
