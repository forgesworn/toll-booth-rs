use crate::types::{BackendError, Invoice, InvoiceStatus};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct PaymentResult {
    pub preimage: String,
}

// async_trait adds #[must_use] to the boxed futures it returns; Clippy 1.99 flags that as double_must_use.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait LightningBackend: Send + Sync {
    async fn create_invoice(
        &self,
        amount_sats: u64,
        memo: Option<&str>,
    ) -> Result<Invoice, BackendError>;
    async fn check_invoice(&self, payment_hash: &str) -> Result<InvoiceStatus, BackendError>;
    async fn send_payment(&self, _bolt11: &str) -> Result<PaymentResult, BackendError> {
        Err(BackendError::NotSupported)
    }
}
