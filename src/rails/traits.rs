use crate::types::{Currency, PriceInfo, RailError, TollBoothRequest};
use async_trait::async_trait;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ChallengeFragment {
    pub headers: HashMap<String, String>,
    pub body: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct RailVerifyResult {
    pub authenticated: bool,
    pub payment_id: String,
    pub mode: PaymentMode,
    pub credit_balance: Option<i64>,
    pub currency: Currency,
    pub custom_caveats: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PaymentMode {
    PerRequest,
    Credit,
    Session,
}

#[async_trait]
pub trait PaymentRail: Send + Sync {
    fn rail_type(&self) -> &str;
    fn credit_supported(&self) -> bool;
    fn detect(&self, req: &TollBoothRequest) -> bool;
    async fn challenge(
        &self,
        route: &str,
        price: &PriceInfo,
    ) -> Result<ChallengeFragment, RailError>;
    async fn verify(&self, req: &TollBoothRequest) -> Result<RailVerifyResult, RailError>;
}
