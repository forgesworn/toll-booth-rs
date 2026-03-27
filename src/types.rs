use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

// --- Currency ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Currency {
    #[default]
    Sat,
    Usd,
}

// --- Pricing ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriceInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sats: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usd: Option<u64>,
}

impl PriceInfo {
    pub fn sats(amount: u64) -> Self {
        PriceInfo {
            sats: Some(amount),
            usd: None,
        }
    }

    pub fn usd(amount: u64) -> Self {
        PriceInfo {
            sats: None,
            usd: Some(amount),
        }
    }

    pub fn amount_for(&self, currency: Currency) -> u64 {
        match currency {
            Currency::Sat => self.sats.unwrap_or(0),
            Currency::Usd => self.usd.unwrap_or(0),
        }
    }
}

// --- Tiered pricing ---

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PricingEntry {
    Simple(u64),
    Detailed(PriceInfo),
    Tiered(HashMap<String, u64>),
}

impl PricingEntry {
    pub fn normalise(&self) -> PriceInfo {
        match self {
            PricingEntry::Simple(sats) => PriceInfo::sats(*sats),
            PricingEntry::Detailed(info) => info.clone(),
            PricingEntry::Tiered(tiers) => {
                let default = tiers.get("default").copied().unwrap_or(0);
                PriceInfo::sats(default)
            }
        }
    }

    pub fn is_tiered(&self) -> bool {
        matches!(self, PricingEntry::Tiered(_))
    }

    pub fn tier_price(&self, tier: &str) -> Option<PriceInfo> {
        match self {
            PricingEntry::Tiered(tiers) => tiers.get(tier).map(|s| PriceInfo::sats(*s)),
            _ => None,
        }
    }
}

pub type PricingTable = HashMap<String, PricingEntry>;

// --- Request / Result ---

#[derive(Debug, Clone)]
pub struct TollBoothRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub ip: String,
    pub tier: Option<String>,
}

impl TollBoothRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Clone)]
pub enum TollBoothResult {
    Proxy {
        upstream: String,
        headers: HashMap<String, String>,
        payment_hash: Option<String>,
        estimated_cost: Option<u64>,
        credit_balance: Option<i64>,
        free_remaining: Option<u64>,
        tier: Option<String>,
    },
    Challenge {
        status: u16,
        headers: HashMap<String, String>,
        body: serde_json::Value,
    },
    Pass {
        upstream: String,
        headers: HashMap<String, String>,
    },
    Blocked {
        status: u16,
        body: serde_json::Value,
    },
}

// --- Invoice types ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invoice {
    pub bolt11: String,
    pub payment_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvoiceStatus {
    pub paid: bool,
    pub preimage: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredInvoice {
    pub payment_hash: String,
    pub bolt11: String,
    pub amount_sats: u64,
    pub macaroon: String,
    pub status_token: String,
    pub created_at: String,
    pub client_ip: Option<String>,
}

// --- Debit result ---

#[derive(Debug, Clone)]
pub struct DebitResult {
    pub success: bool,
    pub remaining: i64,
}

// --- Reconcile result ---

#[derive(Debug, Clone)]
pub struct ReconcileResult {
    pub adjusted: bool,
    pub new_balance: i64,
    pub delta: i64,
}

// --- Payment hash validation ---

pub fn is_valid_payment_hash(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

// --- IP hashing ---

pub fn hash_ip(ip: &str) -> String {
    use sha2::{Digest, Sha256};
    let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
    let mut hasher = Sha256::new();
    hasher.update(format!("{today}:{ip}").as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..16])
}

// --- Tier validation ---

pub fn is_valid_tier(tier: &str) -> bool {
    !tier.is_empty()
        && tier.len() <= 32
        && tier
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
}

// --- Errors ---

#[derive(Debug, Error)]
pub enum TollBoothError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("backend error: {0}")]
    Backend(#[from] BackendError),
    #[error("rail error: {0}")]
    Rail(#[from] RailError),
    #[error("configuration error: {0}")]
    Config(String),
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(String),
    #[error("not found: {0}")]
    NotFound(String),
}

#[derive(Debug, Error)]
pub enum BackendError {
    #[error("backend request failed: {0}")]
    Request(String),
    #[error("invoice not found")]
    NotFound,
    #[error("operation not supported")]
    NotSupported,
}

#[derive(Debug, Error)]
pub enum RailError {
    #[error("challenge generation failed: {0}")]
    Challenge(String),
    #[error("verification failed: {0}")]
    Verification(String),
}

#[derive(Debug, Error)]
pub enum MacaroonError {
    #[error("invalid root key")]
    InvalidRootKey,
    #[error("invalid payment hash")]
    InvalidPaymentHash,
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),
    #[error("invalid caveat: {0}")]
    InvalidCaveat(String),
}
