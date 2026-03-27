use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::backends::LightningBackend;
use crate::macaroon;
use crate::rails::traits::{ChallengeFragment, PaymentMode, PaymentRail, RailVerifyResult};
use crate::storage::StorageBackend;
use crate::types::{Currency, PriceInfo, RailError, TollBoothRequest};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub struct L402RailConfig {
    pub root_key: String,
    pub storage: Arc<dyn StorageBackend>,
    pub default_amount: u64,
    pub backend: Option<Arc<dyn LightningBackend>>,
    pub service_name: Option<String>,
}

// ---------------------------------------------------------------------------
// L402 Rail
// ---------------------------------------------------------------------------

pub struct L402Rail {
    root_key: String,
    storage: Arc<dyn StorageBackend>,
    default_amount: u64,
    backend: Option<Arc<dyn LightningBackend>>,
    service_name: Option<String>,
}

impl L402Rail {
    pub fn new(config: L402RailConfig) -> Self {
        Self {
            root_key: config.root_key,
            storage: config.storage,
            default_amount: config.default_amount,
            backend: config.backend,
            service_name: config.service_name,
        }
    }
}

#[async_trait]
impl PaymentRail for L402Rail {
    fn rail_type(&self) -> &str {
        "l402"
    }

    fn credit_supported(&self) -> bool {
        true
    }

    fn detect(&self, req: &TollBoothRequest) -> bool {
        match req.header("authorization") {
            Some(val) => {
                let trimmed = val.trim();
                trimmed.len() > 5
                    && trimmed[..5].eq_ignore_ascii_case("l402 ")
            }
            None => false,
        }
    }

    async fn challenge(&self, route: &str, price: &PriceInfo) -> Result<ChallengeFragment, RailError> {
        let amount = price.sats.unwrap_or(self.default_amount);
        let memo = self.service_name.as_deref().unwrap_or("L402 access");

        // Get invoice + payment_hash: either from a real backend or generate a random hash
        let (bolt11, payment_hash) = if let Some(ref backend) = self.backend {
            let invoice = backend
                .create_invoice(amount, Some(memo))
                .await
                .map_err(|e| RailError::Challenge(e.to_string()))?;
            (invoice.bolt11, invoice.payment_hash)
        } else {
            let mut hash_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut hash_bytes);
            let payment_hash = hex::encode(hash_bytes);
            ("".to_string(), payment_hash)
        };

        // Mint a credit-balance macaroon
        let credit_balance = amount as i64;
        let macaroon_b64 = macaroon::mint_macaroon(
            &self.root_key,
            &payment_hash,
            credit_balance,
            &[],
            Currency::Sat,
        )
        .map_err(|e| RailError::Challenge(e.to_string()))?;

        // Build the WWW-Authenticate header value
        let www_auth = format!(
            "L402 macaroon=\"{macaroon_b64}\", invoice=\"{bolt11}\""
        );

        let mut headers = HashMap::new();
        headers.insert("WWW-Authenticate".to_string(), www_auth);

        let body = serde_json::json!({
            "l402": {
                "scheme": "L402",
                "description": format!("Payment required: {memo}"),
                "invoice": bolt11,
                "macaroon": macaroon_b64,
                "payment_hash": payment_hash,
                "amount_sats": amount,
                "route": route,
            }
        });

        Ok(ChallengeFragment { headers, body })
    }

    async fn verify(&self, req: &TollBoothRequest) -> Result<RailVerifyResult, RailError> {
        let unauthenticated = |payment_id: &str| RailVerifyResult {
            authenticated: false,
            payment_id: payment_id.to_string(),
            mode: PaymentMode::Credit,
            credit_balance: None,
            currency: Currency::Sat,
            custom_caveats: HashMap::new(),
        };

        // 1. Extract Authorization header (case-insensitive)
        let auth_header = match req.header("authorization") {
            Some(val) => val.to_string(),
            None => return Ok(unauthenticated("")),
        };

        // 2. Strip "L402 " prefix (case-insensitive)
        let trimmed = auth_header.trim();
        if trimmed.len() < 5 || !trimmed[..5].eq_ignore_ascii_case("l402 ") {
            return Ok(unauthenticated(""));
        }
        let credentials = &trimmed[5..];

        // 3. Split on LAST colon: <macaroon_b64>:<preimage_hex>
        let last_colon = match credentials.rfind(':') {
            Some(pos) => pos,
            None => return Ok(unauthenticated("")),
        };
        let macaroon_b64 = &credentials[..last_colon];
        let preimage_hex = &credentials[last_colon + 1..];

        // 4. Verify macaroon with context (path, ip)
        let context = macaroon::VerifyContext {
            path: Some(&req.path),
            ip: Some(&req.ip),
            now: None,
        };

        let verify_result = match macaroon::verify_macaroon(&self.root_key, macaroon_b64, Some(&context)) {
            Ok(result) => result,
            Err(_) => return Ok(unauthenticated("")),
        };

        // 5. If macaroon invalid: return unauthenticated
        let payment_hash = match verify_result.payment_hash {
            Some(ref h) => h.clone(),
            None => return Ok(unauthenticated("")),
        };

        if !verify_result.valid {
            return Ok(unauthenticated(&payment_hash));
        }

        let currency = verify_result.currency;

        // 6. Validate preimage: must be 64 hex chars
        if preimage_hex.len() != 64 || !preimage_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Ok(unauthenticated(&payment_hash));
        }

        // Decode the preimage bytes
        let preimage_bytes = hex::decode(preimage_hex)
            .map_err(|_| RailError::Verification("invalid preimage hex".to_string()))?;

        // Decode the expected payment hash bytes
        let expected_hash_bytes = hex::decode(&payment_hash)
            .map_err(|_| RailError::Verification("invalid payment hash hex".to_string()))?;

        // 7. Lightning preimage check: SHA256(preimage_bytes) == payment_hash (timing-safe)
        let computed_hash = Sha256::digest(&preimage_bytes);
        let lightning_valid = computed_hash.as_slice().ct_eq(&expected_hash_bytes).unwrap_u8() == 1;

        // 8. Cashu fallback: if Lightning check fails, check stored settlement secret
        let preimage_valid = if lightning_valid {
            true
        } else {
            let stored_secret = self
                .storage
                .get_settlement_secret(&payment_hash)
                .map_err(|e| RailError::Verification(e.to_string()))?;

            match stored_secret {
                Some(ref secret) => {
                    let secret_bytes = secret.as_bytes();
                    let preimage_str_bytes = preimage_hex.as_bytes();
                    secret_bytes.len() == preimage_str_bytes.len()
                        && secret_bytes.ct_eq(preimage_str_bytes).unwrap_u8() == 1
                }
                None => false,
            }
        };

        // 9. If neither valid: return unauthenticated
        if !preimage_valid {
            return Ok(unauthenticated(&payment_hash));
        }

        // 10. First-time settlement: generate random secret, credit the account
        let is_settled = self
            .storage
            .is_settled(&payment_hash)
            .map_err(|e| RailError::Verification(e.to_string()))?;

        if !is_settled {
            let mut secret_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut secret_bytes);
            let settlement_secret = hex::encode(secret_bytes);

            let credit_amount = verify_result.credit_balance.unwrap_or(0);
            self.storage
                .settle_with_credit(&payment_hash, credit_amount, Some(&settlement_secret), currency)
                .map_err(|e| RailError::Verification(e.to_string()))?;
        }

        // 11. Get remaining balance from storage
        let balance = self
            .storage
            .balance(&payment_hash, currency)
            .map_err(|e| RailError::Verification(e.to_string()))?;

        Ok(RailVerifyResult {
            authenticated: true,
            payment_id: payment_hash,
            mode: PaymentMode::Credit,
            credit_balance: Some(balance),
            currency,
            custom_caveats: verify_result.custom_caveats,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    fn test_root_key() -> String {
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string()
    }

    fn make_request(headers: HashMap<String, String>) -> TollBoothRequest {
        TollBoothRequest {
            method: "GET".to_string(),
            path: "/api/test".to_string(),
            headers,
            ip: "127.0.0.1".to_string(),
            tier: None,
        }
    }

    fn make_rail(storage: Arc<MemoryStorage>) -> L402Rail {
        L402Rail::new(L402RailConfig {
            root_key: test_root_key(),
            storage,
            default_amount: 100,
            backend: None,
            service_name: Some("Test Service".to_string()),
        })
    }

    // -- detect tests --

    #[test]
    fn test_detect_l402_header() {
        let storage = Arc::new(MemoryStorage::new());
        let rail = make_rail(storage);

        // No authorization header -> false
        let req_none = make_request(HashMap::new());
        assert!(!rail.detect(&req_none));

        // With "L402 abc:def" -> true
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "L402 abc:def".to_string());
        let req_l402 = make_request(headers);
        assert!(rail.detect(&req_l402));

        // Case-insensitive: "l402 abc:def" -> true
        let mut headers_lower = HashMap::new();
        headers_lower.insert("authorization".to_string(), "l402 abc:def".to_string());
        let req_lower = make_request(headers_lower);
        assert!(rail.detect(&req_lower));

        // Wrong scheme -> false
        let mut headers_bearer = HashMap::new();
        headers_bearer.insert("Authorization".to_string(), "Bearer token123".to_string());
        let req_bearer = make_request(headers_bearer);
        assert!(!rail.detect(&req_bearer));
    }

    // -- challenge tests --

    #[tokio::test]
    async fn test_challenge_without_backend() {
        let storage = Arc::new(MemoryStorage::new());
        let rail = make_rail(storage);
        let price = PriceInfo::sats(50);

        let fragment = rail.challenge("/api/test", &price).await.unwrap();

        // Should have WWW-Authenticate header containing "L402" and "macaroon="
        let www_auth = fragment.headers.get("WWW-Authenticate").expect("missing WWW-Authenticate");
        assert!(www_auth.starts_with("L402 "), "header must start with 'L402 '");
        assert!(www_auth.contains("macaroon="), "header must contain macaroon=");
        assert!(www_auth.contains("invoice="), "header must contain invoice=");

        // Body should have l402 object
        let l402 = fragment.body.get("l402").expect("missing l402 body");
        assert_eq!(l402.get("scheme").and_then(|v| v.as_str()), Some("L402"));
        assert_eq!(l402.get("amount_sats").and_then(|v| v.as_u64()), Some(50));
        assert_eq!(l402.get("route").and_then(|v| v.as_str()), Some("/api/test"));

        // payment_hash should be a 64-char hex string
        let ph = l402.get("payment_hash").and_then(|v| v.as_str()).unwrap();
        assert_eq!(ph.len(), 64);
        assert!(ph.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // -- verify tests --

    /// Helper: create a known preimage, compute its SHA256 as the payment hash,
    /// mint a macaroon, and return (payment_hash, preimage_hex, macaroon_b64).
    fn make_valid_credentials(credit_balance: i64) -> (String, String, String) {
        // Known preimage
        let mut preimage_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut preimage_bytes);
        let preimage_hex = hex::encode(preimage_bytes);

        // Compute SHA256 hash
        let payment_hash_bytes = Sha256::digest(&preimage_bytes);
        let payment_hash = hex::encode(payment_hash_bytes);

        // Mint macaroon
        let macaroon_b64 = macaroon::mint_macaroon(
            &test_root_key(),
            &payment_hash,
            credit_balance,
            &[],
            Currency::Sat,
        )
        .unwrap();

        (payment_hash, preimage_hex, macaroon_b64)
    }

    #[tokio::test]
    async fn test_verify_valid_preimage() {
        let storage = Arc::new(MemoryStorage::new());
        let rail = make_rail(storage);

        let (payment_hash, preimage_hex, macaroon_b64) = make_valid_credentials(1000);

        // Build request with Authorization header
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            format!("L402 {macaroon_b64}:{preimage_hex}"),
        );
        let req = make_request(headers);

        let result = rail.verify(&req).await.unwrap();
        assert!(result.authenticated, "valid preimage should authenticate");
        assert_eq!(result.payment_id, payment_hash);
        assert_eq!(result.mode, PaymentMode::Credit);
        assert_eq!(result.credit_balance, Some(1000));
        assert_eq!(result.currency, Currency::Sat);
    }

    #[tokio::test]
    async fn test_verify_wrong_preimage() {
        let storage = Arc::new(MemoryStorage::new());
        let rail = make_rail(storage);

        // Create valid credentials but use a different preimage for verification
        let (payment_hash, _correct_preimage, macaroon_b64) = make_valid_credentials(500);

        // Wrong preimage (all zeros)
        let wrong_preimage = "0000000000000000000000000000000000000000000000000000000000000000";

        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            format!("L402 {macaroon_b64}:{wrong_preimage}"),
        );
        let req = make_request(headers);

        let result = rail.verify(&req).await.unwrap();
        assert!(!result.authenticated, "wrong preimage must not authenticate");
        assert_eq!(result.payment_id, payment_hash);
    }

    #[tokio::test]
    async fn test_verify_settlement_secret() {
        let storage = Arc::new(MemoryStorage::new());
        let rail = make_rail(storage.clone());

        // Create a known payment hash and settlement secret
        let payment_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let settlement_secret = "deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233";

        // Pre-settle with the known secret
        storage
            .settle_with_credit(payment_hash, 2000, Some(settlement_secret), Currency::Sat)
            .unwrap();

        // Mint a macaroon for this payment hash
        let macaroon_b64 = macaroon::mint_macaroon(
            &test_root_key(),
            payment_hash,
            2000,
            &[],
            Currency::Sat,
        )
        .unwrap();

        // Use the settlement secret as the "preimage" (Cashu fallback path)
        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            format!("L402 {macaroon_b64}:{settlement_secret}"),
        );
        let req = make_request(headers);

        let result = rail.verify(&req).await.unwrap();
        assert!(result.authenticated, "settlement secret should authenticate via Cashu fallback");
        assert_eq!(result.payment_id, payment_hash);
        assert_eq!(result.credit_balance, Some(2000));
    }

    #[tokio::test]
    async fn test_verify_replay_still_works() {
        let storage = Arc::new(MemoryStorage::new());
        let rail = make_rail(storage);

        let (_payment_hash, preimage_hex, macaroon_b64) = make_valid_credentials(500);

        let mut headers = HashMap::new();
        headers.insert(
            "Authorization".to_string(),
            format!("L402 {macaroon_b64}:{preimage_hex}"),
        );
        let req = make_request(headers);

        // First verification: settles and credits
        let result1 = rail.verify(&req).await.unwrap();
        assert!(result1.authenticated);
        assert_eq!(result1.credit_balance, Some(500));

        // Second verification: already settled, should still authenticate
        let result2 = rail.verify(&req).await.unwrap();
        assert!(result2.authenticated, "replay should still authenticate (reads existing balance)");
        assert_eq!(result2.credit_balance, Some(500));
    }

    #[tokio::test]
    async fn test_verify_no_auth_header() {
        let storage = Arc::new(MemoryStorage::new());
        let rail = make_rail(storage);

        let req = make_request(HashMap::new());
        let result = rail.verify(&req).await.unwrap();
        assert!(!result.authenticated);
    }

    #[tokio::test]
    async fn test_verify_malformed_credentials() {
        let storage = Arc::new(MemoryStorage::new());
        let rail = make_rail(storage);

        // No colon separator
        let mut headers = HashMap::new();
        headers.insert("Authorization".to_string(), "L402 justabigblob".to_string());
        let req = make_request(headers);
        let result = rail.verify(&req).await.unwrap();
        assert!(!result.authenticated);

        // Preimage too short
        let mut headers2 = HashMap::new();
        headers2.insert("Authorization".to_string(), "L402 mac:abc123".to_string());
        let req2 = make_request(headers2);
        let result2 = rail.verify(&req2).await.unwrap();
        assert!(!result2.authenticated);
    }

    #[tokio::test]
    async fn test_challenge_uses_default_amount() {
        let storage = Arc::new(MemoryStorage::new());
        let rail = make_rail(storage);

        // Price with no sats field
        let price = PriceInfo { sats: None, usd: Some(100) };

        let fragment = rail.challenge("/api/test", &price).await.unwrap();
        let l402 = fragment.body.get("l402").unwrap();
        // Should fall back to default_amount (100 sats)
        assert_eq!(l402.get("amount_sats").and_then(|v| v.as_u64()), Some(100));
    }

    #[test]
    fn test_rail_type_and_credit_supported() {
        let storage = Arc::new(MemoryStorage::new());
        let rail = make_rail(storage);
        assert_eq!(rail.rail_type(), "l402");
        assert!(rail.credit_supported());
    }
}
