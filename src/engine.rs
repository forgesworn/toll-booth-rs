use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand::RngCore;

use crate::free_tier::{CreditFreeTier, FreeTier, IFreeTier};
use crate::rails::{PaymentMode, PaymentRail};
use crate::storage::{MemoryStorage, StorageBackend};
use crate::types::{
    hash_ip, is_valid_tier, Currency, PriceInfo, PricingEntry, ReconcileResult, StoredInvoice,
    TollBoothError, TollBoothRequest, TollBoothResult,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// How to allocate free-tier quota.
#[derive(Debug, Clone)]
pub enum FreeTierConfig {
    /// N free requests per day per IP.
    Requests(u64),
    /// N free credits (sats) per day per IP.
    Credits(u64),
}

/// Top-level configuration for TollBoothEngine.
pub struct TollBoothConfig {
    pub storage: Arc<dyn StorageBackend>,
    pub pricing: HashMap<String, PricingEntry>,
    pub upstream: String,
    pub root_key: String,
    pub rails: Vec<Box<dyn PaymentRail>>,
    pub free_tier: Option<FreeTierConfig>,
    pub service_name: Option<String>,
}

impl Default for TollBoothConfig {
    fn default() -> Self {
        TollBoothConfig {
            storage: Arc::new(MemoryStorage::new()),
            pricing: HashMap::new(),
            upstream: String::new(),
            root_key: String::new(),
            rails: Vec::new(),
            free_tier: None,
            service_name: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Estimated cost tracking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct EstimatedCost {
    cost: u64,
    currency: Currency,
    timestamp: Instant,
}

const MAX_ESTIMATED_ENTRIES: usize = 10_000;
const ESTIMATED_TTL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// TollBoothEngine
// ---------------------------------------------------------------------------

pub struct TollBoothEngine {
    config: TollBoothConfig,
    free_tier: Option<Box<dyn IFreeTier>>,
    estimated_costs: Mutex<HashMap<String, EstimatedCost>>,
}

impl TollBoothEngine {
    pub fn new(config: TollBoothConfig) -> Result<Self, TollBoothError> {
        let free_tier: Option<Box<dyn IFreeTier>> = config.free_tier.as_ref().map(|ft| {
            match ft {
                FreeTierConfig::Requests(n) => Box::new(FreeTier::new(*n)) as Box<dyn IFreeTier>,
                FreeTierConfig::Credits(n) => {
                    Box::new(CreditFreeTier::new(*n)) as Box<dyn IFreeTier>
                }
            }
        });

        Ok(TollBoothEngine {
            config,
            free_tier,
            estimated_costs: Mutex::new(HashMap::new()),
        })
    }

    /// Main request handler. Orchestrates the full payment verification flow.
    pub async fn handle(&self, req: &TollBoothRequest) -> TollBoothResult {
        // 1. Check if route is priced
        let pricing_entry = match self.config.pricing.get(&req.path) {
            Some(entry) => entry,
            None => {
                return TollBoothResult::Pass {
                    upstream: self.config.upstream.clone(),
                    headers: HashMap::new(),
                };
            }
        };

        // 2. Resolve price (with tier support)
        let price = if pricing_entry.is_tiered() {
            match &req.tier {
                Some(tier) => {
                    if !is_valid_tier(tier) {
                        // Invalid tier key format -- return 402 challenge
                        return self.build_challenge(&req.path, &pricing_entry.normalise()).await;
                    }
                    match pricing_entry.tier_price(tier) {
                        Some(p) => p,
                        None => {
                            // Tier not found -- return 402 challenge
                            return self
                                .build_challenge(&req.path, &pricing_entry.normalise())
                                .await;
                        }
                    }
                }
                None => pricing_entry.normalise(),
            }
        } else {
            pricing_entry.normalise()
        };

        let route_cost = price.sats.unwrap_or(0);

        // 3. HEAD request? Return 402 with price headers, no invoices
        if req.method.eq_ignore_ascii_case("HEAD") {
            let mut headers = HashMap::new();
            if let Some(sats) = price.sats {
                headers.insert("X-L402-Price-Sats".to_string(), sats.to_string());
            }
            if let Some(usd) = price.usd {
                headers.insert("X-L402-Price-Usd".to_string(), usd.to_string());
            }
            return TollBoothResult::Challenge {
                status: 402,
                headers,
                body: serde_json::json!({
                    "price": {
                        "sats": price.sats,
                        "usd": price.usd,
                    }
                }),
            };
        }

        // 4. Iterate payment rails
        for rail in &self.config.rails {
            if !rail.detect(req) {
                continue;
            }

            let verify_result = match rail.verify(req).await {
                Ok(r) => r,
                Err(_) => break,
            };

            if verify_result.authenticated {
                let payment_hash = verify_result.payment_id.clone();
                let currency = verify_result.currency;

                // Handle payment mode
                match verify_result.mode {
                    PaymentMode::Credit => {
                        if route_cost > 0 {
                            let debit_result = match self.config.storage.debit(
                                &payment_hash,
                                route_cost as i64,
                                currency,
                            ) {
                                Ok(r) => r,
                                Err(_) => break,
                            };
                            if !debit_result.success {
                                // Insufficient balance -- fall through to challenge
                                break;
                            }

                            // Track estimated cost
                            self.track_estimated_cost(
                                &payment_hash,
                                route_cost,
                                currency,
                            );

                            // Build response headers
                            let mut headers = HashMap::new();
                            headers.insert(
                                "X-Credit-Balance".to_string(),
                                debit_result.remaining.to_string(),
                            );

                            if let Some(ref tier) = req.tier {
                                headers.insert("X-Toll-Tier".to_string(), tier.clone());
                            }

                            // Add custom caveat headers
                            for (key, value) in &verify_result.custom_caveats {
                                headers.insert(
                                    format!("X-Toll-Caveat-{}", capitalise_header(key)),
                                    value.clone(),
                                );
                            }

                            return TollBoothResult::Proxy {
                                upstream: self.config.upstream.clone(),
                                headers,
                                payment_hash: Some(payment_hash),
                                estimated_cost: Some(route_cost),
                                credit_balance: Some(debit_result.remaining),
                                free_remaining: None,
                                tier: req.tier.clone(),
                            };
                        } else {
                            // Zero-cost route with valid auth
                            let balance = verify_result.credit_balance.unwrap_or(0);
                            let mut headers = HashMap::new();
                            headers.insert(
                                "X-Credit-Balance".to_string(),
                                balance.to_string(),
                            );

                            return TollBoothResult::Proxy {
                                upstream: self.config.upstream.clone(),
                                headers,
                                payment_hash: Some(payment_hash),
                                estimated_cost: Some(0),
                                credit_balance: Some(balance),
                                free_remaining: None,
                                tier: req.tier.clone(),
                            };
                        }
                    }
                    PaymentMode::PerRequest | PaymentMode::Session => {
                        let settled = match self.config.storage.settle(&payment_hash) {
                            Ok(s) => s,
                            Err(_) => break,
                        };
                        if !settled {
                            // Already settled (replay) -- fall through to challenge
                            break;
                        }

                        self.track_estimated_cost(&payment_hash, route_cost, currency);

                        let mut headers = HashMap::new();
                        if let Some(ref tier) = req.tier {
                            headers.insert("X-Toll-Tier".to_string(), tier.clone());
                        }
                        for (key, value) in &verify_result.custom_caveats {
                            headers.insert(
                                format!("X-Toll-Caveat-{}", capitalise_header(key)),
                                value.clone(),
                            );
                        }

                        return TollBoothResult::Proxy {
                            upstream: self.config.upstream.clone(),
                            headers,
                            payment_hash: Some(payment_hash),
                            estimated_cost: Some(route_cost),
                            credit_balance: None,
                            free_remaining: None,
                            tier: req.tier.clone(),
                        };
                    }
                }
            } else {
                // Rail detected but auth failed -- break to challenge
                break;
            }
        }

        // 5. Free tier check (only if no rail was detected or auth failed)
        if let Some(ref free_tier) = self.free_tier {
            let hashed_ip = hash_ip(&req.ip);
            let result = free_tier.check(&hashed_ip, route_cost);
            if result.allowed {
                let mut headers = HashMap::new();
                headers.insert(
                    "X-Free-Remaining".to_string(),
                    result.remaining.to_string(),
                );
                return TollBoothResult::Proxy {
                    upstream: self.config.upstream.clone(),
                    headers,
                    payment_hash: None,
                    estimated_cost: None,
                    credit_balance: None,
                    free_remaining: Some(result.remaining),
                    tier: None,
                };
            }
        }

        // 6. Generate challenges from all rails
        self.build_challenge(&req.path, &price).await
    }

    /// Reconcile estimated vs actual cost after the upstream responds.
    pub fn reconcile(&self, payment_hash: &str, actual_cost: u64) -> ReconcileResult {
        let estimated = {
            let map = self.estimated_costs.lock().unwrap();
            map.get(payment_hash).cloned()
        };

        match estimated {
            None => ReconcileResult {
                adjusted: false,
                new_balance: 0,
                delta: 0,
            },
            Some(est) => {
                let delta = est.cost as i64 - actual_cost as i64;
                if delta == 0 {
                    return ReconcileResult {
                        adjusted: false,
                        new_balance: 0,
                        delta: 0,
                    };
                }

                // Refund the difference (positive delta means we overcharged)
                match self
                    .config
                    .storage
                    .adjust_credits(payment_hash, delta, est.currency)
                {
                    Ok(new_balance) => ReconcileResult {
                        adjusted: true,
                        new_balance,
                        delta,
                    },
                    Err(_) => ReconcileResult {
                        adjusted: false,
                        new_balance: 0,
                        delta: 0,
                    },
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn track_estimated_cost(&self, payment_hash: &str, cost: u64, currency: Currency) {
        let mut map = self.estimated_costs.lock().unwrap();

        // Auto-evict expired entries when approaching capacity
        if map.len() >= MAX_ESTIMATED_ENTRIES {
            let now = Instant::now();
            map.retain(|_, v| now.duration_since(v.timestamp) < ESTIMATED_TTL);
        }

        map.insert(
            payment_hash.to_string(),
            EstimatedCost {
                cost,
                currency,
                timestamp: Instant::now(),
            },
        );
    }

    async fn build_challenge(&self, route: &str, price: &PriceInfo) -> TollBoothResult {
        let mut all_www_auth: Vec<String> = Vec::new();
        let mut body = serde_json::Map::new();

        for rail in &self.config.rails {
            match rail.challenge(route, price).await {
                Ok(fragment) => {
                    // Collect WWW-Authenticate values
                    if let Some(www_auth) = fragment.headers.get("WWW-Authenticate") {
                        all_www_auth.push(www_auth.clone());
                    }

                    // Merge body fragments
                    if let serde_json::Value::Object(map) = fragment.body {
                        for (k, v) in map {
                            body.insert(k, v);
                        }
                    }
                }
                Err(_) => continue,
            }
        }

        // Store invoice metadata if present in body
        if let Some(l402_body) = body.get("l402") {
            let payment_hash = l402_body
                .get("payment_hash")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let bolt11 = l402_body
                .get("invoice")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let macaroon = l402_body
                .get("macaroon")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let amount_sats = l402_body
                .get("amount_sats")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if !payment_hash.is_empty() {
                let mut status_token_bytes = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut status_token_bytes);
                let status_token = hex::encode(status_token_bytes);

                let invoice = StoredInvoice {
                    payment_hash: payment_hash.to_string(),
                    bolt11: bolt11.to_string(),
                    amount_sats,
                    macaroon: macaroon.to_string(),
                    status_token,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    client_ip: None,
                };

                let _ = self.config.storage.store_invoice(&invoice);
            }
        }

        let mut headers = HashMap::new();
        if !all_www_auth.is_empty() {
            headers.insert("WWW-Authenticate".to_string(), all_www_auth.join(", "));
        }

        TollBoothResult::Challenge {
            status: 402,
            headers,
            body: serde_json::Value::Object(body),
        }
    }
}

/// Capitalise a header segment: "app_id" -> "App-Id"
fn capitalise_header(key: &str) -> String {
    key.split('_')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(c) => {
                    let upper: String = c.to_uppercase().collect();
                    format!("{}{}", upper, chars.collect::<String>())
                }
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join("-")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macaroon;
    use crate::rails::{L402Rail, L402RailConfig};
    use crate::storage::MemoryStorage;
    use crate::types::Currency;
    use sha2::{Digest, Sha256};

    fn test_root_key() -> String {
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2".to_string()
    }

    fn make_engine(free_requests: Option<u64>) -> TollBoothEngine {
        let storage: Arc<dyn StorageBackend> = Arc::new(MemoryStorage::new());
        let l402 = L402Rail::new(L402RailConfig {
            root_key: test_root_key(),
            storage: storage.clone(),
            default_amount: 100,
            backend: None,
            service_name: None,
        });
        let mut pricing = HashMap::new();
        pricing.insert("/api/test".to_string(), PricingEntry::Simple(100));
        TollBoothEngine::new(TollBoothConfig {
            storage,
            pricing,
            upstream: "http://localhost:8080".into(),
            root_key: test_root_key(),
            rails: vec![Box::new(l402)],
            free_tier: free_requests.map(FreeTierConfig::Requests),
            ..Default::default()
        })
        .unwrap()
    }

    fn make_l402_auth_header(credit_balance: i64) -> (String, String, String) {
        let preimage_bytes = [0xABu8; 32];
        let preimage_hex = hex::encode(preimage_bytes);
        let payment_hash = hex::encode(Sha256::digest(preimage_bytes));
        let macaroon_b64 = macaroon::mint_macaroon(
            &test_root_key(),
            &payment_hash,
            credit_balance,
            &[],
            Currency::Sat,
        )
        .unwrap();
        let header_value = format!("L402 {macaroon_b64}:{preimage_hex}");
        (header_value, payment_hash, preimage_hex)
    }

    fn make_request(method: &str, path: &str, auth: Option<&str>) -> TollBoothRequest {
        let mut headers = HashMap::new();
        if let Some(auth_val) = auth {
            headers.insert("Authorization".to_string(), auth_val.to_string());
        }
        TollBoothRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers,
            ip: "127.0.0.1".to_string(),
            tier: None,
        }
    }

    // -- Test 1: unpriced route passes through --

    #[tokio::test]
    async fn test_unpriced_route_passes_through() {
        let engine = make_engine(None);
        let req = make_request("GET", "/unpriced", None);
        let result = engine.handle(&req).await;

        match result {
            TollBoothResult::Pass { upstream, headers } => {
                assert_eq!(upstream, "http://localhost:8080");
                assert!(headers.is_empty());
            }
            other => panic!("expected Pass, got {:?}", other),
        }
    }

    // -- Test 2: priced route returns 402 --

    #[tokio::test]
    async fn test_priced_route_returns_402() {
        let engine = make_engine(None);
        let req = make_request("GET", "/api/test", None);
        let result = engine.handle(&req).await;

        match result {
            TollBoothResult::Challenge { status, headers, .. } => {
                assert_eq!(status, 402);
                assert!(
                    headers.contains_key("WWW-Authenticate"),
                    "402 response must include WWW-Authenticate header"
                );
            }
            other => panic!("expected Challenge, got {:?}", other),
        }
    }

    // -- Test 3: free tier allows then blocks --

    #[tokio::test]
    async fn test_free_tier_allows_then_blocks() {
        let engine = make_engine(Some(2));

        let req = make_request("GET", "/api/test", None);

        // First request -- allowed
        let r1 = engine.handle(&req).await;
        assert!(
            matches!(r1, TollBoothResult::Proxy { .. }),
            "1st free request should proxy"
        );

        // Second request -- allowed
        let r2 = engine.handle(&req).await;
        assert!(
            matches!(r2, TollBoothResult::Proxy { .. }),
            "2nd free request should proxy"
        );

        // Third request -- blocked (402)
        let r3 = engine.handle(&req).await;
        match r3 {
            TollBoothResult::Challenge { status, .. } => {
                assert_eq!(status, 402, "3rd request should return 402");
            }
            other => panic!("expected Challenge for 3rd request, got {:?}", other),
        }
    }

    // -- Test 4: HEAD returns price headers --

    #[tokio::test]
    async fn test_head_returns_price_headers() {
        let engine = make_engine(None);
        let req = make_request("HEAD", "/api/test", None);
        let result = engine.handle(&req).await;

        match result {
            TollBoothResult::Challenge {
                status, headers, ..
            } => {
                assert_eq!(status, 402);
                assert_eq!(
                    headers.get("X-L402-Price-Sats").map(|s| s.as_str()),
                    Some("100"),
                    "HEAD response must include X-L402-Price-Sats"
                );
            }
            other => panic!("expected Challenge for HEAD, got {:?}", other),
        }
    }

    // -- Test 5: valid L402 auth proxies --

    #[tokio::test]
    async fn test_valid_l402_auth_proxies() {
        let engine = make_engine(None);
        let (auth_header, payment_hash, _) = make_l402_auth_header(1000);
        let req = make_request("GET", "/api/test", Some(&auth_header));
        let result = engine.handle(&req).await;

        match result {
            TollBoothResult::Proxy {
                upstream,
                payment_hash: ph,
                credit_balance,
                ..
            } => {
                assert_eq!(upstream, "http://localhost:8080");
                assert_eq!(ph, Some(payment_hash));
                // Started with 1000, debited 100 -> 900
                assert_eq!(credit_balance, Some(900));
            }
            other => panic!("expected Proxy, got {:?}", other),
        }
    }

    // -- Test 6: insufficient credit returns 402 --

    #[tokio::test]
    async fn test_insufficient_credit_returns_402() {
        let engine = make_engine(None);
        // Mint with only 50 sats credit -- route costs 100
        let (auth_header, _, _) = make_l402_auth_header(50);
        let req = make_request("GET", "/api/test", Some(&auth_header));
        let result = engine.handle(&req).await;

        match result {
            TollBoothResult::Challenge { status, .. } => {
                assert_eq!(status, 402, "insufficient credit should return 402");
            }
            other => panic!("expected Challenge for insufficient credit, got {:?}", other),
        }
    }

    // -- Test 7: reconcile --

    #[tokio::test]
    async fn test_reconcile() {
        let engine = make_engine(None);
        let (auth_header, payment_hash, _) = make_l402_auth_header(1000);

        // Authenticate and debit 100 (route cost)
        let req = make_request("GET", "/api/test", Some(&auth_header));
        let result = engine.handle(&req).await;
        assert!(
            matches!(result, TollBoothResult::Proxy { .. }),
            "should proxy with valid auth"
        );

        // Reconcile: actual cost was 50, we charged 100, so refund 50
        let reconcile_result = engine.reconcile(&payment_hash, 50);
        assert!(reconcile_result.adjusted, "should adjust");
        assert_eq!(reconcile_result.delta, 50, "delta should be 50 (overcharged)");
        // Balance was 900 after debit, + 50 refund = 950
        assert_eq!(reconcile_result.new_balance, 950);
    }

    // -- Test 8: 402 body contains invoice data --

    #[tokio::test]
    async fn test_402_body_contains_invoice_data() {
        let engine = make_engine(None);
        let req = make_request("GET", "/api/test", None);
        let result = engine.handle(&req).await;

        match result {
            TollBoothResult::Challenge { body, .. } => {
                let l402 = body.get("l402").expect("body must contain l402 object");
                assert!(
                    l402.get("payment_hash").and_then(|v| v.as_str()).is_some(),
                    "body must contain l402.payment_hash"
                );
                assert!(
                    l402.get("macaroon").and_then(|v| v.as_str()).is_some(),
                    "body must contain l402.macaroon"
                );
                assert!(
                    l402.get("amount_sats").and_then(|v| v.as_u64()).is_some(),
                    "body must contain l402.amount_sats"
                );
            }
            other => panic!("expected Challenge, got {:?}", other),
        }
    }

    // -- Test 9: multiple requests debit correctly --

    #[tokio::test]
    async fn test_multiple_requests_debit_correctly() {
        let engine = make_engine(None);
        let (auth_header, _, _) = make_l402_auth_header(1000);

        // Request 1: 1000 - 100 = 900
        let req = make_request("GET", "/api/test", Some(&auth_header));
        let r1 = engine.handle(&req).await;
        match r1 {
            TollBoothResult::Proxy { credit_balance, .. } => {
                assert_eq!(credit_balance, Some(900), "after 1st debit: 1000 - 100 = 900");
            }
            other => panic!("expected Proxy for request 1, got {:?}", other),
        }

        // Request 2: 900 - 100 = 800
        let r2 = engine.handle(&req).await;
        match r2 {
            TollBoothResult::Proxy { credit_balance, .. } => {
                assert_eq!(credit_balance, Some(800), "after 2nd debit: 900 - 100 = 800");
            }
            other => panic!("expected Proxy for request 2, got {:?}", other),
        }

        // Request 3: 800 - 100 = 700
        let r3 = engine.handle(&req).await;
        match r3 {
            TollBoothResult::Proxy { credit_balance, .. } => {
                assert_eq!(credit_balance, Some(700), "after 3rd debit: 800 - 100 = 700");
            }
            other => panic!("expected Proxy for request 3, got {:?}", other),
        }
    }

    // -- Bonus: free tier sets X-Free-Remaining header --

    #[tokio::test]
    async fn test_free_tier_proxy_has_remaining_header() {
        let engine = make_engine(Some(5));
        let req = make_request("GET", "/api/test", None);
        let result = engine.handle(&req).await;

        match result {
            TollBoothResult::Proxy {
                free_remaining,
                headers,
                ..
            } => {
                assert!(free_remaining.is_some(), "free_remaining should be set");
                assert!(
                    headers.contains_key("X-Free-Remaining"),
                    "should have X-Free-Remaining header"
                );
            }
            other => panic!("expected Proxy, got {:?}", other),
        }
    }

    // -- Bonus: capitalise_header helper --

    #[test]
    fn test_capitalise_header() {
        assert_eq!(capitalise_header("app_id"), "App-Id");
        assert_eq!(capitalise_header("tier"), "Tier");
        assert_eq!(capitalise_header("my_long_key"), "My-Long-Key");
    }
}
