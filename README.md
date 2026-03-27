# toll-booth

L402 payment middleware for Rust. Gates any HTTP API behind Lightning payments using a bring-your-own-backend, bring-your-own-storage model. Works as a Tower `Layer`, so it drops straight into axum.

One Lightning payment funds multiple API calls. The engine tracks credit balances, debits per request, and re-challenges when the balance runs out. Supports free tiers, tiered pricing, cost reconciliation, and custom macaroon caveats.

## Why toll-booth?

- **Credit-balance model** -- one payment buys N requests, not one. Clients top up and keep calling.
- **Cost reconciliation** -- adjust credits after the upstream responds if actual cost differed from estimate.
- **Free tier** -- configurable free requests or free credits per IP per day, with hashed IPs and daily rotation.
- **Tiered pricing** -- different prices per route per tier, selected by `X-Toll-Tier` header.
- **Pluggable everything** -- bring your own Lightning backend, storage backend, and payment rails.
- **Security defaults** -- constant-time HMAC and preimage verification, overflow-checked arithmetic, daily-salted IP hashing.

## Quick start

```toml
[dependencies]
toll-booth = { version = "0.1", features = ["l402", "axum-middleware"] }
```

```rust
use std::sync::Arc;
use toll_booth::{
    TollBoothEngine, TollBoothConfig,
    L402Rail, L402RailConfig,
    MemoryStorage,
    TollBoothLayer,
    PricingEntry,
};

async fn handler() -> &'static str {
    "Hello from the paid API"
}

#[tokio::main]
async fn main() {
    let storage = Arc::new(MemoryStorage::new());

    let l402 = L402Rail::new(L402RailConfig {
        root_key: std::env::var("L402_ROOT_KEY").unwrap(),
        storage: storage.clone(),
        default_amount: 100,        // sats, used when no backend is attached
        backend: None,              // swap in PhoenixdBackend or similar
        service_name: Some("My API".to_string()),
    });

    let mut pricing = std::collections::HashMap::new();
    pricing.insert("/v1/chat/completions".to_string(), PricingEntry::Simple(100));

    let engine = TollBoothEngine::new(TollBoothConfig {
        storage,
        pricing,
        upstream: "http://127.0.0.1:8080".into(),
        root_key: std::env::var("L402_ROOT_KEY").unwrap(),
        rails: vec![Box::new(l402)],
        ..Default::default()
    })
    .unwrap();

    let app = axum::Router::new()
        .route("/v1/chat/completions", axum::routing::post(handler))
        .layer(TollBoothLayer::new(engine));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
```

A request to a priced route without credentials gets a `402 Payment Required` with:

- `WWW-Authenticate: L402 macaroon="...", invoice="..."`
- JSON body: `{ "l402": { "macaroon": "...", "payment_hash": "...", "invoice": "...", "amount_sats": 100 } }`

The client pays the Lightning invoice, then retries with:

```
Authorization: L402 <macaroon>:<preimage_hex>
```

The engine verifies the preimage against the payment hash, credits the account, and debits on each subsequent request until the balance is exhausted.

## Bring Your Own Backend

Implement `LightningBackend` to connect to any Lightning node:

```rust
use async_trait::async_trait;
use toll_booth::{LightningBackend, Invoice, InvoiceStatus, BackendError};

pub struct MyBackend { /* ... */ }

#[async_trait]
impl LightningBackend for MyBackend {
    async fn create_invoice(
        &self,
        amount_sats: u64,
        memo: Option<&str>,
    ) -> Result<Invoice, BackendError> {
        // call your node, return Invoice { bolt11, payment_hash }
        todo!()
    }

    async fn check_invoice(
        &self,
        payment_hash: &str,
    ) -> Result<InvoiceStatus, BackendError> {
        // return InvoiceStatus { paid, preimage }
        todo!()
    }
}
```

Pass it to `L402RailConfig::backend`:

```rust
backend: Some(Arc::new(MyBackend::new(/* ... */))),
```

When `backend` is `None`, the engine generates a random `payment_hash` and never checks payment status. Useful for development and testing.

## Bring Your Own Storage

Implement `StorageBackend` to persist credit balances to any store:

```rust
use toll_booth::{StorageBackend, DebitResult, StorageError, StoredInvoice, Currency};

pub struct MyStorage { /* ... */ }

impl StorageBackend for MyStorage {
    fn credit(&self, payment_hash: &str, amount: i64, currency: Currency)
        -> Result<(), StorageError>;

    fn debit(&self, payment_hash: &str, amount: i64, currency: Currency)
        -> Result<DebitResult, StorageError>;

    fn balance(&self, payment_hash: &str, currency: Currency)
        -> Result<i64, StorageError>;

    fn settle_with_credit(
        &self,
        payment_hash: &str,
        amount: i64,
        settlement_secret: Option<&str>,
        currency: Currency,
    ) -> Result<bool, StorageError>;

    fn is_settled(&self, payment_hash: &str) -> Result<bool, StorageError>;

    // ... plus invoice store, pruning, and adjust_credits
}
```

`MemoryStorage` is provided for tests and quick prototypes. The `sqlite` feature adds a `SqliteStorage` backend (bundled SQLite, no system dependency).

## Credit model

On first use of a payment credential, the engine calls `settle_with_credit`, which atomically marks the payment settled and credits the `amount_sats` from the macaroon. Subsequent requests debit from that balance. When the balance drops below the route cost, the engine issues a fresh 402.

`TollBoothEngine::reconcile(payment_hash, actual_cost)` adjusts the balance after the upstream responds if the actual cost differed from the estimated cost.

## Free tier

```rust
use toll_booth::FreeTierConfig;

TollBoothConfig {
    free_tier: Some(FreeTierConfig::Requests(10)), // 10 free requests per IP per day
    // or:
    free_tier: Some(FreeTierConfig::Credits(500)),  // 500 free sats per IP per day
    ..Default::default()
}
```

Free-tier checks run after all payment rails are exhausted. IPs are hashed with a daily salt before storage.

## Feature flags

| Feature           | Default | Description                                              |
|-------------------|---------|----------------------------------------------------------|
| `l402`            | yes     | L402 payment rail (macaroon + Lightning preimage)        |
| `axum-middleware` | yes     | Tower `Layer` for axum (`TollBoothLayer`)                |
| `sqlite`          | yes     | SQLite storage backend (bundled, no system dep)          |
| `phoenixd`        | no      | Phoenixd Lightning node backend                          |

## Licence

MIT
