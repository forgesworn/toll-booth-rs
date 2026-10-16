# toll-booth

[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

L402 payment middleware for Rust. Gates any HTTP API behind Lightning payments using a bring-your-own-backend, bring-your-own-storage model. Works as a Tower `Layer`, so it drops straight into axum.

One Lightning payment funds multiple API calls. The engine tracks credit balances, debits per request, and re-challenges when the balance runs out. Supports free tiers, tiered pricing, cost reconciliation, and custom macaroon caveats.

## Why toll-booth?

- **Credit-balance model** -- one payment buys N requests, not one. Clients top up and keep calling.
- **Cost reconciliation** -- adjust credits after the upstream responds if actual cost differed from estimate.
- **Free tier** -- configurable free requests or free credits per IP per day, with hashed IPs and daily rotation.
- **Tiered pricing** -- different prices per route per tier, selected by `X-Toll-Tier` header (see [Pricing](#pricing)).
- **Pluggable everything** -- bring your own Lightning backend, storage backend, and payment rails.
- **Security defaults** -- constant-time HMAC and preimage verification, overflow-checked arithmetic, daily-salted IP hashing.
- **Trusted-proxy IP handling** -- `X-Forwarded-For`/`X-Real-IP` honoured only from configured trusted proxies; free tier fails closed otherwise.
- **Zeroised key material** -- the macaroon root key is held in a `RootKey` type that redacts `Debug` output and zeroises on drop.

## Quick start

```sh
cargo add toll-booth axum@0.8
cargo add tokio --features macros,rt-multi-thread,net
```

or, in `Cargo.toml`:

```toml
[dependencies]
toll-booth = { version = "0.2", features = ["l402", "axum-middleware"] }
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

`axum` must be 0.8 to match the version `toll-booth` builds against. `async-trait` is only needed if you implement `LightningBackend` (see below), and `ipnet` only if you configure trusted proxies (see [Free tier](#free-tier)).

```rust
use std::net::SocketAddr;
use std::sync::Arc;
use toll_booth::{
    L402Rail, L402RailConfig, MemoryStorage, PricingEntry, RootKey, StorageBackend,
    TollBoothConfig, TollBoothEngine, TollBoothLayer,
};

async fn handler() -> &'static str {
    "Hello from the paid API"
}

#[tokio::main]
async fn main() {
    let storage: Arc<dyn StorageBackend> = Arc::new(MemoryStorage::new());

    // 64 hex characters (32 bytes). Generate one with: openssl rand -hex 32
    let root_key = RootKey::from_hex(&std::env::var("L402_ROOT_KEY").expect("L402_ROOT_KEY not set"))
        .expect("L402_ROOT_KEY must be 64 hex characters");

    let l402 = L402Rail::new(L402RailConfig {
        root_key,
        storage: storage.clone(),
        default_amount: 100, // sats; invoice amount when the matched price has no `sats`
        // DEVELOPMENT ONLY. With `None`, challenges carry an empty invoice and a random
        // payment_hash, so no client can pay or authenticate. Do not deploy this.
        // For production pass `Some(Arc::new(your_backend))`.
        backend: None,
        service_name: Some("My API".to_string()),
    });

    let mut pricing = std::collections::HashMap::new();
    pricing.insert("/v1/chat/completions".to_string(), PricingEntry::Simple(100));

    let engine = TollBoothEngine::new(TollBoothConfig {
        storage,
        pricing,
        rails: vec![Box::new(l402)],
        ..Default::default()
    })
    .unwrap();

    let app = axum::Router::new()
        .route("/v1/chat/completions", axum::routing::post(handler))
        .layer(TollBoothLayer::new(engine));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    // ConnectInfo supplies the client IP. Without it the IP is "unknown" and the free tier is never granted.
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .unwrap();
}
```

**Root key.** `L402_ROOT_KEY` must be exactly 64 hex characters (32 bytes, upper or lower case). `RootKey::from_hex` returns `Err(MacaroonError::InvalidRootKey)` ("invalid root key") for anything else. `RootKey` zeroises on drop and redacts `Debug` output, so pass it as a `RootKey`, not a `String`. `L402RailConfig::root_key` takes a `RootKey`; `TollBoothConfig::root_key` takes an `Option<RootKey>` that the engine never reads, so the two do not need to match and the field can stay `None` (the default). The key that signs and verifies macaroons is the one given to `L402RailConfig`. Keep it stable across restarts, or previously issued macaroons stop verifying.

**`upstream`.** `TollBoothLayer` forwards every allowed request to the axum service it wraps and never contacts `TollBoothConfig::upstream` (default: empty string). The value is only copied into `TollBoothResult::Proxy` and `TollBoothResult::Pass` for callers that drive `TollBoothEngine::handle` themselves, so the quick start leaves it unset.

A request to a priced route without credentials gets a `402 Payment Required` with:

- `WWW-Authenticate: L402 macaroon="...", invoice="..."`
- JSON body: `{ "l402": { "macaroon": "...", "payment_hash": "...", "invoice": "...", "amount_sats": 100 } }`

The client pays the Lightning invoice, then retries with:

```
Authorization: L402 <macaroon>:<preimage_hex>
```

The engine verifies the preimage against the payment hash, credits the account, and debits on each subsequent request until the balance is exhausted.

## Bring Your Own Backend

Implement `LightningBackend` to connect to any Lightning node (this needs `async-trait = "0.1"`):

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

    // Optional. The default implementation returns Err(BackendError::NotSupported).
    // async fn send_payment(&self, bolt11: &str)
    //     -> Result<toll_booth::backends::PaymentResult, BackendError>;
}
```

`create_invoice` and `check_invoice` are required; `send_payment` is optional. Pass the backend to `L402RailConfig::backend`:

```rust
backend: Some(Arc::new(MyBackend::new(/* ... */))),
```

`L402Rail` calls only `create_invoice`. It decides whether a payment is genuine by checking `SHA256(preimage) == payment_hash` in constant time, so `check_invoice` and `send_payment` are not called by this crate.

When `backend` is `None`, the challenge carries an empty `invoice` and a random `payment_hash`. Nobody holds a preimage for that hash, so no client can pay or authenticate. Use it only for development and tests.

## Bring Your Own Storage

Implement `StorageBackend` to persist credit balances to any store. The trait is synchronous (no `async_trait`), requires `Send + Sync`, and every method below is required:

```rust
use toll_booth::{Currency, DebitResult, StorageError, StoredInvoice};

pub trait StorageBackend: Send + Sync {
    // Balances
    fn credit(&self, payment_hash: &str, amount: i64, currency: Currency)
        -> Result<(), StorageError>;
    fn debit(&self, payment_hash: &str, amount: i64, currency: Currency)
        -> Result<DebitResult, StorageError>;
    fn balance(&self, payment_hash: &str, currency: Currency) -> Result<i64, StorageError>;
    fn adjust_credits(&self, payment_hash: &str, delta: i64, currency: Currency)
        -> Result<i64, StorageError>;

    // Settlement
    fn settle(&self, payment_hash: &str) -> Result<bool, StorageError>;
    fn settle_with_credit(
        &self,
        payment_hash: &str,
        amount: i64,
        settlement_secret: Option<&str>,
        currency: Currency,
    ) -> Result<bool, StorageError>;
    fn is_settled(&self, payment_hash: &str) -> Result<bool, StorageError>;
    fn get_settlement_secret(&self, payment_hash: &str) -> Result<Option<String>, StorageError>;

    // Invoice store
    fn store_invoice(&self, invoice: &StoredInvoice) -> Result<(), StorageError>;
    fn get_invoice(&self, payment_hash: &str) -> Result<Option<StoredInvoice>, StorageError>;
    fn get_invoice_for_status(&self, payment_hash: &str, status_token: &str)
        -> Result<Option<StoredInvoice>, StorageError>;
    fn pending_invoice_count(&self, client_ip: &str) -> Result<u64, StorageError>;

    // Pruning
    fn prune_expired_invoices(&self, max_age: std::time::Duration) -> Result<u64, StorageError>;
    fn prune_stale_records(&self, max_age: std::time::Duration) -> Result<u64, StorageError>;
}
```

Semantics the engine relies on, taken from `MemoryStorage`:

- `debit` returns `DebitResult { success: false, remaining }` without changing the balance when funds are insufficient; it is not an error.
- `adjust_credits` adds a signed `delta` to the balance and returns the new balance.
- `settle` and `settle_with_credit` return `Ok(true)` the first time and `Ok(false)` once the payment hash is already settled. `settle_with_credit` settles and credits in one atomic step and stores `settlement_secret`.
- Settlement records are the replay guard. `prune_stale_records` must not remove them, and must not remove balances that are non-zero.
- `get_invoice_for_status` returns the invoice only if `status_token` matches, compared in constant time.
- Balances are kept per `Currency`, and arithmetic must be overflow-checked.

`MemoryStorage` is provided for tests and quick prototypes. The `sqlite` and `phoenixd` features are reserved: their modules are empty placeholders, and `SqliteStorage` and `PhoenixdBackend` do not exist yet.

## Credit model

On first use of a payment credential, the engine calls `settle_with_credit`, which atomically marks the payment settled and credits the `amount_sats` from the macaroon. Subsequent requests debit from that balance. When the balance drops below the route cost, the engine issues a fresh 402.

### Cost reconciliation

```rust
pub fn reconcile(&self, request_id: &str, actual_cost: u64) -> ReconcileResult
```

`reconcile` is synchronous. `request_id` is the per-request identifier in `TollBoothResult::Proxy { request_id, .. }` (it is not the `payment_hash`), and each id can be reconciled once. The engine keeps the estimate, and `reconcile` calls `adjust_credits` with `estimated - actual`: a positive difference refunds, a negative one debits more. It returns `ReconcileResult { adjusted, new_balance, delta }`. For an unknown, already-reconciled or evicted id (estimates older than 60 seconds are dropped once 10,000 are held), or when the estimate equals the actual cost, it returns `adjusted: false` with `new_balance: 0` and `delta: 0`.

`TollBoothLayer` does not pass `request_id` or `payment_hash` on to your handlers, so reconciliation needs an integration that calls `TollBoothEngine::handle` directly and reads `request_id` from the `Proxy` result.

## Pricing

`TollBoothConfig::pricing` maps a request path to a `PricingEntry`. Lookup is an exact, case-sensitive match on the URI path (no query string, no wildcards). A path that is not in the table is unpriced and passes straight through (`TollBoothResult::Pass`).

```rust
pub struct PriceInfo {
    pub sats: Option<u64>,
    pub usd: Option<u64>,
}

pub enum PricingEntry {
    Simple(u64),                  // sats
    Detailed(PriceInfo),          // explicit sats and/or usd
    Tiered(HashMap<String, u64>), // tier key -> sats
}
```

`PriceInfo::sats(n)` and `PriceInfo::usd(n)` build a value with only that field set, and `amount_for(Currency)` returns the matching field or `0`.

- **Charging uses `sats` only.** The engine debits and challenges on `PriceInfo::sats`. `usd` is not used for charging; it is only advertised, as the `X-L402-Price-Usd` header and `price.usd` in the body of the `HEAD` response. A `Detailed` entry with `sats: None` costs `0` for an authenticated request, and its challenge asks for `L402RailConfig::default_amount`.
- **`Currency::Usd`** is the second balance bucket that storage keeps per payment hash. A macaroon carries its currency in a `currency` caveat, and the engine debits in that currency. `L402Rail` always mints `Currency::Sat` macaroons, and the engine does not convert between currencies. The source does not define a unit for `usd` amounts.
- **`default_amount`** (`L402RailConfig`) is the invoice amount when the matched price has no `sats`. It never overrides a price that has one.
- **Tiered entries** must contain a `"default"` key. `TollBoothEngine::new` returns `TollBoothError::Config` otherwise. Its message reads `configuration error: tiered pricing for route "/path" is missing the required "default" tier`.
  - No `X-Toll-Tier` header: the `"default"` tier price applies.
  - A tier that is not 1 to 32 characters of lowercase letters, digits, `_` or `-`, or is not in the table: the engine returns a 402 challenge at the `"default"` price, before it looks at credentials or the free tier.
  - The tier is chosen by the client, so it is advisory. To enforce a tier, bind it to a macaroon caveat.

## Custom macaroon caveats

`L402Rail` mints macaroons with only the mandatory caveats. To attach your own free-form caveats, mint a macaroon with `toll_booth::macaroon::mint_macaroon`, for example from a custom `PaymentRail`:

```rust
pub fn mint_macaroon(
    root_key: &RootKey,
    payment_hash: &str,       // 64 hex characters
    credit_balance: i64,
    custom_caveats: &[String], // each "key = value" (space, equals, space)
    currency: Currency,
) -> Result<String, MacaroonError>; // URL-safe base64
```

`payment_hash`, `credit_balance`, `currency`, `route`, `expires` and `ip` are reserved: `mint_macaroon` rejects them in `custom_caveats` with `MacaroonError::InvalidCaveat`, as it does a caveat that is not in `key = value` form. Any other caveat is added to the request and response headers of a charged request as `X-Toll-Caveat-<Key>`, with `_` in the key becoming `-` and each segment capitalised (`app_id` becomes `X-Toll-Caveat-App-Id`).

### Route, expiry and IP restrictions

This crate cannot attach `route`, `expires` or `ip`. `mint_macaroon` is the only public way to mint a macaroon and it rejects those keys, and the internal `Macaroon` type that could add them is not exported. Verification does enforce them: `verify_macaroon`, and so `L402Rail`, rejects a validly signed macaroon that carries one and the request does not satisfy it.

- `route`: an exact path, or a prefix ending in `/*`, matched against the request path.
- `expires`: an RFC 3339 timestamp. A macaroon past it is rejected, and so is one whose value cannot be parsed.
- `ip`: an exact address, compared with the client IP, resolved as described under [Free tier](#free-tier).

To use them, the macaroon has to be minted outside this crate, in the same V2 format with an L402 identifier and signed with the same root key.

## Free tier

```rust
use toll_booth::{FreeTierConfig, TollBoothConfig};

// 10 free requests per IP per day
TollBoothConfig {
    free_tier: Some(FreeTierConfig::Requests(10)),
    ..Default::default()
}

// 500 free sats per IP per day
TollBoothConfig {
    free_tier: Some(FreeTierConfig::Credits(500)),
    ..Default::default()
}
```

Free-tier checks run after all payment rails are exhausted. IPs are hashed with a daily salt before storage.

The client IP comes from axum's `ConnectInfo<SocketAddr>`, so serve with `app.into_make_service_with_connect_info::<SocketAddr>()` as in the quick start. Without a peer address the IP is `"unknown"`, and the free tier fails closed (no free requests are granted).

Behind a reverse proxy, every connection comes from the proxy, so tell the layer which peers to trust with `TollBoothLayer::with_trusted_proxies(Vec<IpNet>)`. `X-Forwarded-For` and `X-Real-IP` are honoured only when the direct peer is inside one of those networks (the default is none). `IpNet` comes from the `ipnet` crate, which `toll-booth` does not re-export, so add `ipnet = "2"` yourself:

```rust
use ipnet::IpNet;

let layer = TollBoothLayer::new(engine)
    .with_trusted_proxies(vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]);
```

`X-Forwarded-For` is read from the right, skipping hops that are themselves trusted proxies, and the first untrusted entry is used as the client IP.

## Feature flags

| Feature           | Default | Description                                              |
|-------------------|---------|----------------------------------------------------------|
| `l402`            | yes     | L402 payment rail (macaroon + Lightning preimage)        |
| `axum-middleware` | yes     | Tower `Layer` for axum (`TollBoothLayer`)                |
| `sqlite`          | yes     | Reserved: enables the `rusqlite` dependency; `SqliteStorage` is not implemented yet |
| `phoenixd`        | no      | Reserved: enables the `reqwest` dependency; `PhoenixdBackend` is not implemented yet |

## Licence

MIT
