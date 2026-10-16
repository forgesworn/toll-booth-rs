# toll-booth

L402 payment middleware for Rust. Gates any HTTP API behind Lightning payments
using a bring-your-own-backend, bring-your-own-storage model. Ships as a Tower
`Layer`, so it drops straight into axum. One Lightning payment funds multiple
API calls: the engine tracks credit balances, debits per request, and
re-challenges when the balance runs out.

## Build & test

| Command | Purpose |
|---------|---------|
| `cargo check --all-features` | Type-check with every feature enabled |
| `cargo test --all-features` | Run the test suite |
| `cargo clippy --all-features -- -D warnings` | Lint, warnings as errors |
| `cargo fmt --all -- --check` | Check formatting |

CI (`.github/workflows/ci.yml`) runs all four on every push and pull request
against `main`.

## Structure

```
src/
  lib.rs             re-exports the public API
  engine.rs          TollBoothEngine, TollBoothConfig, FreeTierConfig
  macaroon.rs         RootKey and macaroon handling
  free_tier.rs        free-tier request/credit tracking
  types.rs            Currency, PriceInfo, PricingEntry and other shared types
  backends/           LightningBackend trait; phoenixd.rs is an empty placeholder
  rails/               PaymentRail trait and the L402Rail implementation
  storage/            StorageBackend trait, MemoryStorage; sqlite.rs is an empty placeholder
  middleware/         TollBoothLayer (axum), gated by the axum-middleware feature
```

## Feature flags

| Feature | Default | Adds |
|---------|---------|------|
| `l402` | yes | L402 payment rail (macaroon + Lightning preimage) |
| `axum-middleware` | yes | `TollBoothLayer`, a Tower `Layer` for axum |
| `sqlite` | yes | Reserved: enables `rusqlite`; `SqliteStorage` is not implemented yet |
| `phoenixd` | no | Reserved: enables `reqwest`; `PhoenixdBackend` is not implemented yet |

## Conventions

- Storage and Lightning backends are pluggable via the `StorageBackend` and
  `LightningBackend` traits; do not hard-code a specific backend into the
  engine.
- The macaroon root key is held in `RootKey`, which redacts `Debug` output and
  zeroises on drop. Never log or `Debug`-print raw key material elsewhere.
- IP hashing for the free tier is daily-salted; do not store raw IPs.
- Arithmetic on credit balances is overflow-checked; keep new balance code the
  same way.

## Common pitfalls

- `middleware` (and `TollBoothLayer`) only exists under the `axum-middleware`
  feature; code referencing it must be behind the same `#[cfg(feature = ...)]`
  or the default feature set.
- `SqliteStorage` and `PhoenixdBackend` do not exist yet; the `sqlite` and `phoenixd`
  features only gate empty placeholder modules. Do not document or import them.
- Free-tier checks run only after every configured payment rail is exhausted;
  do not reorder that.
- Security reports go through GitHub Security Advisories per `SECURITY.md`,
  not the public issue tracker.

## Verifying a change

Run `cargo check --all-features`, `cargo test --all-features`, `cargo clippy
--all-features -- -D warnings` and `cargo fmt --all -- --check` before
committing.
