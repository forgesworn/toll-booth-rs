# Changelog

## Unreleased

Security-hardening follow-up.

### Fixed

- **Unauthenticated invoice-storage exhaustion closed.** `MemoryStorage`
  now caps stored invoices at 100,000 with FIFO eviction, implements
  `prune_expired_invoices` / `prune_stale_records` (previously no-ops), and
  the engine records the client IP on each challenge, caps pending invoices
  at 100 per IP, and prunes invoices older than 24h opportunistically.
  Settlement records are deliberately never pruned: they are the replay
  guard for `settle_with_credit`.
- **X-Forwarded-For chain resolution.** Behind a trusted proxy the client
  IP is now resolved by walking the header right-to-left and skipping hops
  that are themselves trusted proxies, instead of trusting the left-most
  entry. Proxies that *append* (e.g. nginx `$proxy_add_x_forwarded_for`)
  can no longer be abused to rotate spoofed left-most entries and evade
  free-tier quotas or `ip` caveats.
- **`expires` caveat fails closed.** A macaroon carrying an unparseable
  `expires` value is now rejected instead of silently disabling expiry
  enforcement.
- **Free-tier mutex poisoning fails closed.** A poisoned free-tier state
  mutex now denies requests instead of panicking every subsequent request.

## 0.2.0 - 2026-08-08

Security-hardening release (breaking, pre-1.0).

### Fixed

- **X-Forwarded-For spoofing closed.** `X-Forwarded-For`/`X-Real-IP` are
  honoured only when the direct peer is in `trusted_proxies`
  (`TollBoothLayer::with_trusted_proxies`); otherwise the connection peer
  address is used. Free-tier grants fail closed when no trustworthy IP is
  available. Previously a spoofed header gave unlimited free-tier access and
  satisfied IP-restricted macaroon caveats.
- **Inbound `X-Toll-Tier` stripped.** The client-supplied tier header is
  removed before proxying upstream; only engine-supplied headers may set it.
- **Fail-closed error paths.** Rail verification and storage errors now
  return a blocked (500) outcome instead of falling through to the free
  tier. Tiered pricing without a `default` key is rejected at engine
  construction.
- **Reconcile is one-shot.** Cost estimates are keyed by a unique
  per-request id and removed on first reconcile, closing repeated-refund and
  cross-request misattribution bugs.
- **Root key hygiene.** New `RootKey` type: hex-decoded once into
  `Zeroizing<[u8; 32]>`, redacting `Debug`, zeroised on drop.

### Breaking Changes

- `TollBoothConfig.root_key` / `L402RailConfig.root_key` use the `RootKey`
  type (`RootKey::from_hex`).
- `reconcile` takes the per-request id returned on the `Proxy` result
  (`request_id`).

## 0.1.0

Initial release.
