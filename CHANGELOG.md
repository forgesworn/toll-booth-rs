# Changelog

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
