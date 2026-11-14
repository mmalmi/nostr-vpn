# nostr-vpn-core

Shared runtime library for Nostr VPN. It contains configuration and identity
models, signed roster and join flows, FIPS discovery/control state, routing,
MagicDNS, diagnostics, paid-route accounting, secure DNS, and WireGuard
upstream support.

With the `updater` feature, signed release discovery uses nostr-pubsub over the
configured FIPS peers and seeds. Standalone checks join the mesh without a VPN
tunnel, and can use a running same-host FIPS provider. Applications with a live
pubsub provider can pass its fresh subscriber directly. Update checks require a
release announcement received from a peer during the check; an old local cache
alone cannot report “up to date.” Observed roots are saved separately from the
daemon cache so later checks cannot accept an older announcement. Asset downloads still use verified Blossom
content. Explicit GitHub checks and the existing Auto GitHub fallback remain
available; neither needs a Nostr relay.

The public API is still evolving with the Nostr VPN application.

## Peer service credit

The default `peer-credit` library feature exposes
`FipsMeshRuntime::install_credit_exit` for a durably reserved `peer-payments`
allowance. It binds the provider, payer and tunnel address, preserves the existing
public-Internet/private-route checks, and charges each admitted upload packet even
when its IP authorization is cached. Cloned runtimes share quota. A rebuilt
runtime without its live allowance denies the credit session. Existing Cashu
sessions retain their existing admission and ACK-based accounting.

`select_exit_credit_offer` uses signed Nostr follow and mute lists to compare
two-hop providers for the same upload-credit purchase. It checks the seller's
quote signature and the buyer's local service, quantity and price limits before
returning a candidate.

This is a development adapter for the explicit `vpn.exit.upload_bytes` tariff,
not automatic app negotiation and not a replacement for the existing paid-exit
meter. Download traffic is not metered by this tariff. Do not advertise it as a
bidirectional bandwidth meter. App discovery, pricing/acceptance policy, receipt
exchange, lifetime-budget renewal and operator settings still need integration
before enabling it for users. It does not start a mint or Lightning node.

The shared credit implementation is owned by the `cashu-service` repository.
Vendored development snapshots include per-file hashes in `SOURCE.json`; they
are not published-release claims.

## Source

https://github.com/mmalmi/nostr-vpn
