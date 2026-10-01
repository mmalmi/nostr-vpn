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

## Source

https://github.com/mmalmi/nostr-vpn
