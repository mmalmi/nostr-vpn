# Path Maintenance Architecture

FIPS owns private-mesh path maintenance. The removed Unix WireGuard mesh path
manager is not a fallback.

`nostr-vpn` supplies:

- roster and paid-route identities that may carry tunnel traffic
- operator endpoint hints, bootstrap peers, WebSocket settings, LAN discovery,
  Nostr discovery settings, STUN servers, and the active underlay interface
- recent authenticated endpoint hints and peer capability updates
- platform routes that keep control/transport endpoints outside a selected
  default exit

FIPS owns transport probing, direct-versus-transit selection, NAT traversal,
reconnect, rekey, liveness, and recovery after an underlay change. nvpn updates
the endpoint configuration and invalidates stale cached path state when the
network changes; it does not select a UDP path per packet.

Discovery or bootstrap adjacency is transport-only. `FipsMeshRuntime` still
admits tunnel packets only from the active roster or an explicit paid-route
session.

WireGuard can be a local internet source or a paid/private exit provider's
upstream egress. It does not participate in FIPS peer path selection.

The integration is centered in `crates/nostr-vpn-cli/src/fips_private_mesh/`
and `crates/nostr-vpn-cli/src/session_runtime/fips_status_helpers/`. Validate
path changes with the routed-UDP, NAT-safe-MTU, roaming, and host-pair runners
listed in [the dataplane safety net](fips-dataplane-safety-net.md).
