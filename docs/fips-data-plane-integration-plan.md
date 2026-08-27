# FIPS Private Mesh Integration

This document records the current integration boundary. FIPS is the only
private-mesh dataplane; the former selectable or WireGuard-mesh design is
historical.

## Ownership

`nostr-vpn` owns identity, signed enrollment, admin rosters, aliases, IP route
policy, tunnel admission, the platform VPN adapter, exit policy, DNS, and paid
route accounting. FIPS owns authenticated packet transport, encryption,
sessions, path selection, NAT traversal, discovery, rekey, and transport-level
queueing.

The desktop daemon embeds `nvpn-fips-endpoint` without its system TUN. Mobile
uses the same roster/admission and endpoint configuration through app-core.

## Trust Boundaries

- A signed active-network roster grants private-mesh membership.
- FIPS discovery, static hints, public bootstrap peers, and WebSocket routers
  provide connectivity only. Non-roster adjacency does not grant TUN access.
- Authenticated capability frames carry current advertised routes and endpoint
  hints; they do not replace signed membership.
- Explicit paid-route admissions are session-scoped exceptions for public exit
  traffic. They do not add a buyer to the seller's private roster.
- Equal-specificity route ambiguity, an unavailable leak-protected exit, and an
  unauthenticated or unadmitted source fail closed.

## Control And Data

Private IP packets use the embedded FIPS endpoint. nvpn application control is
encoded as `FipsControlFrame`; stateful roster, capability, join-approval, and
paid-exit messages use FIPS-TCP, while probe ping/pong may use endpoint
datagrams. These envelopes are FIPS payloads, not changes to the FIPS wire
protocol.

Join approval is delivered from a durable outbox and removed only after the
joiner has verified and persisted the admin-signed roster and returned the
matching receipt.

Exit nodes are implemented now, not deferred work. A private roster peer may
advertise default routes. Paid exits publish separate expiring signed offers,
then receive explicit buyer admission after the seller accepts a FIPS control
session. A seller can forward to its direct host path, local WireGuard upstream,
or selected private FIPS exit. WireGuard remains a local egress leg, never a
mesh transport.

## Implementation Map

- `crates/nostr-vpn-cli/src/fips_private_mesh/`: endpoint configuration,
  roster/paid-route maps, packet send/receive, platform TUNs, and status
- `crates/nostr-vpn-core/src/fips_mesh.rs`: route selection and source admission
- `crates/nostr-vpn-core/src/fips_control.rs` and `fips_control_tcp.rs`:
  application control envelopes and stateful delivery
- `crates/nostr-vpn-app-core/src/mobile_tunnel/`: mobile endpoint integration
- `crates/nostr-vpn-cli/src/session_runtime/`: daemon reconciliation and
  durable control delivery

See [the dataplane architecture](fips-dataplane-architecture-plan.md) and
[protocol](protocol.md) for the maintained behavior. Code and integration tests
win if this summary diverges.
