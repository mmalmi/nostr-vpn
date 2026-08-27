# Protocol

This document describes the protocol shape currently implemented by
`nostr-vpn`. FIPS wire formats are owned by FIPS; nvpn adds membership, routing,
and application control above the FIPS endpoint API.

## Scope

The system has four related layers:

- signed device enrollment and admin-managed network rosters
- FIPS discovery and authenticated peer connectivity
- roster-gated private IP routing over the FIPS dataplane
- optional private, paid, or local WireGuard internet egress

Only one configured network is active in the live runtime. The legacy relay
peer-announcement and WireGuard mesh modes are removed.

## Identity And Network IDs

The Nostr identity key authenticates the device, signed rosters, admin actions,
FIPS identity, and paid-exit offers/control. User-facing `nsec`/`npub` values
are normalized to hex internally.

`network_id` scopes the roster, LAN discovery, and deterministic tunnel
addresses. Runtime normalization trims the legacy `nostr-vpn:` prefix. UUID-like
hex IDs also ignore whitespace and hyphens and normalize to lowercase.

The derived IPv4 address is:

```text
digest = SHA256(normalized_network_id + "\n" + device_pubkey_hex)
address = 10.44.(digest[0] % 254 + 1).(digest[1] % 254 + 1)/32
```

The address is deterministic, not an identity credential. Packet admission is
still tied to the authenticated FIPS source and current route map.

## Join Approval

An unapproved device creates a short-lived `nvpn://join-request/…` bootstrap.
It contains the stable device AppKey, a separate ephemeral request identity and
secret, timestamps, and an optional device label. It contains no network ID,
membership, admin list, or trusted relay configuration, and ordinary join
requests do not nominate Nostr approval relays.

An admin imports the request, adds the device to an administered network, and
creates a fresh Nostr-signed roster bound to that request secret. Delivery is a
stateful FIPS-TCP control exchange. The joiner accepts it only when the request
matches, the signature is valid, the signer is listed as an admin, the joiner
is in the roster, and freshness checks pass. The joiner persists the roster
before acknowledging it; the admin retains the durable delivery outbox until
that exact receipt arrives.

Receipt-backed manual join uses an out-of-band network/admin/device tuple, but
the admin's roster signature remains the authority.

## Signed Rosters And Capabilities

A version-1 signed roster event contains:

- network ID and name
- device and admin public keys
- per-member aliases
- signing time and signer identity

For an existing network, a newer roster is accepted only from a configured
admin. Removing the local device removes that network locally. Stale, duplicate,
invalid, or far-future updates are ignored or rejected.

Routes and transport addresses are deliberately not roster fields. Connected
members exchange authenticated capability frames containing advertised routes,
endpoint hints, and a timestamp. Capabilities expire from runtime use and never
grant membership.

## FIPS Connectivity And Control

FIPS is the only private-mesh dataplane. Depending on configuration it can use
UDP, LAN discovery, static endpoints, authenticated bootstrap/transit peers,
Nostr-assisted endpoint discovery, WebSocket, and optional WebRTC transport.
Nostr relays carry signed discovery/pubsub events, not private IP datagrams.

Public bootstrap or discovered peers may relay/connect FIPS traffic without
joining the private network. Before an IP packet reaches the TUN,
`FipsMeshRuntime` maps the authenticated FIPS identity to a roster or paid-route
admission and validates the packet source and destination.

`FipsControlFrame` is a versioned nvpn application envelope carried as opaque
FIPS payload. Stateful roster, capability, approval, and paid-exit messages use
FIPS-TCP. Ping/pong probes may use endpoint datagrams. This envelope is not a
FIPS protocol message or wire-format extension.

## Discovery And NAT

nvpn passes configured endpoint hints, STUN servers, discovery policy, and the
listen port into FIPS. FIPS observes and advertises its overlay endpoints and
performs NAT traversal/path recovery. Publishing the operator-supplied exact
UDP endpoint publicly is opt-in and off by default; FIPS can still share
observed endpoints through its configured discovery paths.

PCP, NAT-PMP, and UPnP mapping remains an nvpn runtime aid and diagnostic. The
daemon state's `advertised_endpoint` mirrors the local endpoint and is not a
separate precomputed STUN result.

## Routing And Exits

Each roster member receives its derived `/32`. Fresh authenticated capability
frames can add subnet or default routes. Outbound selection uses longest-prefix
matching; equal-specificity routes from different peers are ambiguous and are
dropped. A selected private exit becomes usable only when the advertising peer
is connected. Leak protection withholds or blocks default routing while the
requested protected path is not ready.

An exit provider forwards admitted member traffic through its selected local
internet source: the host's direct path, a local WireGuard upstream, or another
private FIPS exit. WireGuard can also be selected directly as this device's
internet source. It is never a private-mesh transport.

## Paid Exits

Paid-exit offers are separate expiring, parameterized Nostr events signed by the
seller. They advertise price, Cashu mint/channel terms, IP support, coarse
location, and endpoint hints without granting roster membership.

A buyer selects an offer, establishes a Cashu Spilman payment channel, and sends
a paid-route session-open frame over authenticated FIPS-TCP. The seller validates
the authenticated buyer and terms before returning an admission. Default-route
traffic is not enabled for that seller until the admission is current. The
admission is scoped to the paid session and does not expose the seller's private
network.

Usage is byte-metered at the FIPS/nvpn boundary. Buyer-to-exit IP packets are
billable immediately. Exit-to-buyer UDP is billable only for a recent
buyer-originated flow. TCP download payload becomes billable when acknowledged
by the buyer, without billing retransmitted bytes twice; other inbound protocols
are not billed. Signed payment updates and acknowledgements use FIPS control,
while durable channel/session state governs whether routing remains admitted.

## Exit DNS And Inbound Safety

MagicDNS names are always answered locally. With an active exit, `automatic`
uses DNS IPs from a ready WireGuard profile or built-in Cloudflare DNS-over-HTTPS
for other exits. `encrypted` selects Cloudflare, Quad9, or a custom HTTPS
resolver with literal bootstrap IPs. `through_exit` sends DNS wire messages to
explicit IP resolvers over the selected exit. Resolver or path failure is
fail-closed; secure DNS does not fall back to system or plaintext DNS.

DoH hides DNS contents from the exit, but the resolver sees the query and the
exit still sees destination IPs, timing, volume, and sometimes TLS hostnames.
A WireGuard profile resolver is visible to that WireGuard provider.

Selected FIPS exits are treated as hostile inbound networks. TCP, UDP, and echo
replies are admitted only for locally originated flows, along with valid ICMP
errors quoting tracked flows. Unsolicited, malformed, fragmented, private,
loopback, link-local, multicast, or spoofed mesh-source traffic is dropped
before the TUN for IPv4 and IPv6.

## Canonical Source

If this document and code differ, code wins. The main implementations are:

- `crates/nostr-vpn-core/src/join_requests.rs`, `signed_rosters.rs`, and
  `fips_control.rs`
- `crates/nostr-vpn-core/src/fips_mesh.rs`
- `crates/nostr-vpn-core/src/paid_routes.rs`, `paid_route_store/`, and
  `paid_route_accounting.rs`
- `crates/nostr-vpn-cli/src/fips_private_mesh/`
- `crates/nostr-vpn-cli/src/session_runtime/`
- `crates/nostr-vpn-cli/src/secure_dns_runtime.rs`
- `crates/nostr-vpn-app-core/src/join_approval.rs` and `mobile_tunnel/`
