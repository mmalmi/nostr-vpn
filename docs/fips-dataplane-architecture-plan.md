# FIPS Dataplane Architecture

This page describes the current nvpn/FIPS boundary and the direction for future
dataplane work. It is not a migration log.

## Current Boundary

`nostr-vpn` embeds `nvpn-fips-endpoint` without FIPS's system TUN. The layers
have distinct jobs:

`nostr-vpn` owns:

- device identity, signed enrollment and roster authority
- the visible OS VPN adapter and platform route lifecycle
- roster-derived IP routing and source admission
- application control frames carried over FIPS, including roster,
  capabilities, join-approval, and paid-exit control
- exit selection, leak protection, hostile-inbound filtering, DNS policy, paid
  route admission, and accounting

FIPS owns:

- authenticated and encrypted peer/session transport
- UDP, LAN, Nostr-assisted discovery, WebSocket, and optional WebRTC paths
- NAT traversal, path selection and recovery, replay protection, rekey, and
  transport-level queueing/batching

Discovery peers and bootstrap routers may provide connectivity without becoming
private-network members. Only roster-derived peers or explicit paid-route
admissions may deliver IP packets to the tunnel.

## Packet Flow

Outbound packets follow one canonical path:

1. The platform TUN yields an IP packet.
2. `FipsMeshRuntime` selects one unambiguous longest-prefix roster or paid route.
3. nvpn groups packets for the selected authenticated FIPS identity.
4. The embedded endpoint encrypts and sends them over its selected transport.

Inbound packets follow the reverse boundary:

1. The embedded endpoint authenticates and decrypts a packet run.
2. nvpn maps the FIPS source identity to the current mesh snapshot.
3. Source/destination admission and exit-flow filtering run before TUN delivery.
4. Accepted packets are written to the platform TUN in bounded batches.

The mesh and identity maps are replaced as snapshots when rosters, routes, or
paid admissions change. Packet processing must not fall back to a second mesh
implementation or bypass the admission snapshot.

## Control Plane

`FipsControlFrame` is an nvpn application envelope transported as opaque FIPS
payload; it is not a FIPS wire-protocol extension. Stateful control uses
FIPS-TCP. Probe ping/pong may use endpoint datagrams. Signed rosters remain the
membership authority; authenticated capability frames carry current advertised
routes and endpoint hints.

WireGuard is only an optional local upstream egress for an exit provider or a
locally selected internet source. It is not a private-mesh transport.

## Design Rules

- Keep the nvpn/FIPS adapter thin. Put transport, path, session, rekey, and
  dataplane scheduling policy in FIPS when the compatibility boundary allows.
- Keep membership, IP admission, exit policy, billing, DNS, and OS lifecycle in
  nvpn.
- Preserve one packet path per platform; remove obsolete branches instead of
  adding fallback implementations.
- Keep queues and per-wake work bounded. Pressure must be observable, and
  control/liveness traffic must retain progress under bulk load.
- Preserve packet order for one flow unless an explicit sequencer and real-path
  evidence justify a change.
- Treat route ambiguity, unauthenticated sources, and unavailable protected
  exits as fail-closed conditions.
- Do not change FIPS message types, byte values, record formats, routing
  semantics, or compatibility boundaries without explicit approval.

## Direction

Future work should delete nvpn-side duplication, reduce packet copies and
lock/map churn, and improve platform batching only where measurements identify
the bottleneck. A hot-path change is complete only when focused invariants pass
and the affected production-like path has before/after latency, loss,
throughput, CPU, and recovery evidence.

The current implementation is centered in:

- `crates/nostr-vpn-cli/src/fips_private_mesh.rs` and its modules
- `crates/nostr-vpn-core/src/fips_mesh.rs`
- `crates/nostr-vpn-core/src/fips_control.rs`
- `crates/nostr-vpn-cli/src/session_runtime/`

See [the safety net](fips-dataplane-safety-net.md) for current gates and
[experiments](EXPERIMENTS.md) for evidence rules. The former June 2026 plan is
preserved as a [historical snapshot](archive/fips-dataplane-architecture-plan-2026-06.md).
