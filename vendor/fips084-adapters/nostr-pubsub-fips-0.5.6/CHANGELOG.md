# Changelog

## 0.5.6 - 2026-09-28

- Update to FIPS core 0.4.83 and TCP endpoint 0.2.18 for connection lifecycle,
  discovery, and identity recovery improvements. Pubsub wire behavior is unchanged.

## 0.5.5 - 2026-09-15

- Update to FIPS core 0.4.82 and TCP endpoint 0.2.17 for recovery of
  unanswered sparse traffic and interrupted UDP path handshakes.

## 0.5.4 - 2026-09-10

- Bound repeated service connection attempts to one per three seconds per
  selected peer, including subscription-triggered sends. First attempts remain
  immediate; retained subscriptions recover when a late service becomes ready.
  The default 500 ms one-shot query timeout can expire during this retry window.
- Validate peer identities after admission checks and borrow temporary selection
  keys to remove repeated decoding and copies without caching trust decisions.
- Update to FIPS core 0.4.81 and TCP endpoint 0.2.16. FIPS sizes initial crypto
  work allocations to admitted batches while retaining full-batch capacity,
  continuation growth, packet ordering and the existing wire protocols.
- Request missing route coordinates through existing bounded lookup when a
  session needs to rekey. Key rotation can recover after coordinate cache
  eviction while an existing data route remains active.

## 0.5.3 - 2026-09-10

- Add `shutdown_shared()` so applications can close subscriptions and join owned
  tasks while providers still retain the client. Reject new work after shutdown
  starts and preserve unfinished joins across cancellation.

## 0.5.2 - 2026-09-10

- Apply the shared bounded peer selector and optional trusted-rater policy in
  high-level clients. Trust entrypoints default to empty; service quality alone
  does not grant authority to rate peers or access application data.
- Manage the bounded rating subscription and paced publication with the client.
- Update to FIPS core 0.4.79 and TCP endpoint 0.2.15 for quieter idle feedback.

## 0.5.1 - 2026-09-09

- Restore and announce an evicted payload when a local application explicitly
  retries the original signed event. A durable outbox can now recover messages
  beyond the live replay window after a peer arrives.
- Keep inbound gossip deduplication and payload/seen-ID bounds unchanged.
  Applications should pace retry batches within their configured replay window.
- Reject oversized record prefixes immediately and close only the offending
  stream, preserving healthy peers' frames. Expose framing and transport
  failures through `transport_error_count()`.
- Update to FIPS 0.4.78, TCP 0.2.2 and TCP endpoint 0.2.14 for retained-route
  recovery and bounded repair of a flight of packets lost during an outage.
  Real WebSocket regressions recover through an uninterested restarted router,
  including 70 signed events against a 64-event replay window.

## 0.5.0 - 2026-09-09

- Reach known application service identities through ordinary FIPS routing,
  including intermediates that run no pubsub client. Replace the bounded routed
  roster without rebuilding application subscriptions.
- Add `routed_peers` to `FipsPubsubClientOptions`. Existing explicit struct
  literals must add this field or use `..Default::default()`; this source change
  is why the release advances to 0.5. The wire protocol is unchanged.
- Preserve a stable bounded subset when the endpoint has more physical peers
  than pubsub capacity. Release all old peer state and queue capacity on
  selection turnover; retain/replay subscriptions across recovered streams.
- Update to `nvpn-fips-core` 0.4.77 and `nvpn-fips-tcp-endpoint` 0.2.13,
  including bounded future timestamp skew for signed routing ratings.

## 0.4.19 - 2026-09-08

- Update to `nvpn-fips-core` 0.4.76 and `nvpn-fips-tcp-endpoint` 0.2.12
  for UDP receive error backoff. Wire formats are unchanged.

## 0.4.18 - 2026-09-07

- Update to `nvpn-fips-core` 0.4.75 and `nvpn-fips-tcp-endpoint` 0.2.11 so
  authenticated pubsub carriers recover automatically after a same-identity
  recipient restarts and loses its previous encrypted session.
- Pubsub, FIPS, and TCP/FIPS wire formats are unchanged.

## 0.4.17 - 2026-09-05

- Update to `nvpn-fips-core` 0.4.74 and `nvpn-fips-tcp-endpoint` 0.2.10 for
  bounded replay bookkeeping, authenticated direct-path updates, and correct
  delivery-feedback timing when a quiet path becomes active.
- Inherit corrected simultaneous-handshake ownership and bounded retries for
  the first queued payload while mesh reachability is still arriving.
- Pubsub, FIPS, and TCP/FIPS wire formats are unchanged.

## 0.4.16 - 2026-09-04

- Update to `nvpn-fips-core` 0.4.73 and `nvpn-fips-tcp-endpoint` 0.2.9 so
  authenticated pubsub carriers inherit the routing, transport cleanup, and
  BLE identity hardening.
- Pubsub, FIPS, and TCP/FIPS runtime and wire behavior are unchanged.

## 0.4.15 - 2026-08-31

- Update to `nvpn-fips-core` 0.4.72 and `nvpn-fips-tcp-endpoint` 0.2.8 so
  release verification uses the corrected configured-peer cache fixtures.
- Pubsub, FIPS, and TCP/FIPS runtime and wire behavior are unchanged.

## 0.4.14 - 2026-08-31

- Update to `nvpn-fips-core` 0.4.71 and `nvpn-fips-tcp-endpoint` 0.2.7 so
  authenticated pubsub carriers reuse validated configured-peer identities
  during liveness recovery.
- Pubsub and FIPS wire formats and retry timing are unchanged.

## 0.4.13 - 2026-08-31

- Update to `nvpn-fips-core` 0.4.70 and `nvpn-fips-tcp-endpoint` 0.2.6 so
  authenticated pubsub carriers retry recovered direct paths promptly across
  repeated outages.
- Pubsub and FIPS wire formats are unchanged.

## 0.4.12 - 2026-08-31

- Update to `nvpn-fips-core` 0.4.69 and `nvpn-fips-tcp-endpoint` 0.2.5 so
  authenticated pubsub carriers recover across consecutive outages without
  stale loss feedback immediately degrading the restored direct route.
- Pubsub and FIPS wire formats are unchanged.

## 0.4.11 - 2026-08-28

- Update to `nvpn-fips-core` 0.4.68 and `nvpn-fips-tcp-endpoint` 0.2.4 so
  pubsub streams share repeated roaming, rekey, and live-rebind recovery fixes.
- Pubsub and TCP/FIPS wire formats are unchanged.

## 0.4.10 - 2026-08-28

- Update to `nvpn-fips-core` 0.4.67 and `nvpn-fips-tcp-endpoint` 0.2.3 so
  direct-path payload validation survives in-flight fallback traffic during a
  live network rebind. The pub/sub API and FIPS/TCP wire behavior are
  unchanged.

## 0.4.9 - 2026-08-28

- Update to `nvpn-fips-core` 0.4.66 and `nvpn-fips-tcp-endpoint` 0.2.2 so
  repeated underlay outages and live source-address changes re-arm an
  exhausted direct-path handshake without changing the pub/sub API or FIPS
  wire behavior.

## 0.4.8 - 2026-08-25

- Use the Nostr VPN-maintained `nvpn-fips-core` 0.4.65, `nvpn-fips-tcp` 0.2.1,
  and `nvpn-fips-tcp-endpoint` 0.2.1 packages while preserving the existing
  Rust API names and FIPS wire behavior.

## 0.4.7 - 2026-07-21

- Stop driving an empty TCP/FIPS state machine after the authenticated carrier
  link disappears. Active, connecting, and closing streams retain the 200 ms
  retransmission cadence while idle mobile clients avoid needless polls.

## 0.4.6 - 2026-07-21

- Keep stable authenticated FIPS peer identities out of the 200 ms TCP timer
  path. Decode an npub only when its authenticated link changes, preserving
  retransmission timing while reducing mobile idle CPU and allocation churn.
- Raise the FIPS dependency floor to 0.4.34 for the roaming, reconnect,
  liveness, and rekey repairs.

## 0.4.5 - 2026-07-20

- Bound live `INV` propagation to a deterministic per-event peer fanout. The
  same signed event selects a stable peer set while fresh event IDs rotate the
  load, preserving ordinary multi-hop gossip and late-peer replay without
  multiplying every announcement across every connected adjacency.

## 0.4.4 - 2026-07-20

- Subscribe every high-level FIPS pubsub client to default `fips-overlay-v1`
  kind `37195` endpoint adverts, publish the local signed advert into bounded
  replay, refresh it at half its signed TTL (at most every 30 minutes), and
  ingest received adverts through the transport-neutral FIPS validator without
  opening Nostr relay sockets. Reserve this internal subscription in addition
  to the configured application subscription limit.
- Add optional shared social-graph event admission at the FIPS pubsub boundary,
  before a received event enters local delivery, replay, or multi-hop gossip.

## 0.4.3 - 2026-07-19

- Keep separate bounded accepted-event and observed-ID caches. Structurally
  valid full events and inventory claims are observed per authenticated peer
  and subscription epoch before policy acceptance, with 1,024 IDs per scope
  and a 16,384-ID aggregate ceiling.
- Suppress repeated out-of-filter delivery, score objective provider
  misbehavior with decay, and disconnect providers behind a bounded reconnect
  cooldown after sustained abuse. Malformed records count more strongly;
  isolated filter races do not affect event authors or social reputation.
- Quiesce idle FIPS pubsub transport work, bound provider retries, and expose
  wire/TCP/cooldown counters without changing the reliable INV/WANT/EVENT
  protocol.
- Expose policy checks for already verified Nostr events so callers retain the
  verified object across admission and avoid duplicate signature validation.

## 0.4.2 - 2026-07-18

- Retry `WANT` against its sole advertised provider until the ordinary
  addressed `EVENT` arrives; alternate providers still rotate first. This
  closes live mesh delivery gaps when a queued request coincides with a
  FIPS-TCP connection transition.

## 0.4.1 - 2026-07-18

- Use grouped `INV`, one-event `WANT`, and ordinary addressed `EVENT` for both
  bounded historical replay and new live events over reliable FIPS-TCP.
- Depend on `nostr-pubsub` 0.1.13 so FIPS sources compose with the shared
  historical/live router used by Hashtree indexes and traditional relays.

## 0.4.0 - 2026-07-18

- Carry ordinary Nostr `REQ`, `EVENT`, and `CLOSE` frames exclusively over
  reliable `fips-tcp` on FIPS service port 7368; remove the raw-FSP datagram
  carrier and compatibility fallback.
- Add grouped subscription-scoped `INV`/`WANT` live delivery: duplicate inventories
  from many peers and open subscriptions select one provider and fetch one
  ordinary `EVENT`, then fan it out to every matching local subscription.
- Bound pending inventory, alternate-provider retry, replay, peer, record, and
  byte state; expose delivery counters for deterministic mesh observability.
- Preserve the low-level generic Inv/WANT TCP driver for applications that do
  not use Nostr subscription semantics.

## 0.3.2 - 2026-07-18

- Add an explicit excluded-transport set for applications whose FIPS pubsub
  carrier must not recursively select the transport it is carrying.
- Keep every other authenticated connected peer eligible; default clients
  retain the existing all-transport behavior.

## 0.3.1 - 2026-07-16

- Add a bounded, sans-I/O Inv/WANT record layer for reliable `fips-tcp`
  carriers, with split/coalesced large records and bounded retained input.
- Apply event admission before cache, delivery, or forwarding and peer policy
  before queueing traffic.
- Restore verified durable snapshots into the existing bounded mesh cache and
  replay inventories on every peer connection or reconnection.
- Add the manually driven `fips-tcp-endpoint` production carrier with generic
  service namespace/version, bounded partial-write queues, deterministic
  duplicate-stream selection, and explicit reconnect ownership.
- Exercise two real FIPS endpoints through large split records, coalesced
  records, simultaneous and late connection, forced reconnect, replay, and
  queue pressure.

## 0.3.0 - 2026-07-15

- Move the adapter to `fips-core 0.4.0` without changing its bounded FSP
  datagram protocol.
- Keep external peerfinding on the application-provided `EventBus`; the
  adapter neither opens relay sockets nor adds an adapter-local workaround.
- Advertise `nostr.pubsub/1` only for the lifetime of the registered FSP
  service.
