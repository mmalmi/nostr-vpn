# nostr-pubsub-fips

Reliable authenticated Nostr pubsub over FIPS.

`FipsPubsubClient` carries normal Nostr `REQ`, `EVENT`, and `CLOSE` JSON frames
as bounded records over `fips-tcp`, using FIPS service port `7368` and
capability `nostr.pubsub/1`. There is no raw-FSP datagram fallback and this
crate opens no Nostr relay socket.

The Rust dependencies are published as `nvpn-fips-core`, `nvpn-fips-tcp`, and
`nvpn-fips-tcp-endpoint`. Their dependency aliases preserve the established
Rust API names.

Every high-level client keeps one bounded default subscription for signed
`fips-overlay-v1` kind `37195` endpoint adverts. It publishes its FIPS-generated
local advert into replay, refreshes it at half its signed TTL (capped at 30
minutes), ingests received adverts through FIPS's normal validator, and gossips
them over matching FIPS subscriptions. This works with an empty Nostr relay
list. Applications with a social-graph policy should use
`FipsPubsubClient::start_with_policies` with `FipsPubsubPolicy::client_policies()`
to apply one shared trust projection to peer preference and event admission.
Admission runs before local delivery, replay retention, or forwarding.
The existing `start_with_policy` remains available for event admission alone.

Trust entrypoints come from application configuration through
`FipsPubsubPolicyOptions::reputation.trusted_raters`, which accepts public keys
in hex or npub form and defaults to an empty set. No person's identity is
chosen automatically. This projection consumes signed machine ratings; it does
not import personal follow lists or grant access to application data. Positive
service ratings do not authorize a peer to rate others.

`FipsPubsubClient::start_with_reputation(endpoint, options, reputation_options)`
also manages the bounded rating subscription and paced local publication. It
uses one slot from `max_active_subscriptions`, subscribes only to the local root
and configured raters, and releases its task and subscription with the client.
Local observations update preference even when publication fails. The default
evaluation interval is one minute, and both publication batches and replay are
bounded. `reputation_error_count()` exposes failed updates or publications.
Ratings are retained in memory and recover through available peer replay; use
the policy facade directly when the application needs durable rating storage.

Applications sharing a client through `Arc` must call
`client.shutdown_shared().await` before stopping its FIPS endpoint. It closes
subscriptions, rejects new publication/query/subscription work, and joins every
owned task even while providers retain the client. Concurrent shutdown callers
wait for completion; a cancelled caller leaves unfinished joins available to
the next caller. The consuming `shutdown().await` remains available. Client
shutdown leaves the application-owned endpoint running.

The high-level client uses the same bounded quality selector as the lower-level
mesh. With a peer policy, direct connections and inventory fanout prefer higher
scores while retaining `unknown_peer_reserve` exploration slots (one by default).
Explicit routed identities keep priority if admitted by the policy. Changing
shared policy state updates existing connections and subscriptions; rejected
peers release their pubsub state while application-owned FIPS links stay intact.
Without a peer policy, the original identity-ordered connection selection and
event-dependent fanout remain unchanged.

Repeated pubsub service connection attempts are spaced at least three seconds
apart per selected peer, including attempts triggered by new outgoing frames.
The first attempt remains immediate. This monotonic retry bound avoids busy
reconnect loops when a reachable FIPS peer has no pubsub service or repeatedly
closes its stream. It does not penalize the peer's transport reputation.
Retained subscriptions replay when the service returns. A one-shot query can
still reach its configured timeout during recovery: the default 500 ms query
window is shorter than the retry interval, so applications needing that
recovery window should configure `query_timeout` accordingly.

Applications can supply known service identities in
`FipsPubsubClientOptions::routed_peers`, then replace that bounded roster using
`set_routed_peers` as authorized devices join or leave. These destinations take
priority within the connection limit and use ordinary authenticated FIPS
routing. Intermediate nodes need no pubsub service or matching subscription.
The roster provides identities, not physical addresses or a separate routing
protocol; the endpoint still needs a working route. Restricting peer transports
and routed identities cannot be combined because the endpoint API does not
expose every transport along an indirect path.
The supplied roster must fit `max_connected_peers`; temporarily unreachable
configured identities retain their slots until the application removes them.

Live mesh delivery is inventory-first. For every new event, providers send a
small `INV` containing every matching open `REQ` subscription ID for that peer.
A receiver dedupes the event ID across all peers and all of its live
subscriptions, sends one one-event `WANT` to one provider, and receives one
ordinary subscription `EVENT`. That verified event is then delivered once to
every matching local subscription.
Alternate providers are retained within fixed bounds and selected if the first
request does not complete. `CLOSE` retains its normal subscription semantics.

Recent events are kept in a bounded replay cache so a `REQ` or reconnected TCP
peer can receive inventories for the live window. The same `INV`/`WANT` flow
also works for historical events. For a large stored set, a reconciliation
layer such as NIP-77 Negentropy can identify the missing IDs first and then use
the same event transfer path more efficiently.

An explicit local publish retries a payload that has left this replay window,
while duplicate incoming gossip stays suppressed. Durable application outboxes
should pace retry batches within `max_replay_events` so payloads remain
available while peers request them; the client itself is not a durable store.

The package also exports the lower-level `FipsInvWantTcpDriver` for non-Nostr
mesh protocols, plus transport-neutral FIPS peerfinding and reputation
adapters. It targets the FIPS `0.4.x` endpoint API.
