# Protocol

This document describes the protocol that `nostr-vpn` currently implements in this repository.

The `README.md` should stay product-facing. Protocol details live here so they can track the code more closely.

## Scope

`nostr-vpn` is split into three layers:

- Out-of-band bootstrapping with invite payloads and QR codes
- A Nostr-based control plane for discovery, membership, signaling, and optional relay services
- A UDP/WireGuard data plane for the actual tunnel

Only the active network participates in the live runtime.

## Identities And Stable IDs

| Name | Purpose | Format |
| --- | --- | --- |
| Nostr identity keypair | Authenticates Nostr events and admin actions | `nsec`/`npub` at the edges, normalized to hex internally |
| WireGuard keypair | Authenticates the tunnel peer itself | WireGuard base64 keys |
| `node_id` | Human-meaningful node/session identifier in announcements and disconnects | String |
| `network_id` | Mesh identifier used for signaling scope and tunnel-IP derivation | String |

Important details:

- `network_id` is normalized at runtime by stripping the legacy `nostr-vpn:` prefix if present.
- The active network's signal audience is `participants + admins`, deduped.
- If tunnel IP auto-configuration is enabled, the local node derives its `/32` as:
  - `SHA256(network_id + "\n" + own_nostr_pubkey_hex)`
  - `10.44.(digest[0] % 254 + 1).(digest[1] % 254 + 1)/32`

## Nostr Event Kinds

Two Nostr kinds matter today:

| Kind | Purpose |
| --- | --- |
| `25050` | Mesh signaling, join requests, and relay service control messages |
| `30078` | Public node records used to discover service operators |

Kind `25050` is multiplexed by tags and decrypted JSON shape rather than by separate kinds.

## Control Plane On Kind 25050

### Public Hello

Peers publish a small public heartbeat to let configured peers notice them:

- Kind: `25050`
- Content: empty string
- Tags:
  - `d=hello`
  - `l=hello`
  - `expiration=<now+300s>`
- Subscription lookback: 60 seconds

This message is public and not encrypted.

### Private Mesh Signals

Most control-plane traffic is sent as one NIP-44 v2 encrypted event per recipient:

- Kind: `25050`
- Encryption: NIP-44 v2 from sender Nostr secret key to recipient Nostr pubkey
- Tags:
  - `d=private:<network_id>:<recipient_pubkey_hex>`
  - `p=<recipient_pubkey_hex>`
  - `expiration=<now+300s>`
- Subscription lookback: 120 seconds

Decrypted payload shape:

```json
{
  "network_id": "mesh-home",
  "sender_pubkey": "<sender_pubkey_hex>",
  "payload": {
    "type": "Announce",
    "data": {}
  }
}
```

`payload.type` can currently be:

- `Hello`
- `Announce`
- `Roster`
- `Disconnect`
- `JoinRequest`

In practice:

- `Hello` is published as the public hello event above, then surfaced to the runtime as `SignalPayload::Hello`.
- `JoinRequest` is normally sent with the dedicated join-request envelope described below, then converted into `SignalPayload::JoinRequest` when received.

Receivers discard decrypted signal envelopes unless:

- `network_id` matches a configured active network
- `sender_pubkey` matches the actual event author
- the sender is in the configured participant/admin set for that network

### Peer Announcement Payload

`Announce` carries the current WireGuard and reachability state for a node:

| Field | Meaning |
| --- | --- |
| `node_id` | Sender's node identifier |
| `public_key` | Sender's WireGuard public key |
| `endpoint` | Compatibility endpoint field; usually public when available, otherwise local |
| `local_endpoint` | Sender's LAN/private UDP endpoint when known |
| `public_endpoint` | Sender's discovered public UDP endpoint when known |
| `relay_endpoint` | Temporary relay ingress endpoint when a relay fallback session is active |
| `relay_pubkey` | Relay operator pubkey for `relay_endpoint` |
| `relay_expires_at` | Expiration time for the advertised relay endpoint |
| `tunnel_ip` | Sender's tunnel `/32` |
| `advertised_routes` | Extra routes the sender wants to carry |
| `timestamp` | Sender-side timestamp |

Runtime endpoint selection is path-aware, but the broad rule is:

- Prefer a same-subnet local endpoint when both peers appear to be on the same private LAN
- Otherwise prefer a public endpoint
- Prefer a live relay endpoint over stale direct paths when a relay session is active
- Keep using a recently successful path until there is a reason to rotate

### Disconnect Payload

`Disconnect` contains only:

```json
{
  "type": "Disconnect",
  "data": {
    "node_id": "..."
  }
}
```

It removes the sender's current active announcement from peer presence.

## Membership Protocol

### Invite Format

Invites are shared out of band as:

- `nvpn://invite/<base64url(json)>`

Current invite payload version: `2`

Accepted versions on import: `1` and `2`

Normalized payload shape:

```json
{
  "v": 2,
  "network_name": "Home",
  "network_id": "mesh-home",
  "inviter_npub": "npub1...",
  "inviter_node_name": "laptop",
  "admins": ["npub1..."],
  "participants": ["npub1..."],
  "relays": ["wss://example.com"]
}
```

Normalization rules:

- the inviter is always added to `admins`
- `participants` defaults to the inviter if omitted
- relay URLs are deduped and merged into local config on import
- invite pubkeys are stored in invite payloads as `npub`, then normalized to hex in config/runtime

Invites are bootstrap material, not authority. The authoritative membership state comes from admin-signed shared rosters.

### Join Requests

After importing an invite, a joining node sends join requests to all known admins for that network.

Wire format:

- Kind: `25050`
- Encryption: NIP-44 v2
- Tags:
  - `d=join-request:<recipient_pubkey_hex>`
  - `p=<recipient_pubkey_hex>`
  - `expiration=<now+7d>`

Decrypted payload:

```json
{
  "v": 1,
  "network_id": "mesh-home",
  "requester_node_name": "phone"
}
```

Notes:

- the daemon can stay connected only for join-request listening even when the mesh session itself is paused
- inbound join requests are stored per network and deduped by requester
- once a requester becomes a participant, stale stored join requests for that requester are dropped

### Admin-Signed Shared Roster

Admins synchronize membership by sending `Roster` payloads over the private signal channel.

Payload shape:

```json
{
  "type": "Roster",
  "data": {
    "network_name": "Home",
    "participants": ["<pubkey_hex>", "<pubkey_hex>"],
    "admins": ["<pubkey_hex>"],
    "signed_at": 1760000000
  }
}
```

Rules enforced by the receiver:

- the sender must already be an admin for that network
- `signed_at` must be newer than the local stored roster timestamp
- the roster must contain at least one admin
- the local node removes itself from the persisted participant list when applying a roster

Operational meaning:

- rosters are the current authority for participants, admins, and network name
- local admin edits bump `shared_roster_updated_at` and `shared_roster_signed_by`
- when a newer valid roster arrives, peers reload signaling membership, prune stale participant state, and keep going with the new roster

## Public Service Discovery On Kind 30078

Public service operators advertise node records with kind `30078`.

Tags:

- `d=nostr-vpn:node`
- `t=nostr-vpn-relay` for relay providers
- `t=nostr-vpn-nat-assist` for NAT-assist providers
- `t=nostr-vpn-exit` for exit providers
- `expiration=<record expiry>`

Content shape:

```json
{
  "mode": "public_service",
  "services": [
    {
      "kind": "relay",
      "endpoint": "198.51.100.30:40001"
    }
  ],
  "updated_at": 1760000000,
  "expires_at": 1760003600
}
```

The current relay-fallback implementation discovers public relay operators by subscribing to node records tagged `t=nostr-vpn-relay`.

## Relay Service Control Messages

Relay service control messages also use kind `25050`, but they are a separate private envelope from mesh signaling:

- Kind: `25050`
- Encryption: NIP-44 v2
- Tags:
  - `p=<recipient_pubkey_hex>`
  - `expiration=<now+300s>`

Decrypted payload shape:

```json
{
  "sender_pubkey": "<sender_pubkey_hex>",
  "payload": {
    "type": "RelayAllocationRequest",
    "data": {}
  }
}
```

Current service payloads:

- `RelayAllocationRequest`
- `RelayAllocationGranted`
- `RelayAllocationRejected`
- `RelayProbeRequest`
- `RelayProbeGranted`
- `RelayProbeRejected`

Important request/grant fields:

| Message | Key fields |
| --- | --- |
| `RelayAllocationRequest` | `request_id`, `network_id`, `target_pubkey`, `requested_at` |
| `RelayAllocationGranted` | `request_id`, `network_id`, `relay_pubkey`, `requester_ingress_endpoint`, `target_ingress_endpoint`, `expires_at` |
| `RelayAllocationRejected` | `request_id`, `network_id`, `relay_pubkey`, `reason`, `retry_after_secs` |

How fallback works today:

1. A node without a recent direct handshake discovers relay operators from node records.
2. It requests allocations for specific unreachable participants.
3. On grant, it stores:
   - a local ingress endpoint it will send to
   - a remote ingress endpoint it will advertise to the target peer
4. Private peer announcements start carrying `relay_endpoint`, `relay_pubkey`, and `relay_expires_at`.
5. Relay sessions are verified, expired, cooled down on failure, and can queue standby alternatives.

## NAT Traversal And Endpoint Discovery

`nostr-vpn` tries to make direct UDP work before falling back to public relays.

Current behavior:

- discover a public UDP endpoint from configured reflectors first, then STUN servers
- keep the discovery bound to the same UDP listen port used by the tunnel
- advertise both local and public endpoints when they differ
- run UDP hole-punch attempts toward peer candidate endpoints when there is still no handshake
- re-apply the tunnel runtime after punching so WireGuard uses the refreshed socket state

The path cache tracks:

- endpoints learned from announcements
- endpoints selected by the runtime
- endpoints that produced successful handshakes

That cache keeps working paths sticky enough to avoid flapping while still allowing rotation toward better candidates.

## WireGuard Data Plane

The actual encrypted tunnel is WireGuard in userspace:

- desktop/CLI uses `boringtun`
- mobile targets use platform-specific VPN runtimes around the same control model

For each peer, the runtime builds:

- peer WireGuard public key from the latest announcement
- one selected UDP endpoint
- `allowed_ips` containing:
  - the peer's tunnel `/32`
  - any routes currently assigned to that peer

Exit-node behavior is policy on top of the same data plane:

- peers may advertise default routes
- a client picks at most one exit node
- only the selected exit node gets `0.0.0.0/0` or `::/0`

## Relay Connectivity Policy

Relays are used for signaling, not for the actual tunnel unless relay fallback is active.

If `auto_disconnect_relays_when_mesh_ready` is enabled:

- signaling relays can be paused after the expected mesh is up and handshaking
- cached presence and path state keep the tunnel running
- relays stay connected when needed for join-request listening

## Canonical Source

If this document and the code diverge, the code wins. The main protocol implementations currently live in:

- `crates/nostr-vpn-core/src/signaling.rs`
- `crates/nostr-vpn-core/src/join_requests.rs`
- `crates/nostr-vpn-core/src/node_record.rs`
- `crates/nostr-vpn-core/src/relay.rs`
- `crates/nostr-vpn-core/src/config.rs`
- `crates/nostr-vpn-core/src/paths.rs`
- `crates/nostr-vpn-cli/src/main.rs`
- `crates/nostr-vpn-gui/src-tauri/src/lib.rs`
