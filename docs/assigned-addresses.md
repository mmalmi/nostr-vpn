# Assigned Tunnel Addresses

Status: proposed in #159, not enabled. This document settles the roster schema,
versioning and rollout before any client accepts assignments. The code that
lands with it is limited to validation, the effective-address function and
compatibility fixtures.

## Goal

Let a network admin give a member a fixed tunnel IPv4 address instead of the
derived `10.44.x.y/32`. Two cases motivate it:

- Moving an existing network to nvpn without renumbering, for example a
  Tailscale or headscale tailnet whose `100.64.0.0/10` addresses are written
  into firewall rules, service bind addresses and monitors.
- A member whose LAN overlaps `10.44.0.0/16` (#158).

Automatic addresses stay the default. Most networks never set one.

## One effective address per member

Each member has exactly one effective IPv4 tunnel address: its assigned address
when the roster assigns one, otherwise the derived address. Routing, MagicDNS,
packet admission, exit forwarding sources and mobile route targets all use the
effective address. No consumer derives addresses on its own once assignments
are enabled.

`effective_mesh_tunnel_ipv4s(network_id, members, assignments)` computes the
map from a roster and is the single place that applies the rules below.

## Address policy

An admin may assign any IPv4 address in:

| Range | Source |
| --- | --- |
| `10.0.0.0/8` | RFC 1918 |
| `172.16.0.0/12` | RFC 1918 |
| `192.168.0.0/16` | RFC 1918 |
| `100.64.0.0/10` | RFC 6598, used by Tailscale-style networks |

Public, loopback, link-local, multicast, broadcast and unspecified addresses
are rejected. `10.44.0.0/16` is allowed, subject to the uniqueness rule,
except `10.44.0.53`: nvpn already serves MagicDNS there, so assigning it to a
device would make DNS traffic to that address ambiguous.

There is no per-network address pool. A pool would be one more signed field to
validate, migrate and display, and the migration case needs only the address.
The admin chooses addresses that do not collide with members' LANs; nvpn
cannot know those ranges. A pool can be added later if networks need one.

## Roster tag

```text
["address", "<member pubkey hex>", "<a.b.c.d>/32"]
```

One tag per assigned member. The `/32` matches the allowed-IP format nvpn
already uses and leaves room for `/128` if IPv6 assignments follow.

## Validation

Signing refuses, and verification rejects as a whole, a roster where:

- an `address` tag names a pubkey that is not a `member`;
- a member has more than one `address` tag;
- a value is not an IPv4 `/32` inside the assignable ranges, or is the
  MagicDNS address `10.44.0.53`;
- two members end up with the same effective address, whether assigned or
  derived.

Uniqueness is checked across the final map, not only against assignments. Two
derived addresses can already collide today, and a v1 roster keeps that
behavior. Once a roster assigns any address, a derived collision is rejected
too, even when the assignment is for an unrelated member, and the admin
resolves it by assigning one of the two colliding members.

`roster_address_assignments` checks the tags themselves: a valid pubkey, at
most one tag per member, and an IPv4 `/32`. `effective_mesh_tunnel_ipv4s`
checks membership, the assignable ranges, the MagicDNS reservation and
uniqueness. Signing and verification will call both when assignments are
enabled.

| Fixture in `network_routes.rs` | Pins |
| --- | --- |
| `assignable_space_is_private_and_shared_ipv4_only` | the ranges, with `10.44.0.53` rejected |
| `invalid_assignments_are_rejected` | non-members, public space, the MagicDNS address, shared and reused addresses |
| `colliding_derived_addresses_need_an_assignment_once_a_roster_assigns_any` | v1 keeps a derived collision; an unrelated assignment exposes it; assigning a colliding member resolves it |

## Versioning

- A roster without `address` tags stays exactly as today: `v` is `"1"`, with
  the same tags in the same order.
- A roster with at least one `address` tag carries `v` = `"2"`. Clients before
  the enabling release reject it as an unsupported version. Without the bump
  they would skip the unknown tag, accept the roster and keep deriving a
  different address, so traffic between old and new clients would be dropped
  by packet admission.
- A roster carries exactly one version tag. Until this change the parser
  accepted a roster when any `v` tag matched, so `["v","1"]` plus `["v","2"]`
  passed as v1. Missing, malformed and duplicate version tags are now
  rejected. Clients released before this change keep the old behavior, so
  producers must never emit more than one version tag.

Fixtures in `fips_control_tests.rs` pin each of these:

| Fixture | Pins |
| --- | --- |
| `unassigned_roster_keeps_the_v1_tag_layout` | the exact v1 tag layout |
| `current_parser_rejects_a_roster_with_assigned_addresses` | a v2 roster with an `address` tag is rejected |
| `v1_parser_ignores_an_address_tag_so_assignments_need_a_new_version` | why the version must change |
| `roster_requires_exactly_one_well_formed_version_tag` | missing, malformed and duplicate version tags |

## Rollout

1. **This change.** Design, `roster_address_assignments`,
   `effective_mesh_tunnel_ipv4s`, `is_assignable_tunnel_ipv4`, version-tag
   hardening and fixtures. Neither signing nor verification reads or writes
   `address` tags yet, and v2 rosters are still rejected.
2. **Consumers, one PR per platform.** Desktop (Linux, macOS, Windows) and
   mobile take addresses from the effective map instead of deriving them per
   peer. They still receive only v1 rosters, so behavior does not change.
   Exit forwarding sources and mobile route targets move from the
   `10.44.0.0/16` constant to members' effective `/32`s. The #158 overlap
   fixes land on their own before this step; it builds on them and does not
   block them.
3. **Enable.** The parser accepts v2 rosters and `address` tags, clients
   advertise that they accept v2, and admin apps and the CLI can set
   assignments behind the gate below.

No release advertises assignment support before step 3.

## First v2 roster: the gate

A client that rejects v2 keeps its last v1 roster. It stops receiving roster
updates, including revocations: a member removed in a v2 roster stays admitted
by that client. So the first assignment in a network is gated on evidence that
every retained member can apply v2.

- **Evidence.** From step 3, each client lists the roster versions it accepts
  in the capabilities frame it already sends its peers (`PeerCapabilities`,
  a new `roster_versions` field that older clients ignore). The frame arrives
  over the FIPS session authenticated as that member's key. The admin's
  device keeps the latest list each member sent and when.
- **Gate.** Admin apps and the CLI refuse to sign the first roster with an
  `address` tag while any retained member or admin has not advertised v2. They
  list those members. The admin either waits for them to upgrade and connect,
  or removes them in the same roster, which isolates them: v2 clients stop
  admitting them, and the admin re-adds them after they upgrade. Admins are
  included because an admin device on an old release would sign v1 rosters
  that silently drop every assignment (see the last row below).
- **After the first v2 roster**, the admin's device keeps checking. A member
  whose latest list no longer includes v2, after a downgrade, is flagged with
  the same choice.

Expected behavior:

| Situation | Clients that accept v2 | A client that rejects v2 |
| --- | --- | --- |
| Revocation before the first assignment | Apply it (v1 roster) | Apply it (v1 roster) |
| First v2 roster, retained members all advertise v2 | Apply it | Only possible after a downgrade; see the next rows |
| First v2 roster removes members without evidence | Stop admitting them | Keeps its last v1 roster and is isolated: v2 clients do not admit it, and it reaches only other members still on that roster |
| Revocation in a later v2 roster | Enforce it | Keeps admitting the revoked member until it upgrades or receives a newer v1 roster; the gate and the downgrade flag keep such clients out of the network |
| Newer signed v1 roster (rollback: last assignment removed) | Accept it; members return to derived addresses | Accepts it and catches up, including revocations made while v2 was in effect |
| An older v1 roster replayed after a v2 one | Reject it: a roster must be strictly newer than the current one (`signed_at`, existing rule) | Reject it on the same rule if it already holds a newer v1 roster |
| An admin device on an old release signs a v1 roster | Accept it, as a rollback; assignments disappear until an admin re-signs them | Accepts it |

## Changing, removing and rolling back

- Changing an assignment is a new signed roster. Members rebuild routes,
  MagicDNS records and admission from the new effective map and remove state
  for the old address, as for a member removed and re-added. Connections to
  the old address end.
- Removing the last assignment produces a v1 roster again, which older clients
  accept. That is the rollback path; the table above lists how each client
  treats it.

## Admin UX

As suggested in #159: **Device details → VPN IP → Edit**, available to network
admins.

- **Automatic** (default) shows the current derived address.
- **Custom IPv4** takes an address from the assignable ranges and is checked
  against the rules above before signing.
- **Reset to automatic** removes the assignment.

Prior art: Tailscale's
[stable automatic addresses](https://tailscale.com/docs/concepts/ip-and-dns-addresses)
and [admin IPv4 editing](https://tailscale.com/docs/reference/ip-pool).

## Not covered

IPv6 assignments, per-network address pools, and access control between
members.
