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
are rejected. `10.44.0.0/16` is allowed, subject to the uniqueness rule.

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
- a value is not an IPv4 `/32` inside the assignable ranges;
- an assigned address equals another member's effective address, assigned or
  derived.

`roster_address_assignments` checks the tags themselves: a valid pubkey, at
most one tag per member, and an IPv4 `/32`. `effective_mesh_tunnel_ipv4s`
checks membership, the assignable ranges and uniqueness. Signing and
verification will call both when assignments are enabled.

Two derived addresses can already collide today. That behavior is unchanged,
and an admin can resolve it by assigning one of the two members an address.

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
3. **Enable.** The parser accepts v2 rosters and `address` tags, and admin
   apps and the CLI can set them. Admin apps warn while any member runs a
   version that rejects v2, because those members stop receiving roster
   updates until they upgrade.

No release advertises assignment support before step 3.

## Changing, removing and rolling back

- Changing an assignment is a new signed roster. Members rebuild routes,
  MagicDNS records and admission from the new effective map and remove state
  for the old address, as for a member removed and re-added. Connections to
  the old address end.
- Removing the last assignment produces a v1 roster again, which older clients
  accept. That is the rollback path.

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
