---
name: nostr-vpn
description: Connect an authorized machine to a Nostr VPN private mesh, review device join requests, and verify access with the nvpn CLI. Use for account-free private networking between agent hosts, people, and servers.
---

# Nostr VPN

Use the `nvpn` CLI for private networking without a VPN provider account.
Every device retains its own identity; network membership still needs an
administrator's approval. This workflow does not require paid exits.

## Establish the execution context

- Run `nvpn --version`, `nvpn join-requests --help`, and
  `nvpn join-request --help`. CLI approval and JSON join-request output are
  currently source-only and have not yet shipped in a release. Install a matching
  binary from https://github.com/mmalmi/nostr-vpn/releases/latest or use
  `cargo install nvpn`. Check the release's supported architecture.
- Choose an explicit, persistent absolute config path and pass `--config` on
  every command, including elevated ones. Reuse a designated profile; never
  overwrite an existing one with `init --force`.
- A Linux tunnel needs network privileges, `/dev/net/tun`, and `iproute2`;
  containers need `NET_ADMIN` and the TUN device. macOS/Windows need elevated
  platform networking setup. A cloud terminal or plugin does not confer this
  access. If unavailable, report that specific limitation and use an authorized
  machine with those capabilities.
- Persist config and key sidecars privately. Give separate devices separate
  keys. Do not print private keys, copy the admin identity to a joining device,
  or put join links into public output.

## Create or join

On a new admin host, run `nvpn init --config "$NVPN_CONFIG"`, then use the
printed public `nostr_pubkey` with
`nvpn set --config "$NVPN_CONFIG" --device "$ADMIN_DEVICE_ID"`.
Start it with `nvpn start --config "$NVPN_CONFIG" --daemon --connect`.

On the joining host, initialize its own config and start its daemon the same
way, then run `nvpn join-request --config "$NVPN_CONFIG" --json`. The
`join_request` field contains the link to share with the intended admin through
the user's selected channel. JSON output returns immediately and does not
resume a paused daemon. Keep the daemon connected; obtain a fresh link if a
macOS/Linux joining daemon restarts.

On the admin host, save the received link in a private file and run:

```sh
nvpn join-requests inspect --request-file "$REQUEST_FILE" --json
```

Inspection is read-only. Check the returned device ID with the intended joiner;
the supplied name alone is not proof. When admission of that device to the
config's active network is authorized, run:

```sh
nvpn join-requests approve --config "$NVPN_CONFIG" \
  --request-file "$REQUEST_FILE" --json
```

This signs the roster, queues delivery, and resumes an already-running paused
admin daemon. If it is stopped, start it. `delivery: queued` is not a delivery
receipt. Keep both daemons connected until the joiner receives approval.

For inbound manual-join requests, use
`nvpn join-requests list --config "$NVPN_CONFIG" --json`, then approve exactly
the selected pending ID with `join-requests approve --device "$DEVICE_ID"` and
the same config. Shared links need not appear in that list.

If the installed CLI lacks `join-requests` or `join-request --json`, use the
interactive `join-request` and the native admin app's **Devices → Add Join
Request**, or build current source with
`cargo install --locked --path crates/nostr-vpn-cli` from its checkout. Do not
substitute private-key sharing or manual signed-roster edits.

## Verify the requested result

Run `nvpn status --config "$NVPN_CONFIG" --json`. Interpret readiness only when
`status_source` is `daemon`; config-only readiness is unknown. Use
`nvpn ip --config "$NVPN_CONFIG" --peer --json` and
`nvpn ping --config "$NVPN_CONFIG" "$PEER_TUNNEL_IP"`, then access the actual
service the user requested using its normal authentication. Report queued
approval, mesh reachability, DNS, and service access separately when they differ.

Avoid changing default routes, selecting paid exits, or spending funds unless
that is part of the user's request. Stop only a daemon started for a temporary
task with `nvpn stop --config "$NVPN_CONFIG"`; preserve existing services.

Detailed guide: https://github.com/mmalmi/nostr-vpn/blob/master/docs/agents.md
