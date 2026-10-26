# Connect an agent to your private network

Nostr VPN connects computers, phones, servers, and agent hosts without an email,
phone number, or VPN provider account. Each device generates and keeps its own
keys. An administrator explicitly approves membership in a private network.

Use the [`nostr-vpn` agent plugin](../plugins/nostr-vpn/README.md) for supported agent clients,
or follow this guide with the `nvpn` CLI. The plugin uses the same CLI.

## Install and check the environment

Use a matching CLI archive from the [releases](https://github.com/mmalmi/nostr-vpn/releases/latest),
or `cargo install nvpn`. Check `nvpn --version` and `nvpn join-requests --help`.
The headless approval commands and `join-request --json` are currently available
in source and have not yet shipped in a release. If your
release does not expose them yet, approve the link in an admin app, or build the
current source with `cargo install --locked --path crates/nostr-vpn-cli`.

For a Linux host tunnel, the environment needs root or the appropriate network
permissions, `/dev/net/tun`, and `iproute2`. Containers need `NET_ADMIN` and an
explicitly supplied TUN device. macOS and Windows require their platform's
elevated networking/service setup. A hosted agent's terminal does not imply it
has these privileges. Use an authorized host when its cloud environment cannot
create a tunnel; a plugin cannot grant those permissions.

This walkthrough creates a private mesh. Paid exits are a separate, experimental
feature that needs funds and provider selection; they are not needed here.

## Create a network on the admin host

Choose a persistent, absolute config path. Use that same path for every command,
including elevated commands, so they don't select another identity.

```sh
export NVPN_CONFIG="$HOME/.config/nvpn/agent-network.toml"
nvpn init --config "$NVPN_CONFIG"
```

Copy the public `nostr_pubkey` printed by `init`, then include the admin device:

```sh
export ADMIN_DEVICE_ID='<public device ID from init>'
nvpn set --config "$NVPN_CONFIG" --device "$ADMIN_DEVICE_ID"
nvpn start --config "$NVPN_CONFIG" --daemon --connect
```

Keep the config and its key sidecars together and private. Do not copy the
admin's private keys onto the joining machine. Do not use `init --force` on an
existing profile.

## Request access from the agent host

Initialize a separate config on the joining host, then start its daemon:

```sh
export NVPN_CONFIG="$HOME/.config/nvpn/agent-device.toml"
nvpn init --config "$NVPN_CONFIG"
nvpn start --config "$NVPN_CONFIG" --daemon --connect
nvpn join-request --config "$NVPN_CONFIG" --json
```

The JSON contains `join_request`, an `nvpn://join-request/…` link. Share that link
with the intended administrator through an agreed channel. It contains a request
secret; keep it out of public logs, posts, and repository files. The device's
private key stays on the device.

Keep the daemon connected. On macOS and Linux the pending link belongs to the
running daemon; if it restarts, obtain and review the current link again.
Interactive users can run `nvpn join-request --config "$NVPN_CONFIG"` to show a
QR and wait for approval. `--json` returns immediately and does not resume a
paused daemon.

## Review and approve on the admin host

Save only the received link to a private file, represented by `$REQUEST_FILE`
below. A path avoids putting the link's secret into shell history or process
arguments. Review its public device ID and name:

```sh
nvpn join-requests inspect --request-file "$REQUEST_FILE" --json
```

Inspection changes nothing and omits the request secret. Verify the device ID
with the joining person or agent. The link is an invitation to approve that
device; its label is not proof of who owns it.

After deciding to admit that device to the admin config's **active network**:

```sh
nvpn join-requests approve --config "$NVPN_CONFIG" \
  --request-file "$REQUEST_FILE" --json
```

Approval requires the local identity to be an administrator. It signs the updated
roster and queues it for the existing daemon's FIPS delivery path. A running,
paused admin daemon resumes to deliver it. `"delivery": "queued"` means the
approval is saved, not that the joiner has received it. Start the admin daemon
if it is stopped and keep both devices connected until receipt.

For requests received through `join-manual`, list the pending devices, then
explicitly choose one public ID from the list:

```sh
nvpn join-requests list --config "$NVPN_CONFIG" --json
nvpn join-requests approve --config "$NVPN_CONFIG" \
  --device "$JOINING_DEVICE_ID" --json
```

`list` shows requests received by the daemon; shared links are inspected directly
and do not have to appear there. `--device` rejects an ID without a pending
request. The native app's **Devices → Add Join Request** remains another way to
review and approve the same link.

## Verify a useful connection

```sh
nvpn status --config "$NVPN_CONFIG" --json
nvpn ip --config "$NVPN_CONFIG" --peer --json
nvpn ping --config "$NVPN_CONFIG" "$PEER_TUNNEL_IP"
```

Require `status_source == "daemon"` before interpreting `mesh_ready`. Config-only
status has unknown readiness. Then reach the intended service, for example
`curl --fail --max-time 10 "http://$PEER_TUNNEL_IP:$SERVICE_PORT/health"` when that
service intentionally exposes HTTP on the mesh. Use its normal authentication.
A successful mesh ping does not establish that DNS or the service works.

For a short demo, show the two public device IDs, the reviewed approval, daemon
readiness, and the service response. Record install-to-first-response time and
any manual steps. Exclude join links, secrets, and private host details from a
public recording. Stop only the task's daemon when the demo is finished:
`nvpn stop --config "$NVPN_CONFIG"`.

## Troubleshooting and scope

- **Command missing:** check the installed version and `--help`; use the admin
  app until your CLI includes headless approval.
- **Permission denied / no TUN:** check the host's network privileges before
  retrying. Do not change the host's default route to troubleshoot enrollment.
- **Approved but not joined:** distinguish the saved roster from delivery.
  Check both daemons' status and connectivity; inspect a fresh link after a
  joining-daemon restart. There is no need to share private keys.
- **No system name resolution:** a working private mesh does not automatically
  configure the container's resolver. See the [container notes](../README.md#containers-and-headless-nodes).

See [protocol and privacy details](protocol.md), [verification tiers](verification-tiers.md),
and `nvpn doctor --help` for bounded diagnostics.
