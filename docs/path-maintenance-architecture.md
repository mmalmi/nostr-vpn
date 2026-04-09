# Path Maintenance Architecture

This document describes the staged move from the current Unix boringtun device
runtime toward a Tailscale-style transport manager.

## Current constraint

On Unix, the active WireGuard UDP socket is owned inside boringtun's
`DeviceHandle`. That means any same-port NAT assist packet has to borrow the
exact listen port from the tunnel. Today, `maybe_run_nat_punch` does that by:

1. stopping the tunnel,
2. sending raw UDP punch packets from the WireGuard listen port,
3. recreating the tunnel and reapplying peers and routes.

That is workable for bootstrap, but it is too disruptive once the mesh already
has healthy peers.

## Phase 1: staged recovery

Implemented in April 2026:

- Classify stale peers by impact before escalating.
- Keep ignoring optional stale peers when another peer already has a recent
  handshake and the stale peer is not carrying routes.

This makes runtime behavior closer to Tailscale's per-peer recovery model
without changing socket ownership yet.

## Phase 2: shared transport owner

The next real architecture step is to move Unix toward the userspace transport
shape already used on Windows:

- one long-lived UDP socket owned outside the WireGuard peer state,
- stable per-peer runtime objects,
- per-peer endpoint updates without tearing down the whole interface,
- direct access to non-disruptive path probes and periodic maintenance,
- a soft-recovery window that prefers in-place wakeups before same-port
  disruptive punching when the mesh is already healthy.

The existing userspace building blocks are:

- `crates/nostr-vpn-cli/src/userspace_wg.rs`
- `crates/nostr-vpn-cli/src/windows_tunnel.rs`

Those already own peer runtime state explicitly. The missing piece on Unix is a
cross-platform TUN plus UDP transport wrapper that can replace the current
boringtun device/UAPI path.

## Phase 3: magicsock-style path manager

After the shared transport exists, the path manager can become properly
Tailscale-like:

- maintain per-peer candidate paths,
- keep a sticky current path until a better one proves itself,
- probe alternate paths without rebuilding the tunnel,
- rebind sockets only on real underlay changes,
- keep endpoint success history and relay fallback policy in one place.

At that point, disruptive same-port punching becomes a last-resort bootstrap
tool instead of the normal stale-peer recovery path.
