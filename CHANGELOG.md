# Changelog

All notable changes to this project are documented in this file.

## Unreleased

## 0.3.10 - 2026-04-15

Changes since `v0.3.9` on 2026-04-09.

### Fixed

- Session reconnect logic now drops stale public signaling endpoints after a network change and reconnects relays so roaming between networks recovers cleanly instead of continuing to announce obsolete addresses.

## 0.3.9 - 2026-04-09

Changes since `v0.3.8` on 2026-04-08.

### Added

- A new `nvpn stats` CLI command for inspecting relay-operator state files in either human-readable or JSON form.
- A path-maintenance architecture note describing the staged move from disruptive same-port NAT recovery toward a more stable transport manager.

### Fixed

- Same-port NAT recovery on Unix now avoids disruptive punching for unrelated stale peers when the mesh already has another healthy peer, reducing unnecessary tunnel churn.

## 0.3.7 - 2026-04-08

Changes since `v0.3.6` on 2026-04-06.

### Fixed

- The desktop Diagnostics section now keeps your manual open or closed state across background refreshes, while still auto-opening if new health warnings appear.
- Background-service management controls now stay visible after initial setup, so reinstall, enable, disable, and uninstall actions remain reachable from the GUI.

## 0.3.6 - 2026-04-06

Changes since `v0.3.4` on 2026-04-02.

### Added

- A leaner invite bootstrap flow where QR codes carry only mesh/bootstrap metadata and the rest of the network state is fetched over signed Nostr roster updates.
- New Docker end-to-end coverage for NAT private-to-public reachability and selected-exit-node routing through a dedicated exit-node topology.

### Changed

- Shared participant aliases are now treated as roster state and republished by admins, so renames propagate across peers instead of remaining local-only.
- Desktop invite onboarding is split into a dedicated import panel, and the request-join flow now matches the backend’s automatic join-request behavior after invite import.
- Partial-mesh desktop status wording now favors explicit mesh counts over vague “connecting” copy, and service mismatch prompts show the exact app/service versions involved.

### Fixed

- Exit-node reconnects now recover from stale public endpoint state and still keep punching the selected exit peer when direct WireGuard paths need to be refreshed.
- macOS underlay repair now restarts the tunnel cleanly after network recovery instead of trying to reuse a broken in-memory tunnel handle.
- Desktop background-service timeout warnings now clear once the service actually recovers, instead of lingering after a successful reinstall or restart.
- Non-admin devices can no longer edit shared network identity fields in the GUI, reducing accidental roster drift and local/shared state confusion.
- Docker and Tauri end-to-end lanes now reflect the real join-request and mesh-ready UI states again, restoring full release-path coverage.

## 0.3.4 - 2026-04-02

Changes since `v0.3.3` on 2026-04-01.

### Added

- A new `nostr-vpn-web` HTTP API service plus `VITE_NVPN_API_BASE` frontend support, so the GUI can run against a web backend instead of only the Tauri desktop bridge.

### Fixed

- Desktop session toggles now keep the daemon as the source of truth for `VPN On` and `VPN Off`, while showing `VPN Starting` and `VPN Stopping` during in-flight control requests.
- Daemon pause and resume control requests are now polled every 100ms and persist their runtime state before slower disconnect and NAT refresh work, cutting the long on/off lag that could stretch to several seconds.
- The Docker Tauri driver wrapper now forwards `TAURI_E2E_SCENARIO`, so targeted end-to-end GUI checks run the requested scenario instead of silently defaulting to smoke coverage.

## 0.3.3 - 2026-04-01

Changes since `v0.3.2` on 2026-04-01.

### Fixed

- Relay fallback now uses the peer's active-session age for its direct-handshake grace period, so healthy periodic announces no longer prevent fallback from ever engaging.
- Runtime path caching now drops stale relay ingress endpoints when newer peer announcements stop advertising them, preventing clients from sticking to expired relay ports.
- GUI session toggles now flip immediately to the requested on/off state while the background service finishes the control request, making the desktop switch feel responsive again.
- Daemon pause and resume control now wait for the daemon's completion record instead of timing out on a short intermediate state window, avoiding false "background service did not respond in time" errors while shutting down.
- Daemon control requests now clear stale result files and log when pause, resume, or reload handling starts and completes, making stuck-control diagnosis easier in the bounded debug log.
- Docker relay-fallback end-to-end verification now passes again for the blocked-direct-UDP scenario, with both peers converging on the reachable relay ingress and completing tunnel traffic through it.

## 0.3.2 - 2026-04-01

Changes since `v0.3.1` on 2026-03-31.

### Changed

- Desktop advanced settings now expose the relay-routing toggle in both `Routing & Sharing` and `Session & Relays`, using clearer “Enable routing over relay when direct path fails” wording.
- Pending peer status in the desktop UI now reports when WireGuard is waiting on a relay endpoint instead of implying the direct endpoint is still in use.

### Fixed

- Relay routing no longer preempts a freshly selected direct path immediately; direct UDP now gets a retry window before relay routing takes over.
- Public relay fallback requests now wait for active peer presence and a short direct-handshake grace period instead of firing immediately on just-seen or stale peers.
- Disabling relay routing now drops cached relay endpoints from runtime path selection so the setting takes effect right away.
- Daemon and relay-operator debug logs are now trimmed to a bounded rolling tail instead of growing without limit.

## 0.3.1 - 2026-03-31

Changes since `v0.3.0` on 2026-03-31.

### Changed

- Signaling relays now stay connected so roster updates, exit-node capability changes, and other control-plane updates keep propagating after the mesh is established.
- Private exit-node announcements are refreshed to known peers after reconnects and reloads, reducing stale `Not offered` state after toggling the feature.
- Exit-node wording in the desktop UI and tray now explicitly describes the current mode as a private exit node, leaving room for a future public mode.

### Fixed

- Docker and Tauri coverage now reflects the keep-relays-connected policy instead of expecting relay pause after mesh completion.
- Legacy configs that still contain `auto_disconnect_relays_when_mesh_ready = true` are forced off on load and no longer reserialize that field.

## 0.3.0 - 2026-03-31

Changes since `v0.2.28` on 2026-03-26.

### Breaking Changes

- Invite format moved to version 2. `0.3.0` can still import v1 invites, but older builds that only understand invite v1 will not import invites generated by `0.3.0`.
- Admin-signed roster sync was added to the signaling protocol. Mixed-version peers can still connect at the base mesh layer, but older peers will not participate in the newer admin roster management model.

### Added

- Admin-managed network rosters shared over signed Nostr events, including admin promotion and removal.
- Invite payload support for network names, admin lists, and participant lists.
- Join requests addressed to all known network admins instead of a single inviter.
- Public relay services and relay failover support, including the `nvpn-udp-relay` binary and relay fallback end-to-end coverage.
- GUI service repair and auto-restart flows for updated or broken background services.
- Stable admin visibility in the desktop UI, including admin summaries, participant admin badges, and admin toggle actions.
- New end-to-end coverage for relay fallback, join-request admin propagation in Tauri, and three-peer roster/admin add-remove-rejoin flows in Docker.

### Changed

- The daemon now republishes and applies newer valid shared rosters across peers, with timestamp checks and existing-admin signature checks.
- Desktop startup now keeps background signaling alive when the local device is an admin listening for join requests, not only when autoconnect is enabled.
- The GUI now shows full peer npubs in more places and surfaces admin-specific network management state more clearly.
- Local and CI release paths now include newer signing and release automation updates, including Azure Trusted Signing fallback for Windows artifacts.

### Fixed

- Join-request handling between peers when the owner app was open only for admin/listener duties.
- Docker end-to-end coverage for roster mutations by fixing multiline TOML roster edits in the test harness.
- Several service reload and repair paths that previously required more manual recovery after config or binary changes.

## 0.2.28 - 2026-03-26

- Release `v0.2.28`.
